//! Signal handling for lazypoline
//!
//! This module implements signal handling for lazypoline, particularly
//! for handling the SIGSYS signal used by Syscall User Dispatch (SUD).

use crate::core::gsrel::{BlockScope, get_privilege_level, set_privilege_level};
use crate::ffi::{SpinLock, SpinLockGuard, rt_sigaction_raw};
use libc::{SA_SIGINFO, SIG_DFL, SIG_IGN, SIGSYS, c_int, c_void, sigaction, siginfo_t, sigset_t, ucontext_t};
use std::cell::UnsafeCell;
use std::mem::{self, MaybeUninit};
use std::ptr::null;

/// Flag indicating that a signal is not supported
const SA_UNSUPPORTED: i32 = 0x0000_0400;

/// The maximum number of signals supported by the system
const NSIG: usize = 64;

/// Represents a kernel-level signal action structure
///
/// This structure maps directly to the kernel's internal representation
/// of signal handlers, which differs slightly from the user-space
/// `sigaction` structure exposed by libc.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelSigaction {
	/// The signal handler function pointer
	pub handler: unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void),

	/// Signal handler flags (SA_*)
	pub flags: libc::c_ulong,

	/// Signal return restorer function
	pub restorer: Option<unsafe extern "C" fn()>,

	/// Signal mask to apply during handler execution
	pub mask: sigset_t,
}

/// Represents the different types of default signal dispositions
///
/// This enum categorizes signals by their default behavior when no handler
/// is registered or when `SIG_DFL` is used as the handler.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SigDispType {
	/// Signal is ignored by default
	Ign,
	/// Signal terminates the process by default
	Term,
	/// Signal terminates the process and produces a core dump by default
	Core,
	/// Signal stops the process by default
	Stop,
	/// Signal continues a stopped process by default
	Cont,
}

/// Manages signal handlers for a process
///
/// This structure maintains a table of application-specific signal handlers
/// and allows for intercepting and wrapping signals while maintaining the
/// original handler behavior. It also provides transparent syscall blocking
/// during signal handling to maintain system call interception integrity.
pub struct SignalHandlers {
	/// The default signal handler
	dfl_handler: KernelSigaction,
	/// Array of application-specific signal handlers
	app_handlers: UnsafeCell<[KernelSigaction; NSIG]>,
	/// Lock to synchronize access to the handler array
	lock: SpinLock,
}

// SignalHandlers can be shared across threads safely
unsafe impl Sync for SignalHandlers {}

// External assembly functions used for signal and syscall handling
unsafe extern "C" {
	/// Assembly function that hooks into syscalls for interception
	pub fn asm_syscall_hook();

	/// Assembly trampoline function used to restore the original selector state
	/// after signal handling is complete
	pub fn restore_selector_trampoline();
}

/// Wraps an application's signal handler to manage privilege levels during signal handling
///
/// This function:
/// 1. Preserves the current privilege level at signal entry
/// 2. Temporarily allows syscalls during signal handling
/// 3. Invokes the application's handler
/// 4. Sets up a return trampoline to restore the original privilege level
/// 5. Blocks syscalls until the trampoline executes
unsafe extern "C" fn wrap_signal_handler(signo: c_int, info: *mut siginfo_t, context: *mut c_void) {
	let selector_on_signal_entry = get_privilege_level();

	set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

	let uctxt = unsafe { &mut *context.cast::<ucontext_t>() };
	let gregs = uctxt.uc_mcontext.gregs.as_mut_ptr();
	let rsp = unsafe { *gregs.add(libc::REG_RSP as usize) };

	let gsreldata = unsafe { crate::core::gsrel::GSRelData::new() };
	let signal_handlers = unsafe { *(*gsreldata).signal_handlers.get() };

	unsafe { (*signal_handlers).invoke_app_specific_handler(signo, info, context) };

	// Verify RSP wasn't modified
	assert_eq!(rsp, unsafe { *gregs.add(libc::REG_RSP as usize) });

	// Set up the return trampoline
	// Modify the stack to save the original RIP
	unsafe { *gregs.add(libc::REG_RSP as usize) -= std::mem::size_of::<u64>() as i64 };
	let stack_bottom = (unsafe { *gregs.add(libc::REG_RSP as usize) }) as *mut i64;
	unsafe { *stack_bottom = *gregs.add(libc::REG_RIP as usize) };

	// Change RIP to point to our trampoline
	unsafe { *gregs.add(libc::REG_RIP as usize) = restore_selector_trampoline as i64 };

	let sigreturn_stack_current = unsafe { (*gsreldata).sigreturn_stack_current.get() };
	unsafe { *(*sigreturn_stack_current) = selector_on_signal_entry };
	unsafe { *sigreturn_stack_current = (*sigreturn_stack_current).add(1) };

	// Block syscalls until the sigreturn trampoline restores the original level
	set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_BLOCK);
}

impl SignalHandlers {
	/// Creates a new `SignalHandlers` instance
	///
	/// # Returns
	///
	/// A pointer to the newly allocated `SignalHandlers` instance
	///
	/// # Safety
	///
	/// This function is unsafe because it:
	/// - Allocates memory with malloc
	/// - Sets up signal handlers
	/// - Modifies global process state
	#[must_use]
	pub unsafe fn new() -> *mut Self {
		unsafe {
			let handlers = libc::malloc(std::mem::size_of::<Self>()).cast::<Self>();
			assert!(!handlers.is_null(), "Failed to allocate SignalHandlers");

			// Create a MaybeUninit for dfl_handler
			let mut dfl_handler_uninit: MaybeUninit<KernelSigaction> = MaybeUninit::uninit();
			let dfl_handler_ptr = dfl_handler_uninit.as_mut_ptr();

			// Initialize the handler field with SIG_DFL
			(*dfl_handler_ptr).handler = mem::transmute(SIG_DFL);
			(*dfl_handler_ptr).flags = 0;
			(*dfl_handler_ptr).restorer = None;
			(*dfl_handler_ptr).mask = mem::zeroed(); // sigset_t can be zeroed

			let mut dfl_handler = dfl_handler_uninit.assume_init();

			// Create a MaybeUninit array for app_handlers
			let mut app_handlers_uninit: MaybeUninit<[KernelSigaction; NSIG]> = MaybeUninit::uninit();
			let app_handlers_ptr = app_handlers_uninit.as_mut_ptr().cast::<KernelSigaction>();

			// Initialize each element in the array
			for i in 0..NSIG {
				// Initialize each handler with the default handler
				std::ptr::write(app_handlers_ptr.add(i), dfl_handler);
			}

			// Now properly handle signal actions
			for i in 1..NSIG {
				if i == libc::SIGKILL as usize {
					continue;
				}

				let mut act: MaybeUninit<sigaction> = MaybeUninit::uninit();
				let result = rt_sigaction_raw(i as c_int, null(), act.as_mut_ptr(), 8);
				if result == 0 {
					let act = act.assume_init();

					// Create a MaybeUninit for this handler
					let mut handler_uninit: MaybeUninit<KernelSigaction> = MaybeUninit::uninit();
					let handler_ptr = handler_uninit.as_mut_ptr();

					// Initialize handler fields
					(*handler_ptr).handler = mem::transmute(act.sa_sigaction);
					(*handler_ptr).flags = act.sa_flags as u64;
					(*handler_ptr).restorer = None;
					(*handler_ptr).mask = act.sa_mask;

					let handler = handler_uninit.assume_init();
					std::ptr::write(app_handlers_ptr.add(i), handler);

					if act.sa_sigaction == mem::transmute(SIG_DFL) {
						// If this is a default handler, save it
						dfl_handler = handler;
					}
				}
			}

			let app_handlers = app_handlers_uninit.assume_init();

			std::ptr::write(
				handlers,
				Self {
					dfl_handler,
					app_handlers: UnsafeCell::new(app_handlers),
					lock: SpinLock::new(),
				},
			);

			handlers
		}
	}

	/// Invokes the application-specific handler for a given signal
	///
	/// # Arguments
	///
	/// * `sig` - The signal number
	/// * `info` - Pointer to the signal information structure
	/// * `context` - Pointer to the signal context
	///
	/// # Safety
	///
	/// This function is unsafe because it:
	/// - Dereferences raw pointers
	/// - Calls an arbitrary function pointer provided by the application
	/// - Assumes the signal handlers table is properly initialized
	pub unsafe fn invoke_app_specific_handler(&self, sig: c_int, info: *mut siginfo_t, context: *mut c_void) {
		let _guard = SpinLockGuard::new(&self.lock);
		let app_handler = unsafe { self.get_app_handler(sig as usize) };

		// We don't want to emulate SIG_DFL or SIG_IGN
		assert_ne!(app_handler.handler as usize, { SIG_DFL });
		assert_ne!(app_handler.handler as usize, { SIG_IGN });

		if app_handler.flags & libc::SA_RESETHAND as u64 != 0 {
			let app_handlers_ptr = self.app_handlers.get();
			unsafe {
				(*app_handlers_ptr)[sig as usize] = self.dfl_handler;
			}
		}

		{
			let _block = BlockScope::new();
			unsafe { (app_handler.handler)(sig, info, context) };
		}
	}

	/// Handles signal action (sigaction) requests from the application
	///
	/// This function intercepts the application's attempts to register signal handlers
	/// and maintains internal state while setting up the actual kernel signal handler
	/// to be the wrapper function.
	///
	/// # Arguments
	///
	/// * `signo` - The signal number
	/// * `newact` - Pointer to the new signal action, or null if only querying
	/// * `oldact` - Pointer where to store the old signal action, or null if not interested
	///
	/// # Returns
	///
	/// 0 on success, or a negative error code on failure
	///
	/// # Safety
	///
	/// This function is unsafe because it:
	/// - Dereferences raw pointers
	/// - Modifies signal handling state that affects the entire process
	/// - Uses low-level system calls
	pub unsafe fn handle_app_sigaction(&self, signo: c_int, newact: *const sigaction, oldact: *mut sigaction) -> i64 {
		// Hold lock while operating on app_handlers
		let _guard = SpinLockGuard::new(&self.lock);

		if signo == libc::SIGSYS {
			// Handle SIGSYS specially - we ignore registration for SIGSYS
			// and always terminate the program on non-SUD SIGSYS
			if !newact.is_null() {
				assert_eq!((unsafe { *newact }).sa_flags & SA_UNSUPPORTED, 0);
			}

			if !oldact.is_null() {
				unsafe { *oldact = self.get_kernel_sigaction(SIGSYS as usize) };
			}

			return 0;
		}

		if newact.is_null() || (unsafe { *newact }).sa_sigaction == SIG_IGN {
			let result = unsafe { rt_sigaction_raw(signo, newact, oldact, 8) };
			if result != 0 {
				return i64::from(result);
			}

			if !oldact.is_null() {
				unsafe { *oldact = self.get_kernel_sigaction(signo as usize) };
			}

			if !newact.is_null() {
				// Using get_kernel_sigaction and direct array manipulation
				let app_handlers_ptr = self.app_handlers.get();
				let new_kernel_act = unsafe { *newact };

				// Create a MaybeUninit for the new handler
				let mut new_handler_uninit: MaybeUninit<KernelSigaction> = MaybeUninit::uninit();
				let new_handler_ptr = new_handler_uninit.as_mut_ptr();

				// Initialize handler fields
				unsafe {
					(*new_handler_ptr).handler = mem::transmute::<
						usize,
						unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void),
					>(new_kernel_act.sa_sigaction);
					(*new_handler_ptr).flags = new_kernel_act.sa_flags as u64;
					(*new_handler_ptr).restorer = None;
					(*new_handler_ptr).mask = new_kernel_act.sa_mask;
				}
				let new_handler = unsafe { new_handler_uninit.assume_init() };

				unsafe {
					(*app_handlers_ptr)[signo as usize] = new_handler;
				}
			}

			return 0;
		}

		if (unsafe { *newact }).sa_sigaction == SIG_DFL {
			let result = unsafe { rt_sigaction_raw(signo, newact, oldact, 8) };
			if result == 0 {
				// Get old value before updating
				let old = if oldact.is_null() {
					unsafe { mem::zeroed() }
				} else {
					unsafe { self.get_kernel_sigaction(signo as usize) }
				};

				// Update app_handlers directly
				let app_handlers_ptr = self.app_handlers.get();
				let new_kernel_act = unsafe { *newact };

				// Create a MaybeUninit for the new handler
				let mut new_handler_uninit: MaybeUninit<KernelSigaction> = MaybeUninit::uninit();
				let new_handler_ptr = new_handler_uninit.as_mut_ptr();

				// Initialize handler fields
				unsafe {
					(*new_handler_ptr).handler = mem::transmute::<
						usize,
						unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void),
					>(new_kernel_act.sa_sigaction);
					(*new_handler_ptr).flags = new_kernel_act.sa_flags as u64;
					(*new_handler_ptr).restorer = None;
					(*new_handler_ptr).mask = new_kernel_act.sa_mask;
				}

				let new_handler = unsafe { new_handler_uninit.assume_init() };

				unsafe {
					(*app_handlers_ptr)[signo as usize] = new_handler;
				}

				if !oldact.is_null() {
					unsafe { *oldact = old };
				}
			}
			return i64::from(result);
		}

		let mut newact_cpy = unsafe { *newact };
		newact_cpy.sa_flags |= SA_SIGINFO;
		newact_cpy.sa_sigaction = wrap_signal_handler as usize;

		let result = unsafe { rt_sigaction_raw(signo, &newact_cpy, oldact, 8) };
		if result != 0 {
			return i64::from(result);
		}

		// Get old value before updating
		let old = if oldact.is_null() {
			unsafe { mem::zeroed() }
		} else {
			unsafe { self.get_kernel_sigaction(signo as usize) }
		};

		// Update app_handlers directly
		let app_handlers_ptr = self.app_handlers.get();
		let new_kernel_act = unsafe { *newact };

		// Create a MaybeUninit for the new handler
		let mut new_handler_uninit: MaybeUninit<KernelSigaction> = MaybeUninit::uninit();
		let new_handler_ptr = new_handler_uninit.as_mut_ptr();

		// Initialize handler fields
		unsafe {
			(*new_handler_ptr).handler = mem::transmute::<
				usize,
				unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void),
			>(new_kernel_act.sa_sigaction);
			(*new_handler_ptr).flags = new_kernel_act.sa_flags as u64;
			(*new_handler_ptr).restorer = None;
			(*new_handler_ptr).mask = new_kernel_act.sa_mask;
		}
		let new_handler = unsafe { new_handler_uninit.assume_init() };

		unsafe {
			(*app_handlers_ptr)[signo as usize] = new_handler;
		}

		if !oldact.is_null() {
			unsafe { *oldact = old };
		}

		0
	}

	/// Retrieves the application-specific handler for a given signal
	///
	/// # Arguments
	///
	/// * `signo` - The signal number
	///
	/// # Returns
	///
	/// The application's registered handler for the specified signal
	///
	/// # Safety
	///
	/// This function is unsafe because it dereferences the internal `UnsafeCell`
	/// without synchronization (caller must ensure exclusive access or use the lock)
	unsafe fn get_app_handler(&self, signo: usize) -> KernelSigaction {
		unsafe { (*self.app_handlers.get())[signo] }
	}

	/// Converts an internal `KernelSigaction` to the user-facing sigaction structure
	///
	/// # Arguments
	///
	/// * `signo` - The signal number
	///
	/// # Returns
	///
	/// A sigaction structure representing the current handler for the specified signal
	///
	/// # Safety
	///
	/// This function is unsafe because it dereferences the internal `UnsafeCell`
	/// without synchronization (caller must ensure exclusive access or use the lock)
	unsafe fn get_kernel_sigaction(&self, signo: usize) -> sigaction {
		let handler = unsafe { self.get_app_handler(signo) };

		let mut act: sigaction = unsafe { mem::zeroed() };
		act.sa_sigaction = handler.handler as usize;
		act.sa_flags = handler.flags as i32;
		act.sa_mask = handler.mask;

		act
	}

	/// Determines the default behavior for a given signal
	///
	/// # Arguments
	///
	/// * `signo` - The signal number
	///
	/// # Returns
	///
	/// The default disposition type for the specified signal
	const fn get_default_behavior(signo: c_int) -> SigDispType {
		match signo {
			// Ignored signals
			libc::SIGCHLD | libc::SIGURG | libc::SIGWINCH => SigDispType::Ign,

			// Terminating signals
			libc::SIGALRM
			| libc::SIGHUP
			| libc::SIGINT
			| libc::SIGIO
			| libc::SIGKILL
			| libc::SIGPIPE
			| libc::SIGPROF
			| libc::SIGPWR
			| libc::SIGSTKFLT
			| libc::SIGTERM
			| libc::SIGUSR1
			| libc::SIGUSR2
			| libc::SIGVTALRM => SigDispType::Term,

			// Coredump signals
			libc::SIGABRT
			| libc::SIGBUS
			| libc::SIGFPE
			| libc::SIGILL
			| libc::SIGQUIT
			| libc::SIGSEGV
			| libc::SIGSYS
			| libc::SIGTRAP
			| libc::SIGXCPU
			| libc::SIGXFSZ => SigDispType::Core,

			// Stop signals
			libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => SigDispType::Stop,

			// Cont signals
			libc::SIGCONT => SigDispType::Cont,

			_ => SigDispType::Term,
		}
	}

	/// Determines if a signal would terminate the process by default
	///
	/// # Arguments
	///
	/// * `signo` - The signal number
	///
	/// # Returns
	///
	/// `true` if the signal would terminate the process (with or without core dump),
	/// `false` otherwise
	#[allow(dead_code)]
	fn is_terminating_sig(signo: c_int) -> bool {
		let behavior = Self::get_default_behavior(signo);
		behavior == SigDispType::Term || behavior == SigDispType::Core
	}
}
