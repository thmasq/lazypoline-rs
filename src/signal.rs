use crate::ffi::{SpinLock, SpinLockGuard, rt_sigaction_raw};
use crate::gsrel::{BlockScope, get_privilege_level, set_privilege_level};
use libc::{SA_SIGINFO, SIG_DFL, SIG_IGN, SIGSYS, c_int, c_void, sigaction, siginfo_t, sigset_t, ucontext_t};
use std::cell::UnsafeCell;
use std::mem::{self, MaybeUninit};
use std::ptr::null;

const SA_UNSUPPORTED: i32 = 0x0000_0400;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelSigaction {
	pub handler: unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void),
	pub flags: libc::c_ulong,
	pub restorer: Option<unsafe extern "C" fn()>,
	pub mask: sigset_t,
}

const NSIG: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SigDispType {
	Ign,
	Term,
	Core,
	Stop,
	Cont,
}

pub struct SignalHandlers {
	dfl_handler: KernelSigaction,
	app_handlers: UnsafeCell<[KernelSigaction; NSIG]>,
	lock: SpinLock,
}

unsafe impl Sync for SignalHandlers {}

unsafe extern "C" {
	pub fn asm_syscall_hook();
	pub fn restore_selector_trampoline();
}

unsafe extern "C" fn wrap_signal_handler(signo: c_int, info: *mut siginfo_t, context: *mut c_void) {
	let selector_on_signal_entry = get_privilege_level();

	set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

	let uctxt = unsafe { &mut *context.cast::<ucontext_t>() };
	let gregs = uctxt.uc_mcontext.gregs.as_mut_ptr();
	let rsp = unsafe { *gregs.add(libc::REG_RSP as usize) };

	let gsreldata = crate::gsrel::GSRelData::new();
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
	#[must_use]
	pub fn new() -> *mut Self {
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

	unsafe fn get_app_handler(&self, signo: usize) -> KernelSigaction {
		unsafe { (*self.app_handlers.get())[signo] }
	}

	unsafe fn get_kernel_sigaction(&self, signo: usize) -> sigaction {
		let handler = unsafe { self.get_app_handler(signo) };

		let mut act: sigaction = unsafe { mem::zeroed() };
		act.sa_sigaction = handler.handler as usize;
		act.sa_flags = handler.flags as i32;
		act.sa_mask = handler.mask;

		act
	}

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

	#[allow(dead_code)]
	fn is_terminating_sig(signo: c_int) -> bool {
		let behavior = Self::get_default_behavior(signo);
		behavior == SigDispType::Term || behavior == SigDispType::Core
	}
}
