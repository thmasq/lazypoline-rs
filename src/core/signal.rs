//! Signal handling for lazypoline
//!
//! This module implements signal handling for lazypoline, particularly
//! for handling the SIGSYS signal used by Syscall User Dispatch (SUD).

use crate::core::gsrel::{BlockScope, GSRelData, get_privilege_level, set_privilege_level};
use crate::ffi::rt_sigaction_raw;
use libc::{SA_SIGINFO, SIG_DFL, SIG_IGN, SIGSYS, c_int, c_void, sigaction, siginfo_t, sigset_t, ucontext_t};
use std::cell::UnsafeCell;
use std::mem::{self, MaybeUninit};
use std::ptr::null;
use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

/// Flag indicating that a signal is not supported
const SA_UNSUPPORTED: i32 = 0x0000_0400;

/// The maximum number of signals supported by the system
const NSIG: usize = 64;

/// Capacity of the internal async-signal-safe memory pool
const POOL_SIZE: usize = 1024;
const POOL_BITMAP_WORDS: usize = POOL_SIZE / 64;

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

/// A node in the lock-free memory pool
/// Padded and aligned to 64 bytes to prevent false sharing of cache lines across threads
#[repr(C)]
#[repr(align(64))]
pub struct PoolNode {
	pub data: KernelSigaction,
	pub next_retired: AtomicPtr<Self>,
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
	app_handlers: [AtomicPtr<PoolNode>; NSIG],
	/// Bitmap tracking which slots in the pool are currently allocated (1 = allocated, 0 = free)
	bitmap: [AtomicU64; POOL_BITMAP_WORDS],
	/// Pre-allocated blocks of memory for `KernelSigaction` nodes
	pool: [UnsafeCell<PoolNode>; POOL_SIZE],
	/// Hazard Pointers array. Threads announce which node they are reading to protect it from
	/// reclamation.
	hazard_pointers: [AtomicPtr<PoolNode>; POOL_SIZE],
	/// Tracks the Thread Key (typically the `GSRelData` memory address) that permanently owns the
	/// hazard slot
	hazard_owners: [AtomicUsize; POOL_SIZE],
	/// Lock-free stack of old pointers waiting to be returned to the pool
	retired_head: AtomicPtr<PoolNode>,
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

	let gs_base = unsafe { crate::ffi::get_gs_base() };
	if gs_base == 0 {
		// Note: tracing and panic are technically not async-signal-safe,
		// but since this is a fatal, unrecoverable path, it is acceptable.
		tracing::error!("wrap_signal_handler: Failed to get GSRelData for current thread");
		panic!("Failed to get GSRelData for current thread");
	}

	let gsreldata = gs_base as *mut GSRelData;

	let signal_handlers = unsafe { *(*gsreldata).signal_handlers.get() };
	if signal_handlers.is_null() {
		tracing::error!("wrap_signal_handler: No signal handlers found for current thread");
		panic!("No signal handlers found for current thread");
	}

	// Extract the O(1) cache requirements for the hazard pointers
	let thread_key = gsreldata as usize;
	let cache_ptr = unsafe { (*gsreldata).hazard_slot_idx.get() };

	unsafe { (*signal_handlers).invoke_app_specific_handler(signo, info, context, thread_key, cache_ptr) };

	// Verify RSP wasn't modified
	assert_eq!(rsp, unsafe { *gregs.add(libc::REG_RSP as usize) });

	// Set up the return trampoline
	// Modify the stack to save the original RIP
	unsafe { *gregs.add(libc::REG_RSP as usize) -= std::mem::size_of::<u64>() as i64 };
	let stack_bottom = (unsafe { *gregs.add(libc::REG_RSP as usize) }) as *mut i64;
	unsafe { *stack_bottom = *gregs.add(libc::REG_RIP as usize) };

	// Change RIP to point to our trampoline
	unsafe { *gregs.add(libc::REG_RIP as usize) = restore_selector_trampoline as *const () as i64 };

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
			let handlers = libc::calloc(1, std::mem::size_of::<Self>()).cast::<Self>();
			assert!(!handlers.is_null(), "Failed to allocate SignalHandlers");

			// Create a MaybeUninit for dfl_handler
			let mut dfl_handler_uninit: MaybeUninit<KernelSigaction> = MaybeUninit::uninit();
			let dfl_ptr = dfl_handler_uninit.as_mut_ptr();
			(*dfl_ptr).handler =
				mem::transmute::<usize, unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void)>(SIG_DFL);
			(*dfl_ptr).flags = 0;
			(*dfl_ptr).restorer = None;
			(*dfl_ptr).mask = mem::zeroed();
			let dfl_handler = dfl_handler_uninit.assume_init();

			std::ptr::write(std::ptr::addr_of_mut!((*handlers).dfl_handler), dfl_handler);

			// Check if this is a new thread that should inherit signal handlers
			let should_inherit = {
				let registry = crate::core::thread_registry::registry();
				// Only inherit if we're not the main thread and the parent shares signal handlers
				registry.get_current_thread_info().is_some_and(|thread_info| {
					thread_info.parent_thread_id.is_some() && thread_info.shares_signal_handlers()
				})
			};

			if should_inherit {
				// This is a thread that should inherit signal handlers from its parent
				if let Some(parent_info) = crate::core::thread_registry::registry().get_current_parent_thread_info() {
					// Get the parent's signal handlers
					let parent_gsreldata = parent_info.gsreldata;
					if !parent_gsreldata.is_null() {
						// Get the parent's signal handlers
						let parent_signal_handlers = *(*parent_gsreldata).signal_handlers.get();
						if !parent_signal_handlers.is_null() {
							// We need to fetch the parent's handlers using their thread key
							let parent_key = parent_gsreldata as usize;
							let parent_cache_ptr = (*parent_gsreldata).hazard_slot_idx.get();

							for i in 0..NSIG {
								let handler_copy =
									(*parent_signal_handlers).get_app_handler(i, parent_key, parent_cache_ptr);

								let node = (*handlers).alloc_node();
								(*node).data = handler_copy;
								(*node).next_retired = AtomicPtr::new(std::ptr::null_mut());

								(*handlers).app_handlers[i].store(node, Ordering::Relaxed);
							}

							tracing::debug!("Inherited signal handlers from parent thread");
							(*handlers).dfl_handler = (*parent_signal_handlers).dfl_handler;
						}
					}
				}
			} else {
				// This is a new process or a thread that doesn't share signal handlers
				// Now properly handle signal actions
				for i in 1..NSIG {
					if i == libc::SIGKILL as usize {
						continue;
					}

					let mut act: MaybeUninit<sigaction> = MaybeUninit::uninit();
					let result = rt_sigaction_raw(i as c_int, null(), act.as_mut_ptr(), 8);

					let node = (*handlers).alloc_node();
					(*node).next_retired = AtomicPtr::new(std::ptr::null_mut());

					if result == 0 {
						let act = act.assume_init();
						(*node).data.handler = mem::transmute::<
							usize,
							unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void),
						>(act.sa_sigaction);
						(*node).data.flags = act.sa_flags as u64;
						(*node).data.restorer = None;
						(*node).data.mask = act.sa_mask;

						if act.sa_sigaction == SIG_DFL {
							(*handlers).dfl_handler = (*node).data;
						}
					} else {
						(*node).data = dfl_handler;
					}

					(*handlers).app_handlers[i].store(node, Ordering::Relaxed);
				}
			}

			tracing::debug!("Created signal handlers at {:p}", handlers);
			handlers
		}
	}

	/// Claims a node from the wait-free memory pool via atomic bitwise scanning
	unsafe fn alloc_node(&self) -> *mut PoolNode {
		for i in 0..POOL_BITMAP_WORDS {
			let mut current = self.bitmap[i].load(Ordering::Relaxed);
			loop {
				if current == u64::MAX {
					break;
				}

				let tz = current.trailing_ones() as usize;
				let new_val = current | (1 << tz);

				match self.bitmap[i].compare_exchange_weak(current, new_val, Ordering::AcqRel, Ordering::Relaxed) {
					Ok(_) => {
						let idx = i * 64 + tz;
						return self.pool[idx].get();
					},
					Err(val) => current = val,
				}
			}
		}
		panic!("SignalHandlers memory pool exhausted (over 1024 active handlers)");
	}

	/// Returns a node to the wait-free memory pool by clearing its bit
	unsafe fn free_node(&self, ptr: *mut PoolNode) {
		let base = self.pool.as_ptr().cast::<PoolNode>();
		let offset = unsafe { ptr.offset_from(base) };
		debug_assert!(offset >= 0 && (offset as usize) < POOL_SIZE);

		let offset = offset as usize;
		let i = offset / 64;
		let bit = offset % 64;
		self.bitmap[i].fetch_and(!(1 << bit), Ordering::Release);
	}

	/// Finds the thread's owned hazard slot in O(1) time if cached,
	/// otherwise falls back to O(N) scan to claim/find a slot and updates the cache.
	unsafe fn acquire_hazard_slot(&self, thread_key: usize, cache_ptr: *mut usize, ptr: *mut PoolNode) -> usize {
		let cached_idx = unsafe { *cache_ptr };
		if cached_idx != usize::MAX {
			self.hazard_pointers[cached_idx].store(ptr, Ordering::SeqCst);
			return cached_idx;
		}

		let mut empty_slot = usize::MAX;
		for i in 0..POOL_SIZE {
			let owner = self.hazard_owners[i].load(Ordering::Relaxed);
			if owner == thread_key {
				self.hazard_pointers[i].store(ptr, Ordering::SeqCst);
				unsafe { *cache_ptr = i };
				return i;
			} else if owner == 0 && empty_slot == usize::MAX {
				empty_slot = i;
			}
		}

		if empty_slot != usize::MAX {
			if self.hazard_owners[empty_slot]
				.compare_exchange(0, thread_key, Ordering::Relaxed, Ordering::Relaxed)
				.is_ok()
			{
				self.hazard_pointers[empty_slot].store(ptr, Ordering::SeqCst);
				unsafe { *cache_ptr = empty_slot };
				return empty_slot;
			}
			return unsafe { self.acquire_hazard_slot(thread_key, cache_ptr, ptr) };
		}

		panic!("Hazard pointer slots exhausted");
	}

	unsafe fn push_to_retired(&self, ptr: *mut PoolNode) {
		let mut head = self.retired_head.load(Ordering::Relaxed);
		loop {
			unsafe { (*ptr).next_retired.store(head, Ordering::Relaxed) };
			match self
				.retired_head
				.compare_exchange_weak(head, ptr, Ordering::Release, Ordering::Relaxed)
			{
				Ok(_) => break,
				Err(new_head) => head = new_head,
			}
		}
	}

	unsafe fn retire_node(&self, ptr: *mut PoolNode) {
		unsafe { self.push_to_retired(ptr) };
		unsafe { self.try_reclaim() };
	}

	/// Empties the retired queue, checking Hazard Pointers, and returning unreferenced memory back
	/// to the pool
	unsafe fn try_reclaim(&self) {
		let mut list = self.retired_head.swap(std::ptr::null_mut(), Ordering::Acquire);
		let mut unreclaimable = std::ptr::null_mut();

		while !list.is_null() {
			let node = list;
			list = unsafe { (*node).next_retired.load(Ordering::Relaxed) };

			let mut is_hazardous = false;
			for i in 0..POOL_SIZE {
				if self.hazard_pointers[i].load(Ordering::SeqCst) == node {
					is_hazardous = true;
					break;
				}
			}

			if is_hazardous {
				unsafe { (*node).next_retired.store(unreclaimable, Ordering::Relaxed) };
				unreclaimable = node;
			} else {
				unsafe { self.free_node(node) };
			}
		}

		while !unreclaimable.is_null() {
			let node = unreclaimable;
			unreclaimable = unsafe { (*node).next_retired.load(Ordering::Relaxed) };
			unsafe { self.push_to_retired(node) };
		}
	}

	/// Retrieves the application-specific handler safely via O(1) Hazard Pointer protection
	unsafe fn get_app_handler(&self, signo: usize, thread_key: usize, cache_ptr: *mut usize) -> KernelSigaction {
		let mut hp_idx;
		let mut node_ptr;
		loop {
			node_ptr = self.app_handlers[signo].load(Ordering::Acquire);
			hp_idx = unsafe { self.acquire_hazard_slot(thread_key, cache_ptr, node_ptr) };

			if self.app_handlers[signo].load(Ordering::SeqCst) == node_ptr {
				break;
			}
			self.hazard_pointers[hp_idx].store(std::ptr::null_mut(), Ordering::Release);
		}

		let data = unsafe { (*node_ptr).data };

		// If application longjmp's here, the Hazard Pointer naturally remains active
		// protecting this node. Next time the thread receives a signal, the slot is safely overwritten.
		self.hazard_pointers[hp_idx].store(std::ptr::null_mut(), Ordering::Release);
		data
	}

	pub unsafe fn invoke_app_specific_handler(
		&self,
		sig: c_int,
		info: *mut siginfo_t,
		context: *mut c_void,
		thread_key: usize,
		cache_ptr: *mut usize,
	) {
		let app_handler = unsafe { self.get_app_handler(sig as usize, thread_key, cache_ptr) };

		// We don't want to emulate SIG_DFL or SIG_IGN
		assert_ne!(app_handler.handler as usize, { SIG_DFL });
		assert_ne!(app_handler.handler as usize, { SIG_IGN });

		if app_handler.flags & libc::SA_RESETHAND as u64 != 0 {
			let new_node = unsafe { self.alloc_node() };
			unsafe {
				(*new_node).data = self.dfl_handler;
				(*new_node).next_retired.store(std::ptr::null_mut(), Ordering::Relaxed);
			}
			let old_node = self.app_handlers[sig as usize].swap(new_node, Ordering::Release);
			if !old_node.is_null() {
				unsafe { self.retire_node(old_node) };
			}
		}

		{
			let _block = BlockScope::new();
			unsafe { (app_handler.handler)(sig, info, context) };
		}
	}

	/// Resolves the context required for hazard pointers if called outside a normal signal delivery
	fn get_thread_context() -> (usize, *mut usize) {
		let registry = crate::core::thread_registry::registry();
		let gsreldata = registry.get_current_thread_info().map_or_else(
			|| {
				let gs_base = unsafe { crate::ffi::get_gs_base() };
				if gs_base != 0 {
					gs_base as *mut GSRelData
				} else {
					std::ptr::null_mut()
				}
			},
			|info| info.gsreldata,
		);

		if gsreldata.is_null() {
			// Fallback during early initialization: OS Thread ID and a temporary cache pointer
			let tid = unsafe { libc::syscall(libc::SYS_gettid) as usize };
			let mut dummy_cache = usize::MAX;
			(tid, &raw mut dummy_cache)
		} else {
			(gsreldata as usize, unsafe { (*gsreldata).hazard_slot_idx.get() })
		}
	}

	pub unsafe fn handle_app_sigaction(&self, signo: c_int, newact: *const sigaction, oldact: *mut sigaction) -> i64 {
		// Log the signal action request
		tracing::trace!(
			"handle_app_sigaction: signo={}, newact={:?}, oldact={:?}",
			signo,
			newact,
			oldact
		);

		let (thread_key, cache_ptr) = Self::get_thread_context();

		if signo == libc::SIGSYS {
			// Handle SIGSYS specially - we ignore registration for SIGSYS
			// and always terminate the program on non-SUD SIGSYS
			if !newact.is_null() {
				assert_eq!((unsafe { *newact }).sa_flags & SA_UNSUPPORTED, 0);
			}

			if !oldact.is_null() {
				unsafe { *oldact = self.get_kernel_sigaction(SIGSYS as usize, thread_key, cache_ptr) };
			}

			return 0;
		}

		if newact.is_null() || (unsafe { *newact }).sa_sigaction == SIG_IGN {
			let result = unsafe { rt_sigaction_raw(signo, newact, oldact, 8) };
			if result != 0 {
				return i64::from(result);
			}

			if !oldact.is_null() {
				unsafe { *oldact = self.get_kernel_sigaction(signo as usize, thread_key, cache_ptr) };
			}

			if !newact.is_null() {
				unsafe { self.update_app_handler(signo, *newact) };
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
					unsafe { self.get_kernel_sigaction(signo as usize, thread_key, cache_ptr) }
				};

				unsafe { self.update_app_handler(signo, *newact) };

				if !oldact.is_null() {
					unsafe { *oldact = old };
				}
			}
			return i64::from(result);
		}

		let mut newact_cpy = unsafe { *newact };
		newact_cpy.sa_flags |= SA_SIGINFO;
		newact_cpy.sa_sigaction = wrap_signal_handler as *const () as usize;

		let result = unsafe { rt_sigaction_raw(signo, &raw const newact_cpy, oldact, 8) };
		if result != 0 {
			return i64::from(result);
		}

		// Get old value before updating
		let old = if oldact.is_null() {
			unsafe { mem::zeroed() }
		} else {
			unsafe { self.get_kernel_sigaction(signo as usize, thread_key, cache_ptr) }
		};

		unsafe { self.update_app_handler(signo, *newact) };

		if !oldact.is_null() {
			unsafe { *oldact = old };
		}

		0
	}

	/// Helper to update the application handler array and propagate the change
	unsafe fn update_app_handler(&self, signo: c_int, new_kernel_act: sigaction) {
		let new_node = unsafe { self.alloc_node() };

		unsafe {
			(*new_node).data.handler = mem::transmute::<
				usize,
				unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void),
			>(new_kernel_act.sa_sigaction);
			(*new_node).data.flags = new_kernel_act.sa_flags as u64;
			(*new_node).data.restorer = None;
			(*new_node).data.mask = new_kernel_act.sa_mask;
			(*new_node).next_retired.store(std::ptr::null_mut(), Ordering::Relaxed);
		}

		let old_node = self.app_handlers[signo as usize].swap(new_node, Ordering::Release);

		if !old_node.is_null() {
			unsafe { self.retire_node(old_node) };
		}
	}

	unsafe fn get_kernel_sigaction(&self, signo: usize, thread_key: usize, cache_ptr: *mut usize) -> sigaction {
		let handler = unsafe { self.get_app_handler(signo, thread_key, cache_ptr) };

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
	#[allow(clippy::match_same_arms)]
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

	/// Creates a deep copy of these signal handlers
	///
	/// # Returns
	///
	/// A new `SignalHandlers` instance that is a copy of this one
	#[must_use]
	pub unsafe fn clone(&self) -> *mut Self {
		let new_handlers = unsafe { libc::malloc(std::mem::size_of::<Self>()).cast::<Self>() };
		assert!(!new_handlers.is_null(), "Failed to allocate SignalHandlers");

		unsafe { libc::memset(new_handlers.cast(), 0, std::mem::size_of::<Self>()) };
		unsafe { std::ptr::write(std::ptr::addr_of_mut!((*new_handlers).dfl_handler), self.dfl_handler) };

		let (thread_key, cache_ptr) = Self::get_thread_context();

		for i in 0..NSIG {
			let handler_copy = unsafe { self.get_app_handler(i, thread_key, cache_ptr) };
			let node = unsafe { (*new_handlers).alloc_node() };

			unsafe {
				(*node).data = handler_copy;
				(*node).next_retired.store(std::ptr::null_mut(), Ordering::Relaxed);
				(*new_handlers).app_handlers[i].store(node, Ordering::Relaxed);
			}
		}

		new_handlers
	}
}
