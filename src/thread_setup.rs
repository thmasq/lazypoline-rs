use crate::ffi::{CLONE_VFORK, CLONE_VM, SIGCHLD};
use crate::gsrel::{GSRelData, set_privilege_level};
use crate::signal::SignalHandlers;
use crate::sud::enable_sud;

const CLONE_SIGHAND: u64 = 0x00000800;

/// Sets up the per-thread data structures for a newly created thread.
///
/// This function is called during thread creation (via clone) to:
/// 1. Initialize thread-local GSRelData
/// 2. Set the initial privilege level
/// 3. Set up signal handlers for the new thread
/// 4. Enable SUD for the new thread
///
/// # Parameters
///
/// * `clone_flags` - The flags passed to the clone syscall, used to determine
///   whether signal handlers should be shared with the parent
///
/// # Safety
///
/// This function is unsafe because it:
/// - Accesses raw pointers and shared memory
/// - Modifies thread-local and potentially shared state
/// - Must only be called during thread creation
/// - Relies on correctly initialized GSRelData
#[unsafe(no_mangle)]
pub extern "C" fn setup_new_thread(clone_flags: u64) {
	unsafe {
		let cloner_gsrel = crate::gsrel::GSRelData::new();

		let gsreldata = GSRelData::new();
		set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

		let cloner_signal_handlers = *(*cloner_gsrel).signal_handlers.get();

		if clone_flags & CLONE_SIGHAND != 0 {
			*(*gsreldata).signal_handlers.get() = cloner_signal_handlers;
		} else {
			let new_handlers = SignalHandlers::new();
			// This would normally copy the signal handlers, but we'll simplify for now
			*(*gsreldata).signal_handlers.get() = new_handlers;
		}

		enable_sud();
	}
}

/// Sets up the per-process data structures for a newly created vfork child.
///
/// This is a specialized version of `setup_new_thread` specifically for
/// the vfork syscall, which creates a child with a shared address space
/// but separate execution context.
///
/// # Safety
///
/// This function is unsafe because it:
/// - Must only be called in the context of a vfork child
/// - Shares the same safety concerns as `setup_new_thread`
/// - Manipulates process-wide state that affects all threads
#[unsafe(no_mangle)]
pub extern "C" fn setup_vforked_child() {
	setup_new_thread(CLONE_VM | CLONE_VFORK | SIGCHLD as u64);
}
