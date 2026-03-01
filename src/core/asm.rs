//! Assembly-related functions and bindings
//!
//! This module contains functions that are called from assembly code,
//! particularly for handling thread creation and syscall interposition.

use crate::core::gsrel::{GSRelData, set_privilege_level};
use crate::core::signal::SignalHandlers;
use crate::core::thread_registry;
use crate::ffi::{CLONE_SIGHAND, CLONE_THREAD, CLONE_VFORK, SYSCALL_DISPATCH_FILTER_BLOCK};
use crate::interposer::get_active_interposer;
use libc::{self};
use tracing::{debug, error, trace, warn};

#[allow(dead_code)]
unsafe extern "C" {
	// These functions are implemented in assembly (asm_syscall_hook.s)
	pub fn asm_syscall_hook();
	pub fn restore_selector_trampoline();
}

/// Sets up a new thread's syscall interposition state
///
/// This function is called from assembly when a new thread is created via `clone()`.
/// It initializes the thread-local storage and state needed for syscall interposition.
///
/// # Parameters
///
/// * `clone_flags` - The flags passed to the clone syscall
///
/// # Safety
///
/// This function is unsafe because it:
/// - Is called directly from assembly
/// - Initializes low-level thread state
/// - Manipulates processor registers
#[unsafe(no_mangle)]
pub extern "C" fn setup_new_thread(clone_flags: u64) {
	debug!("Setting up new thread with clone_flags: 0x{:x}", clone_flags);

	// Initialize thread-local storage (GSRelData)
	let gsreldata = unsafe { GSRelData::new() };
	if gsreldata.is_null() {
		error!("Failed to allocate GSRelData for new thread");
		return;
	}

	trace!("GSRelData allocated at {:p}", gsreldata);

	// Set the initial thread privilege level (blocked by default for safety)
	set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);

	// Check if this is a thread vs a process
	let is_thread = (clone_flags & CLONE_THREAD) != 0;
	let shares_sighandlers = (clone_flags & CLONE_SIGHAND as u64) != 0;

	// Register with the thread registry
	let _thread_info = thread_registry::registry().register_child_thread(gsreldata, clone_flags);

	if is_thread {
		// For threads, initialize signal handlers
		if shares_sighandlers {
			// If CLONE_SIGHAND was specified, the thread shares signal handlers
			// with its parent. We need to get the parent's signal handlers.
			debug!("Thread shares signal handlers with parent");

			// Get the parent's signal handlers from the registry
			let parent_gsreldata = thread_registry::registry().get_current_parent_gsreldata();

			if parent_gsreldata.is_null() {
				// Fall back to creating new signal handlers
				warn!("Could not get parent's GSRelData, creating new signal handlers");
				let signal_handlers = unsafe { SignalHandlers::new() };
				if !signal_handlers.is_null() {
					unsafe { *(*gsreldata).signal_handlers.get() = signal_handlers };
					trace!("Created new signal handlers at {:p}", signal_handlers);
				}
			} else {
				unsafe {
					let parent_signal_handlers = *(*parent_gsreldata).signal_handlers.get();
					*(*gsreldata).signal_handlers.get() = parent_signal_handlers;
					trace!("Copied parent signal handlers: {:p}", parent_signal_handlers);
				}
			}
		} else {
			// If CLONE_SIGHAND was not specified, the thread gets its own copy
			// of the signal handlers. Create new signal handlers.
			debug!("Thread gets its own signal handlers");
			let signal_handlers = unsafe { SignalHandlers::new() };
			if !signal_handlers.is_null() {
				unsafe { *(*gsreldata).signal_handlers.get() = signal_handlers };
				trace!("Created new signal handlers at {:p}", signal_handlers);
			}
		}
	}

	// Register with the active interposer
	if get_active_interposer().is_some() {
		debug!("Registered new thread with active interposer");
		// The interposer could maintain thread-specific state or counters
		// if needed for more advanced interposer functionality
	}

	thread_registry::registry().print_summary();
	debug!("New thread setup complete");
}

/// Sets up a vforked child process's syscall interposition state
///
/// This function is called from assembly when a new process is created via `vfork()`.
/// `vfork()` is special because the child shares the parent's address space until `exec()`
/// is called, so we need to be careful about what state we modify.
///
/// # Safety
///
/// This function is unsafe because it:
/// - Is called directly from assembly
/// - Initializes low-level process state
/// - Manipulates processor registers
#[unsafe(no_mangle)]
pub extern "C" fn setup_vforked_child() {
	debug!("Setting up vforked child process");

	// Initialize thread-local storage (GSRelData)
	let gsreldata = unsafe { GSRelData::new() };
	if gsreldata.is_null() {
		error!("Failed to allocate GSRelData for vforked child");
		return;
	}

	trace!("GSRelData allocated at {:p}", gsreldata);

	// Set the initial privilege level (blocked by default for safety)
	set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);

	// Register with the thread registry as a vfork child
	let _thread_info = thread_registry::registry().register_child_thread(gsreldata, CLONE_VFORK);

	// For vfork, we need to be careful about what we share with the parent
	// The child process shares the parent's memory until it calls exec() or _exit()

	// Initialize signal handlers (these need to be separate from the parent)
	let signal_handlers = unsafe { SignalHandlers::new() };
	if !signal_handlers.is_null() {
		unsafe { *(*gsreldata).signal_handlers.get() = signal_handlers };
		trace!("Created new signal handlers at {:p}", signal_handlers);
	}

	// Register with the active interposer
	if get_active_interposer().is_some() {
		debug!("Registered vforked child with active interposer");
		// Interposer could track vforked children specially if needed
	}

	thread_registry::registry().print_summary();
	debug!("Vforked child setup complete");
}

/// Cleans up thread-local metadata when a thread exits
///
/// This function performs cleanup of thread-local resources when a thread
/// is terminating. It ensures that all resources are properly released.
///
/// # Safety
///
/// This function is unsafe because it:
/// - Disables SUD protection
/// - Unmaps memory
/// - Modifies processor state
#[unsafe(no_mangle)]
pub extern "C" fn teardown_thread_metadata() {
	debug!("Tearing down thread metadata");

	let registry = thread_registry::registry();

	let owns_signal_handlers = registry
		.get_current_thread_info()
		.map(|info| !info.shares_signal_handlers())
		.unwrap_or(false);

	// Unregister from the thread registry
	registry.unregister_current_thread();

	// Disable SUD for this thread to allow syscalls during cleanup
	let result = unsafe {
		crate::syscall::syscall6(
			libc::SYS_prctl,
			i64::from(crate::ffi::PR_SET_SYSCALL_USER_DISPATCH),
			i64::from(crate::ffi::PR_SYS_DISPATCH_OFF),
			0,
			0,
			0,
			0,
		)
	};

	if result != 0 {
		error!("Failed to disable SUD during teardown: {}", result);
	}

	// Get the GS base for this thread
	let gs_base = unsafe { crate::ffi::get_gs_base() };

	// Clean up signal handlers
	if gs_base != 0 {
		let gsreldata = gs_base as *mut GSRelData;
		let signal_handlers = unsafe { *(*gsreldata).signal_handlers.get() };

		if !signal_handlers.is_null() {
			trace!("Cleaning up signal handlers at {:p}", signal_handlers);

			if owns_signal_handlers {
				unsafe { libc::free(signal_handlers.cast::<libc::c_void>()) };
			}
		}
	}

	// Unmap GSRelData
	if gs_base != 0 {
		let result = unsafe {
			crate::syscall::syscall6(
				libc::SYS_munmap,
				gs_base as i64,
				4096, // Page size
				0,
				0,
				0,
				0,
			)
		};

		if result != 0 {
			error!("Failed to unmap GSRelData during teardown: {}", result);
		} else {
			trace!("Unmapped GSRelData at address 0x{:x}", gs_base);
		}
	}

	thread_registry::registry().print_summary();
	debug!("Thread metadata teardown complete");
}

/// Handles the clone syscall for thread creation
///
/// This function is called to handle clone syscalls. It provides a hook
/// for interposer implementations to modify thread creation behavior.
///
/// # Parameters
///
/// * `a1`-`a6` - The arguments to the clone syscall
///
/// # Returns
///
/// The result of the syscall, typically the thread ID or -1 on error
///
/// # Safety
///
/// This function is unsafe because it:
/// - Makes raw syscalls
/// - Manipulates thread state
#[unsafe(no_mangle)]
pub extern "C" fn handle_clone_thread(a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
	trace!("Handling clone syscall with flags: 0x{:x}", a1);

	// Check if this is a thread or vfork
	let is_thread = (a1 as u64 & CLONE_THREAD) != 0;
	let is_vfork = (a1 as u64 & CLONE_VFORK) != 0;

	if is_thread {
		debug!("Creating new thread with clone()");
	} else if is_vfork {
		debug!("Creating vforked child with clone()");
	} else {
		debug!("Creating new process with clone()");
	}

	// Allow interposers to modify or block the clone
	if get_active_interposer().is_some() {
		debug!("Forwarding clone syscall to kernel");
		// In a full implementation, the interposer could:
		// 1. Modify the clone flags
		// 2. Block certain types of threads
		// 3. Implement thread quotas or limits
		// 4. Add additional instrumentation
	}

	// Perform the actual clone syscall
	let result = unsafe { crate::syscall::syscall6(libc::SYS_clone, a1, a2, a3, a4, a5, a6) };

	#[allow(clippy::comparison_chain)]
	if result == 0 {
		// This is the child process/thread
		debug!("In child context after clone (tid=0)");
		// Nothing to do here - setup will be handled by setup_new_thread
	} else if result > 0 {
		// This is the parent process, child's TID is in result
		debug!("Clone succeeded in parent context, child tid={}", result);
	} else {
		// Error occurred
		error!("Clone failed with error: {}", result);
	}

	result
}
