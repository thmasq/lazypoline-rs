use crate::ffi::{CLONE_THREAD, CLONE_VFORK, CLONE_VM, SYSCALL_DISPATCH_FILTER_BLOCK, syscall6};
use crate::gsrel::set_privilege_level;
use crate::sud::{enable_sud, init_sud};
use crate::zpoline::init_zpoline;
use libc::{CLONE_SIGHAND, SIG_BLOCK, SIG_SETMASK, c_int, c_long};
use std::mem;
use tracing::{debug, error, info};

// Configuration
const PRINT_SYSCALLS: bool = true;
const RETURN_IMMEDIATELY: bool = false;
const REWRITE_TO_ZPOLINE: bool = true;

unsafe extern "C" {
	pub fn handle_clone_thread(a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64;
	pub fn setup_new_thread(clone_flags: u64);
	pub fn setup_vforked_child();
	pub fn teardown_thread_metadata();
}

/// Initializes the lazypoline syscall interposition mechanism.
///
/// This function sets up all the necessary components for syscall interception:
/// 1. Initializes Syscall User Dispatch (SUD)
/// 2. Sets up the zpoline mechanism for efficient syscall handling
/// 3. Enables SUD for the current process
/// 4. Blocks syscalls through the SUD mechanism
///
/// # Panics
///
/// Panics if:
/// - SUD initialization fails
/// - zpoline initialization fails (if `REWRITE_TO_ZPOLINE` is true)
/// - Privilege level cannot be set
///
/// # Safety
///
/// This function is unsafe because it:
/// - Modifies global process state by enabling SUD
/// - Changes memory protection settings
/// - Requires a correct `LD_PRELOAD` and bootstrap setup
/// - Needs `/proc/sys/vm/mmap_min_addr` set to 0
#[unsafe(no_mangle)]
pub extern "C" fn init_lazypoline() {
	crate::logging::init();
	info!("Initializing lazypoline!");

	unsafe {
		debug!("Initializing Syscall User Dispatch (SUD)...");
		init_sud();

		if REWRITE_TO_ZPOLINE {
			debug!("Initializing zpoline mechanism...");
			match init_zpoline() {
				Ok(()) => {
					debug!("zpoline initialization successful");
				},
				Err(e) => {
					error!("Failed to initialize zpoline: {e}");
					std::process::exit(1);
				},
			}
		}

		debug!("Enabling SUD...");
		enable_sud();

		debug!("Setting privilege level to BLOCK...");
		set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);
		debug!("Initialization completed successfully!");
	}
}

/// Emulates or handles a system call based on its number and arguments.
///
/// This function is called from the assembly hook when a syscall is intercepted.
/// It provides custom handling for certain syscalls (fork, clone, vfork, `rt_sigreturn`, etc.)
/// and passes through other syscalls to the kernel.
///
/// # Parameters
///
/// * `syscall_no` - The syscall number
/// * `a1`-`a6` - The syscall arguments
/// * `should_emulate` - Output parameter that indicates whether the syscall should be
///    emulated by the assembly hook (1) or handled directly (0)
///
/// # Returns
///
/// The syscall result or an error code
///
/// # Panics
///
/// Panics if:
/// - An unsupported syscall variant is used (e.g., unshare)
/// - Invalid combinations of clone flags are provided
///
/// # Safety
///
/// This function is unsafe because it:
/// - Directly interacts with kernel syscall interfaces
/// - Manipulates thread and process state
/// - Modifies memory that may be shared between threads
#[unsafe(no_mangle)]
pub extern "C" fn syscall_emulate(
	syscall_no: i64,
	a1: i64,
	mut a2: i64,
	a3: i64,
	a4: i64,
	a5: i64,
	a6: i64,
	should_emulate: *mut u64,
) -> i64 {
	unsafe {
		if RETURN_IMMEDIATELY {
			return 0;
		}

		assert_eq!(*should_emulate, 0);

		if PRINT_SYSCALLS {
			let syscall_name = get_syscall_name(syscall_no as usize);
			debug!(
				"\x1b[31m[{}] syscall({} [{}], 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x})\x1b[m",
				libc::getpid(),
				syscall_name,
				syscall_no,
				a1,
				a2,
				a3,
				a4,
				a5,
				a6
			);
		}

		assert_ne!(syscall_no, { libc::SYS_unshare });

		if syscall_no == libc::SYS_clone3 {
			return i64::from(-libc::ENOSYS);
		}

		if syscall_no == libc::SYS_fork {
			let result = syscall6(syscall_no as c_long, a1, a2, a3, a4, a5, a6);

			do_postfork_handling(result as i64);
			return result as i64;
		}

		if syscall_no == libc::SYS_vfork {
			*should_emulate = 1;
			return libc::SYS_vfork;
		}

		if syscall_no == libc::SYS_clone {
			let flags = a1 as u64;
			let stack = a2 as usize;

			if flags & CLONE_THREAD != 0 {
				assert_ne!(stack, 0, "Stack must be provided for CLONE_THREAD");
				assert_ne!(flags & CLONE_VM, 0, "CLONE_VM must be set with CLONE_THREAD");
				assert_eq!(flags & CLONE_VFORK, 0, "CLONE_VFORK with CLONE_THREAD is weird");

				*should_emulate = 1;
				return libc::SYS_clone;
			} else if flags & CLONE_VFORK != 0 {
				assert_ne!(stack, 0, "Stack must be provided for CLONE_VFORK");
				assert_ne!(flags & CLONE_VM, 0, "CLONE_VM must be set with CLONE_VFORK");
				assert_eq!(flags & CLONE_THREAD, 0, "CLONE_THREAD with CLONE_VFORK is invalid");

				*should_emulate = 1;
				return libc::SYS_clone;
			} else {
				assert_eq!(stack, 0, "Stack must be NULL for fork-like clone");
				assert_eq!(flags & CLONE_THREAD, 0, "CLONE_THREAD not supported");
				assert_eq!(flags & CLONE_SIGHAND as u64, 0, "CLONE_SIGHAND not supported");
				assert_eq!(flags & CLONE_VFORK, 0, "CLONE_VFORK not supported in fork-like clone");
				assert_eq!(flags & CLONE_VM, 0, "CLONE_VM not supported in fork-like clone");

				let result = syscall6(syscall_no as c_long, a1, a2, a3, a4, a5, a6);

				do_postfork_handling(result as i64);
				return result as i64;
			}
		}

		if syscall_no == libc::SYS_rt_sigprocmask {
			let how = a1 as c_int;
			let set = a2 as *const libc::sigset_t;
			let _oldset = a3 as *mut libc::sigset_t;
			let sigsetsize = a4 as usize;

			assert!(sigsetsize <= mem::size_of::<libc::sigset_t>(), "sigsetsize too large");

			let mut modifiable_mask = [0u8; 128];

			if !set.is_null() && (how == SIG_BLOCK || how == SIG_SETMASK) {
				ptr::copy_nonoverlapping(set.cast::<u8>(), modifiable_mask.as_mut_ptr(), sigsetsize);

				let modified_set = modifiable_mask.as_mut_ptr().cast::<libc::sigset_t>();
				libc::sigdelset(modified_set, libc::SIGSYS);
				a2 = modified_set as i64;
			}

			let result = syscall6(syscall_no as c_long, a1, a2, a3, a4, a5, a6);

			return result as i64;
		}

		if syscall_no == libc::SYS_rt_sigaction {
			let gsreldata = gsrel::GSRelData::new();
			let signal_handlers = *(*gsreldata).signal_handlers.get();

			let signum = a1 as c_int;
			let newact = a2 as *const libc::sigaction;
			let oldact = a3 as *mut libc::sigaction;

			let result = (*signal_handlers).handle_app_sigaction(signum, newact, oldact);
			return result;
		}

		if syscall_no == libc::SYS_rt_sigreturn {
			*should_emulate = 1;
			return libc::SYS_rt_sigreturn;
		}

		if syscall_no == libc::SYS_exit {
			teardown_thread_metadata();
		}

		syscall6(syscall_no as c_long, a1, a2, a3, a4, a5, a6) as i64
	}
}

unsafe fn do_postfork_handling(result: i64) {
	if result < 0 {
	} else if result > 0 {
	} else {
		unsafe {
			enable_sud();
		}
	}
}

const fn get_syscall_name(sysno: usize) -> &'static str {
	match sysno {
		0 => "read",
		1 => "write",
		2 => "open",
		3 => "close",
		4 => "stat",
		5 => "fstat",
		6 => "lstat",
		7 => "poll",
		8 => "lseek",
		9 => "mmap",
		10 => "mprotect",
		11 => "munmap",
		12 => "brk",
		13 => "rt_sigaction",
		14 => "rt_sigprocmask",
		15 => "rt_sigreturn",
		56 => "clone",
		57 => "fork",
		58 => "vfork",
		59 => "execve",
		60 => "exit",
		// ...
		_ => "unknown",
	}
}

use crate::gsrel;
use std::ptr;
