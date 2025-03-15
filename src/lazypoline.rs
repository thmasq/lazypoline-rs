use crate::ffi::{CLONE_THREAD, CLONE_VFORK, CLONE_VM, SYSCALL_DISPATCH_FILTER_BLOCK, syscall6};
use crate::gsrel::set_privilege_level;
use crate::sud::{enable_sud, init_sud};
use crate::zpoline::init_zpoline;
use libc::{CLONE_SIGHAND, SIG_BLOCK, SIG_SETMASK, c_int, c_long};
use std::mem;

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

#[unsafe(no_mangle)]
pub extern "C" fn init_lazypoline() {
	eprintln!("Initializing lazypoline!");

	unsafe {
		eprintln!("lazypoline: Initializing Syscall User Dispatch (SUD)...");
		init_sud();

		if REWRITE_TO_ZPOLINE {
			eprintln!("lazypoline: Initializing zpoline mechanism...");
			match init_zpoline() {
				Ok(_) => {
					eprintln!("lazypoline: zpoline initialization successful");
				},
				Err(e) => {
					eprintln!("lazypoline: Failed to initialize zpoline: {}", e);
					std::process::exit(1);
				},
			}
		}

		eprintln!("lazypoline: Enabling SUD...");
		enable_sud();

		eprintln!("lazypoline: Setting privilege level to BLOCK...");
		set_privilege_level(SYSCALL_DISPATCH_FILTER_BLOCK);
		eprintln!("lazypoline: Initialization completed successfully!");
	}
}

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
			eprintln!(
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

		assert_ne!(syscall_no, libc::SYS_unshare as i64);

		if syscall_no == libc::SYS_clone3 as i64 {
			return -libc::ENOSYS as i64;
		}

		if syscall_no == libc::SYS_fork as i64 {
			let result = syscall6(syscall_no as c_long, a1, a2, a3, a4, a5, a6);

			do_postfork_handling(result as i64);
			return result as i64;
		}

		if syscall_no == libc::SYS_vfork as i64 {
			*should_emulate = 1;
			return libc::SYS_vfork as i64;
		}

		if syscall_no == libc::SYS_clone as i64 {
			let flags = a1 as u64;
			let stack = a2 as usize;

			if flags & CLONE_THREAD != 0 {
				assert_ne!(stack, 0, "Stack must be provided for CLONE_THREAD");
				assert_ne!(flags & CLONE_VM, 0, "CLONE_VM must be set with CLONE_THREAD");
				assert_eq!(flags & CLONE_VFORK, 0, "CLONE_VFORK with CLONE_THREAD is weird");

				*should_emulate = 1;
				return libc::SYS_clone as i64;
			} else if flags & CLONE_VFORK != 0 {
				assert_ne!(stack, 0, "Stack must be provided for CLONE_VFORK");
				assert_ne!(flags & CLONE_VM, 0, "CLONE_VM must be set with CLONE_VFORK");
				assert_eq!(flags & CLONE_THREAD, 0, "CLONE_THREAD with CLONE_VFORK is invalid");

				*should_emulate = 1;
				return libc::SYS_clone as i64;
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

		if syscall_no == libc::SYS_rt_sigprocmask as i64 {
			let how = a1 as c_int;
			let set = a2 as *const libc::sigset_t;
			let _oldset = a3 as *mut libc::sigset_t;
			let sigsetsize = a4 as usize;

			assert!(sigsetsize <= mem::size_of::<libc::sigset_t>(), "sigsetsize too large");

			let mut modifiable_mask = [0u8; 128];

			if !set.is_null() && (how == SIG_BLOCK || how == SIG_SETMASK) {
				ptr::copy_nonoverlapping(set as *const u8, modifiable_mask.as_mut_ptr(), sigsetsize);

				let modified_set = modifiable_mask.as_mut_ptr() as *mut libc::sigset_t;
				libc::sigdelset(modified_set, libc::SIGSYS);
				a2 = modified_set as i64;
			}

			let result = syscall6(syscall_no as c_long, a1, a2, a3, a4, a5, a6);

			return result as i64;
		}

		if syscall_no == libc::SYS_rt_sigaction as i64 {
			let gsreldata = gsrel::GSRelData::new();
			let signal_handlers = *(*gsreldata).signal_handlers.get();

			let signum = a1 as c_int;
			let newact = a2 as *const libc::sigaction;
			let oldact = a3 as *mut libc::sigaction;

			let result = (*signal_handlers).handle_app_sigaction(signum, newact, oldact);
			return result;
		}

		if syscall_no == libc::SYS_rt_sigreturn as i64 {
			*should_emulate = 1;
			return libc::SYS_rt_sigreturn as i64;
		}

		if syscall_no == libc::SYS_exit as i64 {
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

fn get_syscall_name(sysno: usize) -> &'static str {
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
