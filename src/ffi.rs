//! Foreign function interface for lazypoline
//!
//! This module contains the FFI definitions and bindings needed
//! for syscall interposition.

// Re-export useful constants
pub use self::constants::*;

// Re-export useful types
pub use self::types::*;

// Re-export useful functions
pub use self::functions::*;

// Re-export useful utilities
pub use self::utils::*;

// Constants for syscall interposition
pub mod constants {
	pub use libc::{CLONE_SIGHAND, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SIGCHLD};

	/// Allow syscalls to execute normally
	pub const SYSCALL_DISPATCH_FILTER_ALLOW: u8 = 0;

	/// Block syscalls and deliver SIGSYS
	pub const SYSCALL_DISPATCH_FILTER_BLOCK: u8 = 1;

	/// prctl operation to set syscall user dispatch
	pub const PR_SET_SYSCALL_USER_DISPATCH: libc::c_int = 59;

	/// Disable syscall user dispatch
	pub const PR_SYS_DISPATCH_OFF: libc::c_int = 0;

	/// Enable syscall user dispatch
	pub const PR_SYS_DISPATCH_ON: libc::c_int = 1;

	/// Clone flag for creating a thread with a shared memory space
	pub const CLONE_VM: u64 = 0x0000_0100;

	/// Clone flag for creating a vfork child
	pub const CLONE_VFORK: u64 = 0x0000_4000;

	/// Clone flag for creating a thread
	pub const CLONE_THREAD: u64 = 0x0001_0000;

	// Architecture-specific constants for GS base manipulation
	pub const ARCH_SET_GS: i32 = 0x1001;
	pub const ARCH_GET_GS: i32 = 0x1003;
}

// Types for syscall interposition
pub mod types {
	use std::arch::asm;
	use std::sync::atomic::{AtomicUsize, Ordering};

	/// Represents the signal information structure for SIGSYS signals.
	///
	/// This structure maps to the Linux kernel's `siginfo_t` structure
	/// with the specific fields needed for SIGSYS signal handling.
	#[repr(C)]
	#[derive(Clone, Copy)]
	pub struct SigSysInfo {
		// Standard siginfo_t fields
		pub si_signo: libc::c_int,
		pub si_errno: libc::c_int,
		pub si_code: libc::c_int,
		pub pad: libc::c_int,

		// SIGSYS-specific fields
		pub si_call_addr: *mut libc::c_void, // Address of the syscall instruction
		pub si_syscall: libc::c_int,         // Syscall number
		pub si_arch: libc::c_uint,           // Architecture
	}

	impl SigSysInfo {
		/// Converts a raw `siginfo_t` pointer to a `SigSysInfo` pointer.
		///
		/// # Safety
		///
		/// The caller must ensure:
		/// - The provided pointer is valid and properly aligned
		/// - The pointed memory actually contains a valid `siginfo_t` structure
		/// - The signal is indeed a SIGSYS signal
		pub const unsafe fn from_siginfo(info: *mut libc::siginfo_t) -> *mut Self {
			info.cast::<Self>()
		}
	}

	/// A simple spin lock implementation for synchronization.
	///
	/// This lock uses atomic operations to provide mutual exclusion without
	/// requiring operating system support. It should be used only for short
	/// critical sections as it performs busy waiting.
	pub struct SpinLock {
		owner: AtomicUsize,
	}

	impl Default for SpinLock {
		fn default() -> Self {
			Self::new()
		}
	}

	impl SpinLock {
		/// Creates a new unlocked `SpinLock`.
		///
		/// # Returns
		///
		/// A new `SpinLock` instance initialized in the unlocked state.
		#[must_use]
		pub const fn new() -> Self {
			Self {
				owner: AtomicUsize::new(0),
			}
		}

		/// Acquires the lock, blocking until it can be acquired.
		///
		/// This function will spin (busy-wait) until the lock becomes available.
		/// It implements a pause instruction to reduce CPU contention.
		pub fn lock(&self) {
			// pthread_self() is async-signal-safe and does not issue any syscalls
			let tid = unsafe { libc::pthread_self() } as usize;

			if self.owner.load(Ordering::Relaxed) == tid {
				// If a thread tries to acquire a lock it already owns, it likely
				// bypassed the SpinLockGuard drop (e.g., via longjmp out of a signal handler).
				// We abort here to prevent a silent infinite deadlock loop.
				eprintln!(
					"lazypoline: SpinLock deadlock detected! Thread already owns the lock. Did the application longjmp out of a signal handler?"
				);
				std::process::abort();
			}

			// Attempt to acquire the lock
			while self
				.owner
				.compare_exchange_weak(0, tid, Ordering::Acquire, Ordering::Relaxed)
				.is_err()
			{
				while self.owner.load(Ordering::Relaxed) != 0 {
					unsafe { asm!("pause", options(nomem, nostack)) };
				}
			}
		}

		/// Releases the lock.
		///
		/// # Safety
		///
		/// This method is safe to call, but the caller must ensure they actually
		/// hold the lock before calling. Calling `unlock` on a lock that isn't held
		/// by the current thread will lead to undefined behavior for other threads
		/// trying to acquire the lock and may cause data corruption or deadlocks.
		///
		/// Generally, you should prefer using `SpinLockGuard` instead of manually
		/// calling `lock` and `unlock`.
		pub fn unlock(&self) {
			let tid = unsafe { libc::pthread_self() } as usize;
			let prev = self.owner.swap(0, Ordering::Release);

			if prev != tid && prev != 0 {
				// Lock was released by a thread that didn't acquire it.
				// Restore the original owner and abort.
				self.owner.store(prev, Ordering::Release);
				eprintln!("lazypoline: SpinLock unlocked by a thread that does not own it!");
				std::process::abort();
			}
		}
	}

	/// RAII guard for a `SpinLock`.
	///
	/// When this guard is dropped, the lock will be automatically released.
	/// This helps prevent lock leaks in the case of panics or early returns.
	pub struct SpinLockGuard<'a> {
		lock: &'a SpinLock,
	}

	impl<'a> SpinLockGuard<'a> {
		/// Creates a new guard that acquires the given lock.
		///
		/// # Arguments
		///
		/// * `lock` - The spin lock to acquire
		///
		/// # Returns
		///
		/// A new `SpinLockGuard` that has acquired the lock.
		pub fn new(lock: &'a SpinLock) -> Self {
			lock.lock();
			Self { lock }
		}
	}

	impl Drop for SpinLockGuard<'_> {
		fn drop(&mut self) {
			self.lock.unlock();
		}
	}

	/// A wrapper that ensures its contained value is aligned to a page boundary (4096 bytes).
	///
	/// This is useful for data structures that must be page-aligned for
	/// hardware or operating system requirements.
	#[repr(align(4096))]
	pub struct PageAligned<T>(pub T);

	/// A wrapper that ensures its contained value is aligned to a page boundary (64 bytes).
	///
	/// This is useful for data structures that must be page-aligned for
	/// hardware or operating system requirements.
	#[repr(align(64))]
	pub struct XSaveAligned<T>(pub T);
}

// Functions for syscall interposition
pub mod functions {
	use super::constants::{ARCH_GET_GS, ARCH_SET_GS, PR_SET_SYSCALL_USER_DISPATCH};
	#[allow(unused_imports)]
	use crate::syscall::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall6};
	use libc::{c_int, c_long, c_void, sigset_t, size_t};
	use std::io;
	use tracing::{debug, error};

	/// Configures syscall user dispatch mode.
	///
	/// This function enables or disables the syscall user dispatch feature of the Linux kernel,
	/// which allows for filtering and handling syscalls in user space.
	///
	/// # Arguments
	///
	/// * `action` - `PR_SYS_DISPATCH_ON` to enable, `PR_SYS_DISPATCH_OFF` to disable
	/// * `selector_ptr` - Pointer to a filter array that determines which syscalls to intercept
	///
	/// # Returns
	///
	/// * `Ok(())` on success
	/// * `Err(e)` with the system error on failure
	///
	/// # Errors
	///
	/// Returns an error if the prctl call fails, which could happen if:
	/// - The kernel does not support `PR_SET_SYSCALL_USER_DISPATCH` (EINVAL)
	/// - The arguments are invalid (EINVAL):
	///   - Invalid action (not `PR_SYS_DISPATCH_ON` or `PR_SYS_DISPATCH_OFF`)
	///   - Invalid or inaccessible `selector_ptr`
	/// - Permission is denied (EPERM):
	///   - The process does not have `CAP_SYS_ADMIN` capability
	/// - Resource limits are exceeded (ENOMEM):
	///   - Not enough memory to set up the dispatch tables
	pub fn set_syscall_user_dispatch(action: c_int, selector_ptr: *const u8) -> Result<(), io::Error> {
		debug!(
			"FFI: Calling prctl with PR_SET_SYSCALL_USER_DISPATCH ({PR_SET_SYSCALL_USER_DISPATCH}), action {action}, selector_ptr {selector_ptr:p}"
		);

		let result = unsafe {
			syscall6(
				libc::SYS_prctl as c_long,
				c_long::from(PR_SET_SYSCALL_USER_DISPATCH),
				c_long::from(action),
				0,
				0,
				selector_ptr as c_long,
				0,
			)
		};

		if result == 0 {
			debug!("FFI: prctl succeeded!");
			Ok(())
		} else {
			let err = io::Error::from_raw_os_error(-result as i32);
			error!("FFI: prctl failed with error: {} ({})", err, -result);
			Err(err)
		}
	}

	/// Maps a file or device into memory at a specific address.
	///
	/// This is a thin wrapper around the Linux `mmap` system call.
	///
	/// # Safety
	///
	/// The caller must ensure:
	/// - `addr` is a valid address that can be mapped
	/// - `length` is valid
	/// - `prot` and `flags` are valid combinations
	/// - `fd` is a valid file descriptor if mapping a file
	/// - `offset` is valid
	///
	/// # Returns
	///
	/// Returns a pointer to the mapped memory region, or `MAP_FAILED` on error.
	#[inline]
	pub unsafe fn mmap_at_addr(
		addr: *mut c_void,
		length: size_t,
		prot: c_int,
		flags: c_int,
		fd: c_int,
		offset: i64,
	) -> *mut c_void {
		unsafe {
			let result = syscall6(
				libc::SYS_mmap as c_long,
				addr as c_long,
				length as c_long,
				c_long::from(prot),
				c_long::from(flags),
				c_long::from(fd),
				offset as c_long,
			);
			result as *mut c_void
		}
	}

	/// Changes the protection of a memory region.
	///
	/// This is a thin wrapper around the Linux `mprotect` system call.
	///
	/// # Safety
	///
	/// The caller must ensure:
	/// - `addr` points to a valid memory region that was previously mapped
	/// - `len` is valid
	/// - `prot` contains valid protection flags
	///
	/// # Returns
	///
	/// Returns 0 on success, or a negative error code on failure.
	#[inline]
	pub unsafe fn mprotect_raw(addr: *mut c_void, len: size_t, prot: c_int) -> c_int {
		unsafe {
			syscall3(
				libc::SYS_mprotect as c_long,
				addr as c_long,
				len as c_long,
				c_long::from(prot),
			) as c_int
		}
	}

	/// Retrieves the current GS segment base address.
	///
	/// Uses the `arch_prctl` system call to get the GS segment base register value.
	///
	/// # Safety
	///
	/// This function is unsafe as it makes direct system calls and modifies
	/// processor state.
	///
	/// # Panics
	///
	/// Panics if the system call fails, which should not happen on supported systems.
	///
	/// # Returns
	///
	/// The current GS segment base address.
	#[inline]
	#[must_use]
	pub unsafe fn get_gs_base() -> u64 {
		let mut value: u64 = 0;
		unsafe {
			let result = syscall2(
				libc::SYS_arch_prctl as c_long,
				c_long::from(ARCH_GET_GS),
				&raw mut value as c_long,
			);
			assert_eq!(result, 0, "Failed to get GS base");
			value
		}
	}

	/// Sets the GS segment base address.
	///
	/// Uses the `arch_prctl` system call to set the GS segment base register value.
	///
	/// # Safety
	///
	/// This function is unsafe as it makes direct system calls and modifies
	/// processor state.
	///
	/// # Returns
	///
	/// Returns 0 on success, or a negative error code on failure.
	#[inline]
	#[must_use]
	pub unsafe fn set_gs_base(value: u64) -> c_int {
		unsafe {
			syscall2(
				libc::SYS_arch_prctl as c_long,
				c_long::from(ARCH_SET_GS),
				value as c_long,
			) as c_int
		}
	}

	/// Sets or gets the signal action for a specific signal.
	///
	/// This is a thin wrapper around the Linux `rt_sigaction` system call.
	///
	/// # Safety
	///
	/// The caller must ensure:
	/// - `signum` is a valid signal number
	/// - If `act` is not null, it points to a valid `sigaction` structure
	/// - If `oldact` is not null, it points to memory capable of holding a `sigaction` structure
	///
	/// # Returns
	///
	/// Returns 0 on success, or a negative error code on failure.
	#[inline]
	pub unsafe fn rt_sigaction_raw(
		signum: c_int,
		act: *const libc::sigaction,
		oldact: *mut libc::sigaction,
		sigsetsize: size_t,
	) -> c_int {
		unsafe {
			syscall4(
				libc::SYS_rt_sigaction as c_long,
				c_long::from(signum),
				act as c_long,
				oldact as c_long,
				sigsetsize as c_long,
			) as c_int
		}
	}

	/// Changes the list of currently blocked signals.
	///
	/// This is a thin wrapper around the Linux `rt_sigprocmask` system call.
	///
	/// # Safety
	///
	/// The caller must ensure:
	/// - `how` is a valid operation (`SIG_BLOCK`, `SIG_UNBLOCK`, or `SIG_SETMASK`)
	/// - If `set` is not null, it points to a valid signal set
	/// - If `oldset` is not null, it points to memory capable of holding a signal set
	///
	/// # Returns
	///
	/// Returns 0 on success, or a negative error code on failure.
	#[inline]
	pub unsafe fn rt_sigprocmask_raw(
		how: c_int,
		set: *const sigset_t,
		oldset: *mut sigset_t,
		sigsetsize: size_t,
	) -> c_int {
		unsafe {
			syscall4(
				libc::SYS_rt_sigprocmask as c_long,
				c_long::from(how),
				set as c_long,
				oldset as c_long,
				sigsetsize as c_long,
			) as c_int
		}
	}
}

// Utility functions for memory manipulation
pub mod utils {
	/// Aligns an address downward to the specified alignment.
	///
	/// # Arguments
	///
	/// * `addr` - The address to align
	/// * `align` - The alignment, which must be a power of 2
	///
	/// # Returns
	///
	/// The address aligned down to the nearest multiple of `align`.
	///
	/// # Panics
	///
	/// This function does not panic, but will produce incorrect results if `align` is not a power
	/// of 2.
	#[inline]
	#[must_use]
	pub const fn align_down(addr: usize, align: usize) -> usize {
		debug_assert!(align.is_power_of_two(), "align must be a power of 2");
		addr & !(align - 1)
	}

	/// Aligns an address upward to the specified alignment.
	///
	/// # Arguments
	///
	/// * `addr` - The address to align
	/// * `align` - The alignment, which must be a power of 2
	///
	/// # Returns
	///
	/// The address aligned up to the nearest multiple of `align`.
	///
	/// # Panics
	///
	/// This function does not panic, but will produce incorrect results if `align` is not a power
	/// of 2.
	#[inline]
	#[must_use]
	pub const fn align_up(addr: usize, align: usize) -> usize {
		debug_assert!(align.is_power_of_two(), "align must be a power of 2");
		(addr + align - 1) & !(align - 1)
	}
}

/// Main emulation function
///
/// This is called from the assembly handler when a syscall is intercepted.
/// It is exposed for FFI but should not be called directly by users.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_emulate(
	syscall_no: i64,
	ctx: &mut crate::syscall::SyscallContext,
	should_emulate: *mut u64,
) -> i64 {
	// Debugging - uncomment if needed to trace specific syscalls
	/*
	if syscall_no == libc::SYS_open || syscall_no == libc::SYS_read {
		if ctx.args.rdi != 0 {
			let path = unsafe { std::ffi::CStr::from_ptr(ctx.args.rdi as *const i8) }.to_string_lossy();
			tracing::debug!("syscall_emulate: syscall={}, path={}, args={}, {}, {}, {}, {}",
				syscall_no, path, ctx.args.rdi, ctx.args.rsi, ctx.args.rdx, ctx.args.r10, ctx.args.r8);
		} else {
			tracing::debug!("syscall_emulate: syscall={}, args={}, {}, {}, {}, {}",
				syscall_no, ctx.args.rdi, ctx.args.rsi, ctx.args.rdx, ctx.args.r10, ctx.args.r8);
		}
	}
	*/

	match crate::interposer::get_active_interposer() {
		Some(interposer) => {
			let action = interposer.process_syscall(ctx);

			match action {
				crate::syscall::SyscallAction::Allow => unsafe {
					crate::syscall::syscall6(
						syscall_no,
						ctx.args.rdi as i64,
						ctx.args.rsi as i64,
						ctx.args.rdx as i64,
						ctx.args.r10 as i64,
						ctx.args.r8 as i64,
						ctx.args.r9 as i64,
					)
				},
				crate::syscall::SyscallAction::Block(result) => result,
				crate::syscall::SyscallAction::Emulate => {
					if !should_emulate.is_null() {
						unsafe { *should_emulate = 1 };
					}
					syscall_no
				},
				crate::syscall::SyscallAction::Modify(new_args) => unsafe {
					crate::syscall::syscall6(
						syscall_no,
						new_args.rdi as i64,
						new_args.rsi as i64,
						new_args.rdx as i64,
						new_args.r10 as i64,
						new_args.r8 as i64,
						new_args.r9 as i64,
					)
				},
			}
		},
		None => unsafe {
			crate::syscall::syscall6(
				syscall_no,
				ctx.args.rdi as i64,
				ctx.args.rsi as i64,
				ctx.args.rdx as i64,
				ctx.args.r10 as i64,
				ctx.args.r8 as i64,
				ctx.args.r9 as i64,
			)
		},
	}
}
