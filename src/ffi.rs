use libc::{c_int, c_long, sigset_t, size_t};
use std::arch::asm;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error};

pub const SYSCALL_DISPATCH_FILTER_ALLOW: u8 = 0;
pub const SYSCALL_DISPATCH_FILTER_BLOCK: u8 = 1;

pub const PR_SET_SYSCALL_USER_DISPATCH: c_int = 59;
pub const PR_SYS_DISPATCH_OFF: c_int = 0;
pub const PR_SYS_DISPATCH_ON: c_int = 1;

pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_VFORK: u64 = 0x0000_4000;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const SIGCHLD: c_int = 17;

const ARCH_SET_GS: i32 = 0x1001;
const ARCH_GET_GS: i32 = 0x1003;

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

/// Performs a direct system call with six arguments.
///
/// This is a low-level function that directly invokes a Linux system call
/// using the `x86_64` `syscall` instruction.
///
/// # Safety
///
/// The caller must ensure:
/// - The system call number is valid
/// - The arguments are appropriate for the system call
/// - All pointer arguments point to valid memory
///
/// # Returns
///
/// Returns the system call's return value. Negative values typically indicate errors.
#[inline(always)]
#[must_use]
pub unsafe fn syscall6(
	num: c_long,
	arg1: c_long,
	arg2: c_long,
	arg3: c_long,
	arg4: c_long,
	arg5: c_long,
	arg6: c_long,
) -> c_long {
	let mut ret: c_long;
	unsafe {
		asm!(
			"syscall",
			inlateout("rax") num => ret,
			in("rdi") arg1,
			in("rsi") arg2,
			in("rdx") arg3,
			in("r10") arg4,
			in("r8") arg5,
			in("r9") arg6,
			lateout("rcx") _,
			lateout("r11") _,
			options(nostack)
		);
	}
	ret
}

/// A simple spin lock implementation for synchronization.
///
/// This lock uses atomic operations to provide mutual exclusion without
/// requiring operating system support. It should be used only for short
/// critical sections as it performs busy waiting.
pub struct SpinLock {
	lock: AtomicBool,
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
			lock: AtomicBool::new(false),
		}
	}

	/// Acquires the lock, blocking until it can be acquired.
	///
	/// This function will spin (busy-wait) until the lock becomes available.
	/// It implements a pause instruction to reduce CPU contention.
	pub fn lock(&self) {
		while self.lock.swap(true, Ordering::Acquire) {
			while self.lock.load(Ordering::Relaxed) {
				unsafe { asm!("pause", options(nomem, nostack)) };
			}
		}
	}

	/// Releases the lock.
	///
	/// # Safety
	///
	/// This method is safe to call, but the caller should ensure they actually
	/// hold the lock before calling. Calling `unlock` on a lock that isn't held
	/// may lead to undefined behavior for other threads trying to acquire the lock.
	pub fn unlock(&self) {
		self.lock.store(false, Ordering::Release);
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
			prot as c_long,
			flags as c_long,
			fd as c_long,
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
		syscall6(
			libc::SYS_mprotect as c_long,
			addr as c_long,
			len as c_long,
			prot as c_long,
			0,
			0,
			0,
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
		let result = syscall6(
			libc::SYS_arch_prctl as c_long,
			ARCH_GET_GS as c_long,
			&raw mut value as c_long,
			0,
			0,
			0,
			0,
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
		syscall6(
			libc::SYS_arch_prctl as c_long,
			ARCH_SET_GS as c_long,
			value as c_long,
			0,
			0,
			0,
			0,
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
		syscall6(
			libc::SYS_rt_sigaction as c_long,
			signum as c_long,
			act as c_long,
			oldact as c_long,
			sigsetsize as c_long,
			0,
			0,
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
pub unsafe fn rt_sigprocmask_raw(how: c_int, set: *const sigset_t, oldset: *mut sigset_t, sigsetsize: size_t) -> c_int {
	unsafe {
		syscall6(
			libc::SYS_rt_sigprocmask as c_long,
			how as c_long,
			set as c_long,
			oldset as c_long,
			sigsetsize as c_long,
			0,
			0,
		) as c_int
	}
}

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
/// This function does not panic, but will produce incorrect results if `align` is not a power of 2.
#[inline]
#[must_use]
pub const fn align_down(addr: usize, align: usize) -> usize {
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
/// This function does not panic, but will produce incorrect results if `align` is not a power of 2.
#[inline]
#[must_use]
pub const fn align_up(addr: usize, align: usize) -> usize {
	(addr + align - 1) & !(align - 1)
}

/// Represents the arguments to a system call on `x86_64`.
///
/// This structure maps the registers used for passing arguments to system calls
/// on the `x86_64` architecture.
#[repr(C)]
pub struct SyscallArgs {
	pub rdi: u64,
	pub rsi: u64,
	pub rdx: u64,
	pub r10: u64,
	pub r8: u64,
	pub r9: u64,
	pub rax: u64,
}

/// A wrapper that ensures its contained value is aligned to a page boundary (4096 bytes).
///
/// This is useful for data structures that must be page-aligned for
/// hardware or operating system requirements.
#[repr(align(4096))]
pub struct PageAligned<T>(pub T);

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
/// - The kernel does not support `PR_SET_SYSCALL_USER_DISPATCH`
/// - The arguments are invalid
/// - Permission is denied
pub fn set_syscall_user_dispatch(action: c_int, selector_ptr: *const u8) -> Result<(), std::io::Error> {
	debug!(
		"FFI: Calling prctl with PR_SET_SYSCALL_USER_DISPATCH ({PR_SET_SYSCALL_USER_DISPATCH}), action {action}, selector_ptr {selector_ptr:p}"
	);

	let result = unsafe {
		syscall6(
			libc::SYS_prctl as c_long,
			PR_SET_SYSCALL_USER_DISPATCH as c_long,
			action as c_long,
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
		let err = std::io::Error::from_raw_os_error(-result as i32);
		error!("FFI: prctl failed with error: {} ({})", err, -result);
		Err(err)
	}
}
