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

pub const CLONE_VM: u64 = 0x00000100;
pub const CLONE_VFORK: u64 = 0x00004000;
pub const CLONE_THREAD: u64 = 0x00010000;
pub const SIGCHLD: c_int = 17;

const ARCH_SET_GS: i32 = 0x1001;
const ARCH_GET_GS: i32 = 0x1003;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigSysInfo {
	// Standard siginfo_t fields
	pub si_signo: libc::c_int,
	pub si_errno: libc::c_int,
	pub si_code: libc::c_int,
	pub _pad: libc::c_int,

	// SIGSYS-specific fields
	pub si_call_addr: *mut libc::c_void, // Address of the syscall instruction
	pub si_syscall: libc::c_int,         // Syscall number
	pub si_arch: libc::c_uint,           // Architecture
}

impl SigSysInfo {
	pub const unsafe fn from_siginfo(info: *mut libc::siginfo_t) -> *mut Self {
		info.cast::<Self>()
	}
}

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

pub struct SpinLock {
	lock: AtomicBool,
}

impl Default for SpinLock {
	fn default() -> Self {
		Self::new()
	}
}

impl SpinLock {
	#[must_use]
	pub const fn new() -> Self {
		Self {
			lock: AtomicBool::new(false),
		}
	}

	pub fn lock(&self) {
		while self.lock.swap(true, Ordering::Acquire) {
			while self.lock.load(Ordering::Relaxed) {
				unsafe { asm!("pause", options(nomem, nostack)) };
			}
		}
	}

	pub fn unlock(&self) {
		self.lock.store(false, Ordering::Release);
	}
}

pub struct SpinLockGuard<'a> {
	lock: &'a SpinLock,
}

impl<'a> SpinLockGuard<'a> {
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

#[inline]
#[must_use]
pub const fn align_down(addr: usize, align: usize) -> usize {
	addr & !(align - 1)
}

#[inline]
#[must_use]
pub const fn align_up(addr: usize, align: usize) -> usize {
	(addr + align - 1) & !(align - 1)
}

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

#[repr(align(4096))]
pub struct PageAligned<T>(pub T);

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
