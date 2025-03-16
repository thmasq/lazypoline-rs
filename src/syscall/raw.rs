//! Raw syscall interface
//!
//! This module provides functions for making raw system calls
//! directly using the `syscall` instruction.

use libc::c_long;
use std::arch::asm;

/// Make a system call with no arguments
///
/// # Safety
///
/// This function is unsafe because it makes a raw system call.
/// The caller must ensure that the system call number is valid
/// and that any memory passed to the kernel is valid.
#[inline]
#[must_use] pub unsafe fn syscall0(num: c_long) -> c_long {
	let mut ret: c_long;
	unsafe {
		asm!(
			"syscall",
			inlateout("rax") num => ret,
			out("rcx") _,
			out("r11") _,
			options(nostack)
		);
	}
	ret
}

/// Make a system call with one argument
///
/// # Safety
///
/// This function is unsafe because it makes a raw system call.
/// The caller must ensure that the system call number is valid
/// and that any memory passed to the kernel is valid.
#[inline]
#[must_use] pub unsafe fn syscall1(num: c_long, arg1: c_long) -> c_long {
	let mut ret: c_long;
	unsafe {
		asm!(
			"syscall",
			inlateout("rax") num => ret,
			in("rdi") arg1,
			out("rcx") _,
			out("r11") _,
			options(nostack)
		);
	}
	ret
}

/// Make a system call with two arguments
///
/// # Safety
///
/// This function is unsafe because it makes a raw system call.
/// The caller must ensure that the system call number is valid
/// and that any memory passed to the kernel is valid.
#[inline]
#[must_use] pub unsafe fn syscall2(num: c_long, arg1: c_long, arg2: c_long) -> c_long {
	let mut ret: c_long;
	unsafe {
		asm!(
			"syscall",
			inlateout("rax") num => ret,
			in("rdi") arg1,
			in("rsi") arg2,
			out("rcx") _,
			out("r11") _,
			options(nostack)
		);
	}
	ret
}

/// Make a system call with three arguments
///
/// # Safety
///
/// This function is unsafe because it makes a raw system call.
/// The caller must ensure that the system call number is valid
/// and that any memory passed to the kernel is valid.
#[inline]
#[must_use] pub unsafe fn syscall3(num: c_long, arg1: c_long, arg2: c_long, arg3: c_long) -> c_long {
	let mut ret: c_long;
	unsafe {
		asm!(
			"syscall",
			inlateout("rax") num => ret,
			in("rdi") arg1,
			in("rsi") arg2,
			in("rdx") arg3,
			out("rcx") _,
			out("r11") _,
			options(nostack)
		);
	}
	ret
}

/// Make a system call with four arguments
///
/// # Safety
///
/// This function is unsafe because it makes a raw system call.
/// The caller must ensure that the system call number is valid
/// and that any memory passed to the kernel is valid.
#[inline]
#[must_use] pub unsafe fn syscall4(num: c_long, arg1: c_long, arg2: c_long, arg3: c_long, arg4: c_long) -> c_long {
	let mut ret: c_long;
	unsafe {
		asm!(
			"syscall",
			inlateout("rax") num => ret,
			in("rdi") arg1,
			in("rsi") arg2,
			in("rdx") arg3,
			in("r10") arg4,
			out("rcx") _,
			out("r11") _,
			options(nostack)
		);
	}
	ret
}

/// Make a system call with five arguments
///
/// # Safety
///
/// This function is unsafe because it makes a raw system call.
/// The caller must ensure that the system call number is valid
/// and that any memory passed to the kernel is valid.
#[inline]
#[must_use] pub unsafe fn syscall5(num: c_long, arg1: c_long, arg2: c_long, arg3: c_long, arg4: c_long, arg5: c_long) -> c_long {
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
			out("rcx") _,
			out("r11") _,
			options(nostack)
		);
	}
	ret
}

/// Make a system call with six arguments
///
/// # Safety
///
/// This function is unsafe because it makes a raw system call.
/// The caller must ensure that the system call number is valid
/// and that any memory passed to the kernel is valid.
#[inline]
#[must_use] pub unsafe fn syscall6(
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
			out("rcx") _,
			out("r11") _,
			options(nostack)
		);
	}
	ret
}
