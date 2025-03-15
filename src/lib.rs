//! Lazypoline - A fast, exhaustive, and expressive syscall interposer for user-space Linux applications.
//!
//! This library implements a syscall interposition mechanism using Syscall User Dispatch (SUD)
//! and binary rewriting for exhaustive syscall interception with maximum efficiency.
//!
//! # Usage
//!
//! Build this library as a cdylib and load it using LD_PRELOAD:
//!
//! ```bash
//! LIBLAZYPOLINE="path/to/liblazypoline.so" LD_PRELOAD="path/to/libbootstrap.so" your_application
//! ```
//!
//! Note: You need to have `/proc/sys/vm/mmap_min_addr` set to 0 for this to work.

#![allow(unused_unsafe)]
#![allow(non_upper_case_globals)]

pub mod ffi;
pub mod gsrel;
pub mod lazypoline;
pub mod signal;
pub mod sud;
pub mod thread_setup;
pub mod zpoline;

#[cfg(target_arch = "x86_64")]
mod asm;

pub use lazypoline::init_lazypoline;
pub use lazypoline::syscall_emulate;

#[unsafe(no_mangle)]
pub extern "C" fn bootstrap_lazypoline() {
	lazypoline::init_lazypoline();
}

#[cfg(test)]
mod tests {
	#[allow(unused_imports)]
	use super::*;

	#[test]
	fn test_initialization() {
		// This test is more of a placeholder - actual testing would involve
		// running a real program with lazypoline loaded
		// Real testing is done with the executable in the C++ version
	}
}
