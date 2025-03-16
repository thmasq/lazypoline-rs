//! Types for working with syscalls
//!
//! This module contains the core types used to represent syscalls,
//! their arguments, and actions to take when handling them.

use crate::syscall::Syscall;

/// Context for a system call
#[derive(Debug)]
pub struct SyscallContext {
	/// The system call number
	pub syscall: Syscall,
	/// The system call arguments
	pub args: SyscallArgs,
	/// Original instruction pointer
	pub rip: u64,
	/// Whether the syscall should be emulated
	pub should_emulate: bool,
}

/// Syscall arguments
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
	/// First argument (RDI)
	pub rdi: u64,
	/// Second argument (RSI)
	pub rsi: u64,
	/// Third argument (RDX)
	pub rdx: u64,
	/// Fourth argument (R10)
	pub r10: u64,
	/// Fifth argument (R8)
	pub r8: u64,
	/// Sixth argument (R9)
	pub r9: u64,
}

impl SyscallArgs {
	/// Create a new `SyscallArgs` struct from individual arguments
	#[must_use] pub const fn new(rdi: u64, rsi: u64, rdx: u64, r10: u64, r8: u64, r9: u64) -> Self {
		Self {
			rdi,
			rsi,
			rdx,
			r10,
			r8,
			r9,
		}
	}

	/// Get a specific argument by index (0-5)
	#[must_use] pub const fn get(&self, index: usize) -> Option<u64> {
		match index {
			0 => Some(self.rdi),
			1 => Some(self.rsi),
			2 => Some(self.rdx),
			3 => Some(self.r10),
			4 => Some(self.r8),
			5 => Some(self.r9),
			_ => None,
		}
	}

	/// Set a specific argument by index (0-5)
	pub const fn set(&mut self, index: usize, value: u64) -> Result<(), &'static str> {
		match index {
			0 => {
				self.rdi = value;
				Ok(())
			},
			1 => {
				self.rsi = value;
				Ok(())
			},
			2 => {
				self.rdx = value;
				Ok(())
			},
			3 => {
				self.r10 = value;
				Ok(())
			},
			4 => {
				self.r8 = value;
				Ok(())
			},
			5 => {
				self.r9 = value;
				Ok(())
			},
			_ => Err("Invalid argument index"),
		}
	}
}

/// Action to take after handling a system call
#[derive(Debug, Clone, Copy)]
pub enum SyscallAction {
	/// Allow the system call to proceed normally
	Allow,
	/// Block the system call and return the specified value
	Block(i64),
	/// Emulate the system call
	Emulate,
	/// Modify the system call arguments and allow
	Modify(SyscallArgs),
}
