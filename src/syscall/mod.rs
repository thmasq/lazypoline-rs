//! Syscall-related types and functionality
//!
//! This module contains types and functions for working with system calls,
//! including an enum of all Linux syscalls generated at compile time.

mod raw;
mod table;
mod types;

pub use raw::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
pub use table::{Syscall, syscall_from_number};
pub use types::{SyscallAction, SyscallArgs, SyscallContext};
