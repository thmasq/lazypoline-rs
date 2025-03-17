//! lazypoline-rs - A framework for building syscall interposers
//!
//! This framework provides tools for intercepting and handling system calls
//! in user-space Linux applications using Syscall User Dispatch (SUD)
//! and binary rewriting for maximum efficiency.
//!
//! # Getting Started
//!
//! ```rust
//! use lazypoline::{self, syscall, SyscallContext, SyscallAction};
//!
//! #[lazypoline::syscall_handler]
//! fn handle_open(ctx: &mut SyscallContext) -> SyscallAction {
//!     println!("Open syscall: {}", unsafe { std::ffi::CStr::from_ptr(ctx.args.rdi as *const i8).to_string_lossy() });
//!     SyscallAction::Allow
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the interposer
//!     let interposer = lazypoline::new()
//!         .handler(handle_open())
//!         .trace(true)
//!         .build()?
//!         .init()?;
//!
//!     // Your application code here
//!     
//!     // The interposer is automatically cleaned up when dropped
//!     Ok(())
//! }
//! ```

pub mod core;
pub mod ffi;
pub mod interposer;
pub mod syscall;
pub mod util;

pub use lazypoline_macros::{syscall_enum, syscall_handler};

pub use crate::interposer::SyscallHandler;
pub use interposer::{Interposer, InterposerBuilder, InterposerError};
pub use syscall::{Syscall, SyscallAction, SyscallArgs, SyscallContext};

/// Create a new interposer builder
#[must_use]
pub fn new() -> InterposerBuilder {
	InterposerBuilder::new()
}

/// Initialize lazypoline with default settings
///
/// This is equivalent to `new().build().init()`
pub fn init() -> Result<Interposer, InterposerError> {
	new().build()?.init()
}

/// Shorthand for setting up a simple syscall tracer
pub fn trace() -> Result<Interposer, InterposerError> {
	new().trace(true).build()?.init()
}
