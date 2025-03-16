//! Syscall handler traits and implementations
//!
//! This module contains the `SyscallHandler` trait and default
//! implementations for common handlers.

use crate::syscall::{SyscallAction, SyscallContext};
use tracing::debug;

/// Trait for handling system calls
pub trait SyscallHandler: Send + Sync {
	/// Handle a system call
	///
	/// This method is called for each system call that is intercepted.
	/// It should examine the syscall context and return an action to take.
	fn handle_syscall(&self, ctx: &mut SyscallContext) -> SyscallAction;

	/// Get the name of the handler
	///
	/// This is used for debugging and logging purposes.
	fn name(&self) -> &'static str {
		std::any::type_name::<Self>()
	}

	fn clone_box(&self) -> Box<dyn SyscallHandler>;
}

/// Default syscall handler that allows all syscalls
#[derive(Debug, Default)]
pub struct DefaultHandler;

impl DefaultHandler {
	/// Create a new `DefaultHandler`
	#[must_use]
	pub const fn new() -> Self {
		Self
	}
}

impl SyscallHandler for DefaultHandler {
	fn handle_syscall(&self, _ctx: &mut SyscallContext) -> SyscallAction {
		SyscallAction::Allow
	}

	fn name(&self) -> &'static str {
		"DefaultHandler"
	}

	fn clone_box(&self) -> Box<dyn SyscallHandler> {
		Box::new(Self::new())
	}
}

/// Handler that traces all syscalls
#[derive(Debug, Default)]
pub struct TracingHandler;

impl TracingHandler {
	/// Create a new `TracingHandler`
	#[must_use]
	pub const fn new() -> Self {
		Self
	}
}

impl SyscallHandler for TracingHandler {
	fn handle_syscall(&self, ctx: &mut SyscallContext) -> SyscallAction {
		debug!(
			"Syscall: {} ({}), Args: 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}",
			ctx.syscall.name(),
			ctx.syscall.number(),
			ctx.args.rdi,
			ctx.args.rsi,
			ctx.args.rdx,
			ctx.args.r10,
			ctx.args.r8,
			ctx.args.r9
		);

		SyscallAction::Allow
	}

	fn name(&self) -> &'static str {
		"TracingHandler"
	}

	fn clone_box(&self) -> Box<dyn SyscallHandler> {
		Box::new(Self::new())
	}
}

impl Clone for Box<dyn SyscallHandler> {
	fn clone(&self) -> Self {
		self.clone_box()
	}
}
