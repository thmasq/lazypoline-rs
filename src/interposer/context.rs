//! Interposer context
//!
//! This module contains the `InterposerContext` struct, which
//! holds the state and configuration for an interposer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::interposer::builder::InterposerConfig;
use crate::interposer::filter::SyscallFilter;
use crate::interposer::handler::SyscallHandler;
use crate::syscall::Syscall;

/// Statistics about syscall interception
#[derive(Debug, Default, Clone)]
pub struct SyscallStats {
	/// Total number of intercepted syscalls
	pub total_intercepted: usize,
	/// Number of syscalls from VDSO (not rewritten)
	pub vdso_syscalls: usize,
	/// Number of rewritten syscalls
	pub rewritten_syscalls: usize,
	/// Count of each syscall
	pub syscall_counts: HashMap<Syscall, usize>,
}

impl SyscallStats {
	/// Increment the count for a specific syscall
	pub fn increment(&mut self, syscall: Syscall) {
		self.total_intercepted += 1;
		*self.syscall_counts.entry(syscall).or_insert(0) += 1;
	}

	/// Mark a syscall as being in the VDSO
	pub const fn mark_vdso(&mut self) {
		self.vdso_syscalls += 1;
	}

	/// Mark a syscall as being rewritten
	pub const fn mark_rewritten(&mut self) {
		self.rewritten_syscalls += 1;
	}
}

/// Context for an interposer
///
/// This struct holds the state and configuration for an interposer.
#[derive(Clone)]
pub struct InterposerContext {
	/// The configuration for the interposer
	pub config: InterposerConfig,
	/// The handlers for syscalls
	pub handlers: Vec<Box<dyn SyscallHandler>>,
	/// The filter for syscalls
	pub filter: Box<dyn SyscallFilter>,
	/// Statistics about syscall interception
	pub stats: Arc<Mutex<SyscallStats>>,
}

impl std::fmt::Debug for InterposerContext {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("InterposerContext")
			.field("config", &self.config)
			.field("handlers_count", &self.handlers.len())
			.field("filter_type", &self.filter.name())
			.field("stats", &self.stats)
			.finish()
	}
}

impl InterposerContext {
	/// Create a new interposer context
	#[must_use]
	pub fn new(
		config: InterposerConfig,
		handlers: Vec<Box<dyn SyscallHandler>>,
		filter: Box<dyn SyscallFilter>,
	) -> Self {
		Self {
			config,
			handlers,
			filter,
			stats: Arc::new(Mutex::new(SyscallStats::default())),
		}
	}

	/// Process a syscall through the interposer
	///
	/// This method applies the filter and then calls each handler
	/// in order until one returns an action other than `Allow`.
	pub fn process_syscall(&self, ctx: &mut crate::syscall::SyscallContext) -> crate::syscall::SyscallAction {
		// Update statistics if we can get the lock without blocking
		if let Ok(mut stats) = self.stats.try_lock() {
			stats.increment(ctx.syscall);
		}

		// MANDATORY EMULATION OVERRIDE:
		// These syscalls alter the stack pointer or execution context severely.
		// Executing them inline via C-ABI will crash the process/thread.
		if matches!(
			ctx.syscall,
			crate::syscall::Syscall::clone | crate::syscall::Syscall::vfork | crate::syscall::Syscall::rt_sigreturn
		) {
			tracing::debug!(
				"Forcing emulation for context-switching syscall: {}",
				ctx.syscall.name()
			);
			return crate::syscall::SyscallAction::Emulate;
		}

		// Check if the syscall is in a safe list that should always be allowed
		// to prevent deadlocks or system crashes
		if is_critical_syscall(ctx.syscall) {
			return crate::syscall::SyscallAction::Allow;
		}

		// Check if the syscall should be filtered
		if !self.filter.allow_syscall(ctx) {
			tracing::debug!(
				"Blocked syscall {} by filter {}",
				ctx.syscall.name(),
				self.filter.name()
			);
			return crate::syscall::SyscallAction::Block((-libc::EPERM).into());
		}

		// Call each handler until one returns a non-Allow action
		for handler in &self.handlers {
			let action = handler.handle_syscall(ctx);

			#[allow(clippy::needless_continue)]
			match action {
				crate::syscall::SyscallAction::Allow => continue,
				crate::syscall::SyscallAction::Block(code) => {
					tracing::debug!(
						"Blocked syscall {} by handler {} with code {}",
						ctx.syscall.name(),
						handler.name(),
						code
					);
					return action;
				},
				crate::syscall::SyscallAction::Emulate => {
					tracing::debug!("Emulating syscall {} by handler {}", ctx.syscall.name(), handler.name());
					return action;
				},
				crate::syscall::SyscallAction::Modify(_) => {
					tracing::debug!("Modified syscall {} by handler {}", ctx.syscall.name(), handler.name());
					return action;
				},
			}
		}

		// If no handler returns a non-Allow action, allow the syscall
		crate::syscall::SyscallAction::Allow
	}

	/// Get a clone of the current statistics
	#[must_use]
	pub fn get_stats(&self) -> Option<SyscallStats> {
		self.stats.lock().ok().map(|stats| stats.clone())
	}
}

const fn is_critical_syscall(syscall: crate::syscall::Syscall) -> bool {
	// These syscalls are necessary for basic functioning
	// and should never be blocked
	matches!(
		syscall,
		crate::syscall::Syscall::brk
			| crate::syscall::Syscall::exit
			| crate::syscall::Syscall::exit_group
			| crate::syscall::Syscall::mmap
			| crate::syscall::Syscall::mprotect
			| crate::syscall::Syscall::munmap
			| crate::syscall::Syscall::arch_prctl
			| crate::syscall::Syscall::rt_sigaction
			| crate::syscall::Syscall::rt_sigprocmask
			| crate::syscall::Syscall::prctl
	)
}
