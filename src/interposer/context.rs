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
	#[must_use] pub fn new(
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
		// Update statistics
		if let Ok(mut stats) = self.stats.lock() {
			stats.increment(ctx.syscall);
		}

		// Check if the syscall should be filtered
		if !self.filter.allow_syscall(ctx) {
			return crate::syscall::SyscallAction::Block((-libc::EPERM).into());
		}

		// Call each handler until one returns a non-Allow action
		for handler in &self.handlers {
			let action = handler.handle_syscall(ctx);
			match action {
				crate::syscall::SyscallAction::Allow => continue,
				_ => return action,
			}
		}

		// If no handler returns a non-Allow action, allow the syscall
		crate::syscall::SyscallAction::Allow
	}

	/// Get a clone of the current statistics
	#[must_use] pub fn get_stats(&self) -> Option<SyscallStats> {
		self.stats.lock().ok().map(|stats| stats.clone())
	}
}
