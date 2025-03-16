//! Builder for creating interposers
//!
//! This module contains the `InterposerBuilder` struct and related
//! functionality for configuring and building interposers.

use crate::interposer::filter::{AllowAllFilter, SyscallFilter};
use crate::interposer::handler::{DefaultHandler, SyscallHandler, TracingHandler};
use crate::interposer::{Interposer, InterposerContext, Result};

/// Configuration for an interposer
#[derive(Debug, Clone)]
pub struct InterposerConfig {
	/// Whether to trace syscalls
	pub trace: bool,
	/// Whether to rewrite syscalls to zpoline
	pub rewrite_to_zpoline: bool,
	/// Whether to print syscall statistics at exit
	pub print_stats: bool,
}

impl Default for InterposerConfig {
	fn default() -> Self {
		Self {
			trace: false,
			rewrite_to_zpoline: true,
			print_stats: true,
		}
	}
}

/// Builder for creating interposers
///
/// This struct provides a builder pattern for configuring and
/// creating interposers.
pub struct InterposerBuilder {
	/// The configuration for the interposer
	config: InterposerConfig,
	/// The handlers for syscalls
	handlers: Vec<Box<dyn SyscallHandler>>,
	/// The filter for syscalls
	filter: Option<Box<dyn SyscallFilter>>,
}

impl Default for InterposerBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl std::fmt::Debug for InterposerBuilder {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("InterposerBuilder")
			.field("config", &self.config)
			.field("handlers", &format!("[{} handlers]", self.handlers.len()))
			.field("filter", &if self.filter.is_some() { "Some(filter)" } else { "None" })
			.finish()
	}
}

impl InterposerBuilder {
	/// Create a new interposer builder with default settings
	#[must_use]
	pub fn new() -> Self {
		Self {
			config: InterposerConfig::default(),
			handlers: Vec::new(),
			filter: None,
		}
	}

	/// Enable or disable syscall tracing
	#[must_use]
	pub const fn trace(mut self, trace: bool) -> Self {
		self.config.trace = trace;
		self
	}

	/// Enable or disable syscall rewriting to zpoline
	#[must_use]
	pub const fn rewrite_to_zpoline(mut self, rewrite: bool) -> Self {
		self.config.rewrite_to_zpoline = rewrite;
		self
	}

	/// Enable or disable printing syscall statistics at exit
	#[must_use]
	pub const fn print_stats(mut self, print: bool) -> Self {
		self.config.print_stats = print;
		self
	}

	/// Add a syscall handler
	#[must_use]
	pub fn handler<H: SyscallHandler + 'static>(mut self, handler: H) -> Self {
		self.handlers.push(Box::new(handler));
		self
	}

	/// Set the syscall filter
	#[must_use]
	pub fn filter<F: SyscallFilter + 'static>(mut self, filter: F) -> Self {
		self.filter = Some(Box::new(filter));
		self
	}

	/// Build the interposer
	pub fn build(self) -> Result<Interposer> {
		// Add default handlers if none provided
		let mut handlers = self.handlers;
		if handlers.is_empty() {
			handlers.push(Box::new(DefaultHandler::new()));

			if self.config.trace {
				handlers.push(Box::new(TracingHandler::new()));
			}
		}

		// Set default filter if none provided
		let filter = self.filter.unwrap_or_else(|| Box::new(AllowAllFilter::new()));

		let context = InterposerContext::new(self.config, handlers, filter);

		Ok(Interposer::new(context))
	}
}
