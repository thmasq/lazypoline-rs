//! Interposer functionality
//!
//! This module contains the core functionality for building and
//! configuring syscall interposers.

mod builder;
mod context;
mod error;
mod filter;
mod handler;

pub use builder::InterposerBuilder;
pub use context::InterposerContext;
pub use error::{InterposerError, Result};
pub use filter::{AllowAllFilter, BlockAllFilter, SyscallFilter};
pub use handler::{DefaultHandler, SyscallHandler, TracingHandler};
use std::sync::RwLock;

// Global registry for the active interposer
static ACTIVE_INTERPOSER: std::sync::LazyLock<RwLock<Option<InterposerContext>>> = std::sync::LazyLock::new(|| RwLock::new(None));

/// Main interposer struct
///
/// This struct represents a configured and initialized syscall interposer.
/// It is created using the `InterposerBuilder` and provides methods for
/// controlling the interposer.
#[derive(Debug)]
pub struct Interposer {
	/// The internal context for the interposer
	context: InterposerContext,
	/// Whether the interposer is initialized
	initialized: bool,
}

impl Interposer {
	/// Create a new interposer
	///
	/// This is typically called by the `InterposerBuilder` and not directly.
	pub(crate) const fn new(context: InterposerContext) -> Self {
		Self {
			context,
			initialized: false,
		}
	}

	/// Initialize the interposer
	///
	/// This sets up SUD and other necessary mechanisms for syscall interposition.
	pub fn init(mut self) -> Result<Self> {
		if self.initialized {
			return Err(InterposerError::AlreadyInitialized);
		}

		// Register this interposer as the active one
		set_active_interposer(self.context.clone());

		unsafe {
			crate::core::sud::init_sud()?;

			if self.context.config.rewrite_to_zpoline {
				crate::core::zpoline::init_zpoline()?;
			}

			crate::core::sud::enable_sud()?;

			crate::core::gsrel::set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_BLOCK);
		}

		self.initialized = true;
		Ok(self)
	}

	/// Check if the interposer is initialized
	#[must_use] pub const fn is_initialized(&self) -> bool {
		self.initialized
	}

	/// Get the interposer context
	#[must_use] pub const fn context(&self) -> &InterposerContext {
		&self.context
	}

	/// Get a mutable reference to the interposer context
	pub const fn context_mut(&mut self) -> &mut InterposerContext {
		&mut self.context
	}
}

impl Drop for Interposer {
	fn drop(&mut self) {
		if self.initialized {
			clear_active_interposer();

			unsafe {
				crate::core::gsrel::set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);
				crate::core::sud::disable_sud().ok();
			}
		}
	}
}

/// Get the active interposer context
pub fn get_active_interposer() -> Option<InterposerContext> {
	ACTIVE_INTERPOSER.read().unwrap().clone()
}

/// Set the active interposer context
pub(crate) fn set_active_interposer(context: InterposerContext) {
	*ACTIVE_INTERPOSER.write().unwrap() = Some(context);
}

/// Clear the active interposer context
pub(crate) fn clear_active_interposer() {
	*ACTIVE_INTERPOSER.write().unwrap() = None;
}
