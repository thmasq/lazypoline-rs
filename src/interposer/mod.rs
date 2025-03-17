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
static ACTIVE_INTERPOSER: std::sync::LazyLock<RwLock<Option<InterposerContext>>> =
	std::sync::LazyLock::new(|| RwLock::new(None));

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

		// First, initialize logging to make sure we can see what's happening
		crate::util::init_logging();

		tracing::info!("Initializing lazypoline interposer...");

		// Register this interposer as the active one
		set_active_interposer(self.context.clone());

		unsafe {
			// Initialize SUD first
			tracing::info!("Initializing SUD...");
			match crate::core::sud::init_sud() {
				Ok(_) => tracing::info!("SUD initialized successfully"),
				Err(e) => {
					tracing::error!("Failed to initialize SUD: {}", e);
					return Err(e);
				},
			}

			// Get the GSRelData for the main thread
			let gs_base = crate::ffi::get_gs_base();
			if gs_base != 0 {
				// Initialize the thread registry with the main thread
				let gsreldata = gs_base as *mut crate::core::gsrel::GSRelData;
				crate::core::thread_registry::init_with_main_thread(gsreldata);
				tracing::info!("Thread registry initialized with main thread");
			} else {
				tracing::warn!("Could not get GS base, thread registry not initialized");
			}

			// Initialize zpoline if configured
			if self.context.config.rewrite_to_zpoline {
				tracing::info!("Initializing zpoline...");
				match crate::core::zpoline::init_zpoline() {
					Ok(_) => tracing::info!("Zpoline initialized successfully"),
					Err(e) => {
						tracing::error!("Failed to initialize zpoline: {}", e);
						return Err(e);
					},
				}
			}

			// Now enable SUD with everything set up
			tracing::info!("Enabling SUD...");
			match crate::core::sud::enable_sud() {
				Ok(_) => tracing::info!("SUD enabled successfully"),
				Err(e) => {
					tracing::error!("Failed to enable SUD: {}", e);
					return Err(e);
				},
			}

			// Start with syscalls allowed
			tracing::info!("Setting initial privilege level to ALLOW");
			crate::core::gsrel::set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

			// Verify the privilege level is set correctly
			let level = crate::core::gsrel::get_privilege_level();
			tracing::info!("Current privilege level: {}", level);
			if level != crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW {
				tracing::warn!("Privilege level not set to ALLOW, attempting to correct");
				crate::core::gsrel::set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);
			}
		}

		self.initialized = true;
		tracing::info!("Interposer initialized successfully!");
		Ok(self)
	}

	/// Check if the interposer is initialized
	#[must_use]
	pub const fn is_initialized(&self) -> bool {
		self.initialized
	}

	/// Get the interposer context
	#[must_use]
	pub const fn context(&self) -> &InterposerContext {
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
			tracing::info!("Shutting down interposer...");

			// Ensure syscalls are allowed during cleanup
			crate::core::gsrel::set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

			// Clear active interposer
			clear_active_interposer();

			// Disable SUD
			unsafe {
				if let Err(e) = crate::core::sud::disable_sud() {
					tracing::error!("Error disabling SUD during shutdown: {}", e);
				} else {
					tracing::info!("SUD disabled successfully");
				}
			}

			tracing::info!("Interposer shut down successfully");
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
