//! Logging utilities for lazypoline
//!
//! This module provides logging functionality for lazypoline.

use std::sync::Once;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

// Initialize logging once
static INIT: Once = Once::new();

/// Initialize the tracing system
///
/// This function sets up tracing with an `EnvFilter` that:
/// - Honors the `RUST_LOG` environment variable if set
/// - Uses the `LAZYPOLINE_DEBUG` environment variable to control logging level
/// - Only logs warnings and errors by default
pub fn init_logging() {
	INIT.call_once(|| {
		let filter = EnvFilter::try_from_default_env()
			.or_else(|_| {
				std::env::var("LAZYPOLINE_DEBUG").map_or_else(
					|_| Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=warn")),
					|level| match level.to_lowercase().as_str() {
						"trace" => Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=trace")),
						"debug" => Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=debug")),
						"info" => Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=info")),
						"warn" => Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=warn")),
						"error" => Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=error")),
						_ if !level.is_empty() => {
							Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=debug"))
						},
						_ => Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=warn")),
					},
				)
			})
			.unwrap();

		let registry = tracing_subscriber::registry()
			.with(fmt::layer().with_target(true))
			.with(filter);

		match registry.try_init() {
			Ok(()) => {
				tracing::info!("Lazypoline logging initialized at level: {}", log_level());
			},
			Err(e) => {
				eprintln!("Note: Could not initialize tracing (probably already initialized): {e}");
			},
		}
	});
}

/// Get the current log level as a string
///
/// This function returns the current log level as a string:
/// - "trace" - Trace level
/// - "debug" - Debug level
/// - "info" - Info level
/// - "warn" - Warning level
/// - "error" - Error level
/// - "off" - Logging is disabled
#[must_use]
pub fn log_level() -> &'static str {
	if tracing::level_enabled!(tracing::Level::TRACE) {
		"trace"
	} else if tracing::level_enabled!(tracing::Level::DEBUG) {
		"debug"
	} else if tracing::level_enabled!(tracing::Level::INFO) {
		"info"
	} else if tracing::level_enabled!(tracing::Level::WARN) {
		"warn"
	} else if tracing::level_enabled!(tracing::Level::ERROR) {
		"error"
	} else {
		"off"
	}
}
