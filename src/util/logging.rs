//! Logging utilities for lazypoline
//!
//! This module provides logging functionality for lazypoline.

use std::sync::Once;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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
				if std::env::var("LAZYPOLINE_DEBUG").is_ok() {
					Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=debug"))
				} else {
					Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=warn"))
				}
			})
			.unwrap();

		tracing_subscriber::registry()
			.with(fmt::layer().with_target(true))
			.with(filter)
			.init();
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
#[must_use] pub fn log_level() -> &'static str {
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
