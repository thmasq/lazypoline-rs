use std::sync::Once;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

static INIT: Once = Once::new();

/// Initialize the tracing system
///
/// This function sets up tracing with an `EnvFilter` that:
/// - Honors the `RUST_LOG` environment variable if set
/// - Uses the `LAZYPOLINE_DEBUG` environment variable to control logging level
/// - Only logs warnings and errors by default
pub fn init() {
	INIT.call_once(|| {
		let filter = EnvFilter::try_from_default_env()
			.or_else(|_| {
				if std::env::var("LAZYPOLINE_DEBUG").is_ok() {
					Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline_rs=debug"))
				} else {
					Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline_rs=warn"))
				}
			})
			.unwrap();

		tracing_subscriber::registry()
			.with(fmt::layer().with_target(true))
			.with(filter)
			.init();
	});
}
