//! Utility modules for lazypoline
//!
//! This module contains utility functions and types used by lazypoline.

pub mod logging;
pub mod memory;

// Re-export all utility functions
pub use logging::init_logging;
pub use memory::{page_align, page_size};
