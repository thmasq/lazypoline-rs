//! Core functionality for lazypoline
//!
//! This module contains the low-level functionality needed
//! for syscall interposition, including SUD, zpoline, and
//! signal handling.

// We expose these modules publicly within the crate
pub mod asm;
pub mod gsrel;
pub mod signal;
pub mod sud;
pub mod zpoline;

// Also re-export the FFI module for convenience
pub use crate::ffi;
