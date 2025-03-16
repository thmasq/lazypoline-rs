//! Error types for the interposer
//!
//! This module contains error types and a result type for the interposer.

use std::io;
use thiserror::Error;

/// Result type for interposer operations
pub type Result<T> = std::result::Result<T, InterposerError>;

/// Error type for interposer operations
#[derive(Debug, Error)]
pub enum InterposerError {
	/// The interposer is already initialized
	#[error("The interposer is already initialized")]
	AlreadyInitialized,

	/// The interposer is not initialized
	#[error("The interposer is not initialized")]
	NotInitialized,

	/// An I/O error occurred
	#[error("I/O error: {0}")]
	Io(#[from] io::Error),

	/// SUD initialization failed
	#[error("Failed to initialize SUD: {0}")]
	SudInitFailed(String),

	/// Zpoline initialization failed
	#[error("Failed to initialize zpoline: {0}")]
	ZpolineInitFailed(String),

	/// Failed to allocate memory
	#[error("Failed to allocate memory: {0}")]
	MemoryAllocationFailed(String),

	/// The kernel does not support SUD
	#[error("The kernel does not support Syscall User Dispatch. Kernel version >= 5.11 is required.")]
	SudNotSupported,

	/// Missing required privileges
	#[error("Missing required privileges: {0}")]
	MissingPrivileges(String),

	/// Failed to register signal handler
	#[error("Failed to register signal handler: {0}")]
	SignalHandlerRegistrationFailed(String),

	/// Other error
	#[error("{0}")]
	Other(String),
}

impl From<&str> for InterposerError {
	fn from(s: &str) -> Self {
		Self::Other(s.to_string())
	}
}

impl From<String> for InterposerError {
	fn from(s: String) -> Self {
		Self::Other(s)
	}
}
