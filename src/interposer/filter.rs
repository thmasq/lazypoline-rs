//! Syscall filtering
//!
//! This module contains the `SyscallFilter` trait and implementations
//! for common filters.

use crate::syscall::{Syscall, SyscallContext};
use std::collections::HashSet;

/// Trait for filtering syscalls
///
/// A syscall filter decides whether a syscall should be allowed
/// to proceed to the handler chain.
pub trait SyscallFilter: Send + Sync {
	/// Determine if a syscall should be allowed
	///
	/// This method is called for each syscall before handlers
	/// are invoked. If it returns false, the syscall will be
	/// blocked immediately.
	fn allow_syscall(&self, ctx: &SyscallContext) -> bool;

	/// Get the name of the filter
	///
	/// This is used for debugging and logging purposes.
	fn name(&self) -> &'static str {
		std::any::type_name::<Self>()
	}

	fn clone_box(&self) -> Box<dyn SyscallFilter>;
}

/// Filter that allows all syscalls
#[derive(Debug, Clone, Default)]
pub struct AllowAllFilter;

impl AllowAllFilter {
	/// Create a new `AllowAllFilter`
	#[must_use]
	pub const fn new() -> Self {
		Self
	}
}

impl SyscallFilter for AllowAllFilter {
	fn allow_syscall(&self, _ctx: &SyscallContext) -> bool {
		true
	}

	fn name(&self) -> &'static str {
		"AllowAllFilter"
	}

	fn clone_box(&self) -> Box<dyn SyscallFilter> {
		Box::new(self.clone())
	}
}

/// Filter that blocks all syscalls
#[derive(Debug, Clone, Default)]
pub struct BlockAllFilter;

impl BlockAllFilter {
	/// Create a new `BlockAllFilter`
	#[must_use]
	pub const fn new() -> Self {
		Self
	}
}

impl SyscallFilter for BlockAllFilter {
	fn allow_syscall(&self, _ctx: &SyscallContext) -> bool {
		false
	}

	fn name(&self) -> &'static str {
		"BlockAllFilter"
	}

	fn clone_box(&self) -> Box<dyn SyscallFilter> {
		Box::new(self.clone())
	}
}

/// Filter that allows only specified syscalls
#[derive(Debug, Clone, Default)]
pub struct AllowListFilter {
	/// The set of allowed syscalls
	allowed: HashSet<Syscall>,
}

#[allow(dead_code)]
impl AllowListFilter {
	/// Create a new `AllowListFilter` with the specified syscalls
	pub fn new(syscalls: impl IntoIterator<Item = Syscall>) -> Self {
		Self {
			allowed: syscalls.into_iter().collect(),
		}
	}

	/// Add a syscall to the allow list
	pub fn allow(&mut self, syscall: Syscall) -> &mut Self {
		self.allowed.insert(syscall);
		self
	}

	/// Remove a syscall from the allow list
	pub fn disallow(&mut self, syscall: Syscall) -> &mut Self {
		self.allowed.remove(&syscall);
		self
	}
}

impl SyscallFilter for AllowListFilter {
	fn allow_syscall(&self, ctx: &SyscallContext) -> bool {
		self.allowed.contains(&ctx.syscall)
	}

	fn name(&self) -> &'static str {
		"AllowListFilter"
	}

	fn clone_box(&self) -> Box<dyn SyscallFilter> {
		Box::new(self.clone())
	}
}

/// Filter that blocks only specified syscalls
#[derive(Debug, Clone, Default)]
pub struct BlockListFilter {
	/// The set of blocked syscalls
	blocked: HashSet<Syscall>,
}

#[allow(dead_code)]
impl BlockListFilter {
	/// Create a new `BlockListFilter` with the specified syscalls
	pub fn new(syscalls: impl IntoIterator<Item = Syscall>) -> Self {
		Self {
			blocked: syscalls.into_iter().collect(),
		}
	}

	/// Add a syscall to the block list
	pub fn block(&mut self, syscall: Syscall) -> &mut Self {
		self.blocked.insert(syscall);
		self
	}

	/// Remove a syscall from the block list
	pub fn unblock(&mut self, syscall: Syscall) -> &mut Self {
		self.blocked.remove(&syscall);
		self
	}
}

impl SyscallFilter for BlockListFilter {
	fn allow_syscall(&self, ctx: &SyscallContext) -> bool {
		!self.blocked.contains(&ctx.syscall)
	}

	fn name(&self) -> &'static str {
		"BlockListFilter"
	}

	fn clone_box(&self) -> Box<dyn SyscallFilter> {
		// Use the type's Clone implementation
		Box::new(self.clone())
	}
}

impl Clone for Box<dyn SyscallFilter> {
	fn clone(&self) -> Self {
		self.clone_box()
	}
}
