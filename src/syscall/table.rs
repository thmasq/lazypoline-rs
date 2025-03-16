//! Syscall table
//!
//! This module contains the syscall enum and related functionality.
//! The enum is generated at compile time using the proc macro.

use lazypoline_macros::syscall_enum;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Syscall enum
///
/// This enum contains all the Linux syscalls for the x86_64 architecture.
/// It is generated at compile time using the `syscall_enum` proc macro.
#[syscall_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Syscall {
	/// Unknown syscall
	Unknown = -1,
}

static SYSCALL_MAP: LazyLock<HashMap<i64, Syscall>> = LazyLock::new(|| {
	let mut map = HashMap::new();
	for i in 0..512 {
		if let Some(syscall) = Syscall::from_number(i) {
			map.insert(i, syscall);
		}
	}
	map
});

/// Get a syscall from its number
#[must_use]
pub fn syscall_from_number(num: i64) -> Option<Syscall> {
	SYSCALL_MAP.get(&num).copied()
}
