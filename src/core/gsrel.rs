//! GS register-related memory and data structures
//!
//! This module implements the GS register-related functionality
//! used for thread-local storage in lazypoline. The GS register
//! is used to store thread-local state for syscall interposition.

#![allow(clippy::inline_always)]

use crate::core::signal::SignalHandlers;
use crate::ffi::{XSaveAligned, mmap_at_addr, set_gs_base};
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::mem::offset_of;
use std::ptr::null_mut;

/// Offset of the SUD selector in the `GSRelData` structure
pub const SUD_SELECTOR_OFFSET: usize = 0;

/// Offset of the sigreturn stack in the `GSRelData` structure
pub const SIGRETURN_STACK_SP_OFFSET: usize = 16;

/// Offset of the RIP after syscall stack in the `GSRelData` structure
pub const RIP_AFTER_SYSCALL_STACK_SP_OFFSET: usize = 4120;

/// Offset of the XSAVE area stack in the `GSRelData` structure
pub const XSAVE_AREA_STACK_SP_OFFSET: usize = 8224;

/// Flags for XSAVE register saving
pub const XSAVE_EAX: u32 = 0b111; // saves x87 state, XMM & YMM vector registers

/// Size of the XSAVE area, aligned to 64-byte boundary
pub const XSAVE_SIZE: usize = 768;

/// Thread-local data structure accessed via the GS register
///
/// This structure contains thread-local state needed for syscall
/// interposition, including the SUD selector, signal handlers,
/// and stacks for saving register state.
#[repr(C, align(4096))]
pub struct GSRelData {
	/// Selector for Syscall User Dispatch (0 = allow, 1 = block)
	pub sud_selector: UnsafeCell<u8>,

	/// Pointer to the signal handlers
	pub signal_handlers: UnsafeCell<*mut SignalHandlers>,

	/// Current pointer into the sigreturn stack
	pub sigreturn_stack_current: UnsafeCell<*mut u8>,

	/// Base of the sigreturn stack
	pub sigreturn_stack_base: [u8; 0x1000],

	/// Current pointer into the RIP after syscall stack
	pub rip_after_syscall_stack_current: UnsafeCell<*mut u8>,

	/// Base of the RIP after syscall stack
	pub rip_after_syscall_stack_base: [u8; 0x1000],

	/// Current pointer into the XSAVE area stack
	pub xsave_area_stack_current: UnsafeCell<*mut u8>,

	/// Base of the XSAVE area stack
	pub xsave_area_stack_base: XSaveAligned<[u8; XSAVE_SIZE * 6]>, // Offset 8256

	/// Caches the thread's permanently claimed Hazard Pointer slot index.
	/// MUST be initialized to `usize::MAX`.
	pub hazard_slot_idx: std::cell::UnsafeCell<usize>,
}

impl GSRelData {
	/// Creates a new `GSRelData` structure and sets the GS register to point to it
	///
	/// # Returns
	///
	/// A pointer to the newly allocated `GSRelData` structure
	///
	/// # Safety
	///
	/// This function is unsafe because it:
	/// - Allocates memory with mmap
	/// - Sets the GS register
	/// - Modifies global processor state
	#[must_use]
	pub unsafe fn new() -> *mut Self {
		unsafe {
			let mem = mmap_at_addr(
				null_mut(),
				std::mem::size_of::<Self>(),
				PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE,
				-1,
				0,
			);

			assert!(
				!mem.is_null() && mem != libc::MAP_FAILED.cast::<c_void>(),
				"Failed to allocate GSRelData"
			);

			let gsreldata = mem.cast::<Self>();

			// Zero out the entire structure first to ensure clean initialization
			std::ptr::write_bytes(gsreldata, 0, 1);

			// Initialize the selector with the appropriate value
			// Fix: Using a direct value rather than a constant that might be misinterpreted
			*(*gsreldata).sud_selector.get() = 0; // SYSCALL_DISPATCH_FILTER_ALLOW = 0

			(*gsreldata).signal_handlers = UnsafeCell::new(null_mut());

			(*gsreldata).sigreturn_stack_current = UnsafeCell::new((*gsreldata).sigreturn_stack_base.as_mut_ptr());

			(*gsreldata).rip_after_syscall_stack_current =
				UnsafeCell::new((*gsreldata).rip_after_syscall_stack_base.as_mut_ptr());

			(*gsreldata).xsave_area_stack_current = UnsafeCell::new((*gsreldata).xsave_area_stack_base.0.as_mut_ptr());

			(*gsreldata).hazard_slot_idx = UnsafeCell::new(usize::MAX);

			let result = set_gs_base(gsreldata as u64);
			assert_eq!(result, 0, "Failed to set GS base register");

			// Register this GSRelData with the thread registry if we're not the very first thread
			if crate::core::thread_registry::registry().thread_count() > 0 {
				// We're not the main thread, so find our parent
				let parent_thread_id = crate::core::thread_registry::registry()
					.get_current_parent_thread_info()
					.map(|parent_info| parent_info.thread_id);

				// Register current thread
				crate::core::thread_registry::registry().register_current_thread(gsreldata, parent_thread_id, None);
			}

			gsreldata
		}
	}
}

/// Gets the current SUD privilege level from thread-local storage.
///
/// The privilege level determines whether syscalls are allowed (0)
/// or blocked (1) for the current thread.
///
/// # Returns
///
/// The current privilege level (0 = allow, 1 = block)
#[inline(always)]
#[must_use]
pub fn get_privilege_level() -> u8 {
	unsafe {
		#[allow(unused_assignments)]
		let mut value: u8 = 0;
		std::arch::asm!(
			"mov {0}, byte ptr gs:[{1}]",
			out(reg_byte) value,
			const SUD_SELECTOR_OFFSET,
			options(nostack, preserves_flags)
		);
		value
	}
}

/// Sets the SUD privilege level in thread-local storage.
///
/// Setting the privilege level to `SYSCALL_DISPATCH_FILTER_ALLOW` (0) allows
/// syscalls to execute normally. Setting it to `SYSCALL_DISPATCH_FILTER_BLOCK` (1)
/// causes syscalls to trigger SIGSYS.
///
/// # Parameters
///
/// * `level` - The privilege level to set (0 = allow, 1 = block)
#[inline(always)]
pub fn set_privilege_level(level: u8) {
	unsafe {
		std::arch::asm!(
			"mov byte ptr gs:[{1}], {0}",
			in(reg_byte) level,
			const SUD_SELECTOR_OFFSET,
			options(nostack, preserves_flags)
		);
	}
}

/// RAII guard for temporarily unblocking syscalls
///
/// This struct temporarily allows syscalls while it is in scope,
/// and restores the previous privilege level when dropped.
pub struct UnblockScope {
	old_selector: u8,
}

impl Default for UnblockScope {
	fn default() -> Self {
		Self::new()
	}
}

impl UnblockScope {
	/// Creates a new `UnblockScope`
	///
	/// This saves the current privilege level and sets it to allow syscalls.
	#[must_use]
	pub fn new() -> Self {
		let old_selector = get_privilege_level();
		set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);
		Self { old_selector }
	}
}

impl Drop for UnblockScope {
	fn drop(&mut self) {
		set_privilege_level(self.old_selector);
	}
}

/// RAII guard for temporarily blocking syscalls
///
/// This struct temporarily blocks syscalls while it is in scope,
/// and restores the previous privilege level when dropped.
pub struct BlockScope {
	old_selector: u8,
}

impl Default for BlockScope {
	fn default() -> Self {
		Self::new()
	}
}

impl BlockScope {
	/// Creates a new `BlockScope`
	///
	/// This saves the current privilege level and sets it to block syscalls.
	#[must_use]
	pub fn new() -> Self {
		let old_selector = get_privilege_level();
		set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_BLOCK);
		Self { old_selector }
	}
}

impl Drop for BlockScope {
	fn drop(&mut self) {
		set_privilege_level(self.old_selector);
	}
}

const _: () = {
	assert!(offset_of!(GSRelData, sud_selector) == SUD_SELECTOR_OFFSET);
	assert!(offset_of!(GSRelData, sigreturn_stack_current) == SIGRETURN_STACK_SP_OFFSET);
	assert!(offset_of!(GSRelData, rip_after_syscall_stack_current) == RIP_AFTER_SYSCALL_STACK_SP_OFFSET);
	assert!(offset_of!(GSRelData, xsave_area_stack_current) == XSAVE_AREA_STACK_SP_OFFSET);
	assert!(offset_of!(GSRelData, xsave_area_stack_base) % 64 == 0);
};
