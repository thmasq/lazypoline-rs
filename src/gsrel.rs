use crate::ffi::{PageAligned, SYSCALL_DISPATCH_FILTER_BLOCK, mmap_at_addr, set_gs_base};
use crate::signal::SignalHandlers;
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::ptr::null_mut;

pub const SUD_SELECTOR_OFFSET: usize = 0;
pub const SIGRETURN_STACK_SP_OFFSET: usize = 16;
pub const RIP_AFTER_SYSCALL_STACK_SP_OFFSET: usize = 4120;
pub const XSAVE_AREA_STACK_SP_OFFSET: usize = 8256;
pub const XSAVE_EAX: u32 = 0b111; // saves x87 state, XMM & YMM vector registers
pub const XSAVE_SIZE: usize = 768; // aligned to 64-byte boundary

#[repr(C, align(4096))]
pub struct GSRelData {
	pub sud_selector: UnsafeCell<u8>,

	_padding1: [u8; 7], // Padding to align signal_handlers to 8 bytes

	pub signal_handlers: UnsafeCell<*mut SignalHandlers>,

	_padding2: [u8; 8],

	// Sigreturn stack structure (corresponds to the C++ nested structure)
	pub sigreturn_stack_current: UnsafeCell<*mut u8>,
	pub sigreturn_stack_base: [u8; 0x1000],

	// Stack of rip_after_syscall values for vfork handling
	pub rip_after_syscall_stack_current: UnsafeCell<*mut u8>,
	pub rip_after_syscall_stack_base: [u8; 0x1000],

	// XSAVE area stack grows up
	pub xsave_area_stack_current: UnsafeCell<*mut u8>,
	pub xsave_area_stack_base: PageAligned<[u8; XSAVE_SIZE * 6]>,
}

impl GSRelData {
	#[must_use]
	pub fn new() -> *mut Self {
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
			(*gsreldata).sud_selector = UnsafeCell::new(SYSCALL_DISPATCH_FILTER_BLOCK);
			(*gsreldata).signal_handlers = UnsafeCell::new(null_mut());

			(*gsreldata).sigreturn_stack_current = UnsafeCell::new((*gsreldata).sigreturn_stack_base.as_mut_ptr());

			(*gsreldata).rip_after_syscall_stack_current =
				UnsafeCell::new((*gsreldata).rip_after_syscall_stack_base.as_mut_ptr());

			(*gsreldata).xsave_area_stack_current = UnsafeCell::new((*gsreldata).xsave_area_stack_base.0.as_mut_ptr());

			let result = set_gs_base(gsreldata as u64);
			assert_eq!(result, 0, "Failed to set GS base register");

			gsreldata
		}
	}
}

#[inline(always)]
#[must_use]
pub fn get_privilege_level() -> u8 {
	unsafe {
		#[allow(unused_assignments)]
		let mut value: u8 = 0;
		std::arch::asm!(
			"mov {0}, gs:[{1}]",
			out(reg_byte) value,
			const SUD_SELECTOR_OFFSET,
			options(nostack, preserves_flags)
		);
		value
	}
}

#[inline(always)]
pub fn set_privilege_level(level: u8) {
	unsafe {
		std::arch::asm!(
			"mov gs:[{1}], {0}",
			in(reg_byte) level,
			const SUD_SELECTOR_OFFSET,
			options(nostack, preserves_flags)
		);
	}
}

pub struct UnblockScope {
	old_selector: u8,
}

impl Default for UnblockScope {
	fn default() -> Self {
		Self::new()
	}
}

impl UnblockScope {
	#[must_use]
	pub fn new() -> Self {
		let old_selector = get_privilege_level();
		set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);
		Self { old_selector }
	}
}

impl Drop for UnblockScope {
	fn drop(&mut self) {
		debug_assert_eq!(get_privilege_level(), crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);
		set_privilege_level(self.old_selector);
	}
}

pub struct BlockScope {
	old_selector: u8,
}

impl Default for BlockScope {
	fn default() -> Self {
		Self::new()
	}
}

impl BlockScope {
	#[must_use]
	pub fn new() -> Self {
		let old_selector = get_privilege_level();
		set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_BLOCK);
		Self { old_selector }
	}
}

impl Drop for BlockScope {
	fn drop(&mut self) {
		debug_assert_eq!(get_privilege_level(), crate::ffi::SYSCALL_DISPATCH_FILTER_BLOCK);
		set_privilege_level(self.old_selector);
	}
}
