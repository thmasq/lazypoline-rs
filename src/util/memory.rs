//! Memory utilities for lazypoline
//!
//! This module provides memory-related utilities for lazypoline.

/// Get the system page size
///
/// This function returns the page size of the system, which is typically 4096 bytes.
///
/// # Returns
///
/// The page size in bytes
#[inline]
#[must_use] pub fn page_size() -> usize {
	unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// Align a pointer to a page boundary
///
/// This function aligns a pointer to a page boundary by rounding down.
///
/// # Arguments
///
/// * `ptr` - The pointer to align
///
/// # Returns
///
/// The aligned pointer
#[inline]
pub fn page_align<T>(ptr: *mut T) -> *mut T {
	let page_size = page_size();
	let ptr_val = ptr as usize;
	let aligned_ptr = ptr_val & !(page_size - 1);
	aligned_ptr as *mut T
}

/// Check if a pointer is aligned to a page boundary
///
/// This function checks if a pointer is aligned to a page boundary.
///
/// # Arguments
///
/// * `ptr` - The pointer to check
///
/// # Returns
///
/// `true` if the pointer is aligned to a page boundary, `false` otherwise
#[inline]
pub fn is_page_aligned<T>(ptr: *const T) -> bool {
	let page_size = page_size();
	(ptr as usize) % page_size == 0
}

/// Align a value to a page boundary
///
/// This function aligns a value to a page boundary by rounding up.
///
/// # Arguments
///
/// * `size` - The value to align
///
/// # Returns
///
/// The aligned value
#[inline]
#[must_use] pub fn align_to_page(size: usize) -> usize {
	let page_size = page_size();
	(size + page_size - 1) & !(page_size - 1)
}

/// Calculate the number of pages needed to store a given number of bytes
///
/// This function calculates the number of pages needed to store a given number of bytes.
///
/// # Arguments
///
/// * `size` - The number of bytes
///
/// # Returns
///
/// The number of pages needed
#[inline]
#[must_use] pub fn pages_needed(size: usize) -> usize {
	align_to_page(size) / page_size()
}
