#[allow(dead_code)]
unsafe extern "C" {
	pub fn asm_syscall_hook();
	pub fn restore_selector_trampoline();
	pub fn setup_new_thread(clone_flags: u64);
	pub fn setup_vforked_child();
}

#[unsafe(no_mangle)]
pub extern "C" fn teardown_thread_metadata() {
	// In a real implementation, this would clean up thread-local data
	// For now, just a placeholder that would be replaced with proper implementation
	unsafe {
		// Disable SUD
		let result = crate::ffi::syscall6(
			libc::SYS_prctl,
			i64::from(crate::ffi::PR_SET_SYSCALL_USER_DISPATCH),
			i64::from(crate::ffi::PR_SYS_DISPATCH_OFF),
			0,
			0,
			0,
			0,
		);
		assert_eq!(result, 0, "Failed to disable SUD");

		// Unmap GSRelData
		let gs_base = crate::ffi::get_gs_base();
		let result = crate::ffi::syscall6(
			libc::SYS_munmap,
			gs_base.try_into().unwrap(),
			4096, // Page size
			0,
			0,
			0,
			0,
		);
		assert_eq!(result, 0, "Failed to unmap GSRelData");
	}
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_clone_thread(a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
	// In a real implementation, this would handle thread creation
	// For now, just forward to syscall6
	unsafe { crate::ffi::syscall6(libc::SYS_clone, a1, a2, a3, a4, a5, a6) as i64 }
}
