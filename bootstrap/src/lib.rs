//! Bootstrap library for lazypoline
//!
//! This small library uses `dlmopen` to load the main lazypoline library
//! in a new dynamic library namespace, ensuring it doesn't interfere with
//! the application's libraries.

use std::env;
use std::ffi::{CString, c_void};
use std::process;

unsafe extern "C" {
	fn dlmopen(lmid: libc::Lmid_t, filename: *const libc::c_char, flag: libc::c_int) -> *mut c_void;
	fn dlsym(handle: *mut c_void, symbol: *const libc::c_char) -> *mut c_void;
	fn dlerror() -> *mut libc::c_char;
}

#[unsafe(link_section = ".init_array")]
#[used]
static CONSTRUCTOR: fn() = load_runtime;

fn load_runtime() {
	eprintln!("Bootstrap: Loading lazypoline runtime...");

	unsafe {
		let result = libc::mmap(
			std::ptr::null_mut(),
			0x1000,
			libc::PROT_READ | libc::PROT_WRITE,
			libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
			-1,
			0,
		);

		if result == libc::MAP_FAILED {
			eprintln!("Bootstrap: WARNING! Could not map zero page. Is /proc/sys/vm/mmap_min_addr set to 0?");
			eprintln!("Bootstrap: Error: {}", std::io::Error::last_os_error());
		} else {
			eprintln!("Bootstrap: Zero page mapped successfully");
			libc::munmap(result, 0x1000);
		}
	}

	let library_path = match env::var("LIBLAZYPOLINE") {
		Ok(path) => path,
		Err(_) => {
			eprintln!(
				"Bootstrap: 'LIBLAZYPOLINE' not specified: Please set the 'LIBLAZYPOLINE' env var to the path of the lazypoline runtime library"
			);
			process::exit(1);
		},
	};

	eprintln!("Bootstrap: Loading library from: {}", library_path);

	unsafe {
		dlerror();

		let c_library_path = CString::new(library_path).expect("Invalid library path");
		let handle = dlmopen(
			libc::LM_ID_NEWLM,
			c_library_path.as_ptr(),
			libc::RTLD_NOW | libc::RTLD_LOCAL,
		);

		if handle.is_null() {
			let error = dlerror();
			if !error.is_null() {
				let error_str = std::ffi::CStr::from_ptr(error).to_string_lossy();
				eprintln!("Failed to open lazypoline library: {}", error_str);
			} else {
				eprintln!("Failed to open lazypoline library with unknown error");
			}
			process::exit(1);
		}

		let init_sym = CString::new("init_lazypoline").expect("CString conversion failed");
		let init_fn_ptr = dlsym(handle, init_sym.as_ptr());

		if init_fn_ptr.is_null() {
			let error = dlerror();
			if !error.is_null() {
				let error_str = std::ffi::CStr::from_ptr(error).to_string_lossy();
				eprintln!("Failed to find init_lazypoline: {}", error_str);
			} else {
				eprintln!("Failed to find init_lazypoline with unknown error");
			}
			process::exit(1);
		}

		eprintln!("Bootstrap: Found init_lazypoline function at {:p}", init_fn_ptr);

		let init_fn: extern "C" fn() = std::mem::transmute(init_fn_ptr);
		eprintln!("Bootstrap: Calling init_lazypoline...");
		init_fn();
		eprintln!("Bootstrap: init_lazypoline completed");
	}
}
