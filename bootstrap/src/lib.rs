//! Bootstrap library for lazypoline
//!
//! This small library uses `dlmopen` to load the main lazypoline library
//! in a new dynamic library namespace, ensuring it doesn't interfere with
//! the application's libraries.

use std::env;
use std::ffi::{CString, c_void};
use std::process;
use std::sync::Once;
use tracing::{debug, error};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

unsafe extern "C" {
	fn dlmopen(lmid: libc::Lmid_t, filename: *const libc::c_char, flag: libc::c_int) -> *mut c_void;
	fn dlsym(handle: *mut c_void, symbol: *const libc::c_char) -> *mut c_void;
	fn dlerror() -> *mut libc::c_char;
}

static INIT_LOGGER: Once = Once::new();

fn init_logger() {
	INIT_LOGGER.call_once(|| {
		let filter = EnvFilter::try_from_default_env()
			.or_else(|_| {
				if std::env::var("LAZYPOLINE_DEBUG").is_ok() {
					Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=debug"))
				} else {
					Ok::<EnvFilter, Box<dyn std::error::Error>>(EnvFilter::new("lazypoline=warn"))
				}
			})
			.unwrap();

		tracing_subscriber::registry()
			.with(fmt::layer().with_target(false))
			.with(filter)
			.init();
	});
}

#[unsafe(link_section = ".init_array")]
#[used]
static CONSTRUCTOR: fn() = load_runtime;

fn load_runtime() {
	init_logger();

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
			error!("WARNING! Could not map zero page. Is /proc/sys/vm/mmap_min_addr set to 0?");
			error!("Error: {}", std::io::Error::last_os_error());
		} else {
			debug!("Zero page mapped successfully");
			libc::munmap(result, 0x1000);
		}
	}

	let library_path = match env::var("LIBLAZYPOLINE") {
		Ok(path) => path,
		Err(_) => {
			error!(
				"'LIBLAZYPOLINE' not specified: Please set the 'LIBLAZYPOLINE' env var to the path of the lazypoline runtime library"
			);
			process::exit(1);
		},
	};

	debug!("Loading library from: {}", library_path);

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
				error!("Failed to open lazypoline library: {}", error_str);
			} else {
				error!("Failed to open lazypoline library with unknown error");
			}
			process::exit(1);
		}

		let init_sym = CString::new("bootstrap_lazypoline").expect("CString conversion failed");
		let init_fn_ptr = dlsym(handle, init_sym.as_ptr());

		if init_fn_ptr.is_null() {
			let error = dlerror();
			if !error.is_null() {
				let error_str = std::ffi::CStr::from_ptr(error).to_string_lossy();
				error!("Failed to find bootstrap_lazypoline: {}", error_str);
			} else {
				error!("Failed to find bootstrap_lazypoline with unknown error");
			}
			process::exit(1);
		}

		debug!("Found bootstrap_lazypoline function at {:p}", init_fn_ptr);

		let init_fn: extern "C" fn() = std::mem::transmute(init_fn_ptr);
		debug!("Calling bootstrap_lazypoline...");
		init_fn();
		debug!("bootstrap_lazypoline completed");
	}
}
