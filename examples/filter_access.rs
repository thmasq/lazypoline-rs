use lazypoline_rs::{self, Syscall, SyscallAction};
use std::ffi::CStr;
use std::path::Path;

/// A set of paths that should be restricted
const RESTRICTED_PATHS: &[&str] = &["/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/hosts"];

/// Handler for filtering file access
#[lazypoline_rs::syscall_handler]
fn filter_sensitive_files(ctx: &mut SyscallContext) -> SyscallAction {
	match ctx.syscall {
		Syscall::open | Syscall::openat => {
			// Extract the path being opened
			let filepath = if ctx.syscall == Syscall::open {
				ctx.args.rdi as *const i8 // First arg for open is pathname
			} else {
				ctx.args.rsi as *const i8 // Second arg for openat is pathname
			};

			if !filepath.is_null() {
				let path_str = unsafe { CStr::from_ptr(filepath) }.to_string_lossy();
				let path = Path::new(path_str.as_ref());

				// Check if the path matches any restricted path
				for restricted in RESTRICTED_PATHS {
					if path.ends_with(restricted) || path_str == *restricted {
						println!("Access denied to restricted file: {}", path_str);
						// Return EACCES (Permission denied)
						return SyscallAction::Block(-libc::EACCES as i64);
					}
				}
			}
		},
		_ => {}, // Allow all other syscalls
	}

	// Allow the syscall to proceed
	SyscallAction::Allow
}

// This is the entry point that will be called by the bootstrap loader
#[unsafe(no_mangle)]
pub extern "C" fn bootstrap_lazypoline() {
	println!("Initializing file access filter...");
	println!("The following paths will be restricted:");
	for path in RESTRICTED_PATHS {
		println!("  - {}", path);
	}

	// Set up the interposer with our filter handler
	match lazypoline_rs::new()
		.handler(FilterSensitiveFiles::new())
		.build()
		.and_then(|i| i.init())
	{
		Ok(interposer) => {
			// Store interposer in a static to keep it alive (prevent drop)
			use std::sync::Once;
			static INIT: Once = Once::new();
			static mut INTERPOSER: Option<lazypoline_rs::Interposer> = None;

			INIT.call_once(|| {
				unsafe { INTERPOSER = Some(interposer) };
			});

			println!("File access filter initialized successfully!");
			println!("Try accessing a restricted file, for example:");
			println!("  $ cat /etc/passwd");
		},
		Err(e) => {
			eprintln!("Failed to initialize file access filter: {}", e);
			std::process::exit(1);
		},
	}
}
