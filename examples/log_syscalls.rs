use lazypoline_rs::{self, Syscall, SyscallAction};
use std::ffi::CStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Handler for logging syscalls of interest
#[lazypoline_rs::syscall_handler]
fn log_interesting_syscalls(ctx: &mut SyscallContext) -> SyscallAction {
	match ctx.syscall {
		Syscall::open | Syscall::openat => {
			// For open/openat, log the filename being opened
			let filepath = if ctx.syscall == Syscall::open {
				ctx.args.rdi as *const i8 // First arg for open is pathname
			} else {
				ctx.args.rsi as *const i8 // Second arg for openat is pathname
			};

			if !filepath.is_null() {
				let path = unsafe { CStr::from_ptr(filepath) }.to_string_lossy();
				let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
				println!(
					"[{}] {} syscall: path=\"{}\", flags=0x{:x}",
					timestamp,
					ctx.syscall.name(),
					path,
					if ctx.syscall == Syscall::open {
						ctx.args.rsi
					} else {
						ctx.args.rdx
					}
				);
			}
		},
		Syscall::read | Syscall::write => {
			// For read/write, log the file descriptor and buffer size
			let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
			println!(
				"[{}] {} syscall: fd={}, buffer=0x{:x}, size={}",
				timestamp,
				ctx.syscall.name(),
				ctx.args.rdi, // First arg is file descriptor
				ctx.args.rsi, // Second arg is buffer
				ctx.args.rdx
			); // Third arg is count
		},
		_ => {}, // Ignore other syscalls
	}

	// Allow all syscalls to proceed normally
	SyscallAction::Allow
}

// This is the entry point that will be called by the bootstrap loader
#[unsafe(no_mangle)]
pub extern "C" fn bootstrap_lazypoline() {
	println!("Initializing syscall logger...");

	// Set up the interposer with our handler
	match lazypoline_rs::new()
		.handler(LogInterestingSyscalls::new())
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

			println!("Syscall logger initialized successfully!");
			println!("Now logging open, openat, read, and write syscalls...");
		},
		Err(e) => {
			eprintln!("Failed to initialize syscall logger: {}", e);
			std::process::exit(1);
		},
	}
}
