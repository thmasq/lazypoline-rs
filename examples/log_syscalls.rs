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

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Enable logging
	env_logger::init();

	println!("Initializing syscall logger...");

	// Set up the interposer with our handler
	let _interposer = lazypoline_rs::new()
		.handler(LogInterestingSyscalls::new())
		.build()?
		.init()?;

	println!("Syscall logger initialized successfully!");
	println!("Now logging open, openat, read, and write syscalls...");
	println!("Press Ctrl+C to exit");

	// Keep the program running
	loop {
		std::thread::sleep(std::time::Duration::from_secs(60));
	}
}
