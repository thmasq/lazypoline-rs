use lazypoline_rs::{self, Syscall, SyscallAction};
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Custom version string to inject
const FAKE_VERSION: &str = "Fake OS v42.0-1337 (LazyPoline Build) + Gah Nuh Utils 7.7-custom #1 SMP Nope\n";

/// Struct to track open file descriptors
struct FdTracker {
	/// Maps file descriptors to path information
	fd_to_path: HashMap<RawFd, String>,
}

impl FdTracker {
	fn new() -> Self {
		Self {
			fd_to_path: HashMap::new(),
		}
	}

	fn track_open(&mut self, fd: RawFd, path: &str) {
		if fd >= 0 {
			self.fd_to_path.insert(fd, path.to_string());
		}
	}

	fn is_proc_version(&self, fd: RawFd) -> bool {
		self.fd_to_path
			.get(&fd)
			.map(|path| path == "/proc/version")
			.unwrap_or(false)
	}

	fn remove_fd(&mut self, fd: RawFd) {
		self.fd_to_path.remove(&fd);
	}
}

/// Handler for overriding /proc/version
#[lazypoline_rs::syscall_handler]
fn override_proc_version(ctx: &mut SyscallContext) -> SyscallAction {
	// Create a static tracker for file descriptors
	static FD_TRACKER: once_cell::sync::Lazy<Arc<Mutex<FdTracker>>> =
		once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(FdTracker::new())));

	match ctx.syscall {
		Syscall::open | Syscall::openat => {
			// Track open attempts to /proc/version
			let filepath = if ctx.syscall == Syscall::open {
				ctx.args.rdi as *const i8 // First arg for open is pathname
			} else {
				ctx.args.rsi as *const i8 // Second arg for openat is pathname
			};

			if !filepath.is_null() {
				let path_str = unsafe { CStr::from_ptr(filepath) }.to_string_lossy();
				let path = Path::new(path_str.as_ref());

				// Check if opening /proc/version
				if path.ends_with("/proc/version") || path_str == "/proc/version" {
					// Allow the open, but track the returned fd
					println!("Detected open of /proc/version");

					// Remember to track this file descriptor after syscall completes
					let path_copy = path_str.to_string();
					let tracker = FD_TRACKER.clone();

					// Define a callback to run after the syscall
					// (This is not directly supported by lazypoline, so we'll work around it)
					std::thread::spawn(move || {
						// Sleep briefly to ensure the syscall completes
						std::thread::sleep(std::time::Duration::from_millis(1));

						// Try to find fd in /proc/self/fd directory
						if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
							for entry in entries.flatten() {
								if let Ok(target) = std::fs::read_link(entry.path()) {
									if target.to_string_lossy() == "/proc/version" {
										if let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() {
											println!("Tracking /proc/version with fd {}", fd);
											let mut tracker_lock = tracker.lock().unwrap();
											tracker_lock.track_open(fd, &path_copy);
										}
									}
								}
							}
						}
					});
				}
			}
		},
		Syscall::close => {
			// Remove tracking for closed file descriptors
			let fd = ctx.args.rdi as RawFd;
			let mut tracker = FD_TRACKER.lock().unwrap();
			if tracker.is_proc_version(fd) {
				println!("Closed /proc/version (fd={})", fd);
			}
			tracker.remove_fd(fd);
		},
		Syscall::read => {
			// Check if this is reading from /proc/version
			let fd = ctx.args.rdi as RawFd;
			let tracker = FD_TRACKER.lock().unwrap();

			if tracker.is_proc_version(fd) {
				println!("Intercepting read from /proc/version (fd={})", fd);

				// Get the buffer and its size
				let buf = ctx.args.rsi as *mut u8;
				let count = ctx.args.rdx as usize;

				if !buf.is_null() && count > 0 {
					// Copy our fake version string to the buffer
					let fake_bytes = FAKE_VERSION.as_bytes();
					let to_copy = std::cmp::min(fake_bytes.len(), count);

					unsafe {
						std::ptr::copy_nonoverlapping(fake_bytes.as_ptr(), buf, to_copy);
					}

					// Return the number of bytes we wrote
					return SyscallAction::Block(to_copy as i64);
				}
			}
		},
		_ => {}, // Ignore other syscalls
	}

	// Allow the syscall to proceed normally
	SyscallAction::Allow
}

// This is the entry point that will be called by the bootstrap loader
#[unsafe(no_mangle)]
pub extern "C" fn bootstrap_lazypoline() {
	// Initialize logging
	env_logger::init();

	println!("Initializing /proc/version override...");
	println!("Will replace /proc/version with: {}", FAKE_VERSION);

	// Set up the interposer with our override handler
	match lazypoline_rs::new()
		.handler(OverrideProcVersion::new())
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

			println!("Override initialized successfully!");
			println!("Try running: cat /proc/version");
		},
		Err(e) => {
			eprintln!("Failed to initialize proc version override: {}", e);
			std::process::exit(1);
		},
	}
}
