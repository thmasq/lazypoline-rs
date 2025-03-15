//! Test program for lazypoline
//!
//! This program is similar to the `main.cpp` in the original C++ implementation.
//! It tests various syscalls and signal handling to verify that lazypoline
//! intercepts them correctly.
//!
//! Run it with:
//! ```bash
//! LIBLAZYPOLINE="path/to/liblazypoline.so" LD_PRELOAD="path/to/libbootstrap.so" cargo run --example test_lazypoline
//! ```

use std::process::exit;
use std::thread;
use std::time::Duration;

fn handle_sigfpe(_signo: i32) {
	eprintln!("Got a SIGFPE!");
}

fn handle_sigill(_signo: i32, _info: *mut libc::siginfo_t, _context: *mut libc::c_void) {
	eprintln!("Got a SIGILL!");

	// In a real handler, we'd modify RIP to skip past the illegal instruction
	// but for this simple test we'll just handle the signal
}

fn thread_start() {
	for i in 0..5 {
		eprintln!("Hello from thread {}!", i);
		thread::sleep(Duration::from_secs(1));
	}
}

fn main() {
	eprintln!("Hello world!");
	eprintln!("Hello world!");
	eprintln!("Hello world!");
	eprintln!("Bye bye now!");

	// Set up a signal handler for SIGFPE
	unsafe {
		// Register signal handler for SIGFPE
		let mut act: libc::sigaction = std::mem::zeroed();
		act.sa_sigaction = handle_sigfpe as usize;
		libc::sigemptyset(&mut act.sa_mask);
		assert_eq!(libc::sigaction(libc::SIGFPE, &act, std::ptr::null_mut()), 0);

		// Verify signal mask doesn't include SIGFPE
		let mut mask: libc::sigset_t = std::mem::zeroed();
		assert_eq!(libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask), 0);
		assert_eq!(libc::sigismember(&mask, libc::SIGFPE), 0);

		// Raise SIGFPE multiple times
		for _ in 0..6 {
			libc::raise(libc::SIGFPE);
		}
	}

	eprintln!("Good times!");

	// Set up a signal handler for SIGILL
	unsafe {
		// Register signal handler for SIGILL with SA_SIGINFO
		let mut act: libc::sigaction = std::mem::zeroed();
		act.sa_sigaction = handle_sigill as usize;
		act.sa_flags = libc::SA_SIGINFO;
		libc::sigemptyset(&mut act.sa_mask);
		assert_eq!(libc::sigaction(libc::SIGILL, &act, std::ptr::null_mut()), 0);

		// Verify the handler is registered
		let mut oldact: libc::sigaction = std::mem::zeroed();
		assert_eq!(libc::sigaction(libc::SIGILL, std::ptr::null(), &mut oldact), 0);
		assert_eq!(oldact.sa_sigaction, handle_sigill as usize);

		// This will trigger SIGILL (use it carefully)
		// libc::raise(libc::SIGILL);

		// Reset the handlers to default
		act.sa_sigaction = libc::SIG_DFL as usize;
		assert_eq!(libc::sigaction(libc::SIGILL, &act, std::ptr::null_mut()), 0);
		assert_eq!(libc::sigaction(libc::SIGFPE, &act, std::ptr::null_mut()), 0);
	}

	// Test VDSO syscalls
	unsafe {
		let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
		assert_eq!(libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t), 0);
		eprintln!("Current thread time: {}s, {}ns", t.tv_sec, t.tv_nsec);

		assert_eq!(libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t), 0);
		eprintln!("Current thread time: {}s, {}ns", t.tv_sec, t.tv_nsec);

		assert_eq!(libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t), 0);
		eprintln!("Current thread time: {}s, {}ns", t.tv_sec, t.tv_nsec);

		let mut cpu: libc::c_uint = 0;
		let mut node: libc::c_uint = 0;
		// SYS_getcpu is 309 on x86_64 Linux
		// Specify exact type for the null pointer to avoid the E0641 error
		let res = libc::syscall(
			libc::SYS_getcpu,
			&mut cpu as *mut libc::c_uint,
			&mut node as *mut libc::c_uint,
			std::ptr::null_mut::<libc::c_void>(),
		);
		assert_eq!(res, 0);
		eprintln!("Current CPU: {}, current NUMA node: {}", cpu, node);
	}

	// Test fork and thread creation
	unsafe {
		let pid = libc::fork();
		assert!(pid >= 0, "Fork failed");

		if pid == 0 {
			// Child process
			eprintln!("[{}] Child going to sleep!", libc::getpid());
			thread::sleep(Duration::from_secs(10));
			eprintln!("[{}] Child woke up!", libc::getpid());
			exit(0);
		} else {
			// Parent process
			eprintln!("[{}] Parent going to sleep!", libc::getpid());
			thread::sleep(Duration::from_secs(5));
			eprintln!("[{}] Parent woke up!", libc::getpid());
		}
	}

	// Test thread creation
	let handle = thread::spawn(move || {
		thread_start();
	});

	handle.join().unwrap();

	// Wait for child process
	unsafe {
		let mut status = 0;
		libc::wait(&mut status);
	}

	eprintln!("Test completed successfully!");
}
