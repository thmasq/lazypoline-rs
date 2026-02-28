//! Syscall User Dispatch (SUD) implementation
//!
//! This module contains the implementation of the Syscall User Dispatch (SUD)
//! mechanism, which is used to intercept system calls in the kernel.

use crate::core::gsrel::{GSRelData, set_privilege_level};
use crate::core::signal::SignalHandlers;
use crate::ffi::{PR_SYS_DISPATCH_OFF, PR_SYS_DISPATCH_ON, get_gs_base, set_syscall_user_dispatch};
use crate::interposer::{InterposerError, Result};
use libc::{SA_SIGINFO, SIGSYS, c_int};
use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, error, info};

// This value is used to identify SIGSYS signals triggered by Syscall User Dispatch
const SYS_USER_DISPATCH: i32 = 2;

// Global state for the SUD system
static GLOBAL_STATE: OnceLock<SudState> = OnceLock::new();

// Counters for SUD statistics
struct SudState {
	initialized: bool,
	syscall_interceptions: AtomicUsize,
	vdso_syscalls: AtomicUsize,
	rewritten_syscalls: AtomicUsize,
}

impl SudState {
	const fn new() -> Self {
		Self {
			initialized: false,
			syscall_interceptions: AtomicUsize::new(0),
			vdso_syscalls: AtomicUsize::new(0),
			rewritten_syscalls: AtomicUsize::new(0),
		}
	}

	fn track_syscall_interception(&self) -> bool {
		let intercept_count = self.syscall_interceptions.fetch_add(1, Ordering::Relaxed) + 1;
		// Only log every 100th interception after the first 10 to avoid log spam
		intercept_count <= 10 || intercept_count % 100 == 0
	}

	fn track_vdso_syscall(&self) {
		self.vdso_syscalls.fetch_add(1, Ordering::Relaxed);
	}

	fn track_rewritten_syscall(&self) {
		self.rewritten_syscalls.fetch_add(1, Ordering::Relaxed);
	}

	fn get_stats(&self) -> (usize, usize, usize) {
		(
			self.syscall_interceptions.load(Ordering::Relaxed),
			self.vdso_syscalls.load(Ordering::Relaxed),
			self.rewritten_syscalls.load(Ordering::Relaxed),
		)
	}
}

/// Get or initialize the SUD state
fn get_state() -> &'static SudState {
	GLOBAL_STATE.get_or_init(SudState::new)
}

/// SUD SIGSYS handler
///
/// This is the handler that is called when a system call is intercepted.
/// It sets up the necessary state and redirects execution to the syscall handler.
unsafe extern "C" fn handle_sigsys(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
	let state = get_state();
	let should_log = state.track_syscall_interception();

	if should_log {
		debug!("sigsys: Handling SIGSYS signal...");
	}

	set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

	let sysinfo = unsafe { crate::ffi::SigSysInfo::from_siginfo(info) };
	unsafe {
		assert_eq!(sig, SIGSYS);
		assert_eq!((*sysinfo).si_signo, SIGSYS);
		assert_eq!(
			(*sysinfo).si_code,
			SYS_USER_DISPATCH,
			"SUD does not support safely running non-SUD SIGSYS handlers!"
		);
		assert_eq!((*sysinfo).si_errno, 0);
	}

	let syscall_num = unsafe { (*sysinfo).si_syscall };
	let call_addr = unsafe { (*sysinfo).si_call_addr };

	if should_log {
		debug!("sigsys: Intercepted syscall {syscall_num} at address {call_addr:p}");
	}

	// Check if the syscall is in the VDSO and rewrite if necessary
	unsafe {
		if crate::core::zpoline::REWRITE_TO_ZPOLINE {
			// Cast with the correct mutability for the required functions
			let syscall_addr = call_addr.cast::<u16>().offset(-1);
			let vdso = get_vdso_location();
			let in_vdso = vdso.contains(call_addr.cast::<u8>());

			if in_vdso {
				if should_log {
					debug!("sigsys: Not rewriting VDSO syscall at address {syscall_addr:p}");
				}
				state.track_vdso_syscall();
			} else {
				if should_log {
					debug!("sigsys: Rewriting non-VDSO syscall at address {syscall_addr:p}");
				}
				crate::core::zpoline::rewrite_syscall_inst(syscall_addr);
				state.track_rewritten_syscall();
			}
		}
	}

	let uctxt = unsafe { &mut *context.cast::<libc::ucontext_t>() };
	let gregs = uctxt.uc_mcontext.gregs.as_mut_ptr();

	unsafe {
		assert_eq!(*gregs.add(libc::REG_RAX as usize), i64::from((*sysinfo).si_syscall));
	}

	// // Log register values for debugging
	// unsafe {
	// 	if trace::enabled!(target: "lazypoline") {
	// 		trace!("sigsys: RAX (syscall number): {}", *gregs.add(libc::REG_RAX as usize));
	// 		trace!("sigsys: RDI (arg1): 0x{:x}", *gregs.add(libc::REG_RDI as usize));
	// 		trace!("sigsys: RSI (arg2): 0x{:x}", *gregs.add(libc::REG_RSI as usize));
	// 		trace!("sigsys: RDX (arg3): 0x{:x}", *gregs.add(libc::REG_RDX as usize));
	// 		trace!("sigsys: R10 (arg4): 0x{:x}", *gregs.add(libc::REG_R10 as usize));
	// 		trace!("sigsys: R8 (arg5): 0x{:x}", *gregs.add(libc::REG_R8 as usize));
	// 		trace!("sigsys: R9 (arg6): 0x{:x}", *gregs.add(libc::REG_R9 as usize));
	// 		trace!("sigsys: RSP: 0x{:x}", *gregs.add(libc::REG_RSP as usize));
	// 		trace!("sigsys: RIP: 0x{:x}", *gregs.add(libc::REG_RIP as usize));
	// 	}
	// }

	// Set up the stack for the asm_syscall_hook
	unsafe {
		// Push RIP and RAX to set up stack for asm_syscall_hook
		*gregs.add(libc::REG_RSP as usize) -= 2 * std::mem::size_of::<u64>() as i64;
		let stack_bottom = *gregs.add(libc::REG_RSP as usize) as *mut i64;

		*stack_bottom.add(1) = *gregs.add(libc::REG_RIP as usize);
		*stack_bottom = *gregs.add(libc::REG_RAX as usize);
	}

	// Redirect to asm_syscall_hook
	unsafe extern "C" {
		fn asm_syscall_hook();
	}
	unsafe { *gregs.add(libc::REG_RIP as usize) = asm_syscall_hook as *const () as i64 };

	debug!("sigsys: Handler completed, redirecting to asm_syscall_hook");
}

/// Initialize the Syscall User Dispatch (SUD) mechanism.
///
/// This function:
/// 1. Maps the `GSRelData` structure for thread-local storage
/// 2. Sets the initial privilege level
/// 3. Initializes signal handlers
/// 4. Sets up the SIGSYS handler for SUD
///
/// # Safety
///
/// This function is unsafe because it:
/// - Allocates and initializes process-wide state
/// - Sets up signal handlers that affect the entire process
/// - Must be called before enabling SUD
pub unsafe fn init_sud() -> Result<()> {
	info!("sud: Initializing Syscall User Dispatch (SUD)...");

	// Map GSRelData structure
	let gsreldata = unsafe { GSRelData::new() };
	if gsreldata.is_null() {
		return Err(InterposerError::MemoryAllocationFailed(
			"Failed to allocate GSRelData structure".into(),
		));
	}
	info!("sud: GSRelData mapped at address {gsreldata:p}");

	// Initialize the SUD selector - explicitly set to 0 (ALLOW)
	let selector_ptr = unsafe { (*gsreldata).sud_selector.get() };
	unsafe {
		*selector_ptr = crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW;
	}

	// Verify the selector is set properly
	let selector_value = unsafe { *selector_ptr };
	info!("sud: SUD selector initialized to {selector_value} (ALLOW)");

	// Allocate and initialize signal handlers
	let signal_handlers = unsafe { SignalHandlers::new() };
	if signal_handlers.is_null() {
		return Err(InterposerError::MemoryAllocationFailed(
			"Failed to allocate SignalHandlers structure".into(),
		));
	}
	info!("sud: SignalHandlers allocated at address {signal_handlers:p}");

	unsafe { *(*gsreldata).signal_handlers.get() = signal_handlers };
	info!("sud: SignalHandlers registered with GSRelData");

	// Set up SIGSYS handler
	let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
	act.sa_sigaction = handle_sigsys as *const () as usize;
	act.sa_flags = SA_SIGINFO;
	unsafe { libc::sigemptyset(&mut act.sa_mask) };

	let result = unsafe { libc::sigaction(SIGSYS, &act, std::ptr::null_mut()) };
	if result != 0 {
		return Err(InterposerError::SignalHandlerRegistrationFailed(format!(
			"Failed to set up SIGSYS handler: {}",
			std::io::Error::last_os_error()
		)));
	}
	info!("sud: SIGSYS handler registered successfully");

	// Verify the handler is properly registered
	let mut oldact: libc::sigaction = unsafe { std::mem::zeroed() };
	let result = unsafe { libc::sigaction(SIGSYS, std::ptr::null(), &mut oldact) };
	if result != 0 {
		return Err(InterposerError::SignalHandlerRegistrationFailed(format!(
			"Failed to verify SIGSYS handler: {}",
			std::io::Error::last_os_error()
		)));
	}

	if oldact.sa_sigaction != handle_sigsys as *const () as usize {
		return Err(InterposerError::SignalHandlerRegistrationFailed(format!(
			"SIGSYS handler mismatch: expected {:p}, got 0x{:x}",
			handle_sigsys as *mut c_void, oldact.sa_sigaction
		)));
	}
	info!("sud: SIGSYS handler verified");

	// Mark SUD as initialized
	let _state = get_state();
	let _ = GLOBAL_STATE.get_or_init(|| {
		let mut state = SudState::new();
		state.initialized = true;
		state
	});

	info!("sud: Initialization completed successfully");
	Ok(())
}

/// Print SUD statistics
pub fn print_sud_stats() {
	let state = get_state();
	let (interceptions, vdso_calls, rewritten) = state.get_stats();

	info!("SUD Statistics:");
	info!("  Total syscall interceptions: {interceptions}");
	info!("  VDSO syscalls (not rewritten): {vdso_calls}");
	info!("  Rewritten syscalls: {rewritten}");

	if interceptions > 0 {
		#[allow(clippy::cast_precision_loss)]
		let vdso_percent = (vdso_calls * 10000 / interceptions) as f64 / 100.0;
		#[allow(clippy::cast_precision_loss)]
		let rewritten_percent = (rewritten * 10000 / interceptions) as f64 / 100.0;

		info!("  VDSO syscalls: {vdso_percent:.2}%");
		info!("  Rewritten syscalls: {rewritten_percent:.2}%");
	}
}

/// Enable Syscall User Dispatch (SUD) for the current process.
///
/// This function activates the SUD mechanism, which causes the kernel
/// to check our SUD selector before executing syscalls and delivering
/// SIGSYS when blocked.
///
/// # Safety
///
/// This function is unsafe because it:
/// - Changes how syscalls are handled process-wide
/// - Relies on correctly initialized `GSRelData` and SUD
/// - Must have a valid SIGSYS handler set up
pub unsafe fn enable_sud() -> Result<()> {
	info!("sud: Enabling Syscall User Dispatch...");

	// Get the GS base address. This should have been set up by init_sud.
	let gs_base = unsafe { get_gs_base() };
	info!("sud: GS base address: 0x{gs_base:x}");

	// Calculate address of the SUD selector
	let selector_addr = gs_base + crate::core::gsrel::SUD_SELECTOR_OFFSET as u64;
	info!("sud: SUD selector address: 0x{selector_addr:x}");

	// Verify the selector address is accessible and has the right value
	let selector = unsafe { *(selector_addr as *const u8) };
	if selector != crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW {
		// Attempt to correct the value if it's wrong
		unsafe {
			*(selector_addr as *mut u8) = crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW;
		}
		info!(
			"sud: Corrected selector value to {} (ALLOW)",
			crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW
		);
	} else {
		info!("sud: Current selector value: {} (ALLOW)", selector);
	}

	// Enable SUD
	match set_syscall_user_dispatch(PR_SYS_DISPATCH_ON, selector_addr as *const u8) {
		Ok(()) => {
			info!("sud: SUD enabled successfully");

			// Register atexit handler to print statistics
			extern "C" fn print_stats_at_exit() {
				print_sud_stats();
			}

			unsafe {
				libc::atexit(print_stats_at_exit);
			}

			Ok(())
		},
		Err(e) => {
			if e.raw_os_error() == Some(libc::EPERM) {
				error!("Failed to enable SUD: Permission denied. Are you running with CAP_SYS_ADMIN or as root?");
				Err(InterposerError::MissingPrivileges(
					"Permission denied. Are you running with CAP_SYS_ADMIN or as root?".into(),
				))
			} else if e.raw_os_error() == Some(libc::ENOSYS) {
				error!("Failed to enable SUD: System call not implemented. Is your kernel version >= 5.11?");
				Err(InterposerError::SudNotSupported)
			} else {
				error!("Failed to enable SUD: {e}");
				Err(InterposerError::SudInitFailed(format!("{e}")))
			}
		},
	}
}

/// Disable Syscall User Dispatch (SUD) for the current process.
///
/// This function deactivates the SUD mechanism, allowing syscalls
/// to proceed normally without interception.
///
/// # Safety
///
/// This function is unsafe because it changes how syscalls are
/// handled process-wide.
pub unsafe fn disable_sud() -> Result<()> {
	info!("sud: Disabling Syscall User Dispatch...");

	match set_syscall_user_dispatch(PR_SYS_DISPATCH_OFF, std::ptr::null()) {
		Ok(()) => {
			info!("sud: SUD disabled successfully");
			Ok(())
		},
		Err(e) => {
			error!("Failed to disable SUD: {e}");
			Err(InterposerError::Io(e))
		},
	}
}

// Helper struct to track VDSO location
struct VdsoLocation {
	start: *const u8,
	len: usize,
}

// SAFETY: VDSO mapping is fixed for the lifetime of the process
unsafe impl Send for VdsoLocation {}
unsafe impl Sync for VdsoLocation {}

impl VdsoLocation {
	fn contains(&self, addr: *mut u8) -> bool {
		let addr = addr as usize;
		let start = self.start as usize;
		addr >= start && addr < start + self.len
	}
}

// Global VDSO location
static VDSO_LOCATION: std::sync::LazyLock<VdsoLocation> = std::sync::LazyLock::new(|| {
	#[repr(C)]
	struct Elf64Ehdr {
		e_ident: [u8; 16],
		e_type: u16,
		e_machine: u16,
		e_version: u32,
		e_entry: u64,
		e_phoff: u64,
		e_shoff: u64,
		e_flags: u32,
		e_ehsize: u16,
		e_phentsize: u16,
		e_phnum: u16,
		e_shentsize: u16,
		e_shnum: u16,
		e_shstrndx: u16,
	}

	#[repr(C)]
	struct Elf64Phdr {
		p_type: u32,
		p_flags: u32,
		p_offset: u64,
		p_vaddr: u64,
		p_paddr: u64,
		p_filesz: u64,
		p_memsz: u64,
		p_align: u64,
	}

	unsafe {
		// Get VDSO location from auxiliary vector
		let vdso_addr = libc::getauxval(libc::AT_SYSINFO_EHDR) as *const u8;
		assert!(!vdso_addr.is_null(), "Failed to get VDSO address");

		// Parse ELF header - Fix for pointer alignment issue
		let mut ehdr: Elf64Ehdr = std::mem::zeroed();
		std::ptr::copy_nonoverlapping(
			vdso_addr,
			(&raw mut ehdr).cast::<u8>(),
			std::mem::size_of::<Elf64Ehdr>(),
		);
		let hdr = &ehdr;

		// Verify this is a valid ELF header
		assert_eq!(&hdr.e_ident[..4], b"\x7fELF", "Invalid ELF header in VDSO");

		// Calculate program header table address
		let e_phoff = usize::try_from(hdr.e_phoff).expect("Program header offset too large for usize");
		let phdr = (vdso_addr as usize + e_phoff) as *const Elf64Phdr;

		// Find the highest address in any segment to determine total size
		let mut max_addr = 0;

		for i in 0..hdr.e_phnum as usize {
			let entry = &*phdr.add(i);
			// Only consider PT_LOAD segments (loadable segments)
			if entry.p_type == 1 {
				// PT_LOAD = 1
				let segment_end = entry.p_vaddr + entry.p_memsz;
				let segment_end_usize = usize::try_from(segment_end).expect("Segment end address too large for usize");

				if segment_end_usize > max_addr {
					max_addr = segment_end_usize;
				}
			}
		}

		// Calculate full size (offset from start of VDSO)
		let vdso_size = max_addr - vdso_addr as usize;

		debug!("sud: VDSO location: {vdso_addr:p}, size: 0x{vdso_size:x} (parsed from ELF headers)");

		VdsoLocation {
			start: vdso_addr,
			len: vdso_size,
		}
	}
});

// Helper function to get VDSO location
fn get_vdso_location() -> &'static VdsoLocation {
	&VDSO_LOCATION
}
