use crate::ffi::{PR_SYS_DISPATCH_ON, get_gs_base, set_syscall_user_dispatch};
use crate::gsrel::{GSRelData, SUD_SELECTOR_OFFSET, set_privilege_level};
use crate::signal::SignalHandlers;
use libc::{SA_SIGINFO, SIGSYS, c_int};
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, error, info, trace};

// This value is used to identify SIGSYS signals triggered by Syscall User Dispatch
const SYS_USER_DISPATCH: i32 = 2;

// Counters for SUD statistics
static SYSCALL_INTERCEPTIONS: AtomicUsize = AtomicUsize::new(0);
static VDSO_SYSCALLS: AtomicUsize = AtomicUsize::new(0);
static REWRITTEN_SYSCALLS: AtomicUsize = AtomicUsize::new(0);

fn track_syscall_interception() -> bool {
	let intercept_count = SYSCALL_INTERCEPTIONS.fetch_add(1, Ordering::Relaxed) + 1;
	// Only log every 100th interception after the first 10 to avoid log spam
	intercept_count <= 10 || intercept_count % 100 == 0
}

unsafe fn verify_sigsys_info(sig: c_int, sysinfo: *const crate::ffi::SigSysInfo) {
	assert_eq!(sig, SIGSYS);
	assert_eq!((unsafe { *sysinfo }).si_signo, SIGSYS);
	assert_eq!(
		(unsafe { *sysinfo }).si_code,
		SYS_USER_DISPATCH,
		"SUD does not support safely running non-SUD SIGSYS handlers!"
	);
	assert_eq!((unsafe { *sysinfo }).si_errno, 0);
}

unsafe fn handle_zpoline_rewriting(call_addr: *const c_void, should_log: bool) {
	if !crate::zpoline::REWRITE_TO_ZPOLINE {
		return;
	}

	// Cast with the correct mutability for the required functions
	let syscall_addr = unsafe { call_addr.cast::<u16>().offset(-1) }.cast_mut();
	let vdso = get_vdso_location();
	let in_vdso = vdso.contains(call_addr.cast::<u8>().cast_mut());

	if in_vdso {
		if should_log {
			debug!("sigsys: Not rewriting VDSO syscall at address {syscall_addr:p}");
		}
		VDSO_SYSCALLS.fetch_add(1, Ordering::Relaxed);
	} else {
		if should_log {
			debug!("sigsys: Rewriting non-VDSO syscall at address {syscall_addr:p}");
		}
		unsafe { crate::zpoline::rewrite_syscall_inst(syscall_addr) };
		REWRITTEN_SYSCALLS.fetch_add(1, Ordering::Relaxed);
	}
}

unsafe fn log_register_values(gregs: *mut i64) {
	unsafe {
		trace!("sigsys: RAX (syscall number): {}", *gregs.add(libc::REG_RAX as usize));
		trace!("sigsys: RDI (arg1): 0x{:x}", *gregs.add(libc::REG_RDI as usize));
		trace!("sigsys: RSI (arg2): 0x{:x}", *gregs.add(libc::REG_RSI as usize));
		trace!("sigsys: RDX (arg3): 0x{:x}", *gregs.add(libc::REG_RDX as usize));
		trace!("sigsys: R10 (arg4): 0x{:x}", *gregs.add(libc::REG_R10 as usize));
		trace!("sigsys: R8 (arg5): 0x{:x}", *gregs.add(libc::REG_R8 as usize));
		trace!("sigsys: R9 (arg6): 0x{:x}", *gregs.add(libc::REG_R9 as usize));
		trace!("sigsys: RSP: 0x{:x}", *gregs.add(libc::REG_RSP as usize));
		trace!("sigsys: RIP: 0x{:x}", *gregs.add(libc::REG_RIP as usize));
	}
}

unsafe fn setup_stack_for_syscall_hook(gregs: *mut i64) {
	// Push RIP and RAX to set up stack for asm_syscall_hook
	unsafe {
		*gregs.add(libc::REG_RSP as usize) -= 2 * std::mem::size_of::<u64>() as i64;
		let stack_bottom = *gregs.add(libc::REG_RSP as usize) as *mut i64;

		*stack_bottom.add(1) = *gregs.add(libc::REG_RIP as usize);
		*stack_bottom = *gregs.add(libc::REG_RAX as usize);
	}
}

// SIGSYS handler for intercepted system calls
// This is called by the kernel when a system call is intercepted by SUD
unsafe extern "C" fn handle_sigsys(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
	let should_log = track_syscall_interception();

	if should_log {
		debug!("sigsys: Handling SIGSYS signal...");
	}

	set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

	let sysinfo = unsafe { crate::ffi::SigSysInfo::from_siginfo(info) };
	unsafe { verify_sigsys_info(sig, sysinfo) };

	let syscall_num = (unsafe { *sysinfo }).si_syscall;
	let call_addr = (unsafe { *sysinfo }).si_call_addr;

	if should_log {
		debug!("sigsys: Intercepted syscall {syscall_num} at address {call_addr:p}");
	}

	unsafe { handle_zpoline_rewriting(call_addr, should_log) };

	let uctxt = unsafe { &mut *context.cast::<libc::ucontext_t>() };
	let gregs = uctxt.uc_mcontext.gregs.as_mut_ptr();

	assert_eq!(
		unsafe { *gregs.add(libc::REG_RAX as usize) },
		i64::from((unsafe { *sysinfo }).si_syscall)
	);

	unsafe { log_register_values(gregs) };

	unsafe { setup_stack_for_syscall_hook(gregs) };

	#[allow(clippy::items_after_statements)]
	unsafe extern "C" {
		fn asm_syscall_hook();
	}
	unsafe { *gregs.add(libc::REG_RIP as usize) = asm_syscall_hook as i64 };

	assert_eq!(
		unsafe { *gregs.add(libc::REG_RAX as usize) },
		i64::from((unsafe { *sysinfo }).si_syscall)
	);

	debug!("sigsys: Handler completed, redirecting to asm_syscall_hook");
}

/// Initializes the Syscall User Dispatch (SUD) mechanism.
///
/// This function:
/// 1. Maps the `GSRelData` structure for thread-local storage
/// 2. Sets the initial privilege level
/// 3. Initializes signal handlers
/// 4. Sets up the SIGSYS handler for SUD
///
/// # Panics
///
/// Panics if:
/// - `GSRelData` allocation fails
/// - Signal handler setup fails
///
/// # Safety
///
/// This function is unsafe because it:
/// - Allocates and initializes process-wide state
/// - Sets up signal handlers that affect the entire process
/// - Must be called before enabling SUD
pub unsafe fn init_sud() {
	info!("sud: Initializing Syscall User Dispatch (SUD)...");

	// Map GSRelData structure
	let gsreldata = GSRelData::new();
	assert!(!gsreldata.is_null(), "Failed to allocate GSRelData structure");
	info!("sud: GSRelData mapped at address {gsreldata:p}");

	// Initialize the SUD selector
	set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);
	info!("sud: SUD selector initialized to ALLOW");

	// Allocate and initialize signal handlers
	let signal_handlers = SignalHandlers::new();
	assert!(
		!signal_handlers.is_null(),
		"Failed to allocate SignalHandlers structure"
	);
	info!("sud: SignalHandlers allocated at address {signal_handlers:p}");

	unsafe { *(*gsreldata).signal_handlers.get() = signal_handlers };
	info!("sud: SignalHandlers registered with GSRelData");

	// Set up SIGSYS handler
	let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
	act.sa_sigaction = handle_sigsys as usize;
	act.sa_flags = SA_SIGINFO;
	unsafe { libc::sigemptyset(&mut act.sa_mask) };

	let result = unsafe { libc::sigaction(SIGSYS, &act, std::ptr::null_mut()) };
	assert_eq!(
		result,
		0,
		"Failed to set up SIGSYS handler: {}",
		std::io::Error::last_os_error()
	);
	info!("sud: SIGSYS handler registered successfully");

	// Verify the handler is properly registered
	let mut oldact: libc::sigaction = unsafe { std::mem::zeroed() };
	let result = unsafe { libc::sigaction(SIGSYS, std::ptr::null(), &mut oldact) };
	assert_eq!(
		result,
		0,
		"Failed to verify SIGSYS handler: {}",
		std::io::Error::last_os_error()
	);
	assert_eq!(
		oldact.sa_sigaction, handle_sigsys as usize,
		"SIGSYS handler mismatch: expected {:p}, got 0x{:x}",
		handle_sigsys as *mut c_void, oldact.sa_sigaction
	);
	info!("sud: SIGSYS handler verified");

	info!("sud: Initialization completed successfully");
}

// Enable SUD by setting the PR_SET_SYSCALL_USER_DISPATCH prctl
// This tells the kernel to intercept system calls and send SIGSYS
// Print SUD statistics
pub fn print_sud_stats() {
	let interceptions = SYSCALL_INTERCEPTIONS.load(Ordering::Relaxed);
	let vdso_calls = VDSO_SYSCALLS.load(Ordering::Relaxed);
	let rewritten = REWRITTEN_SYSCALLS.load(Ordering::Relaxed);

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

/// Enables Syscall User Dispatch (SUD) for the current process.
///
/// This function activates the SUD mechanism, which causes the kernel
/// to check our SUD selector before executing syscalls and delivering
/// SIGSYS when blocked.
///
/// # Panics
///
/// Panics if:
/// - The prctl call to enable SUD fails
/// - GS base register cannot be accessed
///
/// # Safety
///
/// This function is unsafe because it:
/// - Changes how syscalls are handled process-wide
/// - Relies on correctly initialized `GSRelData` and SUD
/// - Must have a valid SIGSYS handler set up
pub unsafe fn enable_sud() {
	info!("sud: Enabling Syscall User Dispatch...");

	// Get the GS base address. This should have been set up by init_sud.
	let gs_base = unsafe { get_gs_base() };
	info!("sud: GS base address: 0x{gs_base:x}");

	// Calculate address of the SUD selector
	let selector_addr = gs_base + SUD_SELECTOR_OFFSET as u64;
	info!("sud: SUD selector address: 0x{selector_addr:x}");

	// Verify the selector address is accessible
	let selector = unsafe { *(selector_addr as *const u8) };
	info!("sud: Current selector value: {selector}");

	// Enable SUD
	match set_syscall_user_dispatch(PR_SYS_DISPATCH_ON, selector_addr as *const u8) {
		Ok(()) => {
			info!("sud: SUD enabled successfully");

			#[allow(clippy::items_after_statements)]
			extern "C" fn print_stats_at_exit() {
				print_sud_stats();
			}

			unsafe {
				libc::atexit(print_stats_at_exit);
			}
		},
		Err(e) => {
			if e.raw_os_error() == Some(libc::EPERM) {
				error!("Failed to enable SUD: Permission denied. Are you running with CAP_SYS_ADMIN or as root?");
				panic!("Failed to enable SUD: Permission denied. Are you running with CAP_SYS_ADMIN or as root?");
			} else if e.raw_os_error() == Some(libc::ENOSYS) {
				error!("Failed to enable SUD: System call not implemented. Is your kernel version >= 5.11?");
				panic!("Failed to enable SUD: System call not implemented. Is your kernel version >= 5.11?");
			} else {
				error!("Failed to enable SUD: {e}");
				panic!("Failed to enable SUD: {e}");
			}
		},
	}
}

// ELF64 header format
#[repr(C)]
#[allow(clippy::struct_field_names)]
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

// ELF64 program header format
#[repr(C)]
#[allow(clippy::struct_field_names)]
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

// Helper struct to track VDSO location with caching
struct VdsoLocation {
	start: *const u8,
	len: usize,
}

// SAFETY: VDSO mapping is fixed for the lifetime of the process and
// shared among all threads, so it's safe to share these pointers
unsafe impl Send for VdsoLocation {}
unsafe impl Sync for VdsoLocation {}

impl VdsoLocation {
	fn contains(&self, addr: *mut u8) -> bool {
		let addr = addr as usize;
		let start = self.start as usize;
		addr >= start && addr < start + self.len
	}
}

static VDSO_LOCATION: once_cell::sync::Lazy<VdsoLocation> = once_cell::sync::Lazy::new(|| {
	unsafe {
		// Get VDSO location from auxiliary vector
		let vdso_addr = libc::getauxval(libc::AT_SYSINFO_EHDR) as *const u8;
		assert!(!vdso_addr.is_null(), "Failed to get VDSO address");

		// Parse ELF header - Fix for pointer alignment issue
		// Create a properly aligned copy of the ELF header
		let mut ehdr: Elf64Ehdr = std::mem::zeroed();
		std::ptr::copy_nonoverlapping(
			vdso_addr,
			(&raw mut ehdr).cast::<u8>(),
			std::mem::size_of::<Elf64Ehdr>(),
		);
		let hdr = &ehdr;

		// Verify this is a valid ELF header
		assert_eq!(&hdr.e_ident[..4], b"\x7fELF", "Invalid ELF header in VDSO");

		// Calculate program header table address - Fix for possible truncation
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

// Helper function to get VDSO location (cached)
fn get_vdso_location() -> &'static VdsoLocation {
	&VDSO_LOCATION
}
