use crate::ffi::{PR_SYS_DISPATCH_ON, get_gs_base, set_syscall_user_dispatch};
use crate::gsrel::{GSRelData, SUD_SELECTOR_OFFSET, set_privilege_level};
use crate::signal::SignalHandlers;
use libc::{SA_SIGINFO, SIGSYS, c_int};
use std::ffi::c_void;

const SYS_USER_DISPATCH: i32 = 2;

unsafe extern "C" fn handle_sigsys(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
	eprintln!("sigsys: Handling SIGSYS signal...");
	set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

	let sysinfo = unsafe { crate::ffi::SigSysInfo::from_siginfo(info) };

	// Verify this is a SUD-triggered SIGSYS
	assert_eq!(sig, SIGSYS);
	assert_eq!((unsafe { *sysinfo }).si_signo, SIGSYS);
	assert_eq!(
		(unsafe { *sysinfo }).si_code,
		SYS_USER_DISPATCH,
		"SUD does not support safely running non-SUD SIGSYS handlers!"
	);
	assert_eq!((unsafe { *sysinfo }).si_errno, 0);

	// In a real implementation, we'd need to rewrite the syscall instruction here
	// if it's not in the VDSO
	if crate::zpoline::REWRITE_TO_ZPOLINE {
		let syscall_addr = unsafe { ((*sysinfo).si_call_addr as *mut u16).offset(-1) };

		// Check if the syscall is in the VDSO (this is simplified)
		// In a real implementation, we'd need to check against the actual VDSO address range
		let vdso = get_vdso_location();
		if !vdso.contains((unsafe { *sysinfo }).si_call_addr as *mut u8) {
			unsafe { crate::zpoline::rewrite_syscall_inst(syscall_addr) };
		}
	}

	// Emulate the system call by invoking asm_syscall_hook
	// Set up the stack as if we were coming from the rewritten call
	let uctxt = unsafe { &mut *(context as *mut libc::ucontext_t) };
	let gregs = uctxt.uc_mcontext.gregs.as_mut_ptr();

	// Verify syscall number
	assert_eq!(
		unsafe { *gregs.add(libc::REG_RAX as usize) },
		(unsafe { *sysinfo }).si_syscall as i64
	);
	unsafe {
		eprintln!("sigsys: RAX (syscall number): {}", *gregs.add(libc::REG_RAX as usize));
		eprintln!("sigsys: RDI (arg1): 0x{:x}", *gregs.add(libc::REG_RDI as usize));
		eprintln!("sigsys: RSI (arg2): 0x{:x}", *gregs.add(libc::REG_RSI as usize));
		eprintln!("sigsys: RDX (arg3): 0x{:x}", *gregs.add(libc::REG_RDX as usize));
		eprintln!("sigsys: RSP: 0x{:x}", *gregs.add(libc::REG_RSP as usize));
		eprintln!("sigsys: RIP: 0x{:x}", *gregs.add(libc::REG_RIP as usize));
	}

	// Push RIP and RAX to set up stack for asm_syscall_hook
	unsafe {
		*gregs.add(libc::REG_RSP as usize) -= 2 * std::mem::size_of::<u64>() as i64;
		let stack_bottom = *gregs.add(libc::REG_RSP as usize) as *mut i64;
		*stack_bottom.add(1) = *gregs.add(libc::REG_RIP as usize);
		*stack_bottom = *gregs.add(libc::REG_RAX as usize);
	}
	// Set RIP to asm_syscall_hook
	unsafe extern "C" {
		fn asm_syscall_hook();
	}
	unsafe { *gregs.add(libc::REG_RIP as usize) = asm_syscall_hook as i64 };

	// Ensure rax still contains the syscall number
	assert_eq!(
		unsafe { *gregs.add(libc::REG_RAX as usize) },
		(unsafe { *sysinfo }).si_syscall as i64
	);

	eprintln!("sigsys: Handler completed, redirecting to asm_syscall_hook");
}

// Initialize SUD
pub unsafe fn init_sud() {
	// Map GSRelData structure
	let gsreldata = GSRelData::new();

	// Initialize the SUD selector
	set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

	// Allocate and initialize signal handlers
	let signal_handlers = SignalHandlers::new();
	unsafe { *(*gsreldata).signal_handlers.get() = signal_handlers };

	// Set up SIGSYS handler
	let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
	act.sa_sigaction = handle_sigsys as usize;
	act.sa_flags = SA_SIGINFO;
	unsafe { libc::sigemptyset(&mut act.sa_mask) };

	let result = unsafe { libc::sigaction(SIGSYS, &act, std::ptr::null_mut()) };
	assert_eq!(result, 0, "Failed to set up SIGSYS handler");
}

// Enable SUD
pub unsafe fn enable_sud() {
	eprintln!("sud: Enabling Syscall User Dispatch...");
	// Get the GS base address
	let gs_base = unsafe { get_gs_base() };
	eprintln!("sud: GS base address: 0x{:x}", gs_base);

	// Calculate address of the SUD selector
	let selector_addr = gs_base + SUD_SELECTOR_OFFSET as u64;
	eprintln!("sud: SUD selector address: 0x{:x}", selector_addr);

	// Enable SUD
	match set_syscall_user_dispatch(PR_SYS_DISPATCH_ON, selector_addr as *const u8) {
		Ok(_) => {
			eprintln!("sud: SUD enabled successfully");
		},
		Err(e) => {
			eprintln!("sud: Failed to enable Syscall User Dispatch: {}", e);
			panic!("Failed to enable SUD");
		},
	}
}

// Helper function to get VDSO location
struct VdsoLocation {
	start: *const u8,
	len: usize,
}

impl VdsoLocation {
	fn contains(&self, addr: *mut u8) -> bool {
		let addr = addr as usize;
		let start = self.start as usize;
		addr >= start && addr < start + self.len
	}
}

fn get_vdso_location() -> VdsoLocation {
	unsafe {
		// Get VDSO location from auxiliary vector
		let vdso_addr = libc::getauxval(libc::AT_SYSINFO_EHDR) as *const u8;
		assert!(!vdso_addr.is_null(), "Failed to get VDSO address");

		// Assume VDSO size is at least one page
		VdsoLocation {
			start: vdso_addr,
			len: 0x1000, // This is a simplification; real code would determine actual size
		}
	}
}
