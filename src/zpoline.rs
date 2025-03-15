use crate::ffi::{SpinLock, SpinLockGuard, align_down, mmap_at_addr, mprotect_raw};
use libc::{MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use std::ffi::c_void;
use std::ptr::null_mut;
use std::slice;
use tracing::{debug, error, trace};

unsafe extern "C" {
	pub fn asm_syscall_hook();
}

static REWRITE_LOCK: SpinLock = SpinLock::new();

pub const REWRITE_TO_ZPOLINE: bool = true;
#[allow(dead_code)]
const PRINT_SYSCALLS: bool = true;
#[allow(dead_code)]
const SAVE_VECTOR_REGS: bool = true;
#[allow(dead_code)]
const RETURN_IMMEDIATELY: bool = false;
const COMPAT_NONDEP_APP: bool = false;

/// Initializes the zpoline mechanism for efficient syscall interposition.
///
/// This function:
/// 1. Maps the zero page in memory (requires `mmap_min_addr=0`)
/// 2. Sets up syscall trampolines in the zero page
/// 3. Creates a jump to the `asm_syscall_hook` function
/// 4. Makes the zero page executable
///
/// The zpoline mechanism works by rewriting syscall instructions to
/// `call [rax+0]`, which jumps through the zero page to our hook.
///
/// # Returns
///
/// Ok(()) on success, or Err with an error message on failure
///
/// # Safety
///
/// This function is unsafe because it:
/// - Maps memory at address 0 (requires kernel configuration)
/// - Creates executable memory
/// - Modifies global process state
/// - Must be called before any syscalls are intercepted
pub unsafe fn init_zpoline() -> Result<(), &'static str> {
	debug!("zpoline: Initializing zpoline mechanism...");
	debug!("zpoline: Attempting to map zero page...");

	let zeropage = unsafe {
		mmap_at_addr(
			null_mut(),
			0x1000,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
			-1,
			0,
		)
	};

	if zeropage == libc::MAP_FAILED.cast::<c_void>() {
		error!(
			"zpoline: Error: Failed to map zero page with MAP_FIXED: {}",
			std::io::Error::last_os_error()
		);
		error!("zpoline: Please ensure /proc/sys/vm/mmap_min_addr is set to 0");
		return Err("Failed to map zero page");
	}

	debug!("zpoline: Zero page mapped successfully at address {zeropage:p}");

	const NUM_SYSCALLS: usize = 512;

	let zeropage_slice = unsafe { slice::from_raw_parts_mut(zeropage.cast::<u8>(), 0x1000) };

	debug!("zpoline: Setting up syscall trampolines...");

	for i in 0..NUM_SYSCALLS {
		assert_eq!(NUM_SYSCALLS, 512);

		if i >= 0x19b {
			if i % 2 == 0 {
				zeropage_slice[i] = 0x66; // Single-byte NOP
			} else {
				zeropage_slice[i] = 0x90; // Start of 2-byte NOP
			}
		} else {
			match i % 3 {
				0 => zeropage_slice[i] = 0xeb, // RIP += 0x66 (short jump) to next short jump
				1 => zeropage_slice[i] = 0x66, // 2-byte NOP -> short jump
				2 => zeropage_slice[i] = 0x90, // Single-byte NOP -> short jump
				_ => unreachable!(),
			}
		}
	}

	debug!("zpoline: Setting up trampoline to asm_syscall_hook...");

	// Set up trampoline code to jump to asm_syscall_hook
	// Code sequence:
	// push   %rax               (0x50)
	// movabs asm_syscall_hook, %rax (0x48 0xb8 [64-bit addr])
	// jmpq   *%rax             (0xff 0xe0)

	// Save %rax on stack
	zeropage_slice[NUM_SYSCALLS] = 0x50;

	// movabs asm_syscall_hook, %rax
	zeropage_slice[NUM_SYSCALLS + 0x1] = 0x48;
	zeropage_slice[NUM_SYSCALLS + 0x2] = 0xb8;

	// 64-bit address of asm_syscall_hook, byte by byte
	let hook_addr = asm_syscall_hook as usize;
	debug!("zpoline: asm_syscall_hook at address 0x{hook_addr:x}");

	zeropage_slice[NUM_SYSCALLS + 0x3] = hook_addr as u8;
	zeropage_slice[NUM_SYSCALLS + 0x4] = (hook_addr >> 8) as u8;
	zeropage_slice[NUM_SYSCALLS + 0x5] = (hook_addr >> (8 * 2)) as u8;
	zeropage_slice[NUM_SYSCALLS + 0x6] = (hook_addr >> (8 * 3)) as u8;
	zeropage_slice[NUM_SYSCALLS + 0x7] = (hook_addr >> (8 * 4)) as u8;
	zeropage_slice[NUM_SYSCALLS + 0x8] = (hook_addr >> (8 * 5)) as u8;
	zeropage_slice[NUM_SYSCALLS + 0x9] = (hook_addr >> (8 * 6)) as u8;
	zeropage_slice[NUM_SYSCALLS + 0xa] = (hook_addr >> (8 * 7)) as u8;

	// jmpq *%rax
	zeropage_slice[NUM_SYSCALLS + 0xb] = 0xff;
	zeropage_slice[NUM_SYSCALLS + 0xc] = 0xe0;

	debug!("zpoline: Making zero page executable...");

	// Make the page executable (also read-only)
	// PROT_EXEC alone gives XOM (execute-only memory)
	let result = unsafe { mprotect_raw(zeropage, 0x1000, PROT_READ | PROT_EXEC) };
	if result != 0 {
		error!(
			"zpoline: Error: Failed to mark zero page as executable: {}",
			std::io::Error::last_os_error()
		);
		return Err("Failed to mark zero page as executable");
	}

	debug!("zpoline: Initialization completed successfully");
	Ok(())
}

/// Handles a syscall that was redirected via the zpoline mechanism.
///
/// This function is called from the assembly hook (`asm_syscall_hook`) when
/// a rewritten syscall instruction is executed. It forwards the syscall
/// to `syscall_emulate` for actual handling.
///
/// # Parameters
///
/// * `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` - The syscall arguments
/// * `rax` - The syscall number
/// * `rip_after_syscall` - The instruction pointer after the syscall
/// * `should_emulate` - Output parameter that indicates special handling
///
/// # Returns
///
/// The result of the syscall
///
/// # Safety
///
/// This function is unsafe because it:
/// - Is called directly from assembly
/// - Handles raw syscall arguments
/// - Modifies thread state
/// - Must maintain specific register state
#[unsafe(no_mangle)]
pub extern "C" fn zpoline_syscall_handler(
	rdi: i64,
	rsi: i64,
	rdx: i64,
	r10: i64,
	r8: i64,
	r9: i64,
	rax: i64,
	rip_after_syscall: i64,
	should_emulate: *mut u64,
) -> i64 {
	let _ = rip_after_syscall;
	crate::lazypoline::syscall_emulate(rax, rdi, rsi, rdx, r10, r8, r9, should_emulate)
}

/// Rewrites a syscall instruction to use the zpoline mechanism.
///
/// This function modifies a syscall instruction (0x0F05) to a call-near [rax+0]
/// instruction (0xD0FF), which redirects execution through the zero page
/// to our hook function.
///
/// # Parameters
///
/// * `syscall_addr` - Pointer to the syscall instruction to rewrite
///
/// # Panics
///
/// Panics if:
/// - Memory protection cannot be changed
/// - The syscall instruction cannot be rewritten
///
/// # Safety
///
/// This function is unsafe because it:
/// - Modifies executable code at runtime
/// - Changes memory protection settings
/// - Must be called with a valid syscall instruction address
/// - Must be synchronized with execution (instruction must not be executing)
pub unsafe fn rewrite_syscall_inst(syscall_addr: *mut u16) {
	debug!("zpoline: Rewriting syscall at address {syscall_addr:p}");

	let syscall_page = align_down(syscall_addr as usize, 0x1000) as *mut c_void;

	let _guard = SpinLockGuard::new(&REWRITE_LOCK);

	if unsafe { *syscall_addr } == 0xD0FF {
		debug!("zpoline: Syscall already rewritten, skipping");
		return;
	}

	let mut perms = PROT_WRITE | PROT_EXEC;
	if COMPAT_NONDEP_APP {
		perms |= PROT_READ;
	}

	debug!("zpoline: Setting page permissions to allow writing");

	let result = unsafe { mprotect_raw(syscall_page, 0x1000, perms) };
	if result != 0 {
		error!(
			"zpoline: Error: Failed to make syscall page writable: {}",
			std::io::Error::last_os_error()
		);
		panic!("Failed to make syscall page writable");
	}

	trace!(
		"zpoline: Original instruction at {:p}: 0x{:04x}",
		syscall_addr,
		unsafe { *syscall_addr }
	);

	// Rewrite syscall (0x0F05) to call-near [rax+0] (0xD0FF)
	unsafe { *syscall_addr = 0xD0FF };

	debug!("zpoline: Instruction rewritten to 0xD0FF (call-near [rax+0])");

	// Restore original permissions if not in compatibility mode
	if !COMPAT_NONDEP_APP {
		debug!("zpoline: Restoring page permissions");
		let result = unsafe { mprotect_raw(syscall_page, 0x1000, PROT_READ | PROT_EXEC) };
		if result != 0 {
			error!(
				"zpoline: Error: Failed to restore syscall page permissions: {}",
				std::io::Error::last_os_error()
			);
			panic!("Failed to restore syscall page permissions");
		}
	}
}
