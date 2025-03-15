use crate::ffi::{CLONE_VFORK, CLONE_VM, SIGCHLD};
use crate::gsrel::{GSRelData, set_privilege_level};
use crate::signal::SignalHandlers;
use crate::sud::enable_sud;

const CLONE_SIGHAND: u64 = 0x00000800;

#[unsafe(no_mangle)]
pub extern "C" fn setup_new_thread(clone_flags: u64) {
	unsafe {
		let cloner_gsrel = crate::gsrel::GSRelData::new();

		let gsreldata = GSRelData::new();
		set_privilege_level(crate::ffi::SYSCALL_DISPATCH_FILTER_ALLOW);

		let cloner_signal_handlers = *(*cloner_gsrel).signal_handlers.get();

		if clone_flags & CLONE_SIGHAND != 0 {
			*(*gsreldata).signal_handlers.get() = cloner_signal_handlers;
		} else {
			let new_handlers = SignalHandlers::new();
			// This would normally copy the signal handlers, but we'll simplify for now
			*(*gsreldata).signal_handlers.get() = new_handlers;
		}

		enable_sud();
	}
}

#[unsafe(no_mangle)]
pub extern "C" fn setup_vforked_child() {
	setup_new_thread(CLONE_VM | CLONE_VFORK | SIGCHLD as u64);
}
