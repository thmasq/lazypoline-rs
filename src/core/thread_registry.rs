//! Thread registry for lazypoline
//!
//! This module provides a framework-wide registry for tracking threads
//! and their associated `GSRelData` pointers. It enables proper handling of
//! parent-child thread relationships, thread-local state, and cleanup.

use crate::core::gsrel::GSRelData;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::debug;

/// Helper function to reliably get the current OS-level thread ID.
/// This avoids reading uninitialized user-space TLS after a raw clone syscall.
#[inline]
fn get_current_os_tid() -> libc::pid_t {
	unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
}

/// Information about a registered thread
#[derive(Debug)]
pub struct ThreadInfo {
	/// The OS-level thread ID (TID)
	pub thread_id: libc::pid_t,

	/// The process ID (for vfork tracking)
	pub process_id: libc::pid_t,

	/// The parent thread's ID (if known)
	pub parent_thread_id: Option<libc::pid_t>,

	/// Pointer to the thread's `GSRelData`
	pub gsreldata: *mut GSRelData,

	/// Creation time of the thread
	pub creation_time: std::time::Instant,

	/// Clone flags used to create this thread
	pub clone_flags: Option<u64>,
}

// SAFETY: We're telling the compiler that ThreadInfo can be safely shared between threads.
// This is safe because:
// 1. GSRelData pointers are used as identifiers, not for direct mutation across threads
// 2. Each thread has its own GSRelData in thread-local storage
// 3. All actual mutation operations are properly synchronized with locks
// 4. When we do modify across threads (e.g. in signal handlers), we use proper synchronization
unsafe impl Send for ThreadInfo {}
unsafe impl Sync for ThreadInfo {}

impl ThreadInfo {
	/// Check if this is a thread (vs a process)
	#[must_use]
	pub const fn is_thread(&self) -> bool {
		if let Some(flags) = self.clone_flags {
			(flags & crate::ffi::CLONE_THREAD) != 0
		} else {
			// Default to true if we don't know
			true
		}
	}

	/// Check if this thread shares signal handlers with its parent
	#[must_use]
	pub const fn shares_signal_handlers(&self) -> bool {
		if let Some(flags) = self.clone_flags {
			(flags & crate::ffi::CLONE_SIGHAND as u64) != 0
		} else {
			// Default to false if we don't know
			false
		}
	}

	/// Check if this is a vfork child
	#[must_use]
	pub const fn is_vfork_child(&self) -> bool {
		if let Some(flags) = self.clone_flags {
			(flags & crate::ffi::CLONE_VFORK) != 0
		} else {
			false
		}
	}
}

/// Thread registry singleton
///
/// This structure maintains a global registry of all threads and their
/// associated `GSRelData` pointers for the entire framework.
pub struct ThreadRegistry {
	/// Map of OS thread IDs (TID) to thread information
	threads: RwLock<HashMap<libc::pid_t, Arc<ThreadInfo>>>,

	/// Map of process IDs (PID) to thread IDs (TID) (for vfork tracking)
	process_map: RwLock<HashMap<libc::pid_t, libc::pid_t>>,

	/// Map of child thread IDs (TID) to parent thread IDs (TID)
	child_parent_map: RwLock<HashMap<libc::pid_t, libc::pid_t>>,
}

impl ThreadRegistry {
	/// Create a new thread registry
	fn new() -> Self {
		Self {
			threads: RwLock::new(HashMap::new()),
			process_map: RwLock::new(HashMap::new()),
			child_parent_map: RwLock::new(HashMap::new()),
		}
	}

	/// Register the current thread with the registry
	///
	/// # Parameters
	///
	/// * `gsreldata` - Pointer to the thread's `GSRelData`
	/// * `parent_thread_id` - Optional parent OS thread ID
	/// * `clone_flags` - Optional clone flags used to create this thread
	pub fn register_current_thread(
		&self,
		gsreldata: *mut GSRelData,
		parent_thread_id: Option<libc::pid_t>,
		clone_flags: Option<u64>,
	) -> Arc<ThreadInfo> {
		let thread_id = get_current_os_tid();
		let process_id = unsafe { libc::getpid() };

		let thread_info = Arc::new(ThreadInfo {
			thread_id,
			process_id,
			parent_thread_id,
			gsreldata,
			creation_time: std::time::Instant::now(),
			clone_flags,
		});

		// Register in all maps
		{
			let mut threads = self.threads.write().unwrap();
			threads.insert(thread_id, thread_info.clone());
		}

		{
			let mut process_map = self.process_map.write().unwrap();
			process_map.insert(process_id, thread_id);
		}

		if let Some(parent_id) = parent_thread_id {
			let mut child_parent_map = self.child_parent_map.write().unwrap();
			child_parent_map.insert(thread_id, parent_id);
		}

		debug!("Registered thread {} (pid: {})", thread_id, process_id);

		thread_info
	}

	/// Register a child thread
	///
	/// # Parameters
	///
	/// * `gsreldata` - Pointer to the thread's `GSRelData`
	/// * `clone_flags` - Clone flags used to create this thread
	pub fn register_child_thread(&self, gsreldata: *mut GSRelData, clone_flags: u64) -> Arc<ThreadInfo> {
		let parent_thread_id = get_current_os_tid();
		self.register_current_thread(gsreldata, Some(parent_thread_id), Some(clone_flags))
	}

	/// Unregister a thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The OS thread ID (TID) to unregister
	pub fn unregister_thread(&self, thread_id: libc::pid_t) {
		let thread_info = {
			let mut threads = self.threads.write().unwrap();
			threads.remove(&thread_id)
		};

		if let Some(thread_info) = thread_info {
			{
				let mut process_map = self.process_map.write().unwrap();
				process_map.remove(&thread_info.process_id);
			}

			{
				let mut child_parent_map = self.child_parent_map.write().unwrap();
				child_parent_map.remove(&thread_id);
			}

			debug!("Unregistered thread {}", thread_id);
		}
	}

	/// Unregister the current thread
	pub fn unregister_current_thread(&self) {
		let thread_id = get_current_os_tid();
		self.unregister_thread(thread_id);
	}

	/// Get information about a thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The OS thread ID (TID) to get information for
	///
	/// # Returns
	///
	/// Arc to the thread information, or None if not found
	pub fn get_thread_info(&self, thread_id: libc::pid_t) -> Option<Arc<ThreadInfo>> {
		let threads = self.threads.read().unwrap();
		threads.get(&thread_id).cloned()
	}

	/// Get information about the current thread
	///
	/// # Returns
	///
	/// Arc to the thread information, or None if not found
	pub fn get_current_thread_info(&self) -> Option<Arc<ThreadInfo>> {
		let thread_id = get_current_os_tid();
		self.get_thread_info(thread_id)
	}

	/// Get information about the parent thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The OS thread ID (TID) whose parent to get information for
	///
	/// # Returns
	///
	/// Arc to the parent thread information, or None if not found
	pub fn get_parent_thread_info(&self, thread_id: libc::pid_t) -> Option<Arc<ThreadInfo>> {
		let parent_id = {
			let child_parent_map = self.child_parent_map.read().unwrap();
			*child_parent_map.get(&thread_id)?
		};

		self.get_thread_info(parent_id)
	}

	/// Get information about the current thread's parent
	///
	/// # Returns
	///
	/// Arc to the parent thread information, or None if not found
	pub fn get_current_parent_thread_info(&self) -> Option<Arc<ThreadInfo>> {
		let thread_id = get_current_os_tid();
		self.get_parent_thread_info(thread_id)
	}

	/// Get the `GSRelData` for a thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The OS thread ID (TID) to get `GSRelData` for
	///
	/// # Returns
	///
	/// Pointer to the `GSRelData`, or null if not found
	pub fn get_gsreldata(&self, thread_id: libc::pid_t) -> *mut GSRelData {
		self.get_thread_info(thread_id)
			.map_or_else(std::ptr::null_mut, |info| info.gsreldata)
	}

	/// Get the `GSRelData` for the current thread
	///
	/// # Returns
	///
	/// Pointer to the `GSRelData`, or null if not found
	pub fn get_current_gsreldata(&self) -> *mut GSRelData {
		let thread_id = get_current_os_tid();
		self.get_gsreldata(thread_id)
	}

	/// Get the `GSRelData` for the parent thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The OS thread ID (TID) whose parent's `GSRelData` to get
	///
	/// # Returns
	///
	/// Pointer to the parent's `GSRelData`, or null if not found
	pub fn get_parent_gsreldata(&self, thread_id: libc::pid_t) -> *mut GSRelData {
		self.get_parent_thread_info(thread_id)
			.map_or_else(std::ptr::null_mut, |info| info.gsreldata)
	}

	/// Get the `GSRelData` for the current thread's parent
	///
	/// # Returns
	///
	/// Pointer to the parent's `GSRelData`, or null if not found
	pub fn get_current_parent_gsreldata(&self) -> *mut GSRelData {
		let thread_id = get_current_os_tid();
		self.get_parent_gsreldata(thread_id)
	}

	/// Get the number of registered threads
	pub fn thread_count(&self) -> usize {
		let threads = self.threads.read().unwrap();
		threads.len()
	}

	/// Get all registered thread IDs
	pub fn thread_ids(&self) -> Vec<libc::pid_t> {
		let threads = self.threads.read().unwrap();
		threads.keys().copied().collect()
	}

	/// Get all registered thread information
	pub fn all_thread_info(&self) -> Vec<Arc<ThreadInfo>> {
		let threads = self.threads.read().unwrap();
		threads.values().cloned().collect()
	}

	/// Print a summary of all registered threads
	pub fn print_summary(&self) {
		let threads = self.threads.read().unwrap();

		debug!("Thread Registry Summary:");
		debug!("  Total threads: {}", threads.len());

		for (id, info) in threads.iter() {
			let thread_type = if info.is_thread() { "Thread" } else { "Process" };
			let parent_info = info
				.parent_thread_id
				.map_or_else(|| "no parent".to_string(), |parent_id| format!("parent: {parent_id}"));

			debug!(
				"  {}: {} (pid: {}, {}, age: {:?})",
				id,
				thread_type,
				info.process_id,
				parent_info,
				info.creation_time.elapsed()
			);
		}
	}
}

/// Global thread registry singleton
static THREAD_REGISTRY: std::sync::LazyLock<ThreadRegistry> = std::sync::LazyLock::new(ThreadRegistry::new);

/// Get the global thread registry
#[must_use]
pub fn registry() -> &'static ThreadRegistry {
	&THREAD_REGISTRY
}

/// Initialize the thread registry with the main thread
///
/// This function should be called during framework initialization
/// to register the main thread.
///
/// # Parameters
///
/// * `gsreldata` - Pointer to the main thread's `GSRelData`
pub fn init_with_main_thread(gsreldata: *mut GSRelData) {
	let registry = registry();
	registry.register_current_thread(gsreldata, None, None);
	debug!("Initialized thread registry with main thread");
}
