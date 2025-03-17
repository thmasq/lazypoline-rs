//! Thread registry for lazypoline
//!
//! This module provides a framework-wide registry for tracking threads
//! and their associated GSRelData pointers. It enables proper handling of
//! parent-child thread relationships, thread-local state, and cleanup.

use crate::core::gsrel::GSRelData;
use libc::pthread_t;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread::ThreadId;
use tracing::debug;

/// Information about a registered thread
#[derive(Debug)]
pub struct ThreadInfo {
	/// The thread ID
	pub thread_id: ThreadId,

	/// The pthread ID
	pub pthread_id: pthread_t,

	/// The process ID (for vfork tracking)
	pub process_id: libc::pid_t,

	/// The parent thread's ID (if known)
	pub parent_thread_id: Option<ThreadId>,

	/// Pointer to the thread's GSRelData
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
	pub fn is_thread(&self) -> bool {
		if let Some(flags) = self.clone_flags {
			(flags & crate::ffi::CLONE_THREAD) != 0
		} else {
			// Default to true if we don't know
			true
		}
	}

	/// Check if this thread shares signal handlers with its parent
	pub fn shares_signal_handlers(&self) -> bool {
		if let Some(flags) = self.clone_flags {
			(flags & crate::ffi::CLONE_SIGHAND as u64) != 0
		} else {
			// Default to false if we don't know
			false
		}
	}

	/// Check if this is a vfork child
	pub fn is_vfork_child(&self) -> bool {
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
/// associated GSRelData pointers for the entire framework.
pub struct ThreadRegistry {
	/// Map of thread IDs to thread information
	threads: RwLock<HashMap<ThreadId, Arc<ThreadInfo>>>,

	/// Map of pthread IDs to thread IDs (for lookup by pthread ID)
	pthread_map: RwLock<HashMap<pthread_t, ThreadId>>,

	/// Map of process IDs to thread IDs (for vfork tracking)
	process_map: RwLock<HashMap<libc::pid_t, ThreadId>>,

	/// Map of child thread IDs to parent thread IDs
	child_parent_map: RwLock<HashMap<ThreadId, ThreadId>>,
}

impl ThreadRegistry {
	/// Create a new thread registry
	fn new() -> Self {
		Self {
			threads: RwLock::new(HashMap::new()),
			pthread_map: RwLock::new(HashMap::new()),
			process_map: RwLock::new(HashMap::new()),
			child_parent_map: RwLock::new(HashMap::new()),
		}
	}

	/// Register the current thread with the registry
	///
	/// # Parameters
	///
	/// * `gsreldata` - Pointer to the thread's GSRelData
	/// * `parent_thread_id` - Optional parent thread ID
	/// * `clone_flags` - Optional clone flags used to create this thread
	pub fn register_current_thread(
		&self,
		gsreldata: *mut GSRelData,
		parent_thread_id: Option<ThreadId>,
		clone_flags: Option<u64>,
	) -> Arc<ThreadInfo> {
		let thread_id = std::thread::current().id();
		let pthread_id = unsafe { libc::pthread_self() };
		let process_id = unsafe { libc::getpid() };

		let thread_info = Arc::new(ThreadInfo {
			thread_id,
			pthread_id,
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
			let mut pthread_map = self.pthread_map.write().unwrap();
			pthread_map.insert(pthread_id, thread_id);
		}

		{
			let mut process_map = self.process_map.write().unwrap();
			process_map.insert(process_id, thread_id);
		}

		if let Some(parent_id) = parent_thread_id {
			let mut child_parent_map = self.child_parent_map.write().unwrap();
			child_parent_map.insert(thread_id, parent_id);
		}

		debug!(
			"Registered thread {:?} (pthread: {:?}, pid: {})",
			thread_id, pthread_id, process_id
		);

		thread_info
	}

	/// Register a child thread
	///
	/// # Parameters
	///
	/// * `gsreldata` - Pointer to the thread's GSRelData
	/// * `clone_flags` - Clone flags used to create this thread
	pub fn register_child_thread(&self, gsreldata: *mut GSRelData, clone_flags: u64) -> Arc<ThreadInfo> {
		let parent_thread_id = std::thread::current().id();
		self.register_current_thread(gsreldata, Some(parent_thread_id), Some(clone_flags))
	}

	/// Unregister a thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The thread ID to unregister
	pub fn unregister_thread(&self, thread_id: ThreadId) {
		let thread_info = {
			let mut threads = self.threads.write().unwrap();
			threads.remove(&thread_id)
		};

		if let Some(thread_info) = thread_info {
			{
				let mut pthread_map = self.pthread_map.write().unwrap();
				pthread_map.remove(&thread_info.pthread_id);
			}

			{
				let mut process_map = self.process_map.write().unwrap();
				process_map.remove(&thread_info.process_id);
			}

			{
				let mut child_parent_map = self.child_parent_map.write().unwrap();
				child_parent_map.remove(&thread_id);
			}

			debug!("Unregistered thread {:?}", thread_id);
		}
	}

	/// Unregister the current thread
	pub fn unregister_current_thread(&self) {
		let thread_id = std::thread::current().id();
		self.unregister_thread(thread_id);
	}

	/// Get information about a thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The thread ID to get information for
	///
	/// # Returns
	///
	/// Arc to the thread information, or None if not found
	pub fn get_thread_info(&self, thread_id: ThreadId) -> Option<Arc<ThreadInfo>> {
		let threads = self.threads.read().unwrap();
		threads.get(&thread_id).cloned()
	}

	/// Get information about the current thread
	///
	/// # Returns
	///
	/// Arc to the thread information, or None if not found
	pub fn get_current_thread_info(&self) -> Option<Arc<ThreadInfo>> {
		let thread_id = std::thread::current().id();
		self.get_thread_info(thread_id)
	}

	/// Get information about a thread by pthread ID
	///
	/// # Parameters
	///
	/// * `pthread_id` - The pthread ID to get information for
	///
	/// # Returns
	///
	/// Arc to the thread information, or None if not found
	pub fn get_thread_info_by_pthread(&self, pthread_id: pthread_t) -> Option<Arc<ThreadInfo>> {
		let pthread_map = self.pthread_map.read().unwrap();
		let thread_id = pthread_map.get(&pthread_id)?;
		self.get_thread_info(*thread_id)
	}

	/// Get information about the parent thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The thread ID whose parent to get information for
	///
	/// # Returns
	///
	/// Arc to the parent thread information, or None if not found
	pub fn get_parent_thread_info(&self, thread_id: ThreadId) -> Option<Arc<ThreadInfo>> {
		let child_parent_map = self.child_parent_map.read().unwrap();
		let parent_id = child_parent_map.get(&thread_id)?;
		self.get_thread_info(*parent_id)
	}

	/// Get information about the current thread's parent
	///
	/// # Returns
	///
	/// Arc to the parent thread information, or None if not found
	pub fn get_current_parent_thread_info(&self) -> Option<Arc<ThreadInfo>> {
		let thread_id = std::thread::current().id();
		self.get_parent_thread_info(thread_id)
	}

	/// Get the GSRelData for a thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The thread ID to get GSRelData for
	///
	/// # Returns
	///
	/// Pointer to the GSRelData, or null if not found
	pub fn get_gsreldata(&self, thread_id: ThreadId) -> *mut GSRelData {
		match self.get_thread_info(thread_id) {
			Some(info) => info.gsreldata,
			None => std::ptr::null_mut(),
		}
	}

	/// Get the GSRelData for the current thread
	///
	/// # Returns
	///
	/// Pointer to the GSRelData, or null if not found
	pub fn get_current_gsreldata(&self) -> *mut GSRelData {
		let thread_id = std::thread::current().id();
		self.get_gsreldata(thread_id)
	}

	/// Get the GSRelData for the parent thread
	///
	/// # Parameters
	///
	/// * `thread_id` - The thread ID whose parent's GSRelData to get
	///
	/// # Returns
	///
	/// Pointer to the parent's GSRelData, or null if not found
	pub fn get_parent_gsreldata(&self, thread_id: ThreadId) -> *mut GSRelData {
		match self.get_parent_thread_info(thread_id) {
			Some(info) => info.gsreldata,
			None => std::ptr::null_mut(),
		}
	}

	/// Get the GSRelData for the current thread's parent
	///
	/// # Returns
	///
	/// Pointer to the parent's GSRelData, or null if not found
	pub fn get_current_parent_gsreldata(&self) -> *mut GSRelData {
		let thread_id = std::thread::current().id();
		self.get_parent_gsreldata(thread_id)
	}

	/// Get the number of registered threads
	pub fn thread_count(&self) -> usize {
		let threads = self.threads.read().unwrap();
		threads.len()
	}

	/// Get all registered thread IDs
	pub fn thread_ids(&self) -> Vec<ThreadId> {
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
			let parent_info = if let Some(parent_id) = info.parent_thread_id {
				format!("parent: {:?}", parent_id)
			} else {
				"no parent".to_string()
			};

			debug!(
				"  {:?}: {} (pid: {}, {}, age: {:?})",
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
static THREAD_REGISTRY: Lazy<ThreadRegistry> = Lazy::new(ThreadRegistry::new);

/// Get the global thread registry
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
/// * `gsreldata` - Pointer to the main thread's GSRelData
pub fn init_with_main_thread(gsreldata: *mut GSRelData) {
	let registry = registry();
	registry.register_current_thread(gsreldata, None, None);
	debug!("Initialized thread registry with main thread");
}
