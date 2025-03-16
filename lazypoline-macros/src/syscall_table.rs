//! Syscall table generation
//!
//! This module generates a syscall table enum from the system's
//! syscall table using `ausyscall --dump`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;
use std::process::Command;
use syn::DeriveInput;

/// Generate the syscall enum from the system's syscall table
pub fn generate_syscall_enum(input: &DeriveInput) -> Result<TokenStream, String> {
	let name = &input.ident;

	// Get the syscall table from the system
	let syscall_table = generate_syscall_table()?;

	// Generate enum variants
	let variants = syscall_table.iter().map(|(syscall_name, syscall_num)| {
		let variant_name = format_ident!("{}", syscall_name);
		// Cast to isize for enum discriminants
		quote! {
			/// System call #[#syscall_num] - #syscall_name
			#variant_name = #syscall_num as isize
		}
	});

	// Generate from_number implementation
	let match_arms = syscall_table.iter().map(|(syscall_name, syscall_num)| {
		let variant_name = format_ident!("{}", syscall_name);
		quote! {
			#syscall_num => Some(Self::#variant_name)
		}
	});

	// Generate name implementation
	let name_match_arms = syscall_table.iter().map(|(syscall_name, _syscall_num)| {
		let variant_name = format_ident!("{}", syscall_name);
		quote! {
			Self::#variant_name => stringify!(#syscall_name)
		}
	});

	// Generate number implementation
	let number_match_arms = syscall_table.iter().map(|(syscall_name, syscall_num)| {
		let variant_name = format_ident!("{}", syscall_name);
		quote! {
			Self::#variant_name => #syscall_num
		}
	});

	// Generate the enum
	let output = quote! {
		#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
		pub enum #name {
			/// Unknown syscall
			Unknown = -1,

			#(#variants),*
		}

		impl #name {
			/// Convert a syscall number to a Syscall enum variant
			pub fn from_number(num: i64) -> Option<Self> {
				match num {
					#(#match_arms),*,
					_ => None
				}
			}

			/// Get the name of the syscall
			pub fn name(&self) -> &'static str {
				match self {
					Self::Unknown => "unknown",
					#(#name_match_arms),*
				}
			}

			/// Get the number of the syscall
			pub fn number(&self) -> i64 {
				match self {
					Self::Unknown => -1,
					#(#number_match_arms),*
				}
			}
		}
	};

	Ok(output)
}

/// Generate a map of syscall names to syscall numbers using `ausyscall --dump`
///
/// If `ausyscall` is not available, falls back to a hardcoded list of
/// common syscalls.
fn generate_syscall_table() -> Result<HashMap<String, i64>, String> {
	// Try to run ausyscall to get the syscall table
	match Command::new("ausyscall").args(["--dump"]).output() {
		Ok(output) => {
			if output.status.success() {
				let stdout = String::from_utf8_lossy(&output.stdout);
				parse_ausyscall_output(&stdout)
			} else {
				// ausyscall failed, use hardcoded table
				Ok(hardcoded_syscall_table())
			}
		},
		Err(_) => {
			// ausyscall not found, use hardcoded table
			Ok(hardcoded_syscall_table())
		},
	}
}

/// Parse the output of `ausyscall --dump` into a map of syscall names to numbers
fn parse_ausyscall_output(output: &str) -> Result<HashMap<String, i64>, String> {
	let mut table = HashMap::new();

	// Skip the header line
	for line in output.lines().skip(1) {
		let parts: Vec<&str> = line.split_whitespace().collect();
		if parts.len() >= 2 {
			let num = parts[0]
				.parse::<i64>()
				.map_err(|e| format!("Failed to parse syscall number: {}", e))?;
			let name = normalize_syscall_name(parts[1]);
			table.insert(name, num);
		}
	}

	Ok(table)
}

/// Normalize syscall names to valid Rust identifiers
fn normalize_syscall_name(name: &str) -> String {
	// Remove any non-alphanumeric characters
	let name = name
		.chars()
		.map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
		.collect::<String>();

	// Ensure name starts with a letter or underscore
	if name
		.chars()
		.next()
		.map(|c| c.is_alphabetic() || c == '_')
		.unwrap_or(false)
	{
		name
	} else {
		format!("_{}", name)
	}
}

/// Provide a hardcoded table of common syscalls
///
/// This is used as a fallback if `ausyscall` is not available.
fn hardcoded_syscall_table() -> HashMap<String, i64> {
	let mut table = HashMap::new();

	// Add common syscalls (x86_64)
	table.insert("read".into(), 0);
	table.insert("write".into(), 1);
	table.insert("open".into(), 2);
	table.insert("close".into(), 3);
	table.insert("stat".into(), 4);
	table.insert("fstat".into(), 5);
	table.insert("lstat".into(), 6);
	table.insert("poll".into(), 7);
	table.insert("lseek".into(), 8);
	table.insert("mmap".into(), 9);
	table.insert("mprotect".into(), 10);
	table.insert("munmap".into(), 11);
	table.insert("brk".into(), 12);
	table.insert("rt_sigaction".into(), 13);
	table.insert("rt_sigprocmask".into(), 14);
	table.insert("rt_sigreturn".into(), 15);
	table.insert("ioctl".into(), 16);
	table.insert("pread64".into(), 17);
	table.insert("pwrite64".into(), 18);
	table.insert("readv".into(), 19);
	table.insert("writev".into(), 20);
	table.insert("access".into(), 21);
	table.insert("pipe".into(), 22);
	table.insert("select".into(), 23);
	table.insert("sched_yield".into(), 24);
	table.insert("mremap".into(), 25);
	table.insert("msync".into(), 26);
	table.insert("mincore".into(), 27);
	table.insert("madvise".into(), 28);
	table.insert("shmget".into(), 29);
	table.insert("shmat".into(), 30);
	table.insert("shmctl".into(), 31);
	table.insert("dup".into(), 32);
	table.insert("dup2".into(), 33);
	table.insert("pause".into(), 34);
	table.insert("nanosleep".into(), 35);
	table.insert("getitimer".into(), 36);
	table.insert("alarm".into(), 37);
	table.insert("setitimer".into(), 38);
	table.insert("getpid".into(), 39);
	table.insert("sendfile".into(), 40);
	table.insert("socket".into(), 41);
	table.insert("connect".into(), 42);
	table.insert("accept".into(), 43);
	table.insert("sendto".into(), 44);
	table.insert("recvfrom".into(), 45);
	table.insert("sendmsg".into(), 46);
	table.insert("recvmsg".into(), 47);
	table.insert("shutdown".into(), 48);
	table.insert("bind".into(), 49);
	table.insert("listen".into(), 50);
	table.insert("getsockname".into(), 51);
	table.insert("getpeername".into(), 52);
	table.insert("socketpair".into(), 53);
	table.insert("setsockopt".into(), 54);
	table.insert("getsockopt".into(), 55);
	table.insert("clone".into(), 56);
	table.insert("fork".into(), 57);
	table.insert("vfork".into(), 58);
	table.insert("execve".into(), 59);
	table.insert("exit".into(), 60);
	table.insert("wait4".into(), 61);
	table.insert("kill".into(), 62);
	table.insert("uname".into(), 63);
	table.insert("semget".into(), 64);
	table.insert("semop".into(), 65);
	table.insert("semctl".into(), 66);
	table.insert("shmdt".into(), 67);
	table.insert("msgget".into(), 68);
	table.insert("msgsnd".into(), 69);
	table.insert("msgrcv".into(), 70);
	table.insert("msgctl".into(), 71);
	table.insert("fcntl".into(), 72);
	table.insert("flock".into(), 73);
	table.insert("fsync".into(), 74);
	table.insert("fdatasync".into(), 75);
	table.insert("truncate".into(), 76);
	table.insert("ftruncate".into(), 77);
	table.insert("getdents".into(), 78);
	table.insert("getcwd".into(), 79);
	table.insert("chdir".into(), 80);
	table.insert("fchdir".into(), 81);
	table.insert("rename".into(), 82);
	table.insert("mkdir".into(), 83);
	table.insert("rmdir".into(), 84);
	table.insert("creat".into(), 85);
	table.insert("link".into(), 86);
	table.insert("unlink".into(), 87);
	table.insert("symlink".into(), 88);
	table.insert("readlink".into(), 89);
	table.insert("chmod".into(), 90);
	table.insert("fchmod".into(), 91);
	table.insert("chown".into(), 92);
	table.insert("fchown".into(), 93);
	table.insert("lchown".into(), 94);
	table.insert("umask".into(), 95);
	table.insert("gettimeofday".into(), 96);
	table.insert("getrlimit".into(), 97);
	table.insert("getrusage".into(), 98);
	table.insert("sysinfo".into(), 99);
	table.insert("times".into(), 100);

	table
}
