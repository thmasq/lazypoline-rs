//! Build script for lazypoline
//!
//! This script compiles the assembly code for lazypoline.

fn main() {
	// Inform Cargo that if the assembly files change, it should rerun this build script
	println!("cargo:rerun-if-changed=src/asm/asm_syscall_hook.s");

	let mut build = cc::Build::new();

	build
		.file("src/asm/asm_syscall_hook.s")
		.flag("-nostartfiles")
		.flag("-fPIC")
		.flag("-nostdlib")
		.flag("-nodefaultlibs");

	if std::env::var("PROFILE").unwrap() == "debug" {
		build.flag("-g");
	}

	// Set CPU features
	println!("cargo:rustc-env=RUSTFLAGS=-C target-feature=+fsgsbase");

	// Set a feature flag for our crate to indicate if we're on x86_64
	#[cfg(target_arch = "x86_64")]
	println!("cargo:rustc-cfg=feature=\"x86_64\"");

	// Print build info for debugging
	println!(
		"cargo:warning=Building for architecture: {}",
		std::env::var("TARGET").unwrap()
	);
}
