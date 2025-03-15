fn main() {
	// Inform Cargo that if the assembly files change, it should rerun this build script
	println!("cargo:rerun-if-changed=src/asm/asm_syscall_hook.s");

	cc::Build::new()
		.file("src/asm/asm_syscall_hook.s")
		.flag("-nostartfiles")
		.flag("-fPIC")
		.flag("-nostdlib")
		.flag("-nodefaultlibs")
		.static_flag(true)
		.compile("asm_syscall_hook");

	// Set CPU features
	println!("cargo:rustc-env=RUSTFLAGS=-C target-feature=+fsgsbase");
}
