# lazypoline-rs

A Rust implementation of the lazypoline syscall interposition system.

## Description

**lazypoline-rs** is a fast, exhaustive, and expressive syscall interposer for user-space Linux applications. It uses a _hybrid interposition_ mechanism based on Syscall User Dispatch (SUD) and binary rewriting to exhaustively interpose all syscalls with maximal efficiency.

This is a Rust port of the original C++ implementation from "System Call Interposition Without Compromise" (DSN'24 paper).

## Building

Use Cargo to build the project:

```bash
cargo build --release --workspace
```

This builds two shared libraries:

- `target/release/liblazypoline.so` - The main lazypoline library
- `target/release/libbootstrap.so` - The bootstrap loader

## Running

lazypoline-rs can hook syscalls in precompiled binaries by setting the appropriate environment variables when launching:

```bash
LIBLAZYPOLINE="$(pwd)/target/release/liblazypoline.so" LD_PRELOAD="$(pwd)/target/release/libbootstrap.so" <some binary>
```

Note that this way of launching will miss syscalls performed before and while the dynamic loader loads lazypoline.

## Requirements

lazypoline requires permissions to `mmap` at low virtual addresses, i.e., the 0 page. You can permit this via:

```bash
echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
```

Additionally, you need Linux kernel version >= 5.11 for Syscall User Dispatch (SUD) support.

## Extending

You can modify lazypoline-rs to better fit your needs. The `syscall_emulate` function in `src/lazypoline.rs` is your main entry point.

## License

This project is licensed under the GPL v3 License - see the LICENSE file for details.

## Acknowledgements

This is a Rust port of the original C++ lazypoline project by Adriaan Jacobs et al. Check out their amazing work [here](https://github.com/lazypoline/lazypoline).
