# Lazypoline Framework

A comprehensive framework for building syscall interposers in Rust.

## Overview

The Lazypoline Framework enables you to build efficient, exhaustive, and expressive syscall interposers for user-space Linux applications. It uses a hybrid interposition mechanism based on Syscall User Dispatch (SUD) and binary rewriting to exhaustively intercept all syscalls with maximum efficiency.

This framework is a Rust re-implementation and extension of the original lazypoline system described in the paper "[System Call Interposition Without Compromise](https://adriaanjacobs.github.io/files/dsn24lazypoline.pdf)" (DSN'24 paper).

## Features

- **Exhaustive interception**: Intercepts all syscalls, including those in the VDSO
- **Efficient**: Uses binary rewriting (zpoline) for maximum performance
- **Safe**: Written in Rust with a clean, composable API
- **Easy to extend**: Define custom handlers for specific syscalls
- **Cross-thread**: Works across all threads in a process
- **Declarative**: Use macros to define handlers and filters (kinda WIP)

## Getting Started

### Requirements

- Linux kernel >= 5.11 (for Syscall User Dispatch support)
- Permission to map the zero page (`echo 0 | sudo tee /proc/sys/vm/mmap_min_addr`)
- Rust 2021 edition or newer

### Installation

Add lazypoline to your Cargo.toml:

```toml
[dependencies]
lazypoline-rs = "0.2.0"
```

### Simple Example

Here's a simple example that traces all syscalls:

```rust
use lazypoline::{self, SyscallContext, SyscallAction};

#[lazypoline::syscall_handler]
fn handle_open(ctx: &mut SyscallContext) -> SyscallAction {
    println!("Open syscall: {}", unsafe { std::ffi::CStr::from_ptr(ctx.args.rdi as *const i8).to_string_lossy() });
    SyscallAction::Allow
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the interposer
    let interposer = lazypoline::new()
        .handler(HandleOpen::new())
        .trace(true)
        .build()?
        .init()?;
    
    // Your application code here
    
    // The interposer is automatically cleaned up when dropped
    Ok(())
}
```

### Running with Precompiled Binaries

You can use lazypoline to intercept syscalls in existing binaries:

```bash
LIBLAZYPOLINE="path/to/liblazypoline.so" LD_PRELOAD="path/to/libbootstrap.so" your_binary
```

## API Overview

The Lazypoline Framework provides a simple, composable API:

### Core Components

- **Interposer**: Main component that manages syscall interception
- **SyscallHandler**: Trait for handling syscalls
- **SyscallFilter**: Trait for filtering syscalls
- **SyscallContext**: Contains information about a syscall

### Builder Pattern

```rust
let interposer = lazypoline::new()
    .handler(my_handler)
    .filter(my_filter)
    .trace(true)
    .build()?
    .init()?;
```

### Macros

- **syscall_handler**: Define a syscall handler function
- **syscall_enum**: Generate an enum of all syscalls (used internally)

## Advanced Usage

### Custom Handler

```rust
struct BlockWriteHandler;

impl SyscallHandler for BlockWriteHandler {
    fn handle_syscall(&self, ctx: &mut SyscallContext) -> SyscallAction {
        if ctx.syscall == Syscall::write {
            println!("Blocking write to fd {}", ctx.args.rdi);
            SyscallAction::Block(-libc::EPERM)
        } else {
            SyscallAction::Allow
        }
    }
}
```

### Filtering Syscalls

```rust
use lazypoline::interposer::filter::BlockListFilter;

let mut filter = BlockListFilter::new([
    Syscall::execve,
    Syscall::fork,
    Syscall::vfork
]);

let interposer = lazypoline::new()
    .filter(filter)
    .build()?
    .init()?;
```

### Modifying Syscall Arguments

```rust
#[lazypoline::syscall_handler]
fn modify_args(ctx: &mut SyscallContext) -> SyscallAction {
    if ctx.syscall == Syscall::open {
        // Change the first argument (path)
        let mut new_args = ctx.args;
        new_args.rdi = "/dev/null\0".as_ptr() as u64;
        SyscallAction::Modify(new_args)
    } else {
        SyscallAction::Allow
    }
}
```

## Building

Build the libraries with Cargo:

```bash
cargo build --release --workspace
```

This builds:

- `target/release/liblazypoline.so` - The main library
- `target/release/libbootstrap.so` - The bootstrap loader

For proper permissions:

```bash
sudo setcap cap_sys_admin,cap_sys_rawio+ep target/release/libbootstrap.so
```

## Architecture

The Lazypoline Framework consists of several components:

- **Bootstrap**: Loads the main library in a new namespace
- **SUD**: Syscall User Dispatch mechanism for intercepting syscalls
- **Zpoline**: Binary rewriting technique for efficient interception
- **Handlers**: User-defined code for processing intercepted syscalls
- **Filters**: User-defined code for allowing/blocking syscalls

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GPL v3 License - see the LICENSE file for details.

## Acknowledgements

This is a Rust extension of the original lazypoline project by Adriaan Jacobs et al. Check out their paper and code at [github.com/lazypoline/lazypoline](https://github.com/lazypoline/lazypoline).
