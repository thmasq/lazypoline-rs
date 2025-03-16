extern crate proc_macro;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod handlers;
mod syscall_table;

use handlers::handle_syscall_handler;
use syscall_table::generate_syscall_enum;

/// Generate a syscall enum from the system's syscall table
///
/// This macro generates an enum with variants for all syscalls
/// on the system, using `ausyscall --dump` to get the syscall
/// names and numbers.
#[proc_macro_attribute]
pub fn syscall_enum(_attr: TokenStream, item: TokenStream) -> TokenStream {
	let input = parse_macro_input!(item as DeriveInput);

	// Generate the enum content from the syscall table
	match generate_syscall_enum(&input) {
		Ok(enum_output) => enum_output.into(),
		Err(err) => {
			panic!("Failed to generate syscall enum: {}", err);
		},
	}
}

/// Define a syscall handler function
///
/// This macro transforms a regular function into a syscall handler
/// that implements the `SyscallHandler` trait.
///
/// # Example
///
/// ```
/// use lazypoline::{SyscallContext, SyscallAction};
///
/// #[lazypoline::syscall_handler]
/// fn handle_open(ctx: &mut SyscallContext) -> SyscallAction {
///     println!("Open syscall detected");
///     SyscallAction::Allow
/// }
/// ```
#[proc_macro_attribute]
pub fn syscall_handler(attr: TokenStream, item: TokenStream) -> TokenStream {
	handle_syscall_handler(attr, item)
}
