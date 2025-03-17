//! Implementations for the syscall_handler procedural macro
//!
//! This module provides the implementation for the syscall_handler
//! procedural macro, which transforms regular functions into
//! syscall handlers that implement the SyscallHandler trait.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{FnArg, ItemFn, Pat, PatType, ReturnType, parse_macro_input};

/// Transform a function into a syscall handler struct
///
/// This function takes a function definition and transforms it into:
/// 1. A struct with the same name in CamelCase
/// 2. An implementation of the SyscallHandler trait for that struct
/// 3. The original function that is called by the handler
///
/// # Arguments
///
/// * `attr` - The attribute arguments (unused)
/// * `item` - The function to transform
///
/// # Returns
///
/// A TokenStream containing the generated code
pub fn handle_syscall_handler(attr: TokenStream, item: TokenStream) -> TokenStream {
	let _ = attr;
	let input_fn = parse_macro_input!(item as ItemFn);

	// Extract details from the function
	let fn_name = &input_fn.sig.ident;
	let fn_attrs = &input_fn.attrs;
	let fn_vis = &input_fn.vis;
	let fn_block = &input_fn.block;
	let fn_generics = &input_fn.sig.generics;

	// Create the struct name by converting fn_name from snake_case to CamelCase
	let struct_name = fn_name_to_struct_name(fn_name.to_string());
	let struct_ident = format_ident!("{}", struct_name);

	// Check function signature
	validate_handler_signature(&input_fn);

	// Generate the struct and implementation
	let output = quote! {
		#(#fn_attrs)*
		#fn_vis struct #struct_ident #fn_generics;

		impl #fn_generics #struct_ident #fn_generics {
			/// Create a new instance of this syscall handler
			pub fn new() -> Self {
				Self
			}
		}

		impl #fn_generics ::lazypoline_rs::SyscallHandler for #struct_ident #fn_generics {
			fn handle_syscall(&self, ctx: &mut ::lazypoline_rs::SyscallContext) -> ::lazypoline_rs::SyscallAction {
				#fn_name(ctx)
			}

			fn name(&self) -> &'static str {
				stringify!(#fn_name)
			}

			fn clone_box(&self) -> Box<dyn ::lazypoline_rs::SyscallHandler> {
				Box::new(Self)
			}
		}

		#(#fn_attrs)*
		#fn_vis fn #fn_name #fn_generics(ctx: &mut ::lazypoline_rs::SyscallContext) -> ::lazypoline_rs::SyscallAction {
			#fn_block
		}
	};

	output.into()
}

/// Convert a snake_case function name to CamelCase struct name
///
/// # Arguments
///
/// * `name` - The function name in snake_case
///
/// # Returns
///
/// The struct name in CamelCase
fn fn_name_to_struct_name(name: String) -> String {
	// Split by underscores and capitalize each part
	let mut result = String::new();
	for part in name.split('_') {
		let mut chars = part.chars();
		if let Some(first) = chars.next() {
			result.push_str(&first.to_uppercase().to_string());
			result.push_str(chars.as_str());
		}
	}
	result
}

/// Validate that the function has the correct signature for a syscall handler
///
/// A syscall handler must:
/// 1. Take exactly one argument: &mut SyscallContext
/// 2. Return SyscallAction
///
/// # Arguments
///
/// * `input_fn` - The function to validate
///
/// # Panics
///
/// Panics if the function does not have the correct signature
fn validate_handler_signature(input_fn: &ItemFn) {
	// Check return type
	match &input_fn.sig.output {
		ReturnType::Default => {
			panic!("Syscall handler must return SyscallAction");
		},
		ReturnType::Type(_, ty) => {
			let type_str = quote!(#ty).to_string();
			if !type_str.contains("SyscallAction") {
				panic!("Syscall handler must return SyscallAction, got {}", type_str);
			}
		},
	}

	// Check function arguments
	if input_fn.sig.inputs.len() != 1 {
		panic!("Syscall handler must take exactly one argument: &mut SyscallContext");
	}

	let arg = input_fn.sig.inputs.first().unwrap();
	match arg {
		FnArg::Receiver(_) => {
			panic!("Syscall handler cannot be a method");
		},
		FnArg::Typed(PatType { ty, pat, .. }) => {
			let ty_str = quote!(#ty).to_string();

			if !(ty_str.contains('&')
				&& (ty_str.contains("mut") || ty_str.contains(" mut "))
				&& ty_str.contains("SyscallContext"))
			{
				panic!("Syscall handler argument must be &mut SyscallContext, got {}", ty_str);
			}

			// Verify the parameter name is "ctx" to match the trait requirement
			match &**pat {
				Pat::Ident(pat_ident) => {
					let param_name = pat_ident.ident.to_string();
					if param_name != "ctx" {
						panic!("Syscall handler parameter must be named 'ctx'");
					}
				},
				_ => {
					panic!("Syscall handler parameter must be a simple identifier");
				},
			}
		},
	}
}
