#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(deref_nullptr)] // see https://github.com/rust-lang/rust-bindgen/issues/1651
#![allow(clippy::redundant_static_lifetimes)]
include!("./sodium_bindings_gen.rs");
