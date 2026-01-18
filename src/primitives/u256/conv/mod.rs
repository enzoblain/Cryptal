//! Integer conversion utilities
//!
//! This module groups explicit conversion implementations between the
//! fixed-size `U256` primitive and native integer types.
//!
//! Each submodule is responsible for conversions to and from a specific
//! integer width, following these principles:
//! - explicit big-endian semantics
//! - no implicit truncation
//! - fallible conversions when narrowing may lose information
//! - simple, auditable implementations
//!
//! The conversions are intentionally split by integer size to keep each
//! file small, focused, and easy to reason about.

mod u128;
mod u16;
mod u32;
mod u64;
mod u8;
mod usize;
