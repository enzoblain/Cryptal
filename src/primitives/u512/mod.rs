//! 512-bit unsigned integer primitive
//!
//! This module defines the `U512` type, a fixed-size 512-bit unsigned
//! integer used throughout the Nebula ecosystem.
//!
//! `U512` is designed as a low-level, dependency-free primitive rather than
//! a full big-integer abstraction. It provides only the minimal set of
//! functionality required by the project, with explicit semantics and
//! predictable behavior.
//!
//! Typical use cases include:
//! - cryptographic hash outputs (e.g. SHA-512)
//! - identifiers and distances
//! - internal protocol and arithmetic operations
//!
//! The internal representation is big-endian and remains stable across
//! all operations and conversions.

mod conv;
mod core;
mod ops;

/// Fixed-size 512-bit unsigned integer.
///
/// This type is re-exported as the primary 512-bit integer primitive.
pub use core::U512;
