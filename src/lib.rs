#![no_std]

//! Lightweight cryptography primitives and hash functions.
//!
//! Exposes SHA-256 and a minimal 256-bit unsigned integer type (`U256`) with
//! bitwise and shift operations optimized for `no_std` environments.

pub mod hash;
pub mod primitives;

/// Re-export of the 256-bit unsigned integer type.
pub use primitives::U256;
