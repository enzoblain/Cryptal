//! X25519 key exchange.
//!
//! This module provides an implementation of the X25519 Diffie–Hellman
//! key exchange as specified in RFC 7748.
//!
//! The public API is intentionally minimal and re-exports the high-level
//! key exchange function defined in the internal `core` module.
//!
//! ## Structure
//!
//! - `core`  
//!   Contains the full X25519 implementation, including scalar clamping,
//!   Montgomery ladder arithmetic, and field operations.
//!
//! The separation mirrors the structure used in other cryptographic
//! modules of the crate, keeping algorithmic details isolated while
//! exposing a small, explicit interface.

mod core;

// Re-export the public API at the `x25519` level.
pub use core::*;
