//! Hash algorithms exposed by the crate.
//!
//! Currently includes SHA-256 with a pure-Rust implementation.

pub mod sha256;

/// Re-export of the SHA-256 convenience function.
pub use sha256::core::sha256;
