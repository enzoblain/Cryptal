//! Hashing primitives
//!
//! This module groups cryptographic hash functions used throughout the
//! Nebula ecosystem.
//!
//! Hash functions provided here are designed to be:
//! - cryptographically secure
//! - deterministic and portable
//! - free of external dependencies
//! - suitable for identifiers, integrity checks, and higher-level protocols
//!
//! At the moment, this module exposes a SHA-256 implementation, but it is
//! structured to allow additional hash functions to be added in the future.

mod sha256;

/// Computes the SHA-256 hash of the given input.
///
/// This is the primary hashing entry point exposed by this module.
pub use sha256::core::sha256;
