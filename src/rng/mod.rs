//! Random number generation module
//!
//! This module provides cryptographically secure randomness facilities
//! for the Nebula ecosystem.
//!
//! It is built around a ChaCha20-based deterministic random bit generator
//! (DRBG) and exposes a high-level CSPRNG interface suitable for
//! security-critical use cases such as key generation, nonces, and identifiers.

/// Design goals:
/// - Cryptographic security
/// - Deterministic expansion from a secure seed
/// - Forward secrecy through periodic rekeying
/// - No heap allocation
/// - Minimal and explicit API surface
pub(crate) mod chacha20;
mod csprng;

/// Cryptographically secure pseudorandom number generator.
///
/// This type is the primary entry point for generating secure randomness
/// within the Nebula codebase.
pub use csprng::Csprng;
