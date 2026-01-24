//! Ed25519 cryptographic implementation.
//!
//! This module provides a complete, self-contained implementation of the
//! Ed25519 signature scheme and its associated cryptographic primitives.
//!
//! The design follows a strict separation of concerns:
//! - a **high-level API** exposed via the `core` module,
//! - **low-level arithmetic and group logic** isolated in dedicated
//!   internal modules.
//!
//! All cryptographic operations are implemented with constant-time
//! considerations in mind and closely follow the Ed25519 specification
//! (RFC 8032).
//!
//! ## Implementation notes
//!
//! This implementation is written from scratch in Rust, but its structure,
//! algorithms, and mathematical approach are **inspired by** the widely
//! referenced Ed25519 implementation by Orson Peters:
//!
//! <https://github.com/orlp/ed25519>
//!
//! In particular, this code follows the same high-level design principles:
//! - limb-based finite field arithmetic,
//! - explicit carry propagation,
//! - constant-time scalar and group operations,
//! - faithful adherence to the reference formulas.
//!
//! The original implementation is released into the public domain (CC0).
//! While this Rust implementation is not a direct translation, the reference
//! code served as a valuable guide for correctness and structure.

/// High-level Ed25519 API.
///
/// This module exposes the public-facing interface:
/// - key pair generation,
/// - message signing and signature verification,
/// - scalar-based key updates,
/// - Diffie–Hellman–style key exchange built on Curve25519.
///
/// This is the only module most users should interact with directly.
pub(crate) mod core;

/// Constant-time utilities.
///
/// This module contains helpers and traits for constant-time comparisons
/// and bit-level operations used throughout the implementation.
///
/// It prevents timing side-channel leaks in comparisons and conditional logic.
pub(crate) mod ct;

/// Finite field arithmetic.
///
/// Implements arithmetic over the prime field GF(2²⁵⁵ − 19) using a
/// limb-based representation compatible with the Ed25519 reference
/// implementation.
///
/// Provides:
/// - addition, subtraction, multiplication,
/// - squaring and repeated squaring,
/// - inversion and fixed-exponent exponentiation.
///
/// All operations are constant-time and explicitly reduced.
pub(crate) mod field;

/// Edwards curve group operations.
///
/// Implements point representations and operations on the Edwards curve
/// used by Ed25519.
///
/// Includes:
/// - point decompression and compression,
/// - scalar multiplication,
/// - point addition and doubling,
/// - cached and precomputed representations for efficiency.
pub(crate) mod group;

/// Scalar arithmetic.
///
/// Implements arithmetic modulo the Ed25519 group order ℓ.
///
/// Used for:
/// - private key handling,
/// - signature computation,
/// - scalar reduction and linear combinations.
pub(crate) mod scalar;

/// Precomputed tables.
///
/// Contains static precomputed constants and tables used to accelerate
/// scalar multiplication and group operations.
///
/// All values are derived from the Ed25519 specification.
pub(crate) mod table;

// Re-export the public API at the `ed25519` level.
pub use core::*;
