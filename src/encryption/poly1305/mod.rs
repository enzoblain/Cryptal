//! Poly1305 message authentication code (RFC 8439).
//!
//! This module provides an internal implementation of the Poly1305
//! message authentication algorithm, designed to be used as a building
//! block for AEAD constructions such as ChaCha20-Poly1305.
//!
//! The implementation is split into two layers:
//!
//! - `core`: low-level arithmetic and block processing
//! - `mac`: safe, high-level MAC interface
//!
//! This module is **not** intended to be used directly by end users.
//! It is exposed internally to support authenticated encryption schemes.

/// Low-level Poly1305 core implementation.
///
/// This module contains the internal Poly1305 state machine, including:
/// - key clamping
/// - block absorption
/// - modular reduction
/// - final tag computation
///
/// It operates on fixed-size limbs and performs no allocation.
///
/// This module is cryptographically sensitive and must remain internal.
pub mod core;

/// High-level Poly1305 MAC interface.
///
/// This module provides a minimal, safe wrapper around the low-level core:
/// - handles block iteration
/// - enforces one-time key usage
/// - exposes a single-shot `finalize()` API
///
/// It is intended to be used by higher-level constructions such as
/// ChaCha20-Poly1305.
pub(crate) mod mac;
