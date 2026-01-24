//! Cryptographic recovery primitives.
//!
//! This module provides low-level cryptographic mechanisms designed to
//! protect and recover sensitive material in the presence of partial data
//! loss, node failure, or compromise.
//!
//! The focus of this module is **cryptographic survivability**: enabling
//! secrets to remain recoverable without relying on a single point of
//! failure, while preserving strong security guarantees.
//!
//! # Shamir Secret Sharing (SSS)
//!
//! The `shamirsecretsharing` submodule provides an implementation of
//! **Shamir Secret Sharing**, a threshold-based secret distribution scheme.
//!
//! A secret is split into multiple *shares* such that:
//!
//! - Any subset of at least `t` shares can reconstruct the original secret.
//! - Any subset of fewer than `t` shares reveals no information about it.
//!
//! The implementation operates over a finite field (GF(256)) and treats
//! the secret as a sequence of independent bytes, each protected by its
//! own randomly generated polynomial.
//!
//! ## Provided functionality
//!
//! The Shamir implementation exposes three core operations:
//!
//! - **Splitting**
//!   - A secret can be split into `n` shares with a reconstruction threshold `t`.
//!   - Cryptographically secure randomness is used to generate polynomial
//!     coefficients.
//!
//! - **Combining**
//!   - A secret can be reconstructed from any valid subset of at least
//!     `t` shares using Lagrange interpolation at zero.
//!
//! - **Refreshing**
//!   - Existing shares can be refreshed without ever reconstructing the
//!     underlying secret.
//!   - This allows long-lived secrets to remain secure even if shares are
//!     gradually exposed over time.
//!
//! ## Security properties
//!
//! - All arithmetic is performed in a finite field (GF(256)).
//! - No information about the secret is leaked with fewer than `t` shares.
//! - Share refresh does not require secret reconstruction.
//! - The module is agnostic to storage, transport, and policy decisions.
//!
//! ## Intended use cases
//!
//! - Distributed backup of cryptographic keys or seeds
//! - Threshold-based recovery mechanisms
//! - Multi-party custody of sensitive material
//! - Long-term survivability of secrets in distributed systems
//!
//! This module is intentionally minimal and does not include:
//! - authentication or MACs for shares
//! - serialization or networking logic
//! - access control or recovery policies
//!
//! Those concerns are expected to be handled by higher layers of the
//! Nebula stack.

mod sss;

pub use sss::core as shamirsecretsharing;
