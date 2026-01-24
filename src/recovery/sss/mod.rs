//! Shamir Secret Sharing (SSS) implementation.
//!
//! This module provides a low-level, auditable implementation of
//! **Shamir Secret Sharing**, a threshold-based cryptographic scheme for
//! distributing and recovering secrets.
//!
//! The implementation is deliberately split into two layers:
//!
//! - [`core`]  
//!   Public API and protocol logic.
//!
//!   This module defines the externally visible types and operations:
//!   - share representation
//!   - parameter validation
//!   - secret splitting
//!   - secret reconstruction
//!   - share refresh
//!
//!   All functions in `core` operate on explicit inputs and return
//!   deterministic results given their parameters and randomness source.
//!   No storage, networking, or policy logic is included.
//!
//! - [`field`]  
//!   Finite field arithmetic (GF(256)).
//!
//!   This internal module implements the mathematical operations required
//!   by Shamir Secret Sharing, including:
//!   - addition and multiplication in GF(256)
//!   - multiplicative inversion
//!   - polynomial evaluation
//!   - Lagrange interpolation at zero
//!
//!   The field module is kept private to prevent misuse and to ensure that
//!   all cryptographic constructions are mediated through the `core` API.
//!
//! ## Design notes
//!
//! - Each byte of the secret is protected independently using its own
//!   randomly generated polynomial.
//! - All arithmetic is performed in a finite field to guarantee closure
//!   and the existence of multiplicative inverses.
//! - Share identifiers are non-zero field elements and must be unique.
//! - Share refresh renews shares without ever reconstructing the secret.
//!
//! ## Security scope
//!
//! This module provides **confidentiality through threshold secrecy**.
//! It does not provide:
//! - authentication or integrity protection for shares
//! - resistance against malicious or byzantine participants
//! - serialization, storage, or transport mechanisms
//!
//! Those properties must be enforced by higher layers of the system.

pub mod core;
pub(crate) mod field;
