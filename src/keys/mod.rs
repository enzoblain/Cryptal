//! Asymmetric cryptographic algorithms.
//!
//! This module groups asymmetric cryptographic constructions built on
//! top of the crate’s cryptographic primitives and hash functions.
//!
//! It includes:
//! - key pair generation,
//! - private and public key material,
//! - digital signature algorithms,
//! - Diffie–Hellman key agreement.
//!
//! Each submodule corresponds to a concrete, well-specified algorithm
//! and defines its own key types and operations. Implementations are
//! intentionally explicit and self-contained, favoring clarity,
//! auditability, and specification-level correctness over abstraction.
//!
//! ## Ed25519
//!
//! The `ed25519` module implements the Ed25519 signature scheme together
//! with its associated key material, based on twisted Edwards curves over
//! the field 𝔽ₚ where `p = 2²⁵⁵ − 19`.
//!
//! This is a from-scratch Rust implementation inspired by the reference
//! code by Orson Peters:
//!
//! <https://github.com/orlp/ed25519>
//!
//! It closely follows the mathematical structure and execution model of
//! the reference implementation, including:
//! - limb-based field arithmetic,
//! - explicit carry propagation,
//! - constant-time group and scalar operations,
//! - adherence to RFC 8032.
//!
//! ## X25519
//!
//! The `x25519` module implements Curve25519 Diffie–Hellman key agreement
//! using the Montgomery ladder as specified in RFC 7748.
//!
//! It provides constant-time scalar multiplication on Montgomery
//! coordinates and is intended for shared-secret derivation and
//! key exchange, not for signatures.
pub mod ed25519;
pub mod x25519;
