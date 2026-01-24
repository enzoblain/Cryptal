//! Cryptographic utilities and primitives for Nebula
//!
//! This crate provides low-level cryptographic building blocks used
//! throughout the Nebula ecosystem.
//!
//! The focus is on **clarity, predictability, and auditability**, rather
//! than on providing a large or high-level cryptographic API. All components
//! are designed to be dependency-free, explicit in their semantics, and
//! suitable for security-critical code.
//!
//! # Module overview
//!
//! - `utils`  
//!   Low-level, non-cryptographic utilities used by the rest of the crate.
//!   This module contains environment-facing helpers, byte-level utilities,
//!   and other foundational components required to support cryptographic
//!   code without polluting its APIs.
//!
//! - `hash`  
//!   Cryptographic hash functions and related utilities (e.g. SHA-256,
//!   SHA-512). These implementations are intended for internal use and
//!   protocol-level constructions.
//!
//! - `primitives`  
//!   Fixed-size, low-level cryptographic primitives such as `U256` and
//!   `U512`. These types provide explicit, predictable semantics and are
//!   used as fundamental building blocks across the crate.
//!
//! - `rng`  
//!   Cryptographically secure pseudorandom number generators built from
//!   internal primitives. These generators may rely on the `utils` module
//!   for initial entropy or environment interaction, while providing
//!   deterministic and auditable randomness expansion.
//!
//! - `keys`  
//!   Cryptographic key types and key-related operations.
//!
//!   This module defines algorithm-specific key representations (such as
//!   Ed25519 and X25519 keys), along with their derivation, serialization,
//!   and safe transformations. It provides a clear separation between
//!   **key material** and the cryptographic algorithms that operate on it
//!   (signatures, key exchange, etc.).
//!
//!   No signing, verification, or protocol logic lives here—only key
//!   structure and manipulation.
//!
//! - `recovery`  
//!   Cryptographic recovery and survivability mechanisms.
//!
//!   This module contains primitives designed to protect, distribute, and
//!   recover sensitive material in the presence of partial data loss or
//!   compromise. It currently provides an implementation of
//!   **Shamir Secret Sharing (SSS)**, allowing a secret to be split into
//!   multiple shares such that only a configurable threshold of shares is
//!   required for reconstruction.
//!
//!   The Shamir implementation operates entirely over finite fields
//!   (GF(256)), supports threshold-based reconstruction, and includes
//!   share refresh functionality that renews shares without ever
//!   reconstructing the underlying secret.
//!
//!   This module is intended for use cases such as:
//!   - distributed key backup and recovery
//!   - multi-party custody of cryptographic secrets
//!   - long-term survivability of sensitive material
//!   - protection against gradual share compromise
//!
//!   The recovery module is purely cryptographic: it does not perform any
//!   storage, networking, or policy decisions. Those concerns are handled
//!   at higher layers of the Nebula stack.
//!
//! # Design goals
//!
//! - No heap allocations in core primitives
//! - Minimal and explicit APIs
//! - Stable, well-defined semantics
//! - Clear separation between cryptographic code and supporting utilities
//!
//! This crate is not intended to replace full-featured, externally audited
//! cryptographic libraries, but to serve as a small, controlled foundation
//! for Nebula's internal cryptographic needs.

mod utils;

pub mod hash;
pub mod keys;
pub mod primitives;
pub mod recovery;
pub mod rng;
