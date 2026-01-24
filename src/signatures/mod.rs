//! Digital signature schemes.
//!
//! This module groups implementations of digital signature algorithms
//! built on top of the crate’s cryptographic primitives and hash
//! functions.
//!
//! Each submodule corresponds to a specific signature scheme and is
//! responsible for its own key types, signing logic, and verification
//! rules. The implementations are intentionally explicit and
//! self-contained, favoring clarity and auditability over abstraction.
//!
//! This module does not expose shared high-level abstractions across
//! signature schemes. Instead, each algorithm is implemented according
//! to its specification, with minimal indirection.

mod ed25519;

pub use ed25519::core as Ed25519;
