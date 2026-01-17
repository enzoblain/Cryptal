//! Primitive types
//!
//! This module defines low-level primitive types used throughout the
//! Nebula ecosystem.
//!
//! Primitives are simple, fixed-size, dependency-free building blocks that
//! provide well-defined semantics and predictable behavior. They are
//! intentionally minimal and do not attempt to replicate full standard
//! library abstractions.
//!
//! Current primitives include:
//! - `U256`: a fixed-size 256-bit unsigned integer
//!
//! Additional primitives and conversion utilities may be added as the
//! ecosystem evolves.

mod conv;
mod ops;
mod u256;

/// Fixed-size 256-bit unsigned integer.
///
/// This type is re-exported as the primary primitive integer used across
/// the codebase.
pub use u256::U256;
