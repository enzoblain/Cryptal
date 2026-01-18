//! Primitive types
//!
//! This module defines low-level primitive types used throughout the
//! Nebula ecosystem.
//!
//! Primitives are simple, fixed-size, dependency-free building blocks that
//! provide well-defined semantics and predictable behavior. They are
//! intentionally minimal and do not attempt to replicate full standard
//! library abstractions or full-featured big-integer libraries.
//!
//! Current primitives include:
//! - `U256`: a fixed-size 256-bit unsigned integer
//! - `U512`: a fixed-size 512-bit unsigned integer
//!
//! Additional primitives and conversion utilities may be added as the
//! ecosystem evolves.

mod u256;
mod u512;

/// Fixed-size unsigned integer primitives.
///
/// These types are re-exported as the primary primitive integers used
/// across the Nebula codebase.
pub use u256::U256;
pub use u512::U512;
