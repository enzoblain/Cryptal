//! 512-bit unsigned integer primitive
//!
//! This module defines a fixed-size 512-bit unsigned integer type (`U512`)
//! used throughout the Nebula ecosystem.
//!
//! It is designed as a **simple, explicit value type**, not as a full
//! big-integer arithmetic library. Its primary use cases include:
//! - cryptographic hash outputs (e.g. SHA-512)
//! - node identifiers
//! - keys, distances, and comparisons
//!
//! The internal representation is big-endian, which aligns naturally with
//! cryptographic conventions and human-readable hexadecimal formatting.

use std::fmt::{Display, Formatter, Result};

/// Fixed-size 512-bit unsigned integer.
///
/// The value is stored as 64 bytes in **big-endian** order.
///
/// This type intentionally exposes only minimal functionality required
/// by the Nebula project, favoring clarity and correctness over completeness.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct U512(pub(crate) [u8; 64]);

impl U512 {
    /// The value zero.
    pub const ZERO: Self = Self([0u8; 64]);

    /// The value one.
    pub const ONE: Self = Self::one_be();

    /// The maximum representable value (2²⁵¹² − 1).
    pub const MAX: Self = Self([255u8; 64]);

    /// Returns the value one encoded in big-endian form.
    ///
    /// This is a `const` constructor suitable for use in constant contexts.
    pub const fn one_be() -> Self {
        let mut out = [0u8; 64];
        out[63] = 1;
        U512(out)
    }

    /// Counts the number of leading zero bits in the integer.
    ///
    /// This method scans the integer from the most significant byte and
    /// returns the number of zero bits before the first one bit is encountered.
    ///
    /// # Returns
    /// The number of leading zero bits in the range `0..=512`.
    ///
    /// # Notes
    /// This operation is commonly used in cryptographic contexts such as
    /// difficulty calculations, distance metrics, and prefix comparisons.
    pub fn leading_zeros(&self) -> u32 {
        let mut count = 0u32;

        for &byte in self.0.iter() {
            if byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros();
                return count;
            }
        }

        count
    }
}

impl Display for U512 {
    /// Formats the value as a colon-separated hexadecimal string.
    ///
    /// Each byte is printed as two uppercase hexadecimal characters,
    /// separated by `:` for readability.
    ///
    /// Example:
    /// `00:1F:A4:...`
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }

            write!(f, "{:02X}", byte)?;
        }

        Ok(())
    }
}

/// Provides a manual `Default` implementation for `U512`.
///
/// This implementation is required because, on some Rust versions,
/// the `Default` trait is not implemented for arrays larger than 32 elements.
/// As a result, `#[derive(Default)]` cannot be used directly for `[u8; 64]`.
///
/// The default value represents the integer zero, with all 512 bits set to zero.
/// This behavior is consistent with `U512::ZERO` and mirrors the semantics
/// of `Default` for smaller fixed-size integer types.
impl Default for U512 {
    fn default() -> Self {
        U512([0u8; 64])
    }
}
