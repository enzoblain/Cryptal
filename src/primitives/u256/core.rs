//! 256-bit unsigned integer primitive
//!
//! This module defines a fixed-size 256-bit unsigned integer type (`U256`)
//! used throughout the Nebula ecosystem.
//!
//! It is designed as a **simple, explicit value type**, not as a full
//! big-integer arithmetic library. Its primary use cases include:
//! - cryptographic hash outputs (e.g. SHA-256)
//! - node identifiers
//! - keys, distances, and comparisons
//!
//! The internal representation is big-endian, which aligns naturally with
//! cryptographic conventions and human-readable hexadecimal formatting.

use std::fmt::{Display, Formatter, Result};

/// Fixed-size 256-bit unsigned integer.
///
/// The value is stored as 32 bytes in **big-endian** order.
///
/// This type intentionally exposes only minimal functionality required
/// by the Nebula project, favoring clarity and correctness over completeness.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(pub(crate) [u8; 32]);

impl U256 {
        /// Crée un U256 à partir d'un tableau d'octets little-endian (le moins significatif d'abord).
        pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
            let mut be = [0u8; 32];
            for i in 0..32 {
                be[i] = bytes[31 - i];
            }
            U256(be)
        }
    /// The value zero.
    pub const ZERO: Self = Self([0u8; 32]);

    /// The value one.
    pub const ONE: Self = Self::one_be();

    /// The maximum representable value (2²⁵⁶ − 1).
    pub const MAX: Self = Self([255u8; 32]);

    /// Returns the value one encoded in big-endian form.
    ///
    /// This is a `const` constructor suitable for use in constant contexts.
    pub const fn one_be() -> Self {
        let mut out = [0u8; 32];
        out[31] = 1;
        U256(out)
    }

    /// Counts the number of leading zero bits in the integer.
    ///
    /// This method scans the integer from the most significant byte and
    /// returns the number of zero bits before the first one bit is encountered.
    ///
    /// # Returns
    /// The number of leading zero bits in the range `0..=256`.
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

impl Display for U256 {
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
