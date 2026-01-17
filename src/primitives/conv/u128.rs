//! Conversions between `U256` and 128-bit integer representations
//!
//! This module defines explicit conversions between the fixed-size `U256`
//! type and 128-bit integer forms.
//!
//! These conversions are primarily intended to support internal arithmetic
//! operations (such as multiplication) and interoperability with native
//! integer types, while preserving big-endian semantics and avoiding
//! implicit truncation.

use crate::primitives::U256;

/// Converts a `U256` into two 128-bit words.
///
/// The resulting array is ordered as `[high, low]`, where:
/// - `high` contains the most significant 128 bits
/// - `low` contains the least significant 128 bits
impl From<U256> for [u128; 2] {
    fn from(value: U256) -> Self {
        let mut high = [0u8; 16];
        let mut low = [0u8; 16];

        high.copy_from_slice(&value.0[..16]);
        low.copy_from_slice(&value.0[16..]);

        [u128::from_be_bytes(high), u128::from_be_bytes(low)]
    }
}

/// Converts two 128-bit words into a `U256`.
///
/// The input array must be ordered as `[high, low]`, corresponding to the
/// most significant and least significant halves of the 256-bit value.
impl From<[u128; 2]> for U256 {
    fn from(value: [u128; 2]) -> Self {
        let mut out = [0u8; 32];

        out[..16].copy_from_slice(&value[0].to_be_bytes());
        out[16..].copy_from_slice(&value[1].to_be_bytes());

        U256(out)
    }
}

/// Attempts to convert a `U256` into a `u128`.
///
/// The conversion succeeds only if the upper 128 bits of the value are zero.
/// Otherwise, an error is returned to signal that the value does not fit
/// into a 128-bit integer.
impl TryFrom<U256> for u128 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..16].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut buf = [0u8; 16];
        buf.copy_from_slice(&value.0[16..]);

        Ok(u128::from_be_bytes(buf))
    }
}

/// Converts a `u128` into a `U256`.
///
/// The value is placed in the least significant 128 bits of the 256-bit
/// integer, with the upper bits set to zero.
impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&value.to_be_bytes());

        U256(out)
    }
}
