//! Conversions between `U512` and 128-bit integer representations
//!
//! This module defines explicit conversions between the fixed-size `U512`
//! type and 128-bit integer forms.
//!
//! These conversions are primarily intended to support internal arithmetic
//! operations (such as multiplication) and interoperability with native
//! integer types, while preserving big-endian semantics and avoiding
//! implicit truncation.

use crate::primitives::U512;

/// Converts a `U512` into four 128-bit words.
///
/// The resulting array is ordered as `[w0, w1, w2, w3]`, where:
/// - `w0` contains the most significant 128 bits
/// - `w3` contains the least significant 128 bits
impl From<U512> for [u128; 4] {
    fn from(value: U512) -> Self {
        let mut w0 = [0u8; 16];
        let mut w1 = [0u8; 16];
        let mut w2 = [0u8; 16];
        let mut w3 = [0u8; 16];

        w0.copy_from_slice(&value.0[..16]);
        w1.copy_from_slice(&value.0[16..32]);
        w2.copy_from_slice(&value.0[32..48]);
        w3.copy_from_slice(&value.0[48..]);

        [
            u128::from_be_bytes(w0),
            u128::from_be_bytes(w1),
            u128::from_be_bytes(w2),
            u128::from_be_bytes(w3),
        ]
    }
}

/// Converts four 128-bit words into a `U512`.
///
/// The input array must be ordered from most significant to least
/// significant word.
impl From<[u128; 4]> for U512 {
    fn from(value: [u128; 4]) -> Self {
        let mut out = [0u8; 64];

        out[..16].copy_from_slice(&value[0].to_be_bytes());
        out[16..32].copy_from_slice(&value[1].to_be_bytes());
        out[32..48].copy_from_slice(&value[2].to_be_bytes());
        out[48..].copy_from_slice(&value[3].to_be_bytes());

        U512(out)
    }
}

/// Attempts to convert a `U512` into a `u128`.
///
/// The conversion succeeds only if the upper 384 bits of the value are zero.
/// Otherwise, an error is returned to signal that the value does not fit
/// into a 128-bit integer.
impl TryFrom<U512> for u128 {
    type Error = ();

    fn try_from(value: U512) -> Result<Self, Self::Error> {
        if value.0[..48].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut buf = [0u8; 16];
        buf.copy_from_slice(&value.0[48..]);

        Ok(u128::from_be_bytes(buf))
    }
}

/// Converts a `u128` into a `U512`.
///
/// The value is placed in the least significant 128 bits of the 512-bit
/// integer, with the upper bits set to zero.
impl From<u128> for U512 {
    fn from(value: u128) -> Self {
        let mut out = [0u8; 64];
        out[48..].copy_from_slice(&value.to_be_bytes());

        U512(out)
    }
}
