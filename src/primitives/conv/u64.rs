//! Conversions between `U256` and 64-bit integer representations
//!
//! This module defines explicit conversions between the fixed-size `U256`
//! type and 64-bit integer forms.
//!
//! These conversions are intended to support internal arithmetic,
//! serialization, and interoperability with native integer types, while
//! preserving big-endian semantics and preventing implicit truncation.

use crate::primitives::U256;

/// Converts a `U256` into four 64-bit words.
///
/// The resulting array is ordered from most significant to least
/// significant word, using big-endian interpretation.
impl From<U256> for [u64; 4] {
    fn from(value: U256) -> Self {
        let mut out = [0u64; 4];

        for (o, chunk) in out.iter_mut().zip(value.0.chunks_exact(8)) {
            *o = u64::from_be_bytes(chunk.try_into().unwrap());
        }

        out
    }
}

/// Converts four 64-bit words into a `U256`.
///
/// The input array must be ordered from most significant to least
/// significant word.
impl From<[u64; 4]> for U256 {
    fn from(value: [u64; 4]) -> Self {
        let mut out = [0u8; 32];

        for (chunk, v) in out.chunks_exact_mut(8).zip(value.into_iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        U256(out)
    }
}

/// Attempts to convert a `U256` into a `u64`.
///
/// The conversion succeeds only if the upper 192 bits of the value are zero.
/// If any higher-order byte is non-zero, the conversion fails.
impl TryFrom<U256> for u64 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(24);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u64::from_be_bytes(low.try_into().unwrap()))
    }
}

/// Converts a `u64` into a `U256`.
///
/// The value is placed in the least significant 64 bits of the 256-bit
/// integer, with all higher bits set to zero.
impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&value.to_be_bytes());
        U256(out)
    }
}
