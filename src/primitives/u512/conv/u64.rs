//! Conversions between `U512` and 64-bit integer representations
//!
//! This module defines explicit conversions between the fixed-size `U512`
//! type and 64-bit integer forms.
//!
//! These conversions are intended to support internal arithmetic,
//! serialization, and interoperability with native integer types, while
//! preserving big-endian semantics and preventing implicit truncation.

use crate::primitives::U512;

/// Converts a `U512` into eight 64-bit words.
///
/// The resulting array is ordered from most significant to least
/// significant word, using big-endian interpretation.
impl From<U512> for [u64; 8] {
    fn from(value: U512) -> Self {
        let mut out = [0u64; 8];

        for (o, chunk) in out.iter_mut().zip(value.0.chunks_exact(8)) {
            *o = u64::from_be_bytes(chunk.try_into().unwrap());
        }

        out
    }
}

/// Converts eight 64-bit words into a `U512`.
///
/// The input array must be ordered from most significant to least
/// significant word.
impl From<[u64; 8]> for U512 {
    fn from(value: [u64; 8]) -> Self {
        let mut out = [0u8; 64];

        for (chunk, v) in out.chunks_exact_mut(8).zip(value.into_iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        U512(out)
    }
}

/// Attempts to convert a `U512` into a `u64`.
///
/// The conversion succeeds only if the upper 448 bits of the value are zero.
/// If any higher-order byte is non-zero, the conversion fails.
impl TryFrom<U512> for u64 {
    type Error = ();

    fn try_from(value: U512) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(56);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u64::from_be_bytes(low.try_into().unwrap()))
    }
}

/// Converts a `u64` into a `U512`.
///
/// The value is placed in the least significant 64 bits of the 512-bit
/// integer, with all higher bits set to zero.
impl From<u64> for U512 {
    fn from(value: u64) -> Self {
        let mut out = [0u8; 64];
        out[56..64].copy_from_slice(&value.to_be_bytes());
        U512(out)
    }
}
