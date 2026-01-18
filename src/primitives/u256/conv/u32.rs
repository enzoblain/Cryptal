//! Conversions between `U256` and 32-bit integer representations
//!
//! This module defines explicit conversions between the fixed-size `U256`
//! type and 32-bit integer forms.
//!
//! These conversions are intended to support internal arithmetic,
//! serialization, and interoperability with native integer types, while
//! preserving big-endian semantics and preventing implicit truncation.

use crate::primitives::U256;

/// Converts a `U256` into eight 32-bit words.
///
/// The resulting array is ordered from most significant to least
/// significant word, using big-endian interpretation.
impl From<U256> for [u32; 8] {
    fn from(value: U256) -> Self {
        let mut out = [0u32; 8];

        for (o, chunk) in out.iter_mut().zip(value.0.chunks_exact(4)) {
            *o = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        out
    }
}

/// Converts eight 32-bit words into a `U256`.
///
/// The input array must be ordered from most significant to least
/// significant word.
impl From<[u32; 8]> for U256 {
    fn from(value: [u32; 8]) -> Self {
        let mut out = [0u8; 32];

        for (chunk, v) in out.chunks_exact_mut(4).zip(value.into_iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        U256(out)
    }
}

/// Attempts to convert a `U256` into a `u32`.
///
/// The conversion succeeds only if the upper 224 bits of the value are zero.
/// If any higher-order byte is non-zero, the conversion fails.
impl TryFrom<U256> for u32 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(28);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u32::from_be_bytes(low.try_into().unwrap()))
    }
}

/// Converts a `u32` into a `U256`.
///
/// The value is placed in the least significant 32 bits of the 256-bit
/// integer, with all higher bits set to zero.
impl From<u32> for U256 {
    fn from(value: u32) -> Self {
        let mut out = [0u8; 32];
        out[28..32].copy_from_slice(&value.to_be_bytes());
        U256(out)
    }
}
