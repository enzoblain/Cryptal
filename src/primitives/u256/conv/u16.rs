//! Conversions between `U256` and 16-bit integer representations
//!
//! This module defines explicit conversions between the fixed-size `U256`
//! type and 16-bit integer forms.
//!
//! These conversions are intended to support internal arithmetic,
//! serialization, and interoperability with native integer types, while
//! preserving big-endian semantics and preventing implicit truncation.

use crate::primitives::U256;

/// Converts a `U256` into sixteen 16-bit words.
///
/// The resulting array is ordered from most significant to least
/// significant word, using big-endian interpretation.
impl From<U256> for [u16; 16] {
    fn from(value: U256) -> Self {
        let mut out = [0u16; 16];

        for (o, chunk) in out.iter_mut().zip(value.0.chunks_exact(2)) {
            *o = u16::from_be_bytes(chunk.try_into().unwrap());
        }

        out
    }
}

/// Converts sixteen 16-bit words into a `U256`.
///
/// The input array must be ordered from most significant to least
/// significant word.
impl From<[u16; 16]> for U256 {
    fn from(value: [u16; 16]) -> Self {
        let mut out = [0u8; 32];

        for (chunk, v) in out.chunks_exact_mut(2).zip(value.into_iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        U256(out)
    }
}

/// Attempts to convert a `U256` into a `u16`.
///
/// The conversion succeeds only if the upper 240 bits of the value are zero.
/// If any higher-order byte is non-zero, the conversion fails.
impl TryFrom<U256> for u16 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(30);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u16::from_be_bytes(low.try_into().unwrap()))
    }
}

/// Converts a `u16` into a `U256`.
///
/// The value is placed in the least significant 16 bits of the 256-bit
/// integer, with all higher bits set to zero.
impl From<u16> for U256 {
    fn from(value: u16) -> Self {
        let mut out = [0u8; 32];

        out[30] = (value >> 8) as u8;
        out[31] = (value & 0xFF) as u8;

        U256(out)
    }
}
