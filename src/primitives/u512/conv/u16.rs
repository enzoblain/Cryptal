//! Conversions between `U512` and 16-bit integer representations
//!
//! This module defines explicit conversions between the fixed-size `U512`
//! type and 16-bit integer forms.
//!
//! These conversions are intended to support internal arithmetic,
//! serialization, and interoperability with native integer types, while
//! preserving big-endian semantics and preventing implicit truncation.

use crate::primitives::U512;

/// Converts a `U512` into thirty-two 16-bit words.
///
/// The resulting array is ordered from most significant to least
/// significant word, using big-endian interpretation.
impl From<U512> for [u16; 32] {
    fn from(value: U512) -> Self {
        let mut out = [0u16; 32];

        for (o, chunk) in out.iter_mut().zip(value.0.chunks_exact(2)) {
            *o = u16::from_be_bytes(chunk.try_into().unwrap());
        }

        out
    }
}

/// Converts thirty-two 16-bit words into a `U512`.
///
/// The input array must be ordered from most significant to least
/// significant word.
impl From<[u16; 32]> for U512 {
    fn from(value: [u16; 32]) -> Self {
        let mut out = [0u8; 64];

        for (chunk, v) in out.chunks_exact_mut(2).zip(value.into_iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        U512(out)
    }
}

/// Attempts to convert a `U512` into a `u16`.
///
/// The conversion succeeds only if the upper 496 bits of the value are zero.
/// If any higher-order byte is non-zero, the conversion fails.
impl TryFrom<U512> for u16 {
    type Error = ();

    fn try_from(value: U512) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(62);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u16::from_be_bytes(low.try_into().unwrap()))
    }
}

/// Converts a `u16` into a `U512`.
///
/// The value is placed in the least significant 16 bits of the 512-bit
/// integer, with all higher bits set to zero.
impl From<u16> for U512 {
    fn from(value: u16) -> Self {
        let mut out = [0u8; 64];

        out[62] = (value >> 8) as u8;
        out[63] = (value & 0xFF) as u8;

        U512(out)
    }
}
