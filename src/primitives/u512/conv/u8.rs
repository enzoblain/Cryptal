//! Conversions between `U512` and byte representations
//!
//! This module defines explicit conversions between the fixed-size `U512`
//! type and raw byte representations.
//!
//! These conversions are fundamental for:
//! - serialization and deserialization
//! - hashing and cryptographic operations
//! - interoperability with low-level APIs
//!
//! All conversions preserve the internal big-endian representation of
//! `U512` and avoid implicit truncation.

use crate::primitives::U512;

/// Converts a `U512` into a 64-byte array.
///
/// The returned array represents the value in big-endian order.
impl From<U512> for [u8; 64] {
    fn from(value: U512) -> Self {
        value.0
    }
}

/// Converts a 64-byte array into a `U512`.
///
/// The input is interpreted as a big-endian 512-bit value.
impl From<[u8; 64]> for U512 {
    fn from(value: [u8; 64]) -> Self {
        U512(value)
    }
}

/// Attempts to convert a `U512` into a `u8`.
///
/// The conversion succeeds only if the upper 504 bits of the value are zero.
/// If any higher-order byte is non-zero, the conversion fails.
impl TryFrom<U512> for u8 {
    type Error = ();

    fn try_from(value: U512) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(63);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(low[0])
    }
}

/// Converts a `u8` into a `U512`.
///
/// The value is placed in the least significant byte of the 512-bit
/// integer, with all higher bytes set to zero.
impl From<u8> for U512 {
    fn from(value: u8) -> Self {
        let mut out = [0u8; 64];
        out[63] = value;
        U512(out)
    }
}

/// Borrows the underlying byte slice of a `U512`.
///
/// This is useful for read-only access in hashing, serialization,
/// or comparison routines.
impl AsRef<[u8]> for &U512 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Borrows the underlying 64-byte array of a `U512`.
impl AsRef<[u8; 64]> for U512 {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}
