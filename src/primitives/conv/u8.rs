//! Conversions between `U256` and byte representations
//!
//! This module defines explicit conversions between the fixed-size `U256`
//! type and raw byte representations.
//!
//! These conversions are fundamental for:
//! - serialization and deserialization
//! - hashing and cryptographic operations
//! - interoperability with low-level APIs
//!
//! All conversions preserve the internal big-endian representation of
//! `U256` and avoid implicit truncation.

use crate::primitives::U256;

/// Converts a `U256` into a 32-byte array.
///
/// The returned array represents the value in big-endian order.
impl From<U256> for [u8; 32] {
    fn from(value: U256) -> Self {
        value.0
    }
}

/// Converts a 32-byte array into a `U256`.
///
/// The input is interpreted as a big-endian 256-bit value.
impl From<[u8; 32]> for U256 {
    fn from(value: [u8; 32]) -> Self {
        U256(value)
    }
}

/// Attempts to convert a `U256` into a `u8`.
///
/// The conversion succeeds only if the upper 248 bits of the value are zero.
/// If any higher-order byte is non-zero, the conversion fails.
impl TryFrom<U256> for u8 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(31);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(low[0])
    }
}

/// Converts a `u8` into a `U256`.
///
/// The value is placed in the least significant byte of the 256-bit
/// integer, with all higher bytes set to zero.
impl From<u8> for U256 {
    fn from(value: u8) -> Self {
        let mut out = [0u8; 32];
        out[31] = value;
        U256(out)
    }
}

/// Borrows the underlying byte slice of a `U256`.
///
/// This is useful for read-only access in hashing, serialization,
/// or comparison routines.
impl AsRef<[u8]> for &U256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Borrows the underlying 32-byte array of a `U256`.
impl AsRef<[u8; 32]> for U256 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
