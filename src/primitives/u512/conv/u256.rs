//! Conversions between `U512` and `U256`
//!
//! This module defines explicit conversions between the fixed-size `U512`
//! and `U256` integer types.
//!
//! These conversions are intended to support interoperability between
//! different cryptographic widths (e.g. SHA-256 ↔ SHA-512), while preserving
//! big-endian semantics and avoiding implicit truncation.

use crate::primitives::{U256, U512};

/// Converts a `U256` into a `U512`.
///
/// The 256-bit value is placed in the least significant half of the
/// 512-bit integer, with the upper 256 bits set to zero.
impl From<U256> for U512 {
    fn from(value: U256) -> Self {
        let mut out = [0u8; 64];
        out[32..].copy_from_slice(&value.0);
        U512(out)
    }
}

/// Attempts to convert a `U512` into a `U256`.
///
/// The conversion succeeds only if the upper 256 bits of the value are zero.
/// If any higher-order byte is non-zero, the conversion fails.
impl TryFrom<U512> for U256 {
    type Error = ();

    fn try_from(value: U512) -> Result<Self, Self::Error> {
        if value.0[..32].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&value.0[32..]);

        Ok(U256(out))
    }
}
