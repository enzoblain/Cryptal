//! Conversions between `U256` and native integer types
//!
//! This module provides explicit and safe conversions between the fixed-size
//! `U256` type and native platform integer types.
//!
//! The conversions are designed to:
//! - preserve big-endian semantics
//! - avoid implicit truncation
//! - fail explicitly when a value does not fit in the target type
//!
//! Only the conversions required by the Nebula ecosystem are implemented.

use crate::primitives::U256;
use std::mem;

const USIZE_BYTES: usize = mem::size_of::<usize>();

/// Converts a `usize` into a `U256`.
///
/// The value is encoded in big-endian form and placed in the least
/// significant bytes of the 256-bit integer.
impl From<usize> for U256 {
    fn from(value: usize) -> Self {
        let mut out = [0u8; 32];

        let bytes = value.to_be_bytes();
        let offset = 32 - bytes.len();

        out[offset..].copy_from_slice(&bytes);

        U256(out)
    }
}

/// Attempts to convert a `U256` into a `usize`.
///
/// The conversion succeeds only if the value fits entirely within the
/// platform's `usize` width. If any of the higher-order bytes are non-zero,
/// the conversion fails.
impl TryFrom<U256> for usize {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let offset = 32 - USIZE_BYTES;

        if value.0[..offset].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut buf = [0u8; USIZE_BYTES];
        buf.copy_from_slice(&value.0[offset..]);

        Ok(usize::from_be_bytes(buf))
    }
}
