//! Conversions between `U256` and `u8` plus byte views.

use super::U256;

/// Converts a `U256` into its backing 32-byte array.
impl From<U256> for [u8; 32] {
    fn from(value: U256) -> Self {
        value.0
    }
}

/// Builds a `U256` from a 32-byte big-endian array.
impl From<[u8; 32]> for U256 {
    fn from(value: [u8; 32]) -> Self {
        U256(value)
    }
}

/// Attempts to downcast a `U256` into `u8` (fails if high bytes are non-zero).
impl TryFrom<U256> for u8 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..31].iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(value.0[31])
    }
}

/// Promotes a `u8` into big-endian `U256`.
impl From<u8> for U256 {
    fn from(value: u8) -> Self {
        let mut out = [0u8; 32];
        out[31] = value;

        U256(out)
    }
}

/// View `U256` as a byte slice.
impl AsRef<[u8]> for &U256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// View `U256` as a 32-byte array reference.
impl AsRef<[u8; 32]> for U256 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
