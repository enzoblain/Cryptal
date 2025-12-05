//! Conversions between `U256` and `u128` (and arrays of 128-bit halves).

use super::U256;

#[cfg(not(feature = "speed"))]
/// Splits a `U256` into two big-endian `u128` halves.
impl From<U256> for [u128; 2] {
    fn from(value: U256) -> Self {
        let mut hi = [0u8; 16];
        let mut lo = [0u8; 16];

        hi.copy_from_slice(&value.0[..16]);
        lo.copy_from_slice(&value.0[16..]);

        [u128::from_be_bytes(hi), u128::from_be_bytes(lo)]
    }
}

#[cfg(feature = "speed")]
/// Splits a `U256` into two big-endian `u128` halves (unchecked indexing fast path).
impl From<U256> for [u128; 2] {
    fn from(value: U256) -> Self {
        let b = &value.0;
        let hi = ((b[0] as u128) << 120)
            | ((b[1] as u128) << 112)
            | ((b[2] as u128) << 104)
            | ((b[3] as u128) << 96)
            | ((b[4] as u128) << 88)
            | ((b[5] as u128) << 80)
            | ((b[6] as u128) << 72)
            | ((b[7] as u128) << 64)
            | ((b[8] as u128) << 56)
            | ((b[9] as u128) << 48)
            | ((b[10] as u128) << 40)
            | ((b[11] as u128) << 32)
            | ((b[12] as u128) << 24)
            | ((b[13] as u128) << 16)
            | ((b[14] as u128) << 8)
            | (b[15] as u128);

        let b = &value.0[16..];
        let lo = ((b[0] as u128) << 120)
            | ((b[1] as u128) << 112)
            | ((b[2] as u128) << 104)
            | ((b[3] as u128) << 96)
            | ((b[4] as u128) << 88)
            | ((b[5] as u128) << 80)
            | ((b[6] as u128) << 72)
            | ((b[7] as u128) << 64)
            | ((b[8] as u128) << 56)
            | ((b[9] as u128) << 48)
            | ((b[10] as u128) << 40)
            | ((b[11] as u128) << 32)
            | ((b[12] as u128) << 24)
            | ((b[13] as u128) << 16)
            | ((b[14] as u128) << 8)
            | (b[15] as u128);
        [hi, lo]
    }
}

#[cfg(not(feature = "speed"))]
/// Builds a `U256` from two big-endian `u128` halves.
impl From<[u128; 2]> for U256 {
    fn from(value: [u128; 2]) -> Self {
        let mut out = [0u8; 32];

        out[..16].copy_from_slice(&value[0].to_be_bytes());
        out[16..].copy_from_slice(&value[1].to_be_bytes());

        U256(out)
    }
}

#[cfg(feature = "speed")]
/// Builds a `U256` from two big-endian `u128` halves (unchecked indexing fast path).
impl From<[u128; 2]> for U256 {
    fn from(value: [u128; 2]) -> Self {
        let mut out = [0u8; 32];

        let hi = value[0];
        let lo = value[1];

        out[0] = (hi >> 120) as u8;
        out[1] = (hi >> 112) as u8;
        out[2] = (hi >> 104) as u8;
        out[3] = (hi >> 96) as u8;
        out[4] = (hi >> 88) as u8;
        out[5] = (hi >> 80) as u8;
        out[6] = (hi >> 72) as u8;
        out[7] = (hi >> 64) as u8;
        out[8] = (hi >> 56) as u8;
        out[9] = (hi >> 48) as u8;
        out[10] = (hi >> 40) as u8;
        out[11] = (hi >> 32) as u8;
        out[12] = (hi >> 24) as u8;
        out[13] = (hi >> 16) as u8;
        out[14] = (hi >> 8) as u8;
        out[15] = hi as u8;

        out[16] = (lo >> 120) as u8;
        out[17] = (lo >> 112) as u8;
        out[18] = (lo >> 104) as u8;
        out[19] = (lo >> 96) as u8;
        out[20] = (lo >> 88) as u8;
        out[21] = (lo >> 80) as u8;
        out[22] = (lo >> 72) as u8;
        out[23] = (lo >> 64) as u8;
        out[24] = (lo >> 56) as u8;
        out[25] = (lo >> 48) as u8;
        out[26] = (lo >> 40) as u8;
        out[27] = (lo >> 32) as u8;
        out[28] = (lo >> 24) as u8;
        out[29] = (lo >> 16) as u8;
        out[30] = (lo >> 8) as u8;
        out[31] = lo as u8;

        U256(out)
    }
}

#[cfg(not(feature = "speed"))]
/// Attempts to downcast a `U256` into `u128` (fails if high bytes are non-zero).
impl TryFrom<U256> for u128 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..16].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut buf = [0u8; 16];
        buf.copy_from_slice(&value.0[16..]);

        Ok(u128::from_be_bytes(buf))
    }
}

#[cfg(feature = "speed")]
/// Attempts to downcast a `U256` into `u128` (fast path with unchecked indexing).
impl TryFrom<U256> for u128 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..16].iter().any(|&b| b != 0) {
            return Err(());
        }

        let b = &value.0[16..];

        Ok(((b[0] as u128) << 120)
            | ((b[1] as u128) << 112)
            | ((b[2] as u128) << 104)
            | ((b[3] as u128) << 96)
            | ((b[4] as u128) << 88)
            | ((b[5] as u128) << 80)
            | ((b[6] as u128) << 72)
            | ((b[7] as u128) << 64)
            | ((b[8] as u128) << 56)
            | ((b[9] as u128) << 48)
            | ((b[10] as u128) << 40)
            | ((b[11] as u128) << 32)
            | ((b[12] as u128) << 24)
            | ((b[13] as u128) << 16)
            | ((b[14] as u128) << 8)
            | (b[15] as u128))
    }
}

#[cfg(not(feature = "speed"))]
/// Promotes a `u128` into big-endian `U256`.
impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&value.to_be_bytes());

        U256(out)
    }
}

#[cfg(feature = "speed")]
/// Promotes a `u128` into big-endian `U256` (fast path).
impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        let mut out = [0u8; 32];

        out[16] = (value >> 120) as u8;
        out[17] = (value >> 112) as u8;
        out[18] = (value >> 104) as u8;
        out[19] = (value >> 96) as u8;
        out[20] = (value >> 88) as u8;
        out[21] = (value >> 80) as u8;
        out[22] = (value >> 72) as u8;
        out[23] = (value >> 64) as u8;
        out[24] = (value >> 56) as u8;
        out[25] = (value >> 48) as u8;
        out[26] = (value >> 40) as u8;
        out[27] = (value >> 32) as u8;
        out[28] = (value >> 24) as u8;
        out[29] = (value >> 16) as u8;
        out[30] = (value >> 8) as u8;
        out[31] = value as u8;

        U256(out)
    }
}
