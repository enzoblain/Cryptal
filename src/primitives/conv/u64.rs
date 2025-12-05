//! Conversions between `U256` and `u64` (and arrays of 64-bit words).

use super::U256;

#[cfg(not(feature = "speed"))]
/// Splits a `U256` into 4 big-endian `u64` words.
impl From<U256> for [u64; 4] {
    fn from(value: U256) -> Self {
        let mut out = [0u64; 4];

        for (i, chunk) in value.0.chunks_exact(8).enumerate() {
            out[i] = u64::from_be_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
        }

        out
    }
}

#[cfg(feature = "speed")]
/// Splits a `U256` into 4 big-endian `u64` words (unchecked indexing fast path).
impl From<U256> for [u64; 4] {
    fn from(value: U256) -> Self {
        let b = &value.0;

        [
            ((b[0] as u64) << 56)
                | ((b[1] as u64) << 48)
                | ((b[2] as u64) << 40)
                | ((b[3] as u64) << 32)
                | ((b[4] as u64) << 24)
                | ((b[5] as u64) << 16)
                | ((b[6] as u64) << 8)
                | (b[7] as u64),
            ((b[8] as u64) << 56)
                | ((b[9] as u64) << 48)
                | ((b[10] as u64) << 40)
                | ((b[11] as u64) << 32)
                | ((b[12] as u64) << 24)
                | ((b[13] as u64) << 16)
                | ((b[14] as u64) << 8)
                | (b[15] as u64),
            ((b[16] as u64) << 56)
                | ((b[17] as u64) << 48)
                | ((b[18] as u64) << 40)
                | ((b[19] as u64) << 32)
                | ((b[20] as u64) << 24)
                | ((b[21] as u64) << 16)
                | ((b[22] as u64) << 8)
                | (b[23] as u64),
            ((b[24] as u64) << 56)
                | ((b[25] as u64) << 48)
                | ((b[26] as u64) << 40)
                | ((b[27] as u64) << 32)
                | ((b[28] as u64) << 24)
                | ((b[29] as u64) << 16)
                | ((b[30] as u64) << 8)
                | (b[31] as u64),
        ]
    }
}

#[cfg(not(feature = "speed"))]
/// Builds a `U256` from 4 big-endian `u64` words.
impl From<[u64; 4]> for U256 {
    fn from(value: [u64; 4]) -> Self {
        let mut out = [0u8; 32];

        for (i, v) in value.into_iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&v.to_be_bytes());
        }

        U256(out)
    }
}

#[cfg(feature = "speed")]
/// Builds a `U256` from 4 big-endian `u64` words (unchecked indexing fast path).
impl From<[u64; 4]> for U256 {
    fn from(value: [u64; 4]) -> Self {
        let mut out = [0u8; 32];

        for (i, v) in value.into_iter().enumerate() {
            let o = 8 * i;

            out[o] = (v >> 56) as u8;
            out[o + 1] = (v >> 48) as u8;
            out[o + 2] = (v >> 40) as u8;
            out[o + 3] = (v >> 32) as u8;
            out[o + 4] = (v >> 24) as u8;
            out[o + 5] = (v >> 16) as u8;
            out[o + 6] = (v >> 8) as u8;
            out[o + 7] = v as u8;
        }

        U256(out)
    }
}

#[cfg(not(feature = "speed"))]
/// Attempts to downcast a `U256` into `u64` (fails if high bytes are non-zero).
impl TryFrom<U256> for u64 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..24].iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u64::from_be_bytes([
            value.0[24],
            value.0[25],
            value.0[26],
            value.0[27],
            value.0[28],
            value.0[29],
            value.0[30],
            value.0[31],
        ]))
    }
}

#[cfg(feature = "speed")]
/// Attempts to downcast a `U256` into `u64` (fast path with unchecked indexing).
impl TryFrom<U256> for u64 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..24].iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(((value.0[24] as u64) << 56)
            | ((value.0[25] as u64) << 48)
            | ((value.0[26] as u64) << 40)
            | ((value.0[27] as u64) << 32)
            | ((value.0[28] as u64) << 24)
            | ((value.0[29] as u64) << 16)
            | ((value.0[30] as u64) << 8)
            | (value.0[31] as u64))
    }
}

#[cfg(not(feature = "speed"))]
/// Promotes a `u64` into big-endian `U256`.
impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&value.to_be_bytes());

        U256(out)
    }
}

#[cfg(feature = "speed")]
/// Promotes a `u64` into big-endian `U256` (fast path).
impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        let mut out = [0u8; 32];

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
