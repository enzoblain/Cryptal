//! Conversions between `U256` and `u32` (and arrays of 32-bit words).

use super::U256;

#[cfg(not(feature = "speed"))]
/// Splits a `U256` into 8 big-endian `u32` words.
impl From<U256> for [u32; 8] {
    fn from(value: U256) -> Self {
        let mut out = [0u32; 8];

        for (i, chunk) in value.0.chunks_exact(4).enumerate() {
            out[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        out
    }
}

#[cfg(feature = "speed")]
/// Splits a `U256` into 8 big-endian `u32` words (unchecked indexing fast path).
impl From<U256> for [u32; 8] {
    fn from(value: U256) -> Self {
        let b = &value.0;

        [
            ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | (b[3] as u32),
            ((b[4] as u32) << 24) | ((b[5] as u32) << 16) | ((b[6] as u32) << 8) | (b[7] as u32),
            ((b[8] as u32) << 24) | ((b[9] as u32) << 16) | ((b[10] as u32) << 8) | (b[11] as u32),
            ((b[12] as u32) << 24)
                | ((b[13] as u32) << 16)
                | ((b[14] as u32) << 8)
                | (b[15] as u32),
            ((b[16] as u32) << 24)
                | ((b[17] as u32) << 16)
                | ((b[18] as u32) << 8)
                | (b[19] as u32),
            ((b[20] as u32) << 24)
                | ((b[21] as u32) << 16)
                | ((b[22] as u32) << 8)
                | (b[23] as u32),
            ((b[24] as u32) << 24)
                | ((b[25] as u32) << 16)
                | ((b[26] as u32) << 8)
                | (b[27] as u32),
            ((b[28] as u32) << 24)
                | ((b[29] as u32) << 16)
                | ((b[30] as u32) << 8)
                | (b[31] as u32),
        ]
    }
}

#[cfg(not(feature = "speed"))]
/// Builds a `U256` from 8 big-endian `u32` words.
impl From<[u32; 8]> for U256 {
    fn from(value: [u32; 8]) -> Self {
        let mut out = [0u8; 32];

        for (i, v) in value.into_iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }

        U256(out)
    }
}

#[cfg(feature = "speed")]
/// Builds a `U256` from 8 big-endian `u32` words (unchecked indexing fast path).
impl From<[u32; 8]> for U256 {
    fn from(value: [u32; 8]) -> Self {
        let mut out = [0u8; 32];

        for (i, v) in value.into_iter().enumerate() {
            let o = 4 * i;
            out[o] = (v >> 24) as u8;
            out[o + 1] = (v >> 16) as u8;
            out[o + 2] = (v >> 8) as u8;
            out[o + 3] = v as u8;
        }

        U256(out)
    }
}

#[cfg(not(feature = "speed"))]
/// Attempts to downcast a `U256` into `u32` (fails if high bytes are non-zero).
impl TryFrom<U256> for u32 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..28].iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u32::from_be_bytes([
            value.0[28],
            value.0[29],
            value.0[30],
            value.0[31],
        ]))
    }
}

#[cfg(feature = "speed")]
/// Attempts to downcast a `U256` into `u32` (fast path with unchecked indexing).
impl TryFrom<U256> for u32 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..28].iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(((value.0[28] as u32) << 24)
            | ((value.0[29] as u32) << 16)
            | ((value.0[30] as u32) << 8)
            | (value.0[31] as u32))
    }
}

#[cfg(not(feature = "speed"))]
/// Promotes a `u32` into big-endian `U256`.
impl From<u32> for U256 {
    fn from(value: u32) -> Self {
        let mut out = [0u8; 32];
        out[28..32].copy_from_slice(&value.to_be_bytes());

        U256(out)
    }
}

#[cfg(feature = "speed")]
/// Promotes a `u32` into big-endian `U256` (fast path).
impl From<u32> for U256 {
    fn from(value: u32) -> Self {
        let mut out = [0u8; 32];

        out[28] = (value >> 24) as u8;
        out[29] = (value >> 16) as u8;
        out[30] = (value >> 8) as u8;
        out[31] = value as u8;

        U256(out)
    }
}
