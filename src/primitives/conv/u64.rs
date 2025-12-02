use super::U256;

/// u256 -> [u64; 4]
impl From<U256> for [u64; 4] {
    fn from(value: U256) -> Self {
        let mut out = [0u64; 4];

        for (i, chunk) in value.0.chunks_exact(8).enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            out[i] = u64::from_be_bytes(bytes);
        }

        out
    }
}

/// [u64; 4] -> u256
impl From<[u64; 4]> for U256 {
    fn from(value: [u64; 4]) -> Self {
        let mut out = [0u8; 32];

        for (i, v) in value.into_iter().enumerate() {
            let bytes = v.to_be_bytes();
            out[i * 8..i * 8 + 8].copy_from_slice(&bytes);
        }

        Self(out)
    }
}

/// U256 -> u64
impl TryFrom<U256> for u64 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..24].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&value.0[24..32]);

        Ok(u64::from_be_bytes(bytes))
    }
}

/// u64 -> u256
impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&value.to_be_bytes());
        U256(out)
    }
}
