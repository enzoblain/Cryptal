use super::U256;

/// u256 -> [u32; 8]
impl From<U256> for [u32; 8] {
    fn from(value: U256) -> Self {
        let mut out = [0u32; 8];

        for (i, chunk) in value.0.chunks_exact(4).enumerate() {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(chunk);
            out[i] = u32::from_be_bytes(bytes);
        }

        out
    }
}

/// [u32; 8] -> u256
impl From<[u32; 8]> for U256 {
    fn from(value: [u32; 8]) -> Self {
        let mut out = [0u8; 32];

        for (i, v) in value.into_iter().enumerate() {
            let bytes = v.to_be_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        Self(out)
    }
}

/// U256 -> u32
impl TryFrom<U256> for u32 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..28].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&value.0[28..32]);

        Ok(u32::from_be_bytes(bytes))
    }
}

/// u32 -> u256
impl From<u32> for U256 {
    fn from(value: u32) -> Self {
        let mut out = [0u8; 32];
        out[28..32].copy_from_slice(&value.to_be_bytes());
        U256(out)
    }
}
