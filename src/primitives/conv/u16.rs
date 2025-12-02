use super::U256;

/// u256 -> [u16; 16] (with move)
impl From<U256> for [u16; 16] {
    fn from(value: U256) -> Self {
        let mut out = [0u16; 16];

        for (i, chunk) in value.0.chunks_exact(2).enumerate() {
            let mut bytes = [0u8; 2];
            bytes.copy_from_slice(chunk);
            out[i] = u16::from_be_bytes(bytes);
        }

        out
    }
}

/// [u16; 16] -> u256 (with move)
impl From<[u16; 16]> for U256 {
    fn from(value: [u16; 16]) -> Self {
        let mut out = [0u8; 32];

        for (i, v) in value.into_iter().enumerate() {
            let bytes = v.to_be_bytes();
            out[i * 2..i * 2 + 2].copy_from_slice(&bytes);
        }

        Self(out)
    }
}

/// U256 -> u16 (with move)
impl TryFrom<U256> for u16 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..30].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&value.0[30..32]);

        Ok(u16::from_be_bytes(bytes))
    }
}

/// u16 -> u256 (with move)
impl From<u16> for U256 {
    fn from(value: u16) -> Self {
        let mut out = [0u8; 32];
        out[30..32].copy_from_slice(&value.to_be_bytes());
        U256(out)
    }
}
