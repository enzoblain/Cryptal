use crate::primitives::U256;

impl From<U256> for [u32; 8] {
    fn from(value: U256) -> Self {
        let mut out = [0u32; 8];

        for (o, chunk) in out.iter_mut().zip(value.0.chunks_exact(4)) {
            *o = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        out
    }
}

impl From<[u32; 8]> for U256 {
    fn from(value: [u32; 8]) -> Self {
        let mut out = [0u8; 32];

        for (chunk, v) in out.chunks_exact_mut(4).zip(value.into_iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        U256(out)
    }
}

impl TryFrom<U256> for u32 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(28);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u32::from_be_bytes(low.try_into().unwrap()))
    }
}

impl From<u32> for U256 {
    fn from(value: u32) -> Self {
        let mut out = [0u8; 32];

        out[28..32].copy_from_slice(&value.to_be_bytes());

        U256(out)
    }
}
