use crate::primitives::U256;

impl From<U256> for [u64; 4] {
    fn from(value: U256) -> Self {
        let mut out = [0u64; 4];

        for (o, chunk) in out.iter_mut().zip(value.0.chunks_exact(8)) {
            *o = u64::from_be_bytes(chunk.try_into().unwrap());
        }

        out
    }
}

impl From<[u64; 4]> for U256 {
    fn from(value: [u64; 4]) -> Self {
        let mut out = [0u8; 32];

        for (chunk, v) in out.chunks_exact_mut(8).zip(value.into_iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        U256(out)
    }
}

impl TryFrom<U256> for u64 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(24);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u64::from_be_bytes(low.try_into().unwrap()))
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        let mut out = [0u8; 32];

        out[24..32].copy_from_slice(&value.to_be_bytes());

        U256(out)
    }
}
