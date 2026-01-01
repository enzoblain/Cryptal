use crate::primitives::U256;

impl From<U256> for [u16; 16] {
    fn from(value: U256) -> Self {
        let mut out = [0u16; 16];

        for (o, chunk) in out.iter_mut().zip(value.0.chunks_exact(2)) {
            *o = u16::from_be_bytes(chunk.try_into().unwrap());
        }

        out
    }
}

impl From<[u16; 16]> for U256 {
    fn from(value: [u16; 16]) -> Self {
        let mut out = [0u8; 32];

        for (chunk, v) in out.chunks_exact_mut(2).zip(value.into_iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        U256(out)
    }
}

impl TryFrom<U256> for u16 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(30);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(u16::from_be_bytes(low.try_into().unwrap()))
    }
}

impl From<u16> for U256 {
    fn from(value: u16) -> Self {
        let mut out = [0u8; 32];

        out[30] = (value >> 8) as u8;
        out[31] = (value & 0xFF) as u8;

        U256(out)
    }
}
