use crate::primitives::U256;

impl From<U256> for [u8; 32] {
    fn from(value: U256) -> Self {
        value.0
    }
}

impl From<[u8; 32]> for U256 {
    fn from(value: [u8; 32]) -> Self {
        U256(value)
    }
}

impl TryFrom<U256> for u8 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let (high, low) = value.0.split_at(31);

        if high.iter().any(|&b| b != 0) {
            return Err(());
        }

        Ok(low[0])
    }
}

impl From<u8> for U256 {
    fn from(value: u8) -> Self {
        let mut out = [0u8; 32];

        out[31] = value;

        U256(out)
    }
}

impl AsRef<[u8]> for &U256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for U256 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
