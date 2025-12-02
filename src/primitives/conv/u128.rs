use super::U256;

/// u256 -> [u128; 2]
impl From<U256> for [u128; 2] {
    fn from(value: U256) -> Self {
        let mut high_bytes = [0u8; 16];
        let mut low_bytes = [0u8; 16];

        high_bytes.copy_from_slice(&value.0[..16]);
        low_bytes.copy_from_slice(&value.0[16..32]);

        let high = u128::from_be_bytes(high_bytes);
        let low = u128::from_be_bytes(low_bytes);

        [high, low]
    }
}

/// [u128; 2] -> u256
impl From<[u128; 2]> for U256 {
    fn from(value: [u128; 2]) -> Self {
        let mut out = [0u8; 32];

        out[..16].copy_from_slice(&value[0].to_be_bytes());
        out[16..32].copy_from_slice(&value[1].to_be_bytes());

        Self(out)
    }
}

/// U256 -> u128
impl TryFrom<U256> for u128 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..16].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut low = [0u8; 16];
        low.copy_from_slice(&value.0[16..32]);

        Ok(u128::from_be_bytes(low))
    }
}

/// u128 -> u256
impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        let mut out = [0u8; 32];

        out[16..32].copy_from_slice(&value.to_be_bytes());

        U256(out)
    }
}
