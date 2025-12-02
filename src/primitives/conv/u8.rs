use super::U256;

/// u256 -> [u8; 32]
impl From<U256> for [u8; 32] {
    fn from(value: U256) -> Self {
        value.0
    }
}

/// [u8; 32] -> u256
impl From<[u8; 32]> for U256 {
    fn from(value: [u8; 32]) -> Self {
        U256(value)
    }
}

/// U256 -> u8
impl TryFrom<U256> for u8 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0[..31].iter().any(|&b| b != 0) {
            return Err(());
        }
        Ok(value.0[31])
    }
}

/// u8 -> u256
impl From<u8> for U256 {
    fn from(value: u8) -> Self {
        let mut out = [0u8; 32];
        out[31] = value;
        U256(out)
    }
}

// u256 -> [u8]
impl AsRef<[u8]> for &U256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// u256 -> &[u8; 32]
impl AsRef<[u8; 32]> for U256 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
