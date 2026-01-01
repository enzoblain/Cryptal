use crate::primitives::U256;

use std::mem;

const USIZE_BYTES: usize = mem::size_of::<usize>();

impl From<usize> for U256 {
    fn from(value: usize) -> Self {
        let mut out = [0u8; 32];

        let bytes = value.to_be_bytes();
        let offset = 32 - bytes.len();

        out[offset..].copy_from_slice(&bytes);

        U256(out)
    }
}

impl TryFrom<U256> for usize {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        let offset = 32 - USIZE_BYTES;

        if value.0[..offset].iter().any(|&b| b != 0) {
            return Err(());
        }

        let mut buf = [0u8; USIZE_BYTES];
        buf.copy_from_slice(&value.0[offset..]);

        Ok(usize::from_be_bytes(buf))
    }
}
