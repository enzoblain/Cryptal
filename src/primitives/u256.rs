use std::fmt::{Display, Formatter, Result};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(pub(crate) [u8; 32]);

impl U256 {
    pub const ZERO: Self = Self([0u8; 32]);
    pub const ONE: Self = Self::one_be();
    pub const MAX: Self = Self([255u8; 32]);

    pub const fn one_be() -> Self {
        let mut out = [0u8; 32];
        out[31] = 1;

        U256(out)
    }

    pub fn leading_zeros(&self) -> u32 {
        let mut count = 0u32;

        for &byte in self.0.iter() {
            if byte == 0 {
                count += 8;
            } else {
                // Leading zeros for the last byte
                count += byte.leading_zeros();

                return count;
            }
        }

        count
    }
}

impl Display for U256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }

            write!(f, "{:02X}", byte)?;
        }

        Ok(())
    }
}
