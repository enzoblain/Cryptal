use core::fmt;

pub mod conv;
pub mod ops;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(pub [u8; 32]);
impl U256 {
    pub const MAX: Self = Self([255u8; 32]);
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{:02X}", b)?;
        }

        Ok(())
    }
}
