//! Fixed-size integer primitives used across the hashing modules.
//!
//! Currently exposes a `U256` type (32-byte big-endian) with basic bitwise and
//! shift operations plus formatting utilities. Conversion helpers live under
//! [`conv`], and operator implementations under [`ops`].

use core::fmt::{Display, Formatter, Result};

pub mod conv;
pub mod ops;

/// 256-bit unsigned integer stored as 32-byte big-endian.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(pub [u8; 32]);
impl U256 {
    pub const ZERO: Self = Self([0u8; 32]);
    pub const ONE: Self = Self::one_be();
    pub const MAX: Self = Self([255u8; 32]);

    pub const fn one_be() -> Self {
        let mut out = [0u8; 32];
        out[31] = 1;
        U256(out)
    }
}

impl Display for U256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }

            write!(f, "{:02X}", b)?;
        }

        Ok(())
    }
}
