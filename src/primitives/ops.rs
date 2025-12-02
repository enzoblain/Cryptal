use super::U256;

use core::array;
use core::ops::{Add, BitAnd, BitXor, Shl, Shr, Sub};

impl BitXor<U256> for U256 {
    type Output = U256;

    fn bitxor(self, rhs: U256) -> Self::Output {
        let out = array::from_fn(|i| self.0[i] ^ rhs.0[i]);

        U256::from(out)
    }
}

impl BitAnd<U256> for U256 {
    type Output = U256;

    fn bitand(self, rhs: U256) -> Self::Output {
        let out = array::from_fn(|i| self.0[i] & rhs.0[i]);

        U256::from(out)
    }
}

impl Shl<U256> for U256 {
    type Output = U256;

    fn shl(self, rhs: U256) -> Self::Output {
        let s_low = rhs.0[30] as u32;
        let s_high = rhs.0[31] as u32;

        let shift = (s_low << 8) | s_high;
        if shift == 0 {
            return self;
        }
        if shift >= 256 {
            return U256([0u8; 32]);
        }

        let byte_shift = (shift / 8) as usize;
        let bit_shift = (shift % 8) as u8;

        let mut out = [0u8; 32];

        for (i, out_byte) in out.iter_mut().enumerate() {
            let src = i + byte_shift;
            *out_byte = if src < 32 { self.0[src] } else { 0 };
        }

        if bit_shift != 0 {
            let carry_bits = 8 - bit_shift;

            for i in 0..32 {
                let hi = out[i] << bit_shift;
                let carry = if i > 0 { out[i - 1] >> carry_bits } else { 0 };
                out[i] = hi | carry;
            }
        }

        U256::from(out)
    }
}

impl Shr<U256> for U256 {
    type Output = U256;

    fn shr(self, rhs: U256) -> Self::Output {
        let s_low = rhs.0[30] as u32;
        let s_high = rhs.0[31] as u32;

        let shift = (s_low << 8) | s_high;
        if shift == 0 {
            return self;
        }
        if shift >= 256 {
            return U256([0u8; 32]);
        }

        let byte_shift = (shift / 8) as usize;
        let bit_shift = (shift % 8) as u8;

        let mut out = [0u8; 32];

        for (i, out_byte) in out.iter_mut().enumerate() {
            // La source est i.checked_sub(byte_shift)
            *out_byte = if i >= byte_shift {
                self.0[i - byte_shift]
            } else {
                0
            };
        }

        if bit_shift != 0 {
            let carry_bits = 8 - bit_shift;
            let prev = out; // snapshot pour lire sans écraser

            for (i, out_byte) in out.iter_mut().enumerate() {
                let lo = prev[i] >> bit_shift;
                let carry = if i + 1 < 32 {
                    prev[i + 1] << carry_bits
                } else {
                    0
                };
                *out_byte = lo | carry;
            }
        }

        U256::from(out)
    }
}

impl Add for U256 {
    type Output = U256;

    fn add(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];
        let mut carry = 0;

        for i in (0..32).rev() {
            let sum = self.0[i] as u16 + rhs.0[i] as u16 + carry;
            out[i] = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }

        U256(out)
    }
}

impl Sub for U256 {
    type Output = U256;

    fn sub(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];
        let mut borrow = 0;

        for i in (0..32).rev() {
            let lhs = self.0[i] as i16;
            let sub = rhs.0[i] as i16 + borrow as i16;

            if lhs >= sub {
                out[i] = (lhs - sub) as u8;
                borrow = 0;
            } else {
                out[i] = ((lhs + 256) - sub) as u8;
                borrow = 1;
            }
        }

        U256(out)
    }
}
