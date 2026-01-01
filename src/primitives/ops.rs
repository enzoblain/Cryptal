use crate::primitives::u256::U256;

use std::ops::{Add, BitAnd, BitXor, Div, Mul, Shl, Shr, Sub};

impl BitXor<U256> for U256 {
    type Output = U256;

    fn bitxor(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];

        out.iter_mut()
            .zip(self.0.iter().zip(rhs.0.iter()))
            .for_each(|(o, (l, r))| *o = l ^ r);

        U256(out)
    }
}

impl BitAnd<U256> for U256 {
    type Output = U256;

    fn bitand(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];

        out.iter_mut()
            .zip(self.0.iter().zip(rhs.0.iter()))
            .for_each(|(o, (l, r))| *o = l & r);

        U256(out)
    }
}
impl Shl<U256> for U256 {
    type Output = U256;

    fn shl(self, rhs: U256) -> Self::Output {
        let shift = (((rhs.0[30] as u32) << 8) | rhs.0[31] as u32) as usize;

        if shift == 0 {
            return self;
        }
        if shift >= 256 {
            return U256([0; 32]);
        }

        let byte_shift = shift / 8;
        let bit_shift = (shift % 8) as u8;

        let mut tmp = [0u8; 32];
        tmp[..(32 - byte_shift)].copy_from_slice(&self.0[byte_shift..]);

        if bit_shift == 0 {
            return U256(tmp);
        }

        let mut out = [0u8; 32];
        let mut carry = 0u8;

        for i in 0..32 {
            let val = tmp[i];

            out[i] = (val << bit_shift) | carry;
            carry = val >> (8 - bit_shift);
        }

        U256(out)
    }
}

impl Shr<U256> for U256 {
    type Output = U256;

    fn shr(self, rhs: U256) -> Self::Output {
        let shift = (((rhs.0[30] as u32) << 8) | rhs.0[31] as u32) as usize;

        if shift == 0 {
            return self;
        }
        if shift >= 256 {
            return U256([0; 32]);
        }

        let byte_shift = shift / 8;
        let bit_shift = (shift % 8) as u8;

        let mut tmp = [0u8; 32];
        tmp[byte_shift..].copy_from_slice(&self.0[..(32 - byte_shift)]);

        if bit_shift == 0 {
            return U256(tmp);
        }

        let mut out = [0u8; 32];
        let mut carry = 0u8;

        for i in (0..32).rev() {
            let val = tmp[i];

            out[i] = (val >> bit_shift) | carry;
            carry = val << (8 - bit_shift);
        }

        U256(out)
    }
}

impl Add for U256 {
    type Output = U256;

    fn add(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];
        let mut carry = 0u16;

        for ((&a, &b), o) in self.0.iter().zip(rhs.0.iter()).zip(out.iter_mut()).rev() {
            let sum = a as u16 + b as u16 + carry;
            *o = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }

        U256(out)
    }
}

impl Sub for U256 {
    type Output = U256;

    fn sub(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;

        for ((&a, &b), o) in self.0.iter().zip(rhs.0.iter()).zip(out.iter_mut()).rev() {
            let lhs = a as i16;
            let sub = b as i16 + borrow;

            if lhs >= sub {
                *o = (lhs - sub) as u8;
                borrow = 0;
            } else {
                *o = (lhs + 256 - sub) as u8;
                borrow = 1;
            }
        }

        U256(out)
    }
}

impl Mul<U256> for U256 {
    type Output = U256;

    fn mul(self, rhs: U256) -> Self::Output {
        let lhs_be: [u64; 4] = self.into();
        let rhs_be: [u64; 4] = rhs.into();

        let mut lhs = lhs_be;
        let mut rhs = rhs_be;
        lhs.reverse();
        rhs.reverse();

        let mut acc = [0u128; 8];

        for (i, &a) in lhs.iter().enumerate() {
            for (j, &b) in rhs.iter().enumerate() {
                acc[i + j] += a as u128 * b as u128;
            }
        }

        for i in 0..7 {
            let carry = acc[i] >> 64;
            acc[i] &= 0xFFFF_FFFF_FFFF_FFFF;
            acc[i + 1] += carry;
        }

        let mut out = [0u64; 4];
        for (o, &a) in out.iter_mut().zip(acc.iter().take(4).rev()) {
            *o = a as u64;
        }

        U256::from(out)
    }
}

impl Div<U256> for U256 {
    type Output = U256;

    fn div(self, rhs: U256) -> Self::Output {
        assert!(rhs != U256::ZERO, "division by zero");
        if self < rhs {
            return U256::ZERO;
        }

        let mut quotient = [0u8; 32];
        let mut remainder = U256::ZERO;

        for bit in 0..256 {
            let byte_idx = bit >> 3;
            let bit_in_byte = 7 - (bit & 7);

            let incoming = (self.0[byte_idx] >> bit_in_byte) & 1;

            remainder = remainder << U256::from(1u8);

            let mut rem_bytes: [u8; 32] = remainder.into();
            rem_bytes[31] = (rem_bytes[31] & 0xFE) | incoming;
            remainder = U256(rem_bytes);

            if remainder >= rhs {
                remainder = remainder - rhs;
                quotient[byte_idx] |= 1 << bit_in_byte;
            }
        }

        U256(quotient)
    }
}
