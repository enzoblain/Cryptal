//! Arithmetic and bitwise operations for `U512`
//!
//! This module implements a minimal set of arithmetic and bitwise operator
//! traits for the `U512` type.
//!
//! The goal is **not** to provide a full big-integer library, but to supply
//! only the operations that are required by the Nebula ecosystem, such as:
//! - distance computations (XOR, AND, shifts)
//! - comparisons and ordering
//! - basic arithmetic for identifiers and protocol logic
//!
//! All operations are implemented explicitly on fixed-size arrays, with:
//! - no heap allocation
//! - predictable behavior
//! - wrapping semantics where appropriate
//!
//! The internal representation is big-endian.

use crate::primitives::u512::U512;
use std::ops::{Add, BitAnd, BitXor, Div, Mul, Shl, Shr, Sub};

/// Bitwise XOR between two 512-bit values.
impl BitXor<U512> for U512 {
    type Output = U512;

    fn bitxor(self, rhs: U512) -> Self::Output {
        let mut out = [0u8; 64];

        out.iter_mut()
            .zip(self.0.iter().zip(rhs.0.iter()))
            .for_each(|(o, (l, r))| *o = l ^ r);

        U512(out)
    }
}

/// Bitwise AND between two 512-bit values.
impl BitAnd<U512> for U512 {
    type Output = U512;

    fn bitand(self, rhs: U512) -> Self::Output {
        let mut out = [0u8; 64];

        out.iter_mut()
            .zip(self.0.iter().zip(rhs.0.iter()))
            .for_each(|(o, (l, r))| *o = l & r);

        U512(out)
    }
}

/// Logical left shift (`<<`) by a 512-bit value.
///
/// Only the lowest 16 bits of the shift value are considered.
/// Shifts greater than or equal to 512 bits yield zero.
impl Shl<U512> for U512 {
    type Output = U512;

    fn shl(self, rhs: U512) -> Self::Output {
        let shift = (((rhs.0[62] as u32) << 8) | rhs.0[63] as u32) as usize;

        if shift == 0 {
            return self;
        }
        if shift >= 512 {
            return U512([0; 64]);
        }

        let byte_shift = shift / 8;
        let bit_shift = (shift % 8) as u8;

        let mut tmp = [0u8; 64];
        tmp[..(64 - byte_shift)].copy_from_slice(&self.0[byte_shift..]);

        if bit_shift == 0 {
            return U512(tmp);
        }

        let mut out = [0u8; 64];
        let mut carry = 0u8;

        for i in 0..64 {
            let val = tmp[i];
            out[i] = (val << bit_shift) | carry;
            carry = val >> (8 - bit_shift);
        }

        U512(out)
    }
}

/// Logical right shift (`>>`) by a 512-bit value.
///
/// Only the lowest 16 bits of the shift value are considered.
/// Shifts greater than or equal to 512 bits yield zero.
impl Shr<U512> for U512 {
    type Output = U512;

    fn shr(self, rhs: U512) -> Self::Output {
        let shift = (((rhs.0[62] as u32) << 8) | rhs.0[63] as u32) as usize;

        if shift == 0 {
            return self;
        }
        if shift >= 512 {
            return U512([0; 64]);
        }

        let byte_shift = shift / 8;
        let bit_shift = (shift % 8) as u8;

        let mut tmp = [0u8; 64];
        tmp[byte_shift..].copy_from_slice(&self.0[..(64 - byte_shift)]);

        if bit_shift == 0 {
            return U512(tmp);
        }

        let mut out = [0u8; 64];
        let mut carry = 0u8;

        for i in (0..64).rev() {
            let val = tmp[i];
            out[i] = (val >> bit_shift) | carry;
            carry = val << (8 - bit_shift);
        }

        U512(out)
    }
}

/// Addition modulo 2²⁵¹².
impl Add for U512 {
    type Output = U512;

    fn add(self, rhs: U512) -> Self::Output {
        let mut out = [0u8; 64];
        let mut carry = 0u16;

        for ((&a, &b), o) in self.0.iter().zip(rhs.0.iter()).zip(out.iter_mut()).rev() {
            let sum = a as u16 + b as u16 + carry;
            *o = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }

        U512(out)
    }
}

/// Subtraction modulo 2²⁵¹².
impl Sub for U512 {
    type Output = U512;

    fn sub(self, rhs: U512) -> Self::Output {
        let mut out = [0u8; 64];
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

        U512(out)
    }
}

/// Multiplication modulo 2²⁵¹².
///
/// The result is truncated to 512 bits.
impl Mul<U512> for U512 {
    type Output = U512;

    fn mul(self, rhs: U512) -> Self::Output {
        let lhs_be: [u64; 8] = self.into();
        let rhs_be: [u64; 8] = rhs.into();

        let mut lhs = lhs_be;
        let mut rhs = rhs_be;
        lhs.reverse();
        rhs.reverse();

        let mut acc = [0u128; 16];

        for (i, &a) in lhs.iter().enumerate() {
            for (j, &b) in rhs.iter().enumerate() {
                acc[i + j] += a as u128 * b as u128;
            }
        }

        for i in 0..15 {
            let carry = acc[i] >> 64;
            acc[i] &= 0xFFFF_FFFF_FFFF_FFFF;
            acc[i + 1] += carry;
        }

        let mut out = [0u64; 8];
        for (o, &a) in out.iter_mut().zip(acc.iter().take(8).rev()) {
            *o = a as u64;
        }

        U512::from(out)
    }
}

/// Integer division (`/`) producing the quotient.
///
/// This implements a classic shift-and-subtract division algorithm.
impl Div<U512> for U512 {
    type Output = U512;

    fn div(self, rhs: U512) -> Self::Output {
        assert!(rhs != U512::ZERO, "division by zero");

        if self < rhs {
            return U512::ZERO;
        }

        let mut quotient = [0u8; 64];
        let mut remainder = U512::ZERO;

        for bit in 0..512 {
            let byte_idx = bit >> 3;
            let bit_in_byte = 7 - (bit & 7);

            let incoming = (self.0[byte_idx] >> bit_in_byte) & 1;

            remainder = remainder << U512::from(1u8);

            let mut rem_bytes: [u8; 64] = remainder.into();
            rem_bytes[63] = (rem_bytes[63] & 0xFE) | incoming;
            remainder = U512(rem_bytes);

            if remainder >= rhs {
                remainder = remainder - rhs;
                quotient[byte_idx] |= 1 << bit_in_byte;
            }
        }

        U512(quotient)
    }
}
