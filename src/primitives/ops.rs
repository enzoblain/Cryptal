//! Bitwise and shift operations for `U256`.
//!
//! Implements XOR/AND plus logical shifts using two code paths: a safe version
//! and a "speed" feature path that relies on unchecked indexing.

use super::U256;
use core::ops::{Add, BitAnd, BitXor, Shl, Shr, Sub};

#[cfg(not(feature = "speed"))]
impl BitXor<U256> for U256 {
    type Output = U256;

    fn bitxor(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];

        for (o, (l, r)) in out.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            *o = l ^ r;
        }

        U256(out)
    }
}

#[cfg(feature = "speed")]
impl BitXor<U256> for U256 {
    type Output = U256;

    fn bitxor(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];

        for (i, o) in out.iter_mut().enumerate() {
            *o = self.0[i] ^ rhs.0[i];
        }

        U256(out)
    }
}

#[cfg(not(feature = "speed"))]
impl BitAnd<U256> for U256 {
    type Output = U256;
    fn bitand(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];

        for (o, (l, r)) in out.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            *o = l & r;
        }

        U256(out)
    }
}

#[cfg(feature = "speed")]
impl BitAnd<U256> for U256 {
    type Output = U256;

    fn bitand(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];

        for (i, o) in out.iter_mut().enumerate() {
            *o = self.0[i] & rhs.0[i];
        }

        U256(out)
    }
}

#[cfg(not(feature = "speed"))]
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

        let byte_shift = shift >> 3;
        let bit_shift = (shift & 7) as u8;

        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            let src = i + byte_shift;
            *o = if src < 32 { self.0[src] } else { 0 };
        }

        if bit_shift != 0 {
            let carry_bits = 8 - bit_shift;

            for i in 0..32 {
                let hi = out[i] << bit_shift;
                let c = if i > 0 { out[i - 1] >> carry_bits } else { 0 };

                out[i] = hi | c;
            }
        }

        U256(out)
    }
}

#[cfg(feature = "speed")]
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

        let byte_shift = shift >> 3;
        let bit_shift = (shift & 7) as u8;

        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            let src = i + byte_shift;

            *o = if src < 32 { self.0[src] } else { 0 };
        }

        if bit_shift != 0 {
            let carry_bits = 8 - bit_shift;

            for i in 0..32 {
                let hi = out[i] << bit_shift;
                let c = if i > 0 { out[i - 1] >> carry_bits } else { 0 };

                out[i] = hi | c;
            }
        }

        U256(out)
    }
}

#[cfg(not(feature = "speed"))]
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

        let byte_shift = shift >> 3;
        let bit_shift = (shift & 7) as u8;

        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = if i >= byte_shift {
                self.0[i - byte_shift]
            } else {
                0
            };
        }

        if bit_shift != 0 {
            let carry_bits = 8 - bit_shift;
            let prev = out;

            for (i, o) in out.iter_mut().enumerate() {
                let lo = prev[i] >> bit_shift;

                let c = if i + 1 < 32 {
                    prev[i + 1] << carry_bits
                } else {
                    0
                };

                *o = lo | c;
            }
        }

        U256(out)
    }
}

#[cfg(feature = "speed")]
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

        let byte_shift = shift >> 3;
        let bit_shift = (shift & 7) as u8;

        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = if i >= byte_shift {
                self.0[i - byte_shift]
            } else {
                0
            };
        }

        if bit_shift != 0 {
            let carry_bits = 8 - bit_shift;
            let prev = out;

            for (i, o) in out.iter_mut().enumerate() {
                let lo = prev[i] >> bit_shift;

                let c = if i + 1 < 32 {
                    prev[i + 1] << carry_bits
                } else {
                    0
                };
                *o = lo | c;
            }
        }

        U256(out)
    }
}

#[cfg(not(feature = "speed"))]
impl Add for U256 {
    type Output = U256;

    fn add(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];
        let mut carry = 0u16;

        for i in (0..32).rev() {
            let s = self.0[i] as u16 + rhs.0[i] as u16 + carry;

            out[i] = (s & 0xFF) as u8;

            carry = s >> 8;
        }

        U256(out)
    }
}

#[cfg(feature = "speed")]
impl Add for U256 {
    type Output = U256;

    fn add(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];
        let mut carry = 0u16;

        for i in (0..32).rev() {
            let s = self.0[i] as u16 + rhs.0[i] as u16 + carry;

            out[i] = (s & 0xFF) as u8;

            carry = s >> 8;
        }

        U256(out)
    }
}

#[cfg(not(feature = "speed"))]
impl Sub for U256 {
    type Output = U256;

    fn sub(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;

        for i in (0..32).rev() {
            let lhs = self.0[i] as i16;
            let s = rhs.0[i] as i16 + borrow;

            if lhs >= s {
                out[i] = (lhs - s) as u8;
                borrow = 0;
            } else {
                out[i] = (lhs + 256 - s) as u8;
                borrow = 1;
            }
        }

        U256(out)
    }
}

#[cfg(feature = "speed")]
impl Sub for U256 {
    type Output = U256;

    fn sub(self, rhs: U256) -> Self::Output {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;

        for i in (0..32).rev() {
            let lhs = self.0[i] as i16;
            let s = rhs.0[i] as i16 + borrow;

            if lhs >= s {
                out[i] = (lhs - s) as u8;
                borrow = 0;
            } else {
                out[i] = (lhs + 256 - s) as u8;
                borrow = 1;
            }
        }

        U256(out)
    }
}
