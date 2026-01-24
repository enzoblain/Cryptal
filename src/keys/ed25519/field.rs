//! Finite field arithmetic for Ed25519 / Curve25519.
//!
//! This module implements arithmetic in the prime field
//!
//! ```text
//! 𝔽ₚ where p = 2²⁵⁵ − 19
//! ```
//!
//! used by the Ed25519 and Curve25519 elliptic curves.
//!
//! ## Representation
//!
//! Field elements are represented using a 10-limb signed integer format,
//! with alternating limb sizes:
//!
//! ```text
//! [26, 25, 26, 25, 26, 25, 26, 25, 26, 25] bits
//! ```
//!
//! This radix-(2²⁵·⁵) representation matches the original Ed25519 reference
//! implementation and allows efficient carry propagation and reduction.
//!
//! ## Design goals
//!
//! - **Constant-time execution**: no secret-dependent branches or memory access.
//! - **Overflow safety**: all intermediate arithmetic is promoted to `i64`.
//! - **Auditability**: code structure closely follows the Ed25519 reference.
//! - **Deferred reduction**: additions and subtractions may return partially
//!   reduced values, normalized later when required.
//!
//! ## Implemented operations
//!
//! - Field addition, subtraction, negation
//! - Field multiplication and squaring
//! - Repeated squaring
//! - Modular inversion
//! - Exponentiation chains used by Ed25519
//! - Canonical encoding and decoding
//!
//! ## Notes
//!
//! This module is intentionally low-level and explicit.
//! It does not attempt to hide arithmetic details behind abstractions,
//! prioritizing correctness, predictability, and side-channel resistance.
//!
//! The implementation is compatible with the Ed25519 reference behavior
//! and suitable for cryptographic use.

use std::array;
use std::ops::{Add, Mul, Neg, Sub};

/// Multiplies two field limbs with explicit promotion to `i64`.
///
/// This macro is used in `FieldElement` arithmetic (notably `square` and `mul`)
/// to prevent intermediate overflows during limb multiplication.
///
/// Although field limbs are stored as `i32`, intermediate products can exceed
/// 32 bits, especially when involving:
/// - doubled limbs (`2 * f[index]`)
/// - curve-specific constants (`19`, `38`)
/// - accumulated cross products
///
/// Promoting operands to `i64` ensures arithmetic safety while preserving
/// behavior identical to the reference Ed25519 C implementations.
macro_rules! mul {
    ($a:expr, $b:expr) => {
        ($a as i64) * ($b as i64)
    };
}

/// Adds two field limbs with explicit promotion to `i64`.
///
/// This macro is used in `FieldElement` arithmetic (e.g. `add`, `sub`)
/// to ensure intermediate additions do not overflow `i32`.
///
/// Although field limbs are stored as `i32`, intermediate sums may exceed
/// 32-bit limits when:
/// - accumulating multiple partial results
/// - combining carry-adjusted limbs
/// - chaining additions in reduction steps
///
/// Promoting operands to `i64` guarantees correctness and mirrors the
/// behavior of the Ed25519 reference C implementations.
macro_rules! add {
    ($a:expr, $b:expr) => {
        ($a as i64) + ($b as i64)
    };
}

/// Subtracts two field limbs with explicit promotion to `i64`.
///
/// This macro is used in `FieldElement` arithmetic (e.g. `sub`, intermediate
/// reduction steps) to ensure limb subtractions do not overflow `i32`.
///
/// Although field limbs are stored as `i32`, intermediate differences may
/// temporarily exceed the 32-bit range when:
/// - propagating carries or borrows
/// - subtracting unreduced or partially reduced values
/// - chaining arithmetic operations during field reduction
///
/// Promoting operands to `i64` guarantees correctness and matches the behavior
/// of the Ed25519 reference C implementations.
macro_rules! sub {
    ($a:expr, $b:expr) => {
        ($a as i64) - ($b as i64)
    };
}

/// Load 3 bytes from a little-endian byte slice into a `u64`.
///
/// Interprets `input[0..3]` as a 24-bit unsigned integer:
///
/// ```text
/// input[0] + input[1]<<8 + input[2]<<16
/// ```
///
/// Used by Ed25519 field decoding to assemble limbs efficiently.
#[inline(always)]
pub fn load_3(input: &[u8]) -> u64 {
    (input[0] as u64) | ((input[1] as u64) << 8) | ((input[2] as u64) << 16)
}

/// Load 4 bytes from a little-endian byte slice into a `u64`.
///
/// Interprets `input[0..4]` as a 32-bit unsigned integer:
///
/// ```text
/// input[0] + input[1]<<8 + input[2]<<16 + input[3]<<24
/// ```
///
/// This function is used for decoding field elements and scalars
/// following the Ed25519 reference layout.
#[inline(always)]
pub fn load_4(input: &[u8]) -> u64 {
    (input[0] as u64)
        | ((input[1] as u64) << 8)
        | ((input[2] as u64) << 16)
        | ((input[3] as u64) << 24)
}

/// Field element modulo `2^255 - 19`, represented in radix `(2^25.5)`.
///
/// Internally stored as 10 signed 32-bit limbs:
///
/// ```text
/// [26, 25, 26, 25, 26, 25, 26, 25, 26, 25] bits
/// ```
///
/// This layout matches the Ed25519 reference implementation
/// and allows efficient carry propagation.
#[derive(Clone, Copy)]
pub(crate) struct FieldElement(pub(crate) [i32; 10]);

impl FieldElement {
    /// The additive identity (0).
    pub(crate) const ZERO: Self = FieldElement([0i32; 10]);

    /// The multiplicative identity (1).
    pub(crate) const ONE: Self = FieldElement([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Constant-time conditional swap of two field elements.
    ///
    /// If `condition == 1`, swaps `self` and `rhs`.
    /// If `condition == 0`, does nothing.
    ///
    /// This function is **branch-free** and safe for cryptographic use.
    pub(crate) fn swap(&mut self, rhs: &mut Self, condition: u32) {
        let mask = -(condition as i32);

        for (s, r) in self.0.iter_mut().zip(rhs.0.iter_mut()) {
            let tmp = (*s ^ *r) & mask;
            *s ^= tmp;
            *r ^= tmp;
        }
    }

    /// Constant-time conditional move.
    ///
    /// If `condition == 1`, replaces `self` with `rhs`.
    /// If `condition == 0`, leaves `self` unchanged.
    ///
    /// This operation is used in precomputed table selection
    /// and avoids secret-dependent branches.
    pub(crate) fn conditional_move(&mut self, rhs: &Self, condition: u32) {
        let mask = -(condition as i32);

        for (s, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            let tmp = (*s ^ r) & mask;
            *s ^= tmp;
        }
    }

    /// Decode a field element from a 32-byte little-endian encoding.
    ///
    /// The input is interpreted as an integer modulo `2^255 - 19`
    /// and converted into the internal 10-limb representation.
    ///
    /// This function:
    /// - loads overlapping byte windows
    /// - aligns them to limb boundaries
    /// - performs carry propagation
    ///
    /// This matches the Ed25519 reference decoding exactly.
    pub(crate) fn from_bytes(input: &[u8; 32]) -> FieldElement {
        // Configuration describing how each limb is loaded:
        //
        // (byte_offset, load_size, left_shift, apply_mask)
        let load_configs = [
            (0, 4, 0, false),
            (4, 3, 6, false),
            (7, 3, 5, false),
            (10, 3, 3, false),
            (13, 3, 2, false),
            (16, 4, 0, false),
            (20, 3, 7, false),
            (23, 3, 5, false),
            (26, 3, 4, false),
            (29, 3, 2, true), // top limb masked to 23 bits
        ];

        // Use i64 for intermediate values to safely handle carries
        let mut output = [0i64; 10];

        // Load and align each limb from the input bytes
        for (index, &(offset, size, shift, mask)) in load_configs.iter().enumerate() {
            let value = if size == 4 {
                load_4(&input[offset..])
            } else {
                load_3(&input[offset..])
            };

            let value = if mask {
                (value & 8_388_607) << shift // mask to 23 bits
            } else {
                value << shift
            };

            output[index] = value as i64;
        }

        // Carry propagation for odd limbs (25-bit limbs)
        for index in (1..10).step_by(2) {
            let carry = (output[index] + (1i64 << 24)) >> 25;
            output[index] -= carry << 25;

            if index == 9 {
                // Reduction modulo 2^255 - 19
                output[0] += carry * 19;
            } else {
                output[index + 1] += carry;
            }
        }

        // Carry propagation for even limbs (26-bit limbs)
        for index in (0..9).step_by(2) {
            let carry = (output[index] + (1i64 << 25)) >> 26;
            output[index] -= carry << 26;
            output[index + 1] += carry;
        }

        FieldElement(output.map(|x| x as i32))
    }

    /// Encode this field element into its canonical 32-byte little-endian form.
    ///
    /// This function performs:
    /// - final carry propagation
    /// - reduction modulo `2^255 - 19`
    /// - serialization into 32 bytes
    ///
    /// The output is guaranteed to be a canonical encoding suitable for:
    /// - public keys
    /// - signatures
    /// - hashing
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        // Promote limbs to i64 for safe carry handling
        let mut input = self.0.map(|x| x as i64);

        // Initial reduction: fold high limb into limb 0 using 19
        let mut carry = (19 * input[9] + (1i64 << 24)) >> 25;

        // Propagate carry through all limbs to compute final overflow
        for (index, ip) in input.iter().take(10).enumerate() {
            let shift = if index % 2 == 0 { 26 } else { 25 };
            carry = (ip + carry) >> shift;
        }

        // Final modular reduction
        input[0] += 19 * carry;

        // Carry propagation for even limbs (26-bit)
        for index in (0..9).step_by(2) {
            carry = input[index] >> 26;
            input[index] -= carry << 26;
            input[index + 1] += carry;
        }

        // Carry propagation for odd limbs (25-bit)
        for index in (1..10).step_by(2) {
            carry = input[index] >> 25;
            input[index] -= carry << 25;

            if index < 9 {
                input[index + 1] += carry;
            }
        }

        // Configuration describing how limbs are packed into bytes.
        //
        // Each entry is:
        // (output_byte_index, limb_index, right_shift, optional_cross_limb)
        //
        // The optional value specifies:
        // - which next limb contributes bits
        // - how much it must be left-shifted
        let encode_configs = [
            (0, 0, 0, None),
            (1, 0, 8, None),
            (2, 0, 16, None),
            (3, 0, 24, Some((1, 2))),
            (4, 1, 6, None),
            (5, 1, 14, None),
            (6, 1, 22, Some((2, 3))),
            (7, 2, 5, None),
            (8, 2, 13, None),
            (9, 2, 21, Some((3, 5))),
            (10, 3, 3, None),
            (11, 3, 11, None),
            (12, 3, 19, Some((4, 6))),
            (13, 4, 2, None),
            (14, 4, 10, None),
            (15, 4, 18, None),
            (16, 5, 0, None),
            (17, 5, 8, None),
            (18, 5, 16, None),
            (19, 5, 24, Some((6, 1))),
            (20, 6, 7, None),
            (21, 6, 15, None),
            (22, 6, 23, Some((7, 3))),
            (23, 7, 5, None),
            (24, 7, 13, None),
            (25, 7, 21, Some((8, 4))),
            (26, 8, 4, None),
            (27, 8, 12, None),
            (28, 8, 20, Some((9, 6))),
            (29, 9, 2, None),
            (30, 9, 10, None),
            (31, 9, 18, None),
        ];

        // Serialize limbs into 32 bytes
        let mut output = [0u8; 32];
        for &(index, limb, shift, next) in &encode_configs {
            let value = if let Some((next_limb, next_shift)) = next {
                ((input[limb] >> shift) | (input[next_limb] << next_shift)) as u8
            } else {
                (input[limb] >> shift) as u8
            };

            output[index] = value;
        }

        output
    }

    /// Returns `1` if this field element is non-zero, `0` otherwise.
    ///
    /// This function performs a **constant-time** check by OR-ing all bytes of
    /// the canonical byte representation and testing the result.
    ///
    /// # Returns
    /// - `1` if the element is non-zero
    /// - `0` if the element is exactly zero
    ///
    /// # Constant-time
    /// This method does **not** early-exit and does not branch on secret data,
    /// making it safe for cryptographic use.
    #[inline(always)]
    pub(crate) fn is_non_zero(&self) -> i32 {
        (self.to_bytes().iter().fold(0u8, |acc, &b| acc | b) != 0) as i32
    }

    /// Returns `1` if this field element is negative, `0` otherwise.
    ///
    /// In Ed25519, the sign of a field element is defined as the least
    /// significant bit of its canonical byte encoding.
    ///
    /// This function extracts that bit in constant time.
    ///
    /// # Returns
    /// - `1` if the element is negative
    /// - `0` if the element is non-negative
    ///
    /// # Constant-time
    /// This method does not branch on secret data and is safe for
    /// cryptographic use.
    #[inline(always)]
    pub(crate) fn is_negative(&self) -> i32 {
        (self.to_bytes()[0] & 1) as i32
    }

    /// Multiplies this field element by the constant `121666`.
    ///
    /// This operation is specific to Curve25519 / Ed25519 arithmetic and
    /// appears in the Montgomery ladder during scalar multiplication.
    ///
    /// The constant `121666` comes from the curve equation:
    /// `y² = x³ + 486662·x² + x`, where `(486662 − 2) / 4 = 121666`.
    ///
    /// Internally, the multiplication is performed in 64-bit limbs,
    /// followed by carry propagation and modular reduction modulo `2²⁵⁵ − 19`.
    ///
    /// # Returns
    /// A new `FieldElement` equal to `self * 121666 (mod p)`.
    ///
    /// # Constant-time
    /// This function runs in constant time with respect to secret data
    /// and is safe for cryptographic use.
    #[inline(always)]
    pub(crate) fn mul121666(&self) -> Self {
        let input = self.0.map(|x| x as i64);
        let mut output = input.map(|x| x * 121_666i64);

        // Reduce odd limbs (25-bit)
        for index in (1..10).step_by(2) {
            let carry = (output[index] + (1i64 << 24)) >> 25;
            output[index] -= carry << 25;

            if index == 9 {
                output[0] += carry * 19;
            } else {
                output[index + 1] += carry;
            }
        }

        // Reduce even limbs (26-bit)
        for index in (0..9).step_by(2) {
            let carry = (output[index] + (1i64 << 25)) >> 26;
            output[index] -= carry << 26;
            output[index + 1] += carry;
        }

        FieldElement(output.map(|x| x as i32))
    }

    /// Computes the square of this field element.
    ///
    /// This function returns `self²` in the finite field
    /// 𝔽ₚ where p = 2²⁵⁵ − 19, the prime field used by Ed25519.
    ///
    /// ## Field representation
    ///
    /// Field elements are represented using 10 signed 32-bit limbs in a
    /// mixed radix representation (alternating 26-bit and 25-bit limbs).
    /// Intermediate values are computed using 64-bit integers to safely
    /// handle multiplication and carry propagation.
    ///
    /// ## Algorithm
    ///
    /// - Exploits symmetry specific to squaring to reduce the total number
    ///   of multiplications compared to a generic field multiplication.
    /// - Precomputes:
    ///   - doubled limbs (`2·f[index]`) to avoid repeated additions,
    ///   - scaled limbs (`19·f[index]`, `38·f[index]`) to efficiently apply the
    ///     reduction modulo 2²⁵⁵ − 19.
    /// - Accumulates partial products into 64-bit temporaries.
    /// - Performs staged carry propagation to normalize all limbs.
    /// - Applies the modulus reduction rule `2²⁵⁵ ≡ 19 (mod p)`.
    ///
    /// ## Constant-time behavior
    ///
    /// This operation is constant-time with respect to the input value.
    /// It contains no data-dependent branches or memory accesses.
    ///
    /// ## Returns
    ///
    /// A new `FieldElement` equal to `self · self (mod 2²⁵⁵ − 19)`.
    pub(crate) fn square(self) -> FieldElement {
        let f = self.0;

        let (f_2, f_mult): ([i32; 10], [i32; 10]) = {
            let mut doubles = [0i32; 10];
            let mut mults = [0i32; 10];

            for index in 0..10 {
                doubles[index] = 2 * f[index];
            }

            mults[5] = 38 * f[5];
            mults[6] = 19 * f[6];
            mults[7] = 38 * f[7];
            mults[8] = 19 * f[8];
            mults[9] = 38 * f[9];

            (doubles, mults)
        };

        let (f0f0, f0f1_2, f0f2_2, f0f3_2, f0f4_2, f0f5_2, f0f6_2, f0f7_2, f0f8_2, f0f9_2) = (
            mul!(f[0], f[0]),
            mul!(f_2[0], f[1]),
            mul!(f_2[0], f[2]),
            mul!(f_2[0], f[3]),
            mul!(f_2[0], f[4]),
            mul!(f_2[0], f[5]),
            mul!(f_2[0], f[6]),
            mul!(f_2[0], f[7]),
            mul!(f_2[0], f[8]),
            mul!(f_2[0], f[9]),
        );

        let (f1f1_2, f1f2_2, f1f3_4, f1f4_2, f1f5_4, f1f6_2, f1f7_4, f1f8_2, f1f9_76) = (
            mul!(f_2[1], f[1]),
            mul!(f_2[1], f[2]),
            mul!(f_2[1], f_2[3]),
            mul!(f_2[1], f[4]),
            mul!(f_2[1], f_2[5]),
            mul!(f_2[1], f[6]),
            mul!(f_2[1], f_2[7]),
            mul!(f_2[1], f[8]),
            mul!(f_2[1], f_mult[9]),
        );

        let (f2f2, f2f3_2, f2f4_2, f2f5_2, f2f6_2, f2f7_2, f2f8_38, f2f9_38) = (
            mul!(f[2], f[2]),
            mul!(f_2[2], f[3]),
            mul!(f_2[2], f[4]),
            mul!(f_2[2], f[5]),
            mul!(f_2[2], f[6]),
            mul!(f_2[2], f[7]),
            mul!(f_2[2], f_mult[8]),
            mul!(f[2], f_mult[9]),
        );

        let (f3f3_2, f3f4_2, f3f5_4, f3f6_2, f3f7_76, f3f8_38, f3f9_76) = (
            mul!(f_2[3], f[3]),
            mul!(f_2[3], f[4]),
            mul!(f_2[3], f_2[5]),
            mul!(f_2[3], f[6]),
            mul!(f_2[3], f_mult[7]),
            mul!(f_2[3], f_mult[8]),
            mul!(f_2[3], f_mult[9]),
        );

        let (f4f4, f4f5_2, f4f6_38, f4f7_38, f4f8_38, f4f9_38) = (
            mul!(f[4], f[4]),
            mul!(f_2[4], f[5]),
            mul!(f_2[4], f_mult[6]),
            mul!(f[4], f_mult[7]),
            mul!(f_2[4], f_mult[8]),
            mul!(f[4], f_mult[9]),
        );

        let (f5f5_38, f5f6_38, f5f7_76, f5f8_38, f5f9_76) = (
            mul!(f[5], f_mult[5]),
            mul!(f_2[5], f_mult[6]),
            mul!(f_2[5], f_mult[7]),
            mul!(f_2[5], f_mult[8]),
            mul!(f_2[5], f_mult[9]),
        );

        let (f6f6_19, f6f7_38, f6f8_38, f6f9_38) = (
            mul!(f[6], f_mult[6]),
            mul!(f[6], f_mult[7]),
            mul!(f_2[6], f_mult[8]),
            mul!(f[6], f_mult[9]),
        );

        let (f7f7_38, f7f8_38, f7f9_76) = (
            mul!(f[7], f_mult[7]),
            mul!(f_2[7], f_mult[8]),
            mul!(f_2[7], f_mult[9]),
        );

        let (f8f8_19, f8f9_38, f9f9_38) = (
            mul!(f[8], f_mult[8]),
            mul!(f[8], f_mult[9]),
            mul!(f[9], f_mult[9]),
        );

        let mut h = [
            f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38,
            f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38,
            f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19,
            f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38,
            f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38,
            f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38,
            f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19,
            f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38,
            f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38,
            f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2,
        ];

        for index in [0, 4] {
            let carry = (h[index] + (1i64 << 25)) >> 26;
            h[index + 1] += carry;
            h[index] -= carry << 26;
        }

        for index in [1, 5] {
            let carry = (h[index] + (1i64 << 24)) >> 25;
            h[index + 1] += carry;
            h[index] -= carry << 25;
        }

        for index in [2, 6] {
            let carry = (h[index] + (1i64 << 25)) >> 26;
            h[index + 1] += carry;
            h[index] -= carry << 26;
        }

        for index in [3, 7] {
            let carry = (h[index] + (1i64 << 24)) >> 25;
            h[index + 1] += carry;
            h[index] -= carry << 25;
        }

        let carry4 = (h[4] + (1i64 << 25)) >> 26;
        h[5] += carry4;
        h[4] -= carry4 << 26;

        let carry8 = (h[8] + (1i64 << 25)) >> 26;
        h[9] += carry8;
        h[8] -= carry8 << 26;

        let carry9 = (h[9] + (1i64 << 24)) >> 25;
        h[0] += carry9 * 19;
        h[9] -= carry9 << 25;

        let carry0 = (h[0] + (1i64 << 25)) >> 26;
        h[1] += carry0;
        h[0] -= carry0 << 26;

        FieldElement(h.map(|x| x as i32))
    }

    /// Repeatedly squares this field element `n` times.
    ///
    /// This function computes:
    ///
    /// ```text
    /// self^(2ⁿ)
    /// ```
    ///
    /// by applying the field squaring operation `n` consecutive times.
    ///
    /// ## Use cases
    ///
    /// This operation is commonly used in exponentiation chains,
    /// particularly for computing inverses via fixed addition chains
    /// (e.g. in field inversion or square-root computations).
    ///
    /// ## Constant-time
    ///
    /// The number of iterations depends only on `n` and not on the value
    /// of the field element.
    ///
    /// ## Parameters
    ///
    /// - `n`: Number of successive squaring operations to apply.
    ///
    /// ## Returns
    ///
    /// A new `FieldElement` equal to `self` squared `n` times.
    pub(crate) fn n_square(self, n: usize) -> FieldElement {
        (0..n).fold(self, |acc, _| acc.square())
    }

    /// Computes twice the square of this field element.
    ///
    /// This function returns `2 · self²` in the finite field
    /// 𝔽ₚ where p = 2²⁵⁵ − 19, the prime field used by Ed25519.
    ///
    /// ## Purpose
    ///
    /// This operation is a specialized and optimized variant of squaring,
    /// used in contexts where `2·x²` is required directly (for example in
    /// point doubling formulas on Edwards or Montgomery curves).
    ///
    /// Compared to calling `square()` followed by a doubling, this function:
    /// - avoids redundant work,
    /// - reuses intermediate products,
    /// - performs a single reduction pass.
    ///
    /// ## Field representation
    ///
    /// Field elements are stored as 10 signed 32-bit limbs in a mixed radix
    /// representation (alternating 26-bit and 25-bit limbs).
    /// All intermediate computations use 64-bit integers to safely handle
    /// multiplication and carry propagation.
    ///
    /// ## Algorithm
    ///
    /// - Computes the same partial products as `square()`.
    /// - Doubles the final accumulated result in-place (`h[index] <<= 1`).
    /// - Applies carry propagation and modular reduction using the identity
    ///   `2²⁵⁵ ≡ 19 (mod p)`.
    ///
    /// ## Constant-time behavior
    ///
    /// This function is constant-time with respect to the input value.
    /// It contains no data-dependent branches or memory accesses.
    ///
    /// ## Returns
    ///
    /// A new `FieldElement` equal to `2 · self · self (mod 2²⁵⁵ − 19)`.
    pub(crate) fn double_square(self) -> FieldElement {
        let f = self.0;

        let (f_2, f_mult) = {
            let mut doubles = [0i32; 10];
            let mut mults = [0i32; 10];

            for index in 0..10 {
                doubles[index] = 2 * f[index];
            }

            mults[5] = 38 * f[5];
            mults[6] = 19 * f[6];
            mults[7] = 38 * f[7];
            mults[8] = 19 * f[8];
            mults[9] = 38 * f[9];

            (doubles, mults)
        };

        let (f0f0, f0f1_2, f0f2_2, f0f3_2, f0f4_2, f0f5_2, f0f6_2, f0f7_2, f0f8_2, f0f9_2) = (
            mul!(f[0], f[0]),
            mul!(f_2[0], f[1]),
            mul!(f_2[0], f[2]),
            mul!(f_2[0], f[3]),
            mul!(f_2[0], f[4]),
            mul!(f_2[0], f[5]),
            mul!(f_2[0], f[6]),
            mul!(f_2[0], f[7]),
            mul!(f_2[0], f[8]),
            mul!(f_2[0], f[9]),
        );

        let (f1f1_2, f1f2_2, f1f3_4, f1f4_2, f1f5_4, f1f6_2, f1f7_4, f1f8_2, f1f9_76) = (
            mul!(f_2[1], f[1]),
            mul!(f_2[1], f[2]),
            mul!(f_2[1], f_2[3]),
            mul!(f_2[1], f[4]),
            mul!(f_2[1], f_2[5]),
            mul!(f_2[1], f[6]),
            mul!(f_2[1], f_2[7]),
            mul!(f_2[1], f[8]),
            mul!(f_2[1], f_mult[9]),
        );

        let (f2f2, f2f3_2, f2f4_2, f2f5_2, f2f6_2, f2f7_2, f2f8_38, f2f9_38) = (
            mul!(f[2], f[2]),
            mul!(f_2[2], f[3]),
            mul!(f_2[2], f[4]),
            mul!(f_2[2], f[5]),
            mul!(f_2[2], f[6]),
            mul!(f_2[2], f[7]),
            mul!(f_2[2], f_mult[8]),
            mul!(f[2], f_mult[9]),
        );

        let (f3f3_2, f3f4_2, f3f5_4, f3f6_2, f3f7_76, f3f8_38, f3f9_76) = (
            mul!(f_2[3], f[3]),
            mul!(f_2[3], f[4]),
            mul!(f_2[3], f_2[5]),
            mul!(f_2[3], f[6]),
            mul!(f_2[3], f_mult[7]),
            mul!(f_2[3], f_mult[8]),
            mul!(f_2[3], f_mult[9]),
        );

        let (f4f4, f4f5_2, f4f6_38, f4f7_38, f4f8_38, f4f9_38) = (
            mul!(f[4], f[4]),
            mul!(f_2[4], f[5]),
            mul!(f_2[4], f_mult[6]),
            mul!(f[4], f_mult[7]),
            mul!(f_2[4], f_mult[8]),
            mul!(f[4], f_mult[9]),
        );

        let (f5f5_38, f5f6_38, f5f7_76, f5f8_38, f5f9_76) = (
            mul!(f[5], f_mult[5]),
            mul!(f_2[5], f_mult[6]),
            mul!(f_2[5], f_mult[7]),
            mul!(f_2[5], f_mult[8]),
            mul!(f_2[5], f_mult[9]),
        );

        let (f6f6_19, f6f7_38, f6f8_38, f6f9_38) = (
            mul!(f[6], f_mult[6]),
            mul!(f[6], f_mult[7]),
            mul!(f_2[6], f_mult[8]),
            mul!(f[6], f_mult[9]),
        );

        let (f7f7_38, f7f8_38, f7f9_76) = (
            mul!(f[7], f_mult[7]),
            mul!(f_2[7], f_mult[8]),
            mul!(f_2[7], f_mult[9]),
        );

        let (f8f8_19, f8f9_38, f9f9_38) = (
            mul!(f[8], f_mult[8]),
            mul!(f[8], f_mult[9]),
            mul!(f[9], f_mult[9]),
        );

        let mut h = [
            f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38,
            f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38,
            f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19,
            f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38,
            f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38,
            f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38,
            f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19,
            f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38,
            f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38,
            f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2,
        ];

        h.iter_mut().for_each(|v| *v <<= 1);

        for index in [0, 4] {
            let carry = (h[index] + (1i64 << 25)) >> 26;
            h[index + 1] += carry;
            h[index] -= carry << 26;
        }

        for index in [1, 5] {
            let carry = (h[index] + (1i64 << 24)) >> 25;
            h[index + 1] += carry;
            h[index] -= carry << 25;
        }

        for index in [2, 6] {
            let carry = (h[index] + (1i64 << 25)) >> 26;
            h[index + 1] += carry;
            h[index] -= carry << 26;
        }

        for index in [3, 7] {
            let carry = (h[index] + (1i64 << 24)) >> 25;
            h[index + 1] += carry;
            h[index] -= carry << 25;
        }

        let carry4 = (h[4] + (1i64 << 25)) >> 26;
        h[5] += carry4;
        h[4] -= carry4 << 26;

        let carry8 = (h[8] + (1i64 << 25)) >> 26;
        h[9] += carry8;
        h[8] -= carry8 << 26;

        let carry9 = (h[9] + (1i64 << 24)) >> 25;
        h[0] += carry9 * 19;
        h[9] -= carry9 << 25;

        let carry0 = (h[0] + (1i64 << 25)) >> 26;
        h[1] += carry0;
        h[0] -= carry0 << 26;

        FieldElement(h.map(|x| x as i32))
    }

    /// Raises this field element to the power `2^252 − 3`.
    ///
    /// This exponentiation is a fixed addition-chain used in the Ed25519
    /// finite field 𝔽ₚ where `p = 2²⁵⁵ − 19`.
    ///
    /// ## Mathematical meaning
    ///
    /// This function computes:
    ///
    /// ```text
    /// self^(2^252 − 3) mod p
    /// ```
    ///
    /// In this field, this value is used to derive inverses and square roots,
    /// since:
    ///
    /// ```text
    /// x^(p−2) ≡ x^(-1) (mod p)
    /// ```
    ///
    /// and:
    ///
    /// ```text
    /// (2^252 − 3) = (p − 5) / 8
    /// ```
    ///
    /// This specific exponent is required by the Ed25519 square-root and
    /// point decompression algorithms.
    ///
    /// ## Implementation details
    ///
    /// - Uses a hand-written addition chain for minimal squarings and
    ///   multiplications.
    /// - Relies on `square()` and `n_square()` for efficient repeated squaring.
    /// - All operations are performed in constant time.
    /// - Intermediate variables (`t0`, `t1`, `t2`) mirror the reference
    ///   implementation structure.
    ///
    /// ## Constant-time behavior
    ///
    /// This function is constant-time with respect to the input value.
    /// It contains no secret-dependent branches or memory accesses.
    ///
    /// ## Returns
    ///
    /// A new `FieldElement` equal to `self^(2^252 − 3) mod (2^255 − 19)`.
    pub(crate) fn pow22523(&self) -> Self {
        let mut t0 = self.square();
        let mut t1 = t0.n_square(2);

        t1 = *self * t1;
        t0 = t0 * t1;

        t0 = t0.square();
        t0 = t1 * t0;

        t1 = t0.n_square(5);
        t0 = t1 * t0;

        t1 = t0.n_square(10);
        t1 = t1 * t0;

        let mut t2 = t1.n_square(20);
        t1 = t2 * t1;

        t1 = t1.n_square(10);
        t0 = t1 * t0;

        t1 = t0.n_square(50);
        t1 = t1 * t0;

        t2 = t1.n_square(100);
        t1 = t2 * t1;

        t1 = t1.n_square(50);
        t0 = t1 * t0;

        t0 = t0.n_square(2);

        t0 * *self
    }

    /// Computes the multiplicative inverse of this field element.
    ///
    /// This function returns:
    ///
    /// ```text
    /// self^(-1) mod p
    /// ```
    ///
    /// where the field modulus is:
    ///
    /// ```text
    /// p = 2^255 − 19
    /// ```
    ///
    /// ## Mathematical background
    ///
    /// In a prime field 𝔽ₚ, the multiplicative inverse of a non-zero element `x`
    /// is given by Fermat’s little theorem:
    ///
    /// ```text
    /// x^(p−2) ≡ x^(-1) (mod p)
    /// ```
    ///
    /// For Ed25519, this corresponds to the exponent:
    ///
    /// ```text
    /// p − 2 = 2^255 − 21
    /// ```
    ///
    /// This function computes that exponent using a fixed addition chain composed
    /// of squarings and multiplications.
    ///
    /// ## Implementation details
    ///
    /// - Uses a hand-optimized addition chain derived from the Ed25519 reference
    ///   implementation.
    /// - Built on top of `square()` and `n_square()` to minimize the total number
    ///   of multiplications.
    /// - Intermediate variables (`t0`, `t1`, `t2`, `t3`) follow the canonical
    ///   ref10 naming scheme.
    /// - All arithmetic is performed modulo `2^255 − 19`.
    ///
    /// ## Constant-time behavior
    ///
    /// This implementation is constant-time with respect to the input value:
    ///
    /// - No secret-dependent branches
    /// - No secret-dependent memory accesses
    ///
    /// This property is critical for cryptographic safety.
    ///
    /// ## Correctness notes
    ///
    /// - If `self` is zero, the result is mathematically undefined; this function
    ///   returns zero in that case, matching Ed25519 convention.
    /// - For any non-zero field element `x`, the returned value satisfies:
    ///
    /// ```text
    /// x * invert(x) ≡ 1 (mod p)
    /// ```
    ///
    /// ## Returns
    ///
    /// A new `FieldElement` equal to the multiplicative inverse of `self` in
    /// the Ed25519 finite field.
    pub(crate) fn invert(&self) -> Self {
        let mut t0 = self.square();
        let mut t1 = t0.n_square(2);

        t1 = *self * t1;
        t0 = t0 * t1;

        let mut t2 = t0.square();
        t1 = t1 * t2;

        t2 = t1.n_square(5);
        t1 = t2 * t1;

        t2 = t1.n_square(10);
        t2 = t2 * t1;

        let mut t3 = t2.n_square(20);
        t2 = t3 * t2;

        t2 = t2.n_square(10);
        t1 = t2 * t1;

        t2 = t1.n_square(50);
        t2 = t2 * t1;

        t3 = t2.n_square(100);
        t2 = t3 * t2;

        t2 = t2.n_square(50);
        t1 = t2 * t1;

        t1 = t1.n_square(5);

        t1 * t0
    }
}

/// Field element addition.
///
/// Implements limb-wise addition of two `FieldElement`s in the Ed25519 field
/// representation.
///
/// Each of the 10 limbs is added independently using explicit promotion
/// to `i64` via the `add!` macro, preventing intermediate overflows during
/// addition.
///
/// This operation does **not** perform full modular reduction.
/// The result may be only *partially reduced* and is expected to be
/// normalized later by carry propagation or reduction steps.
///
/// This behavior exactly mirrors the reference Ed25519 implementations,
/// where additions are cheap and reductions are deferred.
impl Add for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        FieldElement(array::from_fn(|index| {
            add!(self.0[index], rhs.0[index]) as i32
        }))
    }
}

/// Field element subtraction.
///
/// Implements limb-wise subtraction of two `FieldElement`s in the Ed25519 field
/// representation.
///
/// Each limb is subtracted independently using explicit promotion to `i64`
/// via the `sub!` macro, ensuring correctness even when intermediate values
/// temporarily exceed the `i32` range.
///
/// This operation does **not** guarantee the result is fully reduced.
/// Negative or out-of-range limbs are allowed at this stage and are handled
/// later by normalization or reduction routines.
///
/// This matches the arithmetic model used by the Ed25519 reference C code.
impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        FieldElement(array::from_fn(|index| {
            sub!(self.0[index], rhs.0[index]) as i32
        }))
    }
}

/// Field element multiplication.
///
/// Computes the product of two `FieldElement`s in the prime field
/// \\( \mathbb{F}_{2^{255} - 19} \\).
///
/// This implementation follows the limb-based multiplication strategy used
/// in the Ed25519 reference implementations:
/// - Field elements are represented as 10 signed 32-bit limbs with alternating
///   25-bit and 26-bit widths.
/// - Intermediate products are promoted to `i64` to avoid overflow.
/// - Curve-specific reduction constants (`19`, `38`) are applied eagerly to
///   fold high limbs back into the field.
///
/// ### Algorithm overview
///
/// 1. **Precomputation**
///    - `g_19`: each limb of the right operand multiplied by 19, used for
///      reduction modulo \\(2^{255} - 19\\).
///    - `f_2`: doubled odd limbs of the left operand to reduce the number of
///      multiplications.
///
/// 2. **Cross-product expansion**
///    - All limb cross-products `f[i] * g[j]` are computed explicitly.
///    - Terms that exceed the field size are multiplied by 19 (or 38 = 2×19)
///      and folded back according to the modulus.
///
/// 3. **Accumulation**
///    - The intermediate 10-limb result `h` is built by summing the appropriate
///      cross-products for each limb.
///
/// 4. **Carry propagation**
///    - Carries are propagated in alternating 26-bit / 25-bit limbs.
///    - Final reduction ensures the result fits within canonical limb bounds,
///      though it may not be fully normalized.
///
/// ### Invariants
///
/// - The result represents the correct field product.
/// - The returned `FieldElement` is valid but **not guaranteed to be fully
///   reduced**; further normalization may be applied later if required.
/// - The operation is constant-time with respect to input values.
///
/// This implementation mirrors the structure and behavior of the original
/// Ed25519 C code and prioritizes correctness, performance, and side-channel
/// resistance.
impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: Self) -> Self::Output {
        let f = self.0;
        let g = rhs.0;

        let (g_19, f_2): ([i32; 10], [i32; 10]) = {
            let mut g_mult = [0i32; 10];
            let mut f_mult = [0i32; 10];

            for index in 0..10 {
                g_mult[index] = 19 * g[index];
            }

            for index in [1, 3, 5, 7, 9] {
                f_mult[index] = 2 * f[index];
            }

            (g_mult, f_mult)
        };

        macro_rules! mul {
            ($a:expr, $b:expr) => {
                $a as i64 * $b as i64
            };
        }

        let (f0g0, f0g1, f0g2, f0g3, f0g4, f0g5, f0g6, f0g7, f0g8, f0g9) = (
            mul!(f[0], g[0]),
            mul!(f[0], g[1]),
            mul!(f[0], g[2]),
            mul!(f[0], g[3]),
            mul!(f[0], g[4]),
            mul!(f[0], g[5]),
            mul!(f[0], g[6]),
            mul!(f[0], g[7]),
            mul!(f[0], g[8]),
            mul!(f[0], g[9]),
        );

        let (f1g0, f1g1_2, f1g2, f1g3_2, f1g4, f1g5_2, f1g6, f1g7_2, f1g8, f1g9_38) = (
            mul!(f[1], g[0]),
            mul!(f_2[1], g[1]),
            mul!(f[1], g[2]),
            mul!(f_2[1], g[3]),
            mul!(f[1], g[4]),
            mul!(f_2[1], g[5]),
            mul!(f[1], g[6]),
            mul!(f_2[1], g[7]),
            mul!(f[1], g[8]),
            mul!(f_2[1], g_19[9]),
        );

        let (f2g0, f2g1, f2g2, f2g3, f2g4, f2g5, f2g6, f2g7, f2g8_19, f2g9_19) = (
            mul!(f[2], g[0]),
            mul!(f[2], g[1]),
            mul!(f[2], g[2]),
            mul!(f[2], g[3]),
            mul!(f[2], g[4]),
            mul!(f[2], g[5]),
            mul!(f[2], g[6]),
            mul!(f[2], g[7]),
            mul!(f[2], g_19[8]),
            mul!(f[2], g_19[9]),
        );

        let (f3g0, f3g1_2, f3g2, f3g3_2, f3g4, f3g5_2, f3g6, f3g7_38, f3g8_19, f3g9_38) = (
            mul!(f[3], g[0]),
            mul!(f_2[3], g[1]),
            mul!(f[3], g[2]),
            mul!(f_2[3], g[3]),
            mul!(f[3], g[4]),
            mul!(f_2[3], g[5]),
            mul!(f[3], g[6]),
            mul!(f_2[3], g_19[7]),
            mul!(f[3], g_19[8]),
            mul!(f_2[3], g_19[9]),
        );

        let (f4g0, f4g1, f4g2, f4g3, f4g4, f4g5, f4g6_19, f4g7_19, f4g8_19, f4g9_19) = (
            mul!(f[4], g[0]),
            mul!(f[4], g[1]),
            mul!(f[4], g[2]),
            mul!(f[4], g[3]),
            mul!(f[4], g[4]),
            mul!(f[4], g[5]),
            mul!(f[4], g_19[6]),
            mul!(f[4], g_19[7]),
            mul!(f[4], g_19[8]),
            mul!(f[4], g_19[9]),
        );

        let (f5g0, f5g1_2, f5g2, f5g3_2, f5g4, f5g5_38, f5g6_19, f5g7_38, f5g8_19, f5g9_38) = (
            mul!(f[5], g[0]),
            mul!(f_2[5], g[1]),
            mul!(f[5], g[2]),
            mul!(f_2[5], g[3]),
            mul!(f[5], g[4]),
            mul!(f_2[5], g_19[5]),
            mul!(f[5], g_19[6]),
            mul!(f_2[5], g_19[7]),
            mul!(f[5], g_19[8]),
            mul!(f_2[5], g_19[9]),
        );

        let (f6g0, f6g1, f6g2, f6g3, f6g4_19, f6g5_19, f6g6_19, f6g7_19, f6g8_19, f6g9_19) = (
            mul!(f[6], g[0]),
            mul!(f[6], g[1]),
            mul!(f[6], g[2]),
            mul!(f[6], g[3]),
            mul!(f[6], g_19[4]),
            mul!(f[6], g_19[5]),
            mul!(f[6], g_19[6]),
            mul!(f[6], g_19[7]),
            mul!(f[6], g_19[8]),
            mul!(f[6], g_19[9]),
        );

        let (f7g0, f7g1_2, f7g2, f7g3_38, f7g4_19, f7g5_38, f7g6_19, f7g7_38, f7g8_19, f7g9_38) = (
            mul!(f[7], g[0]),
            mul!(f_2[7], g[1]),
            mul!(f[7], g[2]),
            mul!(f_2[7], g_19[3]),
            mul!(f[7], g_19[4]),
            mul!(f_2[7], g_19[5]),
            mul!(f[7], g_19[6]),
            mul!(f_2[7], g_19[7]),
            mul!(f[7], g_19[8]),
            mul!(f_2[7], g_19[9]),
        );

        let (f8g0, f8g1, f8g2_19, f8g3_19, f8g4_19, f8g5_19, f8g6_19, f8g7_19, f8g8_19, f8g9_19) = (
            mul!(f[8], g[0]),
            mul!(f[8], g[1]),
            mul!(f[8], g_19[2]),
            mul!(f[8], g_19[3]),
            mul!(f[8], g_19[4]),
            mul!(f[8], g_19[5]),
            mul!(f[8], g_19[6]),
            mul!(f[8], g_19[7]),
            mul!(f[8], g_19[8]),
            mul!(f[8], g_19[9]),
        );

        let (f9g0, f9g1_38, f9g2_19, f9g3_38, f9g4_19, f9g5_38, f9g6_19, f9g7_38, f9g8_19, f9g9_38) = (
            mul!(f[9], g[0]),
            mul!(f_2[9], g_19[1]),
            mul!(f[9], g_19[2]),
            mul!(f_2[9], g_19[3]),
            mul!(f[9], g_19[4]),
            mul!(f_2[9], g_19[5]),
            mul!(f[9], g_19[6]),
            mul!(f_2[9], g_19[7]),
            mul!(f[9], g_19[8]),
            mul!(f_2[9], g_19[9]),
        );

        let mut h = [
            f0g0 + f1g9_38
                + f2g8_19
                + f3g7_38
                + f4g6_19
                + f5g5_38
                + f6g4_19
                + f7g3_38
                + f8g2_19
                + f9g1_38,
            f0g1 + f1g0
                + f2g9_19
                + f3g8_19
                + f4g7_19
                + f5g6_19
                + f6g5_19
                + f7g4_19
                + f8g3_19
                + f9g2_19,
            f0g2 + f1g1_2
                + f2g0
                + f3g9_38
                + f4g8_19
                + f5g7_38
                + f6g6_19
                + f7g5_38
                + f8g4_19
                + f9g3_38,
            f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19,
            f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38,
            f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19,
            f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38,
            f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19,
            f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38,
            f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0,
        ];

        for index in [0, 4] {
            let carry = (h[index] + (1i64 << 25)) >> 26;

            h[index + 1] += carry;
            h[index] -= carry << 26;
        }

        for index in [1, 5] {
            let carry = (h[index] + (1i64 << 24)) >> 25;

            h[index + 1] += carry;
            h[index] -= carry << 25;
        }

        for index in [2, 6] {
            let carry = (h[index] + (1i64 << 25)) >> 26;

            h[index + 1] += carry;
            h[index] -= carry << 26;
        }

        for index in [3, 7] {
            let carry = (h[index] + (1i64 << 24)) >> 25;

            h[index + 1] += carry;
            h[index] -= carry << 25;
        }

        let carry4 = (h[4] + (1i64 << 25)) >> 26;
        h[5] += carry4;
        h[4] -= carry4 << 26;

        let carry8 = (h[8] + (1i64 << 25)) >> 26;
        h[9] += carry8;
        h[8] -= carry8 << 26;

        let carry9 = (h[9] + (1i64 << 24)) >> 25;
        h[0] += carry9 * 19;
        h[9] -= carry9 << 25;

        let carry0 = (h[0] + (1i64 << 25)) >> 26;
        h[1] += carry0;
        h[0] -= carry0 << 26;

        FieldElement(h.map(|x| x as i32))
    }
}

/// Field element negation.
///
/// Implements limb-wise negation of a `FieldElement`.
///
/// Each of the 10 limbs is negated independently by applying unary minus.
/// This corresponds to computing the additive inverse in the underlying
/// integer representation of the field element.
///
/// This operation does **not** perform modular reduction.
/// The resulting limbs may temporarily fall outside their canonical bounds
/// and are expected to be normalized later through reduction or carry
/// propagation.
///
/// This behavior is intentional and matches the Ed25519 reference
/// implementations, where negation is a cheap, non-reducing operation.
impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        FieldElement(self.0.map(|x| -x))
    }
}
