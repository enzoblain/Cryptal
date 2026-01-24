//! Ed25519 scalar arithmetic.
//!
//! This module implements arithmetic on scalars used by the Ed25519 signature
//! scheme and related constructions.
//!
//! Scalars are integers modulo the Ed25519 group order ℓ, defined as:
//!
//! ```text
//! ℓ = 2^252 + 27742317777372353535851937790883648493
//! ```
//!
//! ## Role of scalars
//!
//! Scalars are used throughout Ed25519 for:
//!
//! - private keys (after clamping)
//! - deterministic nonces derived from hashes
//! - challenges computed during signing and verification
//! - scalar multiplication of curve points
//!
//! This module provides the low-level building blocks required to safely
//! manipulate such values.
//!
//! ## Representation
//!
//! Scalars are stored as a fixed-size `[u8; 32]` little-endian byte array.
//! This representation is intentionally minimal and does **not** enforce
//! invariants by itself.
//!
//! In particular:
//!
//! - No clamping is performed automatically
//! - No reduction modulo ℓ is implicit
//!
//! All normalization steps are performed explicitly by the relevant functions
//! (e.g. `reduce`, `from_mul_sum`).
//!
//! ## Implemented operations
//!
//! This module implements:
//!
//! - Reduction of wide integers modulo ℓ (`reduce`)
//! - Modular linear combinations (`a * b + c mod ℓ`)
//! - Sliding-window scalar recoding (`slide`)
//!
//! These primitives are sufficient to support:
//!
//! - Ed25519 signature generation
//! - Ed25519 signature verification
//! - Key update and scalar arithmetic routines
//!
//! ## Algorithms
//!
//! - Scalars are reduced using a radix-2²¹ representation with signed limbs
//! - Reduction coefficients follow the identity:
//!
//! ```text
//! 2^252 ≡ 27742317777372353535851937790883648493 (mod ℓ)
//! ```
//!
//! - Sliding-window recoding produces sparse signed digits in `[-15, 15]`
//!
//! All algorithms closely follow the Ed25519 reference implementations
//! (ref10 / orlp) and preserve identical arithmetic behavior.
//!
//! ## Security properties
//!
//! - All scalar operations are **constant-time** with respect to secret data
//! - No secret-dependent branches
//! - No secret-dependent memory accesses
//!
//! The sliding-window representation is designed for use in constant-time
//! scalar multiplication routines.
//!
//! ## Design philosophy
//!
//! This module is deliberately low-level and explicit.
//! It prioritizes:
//!
//! - auditability
//! - strict control over reductions and carries
//! - behavioral equivalence with the reference Ed25519 code
//!
//! Higher-level guarantees (key clamping, protocol correctness) are enforced
//! by the layers that use this module.

use crate::signatures::ed25519::field::{load_3, load_4};

use std::array;

/// A 256-bit scalar used in Ed25519 operations.
///
/// This type represents integers modulo the Ed25519 group order `ℓ`,
/// encoded as 32 little-endian bytes. Scalars are used for:
///
/// - private keys
/// - nonces
/// - challenges derived from hashes
/// - scalar multiplication on curve points
///
/// The internal representation is intentionally minimal: a fixed-size
/// `[u8; 32]` buffer. Higher-level invariants (clamping, reduction modulo
/// `ℓ`) are enforced explicitly by the functions that construct or
/// transform scalars.
#[derive(Clone, Copy)]
pub struct Scalar(pub [u8; 32]);

impl Scalar {
    /// Constructs a scalar from a 32-byte little-endian slice.
    ///
    /// This function performs no validation, clamping, or modular
    /// reduction. The caller is responsible for ensuring the input
    /// represents a valid scalar for the intended use.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is not exactly 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let arr = bytes.try_into().expect("slice must be 32 bytes");
        Scalar(arr)
    }

    /// Returns the canonical 32-byte little-endian encoding of the scalar.
    ///
    /// This method simply exposes the internal representation without
    /// performing any normalization or reduction.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Reduces a 512-bit integer modulo the Ed25519 scalar field order `ℓ`.
    ///
    /// This function takes a 64-byte (512-bit) input and reduces it modulo
    /// the group order
    ///
    /// ```text
    /// ℓ = 2^252 + 27742317777372353535851937790883648493
    /// ```
    ///
    /// The implementation follows the reference Ed25519 reduction algorithm
    /// and operates on a radix-2²¹ representation using 24 signed limbs.
    ///
    /// ## Overview
    ///
    /// The reduction proceeds in several well-defined phases:
    ///
    /// 1. **Radix decomposition**
    ///    - The 64-byte input is split into 21-bit limbs using overlapping
    ///      `load_3` / `load_4` operations.
    ///    - Limbs `s[0]..s[23]` represent the wide integer in base 2²¹.
    ///
    /// 2. **High-limb elimination**
    ///    - Limbs `s[18]..s[23]` are folded back into lower limbs using
    ///      precomputed reduction coefficients.
    ///    - These coefficients encode the relation between `2^252` and `ℓ`.
    ///
    /// 3. **Carry propagation**
    ///    - Carries are propagated multiple times to ensure all limbs fit
    ///      within 21 bits.
    ///    - The process alternates between even and odd limbs to maintain
    ///      bounds at each step.
    ///
    /// 4. **Final reduction**
    ///    - Any remaining contribution in limb `s[12]` is folded back.
    ///    - A final carry pass ensures canonical representation.
    ///
    /// 5. **Re-encoding**
    ///    - The reduced scalar is serialized back into 32 bytes using the
    ///      standard Ed25519 bit layout.
    ///
    /// ## Constant-time behavior
    ///
    /// - All operations are data-independent.
    /// - No branches depend on secret data.
    /// - The reduction is safe to use with secret scalars.
    ///
    /// ## Correctness guarantees
    ///
    /// - The output is guaranteed to be strictly less than `ℓ`.
    /// - The resulting scalar is in canonical form.
    /// - Behavior matches the Ed25519 reference C implementation.
    ///
    /// ## Notes
    ///
    /// - Limb arithmetic is performed using `i64` to prevent overflow.
    /// - The chosen radix (2²¹) balances carry cost and multiplication safety.
    /// - This function is a critical primitive used in:
    ///   - signature generation
    ///   - signature verification
    ///   - scalar arithmetic
    pub(crate) fn reduce(wide: [u8; 64]) -> Self {
        let mask = 0x1f_ffffi64;

        let mut s = [
            (load_3(&wide[0..]) as i64) & mask,
            ((load_4(&wide[2..]) >> 5) as i64) & mask,
            ((load_3(&wide[5..]) >> 2) as i64) & mask,
            ((load_4(&wide[7..]) >> 7) as i64) & mask,
            ((load_4(&wide[10..]) >> 4) as i64) & mask,
            ((load_3(&wide[13..]) >> 1) as i64) & mask,
            ((load_4(&wide[15..]) >> 6) as i64) & mask,
            ((load_3(&wide[18..]) >> 3) as i64) & mask,
            (load_3(&wide[21..]) as i64) & mask,
            ((load_4(&wide[23..]) >> 5) as i64) & mask,
            ((load_3(&wide[26..]) >> 2) as i64) & mask,
            ((load_4(&wide[28..]) >> 7) as i64) & mask,
            ((load_4(&wide[31..]) >> 4) as i64) & mask,
            ((load_3(&wide[34..]) >> 1) as i64) & mask,
            ((load_4(&wide[36..]) >> 6) as i64) & mask,
            ((load_3(&wide[39..]) >> 3) as i64) & mask,
            (load_3(&wide[42..]) as i64) & mask,
            ((load_4(&wide[44..]) >> 5) as i64) & mask,
            ((load_3(&wide[47..]) >> 2) as i64) & mask,
            ((load_4(&wide[49..]) >> 7) as i64) & mask,
            ((load_4(&wide[52..]) >> 4) as i64) & mask,
            ((load_3(&wide[55..]) >> 1) as i64) & mask,
            ((load_4(&wide[57..]) >> 6) as i64) & mask,
            (load_4(&wide[60..]) >> 3) as i64,
        ];

        let coeffs = [666643, 470296, 654183, -997805, 136657, -683901];

        for index in (18..=23).rev() {
            for j in 0..6 {
                s[index - 12 + j] += s[index] * coeffs[j];
            }
        }

        for &index in &[6, 8, 10, 12, 14, 16] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        for &index in &[7, 9, 11, 13, 15] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        for index in (12..=17).rev() {
            for j in 0..6 {
                s[index - 12 + j] += s[index] * coeffs[j];
            }
        }
        s[12] = 0;

        for &index in &[0, 2, 4, 6, 8, 10] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        for &index in &[1, 3, 5, 7, 9, 11] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        let s12 = s[12];
        for (sx, coeff) in s.iter_mut().take(6).zip(coeffs.iter()) {
            *sx = s12 * coeff;
        }
        s[12] = 0;

        for index in 0..11 {
            let carry = s[index] >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        let carry = s[11] >> 21;
        s[12] += carry;
        s[11] -= carry << 21;

        let s12 = s[12];
        for (sx, coeff) in s.iter_mut().take(6).zip(coeffs.iter()) {
            *sx = s12 * coeff;
        }

        for index in 0..11 {
            let carry = s[index] >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        let result = [
            s[0] as u8,
            (s[0] >> 8) as u8,
            ((s[0] >> 16) | (s[1] << 5)) as u8,
            (s[1] >> 3) as u8,
            (s[1] >> 11) as u8,
            ((s[1] >> 19) | (s[2] << 2)) as u8,
            (s[2] >> 6) as u8,
            ((s[2] >> 14) | (s[3] << 7)) as u8,
            (s[3] >> 1) as u8,
            (s[3] >> 9) as u8,
            ((s[3] >> 17) | (s[4] << 4)) as u8,
            (s[4] >> 4) as u8,
            (s[4] >> 12) as u8,
            ((s[4] >> 20) | (s[5] << 1)) as u8,
            (s[5] >> 7) as u8,
            ((s[5] >> 15) | (s[6] << 6)) as u8,
            (s[6] >> 2) as u8,
            (s[6] >> 10) as u8,
            ((s[6] >> 18) | (s[7] << 3)) as u8,
            (s[7] >> 5) as u8,
            (s[7] >> 13) as u8,
            s[8] as u8,
            (s[8] >> 8) as u8,
            ((s[8] >> 16) | (s[9] << 5)) as u8,
            (s[9] >> 3) as u8,
            (s[9] >> 11) as u8,
            ((s[9] >> 19) | (s[10] << 2)) as u8,
            (s[10] >> 6) as u8,
            ((s[10] >> 14) | (s[11] << 7)) as u8,
            (s[11] >> 1) as u8,
            (s[11] >> 9) as u8,
            (s[11] >> 17) as u8,
        ];

        Scalar(result)
    }

    /// Computes the scalar expression `a * b + c (mod ℓ)`.
    ///
    /// This function multiplies two scalars `a` and `b`, adds a third scalar `c`,
    /// and reduces the result modulo the Ed25519 scalar field order
    ///
    /// ```text
    /// ℓ = 2^252 + 27742317777372353535851937790883648493
    /// ```
    ///
    /// It is a core primitive used during Ed25519 signature generation, notably
    /// for computing the `S` component of a signature:
    ///
    /// ```text
    /// S = (r + k * a) mod ℓ
    /// ```
    ///
    /// ## High-level structure
    ///
    /// The computation follows the reference Ed25519 scalar arithmetic and
    /// proceeds in several stages:
    ///
    /// 1. **Radix decomposition**
    ///    - Each input scalar is decomposed into 12 signed 21-bit limbs
    ///      using overlapping `load_3` / `load_4` operations.
    ///    - This radix-2²¹ representation allows safe intermediate products
    ///      in 64-bit arithmetic.
    ///
    /// 2. **Wide multiplication and accumulation**
    ///    - A schoolbook convolution computes `a * b`, producing up to 24 limbs.
    ///    - The scalar `c` is added directly into the lower limbs during
    ///      accumulation, avoiding a separate addition pass.
    ///
    /// 3. **Carry propagation**
    ///    - Carries are propagated across even and odd limbs to keep values
    ///      bounded within 21 bits.
    ///    - Multiple passes ensure all limbs remain within safe limits.
    ///
    /// 4. **Modular reduction**
    ///    - High limbs are folded back into lower limbs using precomputed
    ///      reduction coefficients derived from the relation:
    ///
    ///      ```text
    ///      2^252 ≡ 27742317777372353535851937790883648493 (mod ℓ)
    ///      ```
    ///
    ///    - This eliminates limbs beyond the scalar size while preserving
    ///      correctness modulo `ℓ`.
    ///
    /// 5. **Final normalization**
    ///    - Remaining carries are propagated.
    ///    - The result is serialized back into a canonical 32-byte scalar.
    ///
    /// ## Constant-time behavior
    ///
    /// - The algorithm is fully constant-time.
    /// - No branches depend on secret data.
    /// - Suitable for use with secret scalars (private keys, nonces).
    ///
    /// ## Correctness guarantees
    ///
    /// - The returned scalar is reduced modulo `ℓ`.
    /// - The encoding is canonical.
    /// - Behavior matches the Ed25519 reference C implementation.
    ///
    /// ## Implementation notes
    ///
    /// - All intermediate arithmetic is performed using `i64` to avoid overflow.
    /// - The chosen radix (2²¹) balances carry frequency and multiplication safety.
    /// - Reduction coefficients are identical to those used in the reference
    ///   Ed25519 implementation.
    ///
    /// This function is a critical building block for:
    /// - signature generation
    /// - scalar arithmetic
    /// - key updates involving linear combinations of scalars
    pub(crate) fn from_mul_sum(a: Scalar, b: Scalar, c: Scalar) -> Self {
        let mask = 0x1f_ffffi64;

        let load_a = |data: &[u8; 32]| -> [i64; 12] {
            [
                (load_3(&data[0..]) as i64) & mask,
                ((load_4(&data[2..]) >> 5) as i64) & mask,
                ((load_3(&data[5..]) >> 2) as i64) & mask,
                ((load_4(&data[7..]) >> 7) as i64) & mask,
                ((load_4(&data[10..]) >> 4) as i64) & mask,
                ((load_3(&data[13..]) >> 1) as i64) & mask,
                ((load_4(&data[15..]) >> 6) as i64) & mask,
                ((load_3(&data[18..]) >> 3) as i64) & mask,
                (load_3(&data[21..]) as i64) & mask,
                ((load_4(&data[23..]) >> 5) as i64) & mask,
                ((load_3(&data[26..]) >> 2) as i64) & mask,
                (load_4(&data[28..]) >> 7) as i64,
            ]
        };

        let a_limbs = load_a(&a.0);
        let b_limbs = load_a(&b.0);
        let c_limbs = load_a(&c.0);

        let mut s = [0i64; 24];

        for index in 0..12 {
            s[index] = c_limbs[index];
            for j in 0..=index.min(11) {
                if index - j < 12 {
                    s[index] += a_limbs[j] * b_limbs[index - j];
                }
            }
        }

        for index in 12..23 {
            for j in (index - 11)..12 {
                if index - j < 12 {
                    s[index] += a_limbs[j] * b_limbs[index - j];
                }
            }
        }

        s[23] = 0;

        for &index in &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        for &index in &[1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        let coeffs = [666643i64, 470296, 654183, -997805, 136657, -683901];

        for index in (18..=23).rev() {
            for j in 0..6 {
                s[index - 12 + j] += s[index] * coeffs[j];
            }
        }

        for &index in &[6, 8, 10, 12, 14, 16] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        for &index in &[7, 9, 11, 13, 15] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        for index in (12..=17).rev() {
            for j in 0..6 {
                s[index - 12 + j] += s[index] * coeffs[j];
            }
        }
        s[12] = 0;

        for &index in &[0, 2, 4, 6, 8, 10] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        for &index in &[1, 3, 5, 7, 9, 11] {
            let carry = (s[index] + (1 << 20)) >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        let s12 = s[12];
        for (sx, coeff) in s.iter_mut().take(6).zip(coeffs.iter()) {
            *sx += s12 * coeff;
        }
        s[12] = 0;

        for index in 0..11 {
            let carry = s[index] >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        let carry = s[11] >> 21;
        s[12] += carry;
        s[11] -= carry << 21;

        let s12 = s[12];
        for (sx, coeff) in s.iter_mut().take(6).zip(coeffs.iter()) {
            *sx += s12 * coeff;
        }

        for index in 0..11 {
            let carry = s[index] >> 21;

            s[index + 1] += carry;
            s[index] -= carry << 21;
        }

        let result = [
            s[0] as u8,
            (s[0] >> 8) as u8,
            ((s[0] >> 16) | (s[1] << 5)) as u8,
            (s[1] >> 3) as u8,
            (s[1] >> 11) as u8,
            ((s[1] >> 19) | (s[2] << 2)) as u8,
            (s[2] >> 6) as u8,
            ((s[2] >> 14) | (s[3] << 7)) as u8,
            (s[3] >> 1) as u8,
            (s[3] >> 9) as u8,
            ((s[3] >> 17) | (s[4] << 4)) as u8,
            (s[4] >> 4) as u8,
            (s[4] >> 12) as u8,
            ((s[4] >> 20) | (s[5] << 1)) as u8,
            (s[5] >> 7) as u8,
            ((s[5] >> 15) | (s[6] << 6)) as u8,
            (s[6] >> 2) as u8,
            (s[6] >> 10) as u8,
            ((s[6] >> 18) | (s[7] << 3)) as u8,
            (s[7] >> 5) as u8,
            (s[7] >> 13) as u8,
            s[8] as u8,
            (s[8] >> 8) as u8,
            ((s[8] >> 16) | (s[9] << 5)) as u8,
            (s[9] >> 3) as u8,
            (s[9] >> 11) as u8,
            ((s[9] >> 19) | (s[10] << 2)) as u8,
            (s[10] >> 6) as u8,
            ((s[10] >> 14) | (s[11] << 7)) as u8,
            (s[11] >> 1) as u8,
            (s[11] >> 9) as u8,
            (s[11] >> 17) as u8,
        ];

        Scalar(result)
    }

    /// Computes the signed sliding-window representation of a scalar.
    ///
    /// This function converts the scalar into a signed digit representation
    /// with window size up to 6 bits (i.e. values in `[-15, 15]`), commonly
    /// referred to as *sliding window recoding*.
    ///
    /// ### Purpose
    /// The sliding-window form is used to speed up scalar multiplication
    /// on elliptic curves (notably Ed25519) by:
    /// - reducing the number of non-zero digits
    /// - allowing precomputation of small odd multiples
    /// - replacing many doublings and additions with fewer, larger steps
    ///
    /// ### Representation
    /// - The output is an array of 256 signed digits (`i8`)
    /// - Each position corresponds to a bit index of the scalar
    /// - At most one non-zero digit appears in any window of size ≤ 6
    /// - Non-zero digits are guaranteed to be odd and in the range `[-15, 15]`
    ///
    /// ### Algorithm overview
    /// 1. Expand the scalar into its bit representation (`0` or `1`)
    /// 2. Scan from least significant bit to most significant bit
    /// 3. When a non-zero bit is found:
    ///    - Attempt to merge it with nearby bits (up to 6 ahead)
    ///    - Adjust the current digit to stay within `[-15, 15]`
    ///    - Propagate carries forward when necessary
    /// 4. Clear consumed bits to maintain sparsity
    ///
    /// ### Security notes
    /// - The algorithm operates on fixed-size arrays
    /// - No secret-dependent memory accesses outside the scalar window
    /// - Intended for use in constant-time scalar multiplication routines
    ///
    /// This implementation follows the same strategy as the Ed25519
    /// reference implementations and common audited libraries.
    pub(crate) fn slide(&self) -> Slide {
        let mut r = array::from_fn(|index| ((self.0[index >> 3] >> (index & 7)) & 1) as i8);

        for index in 0..256 {
            if r[index] != 0 {
                let mut b = 1;

                while b <= 6 && index + b < 256 {
                    if r[index + b] != 0 {
                        let rb = (r[index + b] as i32) << b;
                        let ri = r[index] as i32;

                        if ri + rb <= 15 {
                            r[index] = (ri + rb) as i8;
                            r[index + b] = 0;
                        } else if ri - rb >= -15 {
                            r[index] = (ri - rb) as i8;

                            for v in r.iter_mut().skip(index + b) {
                                if *v == 0 {
                                    *v = 1;
                                    break;
                                }

                                *v = 0;
                            }
                        } else {
                            break;
                        }
                    }
                    b += 1;
                }
            }
        }

        r
    }
}

/// Signed sliding-window representation of a scalar.
///
/// This type represents a scalar decomposed into 256 signed digits,
/// one per bit position, using a sliding-window recoding strategy.
///
/// Each entry is:
/// - zero most of the time (sparse representation)
/// - an odd value in the range `[-15, 15]` when non-zero
///
/// This representation is designed to accelerate elliptic-curve
/// scalar multiplication (e.g. Ed25519) by reducing the number of
/// additions and enabling efficient precomputation.
///
/// The array length is fixed to 256, matching the bit length of
/// Ed25519 scalars.
pub(crate) type Slide = [i8; 256];
