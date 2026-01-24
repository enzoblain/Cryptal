//! Finite field arithmetic for Shamir Secret Sharing.
//!
//! This module implements arithmetic over a finite field of 256 elements
//! (GF(256)), which is the mathematical foundation of the Shamir Secret
//! Sharing scheme used elsewhere in the crate.
//!
//! All operations are defined over `u8` values and follow the standard
//! construction used in cryptographic systems such as AES. The field is
//! defined by polynomial arithmetic modulo an irreducible polynomial
//! of degree 8.
//!
//! This module is intentionally kept private to the Shamir implementation
//! to avoid misuse and to ensure that all cryptographic constructions are
//! mediated through higher-level, validated APIs.
//!
//! ## Design principles
//!
//! - Small, explicit, and auditable implementation
//! - No heap allocation
//! - Deterministic behavior
//! - Closed arithmetic with guaranteed inverses for non-zero elements
//!
//! ## Security notes
//!
//! - All arithmetic is performed in GF(256).
//! - Addition is implemented as bitwise XOR.
//! - Multiplication uses polynomial reduction modulo an irreducible
//!   polynomial.
//! - Every non-zero element has a multiplicative inverse.
//!
//! This module does **not** perform any validation of Shamir-specific
//! parameters such as thresholds or share identifiers. Those checks are
//! handled at higher layers.

use std::ops::{Add, Div, Mul};

/// An element of the finite field GF(256).
///
/// This type represents a single element of the field as an 8-bit value.
/// All arithmetic operations (`+`, `*`, `/`) are defined according to
/// finite field rules rather than integer arithmetic.
///
/// The underlying representation is opaque outside this module.
#[derive(Clone, Copy)]
pub(crate) struct FieldElement(u8);

impl FieldElement {
    /// The additive identity of the field.
    pub(crate) const ZERO: Self = FieldElement(0);

    /// The multiplicative identity of the field.
    pub(crate) const ONE: Self = FieldElement(1);

    /// Constructs a field element from a raw byte.
    ///
    /// This is a simple wrapper and performs no validation.
    #[inline]
    pub(crate) fn from(n: u8) -> Self {
        Self(n)
    }

    /// Returns the underlying byte representation of the field element.
    ///
    /// This is primarily intended for serialization or for transferring
    /// values back into higher-level Shamir structures.
    #[inline]
    pub(crate) fn into_number(self) -> u8 {
        self.0
    }

    /// Computes the multiplicative inverse of the field element.
    ///
    /// # Panics
    ///
    /// Panics if called on zero, which has no multiplicative inverse in
    /// a finite field.
    ///
    /// # Implementation details
    ///
    /// The inverse is computed using exponentiation:
    ///
    /// ```text
    /// a⁻¹ = a²⁵⁴  (in GF(256))
    /// ```
    ///
    /// This method is simple, deterministic, and suitable for small
    /// field sizes.
    pub(crate) fn invert(self) -> Self {
        assert!(self.0 != 0, "0 has no inverse in FieldElement(256)");

        let mut t = self;
        for _ in 0..253 {
            t = t * self;
        }
        t
    }

    /// Evaluates a polynomial at a given field element.
    ///
    /// The polynomial is provided as a slice of coefficients in increasing
    /// degree order:
    ///
    /// ```text
    /// f(x) = coeffs[0] + coeffs[1]·x + coeffs[2]·x² + ...
    /// ```
    ///
    /// Evaluation is performed using Horner's method.
    ///
    /// This function is used during secret splitting and share refresh.
    pub(crate) fn from_polynomial(coeffs: &[Self], x: Self) -> Self {
        let mut acc = FieldElement::ZERO;

        for &c in coeffs.iter().rev() {
            acc = acc * x + c;
        }

        acc
    }

    /// Computes the value of a polynomial at zero using Lagrange interpolation.
    ///
    /// The input is a slice of `(x, y)` points, where each point represents
    /// an evaluation of the same polynomial at a distinct, non-zero `x`.
    ///
    /// This function reconstructs `f(0)` without ever reconstructing the
    /// polynomial itself.
    ///
    /// # Usage
    ///
    /// This operation is the core of Shamir Secret Sharing reconstruction
    /// and is used to recover a secret byte from a set of shares.
    ///
    /// # Preconditions
    ///
    /// - All `x` values must be distinct and non-zero.
    /// - The number of points must be sufficient to uniquely determine
    ///   the polynomial.
    pub(crate) fn lagrange_at_zero(points: &[(Self, Self)]) -> Self {
        let mut acc = FieldElement::ZERO;

        for (i, &(xi, yi)) in points.iter().enumerate() {
            let mut num = FieldElement::ONE;
            let mut den = FieldElement::ONE;

            for (j, &(xj, _)) in points.iter().enumerate() {
                if i != j {
                    num = num * xj;
                    // In GF(2⁸), subtraction is equivalent to addition (XOR)
                    den = (xj + xi) * den;
                }
            }

            acc = (num / den) * yi + acc;
        }

        acc
    }
}

/// Field addition.
///
/// In GF(256), addition is defined as bitwise XOR.
impl Add for FieldElement {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

/// Field multiplication.
///
/// Multiplication is implemented using polynomial multiplication with
/// reduction modulo an irreducible polynomial.
impl Mul for FieldElement {
    type Output = Self;

    fn mul(mut self, mut rhs: Self) -> Self {
        let mut res = 0u8;

        while rhs.0 != 0 {
            if rhs.0 & 1 != 0 {
                res ^= self.0;
            }

            let carry = self.0 & 0x80;
            self.0 <<= 1;

            if carry != 0 {
                // Reduction polynomial (x⁸ + x⁴ + x³ + x + 1)
                self.0 ^= 0x1B;
            }

            rhs.0 >>= 1;
        }

        Self(res)
    }
}

/// Field division.
///
/// Division is defined as multiplication by the multiplicative inverse.
impl Div for FieldElement {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.invert()
    }
}
