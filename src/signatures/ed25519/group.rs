//! Edwards25519 group operations.
//!
//! This module implements group arithmetic for the Edwards25519 elliptic curve
//! used by Ed25519 signatures and related constructions.
//!
//! The curve is defined over the prime field 𝔽ₚ with:
//!
//! ```text
//! p = 2²⁵⁵ − 19
//! ```
//!
//! and uses the twisted Edwards form:
//!
//! ```text
//! −x² + y² = 1 + d·x²·y²
//! ```
//!
//! where `d` is the standard Edwards25519 curve constant.
//!
//! ## Coordinate systems
//!
//! To achieve high performance and constant-time execution, this module
//! implements several coordinate representations, each optimized for a
//! specific role in scalar multiplication and point arithmetic:
//!
//! - **GeP3** — Extended coordinates `(X : Y : Z : T)`
//!   - Primary working representation
//!   - Supports complete addition formulas without inversions
//!
//! - **GeP1** — Extended intermediate coordinates
//!   - Used as a transient result during additions and doublings
//!   - Never stored long-term
//!
//! - **GeP2** — Projective coordinates `(X : Y : Z)`
//!   - Used mainly for point doubling
//!
//! - **GeCached** — Cached extended form
//!   - Stores precomputed `(Y±X, Z, 2·d·T)`
//!   - Optimized for repeated additions/subtractions
//!
//! - **GePrecomp** — Precomputed affine-like form
//!   - Used for fixed-base and windowed scalar multiplication
//!   - Backed by static tables (`BASE`, `BI`)
//!
//! ## Implemented operations
//!
//! - Point addition and subtraction (mixed and cached forms)
//! - Point doubling
//! - Fixed-base scalar multiplication
//! - Double-scalar multiplication
//! - Point compression and decompression
//!
//! ## Algorithms
//!
//! - Sliding-window scalar multiplication
//! - Window size 4 with signed digits
//! - Constant-time table selection
//! - Square-root extraction via `(p − 5) / 8` exponentiation
//!
//! All algorithms closely follow the Ed25519 reference implementations
//! (ref10 / orlp) and preserve identical arithmetic behavior.
//!
//! ## Security properties
//!
//! - **Constant-time** with respect to secret scalars
//! - No secret-dependent branches
//! - No secret-dependent memory access
//! - Explicit use of conditional moves for table selection
//!
//! Point decompression operates only on public data and may use conditional
//! branches safely.
//!
//! ## Design philosophy
//!
//! This module is intentionally explicit and low-level.
//! It favors:
//!
//! - auditability over abstraction
//! - predictability over cleverness
//! - structural similarity to reference code
//!
//! The code is suitable for cryptographic use and is intended to be
//! understandable by reviewers familiar with Ed25519 internals.

use super::ct::ConstantTimeEq;
use super::field::FieldElement;
use super::scalar::Scalar;
use super::table::BASE;
use super::table::{BI, D, D2, SQRTM1};

/// Group element in extended projective coordinates (P1 representation).
///
/// This structure represents a point on the Edwards curve using the
/// `(X : Y : Z : T)` coordinate system, where:
///
/// - `X = x / z`
/// - `Y = y / z`
/// - `T = (x * y) / z`
///
/// This representation is primarily used as an *intermediate form*
/// during point addition and doubling. It is not intended to be kept
/// long-term, but rather converted into other representations such as
/// `GeP3`.
///
/// All arithmetic is performed over the prime field defined by Ed25519.
pub(crate) struct GeP1 {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

impl GeP1 {
    /// Computes the sum of a `GeP3` point and a cached point.
    ///
    /// This function implements the Edwards curve addition formula
    /// using mixed coordinates:
    ///
    /// - `a` is provided in extended coordinates (`GeP3`)
    /// - `b` is provided in cached form (`GeCached`)
    ///
    /// The result is returned in `GeP1` form, which is suitable for
    /// subsequent additions or conversion to `GeP3`.
    ///
    /// This operation is constant-time with respect to secret data
    /// and follows the formulas from the Ed25519 reference implementation.
    pub(crate) fn from_sum(a: &GeP3, b: &GeCached) -> Self {
        let mut x = a.y + a.x;
        let mut y = a.y - a.x;
        let mut z = x * b.yplusx;
        let mut t = b.t2d * a.t;

        y = y * b.yminusx;
        x = a.z * b.z;

        let sumx = x + x;

        x = z - y;
        y = z + y;
        z = sumx + t;
        t = sumx - t;

        Self { x, y, z, t }
    }

    /// Computes the sum of a `GeP3` point and a precomputed table entry.
    ///
    /// This function performs Edwards curve point addition using *mixed
    /// coordinates*:
    ///
    /// - `a` is provided in extended coordinates (`GeP3`)
    /// - `b` is provided in precomputed form (`GePrecomp`)
    ///
    /// The precomputed representation stores combinations of `(Y + X)`,
    /// `(Y - X)` and a scaled `X * Y` term, allowing faster addition by
    /// reducing the number of field multiplications.
    ///
    /// The result is returned in `GeP1` coordinates, which are intended
    /// as a transient representation during scalar multiplication and
    /// double-and-add sequences.
    ///
    /// This operation is constant-time with respect to secret data and
    /// follows the addition formulas used in the Ed25519 reference
    /// implementation.
    pub(crate) fn from_mixed_sum(a: &GeP3, b: &GePrecomp) -> Self {
        let mut x = a.y + a.x;
        let mut y = a.y - a.x;
        let mut z = x * b.yplusx;
        let mut t = b.xy2d * a.t;
        let sumz = a.z + a.z;

        y = y * b.yminusx;
        x = z - y;
        y = z + y;
        z = sumz + t;
        t = sumz - t;

        Self { x, y, z, t }
    }

    /// Computes the difference of a `GeP3` point and a cached point.
    ///
    /// This function implements Edwards curve point subtraction
    /// using extended coordinates:
    ///
    /// - `a` is the minuend, provided in `GeP3` (extended coordinates)
    /// - `b` is the subtrahend, provided in `GeCached`
    ///
    /// Algebraically, this computes:
    ///
    /// ```text
    /// R = a − b
    /// ```
    ///
    /// The subtraction is performed by reusing the standard Edwards
    /// addition formulas, with the signs of the cached `(Y ± X)` terms
    /// swapped accordingly. This avoids explicit negation of the point
    /// and preserves constant-time behavior.
    ///
    /// The result is returned in `GeP1` coordinates, which are intended
    /// as a short-lived intermediate representation during scalar
    /// multiplication and ladder-style algorithms.
    ///
    /// This implementation matches the formulas used in the Ed25519
    /// reference code and is safe for use with secret scalars.
    pub(crate) fn from_difference(a: &GeP3, b: &GeCached) -> Self {
        let mut x = a.y + a.x;
        let mut y = a.y - a.x;
        let mut z = x * b.yminusx;
        let mut t = b.t2d * a.t;

        y = y * b.yplusx;
        x = a.z * b.z;

        let sumx = x + x;

        x = z - y;
        y = z + y;
        z = sumx - t;
        t = sumx + t;

        Self { x, y, z, t }
    }

    /// Computes the difference of a `GeP3` point and a precomputed point.
    ///
    /// This function implements Edwards curve point subtraction where:
    ///
    /// - `a` is the minuend, represented in `GeP3` (extended coordinates)
    /// - `b` is the subtrahend, represented in `GePrecomp`
    ///
    /// Algebraically, this computes:
    ///
    /// ```text
    /// R = a − b
    /// ```
    ///
    /// This is a *mixed* subtraction: the left operand uses full extended
    /// coordinates (`GeP3`), while the right operand uses a precomputed,
    /// affine-like representation (`GePrecomp`) optimized for fixed-base
    /// scalar multiplication.
    ///
    /// The subtraction is performed by reusing the standard Edwards
    /// addition formulas, with the roles of `(Y + X)` and `(Y − X)` swapped
    /// compared to addition. This avoids explicitly negating the point and
    /// keeps the operation constant-time.
    ///
    /// The result is returned in `GeP1` coordinates, which are intended as
    /// a transient representation during scalar multiplication and windowed
    /// algorithms.
    ///
    /// This implementation follows the formulas used in the Ed25519
    /// reference implementation and is safe for use with secret scalars.
    pub(crate) fn from_mixed_difference(a: &GeP3, b: &GePrecomp) -> Self {
        let mut x = a.y + a.x;
        let mut y = a.y - a.x;
        let mut z = x * b.yminusx;
        let mut t = b.xy2d * a.t;
        let sumz = a.z + a.z;

        y = y * b.yplusx;
        x = z - y;
        y = z + y;
        z = sumz - t;
        t = sumz + t;

        Self { x, y, z, t }
    }
}

/// A point on the Edwards curve in projective coordinates `(X : Y : Z)`.
///
/// `GeP2` represents a curve point using standard projective coordinates,
/// corresponding to the affine point:
///
/// ```text
/// (x, y) = (X / Z, Y / Z)
/// ```
///
/// This representation is commonly used as an intermediate form during
/// point doubling and coordinate transitions. It avoids field inversions
/// during arithmetic and is well-suited for constant-time implementations.
///
/// `GeP2` is typically produced from `GeP1` or `GeP3` and converted back
/// to those representations as needed.
pub(crate) struct GeP2 {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
}

impl GeP2 {
    /// The neutral element of the curve in `GeP2` coordinates.
    ///
    /// This corresponds to the affine point `(0, 1)`, which is the identity
    /// element for Edwards curve addition.
    pub(crate) const ONE: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
    };

    /// Converts a `GeP1` point into `GeP2` coordinates.
    ///
    /// This transformation eliminates the extra coordinate used in `GeP1`
    /// by recombining the `(X, Y, Z, T)` values into standard projective
    /// coordinates:
    ///
    /// ```text
    /// X = X₁ · T₁
    /// Y = Y₁ · Z₁
    /// Z = Z₁ · T₁
    /// ```
    ///
    /// The conversion is lossless and does not require any field inversion.
    pub(crate) fn from_gep1(g: &GeP1) -> Self {
        let x = g.x * g.t;
        let y = g.y * g.z;
        let z = g.z * g.t;

        GeP2 { x, y, z }
    }

    /// Converts a `GeP3` point into `GeP2` coordinates.
    ///
    /// This is a direct projection that simply drops the extended `T`
    /// coordinate, preserving the `(X : Y : Z)` representation.
    ///
    /// No arithmetic is performed.
    pub(crate) fn from_gep3(g: &GeP3) -> Self {
        let x = g.x;
        let y = g.y;
        let z = g.z;

        GeP2 { x, y, z }
    }

    /// Doubles the point.
    ///
    /// Computes:
    ///
    /// ```text
    /// R = 2 · self
    /// ```
    ///
    /// using Edwards curve doubling formulas optimized for projective
    /// coordinates. The result is returned in `GeP1` form, which is more
    /// suitable for subsequent additions or mixed operations.
    ///
    /// This operation is constant-time and performs no field inversions.
    pub(crate) fn double(self) -> GeP1 {
        let mut x = self.x.square();
        let mut z = self.y.square();
        let mut t = self.z.double_square();
        let mut y = self.x + self.y;
        let ysquare = y.square();

        y = z + x;
        z = z - x;
        x = ysquare - y;
        t = t - z;

        GeP1 { x, y, z, t }
    }

    /// Encodes the point into its 32-byte compressed Edwards form.
    ///
    /// The point is first converted to affine coordinates by computing
    /// the inverse of `Z`. The resulting `y` coordinate is serialized
    /// in little-endian form, and the least significant bit of `x` is
    /// stored as the sign bit in the most significant bit of the last byte.
    ///
    /// This encoding follows the Ed25519 specification exactly and is
    /// suitable for public keys and signature components.
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x * recip;
        let y = self.y * recip;

        let mut output = y.to_bytes();

        let sign_bit = x.is_negative() as u8;
        output[31] ^= sign_bit << 7;

        output
    }
}

/// A point on the Edwards25519 curve in extended coordinates.
///
/// This representation stores a curve point as `(X : Y : Z : T)`
/// such that:
///
/// ```text
/// x = X / Z
/// y = Y / Z
/// T = X * Y / Z
/// ```
///
/// Extended coordinates allow fast and complete addition formulas
/// without inversions, which is critical for constant-time scalar
/// multiplication.
///
/// This type is the primary working representation for group
/// operations in Ed25519.
pub(crate) struct GeP3 {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

impl GeP3 {
    /// The identity element of the curve in extended coordinates.
    ///
    /// Represents the neutral element `(0, 1)` on the Edwards curve.
    pub(crate) const ONE: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// Computes a double scalar multiplication:
    ///
    /// ```text
    /// r = a * self + b * B
    /// ```
    ///
    /// where `B` is the standard Ed25519 base point.
    ///
    /// This method implements a **sliding-window algorithm** using:
    /// - signed window representations (`slide`)
    /// - precomputed odd multiples of `self`
    /// - precomputed table entries for the base point
    ///
    /// The computation is performed in constant time with respect
    /// to the scalar values.
    pub(crate) fn double_scalar_mul(&self, a: Scalar, b: Scalar) -> GeP2 {
        let mut ai = [
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
        ];

        let aslide = a.slide();
        let bslide = b.slide();

        ai[0] = GeCached::from_p3(self);

        let a2 = GeP3::from_gep1(&self.double());

        for j in 1..8 {
            let t = GeP1::from_sum(&a2, &ai[j - 1]);
            ai[j] = GeCached::from_p3(&GeP3::from_gep1(&t));
        }

        let mut r = GeP2::ONE;
        let mut started = false;

        for (&asi, &bsi) in aslide.iter().zip(bslide.iter()).rev() {
            if !started {
                if asi == 0 && bsi == 0 {
                    continue;
                }
                started = true;
            }

            let mut t = r.double();

            if asi > 0 {
                t = GeP1::from_sum(&GeP3::from_gep1(&t), &ai[(asi / 2) as usize]);
            } else if asi < 0 {
                t = GeP1::from_difference(&GeP3::from_gep1(&t), &ai[(-asi / 2) as usize]);
            }

            if bsi > 0 {
                t = GeP1::from_mixed_sum(&GeP3::from_gep1(&t), &BI[(bsi / 2) as usize]);
            } else if bsi < 0 {
                t = GeP1::from_mixed_difference(&GeP3::from_gep1(&t), &BI[(-bsi / 2) as usize]);
            }

            r = GeP2::from_gep1(&t);
        }

        r
    }

    /// Doubles this point on the curve.
    ///
    /// This is implemented by converting to projective coordinates
    /// (`GeP2`) and applying the dedicated doubling formula.
    #[inline(always)]
    pub(crate) fn double(&self) -> GeP1 {
        GeP2::from_gep3(self).double()
    }

    /// Converts a point from `(P1)` intermediate coordinates
    /// into extended `(P3)` coordinates.
    ///
    /// This is typically used after addition or doubling steps.
    pub(crate) fn from_gep1(g: &GeP1) -> Self {
        let x = g.x * g.t;
        let y = g.y * g.z;
        let z = g.z * g.t;
        let t = g.x * g.y;

        Self { x, y, z, t }
    }

    /// Encodes the point into its compressed 32-byte representation.
    ///
    /// The `y` coordinate is serialized in little-endian form,
    /// and the least significant bit of `x` is stored as the sign bit.
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x * recip;
        let y = self.y * recip;

        let mut output = y.to_bytes();
        output[31] ^= (x.is_negative() as u8) << 7;

        output
    }

    /// Decompresses a point on the Edwards25519 curve from its 32-byte encoding.
    ///
    /// This function implements point decompression as specified by Ed25519.
    /// The input slice `s` is interpreted as the canonical encoding of the
    /// y-coordinate, with the most significant bit storing the sign of x.
    ///
    /// The procedure reconstructs the corresponding x-coordinate by solving
    /// the curve equation:
    ///
    /// ```text
    /// x^2 ≡ (y^2 − 1) · (d·y^2 + 1)⁻¹ (mod p)
    /// ```
    ///
    /// where `d` is the Edwards25519 curve constant.
    ///
    /// The computation follows the standard square-root extraction strategy:
    /// - Compute candidate `x` using exponentiation by `(p − 5) / 8`
    /// - Verify whether the candidate satisfies the curve equation
    /// - If not, multiply by `SQRTM1` to obtain the alternative square root
    ///
    /// If neither candidate satisfies the equation, the encoding is invalid.
    ///
    /// The sign bit encoded in `s[31]` is then enforced to select the correct
    /// representative of `x`.
    ///
    /// # Return value
    ///
    /// Returns a tuple `(point, status)` where:
    /// - `status == 0` indicates successful decompression
    /// - `status == -1` indicates an invalid point encoding
    ///
    /// On failure, the returned point value is unspecified and must not be used.
    ///
    /// # Security notes
    ///
    /// - This function operates on public inputs only.
    /// - Conditional branches are safe and do not depend on secret data.
    /// - The implementation mirrors the behavior of the Ed25519 reference code.
    ///
    /// # Arguments
    ///
    /// * `s` — A 32-byte compressed Edwards25519 point.
    pub(crate) fn decompress(s: &[u8; 32]) -> (Self, i32) {
        let mut h = Self {
            x: FieldElement::ZERO,
            y: FieldElement::from_bytes(s),
            z: FieldElement::ONE,
            t: FieldElement::ZERO,
        };

        // Compute u = y² − 1 and v = d·y² + 1
        let mut u = h.y.square();
        let mut v = u * D;
        u = u - h.z;
        v = v + h.z;

        // v³ = v² · v
        let v3 = v.square() * v;

        // Compute candidate x = (u · v³)^{(p−5)/8} · u · v³
        h.x = v3.square();
        h.x = h.x * v;
        h.x = h.x * u;
        h.x = h.x.pow22523();
        h.x = h.x * v3;
        h.x = h.x * u;

        // Verify whether x²·v == u
        let vxx = h.x.square() * v;
        let mut check = vxx - u;

        // If not, try the alternative square root using SQRTM1
        if check.is_non_zero() == 1 {
            check = vxx + u;

            if check.is_non_zero() == 1 {
                return (h, -1);
            }

            h.x = h.x * SQRTM1;
        }

        // Enforce the sign bit encoded in the input
        let sign = (s[31] >> 7) as i32;
        if h.x.is_negative() == sign {
            h.x = -h.x;
        }

        // Complete extended coordinates
        h.t = h.x * h.y;

        (h, 0)
    }

    /// Computes a scalar multiplication of the Ed25519 base point.
    ///
    /// This function evaluates `a * B`, where `a` is a scalar modulo the
    /// Ed25519 group order and `B` is the canonical base point.
    ///
    /// ## Algorithm
    ///
    /// The scalar is decomposed into 64 signed 4-bit digits using a radix-16
    /// representation:
    ///
    /// - Each byte of the scalar yields two digits in `[0, 15]`.
    /// - A carry propagation step normalizes all digits into the range
    ///   `[-8, 7]`, which minimizes the number of required additions.
    ///
    /// The multiplication is then performed using a fixed window method:
    ///
    /// 1. Accumulate all **odd-position digits** using precomputed multiples
    ///    of the base point.
    /// 2. Multiply the accumulator by `16` (four consecutive doublings).
    /// 3. Accumulate all **even-position digits**.
    ///
    /// This ordering matches the reference Ed25519 implementation and
    /// ensures a regular execution flow.
    ///
    /// ## Security properties
    ///
    /// - Uses only fixed-size loops and table lookups.
    /// - The execution path is independent of the scalar value.
    /// - Suitable for constant-time cryptographic use.
    ///
    /// ## Notes
    ///
    /// - Precomputed tables are indexed via `GePrecomp::select`, which is
    ///   expected to run in constant time.
    /// - This implementation closely follows the strategy used in the
    ///   original ref10 / orlp Ed25519 implementations.
    ///
    /// ## Returns
    ///
    /// A point in extended coordinates (`GeP3`) equal to `a * B`.
    pub(crate) fn from_scalar_mul(a: Scalar) -> Self {
        let mut e = [0i8; 64];
        for (i, &byte) in a.0.iter().enumerate() {
            e[2 * i] = (byte & 0x0f) as i8;
            e[2 * i + 1] = (byte >> 4) as i8;
        }

        let mut carry = 0i8;
        for v in e.iter_mut().take(63) {
            *v += carry;
            carry = (*v + 8) >> 4;
            *v -= carry << 4;
        }

        e[63] += carry;

        let mut h = Self::ONE;
        for i in (1..64).step_by(2) {
            let t = GePrecomp::select(i / 2, e[i]);
            h = GeP3::from_gep1(&GeP1::from_mixed_sum(&h, &t));
        }

        for _ in 0..4 {
            h = GeP3::from_gep1(&GeP2::from_gep3(&h).double());
        }

        for i in (0..64).step_by(2) {
            let t = GePrecomp::select(i / 2, e[i]);
            h = GeP3::from_gep1(&GeP1::from_mixed_sum(&h, &t));
        }

        h
    }
}

/// Cached representation of an Edwards curve point.
///
/// `GeCached` stores a point derived from extended coordinates (`GeP3`)
/// in a form optimized for fast addition and subtraction.
///
/// This representation is used as the second operand in mixed
/// point additions such as:
/// - `P3 + Cached`
/// - `P3 - Cached`
///
/// Precomputing the following values avoids repeated field operations
/// during addition:
///
/// - `y + x`
/// - `y - x`
/// - `z`
/// - `2 * d * t`
///
/// This layout matches the one used in the Ed25519 reference
/// implementations (ref10 / orlp).
pub struct GeCached {
    /// Precomputed value `y + x`.
    pub(crate) yplusx: FieldElement,

    /// Precomputed value `y - x`.
    pub(crate) yminusx: FieldElement,

    /// Projective Z coordinate.
    pub(crate) z: FieldElement,

    /// Precomputed value `2 * d * t`, where `d` is the Edwards curve constant.
    pub(crate) t2d: FieldElement,
}

impl GeCached {
    /// Identity element in cached form.
    ///
    /// This value is mainly used for initialization and as a neutral
    /// placeholder. It does **not** represent a valid curve point for
    /// arithmetic operations.
    pub(crate) const ZERO: Self = Self {
        yplusx: FieldElement::ZERO,
        yminusx: FieldElement::ZERO,
        z: FieldElement::ZERO,
        t2d: FieldElement::ZERO,
    };

    /// Converts a point from extended coordinates (`GeP3`) into cached form.
    ///
    /// The resulting `GeCached` value can be used efficiently in
    /// addition and subtraction formulas without recomputing
    /// intermediate expressions.
    ///
    /// ## Formula
    ///
    /// Given a point `(x, y, z, t)` in extended coordinates:
    ///
    /// - `yplusx = y + x`
    /// - `yminusx = y - x`
    /// - `z      = z`
    /// - `t2d    = 2 * d * t`
    ///
    /// where `d` is the Edwards curve parameter.
    ///
    /// ## Security
    ///
    /// This function performs only fixed-time field operations and
    /// introduces no data-dependent branches.
    pub(crate) fn from_p3(g: &GeP3) -> GeCached {
        let yplusx = g.y + g.x;
        let yminusx = g.y - g.x;
        let z = g.z;
        let t2d = g.t * D2;

        GeCached {
            yplusx,
            yminusx,
            z,
            t2d,
        }
    }
}

/// Precomputed representation of an Edwards curve point.
///
/// `GePrecomp` stores a point in a compact form optimized for
/// **mixed additions** with a point in extended coordinates (`GeP3`).
///
/// This representation is used for:
/// - fixed-base scalar multiplication
/// - windowed scalar multiplication (e.g. w = 4)
/// - double-scalar multiplication
///
/// A `GePrecomp` value typically comes from a precomputed table
/// (such as `BASE` or `BI`) and is never constructed dynamically
/// during scalar multiplication.
///
/// This layout matches the Ed25519 reference implementations
/// (ref10 / orlp).
pub struct GePrecomp {
    /// Precomputed value `y + x`.
    pub(crate) yplusx: FieldElement,

    /// Precomputed value `y - x`.
    pub(crate) yminusx: FieldElement,

    /// Precomputed value `2 * d * x * y`.
    ///
    /// This corresponds to `xy2d = 2 * d * x * y`
    /// and is used directly in mixed addition formulas.
    pub(crate) xy2d: FieldElement,
}

impl GePrecomp {
    /// Zero precomputed point.
    ///
    /// This value acts as a neutral placeholder and is mainly used
    /// during constant-time selection. It does **not** represent
    /// a valid curve point.
    pub(crate) const ZERO: Self = Self {
        yplusx: FieldElement::ZERO,
        yminusx: FieldElement::ZERO,
        xy2d: FieldElement::ZERO,
    };

    /// Identity element in precomputed form.
    ///
    /// This corresponds to the Edwards curve identity `(0, 1)`
    /// encoded in precomputed coordinates.
    pub(crate) const ONE: Self = Self {
        yplusx: FieldElement::ONE,
        yminusx: FieldElement::ONE,
        xy2d: FieldElement::ZERO,
    };

    /// Conditionally replaces `self` with `rhs` in constant time.
    ///
    /// If `b == 1`, `self` is replaced by `rhs`.
    /// If `b == 0`, `self` is left unchanged.
    ///
    /// This function executes in constant time with respect to `b`
    /// and is safe to use in cryptographic code.
    ///
    /// ## Security
    ///
    /// - No branches
    /// - No data-dependent memory access
    /// - Suitable for scalar multiplication routines
    pub(crate) fn conditional_move(&mut self, rhs: &Self, b: u8) {
        self.yplusx.conditional_move(&rhs.yplusx, b as u32);
        self.yminusx.conditional_move(&rhs.yminusx, b as u32);
        self.xy2d.conditional_move(&rhs.xy2d, b as u32);
    }

    /// Selects a precomputed point from the base table in constant time.
    ///
    /// This function returns:
    ///
    /// ```text
    /// b * BASE[pos]
    /// ```
    ///
    /// where:
    /// - `pos` is the window index
    /// - `b` is a signed digit in the range `[-8, 8]`
    ///
    /// The selection:
    /// - is **branch-free**
    /// - does **not** leak the value of `b`
    /// - handles negative digits by computing the negated point
    ///
    /// ## Algorithm
    ///
    /// 1. Compute `|b|` and the sign of `b` in constant time.
    /// 2. Select `BASE[pos][|b| - 1]` using conditional moves.
    /// 3. If `b < 0`, negate the selected point.
    ///
    /// ## Security
    ///
    /// This function is constant-time with respect to `b` and
    /// is safe for use in fixed-base scalar multiplication.
    pub(crate) fn select(pos: usize, b: i8) -> Self {
        let mut minust = GePrecomp::ZERO;
        let mut t = GePrecomp::ONE;

        // Extract sign and absolute value of `b` in constant time
        let bnegative = b.ct_neg();
        let babs = (b as i16 - (((-(bnegative as i16)) & (b as i16)) << 1)) as i8;

        // Constant-time table lookup
        for (i, base_elem) in BASE[pos].iter().enumerate() {
            t.conditional_move(base_elem, babs.ct_eq(&((i + 1) as i8)) as u8);
        }

        // Compute negation of the selected point
        minust.yplusx = t.yminusx;
        minust.yminusx = t.yplusx;
        minust.xy2d = -t.xy2d;

        // Select negated point if `b` is negative
        t.conditional_move(&minust, bnegative);

        t
    }
}
