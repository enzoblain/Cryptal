//! SHA-256 internal computations
//!
//! This module contains the low-level bitwise functions and the compression
//! round logic used by the SHA-256 hash function, as defined in FIPS 180-4.
//!
//! It is intentionally kept separate from the public hashing interface to:
//! - make the core algorithm easier to audit
//! - isolate performance-critical logic
//! - clearly distinguish specification-defined primitives
//!
//! All operations are implemented in constant time and use only
//! fixed-size integer arithmetic.

use crate::hash::sha256::K256;

/// SHA-256 small sigma function σ₀.
///
/// Defined as:
/// σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
#[inline(always)]
pub fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// SHA-256 small sigma function σ₁.
///
/// Defined as:
/// σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
#[inline(always)]
pub fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// SHA-256 big sigma function Σ₀.
///
/// Defined as:
/// Σ₀(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
#[inline(always)]
pub fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// SHA-256 big sigma function Σ₁.
///
/// Defined as:
/// Σ₁(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
#[inline(always)]
pub fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// SHA-256 choice function `Ch`.
///
/// Chooses bits from `f` or `g` depending on `e`.
///
/// Defined as:
/// Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)
#[inline(always)]
pub fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ ((!e) & g)
}

/// SHA-256 majority function `Maj`.
///
/// For each bit position, returns the majority value of `a`, `b`, and `c`.
///
/// Defined as:
/// Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
#[inline(always)]
pub fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// Executes all 64 rounds of the SHA-256 compression function.
///
/// This function expands the message schedule using a 16-word circular
/// buffer and updates the provided hash state in place.
///
/// # Parameters
/// - `state`: The current hash state (8 × 32-bit words)
/// - `w`: The first 16 words of the message schedule (big-endian)
///
/// # Notes
/// - The message schedule is expanded on-the-fly using modulo indexing.
/// - All arithmetic is performed modulo 2³².
/// - The function follows the exact round structure defined in FIPS 180-4.
pub fn all_rounds(state: &mut [u32; 8], mut w: [u32; 16]) {
    // Load hash state into working variables
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        if i >= 16 {
            // Expand message schedule using a 16-word circular buffer
            let w16 = w[(i - 16) & 15];
            let w15 = w[(i - 15) & 15];
            let w7 = w[(i - 7) & 15];
            let w2 = w[(i - 2) & 15];

            let s0 = small_sigma0(w15);
            let s1 = small_sigma1(w2);

            w[i & 15] = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
        }

        let wi = w[i & 15];
        let ki = K256[i];

        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(wi)
            .wrapping_add(ki);

        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // Add the compressed chunk to the current hash state
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}
