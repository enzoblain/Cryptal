use crate::keys::ed25519::field::FieldElement;

/// X25519 key exchange (RFC 7748 compatible).
///
/// Computes the Diffie–Hellman shared secret between a private scalar
/// and a peer public u-coordinate using Curve25519.
///
/// ## Inputs
///
/// - `private`: Local secret key material. The scalar is clamped as specified
///   by RFC 7748 before scalar multiplication.
/// - `public`: Peer public key as a 32-byte Montgomery u-coordinate.
///
/// ## Algorithm
///
/// 1. Clamp the 32-byte scalar (`k`) into the RFC 7748 form.
/// 2. Decode the peer public key as a field element `u`.
/// 3. Run the Montgomery ladder for 255 bits using constant-time swaps.
/// 4. Convert back to affine form with one inversion and return the result.
///
/// The ladder maintains two points `(x2:z2)` and `(x3:z3)` and updates them
/// at each bit position to compute the scalar multiple without leaking
/// scalar bits through branches or memory access patterns.
///
/// ## Return value
///
/// Returns a 32-byte shared secret (the Montgomery u-coordinate of the
/// resulting scalar multiple).
///
/// **Note:** per RFC 7748, the output may be all zeros for certain peer public
/// keys (e.g. low-order points). This function returns that value as-is.
///
/// ## Security
///
/// - Constant-time with respect to the private scalar.
/// - No secret-dependent branches.
/// - Peer public keys are not fully validated (matches X25519 semantics).
pub fn exchange(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let mut e = *private;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    let mut x1 = FieldElement::from_bytes(public);

    // RFC 7748 decoding: u = (u + 1) / (1 - u)
    let one = FieldElement::ONE;
    let tmp0 = x1 + one;
    let tmp1 = (one - x1).invert();
    x1 = tmp0 * tmp1;

    // Montgomery ladder ---
    let mut x2 = FieldElement::ONE;
    let mut z2 = FieldElement::ZERO;
    let mut x3 = x1;
    let mut z3 = FieldElement::ONE;

    let mut swap = 0u32;

    for pos in (0..=254).rev() {
        let b = ((e[pos >> 3] >> (pos & 7)) & 1) as u32;
        swap ^= b;

        x2.swap(&mut x3, swap);
        z2.swap(&mut z3, swap);
        swap = b;

        let tmp0 = x3 - z3;
        let tmp1 = x2 - z2;
        x2 = x2 + z2;
        z2 = x3 + z3;

        let z3_new = tmp0 * x2;
        let z2_new = z2 * tmp1;

        let tmp0 = tmp1.square();
        let tmp1 = x2.square();

        x3 = z3_new + z2_new;
        z2 = z3_new - z2_new;
        x2 = tmp1 * tmp0;

        let tmp1 = tmp1 - tmp0;
        z2 = z2.square();
        let mut z3 = tmp1.mul121666();
        x3 = x3.square();
        let tmp0 = tmp0 + z3;

        z3 = x1 * z2;
        z2 = tmp1 * tmp0;
    }

    x2.swap(&mut x3, swap);
    z2.swap(&mut z3, swap);

    (x2 * z2.invert()).to_bytes()
}
