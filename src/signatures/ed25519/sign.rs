use crate::hash::sha512;

use super::{group::GeP3, scalar::Scalar};

pub fn ed25519_sign(
    signature: &mut [u8; 64],
    message: &[u8],
    public_key: &[u8; 32],
    private_key: &[u8; 64],
) {
    let a: &[u8; 32] = (&private_key[..32]).try_into().unwrap();
    let prefix: &[u8; 32] = (&private_key[32..64]).try_into().unwrap();

    let mut r_digest_input = Vec::with_capacity(32 + message.len());
    r_digest_input.extend_from_slice(prefix);
    r_digest_input.extend_from_slice(message);
    let r_digest = sha512(&r_digest_input);

    let r = Scalar::reduce(*r_digest.as_ref());

    let r_point = GeP3::from_scalar_mul(r);
    signature[..32].copy_from_slice(&r_point.to_bytes());

    let mut k_digest_input = Vec::with_capacity(32 + 32 + message.len());
    k_digest_input.extend_from_slice(&signature[..32]);
    k_digest_input.extend_from_slice(public_key);
    k_digest_input.extend_from_slice(message);
    let k_digest = sha512(&k_digest_input);

    let k = Scalar::reduce(*k_digest.as_ref());
    let sig_s: &mut [u8; 32] = (&mut signature[32..64]).try_into().unwrap();

    *sig_s = Scalar::from_mul_sum(k, Scalar(*a), r).0;
}
