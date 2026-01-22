use crate::hash::sha512;

use super::{
    ge::{GeP3, ge_p3_tobytes, ge_scalarmult_base},
    sc::{sc_muladd, sc_reduce},
};

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
    let mut r_scalar = [0u8; 64];
    r_scalar.copy_from_slice(r_digest.as_ref());
    sc_reduce(&mut r_scalar);

    let mut r_point = GeP3::default();
    let r_red: &[u8; 32] = (&r_scalar[..32]).try_into().unwrap();
    ge_scalarmult_base(&mut r_point, r_red);
    ge_p3_tobytes((&mut signature[..32]).try_into().unwrap(), &r_point);

    let mut k_digest_input = Vec::with_capacity(32 + 32 + message.len());
    k_digest_input.extend_from_slice(&signature[..32]);
    k_digest_input.extend_from_slice(public_key);
    k_digest_input.extend_from_slice(message);
    let k_digest = sha512(&k_digest_input);
    let mut k_scalar = [0u8; 64];
    k_scalar.copy_from_slice(k_digest.as_ref());
    sc_reduce(&mut k_scalar);

    let sig_s: &mut [u8; 32] = (&mut signature[32..64]).try_into().unwrap();
    let k_red: &[u8; 32] = (&k_scalar[..32]).try_into().unwrap();
    let r_red_32: &[u8; 32] = (&r_scalar[..32]).try_into().unwrap();
    sc_muladd(sig_s, k_red, a, r_red_32);
}
