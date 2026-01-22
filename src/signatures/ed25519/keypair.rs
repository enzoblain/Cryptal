use super::ge::{GeP3, ge_p3_tobytes, ge_scalarmult_base};
use crate::hash::sha512;

pub fn ed25519_create_keypair(
    public_key: &mut [u8; 32],
    private_key: &mut [u8; 64],
    seed: &[u8; 32],
) {
    let mut a = GeP3::default();

    let digest = sha512(seed);
    private_key.copy_from_slice(digest.as_ref());
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&mut a, &private_key[..32].try_into().unwrap());
    ge_p3_tobytes(public_key, &a);
}
