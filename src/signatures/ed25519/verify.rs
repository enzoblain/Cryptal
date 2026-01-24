use crate::{hash::sha512, signatures::ed25519::scalar::Scalar};

use super::group::GeP3;

#[inline(never)]
pub fn consttime_equal(x: &[u8; 32], y: &[u8; 32]) -> bool {
    let mut r: u8 = 0;
    for i in 0..32 {
        r |= x[i] ^ y[i];
    }
    r == 0
}

pub fn ed25519_verify(signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
    if (signature[63] & 224) != 0 {
        return false;
    }

    let (a, res) = GeP3::decompress(public_key);
    if res != 0 {
        return false;
    }

    let mut buf = Vec::with_capacity(32 + 32 + message.len());
    buf.extend_from_slice(&signature[..32]);
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(message);

    let digest = sha512(&buf);

    let mut h = [0u8; 64];
    h.copy_from_slice(digest.as_ref());

    let h_red = Scalar::reduce(h);
    let s = Scalar((signature[32..64]).try_into().unwrap());

    let r = a.double_scalar_mul(h_red, s);
    let checker = r.to_bytes();

    consttime_equal(&checker, (&signature[..32]).try_into().unwrap())
}
