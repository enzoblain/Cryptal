use crate::hash::sha512;

use super::{
    ge::{GeP2, GeP3, ge_double_scalarmult_vartime, ge_frombytes_negate_vartime, ge_tobytes},
    sc::sc_reduce,
};

#[inline(never)]
pub fn consttime_equal(x: &[u8; 32], y: &[u8; 32]) -> bool {
    let mut r: u8 = 0;
    for i in 0..32 {
        r |= x[i] ^ y[i];
    }
    r == 0
}

pub fn ed25519_verify(signature: &[u8; 64], message: &[u8], public_key: &[u8; 32]) -> bool {
    let mut h = [0u8; 64];
    let mut checker = [0u8; 32];

    let mut a = GeP3::default();
    let mut r = GeP2::default();

    if (signature[63] & 224) != 0 {
        return false;
    }

    if ge_frombytes_negate_vartime(&mut a, public_key) != 0 {
        return false;
    }

    let mut buf = Vec::with_capacity(32 + 32 + message.len());
    buf.extend_from_slice(&signature[..32]);
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(message);

    let digest = sha512(&buf);
    h.copy_from_slice(digest.as_ref());

    sc_reduce(&mut h);

    let h_red: &[u8; 32] = (&h[..32]).try_into().unwrap();
    let s: &[u8; 32] = (&signature[32..64]).try_into().unwrap();

    ge_double_scalarmult_vartime(&mut r, h_red, &a, s);
    ge_tobytes(&mut checker, &r);

    consttime_equal(&checker, (&signature[..32]).try_into().unwrap())
}
