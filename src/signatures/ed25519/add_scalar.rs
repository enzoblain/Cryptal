use super::group::{GeCached, GeP1, GeP3};
use crate::hash::sha512;
use crate::signatures::ed25519::scalar::Scalar;

pub fn ed25519_add_scalar(
    public_key: Option<&mut [u8; 32]>,
    private_key: Option<&mut [u8; 64]>,
    scalar: &[u8; 32],
) {
    let mut sc_1 = [0u8; 32];
    sc_1[0] = 1;

    let mut n = [0u8; 32];

    n[..31].copy_from_slice(&scalar[..31]);
    n[31] = scalar[31] & 127;

    match (private_key, public_key) {
        (Some(private), Some(public)) => {
            let mut sk0 = [0u8; 32];
            sk0.copy_from_slice(&private[..32]);

            let p1 = Scalar::from_mul_sum(Scalar(sc_1), Scalar(n), Scalar(sk0));
            private[0..32].copy_from_slice(&p1.0);

            let mut new_sk = [0u8; 32];
            new_sk.copy_from_slice(&private[..32]);

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&private[32..64]);
            buf[32..].copy_from_slice(scalar);

            let hashbuf = sha512(&buf);

            let mut h0 = [0u8; 32];
            h0.copy_from_slice(&hashbuf.as_ref()[..32]);

            private[32..64].copy_from_slice(&hashbuf.as_ref()[..32]);

            *public = GeP3::from_scalar_mul(Scalar((&private[..32]).try_into().unwrap())).to_bytes()
        }

        (Some(private), None) => {
            let mut sk0 = [0u8; 32];
            sk0.copy_from_slice(&private[..32]);

            let p1 = Scalar::from_mul_sum(Scalar(sc_1), Scalar(n), Scalar(sk0));
            private[0..32].copy_from_slice(&p1.0);

            let mut new_sk = [0u8; 32];
            new_sk.copy_from_slice(&private[..32]);

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&private[32..64]);
            buf[32..].copy_from_slice(scalar);

            let hashbuf = sha512(&buf);

            let mut h0 = [0u8; 32];
            h0.copy_from_slice(&hashbuf.as_ref()[..32]);

            private[32..64].copy_from_slice(&hashbuf.as_ref()[..32]);
        }

        (None, Some(public)) => {
            let mut public_key_unpacked = GeP3::decompress(public).0;

            let pkux = public_key_unpacked.x;
            let pkut = public_key_unpacked.t;

            public_key_unpacked.x = -pkux;
            public_key_unpacked.t = -pkut;

            let t = GeCached::from_p3(&public_key_unpacked);

            let nb = GeP3::from_scalar_mul(Scalar(n));

            let a_p1p1 = GeP1::from_sum(&nb, &t);

            *public = GeP3::from_gep1(&a_p1p1).to_bytes()
        }

        (None, None) => {}
    }
}
