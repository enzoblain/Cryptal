use crate::{
    hash::sha512,
    rng::Csprng,
    signatures::ed25519::{
        consttime::equal_u8_32,
        field::FieldElement,
        group::{GeCached, GeP1, GeP3},
    },
};

pub use super::scalar::Scalar;

#[derive(Clone, Copy)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy)]
pub struct PrivateKey {
    scalar: Scalar,
    prefix: [u8; 32],
}

impl PrivateKey {
    pub(crate) fn scalar(self) -> Scalar {
        self.scalar
    }

    pub fn prefix(&self) -> [u8; 32] {
        self.prefix
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];

        out[..32].copy_from_slice(&self.scalar().to_bytes());
        out[32..].copy_from_slice(&self.prefix());

        out
    }
}

#[derive(Clone, Copy)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

pub fn generate_keypair() -> (PublicKey, PrivateKey) {
    let mut rng = Csprng::new();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let digest = sha512(&seed).to_bytes();

    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&digest[..32]);
    a_bytes[0] &= 248;
    a_bytes[31] &= 63;
    a_bytes[31] |= 64;
    let a = Scalar::from_bytes(&a_bytes);

    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&digest[32..64]);

    let public = PublicKey(GeP3::from_scalar_mul(a).to_bytes());

    let private = PrivateKey { scalar: a, prefix };

    (public, private)
}

pub fn sign(message: &[u8], public: PublicKey, private: PrivateKey) -> Signature {
    let a = private.scalar();
    let prefix = private.prefix();

    let mut r_digest_input = Vec::with_capacity(32 + message.len());
    r_digest_input.extend_from_slice(&prefix);
    r_digest_input.extend_from_slice(message);
    let r_digest = sha512(&r_digest_input);

    let r = Scalar::reduce(*r_digest.as_ref());

    let r_point = GeP3::from_scalar_mul(r);
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_point.to_bytes());

    let mut k_digest_input = Vec::with_capacity(32 + 32 + message.len());
    k_digest_input.extend_from_slice(&signature[..32]);
    k_digest_input.extend_from_slice(&public.to_bytes());
    k_digest_input.extend_from_slice(message);
    let k_digest = sha512(&k_digest_input);

    let k = Scalar::reduce(*k_digest.as_ref());
    let sig_s: &mut [u8; 32] = (&mut signature[32..64]).try_into().unwrap();

    *sig_s = Scalar::from_mul_sum(k, a, r).0;

    Signature(signature)
}

pub fn verify(signature: Signature, message: &[u8], public: PublicKey) -> bool {
    if (signature.0[63] & 224) != 0 {
        return false;
    }

    let (a, res) = GeP3::decompress(&public.to_bytes());
    if res != 0 {
        return false;
    }

    let mut buf = Vec::with_capacity(32 + 32 + message.len());
    buf.extend_from_slice(&signature.0[..32]);
    buf.extend_from_slice(&public.to_bytes());
    buf.extend_from_slice(message);

    let digest = sha512(&buf);

    let mut h = [0u8; 64];
    h.copy_from_slice(digest.as_ref());

    let h_red = Scalar::reduce(h);
    let s = Scalar((signature.0[32..64]).try_into().unwrap());

    let r = a.double_scalar_mul(h_red, s);
    let checker = r.to_bytes();

    equal_u8_32(&checker, (&signature.0[..32]).try_into().unwrap())
}

pub fn add_scalar(
    public_key: Option<&mut PublicKey>,
    private_key: Option<&mut PrivateKey>,
    scalar: Scalar,
) {
    let mut sc_1 = [0u8; 32];
    sc_1[0] = 1;

    let scalar_bytes = scalar.to_bytes();

    let mut n = [0u8; 32];
    n[..31].copy_from_slice(&scalar_bytes[..31]);
    n[31] = scalar_bytes[31] & 127;

    match (private_key, public_key) {
        (Some(private), Some(public)) => {
            // ---- private scalar ----
            let p1 = Scalar::from_mul_sum(Scalar(sc_1), Scalar(n), private.scalar);
            private.scalar = p1;

            // ---- prefix ----
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&private.prefix);
            buf[32..].copy_from_slice(&scalar_bytes);

            let hashbuf = sha512(&buf);
            private.prefix.copy_from_slice(&hashbuf.as_ref()[..32]);

            // ---- public ----
            *public = PublicKey(GeP3::from_scalar_mul(private.scalar).to_bytes());
        }

        (Some(private), None) => {
            let p1 = Scalar::from_mul_sum(Scalar(sc_1), Scalar(n), private.scalar);
            private.scalar = p1;

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&private.prefix);
            buf[32..].copy_from_slice(&scalar_bytes);

            let hashbuf = sha512(&buf);
            private.prefix.copy_from_slice(&hashbuf.as_ref()[..32]);
        }

        (None, Some(public)) => {
            let (mut p3, _) = GeP3::decompress(&public.to_bytes());

            p3.x = -p3.x;
            p3.t = -p3.t;

            let t = GeCached::from_p3(&p3);
            let nb = GeP3::from_scalar_mul(Scalar(n));
            let r = GeP1::from_sum(&nb, &t);

            *public = PublicKey(GeP3::from_gep1(&r).to_bytes());
        }

        (None, None) => {}
    }
}

pub fn exchange(private: &PrivateKey, public: &PublicKey) -> [u8; 32] {
    let mut e = [0u8; 32];
    e.copy_from_slice(&private.scalar().to_bytes());

    e[0] &= 248;
    e[31] &= 63;
    e[31] |= 64;

    let mut x1;
    let mut x2;
    let mut z2;
    let mut x3;
    let mut z3;
    let mut tmp0;
    let mut tmp1;

    x1 = FieldElement::from_bytes(&public.to_bytes());

    tmp1 = FieldElement::ONE;
    tmp0 = x1 + tmp1;
    tmp1 = tmp1 - x1;
    tmp1 = tmp1.invert();
    x1 = tmp0 * tmp1;

    x2 = FieldElement::ONE;
    z2 = FieldElement::ZERO;
    x3 = x1;
    z3 = FieldElement::ONE;

    let mut swap: u32 = 0;

    for pos in (0..=254).rev() {
        let b = (e[pos / 8] >> (pos & 7)) & 1;
        let b_u32 = b as u32;

        swap ^= b_u32;
        x2.swap(&mut x3, swap);
        z2.swap(&mut z3, swap);
        swap = b_u32;

        tmp0 = x3 - z3;
        tmp1 = x2 - z2;
        x2 = x2 + z2;
        z2 = x3 + z3;
        z3 = tmp0 * x2;
        z2 = z2 * tmp1;
        tmp0 = tmp1.sq();
        tmp1 = x2.sq();
        x3 = z3 + z2;
        z2 = z3 - z2;
        x2 = tmp1 * tmp0;
        tmp1 = tmp1 - tmp0;
        z2 = z2.sq();
        z3 = tmp1.mul121666();
        x3 = x3.sq();
        tmp0 = tmp0 + z3;
        z3 = x1 * z2;
        z2 = tmp1 * tmp0;
    }

    x2.swap(&mut x3, swap);
    z2.swap(&mut z3, swap);

    z2 = z2.invert();
    x2 = x2 * z2;

    x2.to_bytes()
}
