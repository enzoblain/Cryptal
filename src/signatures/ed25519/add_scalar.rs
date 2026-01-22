use crate::hash::sha512;

use super::{
    fe::fe_neg,
    ge::{
        GeCached, GeP1P1, GeP3, ge_add, ge_frombytes_negate_vartime, ge_p1p1_to_p3,
        ge_p3_to_cached, ge_p3_tobytes, ge_scalarmult_base,
    },
    sc::sc_muladd,
};

fn hex32(x: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in x.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex64(x: &[u8; 64]) -> String {
    let mut s = String::with_capacity(128);
    for b in x.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn ed25519_add_scalar(
    public_key: Option<&mut [u8; 32]>,
    private_key: Option<&mut [u8; 64]>,
    scalar: &[u8; 32],
) {
    println!("=== ed25519_add_scalar: ENTER ===");
    println!("scalar (in)      = {}", hex32(scalar));

    let mut sc_1 = [0u8; 32];
    sc_1[0] = 1;
    println!("sc_1             = {}", hex32(&sc_1));

    let mut n = [0u8; 32];

    let mut nb = GeP3::default();
    let mut a_p1p1 = GeP1P1::default();
    let mut a = GeP3::default();
    let mut public_key_unpacked = GeP3::default();
    let mut t = GeCached::default();

    // clamp-like truncation used by this routine
    n[..31].copy_from_slice(&scalar[..31]);
    n[31] = scalar[31] & 127;

    println!("n (masked)       = {}", hex32(&n));
    println!(
        "match arms: private_key.is_some={} public_key.is_some={}",
        private_key.is_some(),
        public_key.is_some(),
    );

    match (private_key, public_key) {
        (Some(private), Some(public)) => {
            println!("--- ARM: (Some(private), Some(public)) ---");
            println!("private (in)     = {}", hex64(private));

            let mut sk0 = [0u8; 32];
            sk0.copy_from_slice(&private[..32]);
            println!("sk0 (old sk)     = {}", hex32(&sk0));

            println!("sc_muladd(out=sk, h=1, a=n, r=sk0) START");
            sc_muladd(&mut private[..32], &sc_1, &n, &sk0);
            println!("sc_muladd END");

            let mut new_sk = [0u8; 32];
            new_sk.copy_from_slice(&private[..32]);
            println!("sk (new)         = {}", hex32(&new_sk));

            println!("prefix priv[32..64] (before) = {}", {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(&private[32..64]);
                hex32(&tmp)
            });

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&private[32..64]);
            buf[32..].copy_from_slice(scalar);

            println!("buf = priv_suffix||scalar = {}", hex64(&buf));
            println!("sha512(buf) START");
            let hashbuf = sha512(&buf);
            println!("sha512(buf) END");

            let mut h0 = [0u8; 32];
            h0.copy_from_slice(&hashbuf.as_ref()[..32]);
            println!("hash[0..32]      = {}", hex32(&h0));

            private[32..64].copy_from_slice(&hashbuf.as_ref()[..32]);
            println!("private suffix (after)    = {}", {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(&private[32..64]);
                hex32(&tmp)
            });

            println!("ge_scalarmult_base(sk) START");
            ge_scalarmult_base(&mut a, (&private[..32]).try_into().unwrap());
            println!("ge_scalarmult_base END");

            println!("ge_p3_tobytes(pub) START");
            ge_p3_tobytes(public, &a);
            println!("ge_p3_tobytes END");

            println!("public (out)     = {}", hex32(public));
            println!("private (out)    = {}", hex64(private));
        }

        (Some(private), None) => {
            println!("--- ARM: (Some(private), None) ---");
            println!("private (in)     = {}", hex64(private));

            let mut sk0 = [0u8; 32];
            sk0.copy_from_slice(&private[..32]);
            println!("sk0 (old sk)     = {}", hex32(&sk0));

            println!("sc_muladd(out=sk, h=1, a=n, r=sk0) START");
            sc_muladd(&mut private[..32], &sc_1, &n, &sk0);
            println!("sc_muladd END");

            let mut new_sk = [0u8; 32];
            new_sk.copy_from_slice(&private[..32]);
            println!("sk (new)         = {}", hex32(&new_sk));

            println!("prefix priv[32..64] (before) = {}", {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(&private[32..64]);
                hex32(&tmp)
            });

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&private[32..64]);
            buf[32..].copy_from_slice(scalar);

            println!("buf = priv_suffix||scalar = {}", hex64(&buf));
            println!("sha512(buf) START");
            let hashbuf = sha512(&buf);
            println!("sha512(buf) END");

            let mut h0 = [0u8; 32];
            h0.copy_from_slice(&hashbuf.as_ref()[..32]);
            println!("hash[0..32]      = {}", hex32(&h0));

            private[32..64].copy_from_slice(&hashbuf.as_ref()[..32]);
            println!("private suffix (after)    = {}", {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(&private[32..64]);
                hex32(&tmp)
            });

            println!("private (out)    = {}", hex64(private));
        }

        (None, Some(public)) => {
            println!("--- ARM: (None, Some(public)) ---");
            println!("public (in)      = {}", hex32(public));

            println!("ge_frombytes_negate_vartime START");
            ge_frombytes_negate_vartime(&mut public_key_unpacked, public);
            println!("ge_frombytes_negate_vartime END");

            println!("fe_neg(x,t) START");
            let pkux = public_key_unpacked.x;
            let pkut = public_key_unpacked.t;
            fe_neg(&mut public_key_unpacked.x, &pkux);
            fe_neg(&mut public_key_unpacked.t, &pkut);
            println!("fe_neg(x,t) END");

            println!("ge_p3_to_cached START");
            ge_p3_to_cached(&mut t, &public_key_unpacked);
            println!("ge_p3_to_cached END");

            println!("ge_scalarmult_base(n) START");
            ge_scalarmult_base(&mut nb, &n);
            println!("ge_scalarmult_base(n) END");

            println!("ge_add(nb + cached(pk)) START");
            ge_add(&mut a_p1p1, &nb, &t);
            println!("ge_add END");

            println!("ge_p1p1_to_p3 START");
            ge_p1p1_to_p3(&mut a, &a_p1p1);
            println!("ge_p1p1_to_p3 END");

            println!("ge_p3_tobytes(pub) START");
            ge_p3_tobytes(public, &a);
            println!("ge_p3_tobytes END");

            println!("public (out)     = {}", hex32(public));
        }

        (None, None) => {
            println!("--- ARM: (None, None) ---");
            println!("no-op");
        }
    }

    println!("=== ed25519_add_scalar: EXIT ===");
}
