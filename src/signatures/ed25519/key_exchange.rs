use super::fe::{
    FE, fe_0, fe_1, fe_add, fe_copy, fe_cswap, fe_frombytes, fe_invert, fe_mul, fe_mul121666,
    fe_sq, fe_sub, fe_tobytes,
};

pub fn ed25519_key_exchange(
    shared_secret: &mut [u8; 32],
    public_key: &[u8; 32],
    private_key: &[u8; 32],
) {
    let mut e = [0u8; 32];
    e.copy_from_slice(private_key);

    e[0] &= 248;
    e[31] &= 63;
    e[31] |= 64;

    let mut x1: FE = [0i32; 10];
    let mut x2: FE = [0i32; 10];
    let mut z2: FE = [0i32; 10];
    let mut x3: FE = [0i32; 10];
    let mut z3: FE = [0i32; 10];
    let mut tmp0: FE = [0i32; 10];
    let mut tmp1: FE = [0i32; 10];

    // unpack + edwards->montgomery
    fe_frombytes(&mut x1, public_key);
    fe_1(&mut tmp1);
    fe_add(&mut tmp0, &x1, &tmp1);
    {
        let t = tmp1; // tmp1 (courant)
        fe_sub(&mut tmp1, &t, &x1);
    }
    {
        let t = tmp1;
        fe_invert(&mut tmp1, &t);
    }
    {
        let t0 = tmp0;
        let t1 = tmp1;
        fe_mul(&mut x1, &t0, &t1);
    }

    fe_1(&mut x2);
    fe_0(&mut z2);
    fe_copy(&mut x3, &x1);
    fe_1(&mut z3);

    let mut swap: u32 = 0;

    for pos in (0..=254).rev() {
        let b = (e[pos / 8] >> (pos & 7)) & 1;
        let b_u32 = b as u32;

        swap ^= b_u32;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = b_u32;

        // fe_sub(tmp0, x3, z3);
        {
            let a = x3;
            let b = z3;
            fe_sub(&mut tmp0, &a, &b);
        }
        // fe_sub(tmp1, x2, z2);
        {
            let a = x2;
            let b = z2;
            fe_sub(&mut tmp1, &a, &b);
        }
        // fe_add(x2, x2, z2);
        {
            let a = x2;
            let b = z2;
            fe_add(&mut x2, &a, &b);
        }
        // fe_add(z2, x3, z3);
        {
            let a = x3;
            let b = z3;
            fe_add(&mut z2, &a, &b);
        }
        // fe_mul(z3, tmp0, x2);
        {
            let a = tmp0;
            let b = x2;
            fe_mul(&mut z3, &a, &b);
        }
        // fe_mul(z2, z2, tmp1);
        {
            let a = z2;
            let b = tmp1;
            fe_mul(&mut z2, &a, &b);
        }
        // fe_sq(tmp0, tmp1);
        {
            let a = tmp1;
            fe_sq(&mut tmp0, &a);
        }
        // fe_sq(tmp1, x2);
        {
            let a = x2;
            fe_sq(&mut tmp1, &a);
        }
        // fe_add(x3, z3, z2);
        {
            let a = z3;
            let b = z2;
            fe_add(&mut x3, &a, &b);
        }
        // fe_sub(z2, z3, z2);
        {
            let a = z3;
            let b = z2;
            fe_sub(&mut z2, &a, &b);
        }
        // fe_mul(x2, tmp1, tmp0);
        {
            let a = tmp1;
            let b = tmp0;
            fe_mul(&mut x2, &a, &b);
        }
        // fe_sub(tmp1, tmp1, tmp0);
        {
            let a = tmp1;
            let b = tmp0;
            fe_sub(&mut tmp1, &a, &b);
        }
        // fe_sq(z2, z2);
        {
            let a = z2;
            fe_sq(&mut z2, &a);
        }
        // fe_mul121666(z3, tmp1);
        {
            let a = tmp1;
            fe_copy(&mut z3, &a);
            let z33 = z3;
            fe_mul121666(&mut z3, &z33);
        }
        // fe_sq(x3, x3);
        {
            let a = x3;
            fe_sq(&mut x3, &a);
        }
        // fe_add(tmp0, tmp0, z3);
        {
            let a = tmp0;
            let b = z3;
            fe_add(&mut tmp0, &a, &b);
        }
        // fe_mul(z3, x1, z2);
        {
            let a = x1;
            let b = z2;
            fe_mul(&mut z3, &a, &b);
        }
        // fe_mul(z2, tmp1, tmp0);
        {
            let a = tmp1;
            let b = tmp0;
            fe_mul(&mut z2, &a, &b);
        }
    }

    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    {
        let a = z2;
        fe_invert(&mut z2, &a);
    }
    {
        let a = x2;
        let b = z2;
        fe_mul(&mut x2, &a, &b);
    }

    fe_tobytes(shared_secret, &x2);
}
