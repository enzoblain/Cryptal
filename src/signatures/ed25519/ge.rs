use super::{
    fe::{
        FE, fe_0, fe_1, fe_add, fe_cmov, fe_copy, fe_frombytes, fe_invert, fe_isnegative,
        fe_isnonzero, fe_mul, fe_neg, fe_pow22523, fe_sq, fe_sq2, fe_sub, fe_tobytes,
    },
    precomp_data::{BASE, BI},
};

#[derive(Default)]
pub struct GeP2 {
    pub x: FE,
    pub y: FE,
    pub z: FE,
}

#[derive(Default)]
pub struct GeP3 {
    pub x: FE,
    pub y: FE,
    pub z: FE,
    pub t: FE,
}

#[derive(Default)]
pub struct GeP1P1 {
    pub x: FE,
    pub y: FE,
    pub z: FE,
    pub t: FE,
}

#[derive(Default, Clone, Copy)]
pub struct GeCached {
    pub yplusx: FE,
    pub yminusx: FE,
    pub z: FE,
    pub t2d: FE,
}

#[derive(Default)]
pub struct GePrecomp {
    pub yplusx: FE,
    pub yminusx: FE,
    pub xy2d: FE,
}

pub fn ge_add(r: &mut GeP1P1, p: &GeP3, q: &GeCached) {
    let mut t0: FE = [0i32; 10];

    fe_add(&mut r.x, &p.y, &p.x);
    fe_sub(&mut r.y, &p.y, &p.x);
    fe_mul(&mut r.z, &r.x, &q.yplusx);
    let y = r.y;
    fe_mul(&mut r.y, &y, &q.yminusx);
    fe_mul(&mut r.t, &q.t2d, &p.t);
    fe_mul(&mut r.x, &p.z, &q.z);
    fe_add(&mut t0, &r.x, &r.x);
    fe_sub(&mut r.x, &r.z, &r.y);
    let y = r.y;
    fe_add(&mut r.y, &r.z, &y);
    fe_add(&mut r.z, &t0, &r.t);
    let t = r.t;
    fe_sub(&mut r.t, &t0, &t);
}

pub fn slide(r: &mut [i8], a: &[u8; 32]) {
    assert_eq!(r.len(), 256);

    for i in 0..256 {
        r[i] = ((a[i >> 3] >> (i & 7)) & 1) as i8;
    }

    for i in 0..256 {
        if r[i] != 0 {
            let mut b = 1usize;
            while b <= 6 && i + b < 256 {
                if r[i + b] != 0 {
                    let rb = (r[i + b] as i32) << b;
                    let ri = r[i] as i32;

                    if ri + rb <= 15 {
                        r[i] = (ri + rb) as i8;
                        r[i + b] = 0;
                    } else if ri - rb >= -15 {
                        r[i] = (ri - rb) as i8;

                        let mut k = i + b;
                        while k < 256 {
                            if r[k] == 0 {
                                r[k] = 1;
                                break;
                            }
                            r[k] = 0;
                            k += 1;
                        }
                    } else {
                        break;
                    }
                }
                b += 1;
            }
        }
    }
}

pub fn ge_double_scalarmult_vartime(r: &mut GeP2, a: &[u8; 32], a_point: &GeP3, b: &[u8; 32]) {
    let mut aslide: [i8; 256] = [0; 256];
    let mut bslide: [i8; 256] = [0; 256];

    let mut ai: [GeCached; 8] = [GeCached {
        yplusx: [0; 10],
        yminusx: [0; 10],
        z: [0; 10],
        t2d: [0; 10],
    }; 8];

    let mut t = GeP1P1 {
        x: [0; 10],
        y: [0; 10],
        z: [0; 10],
        t: [0; 10],
    };
    let mut u = GeP3 {
        x: [0; 10],
        y: [0; 10],
        z: [0; 10],
        t: [0; 10],
    };
    let mut a2 = GeP3 {
        x: [0; 10],
        y: [0; 10],
        z: [0; 10],
        t: [0; 10],
    };

    slide(&mut aslide, a);
    slide(&mut bslide, b);

    ge_p3_to_cached(&mut ai[0], a_point);

    ge_p3_dbl(&mut t, a_point);
    ge_p1p1_to_p3(&mut a2, &t);

    // Ai[1..7]
    for j in 1..8 {
        ge_add(&mut t, &a2, &ai[j - 1]);
        ge_p1p1_to_p3(&mut u, &t);
        ge_p3_to_cached(&mut ai[j], &u);
    }

    ge_p2_0(r);

    let mut i: i32 = 255;
    while i >= 0 {
        if aslide[i as usize] != 0 || bslide[i as usize] != 0 {
            break;
        }
        i -= 1;
    }

    while i >= 0 {
        let asi = aslide[i as usize];
        let bsi = bslide[i as usize];

        ge_p2_dbl(&mut t, r);

        if asi > 0 {
            ge_p1p1_to_p3(&mut u, &t);
            let idx = (asi / 2) as usize;
            ge_add(&mut t, &u, &ai[idx]);
        } else if asi < 0 {
            ge_p1p1_to_p3(&mut u, &t);
            let idx = ((-asi) / 2) as usize;
            ge_sub(&mut t, &u, &ai[idx]);
        }

        if bsi > 0 {
            ge_p1p1_to_p3(&mut u, &t);
            let idx = (bsi / 2) as usize;
            ge_madd(&mut t, &u, &BI[idx]);
        } else if bsi < 0 {
            ge_p1p1_to_p3(&mut u, &t);
            let idx = ((-bsi) / 2) as usize;
            ge_msub(&mut t, &u, &BI[idx]);
        }

        ge_p1p1_to_p2(r, &t);
        i -= 1;
    }
}

pub const D: FE = [
    -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448,
    -12055116,
];

pub const SQRTM1: FE = [
    -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482,
];

pub fn ge_frombytes_negate_vartime(h: &mut GeP3, s: &[u8; 32]) -> i32 {
    let mut u: FE = [0; 10];
    let mut v: FE = [0; 10];
    let mut v3: FE = [0; 10];
    let mut vxx: FE = [0; 10];
    let mut check: FE = [0; 10];

    fe_frombytes(&mut h.y, s);
    fe_1(&mut h.z);
    fe_sq(&mut u, &h.y);
    fe_mul(&mut v, &u, &D);
    let uu = u;
    fe_sub(&mut u, &uu, &h.z);
    let vv = v;
    fe_add(&mut v, &vv, &h.z);
    fe_sq(&mut v3, &v);
    let v33 = v3;
    fe_mul(&mut v3, &v33, &v);
    fe_sq(&mut h.x, &v3);
    let x = h.x;
    fe_mul(&mut h.x, &x, &v);
    let x = h.x;
    fe_mul(&mut h.x, &x, &u);
    let x = h.x;
    fe_pow22523(&mut h.x, &x);
    let x = h.x;
    fe_mul(&mut h.x, &x, &v3);
    let x = h.x;
    fe_mul(&mut h.x, &x, &u);
    fe_sq(&mut vxx, &h.x);
    let vxxx = vxx;
    fe_mul(&mut vxx, &vxxx, &v);
    fe_sub(&mut check, &vxx, &u);

    if fe_isnonzero(&check) == 1 {
        fe_add(&mut check, &vxx, &u);
        if fe_isnonzero(&check) == 1 {
            return -1;
        }
        let x = h.x;
        fe_mul(&mut h.x, &x, &SQRTM1);
    }

    let sign = (s[31] >> 7) != 0;
    if fe_isnegative(&h.x) == sign as i32 {
        let hx = h.x;
        fe_neg(&mut h.x, &hx);
    }

    fe_mul(&mut h.t, &h.x, &h.y);
    0
}

pub fn ge_madd(r: &mut GeP1P1, p: &GeP3, q: &GePrecomp) {
    let mut t0: FE = [0; 10];

    fe_add(&mut r.x, &p.y, &p.x);
    fe_sub(&mut r.y, &p.y, &p.x);
    fe_mul(&mut r.z, &r.x, &q.yplusx);
    let y = r.y;
    fe_mul(&mut r.y, &y, &q.yminusx);
    fe_mul(&mut r.t, &q.xy2d, &p.t);
    fe_add(&mut t0, &p.z, &p.z);
    fe_sub(&mut r.x, &r.z, &r.y);
    let y = r.y;
    fe_add(&mut r.y, &r.z, &y);
    fe_add(&mut r.z, &t0, &r.t);
    let t = r.t;
    fe_sub(&mut r.t, &t0, &t);
}

pub fn ge_msub(r: &mut GeP1P1, p: &GeP3, q: &GePrecomp) {
    let mut t0: FE = [0; 10];

    fe_add(&mut r.x, &p.y, &p.x);
    fe_sub(&mut r.y, &p.y, &p.x);
    fe_mul(&mut r.z, &r.x, &q.yminusx);
    let y = r.y;
    fe_mul(&mut r.y, &y, &q.yplusx);
    fe_mul(&mut r.t, &q.xy2d, &p.t);
    fe_add(&mut t0, &p.z, &p.z);
    fe_sub(&mut r.x, &r.z, &r.y);
    let y = r.y;
    fe_add(&mut r.y, &r.z, &y);
    fe_sub(&mut r.z, &t0, &r.t);
    let t = r.t;
    fe_add(&mut r.t, &t0, &t);
}

pub fn ge_p1p1_to_p2(r: &mut GeP2, p: &GeP1P1) {
    fe_mul(&mut r.x, &p.x, &p.t);
    fe_mul(&mut r.y, &p.y, &p.z);
    fe_mul(&mut r.z, &p.z, &p.t);
}

pub fn ge_p1p1_to_p3(r: &mut GeP3, p: &GeP1P1) {
    fe_mul(&mut r.x, &p.x, &p.t);
    fe_mul(&mut r.y, &p.y, &p.z);
    fe_mul(&mut r.z, &p.z, &p.t);
    fe_mul(&mut r.t, &p.x, &p.y);
}

pub fn ge_p2_0(h: &mut GeP2) {
    fe_0(&mut h.x);
    fe_1(&mut h.y);
    fe_1(&mut h.z);
}

pub fn ge_p2_dbl(r: &mut GeP1P1, p: &GeP2) {
    let mut t0: FE = [0; 10];

    fe_sq(&mut r.x, &p.x);
    fe_sq(&mut r.z, &p.y);
    fe_sq2(&mut r.t, &p.z);
    fe_add(&mut r.y, &p.x, &p.y);
    fe_sq(&mut t0, &r.y);
    fe_add(&mut r.y, &r.z, &r.x);
    let z = r.z;
    fe_sub(&mut r.z, &z, &r.x);
    fe_sub(&mut r.x, &t0, &r.y);
    let t = r.t;
    fe_sub(&mut r.t, &t, &r.z);
}

pub fn ge_p3_0(h: &mut GeP3) {
    fe_0(&mut h.x);
    fe_1(&mut h.y);
    fe_1(&mut h.z);
    fe_0(&mut h.t);
}

pub fn ge_p3_dbl(r: &mut GeP1P1, p: &GeP3) {
    let mut q = GeP2 {
        x: [0; 10],
        y: [0; 10],
        z: [0; 10],
    };

    ge_p3_to_p2(&mut q, p);
    ge_p2_dbl(r, &q);
}

pub const D2: FE = [
    -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968,
    9444199,
];

pub fn ge_p3_to_cached(r: &mut GeCached, p: &GeP3) {
    fe_add(&mut r.yplusx, &p.y, &p.x);
    fe_sub(&mut r.yminusx, &p.y, &p.x);
    fe_copy(&mut r.z, &p.z);
    fe_mul(&mut r.t2d, &p.t, &D2);
}

pub fn ge_p3_to_p2(r: &mut GeP2, p: &GeP3) {
    fe_copy(&mut r.x, &p.x);
    fe_copy(&mut r.y, &p.y);
    fe_copy(&mut r.z, &p.z);
}

pub fn ge_p3_tobytes(s: &mut [u8; 32], h: &GeP3) {
    let mut recip: FE = [0; 10];
    let mut x: FE = [0; 10];
    let mut y: FE = [0; 10];

    fe_invert(&mut recip, &h.z);
    fe_mul(&mut x, &h.x, &recip);
    fe_mul(&mut y, &h.y, &recip);
    fe_tobytes(s, &y);

    let bit = if fe_isnegative(&x) == 1 { 1u8 } else { 0u8 };
    s[31] ^= bit << 7;
}

pub fn equal(b: i8, c: i8) -> u8 {
    let ub = b as u8;
    let uc = c as u8;
    let x = ub ^ uc;
    let mut y = x as u64;
    y = y.wrapping_sub(1);
    y >>= 63;
    y as u8
}

pub fn negative(b: i8) -> u8 {
    let mut x = b as i64 as u64;
    x >>= 63;
    x as u8
}

pub fn cmov(t: &mut GePrecomp, u: &GePrecomp, b: u8) {
    fe_cmov(&mut t.yplusx, &u.yplusx, b as u32);
    fe_cmov(&mut t.yminusx, &u.yminusx, b as u32);
    fe_cmov(&mut t.xy2d, &u.xy2d, b as u32);
}

pub fn select(t: &mut GePrecomp, pos: usize, b: i8) {
    let mut minust = GePrecomp {
        yplusx: [0; 10],
        yminusx: [0; 10],
        xy2d: [0; 10],
    };

    let bnegative = negative(b);
    let babs = (b as i16 - (((-(bnegative as i16)) & (b as i16)) << 1)) as i8;

    fe_1(&mut t.yplusx);
    fe_1(&mut t.yminusx);
    fe_0(&mut t.xy2d);

    cmov(t, &BASE[pos][0], equal(babs, 1));
    cmov(t, &BASE[pos][1], equal(babs, 2));
    cmov(t, &BASE[pos][2], equal(babs, 3));
    cmov(t, &BASE[pos][3], equal(babs, 4));
    cmov(t, &BASE[pos][4], equal(babs, 5));
    cmov(t, &BASE[pos][5], equal(babs, 6));
    cmov(t, &BASE[pos][6], equal(babs, 7));
    cmov(t, &BASE[pos][7], equal(babs, 8));

    fe_copy(&mut minust.yplusx, &t.yminusx);
    fe_copy(&mut minust.yminusx, &t.yplusx);
    fe_neg(&mut minust.xy2d, &t.xy2d);
    cmov(t, &minust, bnegative);
}

pub fn ge_scalarmult_base(h: &mut GeP3, a: &[u8; 32]) {
    let mut e = [0i8; 64];
    let mut r = GeP1P1 {
        x: [0; 10],
        y: [0; 10],
        z: [0; 10],
        t: [0; 10],
    };
    let mut s = GeP2 {
        x: [0; 10],
        y: [0; 10],
        z: [0; 10],
    };
    let mut t = GePrecomp {
        yplusx: [0; 10],
        yminusx: [0; 10],
        xy2d: [0; 10],
    };

    for i in 0..32 {
        e[2 * i] = (a[i] & 15) as i8;
        e[2 * i + 1] = ((a[i] >> 4) & 15) as i8;
    }

    let mut carry: i8 = 0;
    for v in e.iter_mut().take(63) {
        *v += carry;
        carry = (*v + 8) >> 4;
        *v -= carry << 4;
    }
    e[63] += carry;

    ge_p3_0(h);

    for i in (1..64).step_by(2) {
        select(&mut t, i / 2, e[i]);
        ge_madd(&mut r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }

    ge_p3_dbl(&mut r, h);
    ge_p1p1_to_p2(&mut s, &r);
    ge_p2_dbl(&mut r, &s);
    ge_p1p1_to_p2(&mut s, &r);
    ge_p2_dbl(&mut r, &s);
    ge_p1p1_to_p2(&mut s, &r);
    ge_p2_dbl(&mut r, &s);
    ge_p1p1_to_p3(h, &r);

    for i in (0..64).step_by(2) {
        select(&mut t, i / 2, e[i]);
        ge_madd(&mut r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }
}

pub fn ge_sub(r: &mut GeP1P1, p: &GeP3, q: &GeCached) {
    let mut t0: FE = [0; 10];

    fe_add(&mut r.x, &p.y, &p.x);
    fe_sub(&mut r.y, &p.y, &p.x);

    fe_mul(&mut r.z, &r.x, &q.yminusx);

    let ry = r.y;
    fe_mul(&mut r.y, &ry, &q.yplusx);

    fe_mul(&mut r.t, &q.t2d, &p.t);
    fe_mul(&mut r.x, &p.z, &q.z);

    fe_add(&mut t0, &r.x, &r.x);

    fe_sub(&mut r.x, &r.z, &r.y);
    let ry = r.y;
    fe_add(&mut r.y, &r.z, &ry);

    fe_sub(&mut r.z, &t0, &r.t);
    let rt = r.t;
    fe_add(&mut r.t, &t0, &rt);
}

pub fn ge_tobytes(s: &mut [u8; 32], h: &GeP2) {
    let mut recip: FE = [0; 10];
    let mut x: FE = [0; 10];
    let mut y: FE = [0; 10];

    fe_invert(&mut recip, &h.z);
    fe_mul(&mut x, &h.x, &recip);
    fe_mul(&mut y, &h.y, &recip);
    fe_tobytes(s, &y);

    let bit = if fe_isnegative(&x) == 1 { 1u8 } else { 0u8 };
    s[31] ^= bit << 7;
}
