use crate::hash::sha256::K256;

#[inline(always)]
pub fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
pub fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[inline(always)]
pub fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
pub fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
pub fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ ((!e) & g)
}

#[inline(always)]
pub fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

pub fn all_rounds(state: &mut [u32; 8], mut w: [u32; 16]) {
    // Load hash state into working variables
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        if i >= 16 {
            // Circular buffer indexing: access W[i-2], W[i-7], W[i-15], W[i-16] via modulo 16
            let w16 = w[(i - 16) & 15];
            let w15 = w[(i - 15) & 15];
            let w7 = w[(i - 7) & 15];
            let w2 = w[(i - 2) & 15];

            let s0 = small_sigma0(w15);
            let s1 = small_sigma1(w2);

            w[i & 15] = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
        }

        let wi = w[i & 15];
        let ki = K256[i];

        let bs1 = big_sigma1(e);
        let ch = ch(e, f, g);

        let bs0 = big_sigma0(a);
        let maj = maj(a, b, c);

        let t1 = h
            .wrapping_add(bs1)
            .wrapping_add(ch)
            .wrapping_add(wi)
            .wrapping_add(ki);

        let t2 = bs0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}
