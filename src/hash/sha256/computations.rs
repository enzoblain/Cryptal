pub use super::K256;

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

#[cfg(not(feature = "speed"))]
pub fn all_rounds(state: &mut [u32; 8], mut w: [u32; 16]) {
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
            unsafe {
                let w16 = *w.get_unchecked((i - 16) & 15);
                let w15 = *w.get_unchecked((i - 15) & 15);
                let w7 = *w.get_unchecked((i - 7) & 15);
                let w2 = *w.get_unchecked((i - 2) & 15);

                let s0 = small_sigma0(w15);
                let s1 = small_sigma1(w2);

                *w.get_unchecked_mut(i & 15) =
                    w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
            }
        }

        let wi = unsafe { *w.get_unchecked(i & 15) };
        let ki = unsafe { *K256.get_unchecked(i) };

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

#[cfg(feature = "speed")]
pub fn all_rounds(state: &mut [u32; 8], w: &mut [u32; 16]) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    macro_rules! R {
        ($i:expr) => {{
            if $i >= 16 {
                unsafe {
                    let w16 = *w.get_unchecked(($i - 16) & 15);
                    let w15 = *w.get_unchecked(($i - 15) & 15);
                    let w7 = *w.get_unchecked(($i - 7) & 15);
                    let w2 = *w.get_unchecked(($i - 2) & 15);

                    let s0 = small_sigma0(w15);
                    let s1 = small_sigma1(w2);

                    *w.get_unchecked_mut($i & 15) =
                        w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
                }
            }

            let wi = unsafe { *w.get_unchecked($i & 15) };
            let ki = unsafe { *K256.get_unchecked($i) };

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
        }};
    }

    R!(0);
    R!(1);
    R!(2);
    R!(3);
    R!(4);
    R!(5);
    R!(6);
    R!(7);
    R!(8);
    R!(9);
    R!(10);
    R!(11);
    R!(12);
    R!(13);
    R!(14);
    R!(15);

    R!(16);
    R!(17);
    R!(18);
    R!(19);
    R!(20);
    R!(21);
    R!(22);
    R!(23);
    R!(24);
    R!(25);
    R!(26);
    R!(27);
    R!(28);
    R!(29);
    R!(30);
    R!(31);

    R!(32);
    R!(33);
    R!(34);
    R!(35);
    R!(36);
    R!(37);
    R!(38);
    R!(39);
    R!(40);
    R!(41);
    R!(42);
    R!(43);
    R!(44);
    R!(45);
    R!(46);
    R!(47);

    R!(48);
    R!(49);
    R!(50);
    R!(51);
    R!(52);
    R!(53);
    R!(54);
    R!(55);
    R!(56);
    R!(57);
    R!(58);
    R!(59);
    R!(60);
    R!(61);
    R!(62);
    R!(63);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}
