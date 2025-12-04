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
pub fn all_rounds(state: &mut [u32; 8], mut w: [u32; 64]) {
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
            w[i] = (w[i - 16])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma1(w[i - 2]));
        }

        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

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
pub fn all_rounds(state: &mut [u32; 8], w: &mut [u32; 64]) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    let wp = w.as_ptr();
    let kp = K256.as_ptr();
    macro_rules! R {
        ($i:expr) => {{
            if $i >= 16 {
                w[$i] = small_sigma1(w[$i - 2])
                    .wrapping_add(w[$i - 7])
                    .wrapping_add(small_sigma0(w[$i - 15]))
                    .wrapping_add(w[$i - 16]);
            }

            let wi = unsafe { *wp.add($i) };
            let ki = unsafe { *kp.add($i) };

            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(wi)
                .wrapping_add(ki);

            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

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
