use super::field::FieldElement;
use super::precomp_data::BI;
use crate::signatures::ed25519::consttime::{equal_i8, negative};
use crate::signatures::ed25519::field::{D, D2, SQRTM1};
use crate::signatures::ed25519::precomp_data::BASE;
use crate::signatures::ed25519::scalar::Scalar;

pub struct GeP1 {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

impl GeP1 {
    pub(crate) fn from_sum(a: &GeP3, b: &GeCached) -> Self {
        let mut x = a.y + a.x;
        let mut y = a.y - a.x;
        let mut z = x * b.yplusx;
        let mut t = b.t2d * a.t;

        y = y * b.yminusx;
        x = a.z * b.z;

        let sumx = x + x;

        x = z - y;
        y = z + y;
        z = sumx + t;
        t = sumx - t;

        Self { x, y, z, t }
    }

    pub(crate) fn from_mixed_sum(a: &GeP3, b: &GePrecomp) -> Self {
        let mut x = a.y + a.x;
        let mut y = a.y - a.x;
        let mut z = x * b.yplusx;
        let mut t = b.xy2d * a.t;
        let sumz = a.z + a.z;

        y = y * b.yminusx;
        x = z - y;
        y = z + y;
        z = sumz + t;
        t = sumz - t;

        Self { x, y, z, t }
    }

    pub(crate) fn from_difference(a: &GeP3, b: &GeCached) -> Self {
        let mut x = a.y + a.x;
        let mut y = a.y - a.x;
        let mut z = x * b.yminusx;
        let mut t = b.t2d * a.t;

        y = y * b.yplusx;
        x = a.z * b.z;

        let sumx = x + x;

        x = z - y;
        y = z + y;
        z = sumx - t;
        t = sumx + t;

        Self { x, y, z, t }
    }

    pub(crate) fn from_mixed_difference(a: &GeP3, b: &GePrecomp) -> Self {
        let mut x = a.y + a.x;
        let mut y = a.y - a.x;
        let mut z = x * b.yminusx;
        let mut t = b.xy2d * a.t;
        let sumz = a.z + a.z;

        y = y * b.yplusx;
        x = z - y;
        y = z + y;
        z = sumz - t;
        t = sumz + t;

        Self { x, y, z, t }
    }
}

pub struct GeP2 {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
}

impl GeP2 {
    pub(crate) const ONE: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
    };

    pub(crate) fn from_gep1(g: &GeP1) -> Self {
        let x = g.x * g.t;
        let y = g.y * g.z;
        let z = g.z * g.t;

        GeP2 { x, y, z }
    }

    pub(crate) fn from_gep3(g: &GeP3) -> Self {
        let x = g.x;
        let y = g.y;
        let z = g.z;

        GeP2 { x, y, z }
    }

    pub(crate) fn double(self) -> GeP1 {
        let mut x = self.x.sq();
        let mut z = self.y.sq();
        let mut t = self.z.sq2();
        let mut y = self.x + self.y;
        let ysq = y.sq();

        y = z + x;
        z = z - x;
        x = ysq - y;
        t = t - z;

        GeP1 { x, y, z, t }
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x * recip;
        let y = self.y * recip;

        let mut output = y.to_bytes();

        let sign_bit = x.is_negative() as u8;
        output[31] ^= sign_bit << 7;

        output
    }
}

pub struct GeP3 {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

impl GeP3 {
    pub(crate) const ONE: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    pub(crate) fn double_scalar_mul(&self, a: Scalar, b: Scalar) -> GeP2 {
        let mut ai = [
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
            GeCached::ZERO,
        ];
        let aslide = a.slide();
        let bslide = b.slide();

        ai[0] = GeCached::from_p3(self);

        let mut t = self.double();
        let a2 = GeP3::from_gep1(&t);
        let mut u;

        for j in 1..8 {
            t = GeP1::from_sum(&a2, &ai[j - 1]);
            u = GeP3::from_gep1(&t);
            ai[j] = GeCached::from_p3(&u);
        }

        let mut r = GeP2::ONE;

        let mut i: i32 = 255;
        while i >= 0 {
            if aslide.0[i as usize] != 0 || bslide.0[i as usize] != 0 {
                break;
            }
            i -= 1;
        }

        while i >= 0 {
            let asi = aslide.0[i as usize];
            let bsi = bslide.0[i as usize];

            t = r.double();

            if asi > 0 {
                u = GeP3::from_gep1(&t);
                let idx = (asi / 2) as usize;
                t = GeP1::from_sum(&u, &ai[idx]);
            } else if asi < 0 {
                u = GeP3::from_gep1(&t);
                let idx = ((-asi) / 2) as usize;
                t = GeP1::from_difference(&u, &ai[idx]);
            }

            if bsi > 0 {
                u = GeP3::from_gep1(&t);
                let idx = (bsi / 2) as usize;
                t = GeP1::from_mixed_sum(&u, &BI[idx]);
            } else if bsi < 0 {
                u = GeP3::from_gep1(&t);
                let idx = ((-bsi) / 2) as usize;
                t = GeP1::from_mixed_difference(&u, &BI[idx]);
            }

            r = GeP2::from_gep1(&t);
            i -= 1;
        }

        r
    }

    pub(crate) fn double(&self) -> GeP1 {
        GeP2::from_gep3(self).double()
    }

    pub(crate) fn from_gep1(g: &GeP1) -> Self {
        let x = g.x * g.t;
        let y = g.y * g.z;
        let z = g.z * g.t;
        let t = g.x * g.y;

        Self { x, y, z, t }
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x * recip;
        let y = self.y * recip;

        let mut output = y.to_bytes();

        let sign_bit = x.is_negative() as u8;
        output[31] ^= sign_bit << 7;

        output
    }

    pub(crate) fn decompress(s: &[u8; 32]) -> (Self, i32) {
        let mut h = Self {
            x: FieldElement::ZERO,
            y: FieldElement::from_bytes(s),
            z: FieldElement::ONE,
            t: FieldElement::ZERO,
        };

        let mut u = h.y.sq();
        let mut v = u * D;
        u = u - h.z;
        v = v + h.z;

        let v3 = v.sq();
        let v3 = v3 * v;

        h.x = v3.sq();
        h.x = h.x * v;
        h.x = h.x * u;
        h.x = h.x.pow22523();
        h.x = h.x * v3;
        h.x = h.x * u;

        let mut vxx = h.x.sq();
        vxx = vxx * v;
        let mut check = vxx - u;

        if check.is_non_zero() == 1 {
            check = vxx + u;
            if check.is_non_zero() == 1 {
                return (h, -1);
            }
            h.x = h.x * SQRTM1;
        }

        let sign = (s[31] >> 7) as i32;
        if h.x.is_negative() == sign {
            h.x = -h.x;
        }

        h.t = h.x * h.y;

        (h, 0)
    }

    pub(crate) fn from_scalar_mul(a: Scalar) -> Self {
        let mut e = [0i8; 64];
        let mut t;

        for i in 0..32 {
            e[2 * i] = (a.0[i] & 15) as i8;
            e[2 * i + 1] = ((a.0[i] >> 4) & 15) as i8;
        }

        let mut carry: i8 = 0;
        for v in e.iter_mut().take(63) {
            *v += carry;
            carry = (*v + 8) >> 4;
            *v -= carry << 4;
        }
        e[63] += carry;

        let mut h = Self::ONE;

        let mut r;
        for i in (1..64).step_by(2) {
            t = GePrecomp::select(i / 2, e[i]);
            r = GeP1::from_mixed_sum(&h, &t);
            h = GeP3::from_gep1(&r);
        }

        let mut r = h.double();
        let mut s = GeP2::from_gep1(&r);
        r = s.double();
        s = GeP2::from_gep1(&r);
        r = s.double();
        s = GeP2::from_gep1(&r);
        r = s.double();
        h = GeP3::from_gep1(&r);

        for i in (0..64).step_by(2) {
            t = GePrecomp::select(i / 2, e[i]);
            r = GeP1::from_mixed_sum(&h, &t);
            h = GeP3::from_gep1(&r);
        }

        h
    }
}

pub struct GeCached {
    pub(crate) yplusx: FieldElement,
    pub(crate) yminusx: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t2d: FieldElement,
}

impl GeCached {
    pub(crate) const ZERO: Self = Self {
        yplusx: FieldElement::ZERO,
        yminusx: FieldElement::ZERO,
        z: FieldElement::ZERO,
        t2d: FieldElement::ZERO,
    };

    pub(crate) fn from_p3(g: &GeP3) -> GeCached {
        let yplusx = g.y + g.x;
        let yminusx = g.y - g.x;
        let z = g.z;
        let t2d = g.t * D2;

        GeCached {
            yplusx,
            yminusx,
            z,
            t2d,
        }
    }
}

pub struct GePrecomp {
    pub(crate) yplusx: FieldElement,
    pub(crate) yminusx: FieldElement,
    pub(crate) xy2d: FieldElement,
}

impl GePrecomp {
    pub(crate) const ZERO: Self = Self {
        yplusx: FieldElement::ZERO,
        yminusx: FieldElement::ZERO,
        xy2d: FieldElement::ZERO,
    };

    pub(crate) const ONE: Self = Self {
        yplusx: FieldElement::ONE,
        yminusx: FieldElement::ONE,
        xy2d: FieldElement::ZERO,
    };

    pub(crate) fn conditional_move(&mut self, rhs: &Self, b: u8) {
        self.yplusx.conditional_move(&rhs.yplusx, b as u32);
        self.yminusx.conditional_move(&rhs.yminusx, b as u32);
        self.xy2d.conditional_move(&rhs.xy2d, b as u32);
    }

    pub(crate) fn select(pos: usize, b: i8) -> Self {
        let mut minust = GePrecomp::ZERO;
        let mut t = GePrecomp::ONE;

        let bnegative = negative(b);
        let babs = (b as i16 - (((-(bnegative as i16)) & (b as i16)) << 1)) as i8;

        t.conditional_move(&BASE[pos][0], equal_i8(babs, 1));
        t.conditional_move(&BASE[pos][1], equal_i8(babs, 2));
        t.conditional_move(&BASE[pos][2], equal_i8(babs, 3));
        t.conditional_move(&BASE[pos][3], equal_i8(babs, 4));
        t.conditional_move(&BASE[pos][4], equal_i8(babs, 5));
        t.conditional_move(&BASE[pos][5], equal_i8(babs, 6));
        t.conditional_move(&BASE[pos][6], equal_i8(babs, 7));
        t.conditional_move(&BASE[pos][7], equal_i8(babs, 8));

        minust.yplusx = t.yminusx;
        minust.yminusx = t.yplusx;
        minust.xy2d = -t.xy2d;

        t.conditional_move(&minust, bnegative);

        t
    }
}
