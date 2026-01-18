use cryptal::primitives::{U256, U512};

use core::convert::TryFrom;

#[test]
fn u512_max_const() {
    assert_eq!(U512::MAX, U512::from([255u8; 64]));
}

#[test]
fn u512_try_from_small_ints_and_back() {
    let a = U512::from(0x12u8);
    assert_eq!(u8::try_from(a).unwrap(), 0x12u8);

    let bad = U512::from([1u8; 64]);
    assert!(u8::try_from(bad).is_err());

    let a = U512::from(0x1234u16);
    assert_eq!(u16::try_from(a).unwrap(), 0x1234u16);

    let mut bad = [0u8; 64];
    bad[0] = 1;
    assert!(u16::try_from(U512::from(bad)).is_err());

    let a = U512::from(0xDEADBEEFu32);
    assert_eq!(u32::try_from(a).unwrap(), 0xDEADBEEFu32);

    let a = U512::from(0x0123_4567_89AB_CDEFu64);
    assert_eq!(u64::try_from(a).unwrap(), 0x0123_4567_89AB_CDEFu64);

    let a = U512::from(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEFu128);
    assert_eq!(
        u128::try_from(a).unwrap(),
        0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEFu128
    );

    let val: usize = if usize::BITS == 64 {
        0x0123_4567_89AB_CDEFusize
    } else {
        0x89AB_CDEFusize
    };
    let a = U512::from(val);
    assert_eq!(usize::try_from(a).unwrap(), val);

    let mut bad_usize = [0u8; 64];
    bad_usize[0] = 1;
    assert!(usize::try_from(U512::from(bad_usize)).is_err());

    let u256 = U256::from(0xDEADBEEFu32);
    let widened = U512::from(u256);

    // value preserved in lower 256 bits
    let back = U256::try_from(widened).unwrap();
    assert_eq!(back, u256);

    // upper 256 bits non-zero → error
    let mut bad = [0u8; 64];
    bad[0] = 1;
    let bad_u512 = U512::from(bad);
    assert!(U256::try_from(bad_u512).is_err());
}

#[test]
fn u512_leading_zeros() {
    let zero = U512::ZERO;
    assert_eq!(zero.leading_zeros(), 512);

    let one = U512::from(1u8);
    assert_eq!(one.leading_zeros(), 511);

    let mut high = [0u8; 64];
    high[0] = 0x10;
    let h = U512::from(high);
    assert_eq!(h.leading_zeros(), 3);

    let mut mid = [0u8; 64];
    mid[10] = 0x01;
    let m = U512::from(mid);
    assert_eq!(m.leading_zeros(), 87u32);
}

#[test]
fn u512_bitwise_ops() {
    let a = U512::from([0xFFu8; 64]);
    let b = U512::from([0x0Fu8; 64]);

    let and = a & b;
    assert_eq!(and, U512::from([0x0Fu8; 64]));

    let xor = a ^ b;
    assert_eq!(xor, U512::from([0xF0u8; 64]));
}

#[test]
fn u512_shifts_byte_aligned() {
    let one = U512::from(1u8);

    let shifted = one << U512::from(8u8);
    let mut expect = [0u8; 64];
    expect[62] = 1u8;
    assert_eq!(shifted, U512::from(expect));

    let val = U512::from(expect);
    let back = val >> U512::from(8u8);
    assert_eq!(back, one);
}

#[test]
fn u512_shifts_bit_aligned() {
    let mut arr = [0u8; 64];
    arr[63] = 0b0000_0001;
    let v = U512::from(arr);

    let s = v << U512::from(1u8);
    let mut expected = [0u8; 64];
    expected[63] = 0b0000_0010;
    assert_eq!(s, U512::from(expected));

    let s: U512 = v << U512::from(9u8);
    let mut expected = [0u8; 64];
    expected[62] = 0b0000_0010;
    assert_eq!(s, U512::from(expected));
}

#[test]
fn u512_shift_out_of_range_returns_zero() {
    let v = U512::from(1u8);
    let mut rhs = [0u8; 64];

    rhs[62] = 2;
    rhs[63] = 0;

    let r = U512::from(rhs);

    assert_eq!(v << r, U512::from([0u8; 64]));
    assert_eq!(v >> r, U512::from([0u8; 64]));
}

#[test]
fn u512_add_and_sub_carry_borrow() {
    let a = U512::from(255u8);
    let b = U512::from(1u8);
    let sum = a + b;

    let mut expected = [0u8; 64];
    expected[62] = 1u8;
    expected[63] = 0u8;

    assert_eq!(sum, U512::from(expected));

    let big = U512::from(expected);
    let one = U512::from(1u8);
    let diff = big - one;

    assert_eq!(diff, U512::from(255u8));
}

#[test]
fn u512_mul_basic_and_overflow_truncates() {
    let a = U512::from(2u8);
    let b = U512::from(3u8);

    assert_eq!(a * b, U512::from(6u8));

    let doubled = U512::MAX * U512::from(2u8);
    let mut expected = [0xFFu8; 64];
    expected[63] = 0xFE;

    assert_eq!(doubled, U512::from(expected));
}

#[test]
fn u512_div_basic_cases() {
    let nine = U512::from(9u8);
    let three = U512::from(3u8);

    assert_eq!(nine / three, U512::from(3u8));

    let ten = U512::from(10u8);
    assert_eq!(ten / three, U512::from(3u8));

    let small = U512::from(5u8);
    let bigger = U512::from(10u8);

    assert_eq!(small / bigger, U512::ZERO);
}

#[test]
fn u512_div_by_one_identity() {
    let wide = U512::from([0xFFFF_FFFF_FFFF_FFFFu64; 8]);

    assert_eq!(wide / U512::ONE, wide);
}

#[test]
#[should_panic(expected = "division by zero")]
fn u512_div_by_zero_panics() {
    let _ = U512::from(1u8) / U512::ZERO;
}

#[test]
fn u512_display_and_asref() {
    let v = U512::from(1u8);
    let s: &[u8] = v.as_ref();

    assert_eq!(s.len(), 64);
    assert_eq!(s[63], 1u8);

    let formatted = format!("{}", v);
    assert!(formatted.ends_with(":01"));
}
