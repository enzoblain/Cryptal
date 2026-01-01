use cryptal::primitives::U256;

use core::convert::TryFrom;

#[test]
fn u256_max_const() {
    assert_eq!(U256::MAX, U256::from([255u8; 32]));
}

#[test]
fn u256_try_from_small_ints_and_back() {
    let a = U256::from(0x12u8);
    assert_eq!(u8::try_from(a).unwrap(), 0x12u8);

    let bad = U256::from([1u8; 32]);
    assert!(u8::try_from(bad).is_err());

    let a = U256::from(0x1234u16);
    assert_eq!(u16::try_from(a).unwrap(), 0x1234u16);
    let mut bad = [0u8; 32];
    bad[0] = 1;
    assert!(u16::try_from(U256::from(bad)).is_err());

    let a = U256::from(0xDEADBEEFu32);
    assert_eq!(u32::try_from(a).unwrap(), 0xDEADBEEFu32);

    let a = U256::from(0x0123_4567_89AB_CDEFu64);
    assert_eq!(u64::try_from(a).unwrap(), 0x0123_4567_89AB_CDEFu64);

    // u128
    let a = U256::from(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEFu128);
    assert_eq!(
        u128::try_from(a).unwrap(),
        0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEFu128
    );

    let val: usize = if usize::BITS == 64 {
        0x0123_4567_89AB_CDEFusize
    } else {
        0x89AB_CDEFusize
    };
    let a = U256::from(val);
    assert_eq!(usize::try_from(a).unwrap(), val);

    let mut bad_usize = [0u8; 32];
    bad_usize[0] = 1;
    assert!(usize::try_from(U256::from(bad_usize)).is_err());
}

#[test]
fn u256_leading_zeros() {
    let zero = U256::ZERO;
    assert_eq!(zero.leading_zeros(), 256);

    let one = U256::from(1u8);
    assert_eq!(one.leading_zeros(), 255);

    let mut high = [0u8; 32];
    high[0] = 0x10;
    let h = U256::from(high);
    assert_eq!(h.leading_zeros(), 3);

    let mut mid = [0u8; 32];
    mid[10] = 0x01;
    let m = U256::from(mid);
    assert_eq!(m.leading_zeros(), 87u32);
}

#[test]
fn u256_bitwise_ops() {
    let a = U256::from([0xFFu8; 32]);
    let b = U256::from([0x0Fu8; 32]);

    let and = a & b;
    assert_eq!(and, U256::from([0x0Fu8; 32]));

    let xor = a ^ b;
    assert_eq!(xor, U256::from([0xF0u8; 32]));
}

#[test]
fn u256_shifts_byte_aligned() {
    let one = U256::from(1u8);

    let shifted = one << U256::from(8u8);
    let mut expect = [0u8; 32];
    expect[30] = 1u8;
    assert_eq!(shifted, U256::from(expect));

    let val = U256::from(expect);
    let back = val >> U256::from(8u8);
    assert_eq!(back, one);
}

#[test]
fn u256_shifts_bit_aligned() {
    let mut arr = [0u8; 32];
    arr[31] = 0b0000_0001;
    let v = U256::from(arr);

    let s = v << U256::from(1u8);
    let mut expected = [0u8; 32];
    expected[31] = 0b0000_0010;
    assert_eq!(s, U256::from(expected));

    let s: U256 = v << U256::from(9u8);
    let mut expected = [0u8; 32];
    expected[30] = 0b0000_0010;
    assert_eq!(s, U256::from(expected));
}

#[test]
fn u256_shift_out_of_range_returns_zero() {
    let v = U256::from(1u8);
    let mut rhs = [0u8; 32];

    rhs[30] = 1;
    rhs[31] = 0;

    let r = U256::from(rhs);

    assert_eq!(v << r, U256::from([0u8; 32]));
    assert_eq!(v >> r, U256::from([0u8; 32]));
}

#[test]
fn u256_add_and_sub_carry_borrow() {
    let a = U256::from(255u8);
    let b = U256::from(1u8);
    let sum = a + b;

    let mut expected = [0u8; 32];
    expected[30] = 1u8;
    expected[31] = 0u8;

    assert_eq!(sum, U256::from(expected));

    let big = U256::from(expected);
    let one = U256::from(1u8);
    let diff = big - one;

    assert_eq!(diff, U256::from(255u8));
}

#[test]
fn u256_mul_basic_and_overflow_truncates() {
    let a = U256::from(2u8);
    let b = U256::from(3u8);

    assert_eq!(a * b, U256::from(6u8));

    let doubled = U256::MAX * U256::from(2u8);
    let mut expected = [0xFFu8; 32];
    expected[31] = 0xFE;

    assert_eq!(doubled, U256::from(expected));
}

#[test]
fn u256_mul_cross_limb_carry() {
    let hi128 = U256::from([0u64, 1, 0, 0]);
    let mid64 = U256::from([0u64, 0, 1, 0]);
    let product = hi128 * mid64;

    assert_eq!(product, U256::from([1u64, 0, 0, 0]));
}

#[test]
fn u256_div_basic_cases() {
    let nine = U256::from(9u8);
    let three = U256::from(3u8);

    assert_eq!(nine / three, U256::from(3u8));

    let ten = U256::from(10u8);
    assert_eq!(ten / three, U256::from(3u8));

    let small = U256::from(5u8);
    let bigger = U256::from(10u8);

    assert_eq!(small / bigger, U256::ZERO);
}

#[test]
fn u256_div_cross_limb() {
    let dividend = U256::from(256u16);
    let divisor = U256::from(1u16);
    let expected = U256::from(256u16);

    assert_eq!(dividend / divisor, expected);
}

#[test]
fn u256_div_by_one_identity() {
    let wide = U256::from([0xFFFF_FFFF_FFFF_FFFFu64; 4]);

    assert_eq!(wide / U256::ONE, wide);
}

#[test]
#[should_panic(expected = "division by zero")]
fn u256_div_by_zero_panics() {
    let _ = U256::from(1u8) / U256::ZERO;
}

#[test]
fn u256_display_and_asref() {
    let v = U256::from(1u8);
    let s: &[u8] = v.as_ref();

    assert_eq!(s.len(), 32);
    assert_eq!(s[31], 1u8);

    let formatted = format!("{}", v);
    assert!(formatted.ends_with(":01"));
}
