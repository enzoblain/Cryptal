use core::convert::TryFrom;

use cryptography::primitives::U256;

#[test]
fn u256_max_const() {
    assert_eq!(U256::MAX, U256([255u8; 32]));
}

#[test]
fn u256_try_from_small_ints_and_back() {
    // u8
    let a = U256::from(0x12u8);
    assert_eq!(u8::try_from(a).unwrap(), 0x12u8);
    let bad = U256([1u8; 32]);
    assert!(u8::try_from(bad).is_err());

    // u16
    let b = U256::from(0x1234u16);
    assert_eq!(u16::try_from(b).unwrap(), 0x1234u16);
    let mut bad2 = [0u8; 32];
    bad2[0] = 1;
    assert!(u16::try_from(U256(bad2)).is_err());

    // u32
    let c = U256::from(0xDEADBEEFu32);
    assert_eq!(u32::try_from(c).unwrap(), 0xDEADBEEFu32);

    // u64
    let d = U256::from(0x0123_4567_89AB_CDEFu64);
    assert_eq!(u64::try_from(d).unwrap(), 0x0123_4567_89AB_CDEFu64);

    // u128
    let e = U256::from(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEFu128);
    assert_eq!(
        u128::try_from(e).unwrap(),
        0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEFu128
    );
}

#[test]
fn u256_bitwise_ops() {
    let a = U256::from([0xFFu8; 32]);
    let b = U256::from([0x0Fu8; 32]);

    let and = a & b;
    assert_eq!(and, U256::from([0x0Fu8; 32]));

    let xor = a ^ b;
    // 0xFF ^ 0x0F = 0xF0
    assert_eq!(xor, U256::from([0xF0u8; 32]));
}

#[test]
fn u256_shifts_byte_aligned() {
    let one = U256::from(1u8);

    // left shift by 8 -> moves LSB at index 31 to index 30
    let shifted = one << U256::from(8u8);
    let mut expect = [0u8; 32];
    expect[30] = 1u8;
    assert_eq!(shifted, U256(expect));

    // right shift by 8 -> reverse
    let val = U256(expect);
    let back = val >> U256::from(8u8);
    assert_eq!(back, one);
}

#[test]
fn u256_shifts_bit_aligned() {
    // test a small bit shift that causes carries between bytes
    let mut arr = [0u8; 32];
    arr[31] = 0b0000_0001;
    let v = U256(arr);

    // shift left by 1 -> bit moves into previous byte
    let s = v << U256::from(1u8);
    let mut expected = [0u8; 32];
    expected[31] = 0b0000_0010;
    assert_eq!(s, U256(expected));

    // shift left by 9 -> moves into index 30 with one-bit carry
    let s9 = v << U256::from(9u8);
    let mut expected9 = [0u8; 32];
    expected9[30] = 0b0000_0010;
    assert_eq!(s9, U256(expected9));
}

#[test]
fn u256_shift_out_of_range_returns_zero() {
    let v = U256::from(1u8);
    // build RHS with value 256
    let mut rhs = [0u8; 32];
    rhs[30] = 1; // high byte
    rhs[31] = 0; // low byte -> 256

    let r = U256(rhs);
    assert_eq!(v << r, U256([0u8; 32]));
    assert_eq!(v >> r, U256([0u8; 32]));
}

#[test]
fn u256_add_and_sub_carry_borrow() {
    // 255 + 1 -> carry into previous byte
    let a = U256::from(255u8);
    let b = U256::from(1u8);
    let sum = a + b;
    let mut expected = [0u8; 32];
    expected[30] = 1u8;
    expected[31] = 0u8;
    assert_eq!(sum, U256(expected));

    // subtraction with borrow: (1 << 8) - 1 = 255
    let big = U256(expected);
    let one = U256::from(1u8);
    let diff = big - one;
    assert_eq!(diff, U256::from(255u8));
}

#[test]
fn u256_display_and_asref() {
    let v = U256::from(1u8);
    // as_ref returns a 32-byte slice whose last element is 1
    let s: &[u8] = v.as_ref();
    assert_eq!(s.len(), 32);
    assert_eq!(s[31], 1u8);

    // display produces hex groups separated by ':'
    let formatted = format!("{}", v);
    // should end with ":01"
    assert!(formatted.ends_with(":01"));
}
