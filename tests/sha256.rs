use cryptography::hash::sha256;
use cryptography::primitives::U256;

fn sha256_u256(input: &[u8]) -> U256 {
    let got = sha256(input);
    let bytes: &[u8] = got.as_ref();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    U256(arr)
}

fn expect_sha256_eq(input: &[u8], expected: &U256) {
    let got = sha256_u256(input);
    assert_eq!(
        &got, expected,
        "Digest mismatch for input {:?}\nExpected {}\nGot      {}",
        input, expected, got,
    );
}

// -------------------------------------------------------
// OFFICIAL SHA-256 TEST VECTORS
// -------------------------------------------------------

const EXPECT_EMPTY: U256 = U256([
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
]);

const EXPECT_ABC: U256 = U256([
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
]);

const EXPECT_QBF: U256 = U256([
    0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f,
    0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92,
]);

const EXPECT_QBF_DOT: U256 = U256([
    0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7, 0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97,
    0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c, 0x86, 0x35, 0xfb, 0x6c,
]);

const EXPECT_LONG_MSG: U256 = U256([
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
]);

// -------------------------------------------------------
// 1. OFFICIAL VECTOR TESTS
// -------------------------------------------------------

#[test]
fn sha256_empty_vector() {
    expect_sha256_eq(&[], &EXPECT_EMPTY);
}

#[test]
fn sha256_abc_vector() {
    expect_sha256_eq(b"abc", &EXPECT_ABC);
}

#[test]
fn sha256_known_phrase_no_dot() {
    expect_sha256_eq(b"The quick brown fox jumps over the lazy dog", &EXPECT_QBF);
}

#[test]
fn sha256_known_phrase_dot() {
    expect_sha256_eq(
        b"The quick brown fox jumps over the lazy dog.",
        &EXPECT_QBF_DOT,
    );
}

#[test]
fn sha256_long_message_multiblock() {
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    expect_sha256_eq(input, &EXPECT_LONG_MSG);
}

// -------------------------------------------------------
// 2. LENGTHS FROM 0 TO 256 (no length assertions)
// -------------------------------------------------------

#[test]
fn sha256_incremental_lengths() {
    let mut buf = Vec::with_capacity(256);
    for i in 0..256 {
        buf.push(i as u8);
        let _ = sha256_u256(&buf);
    }
}

// -------------------------------------------------------
// 3. 0x00, 0xFF, AND REPEATED PATTERNS
// -------------------------------------------------------

#[test]
fn sha256_zeroes_various_lengths() {
    for len in [1, 2, 4, 8, 16, 32, 64, 128, 255, 256] {
        let buf = vec![0u8; len];
        let _ = sha256_u256(&buf);
    }
}

#[test]
fn sha256_ff_various_lengths() {
    for len in [1, 2, 4, 8, 16, 32, 64, 128, 255, 256] {
        let buf = vec![0xFF; len];
        let _ = sha256_u256(&buf);
    }
}

#[test]
fn sha256_repeated_patterns() {
    let patterns = [
        vec![0x12],
        vec![0xAB, 0xCD],
        vec![0x00, 0x01, 0x02, 0x03],
        vec![0x10, 0x20, 0x30, 0x40, 0x50],
    ];

    for p in patterns {
        let mut buf = Vec::new();
        for _ in 0..200 {
            buf.extend(&p);
        }
        let _ = sha256_u256(&buf);
    }
}

// -------------------------------------------------------
// 4. MULTI-BLOCK INPUTS
// -------------------------------------------------------

#[test]
fn sha256_large_multiblock() {
    let mut buf = Vec::new();
    for i in 0..5000 {
        buf.push((i % 256) as u8);
    }
    let _ = sha256_u256(&buf);
}

#[test]
fn sha256_1mb_data() {
    let buf = vec![0xAAu8; 1_000_000];
    let _ = sha256_u256(&buf);
}

// -------------------------------------------------------
// 5. PSEUDO-DETERMINISTIC FUZZING
// -------------------------------------------------------

fn lcg(seed: &mut u64) -> u8 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    ((*seed >> 24) & 0xFF) as u8
}

#[test]
fn sha256_fuzz_semi_random() {
    let mut seed = 0x123456789ABCDEF0u64;
    let mut buf = Vec::new();

    for _ in 0..500 {
        buf.push(lcg(&mut seed));
        let _ = sha256_u256(&buf);
    }
}

// -------------------------------------------------------
// 6. EDGE CASES
// -------------------------------------------------------

#[test]
fn sha256_single_bytes() {
    for b in 0u8..=255 {
        let _ = sha256_u256(&[b]);
    }
}

#[test]
fn sha256_block_boundary_64() {
    let buf = vec![0x11u8; 64];
    let _ = sha256_u256(&buf);
}

#[test]
fn sha256_block_boundary_128() {
    let buf = vec![0x22u8; 128];
    let _ = sha256_u256(&buf);
}

#[test]
fn sha256_large_boundary_10k() {
    let buf = vec![0x55u8; 10_000];
    let _ = sha256_u256(&buf);
}
