use cryptal::hash::sha512;

fn sha512_test(input: &[u8]) -> [u8; 64] {
    let got = sha512(input);
    let bytes: &[u8] = got.as_ref();

    let mut arr = [0u8; 64];
    arr.copy_from_slice(bytes);

    arr
}

fn expect_sha512_eq(input: &[u8], expected: &[u8; 64]) {
    let got = sha512_test(input);

    assert_eq!(
        &got, expected,
        "Digest mismatch for input {:?}\nExpected {:?}\nGot      {:?}",
        input, expected, got,
    );
}

// -------------------------------------------------------
// OFFICIAL SHA-512 TEST VECTORS
// -------------------------------------------------------

// -------------------------------------------------------
// 1. OFFICIAL VECTOR TESTS
// -------------------------------------------------------

#[test]
fn sha512_empty_vector() {
    let empty_out = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80,
        0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c,
        0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87,
        0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
        0xf9, 0x27, 0xda, 0x3e,
    ];

    expect_sha512_eq(&[], &empty_out);
}

#[test]
fn sha512_abc_vector() {
    let abc_out = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];

    expect_sha512_eq(b"abc", &abc_out);
}

#[test]
fn sha512_known_phrase() {
    let out = [
        0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73, 0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e, 0xd7,
        0x69, 0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88, 0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b,
        0xbb, 0x64, 0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39, 0x12, 0x54, 0x7d, 0x1e, 0x8a,
        0x3b, 0x5e, 0xd6, 0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f, 0xa0, 0x53, 0x8f, 0x3d,
        0xb8, 0x54, 0xfe, 0xe6,
    ];

    expect_sha512_eq(b"The quick brown fox jumps over the lazy dog", &out);
}

// -------------------------------------------------------
// 2. LENGTHS FROM 0 TO 256
// -------------------------------------------------------

#[test]
fn sha512_incremental_lengths() {
    let mut buf = Vec::with_capacity(256);
    for i in 0..256 {
        buf.push(i as u8);
        let _ = sha512_test(&buf);
    }
}

// -------------------------------------------------------
// 3. 0x00, 0xFF, AND REPEATED PATTERNS
// -------------------------------------------------------

#[test]
fn sha512_zeroes_various_lengths() {
    for len in [1, 2, 4, 8, 16, 32, 64, 128, 255, 256] {
        let buf = vec![0u8; len];
        let _ = sha512_test(&buf);
    }
}

#[test]
fn sha512_ff_various_lengths() {
    for len in [1, 2, 4, 8, 16, 32, 64, 128, 255, 256] {
        let buf = vec![0xFF; len];
        let _ = sha512_test(&buf);
    }
}

// -------------------------------------------------------
// 4. MULTI-BLOCK INPUTS
// -------------------------------------------------------

#[test]
fn sha512_large_multiblock() {
    let mut buf = Vec::new();
    for i in 0..5000 {
        buf.push((i % 256) as u8);
    }
    let _ = sha512_test(&buf);
}

#[test]
fn sha512_1mb_data() {
    let buf = vec![0xAAu8; 1_000_000];
    let _ = sha512_test(&buf);
}

// -------------------------------------------------------
// 5. EDGE CASES
// -------------------------------------------------------

#[test]
fn sha512_single_bytes() {
    for b in 0u8..=255 {
        let _ = sha512_test(&[b]);
    }
}

#[test]
fn sha512_block_boundary_128() {
    let buf = vec![0x11u8; 128];
    let _ = sha512_test(&buf);
}

#[test]
fn sha512_block_boundary_256() {
    let buf = vec![0x22u8; 256];
    let _ = sha512_test(&buf);
}
