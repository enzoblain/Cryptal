use cryptal::derivation::{Argon2Params, argon2id};

#[test]
fn argon2id_is_deterministic() {
    let params = Argon2Params {
        mem_kib: 32,
        lanes: 4,
        time: 3,
        tag_len: 32,
        secret: None,
        associated_data: None,
    };
    let a = argon2id(b"password", b"saltsalt", &params).unwrap();
    let b = argon2id(b"password", b"saltsalt", &params).unwrap();
    assert_eq!(a, b);
}

#[test]
fn argon2id_changes_with_salt() {
    let params = Argon2Params {
        mem_kib: 32,
        lanes: 4,
        time: 3,
        tag_len: 32,
        secret: None,
        associated_data: None,
    };
    let a = argon2id(b"password", b"saltAAAA", &params).unwrap();
    let b = argon2id(b"password", b"saltBBBB", &params).unwrap();
    assert_ne!(a, b);
}

#[test]
fn argon2id_respects_output_length() {
    let params = Argon2Params {
        mem_kib: 32,
        lanes: 4,
        time: 1,
        tag_len: 64,
        secret: None,
        associated_data: None,
    };
    let out = argon2id(b"password", b"saltsalt", &params).unwrap();
    assert_eq!(out.len(), 64);
}

#[test]
fn argon2id_simple_vectors() {
    let params1 = Argon2Params {
        mem_kib: 32,
        lanes: 1,
        time: 1,
        tag_len: 32,
        secret: None,
        associated_data: None,
    };
    let result1 = argon2id(b"password", b"saltsalt", &params1).unwrap();
    assert_eq!(result1.len(), 32);

    let params2 = Argon2Params {
        mem_kib: 64,
        lanes: 2,
        time: 2,
        tag_len: 32,
        secret: None,
        associated_data: None,
    };
    let result2 = argon2id(b"password", b"saltsalt", &params2).unwrap();
    assert_ne!(result1, result2,);

    let result3 = argon2id(b"different", b"saltsalt", &params1).unwrap();
    assert_ne!(result1, result3,);
}

/// RFC 9106 test vector for Argon2id
/// Section 5.3 - Argon2id Test Vectors
///
/// Input:
///   password: 0x0101010101010101010101010101010101010101010101010101010101010101 (32 bytes of 0x01)
///   salt: 0x02020202020202020202020202020202 (16 bytes of 0x02)
///   secret: 0x0303030303030303 (8 bytes of 0x03)
///   associated data: 0x040404040404040404040404 (12 bytes of 0x04)
///   parallelism: 4
///   tag length: 32
///   memory: 32 (KiB)
///   iterations: 3
///   version: 0x13
///   type: Argon2id (2)
#[test]
fn argon2id_rfc9106_test_vector() {
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = vec![0x03u8; 8];
    let associated_data = vec![0x04u8; 12];

    let params = Argon2Params {
        mem_kib: 32,
        lanes: 4,
        time: 3,
        tag_len: 32,
        secret: Some(secret),
        associated_data: Some(associated_data),
    };

    let result = argon2id(&password, &salt, &params).unwrap();

    // Expected output from RFC 9106 Section 5.3
    // Tag: 0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9
    //      d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59
    let expected = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53,
        0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01,
        0xe6, 0x59,
    ];

    assert_eq!(
        result, expected,
        "Argon2id output does not match RFC 9106 test vector"
    );
}

/// Test with minimum parameters
#[test]
fn argon2id_minimum_params() {
    let params = Argon2Params {
        mem_kib: 8, // minimum for 1 lane
        lanes: 1,
        time: 1,
        tag_len: 4, // minimum tag length
        secret: None,
        associated_data: None,
    };

    let result = argon2id(b"pass", b"saltsalt", &params).unwrap();
    assert_eq!(result.len(), 4);
}

/// Test different tag lengths
#[test]
fn argon2id_various_tag_lengths() {
    let params_short = Argon2Params {
        mem_kib: 32,
        lanes: 1,
        time: 1,
        tag_len: 16,
        secret: None,
        associated_data: None,
    };

    let params_medium = Argon2Params {
        mem_kib: 32,
        lanes: 1,
        time: 1,
        tag_len: 32,
        secret: None,
        associated_data: None,
    };

    let params_long = Argon2Params {
        mem_kib: 32,
        lanes: 1,
        time: 1,
        tag_len: 128,
        secret: None,
        associated_data: None,
    };

    let short = argon2id(b"password", b"saltsalt", &params_short).unwrap();
    let medium = argon2id(b"password", b"saltsalt", &params_medium).unwrap();
    let long = argon2id(b"password", b"saltsalt", &params_long).unwrap();

    assert_eq!(short.len(), 16);
    assert_eq!(medium.len(), 32);
    assert_eq!(long.len(), 128);
}

/// Test with recommended OWASP parameters (2024)
#[test]
fn argon2id_recommended_params() {
    let params = Argon2Params {
        mem_kib: 19456, // 19 MiB
        lanes: 1,
        time: 2,
        tag_len: 32,
        secret: None,
        associated_data: None,
    };

    let result = argon2id(b"my_secure_password", b"random_salt_16_b", &params).unwrap();
    assert_eq!(result.len(), 32);
}
