use cryptal::recovery::shamirsecretsharing::{combine, refresh, split};

#[test]
fn split_and_combine_roundtrip() {
    let secret = b"shamir works";

    let shares = split(secret, 3, 5).unwrap();
    let recovered = combine(&shares[..3]).unwrap();

    assert_eq!(recovered, secret);
}

#[test]
fn combine_order_independent() {
    let secret = b"order does not matter";

    let shares = split(secret, 3, 5).unwrap();

    let recovered = combine(&[shares[4].clone(), shares[1].clone(), shares[3].clone()]).unwrap();

    assert_eq!(recovered, secret);
}

#[test]
fn combine_fails_with_not_enough_shares() {
    let secret = b"threshold matters";

    let shares = split(secret, 3, 5).unwrap();
    let result = combine(&shares[..2]);

    assert!(result.is_err());
}

#[test]
fn combine_fails_with_duplicate_ids() {
    let secret = b"duplicate ids";

    let mut shares = split(secret, 3, 5).unwrap();
    shares[1].id = shares[0].id; // corruption volontaire

    let result = combine(&shares[..3]);
    assert!(result.is_err());
}

#[test]
fn combine_fails_with_inconsistent_threshold() {
    let secret = b"inconsistent threshold";

    let mut shares = split(secret, 3, 5).unwrap();
    shares[0].threshold = 4;

    let result = combine(&shares[..3]);
    assert!(result.is_err());
}

#[test]
fn combine_fails_with_inconsistent_length() {
    let secret = b"inconsistent length";

    let mut shares = split(secret, 3, 5).unwrap();
    shares[0].data.pop(); // corruption volontaire

    let result = combine(&shares[..3]);
    assert!(result.is_err());
}

#[test]
fn refresh_preserves_secret() {
    let secret = b"refresh preserves secret";

    let shares = split(secret, 3, 5).unwrap();
    let refreshed = refresh(&shares).unwrap();

    let recovered = combine(&refreshed[..3]).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn old_and_new_shares_cannot_mix() {
    let secret = b"refresh isolation";

    let shares = split(secret, 3, 5).unwrap();
    let refreshed = refresh(&shares).unwrap();

    let mixed = vec![
        shares[0].clone(),
        refreshed[1].clone(),
        refreshed[2].clone(),
    ];

    let result = combine(&mixed);

    assert!(result.is_err() || result.unwrap() != secret);
}

#[test]
fn various_secret_sizes() {
    for size in [1usize, 2, 7, 16, 32, 64, 128] {
        let secret = vec![0x42u8; size];

        let shares = split(&secret, 3, 5).unwrap();
        let recovered = combine(&shares[..3]).unwrap();

        assert_eq!(recovered, secret);
    }
}

#[test]
fn threshold_one() {
    let secret = b"threshold one";

    let shares = split(secret, 1, 5).unwrap();
    let recovered = combine(&[shares[2].clone()]).unwrap();

    assert_eq!(recovered, secret);
}
