use cryptal::primitives::U256;
use cryptal::rng::Csprng;

#[test]
fn test_csprng_deterministic_from_seed() {
    let seed = U256::from([0x42u8; 32]);

    let mut rng1 = Csprng::from_seed(seed);
    let mut rng2 = Csprng::from_seed(seed);

    let mut a = [0u8; 128];
    let mut b = [0u8; 128];

    rng1.fill_bytes(&mut a);
    rng2.fill_bytes(&mut b);

    assert_eq!(a, b);
}

#[test]
fn test_csprng_rekey_changes_output() {
    let seed = U256::from([0xAAu8; 32]);
    let mut rng = Csprng::from_seed(seed);

    let mut a = [0u8; 64];
    let mut b = [0u8; 64];

    rng.fill_bytes(&mut a);
    rng.fill_bytes(&mut b);

    assert_ne!(a, b);
}

#[test]
fn test_csprng_not_all_zero() {
    let seed = U256::from([0u8; 32]);
    let mut rng = Csprng::from_seed(seed);

    let mut out = [0u8; 64];
    rng.fill_bytes(&mut out);

    assert!(out.iter().any(|&b| b != 0));
}
