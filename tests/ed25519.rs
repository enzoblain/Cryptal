use cryptal::rng::Csprng;

use cryptal::signatures::ed25519::{
    add_scalar::ed25519_add_scalar, key_exchange::ed25519_key_exchange,
    keypair::ed25519_create_keypair, sign::ed25519_sign, verify::ed25519_verify,
};

#[test]
fn test_ed25519_sign_and_verify() {
    let mut public_key = [0u8; 32];
    let mut private_key = [0u8; 64];
    let mut seed = [0u8; 32];
    let mut signature = [0u8; 64];

    let message: &[u8] = b"Hello, world!";

    let mut rng = Csprng::new();
    rng.fill_bytes(&mut seed);

    ed25519_create_keypair(&mut public_key, &mut private_key, &seed);

    ed25519_sign(&mut signature, message, &public_key, &private_key);
    assert!(
        ed25519_verify(&signature, message, &public_key),
        "signature should be valid"
    );

    signature[44] ^= 0x10;
    assert!(
        !ed25519_verify(&signature, message, &public_key),
        "signature modification must be detected"
    );
}

#[test]
fn test_ed25519_add_scalar() {
    let mut public_key = [0u8; 32];
    let mut private_key = [0u8; 64];
    let mut seed = [0u8; 32];
    let mut scalar = [0u8; 32];
    let mut signature = [0u8; 64];

    let message: &[u8] = b"Hello, world!";

    let mut rng = Csprng::new();
    rng.fill_bytes(&mut seed);
    rng.fill_bytes(&mut scalar);

    ed25519_create_keypair(&mut public_key, &mut private_key, &seed);

    ed25519_add_scalar(Some(&mut public_key), Some(&mut private_key), &scalar);

    ed25519_sign(&mut signature, message, &public_key, &private_key);
    assert!(
        ed25519_verify(&signature, message, &public_key),
        "signature after scalar addition must be valid"
    );
}

#[test]
fn test_ed25519_key_exchange() {
    let mut public_key = [0u8; 32];
    let mut private_key = [0u8; 64];
    let mut other_public_key = [0u8; 32];
    let mut other_private_key = [0u8; 64];

    let mut seed = [0u8; 32];
    let mut shared_secret = [0u8; 32];
    let mut other_shared_secret = [0u8; 32];

    let mut rng = Csprng::new();

    rng.fill_bytes(&mut seed);
    ed25519_create_keypair(&mut public_key, &mut private_key, &seed);

    rng.fill_bytes(&mut seed);
    ed25519_create_keypair(&mut other_public_key, &mut other_private_key, &seed);

    let sk_a: &[u8; 32] = (&private_key[..32]).try_into().unwrap();
    let sk_b: &[u8; 32] = (&other_private_key[..32]).try_into().unwrap();

    ed25519_key_exchange(&mut shared_secret, &other_public_key, sk_a);
    ed25519_key_exchange(&mut other_shared_secret, &public_key, sk_b);

    assert_eq!(
        shared_secret, other_shared_secret,
        "key exchange secrets must match"
    );
}
