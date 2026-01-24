use cryptal::signatures::Ed25519::{
    Scalar, Signature, add_scalar, exchange, generate_keypair, sign, verify,
};

#[test]
fn test_sign_and_verify() {
    let message = b"Hello, world!";

    let (public, private) = generate_keypair();

    let mut signature = sign(message, public, private);
    assert!(verify(signature, message, public));

    let mut bytes = signature.to_bytes();
    bytes[44] ^= 0x10;
    signature = Signature::from_bytes(bytes);

    assert!(!verify(signature, message, public));
}

#[test]
fn test_add_scalar_keeps_valid_signatures() {
    let message = b"Hello, world!";

    let (mut public, mut private) = generate_keypair();
    let scalar = Scalar::from_bytes(&[42u8; 32]);

    let sig_before = sign(message, public, private);
    assert!(verify(sig_before, message, public));

    add_scalar(Some(&mut public), Some(&mut private), scalar);

    let sig_after = sign(message, public, private);
    assert!(verify(sig_after, message, public));

    assert_ne!(sig_before.to_bytes(), sig_after.to_bytes());
}

#[test]
fn test_key_exchange() {
    let (alice_public, alice_private) = generate_keypair();
    let (bob_public, bob_private) = generate_keypair();

    let alice_shared = exchange(&alice_private, &bob_public);
    let bob_shared = exchange(&bob_private, &alice_public);

    assert_eq!(alice_shared, bob_shared);
}
