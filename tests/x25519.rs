use cryptal::keys::ed25519::generate_keypair;
use cryptal::keys::x25519::exchange;

#[test]
fn test_x25519_key_exchange() {
    let (alice_public, alice_private) = generate_keypair();
    let (bob_public, bob_private) = generate_keypair();

    let alice_shared = exchange(&alice_private.scalar().to_bytes(), &bob_public.to_bytes());
    let bob_shared = exchange(&bob_private.scalar().to_bytes(), &alice_public.to_bytes());

    assert_eq!(alice_shared, bob_shared);
}
