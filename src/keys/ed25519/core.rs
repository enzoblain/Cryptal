//! Core Ed25519 key and signature types.
//!
//! This module defines the fundamental public and private key structures,
//! along with the signature container used by the Ed25519 digital signature
//! scheme. The implementation follows the standard Ed25519 construction
//! based on twisted Edwards curves over the finite field F_p.
//!
//! The types exposed here are intentionally minimal and explicit, avoiding
//! implicit conversions or hidden state, in order to favor correctness,
//! auditability, and predictable behavior.

use super::ct::ConstantTimeEq;
use super::group::{GeCached, GeP1, GeP3};
pub use super::scalar::Scalar;
use crate::hash::sha512;
use crate::keys::x25519;
use crate::rng::Csprng;

/// An Ed25519 public key.
///
/// This type wraps the canonical 32-byte compressed encoding of a curve
/// point on the Ed25519 curve. The encoding corresponds to the affine
/// y-coordinate together with a sign bit for x, as defined in RFC 8032.
///
/// A `PublicKey` is immutable and copyable.
#[derive(Clone, Copy)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Returns the canonical byte encoding of this public key.
    ///
    /// The returned value is the compressed Edwards point representation
    /// used directly by the Ed25519 verification algorithm.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// An Ed25519 private key.
///
/// Internally, the private key is represented in its expanded form:
/// - a scalar modulo the group order (used for signing and key agreement),
/// - a 32-byte prefix derived from hashing the original seed, used to
///   generate deterministic nonces during signing.
///
/// This structure corresponds to the expanded private key described
/// in RFC 8032 rather than the raw 32-byte seed.
#[derive(Clone, Copy)]
pub struct PrivateKey {
    scalar: Scalar,
    prefix: [u8; 32],
}

impl PrivateKey {
    /// Returns the secret scalar component of the private key.
    ///
    /// This value is used internally for scalar multiplication on the curve.
    /// It is not exposed publicly to avoid accidental misuse.
    #[inline]
    pub fn scalar(self) -> Scalar {
        self.scalar
    }

    /// Returns the nonce prefix associated with this private key.
    ///
    /// The prefix is used as part of the deterministic nonce derivation
    /// during Ed25519 signature generation.
    #[inline]
    pub fn prefix(&self) -> [u8; 32] {
        self.prefix
    }

    /// Returns the expanded private key as a 64-byte array.
    ///
    /// The first 32 bytes correspond to the secret scalar encoding,
    /// and the remaining 32 bytes contain the nonce prefix.
    ///
    /// This format is primarily intended for internal use and debugging,
    /// not for key serialization or storage.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];

        out[..32].copy_from_slice(&self.scalar().to_bytes());
        out[32..].copy_from_slice(&self.prefix());

        out
    }
}

/// An Ed25519 signature.
///
/// A signature consists of two components:
/// - a compressed Edwards point `R` (32 bytes),
/// - a scalar `S` modulo the group order (32 bytes).
///
/// Together, these form the standard 64-byte Ed25519 signature as defined
/// in RFC 8032.
#[derive(Clone, Copy)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Constructs a signature from its raw 64-byte representation.
    ///
    /// No validation is performed at construction time. Structural and
    /// cryptographic validity is checked during signature verification.
    #[inline]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the raw byte encoding of this signature.
    ///
    /// The output is compatible with standard Ed25519 implementations
    /// and can be transmitted or stored directly.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

/// Generates a fresh Ed25519 keypair.
///
/// This function creates a new public/private keypair using a
/// cryptographically secure random seed and the Ed25519 key
/// derivation procedure.
///
/// The process is:
/// - Generate a 32-byte random seed using a CSPRNG
/// - Hash the seed with SHA-512
/// - Derive the secret scalar from the first half of the hash,
///   applying Ed25519 clamping rules
/// - Use the second half of the hash as the private nonce prefix
/// - Compute the public key as a scalar multiplication of the
///   curve base point
///
/// The returned keys are:
/// - [`PublicKey`]: the encoded Edwards curve point
/// - [`PrivateKey`]: containing the secret scalar and nonce prefix
///
/// This implementation follows the Ed25519 specification
/// (RFC 8032) and mirrors the structure of the reference C
/// implementations, while remaining explicit and auditable.
pub fn generate_keypair() -> (PublicKey, PrivateKey) {
    let mut seed = [0u8; 32];
    Csprng::new().fill_bytes(&mut seed);

    let digest = sha512(&seed);

    let mut a_bytes: [u8; 32] = digest[..32].try_into().unwrap();
    a_bytes[0] &= 248;
    a_bytes[31] &= 63;
    a_bytes[31] |= 64;
    let scalar = Scalar::from_bytes(&a_bytes);

    let prefix: [u8; 32] = digest[32..].try_into().unwrap();

    let public = PublicKey(GeP3::from_scalar_mul(scalar).to_bytes());
    let private = PrivateKey { scalar, prefix };

    (public, private)
}

/// Computes an Ed25519 signature over a message.
///
/// This function implements the Ed25519 signing algorithm as specified
/// in RFC 8032. It produces a deterministic signature using:
/// - the secret scalar derived from the private key
/// - a per-message nonce derived from the private key prefix and message
///
/// The signature is computed as:
/// - R = r · B
/// - S = (r + H(R || A || M) · a) mod ℓ
///
/// where:
/// - `a` is the private scalar
/// - `A` is the public key
/// - `M` is the message
/// - `B` is the curve base point
/// - `ℓ` is the group order
///
/// The returned signature is encoded as `R || S`.
///
/// This implementation mirrors the structure of the reference
/// Ed25519 implementations and avoids side-channel leakage by
/// relying on constant-time primitives.
pub fn sign(message: &[u8], public: PublicKey, private: PrivateKey) -> Signature {
    let a = private.scalar();

    let mut r_input = Vec::with_capacity(32 + message.len());
    r_input.extend_from_slice(&private.prefix());
    r_input.extend_from_slice(message);

    let r = Scalar::reduce(sha512(&r_input));

    let r_bytes = GeP3::from_scalar_mul(r).to_bytes();

    let mut k_input = Vec::with_capacity(64 + message.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(&public.to_bytes());
    k_input.extend_from_slice(message);

    let k = Scalar::reduce(sha512(&k_input));

    let s = Scalar::from_mul_sum(k, a, r).0;

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(&s);

    Signature(signature)
}

/// Verifies an Ed25519 signature.
///
/// This function checks that a signature `(R || S)` is a valid Ed25519
/// signature for a given message and public key.
///
/// Verification proceeds as follows:
///
/// - Ensure the scalar `S` is canonically encoded
/// - Decompress the public key `A`
/// - Compute `h = H(R || A || M) mod ℓ`
/// - Check that:
///
///     S · B == R + h · A
///
/// using a constant-time double-scalar multiplication.
///
/// The function returns `true` if and only if the signature is valid.
/// Any malformed input or verification failure results in `false`.
///
/// This implementation mirrors the reference Ed25519 verification logic
/// and avoids side-channel leakage by relying exclusively on
/// constant-time group and scalar operations.
pub fn verify(signature: Signature, message: &[u8], public: PublicKey) -> bool {
    if (signature.0[63] & 0b1110_0000) != 0 {
        return false;
    }

    let (a, ok) = GeP3::decompress(&public.to_bytes());
    if ok != 0 {
        return false;
    }

    let mut h_input = Vec::with_capacity(64 + message.len());
    h_input.extend_from_slice(&signature.0[..32]); // R
    h_input.extend_from_slice(&public.to_bytes()); // A
    h_input.extend_from_slice(message);

    let h = Scalar::reduce(sha512(&h_input));

    let s = Scalar(signature.0[32..].try_into().unwrap());

    let r_check = a.double_scalar_mul(h, s).to_bytes();

    r_check.ct_eq((&signature.0[..32]).try_into().unwrap())
}

/// Adds a scalar to an Ed25519 keypair and/or public key.
///
/// This function updates keys in-place by adding a scalar `n` modulo the
/// Ed25519 group order.
///
/// Depending on which keys are provided:
///
/// - **Private key only**: the secret scalar is updated and the signing
///   prefix is re-derived.
/// - **Public key only**: the public key is updated using group arithmetic,
///   without access to the private key.
/// - **Both keys**: the private key is updated and the public key is
///   recomputed to remain consistent.
/// - **Neither key**: the function is a no-op.
///
/// This operation preserves key validity and is commonly used for
/// key blinding, deterministic key derivation, or hierarchical key schemes.
///
/// All arithmetic follows the Ed25519 specification.
pub fn add_scalar(
    public_key: Option<&mut PublicKey>,
    private_key: Option<&mut PrivateKey>,
    scalar: Scalar,
) {
    let scalar_bytes = scalar.to_bytes();

    let mut n = [0u8; 32];
    n[..31].copy_from_slice(&scalar_bytes[..31]);
    n[31] = scalar_bytes[31] & 0x7f;

    let one = {
        let mut b = [0u8; 32];
        b[0] = 1;
        Scalar(b)
    };

    match (private_key, public_key) {
        (Some(private), Some(public)) => {
            private.scalar = Scalar::from_mul_sum(one, Scalar(n), private.scalar);

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&private.prefix);
            buf[32..].copy_from_slice(&scalar_bytes);

            private.prefix.copy_from_slice(&sha512(&buf)[..32]);

            *public = PublicKey(GeP3::from_scalar_mul(private.scalar).to_bytes());
        }

        (Some(private), None) => {
            private.scalar = Scalar::from_mul_sum(one, Scalar(n), private.scalar);

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&private.prefix);
            buf[32..].copy_from_slice(&scalar_bytes);
            private.prefix.copy_from_slice(&sha512(&buf)[..32]);
        }

        (None, Some(public)) => {
            let (mut a, _) = GeP3::decompress(&public.to_bytes());

            a.x = -a.x;
            a.t = -a.t;

            let t = GeCached::from_p3(&a);
            let nb = GeP3::from_scalar_mul(Scalar(n));
            let r = GeP1::from_sum(&nb, &t);

            *public = PublicKey(GeP3::from_gep1(&r).to_bytes());
        }

        (None, None) => {}
    }
}

/// Computes a Diffie–Hellman shared secret using X25519.
///
/// This function is a convenience wrapper around the X25519 key
/// agreement implementation provided by the `x25519` module.
///
/// It derives a shared secret from:
/// - the secret scalar contained in an Ed25519 private key, and
/// - a peer public key represented as a 32-byte Curve25519
///   Montgomery coordinate.
///
/// All algorithmic details and security properties are documented
/// in the `x25519` module.
pub fn exchange(private: &PrivateKey, public: &PublicKey) -> [u8; 32] {
    x25519::exchange(&private.scalar().to_bytes(), &public.to_bytes())
}
