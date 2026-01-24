//! ChaCha20-Poly1305 authenticated encryption (RFC 8439).
//!
//! This module implements the ChaCha20-Poly1305 AEAD construction as specified
//! in RFC 8439. It combines:
//!
//! - ChaCha20 as a stream cipher for confidentiality
//! - Poly1305 as a one-time MAC for authentication
//!
//! ## Design goals
//!
//! - Dependency-free
//! - Constant-time authentication check
//! - Explicit nonce and key management
//! - Clear separation between cipher and MAC
//!
//! ## Notes
//!
//! - This implementation currently uses an empty AAD (`AAD = []`).
//! - The caller must ensure `(key, nonce)` uniqueness.
//! - Reusing a `(key, nonce)` pair breaks security.

use super::mac::Poly1305;
use crate::rng::chacha20::{block, xor};

/// Additional Authenticated Data (AAD).
///
/// This data is authenticated but not encrypted.
/// It is currently empty, but the construction fully supports AAD.
///
/// In a production API, this should be provided by the caller.
const AAD: &[u8] = &[];

/// Errors that can occur during ChaCha20-Poly1305 decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chacha20Poly1305Error {
    /// The input and output buffers have mismatched lengths.
    InvalidLength,
    /// The authentication tag verification failed.
    AuthenticationFailed,
}

/// Encrypts and authenticates a message using ChaCha20-Poly1305.
///
/// # Parameters
///
/// - `key`: 256-bit secret key
/// - `nonce`: 96-bit nonce (IETF variant)
/// - `plaintext`: Input message to encrypt
/// - `ciphertext`: Output buffer for encrypted data (same length as `plaintext`)
/// - `tag`: Output authentication tag (16 bytes)
///
/// # Panics
///
/// Panics if `plaintext.len() != ciphertext.len()`.
///
/// # Algorithm
///
/// 1. Derive the Poly1305 one-time key using `ChaCha20(key, nonce, counter = 0)`
/// 2. Encrypt the plaintext using ChaCha20 starting at counter = 1
/// 3. Construct the MAC input:
///    - AAD || pad16
///    - ciphertext || pad16
///    - len(AAD) || len(ciphertext)
/// 4. Compute the Poly1305 authentication tag
///
/// # Security Notes
///
/// - This function does not allocate secret material on the heap except
///   for the MAC buffer.
/// - `(key, nonce)` MUST be unique per encryption.
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) {
    assert_eq!(plaintext.len(), ciphertext.len());

    // Generate one-time key for Poly1305
    let block0 = block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // Encrypt plaintext (ChaCha20 is symmetric)
    xor(key, nonce, 1, plaintext, ciphertext);

    // Build MAC input according to RFC 8439
    let mut mac_data = Vec::new();

    mac_data.extend_from_slice(AAD);
    pad16(&mut mac_data);

    mac_data.extend_from_slice(ciphertext);
    pad16(&mut mac_data);

    mac_data.extend_from_slice(&(AAD.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    // Compute authentication tag
    auth(tag, &otk, &mac_data);
}

/// Decrypts and authenticates a message using ChaCha20-Poly1305.
///
/// # Parameters
///
/// - `key`: 256-bit secret key
/// - `nonce`: 96-bit nonce (IETF variant)
/// - `ciphertext`: Encrypted input data
/// - `tag`: Authentication tag to verify
/// - `plaintext`: Output buffer for decrypted data
///
/// # Returns
///
/// - `Ok(())` if authentication succeeds and decryption is successful
/// - `Err(InvalidLength)` if buffer sizes mismatch
/// - `Err(AuthenticationFailed)` if tag verification fails
///
/// # Algorithm
///
/// 1. Recompute the Poly1305 one-time key
/// 2. Rebuild the MAC input exactly as in `encrypt`
/// 3. Verify the authentication tag in constant time
/// 4. Decrypt the ciphertext if authentication succeeds
///
/// # Security Notes
///
/// - Decryption is only performed after successful authentication
/// - Tag comparison is constant-time
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext: &mut [u8],
) -> Result<(), Chacha20Poly1305Error> {
    if plaintext.len() != ciphertext.len() {
        return Err(Chacha20Poly1305Error::InvalidLength);
    }

    let block0 = block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    let mut mac_data = Vec::new();

    mac_data.extend_from_slice(AAD);
    pad16(&mut mac_data);

    mac_data.extend_from_slice(ciphertext);
    pad16(&mut mac_data);

    mac_data.extend_from_slice(&(AAD.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let mut expected_tag = [0u8; 16];
    auth(&mut expected_tag, &otk, &mac_data);

    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ tag[i];
    }

    otk.fill(0);

    if diff != 0 {
        return Err(Chacha20Poly1305Error::AuthenticationFailed);
    }

    xor(key, nonce, 1, ciphertext, plaintext);
    Ok(())
}

/// Pads a buffer with zero bytes until its length is a multiple of 16.
///
/// This is required by the Poly1305 input format defined in RFC 8439.
#[inline(always)]
fn pad16(buf: &mut Vec<u8>) {
    let rem = buf.len() % 16;
    if rem != 0 {
        buf.resize(buf.len() + (16 - rem), 0);
    }
}

/// Computes a Poly1305 authentication tag.
///
/// # Parameters
///
/// - `tag`: Output tag (16 bytes)
/// - `one_time_key`: 256-bit Poly1305 key derived from ChaCha20
/// - `msg`: Message to authenticate
///
/// # Notes
///
/// - The message is processed in 16-byte blocks
/// - The Poly1305 instance must not be reused
pub fn auth(tag: &mut [u8; 16], one_time_key: &[u8; 32], msg: &[u8]) {
    let mut mac = Poly1305::new(one_time_key);

    for chunk in msg.chunks(16) {
        mac.update_block(chunk);
    }

    *tag = mac.finalize();
}
