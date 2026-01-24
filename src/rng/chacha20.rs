//! ChaCha20 core implementation
//!
//! This module provides a low-level, dependency-free implementation of the
//! ChaCha20 block function as specified in RFC 8439.
//!
//! It is designed to be used as a cryptographic primitive inside the Nebula
//! ecosystem (e.g. Kadnet, secure channels, AEAD constructions), and therefore:
//! - avoids heap allocations
//! - runs in constant time
//! - exposes only minimal, explicit APIs
//!
//! This module **does not** implement authenticated encryption by itself.
//! It only generates a single 64-byte ChaCha20 keystream block.
//! Higher-level constructions (such as ChaCha20-Poly1305) must be built
//! on top of this primitive with strict nonce and key management.

/// ChaCha20 constant words.
///
/// These values correspond to the ASCII string:
/// `"expand 32-byte k"` encoded as little-endian `u32` words, as defined
/// in RFC 8439.
///
/// They are public, fixed, and non-secret, and define the ChaCha20
/// permutation domain.
const CHACHA20_CONSTANTS: [u32; 4] = [
    0x6170_7865, // "expa"
    0x3320_646e, // "nd 3"
    0x7962_2d32, // "2-by"
    0x6b20_6574, // "te k"
];

/// Performs one ChaCha20 quarter round.
///
/// A quarter round mixes four 32-bit words of the internal state using
/// addition modulo 2³², XOR, and fixed left rotations. This operation is
/// the fundamental source of diffusion and non-linearity in ChaCha20.
///
/// The function is branchless and runs in constant time.
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Applies the full ChaCha20 permutation (20 rounds).
///
/// The permutation consists of 10 iterations, each performing:
/// - 4 column quarter rounds
/// - 4 diagonal quarter rounds
///
/// This results in a total of 20 rounds, which is the standard and
/// conservative security setting for ChaCha20.
pub fn rounds(state: &mut [u32; 16]) {
    for _ in 0..10 {
        // Column rounds
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);

        // Diagonal rounds
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

/// Generates a single 64-byte ChaCha20 keystream block.
///
/// # Parameters
/// - `key`: 256-bit secret key (32 bytes)
/// - `counter`: 32-bit block counter
/// - `nonce`: 96-bit nonce (IETF variant)
///
/// # Returns
/// A 64-byte keystream block that can be XORed with plaintext or ciphertext.
///
/// # Security Notes
/// - This function does **not** perform encryption or authentication.
/// - Reusing the same `(key, nonce, counter)` tuple is catastrophic for
///   security and must be prevented by higher-level protocols.
pub(crate) fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    // Initialize the ChaCha20 state
    let mut state = [0u32; 16];

    // Constants
    state[0..4].copy_from_slice(&CHACHA20_CONSTANTS);

    // Key (256-bit, as little-endian words)
    state[4..12]
        .iter_mut()
        .zip(key.chunks_exact(4))
        .for_each(|(s, k)| {
            *s = u32::from_le_bytes(k.try_into().unwrap());
        });

    // Block counter
    state[12] = counter;

    // Nonce (96-bit, little-endian)
    state[13..16]
        .iter_mut()
        .zip(nonce.chunks_exact(4))
        .for_each(|(s, n)| {
            *s = u32::from_le_bytes(n.try_into().unwrap());
        });

    // Preserve original state for feed-forward
    let original = state;

    // Apply ChaCha20 permutation
    rounds(&mut state);

    // Add original state (feed-forward)
    state.iter_mut().zip(&original).for_each(|(s, o)| {
        *s = s.wrapping_add(*o);
    });

    // Serialize output as little-endian bytes
    let mut out = [0u8; 64];
    out.chunks_exact_mut(4)
        .zip(&state)
        .for_each(|(chunk, word)| {
            chunk.copy_from_slice(&word.to_le_bytes());
        });

    out
}

/// XORs input data with the ChaCha20 keystream.
///
/// This function implements the ChaCha20 stream cipher by generating
/// successive 64-byte keystream blocks and XORing them with the input.
///
/// # Parameters
/// - `key`: 256-bit secret key (32 bytes)
/// - `nonce`: 96-bit nonce (IETF variant)
/// - `counter`: Initial 32-bit block counter
/// - `input`: Plaintext or ciphertext input
/// - `output`: Output buffer (must be the same length as `input`)
///
/// # Notes
/// - Encryption and decryption are identical operations.
/// - This function performs no authentication.
/// - The caller must ensure `(key, nonce)` uniqueness.
pub(crate) fn xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), output.len());

    let mut block_counter = counter;
    let mut offset = 0usize;

    while offset < input.len() {
        // Generate keystream block
        let keystream = block(key, block_counter, nonce);
        block_counter = block_counter.wrapping_add(1);

        // XOR keystream with input
        let remaining = input.len() - offset;
        let take = remaining.min(64);

        for i in 0..take {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }

        offset += take;
    }
}
