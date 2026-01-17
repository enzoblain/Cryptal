//! SHA-256 core hashing functions
//!
//! This module implements the core logic of the SHA-256 cryptographic hash
//! function as defined in FIPS 180-4.
//!
//! It provides:
//! - the compression function operating on 512-bit blocks
//! - a complete SHA-256 hashing function for arbitrary-length input
//!
//! The implementation is designed to be minimal, explicit, and suitable
//! for use as a low-level primitive within the Nebula ecosystem.

use crate::hash::sha256::H256_INIT;
use crate::hash::sha256::computations::all_rounds;
use crate::primitives::U256;

/// Compresses a single 512-bit message block.
///
/// This function performs the SHA-256 compression step on a single
/// 64-byte block, updating the internal hash state in place.
///
/// # Parameters
/// - `block`: A 512-bit (64-byte) message block
/// - `state`: The current hash state (8 × 32-bit words)
///
/// # Notes
/// - The message schedule is partially expanded here and fully processed
///   by `all_rounds`.
/// - Input words are interpreted as big-endian, as required by SHA-256.
pub fn compress(block: &[u8; 64], state: &mut [u32; 8]) {
    // Message schedule (first 16 words)
    let mut w = [0u32; 16];

    for (slot, chunk) in w.iter_mut().zip(block.chunks_exact(4)).take(16) {
        *slot = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    // Apply all SHA-256 rounds
    all_rounds(state, w);
}

/// Computes the SHA-256 hash of the given input.
///
/// This function processes the input message in 512-bit blocks, applies
/// the SHA-256 padding rules, and returns the final 256-bit hash value.
///
/// # Parameters
/// - `input`: Arbitrary-length input message
///
/// # Returns
/// A 256-bit hash value represented as a `U256`.
///
/// # Notes
/// - The implementation follows the standard Merkle–Damgård construction.
/// - Message length is encoded as a 64-bit big-endian integer (in bits).
/// - No heap allocations are performed.
pub fn sha256(input: &[u8]) -> U256 {
    // Initialize hash state
    let mut state = H256_INIT;

    let mut i = 0;
    let len = input.len();

    // Process full 512-bit blocks
    while i + 64 <= len {
        let block: &[u8; 64] = input[i..i + 64].try_into().unwrap();
        compress(block, &mut state);
        i += 64;
    }

    // Prepare final padded block(s)
    let mut block = [0u8; 64];
    let rem = len - i;

    // Copy remaining bytes and append the padding bit (0x80)
    block[..rem].copy_from_slice(&input[i..]);
    block[rem] = 0x80;

    // If there is not enough space for the length field, process this block
    // and use an additional zeroed block.
    if rem > 55 {
        compress(&block, &mut state);
        block = [0; 64];
    }

    // Append the message length in bits as a 64-bit big-endian integer
    let bit_len = (len as u64) << 3;
    let len_bytes = bit_len.to_be_bytes();
    block[56..64].copy_from_slice(&len_bytes);

    // Final compression
    compress(&block, &mut state);

    // Convert final state into a 256-bit value
    U256::from(state)
}
