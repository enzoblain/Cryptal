//! SHA-512 core hashing functions
//!
//! This module implements the core logic of the SHA-512 cryptographic hash
//! function as defined in FIPS 180-4.
//!
//! It provides:
//! - the compression function operating on 1024-bit blocks
//! - a complete SHA-512 hashing function for arbitrary-length input
//!
//! The implementation is intentionally minimal, explicit, and designed
//! for use as a low-level primitive within the Nebula ecosystem.

use crate::hash::sha512::H512_INIT;
use crate::hash::sha512::computations::all_rounds;

/// Compresses a single 1024-bit message block.
///
/// This function performs the SHA-512 compression step on a single
/// 128-byte block, updating the internal hash state in place.
///
/// # Parameters
/// - `block`: A 1024-bit (128-byte) message block
/// - `state`: The current hash state (8 × 64-bit words)
///
/// # Notes
/// - The message schedule is partially expanded here and fully processed
///   by `all_rounds`.
/// - Input words are interpreted as big-endian, as required by SHA-512.
pub fn compress(block: &[u8; 128], state: &mut [u64; 8]) {
    // Message schedule (first 16 words)
    let mut w = [0u64; 16];

    for (slot, chunk) in w.iter_mut().zip(block.chunks_exact(8)).take(16) {
        *slot = u64::from_be_bytes(chunk.try_into().unwrap());
    }

    // Apply all SHA-512 rounds
    all_rounds(state, w);
}

/// Computes the SHA-512 hash of the given input.
///
/// This function processes the input message in 1024-bit blocks, applies
/// the SHA-512 padding rules, and returns the final 512-bit hash value.
///
/// # Parameters
/// - `input`: Arbitrary-length input message
///
/// # Returns
/// - The final SHA-512 hash as 64 bytes (`[u8; 64]`)
///
/// # Notes
/// - The implementation follows the standard Merkle–Damgård construction.
/// - Message length is encoded as a 128-bit big-endian integer (in bits).
/// - The internal state uses 8 × 64-bit words and is serialized in big-endian.
/// - No heap allocations are performed.
pub fn sha512(input: &[u8]) -> [u8; 64] {
    // Initialize hash state
    let mut state = H512_INIT;

    let mut i = 0;
    let len = input.len();

    // Process full 1024-bit blocks
    while i + 128 <= len {
        let block: &[u8; 128] = input[i..i + 128].try_into().unwrap();
        compress(block, &mut state);
        i += 128;
    }

    // Prepare final padded block(s)
    let mut block = [0u8; 128];
    let rem = len - i;

    // Copy remaining bytes and append the padding bit (0x80)
    block[..rem].copy_from_slice(&input[i..]);
    block[rem] = 0x80;

    // If there is not enough space for the 128-bit length field,
    // process this block and use an additional zeroed block.
    if rem > 111 {
        compress(&block, &mut state);
        block = [0; 128];
    }

    // Append the message length in bits as a 128-bit big-endian integer
    let bit_len = (len as u128) << 3;
    block[112..128].copy_from_slice(&bit_len.to_be_bytes());

    // Final compression
    compress(&block, &mut state);

    // Serialize final state into big-endian bytes
    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }

    out
}
