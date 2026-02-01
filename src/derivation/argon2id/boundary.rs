//! Initialization and finalization for Argon2.
//!
//! This module handles the boundary operations of the Argon2 algorithm:
//! computing the initial hash H0 from all inputs, and deriving the final
//! tag from the filled memory.

use super::block::Block;
use super::params::Argon2Params;
use crate::hash::{blake2b, blake2b_long};

/// Argon2 version 1.3 (0x13 in little-endian).
const ARGON2_VERSION: u32 = 0x13;

/// Computes the initial hash H0 from all Argon2 inputs.
///
/// H0 is a 64-byte BLAKE2b hash of the concatenation of all parameters
/// and inputs, each prefixed with its length. This ensures that all
/// inputs influence the entire computation and provides domain separation.
///
/// The input format is defined in RFC 9106 §3.2:
/// ```text
/// H0 = BLAKE2b(p || T || m || t || v || y || |P| || P || |S| || S || |K| || K || |X| || X)
/// ```
pub(crate) fn init(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
    mem_kib_rounded: u32,
) -> [u8; 64] {
    let mut buf = Vec::new();

    buf.extend_from_slice(&params.lanes.to_le_bytes());
    buf.extend_from_slice(&(params.tag_len as u32).to_le_bytes());
    buf.extend_from_slice(&mem_kib_rounded.to_le_bytes());
    buf.extend_from_slice(&params.time.to_le_bytes());
    buf.extend_from_slice(&ARGON2_VERSION.to_le_bytes());
    buf.extend_from_slice(&2u32.to_le_bytes()); // type = Argon2id

    buf.extend_from_slice(&(password.len() as u32).to_le_bytes());
    buf.extend_from_slice(password);

    buf.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    buf.extend_from_slice(salt);

    if let Some(ref secret) = params.secret {
        buf.extend_from_slice(&(secret.len() as u32).to_le_bytes());
        buf.extend_from_slice(secret);
    } else {
        buf.extend_from_slice(&0u32.to_le_bytes());
    }

    if let Some(ref ad) = params.associated_data {
        buf.extend_from_slice(&(ad.len() as u32).to_le_bytes());
        buf.extend_from_slice(ad);
    } else {
        buf.extend_from_slice(&0u32.to_le_bytes());
    }

    blake2b(64, &buf)
}

/// Finalizes the Argon2 computation to produce the output tag.
///
/// The finalization XORs together the last block of each lane (forming
/// a single 1024-byte block), then applies the variable-length hash
/// function H' to produce the final tag of the requested length.
///
/// This construction ensures that all lanes contribute to the final
/// output, preventing attackers from skipping lane computations.
pub(crate) fn finalize(memory: &[Block], lanes: u32, lane_len: u32, tag_len: usize) -> Vec<u8> {
    let mut final_block = Block::ZERO;

    for lane in 0..lanes {
        let last_block_idx = ((lane + 1) * lane_len - 1) as usize;
        final_block.in_place_xor(&memory[last_block_idx]);
    }

    blake2b_long(tag_len, &final_block.to_bytes())
}
