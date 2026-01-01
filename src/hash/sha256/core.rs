use crate::hash::sha256::H256_INIT;
use crate::hash::sha256::computations::all_rounds;

use crate::primitives::U256;

pub fn compress(block: &[u8; 64], state: &mut [u32; 8]) {
    let mut w = [0u32; 16];

    for (slot, chunk) in w.iter_mut().zip(block.chunks_exact(4)).take(16) {
        *slot = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    all_rounds(state, w);
}

pub fn sha256(input: &[u8]) -> U256 {
    let mut state = H256_INIT;

    let mut i = 0;
    let len = input.len();

    while i + 64 <= len {
        let block: &[u8; 64] = input[i..i + 64].try_into().unwrap();
        compress(block, &mut state);
        i += 64;
    }

    let mut block = [0u8; 64];
    let rem = len - i;

    // Copy remaining bytes and add padding bit
    block[..rem].copy_from_slice(&input[i..]);
    block[rem] = 0x80; // SHA-256 padding bit

    if rem > 55 {
        // Need extra block for message length
        compress(&block, &mut state);
        block = [0; 64];
    }

    let bit_len = (len as u64) << 3; // Convert bytes to bits
    let len_bytes = bit_len.to_be_bytes();

    // Insert message length in the last 8 bytes
    block[56..64].copy_from_slice(&len_bytes);

    compress(&block, &mut state);

    U256::from(state)
}
