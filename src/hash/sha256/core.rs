use super::H256_INIT;
use super::computations::all_rounds;
use crate::primitives::U256;

#[inline(always)]
pub fn compress(block: &[u8; 64], state: &mut [u32; 8]) {
    let mut w = [0u32; 64];

    for i in 0..16 {
        let bytes = &block[i * 4..i * 4 + 4];
        w[i] = u32::from_be_bytes(bytes.try_into().unwrap());
    }

    #[cfg(not(feature = "speed"))]
    all_rounds(state, w);

    #[cfg(feature = "speed")]
    all_rounds(state, &mut w);
}

pub fn sha256(input: &[u8]) -> U256 {
    let mut state = H256_INIT;

    let mut i = 0;
    let len = input.len();

    while i + 64 <= len {
        let block = input[i..i + 64].try_into().unwrap();
        compress(block, &mut state);
        i += 64;
    }

    let mut block = [0u8; 64];
    let rem = len - i;

    block[..rem].copy_from_slice(&input[i..]);
    block[rem] = 0x80;

    if rem > 55 {
        compress(&block, &mut state);
        block = [0; 64];
    }

    let bit_len = (len as u64) << 3;
    block[56..].copy_from_slice(&bit_len.to_be_bytes());

    compress(&block, &mut state);

    U256::from(state)
}
