use super::H256_INIT;
use super::computations::all_rounds;
use crate::primitives::U256;

use core::ptr::{copy_nonoverlapping, read_unaligned};

#[inline(always)]
pub fn compress(block: &[u8; 64], state: &mut [u32; 8]) {
    let mut w = [0u32; 16];

    for (i, slot) in w.iter_mut().enumerate().take(16) {
        let ptr = unsafe { block.as_ptr().add(i * 4) as *const u32 };

        *slot = u32::from_be(unsafe { read_unaligned(ptr) });
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
        let block: &[u8; 64] = unsafe { &*(input.as_ptr().add(i) as *const [u8; 64]) };
        compress(block, &mut state);

        i += 64;
    }

    let mut block = [0u8; 64];
    let rem = len - i;

    unsafe {
        let src = input.as_ptr().add(i);
        let dst = block.as_mut_ptr();

        copy_nonoverlapping(src, dst, rem);

        *block.as_mut_ptr().add(rem) = 0x80;
    }

    if rem > 55 {
        compress(&block, &mut state);
        block = [0; 64];
    }

    let bit_len = (len as u64) << 3;
    let len_bytes = bit_len.to_be_bytes();

    unsafe {
        let src = len_bytes.as_ptr();
        let dst = block.as_mut_ptr().add(56);

        copy_nonoverlapping(src, dst, 8);
    }

    compress(&block, &mut state);

    U256::from(state)
}
