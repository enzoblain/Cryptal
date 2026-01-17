const CHACHA20_CONSTANTS: [u32; 4] = [
    0x6170_7865, // "expa"
    0x3320_646e, // "nd 3"
    0x7962_2d32, // "2-by"
    0x6b20_6574, // "te k"
];

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

fn chacha20_rounds(state: &mut [u32; 16]) {
    for _ in 0..10 {
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);

        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

pub(crate) fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];

    state[0..4].copy_from_slice(&CHACHA20_CONSTANTS);
    state[4..12]
        .iter_mut()
        .zip(key.chunks_exact(4))
        .for_each(|(s, k)| *s = u32::from_le_bytes(k.try_into().unwrap()));
    state[12] = counter;
    state[13..16]
        .iter_mut()
        .zip(nonce.chunks_exact(4))
        .for_each(|(s, n)| *s = u32::from_le_bytes(n.try_into().unwrap()));

    let original = state;

    chacha20_rounds(&mut state);

    state
        .iter_mut()
        .zip(&original)
        .for_each(|(s, o)| *s = s.wrapping_add(*o));

    let mut out = [0u8; 64];
    out.chunks_exact_mut(4)
        .zip(&state)
        .for_each(|(c, &w)| c.copy_from_slice(&w.to_le_bytes()));

    out
}
