//! Block operations for Argon2.
//!
//! This module defines the fundamental 1024-byte block structure and the
//! compression function G that forms the core of the Argon2 algorithm.
//! The compression function is based on the BLAKE2b round function but
//! uses additional multiplication operations for enhanced diffusion.

/// A 1024-byte memory block (128 × 64-bit words).
///
/// Blocks are the fundamental unit of memory in Argon2. The algorithm
/// operates by filling and mixing these blocks using the compression
/// function G. Each block is zeroed on drop for security.
#[derive(Debug, Clone)]
pub struct Block(pub [u64; 128]);

impl Block {
    pub(crate) const ZERO: Self = Self([0u64; 128]);

    pub(crate) fn in_place_xor(&mut self, other: &Block) {
        self.0
            .iter_mut()
            .zip(other.0.iter())
            .for_each(|(a, b)| *a ^= b);
    }

    pub(crate) fn from_bytes(bytes: [u8; 1024]) -> Self {
        let words = core::array::from_fn(|i| {
            let start = i * 8;
            u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap())
        });
        Block(words)
    }

    pub(crate) fn to_bytes(&self) -> [u8; 1024] {
        let mut out = [0u8; 1024];
        self.0.iter().enumerate().for_each(|(i, word)| {
            let start = i * 8;
            out[start..start + 8].copy_from_slice(&word.to_le_bytes());
        });
        out
    }

    /// Compression function G (RFC 9106 §3.5).
    ///
    /// Computes G(X, Y) = P(P(X ⊕ Y)) ⊕ X ⊕ Y, where P is a permutation
    /// based on the BLAKE2b round function. The permutation is applied
    /// twice: first on rows of 16 words, then on columns.
    ///
    /// This function provides the mixing that gives Argon2 its security
    /// properties. The XOR at the end ensures that information from both
    /// input blocks propagates to the output.
    pub(crate) fn compress(x: &Self, y: &Self) -> Self {
        let mut r = Block::ZERO;
        for i in 0..128 {
            r.0[i] = x.0[i] ^ y.0[i];
        }

        let mut z = r.clone();

        // First pass: P on 8 groups of 16 consecutive words
        for i in 0..8 {
            let base = 16 * i;
            let mut v: [u64; 16] = z.0[base..base + 16].try_into().unwrap();
            permute_p(&mut v);
            z.0[base..base + 16].copy_from_slice(&v);
        }

        // Second pass: P on 8 groups with interleaved indices
        for i in 0..8 {
            let mut v = [
                z.0[2 * i],
                z.0[2 * i + 1],
                z.0[2 * i + 16],
                z.0[2 * i + 17],
                z.0[2 * i + 32],
                z.0[2 * i + 33],
                z.0[2 * i + 48],
                z.0[2 * i + 49],
                z.0[2 * i + 64],
                z.0[2 * i + 65],
                z.0[2 * i + 80],
                z.0[2 * i + 81],
                z.0[2 * i + 96],
                z.0[2 * i + 97],
                z.0[2 * i + 112],
                z.0[2 * i + 113],
            ];

            permute_p(&mut v);

            z.0[2 * i] = v[0];
            z.0[2 * i + 1] = v[1];
            z.0[2 * i + 16] = v[2];
            z.0[2 * i + 17] = v[3];
            z.0[2 * i + 32] = v[4];
            z.0[2 * i + 33] = v[5];
            z.0[2 * i + 48] = v[6];
            z.0[2 * i + 49] = v[7];
            z.0[2 * i + 64] = v[8];
            z.0[2 * i + 65] = v[9];
            z.0[2 * i + 80] = v[10];
            z.0[2 * i + 81] = v[11];
            z.0[2 * i + 96] = v[12];
            z.0[2 * i + 97] = v[13];
            z.0[2 * i + 112] = v[14];
            z.0[2 * i + 113] = v[15];
        }

        for i in 0..128 {
            z.0[i] ^= r.0[i];
        }

        z
    }

    /// Generates an address block for data-independent indexing.
    ///
    /// In data-independent mode (first pass, slices 0-1), the reference
    /// block indices are derived from this address block rather than from
    /// previously computed block contents. This provides resistance against
    /// side-channel attacks during the critical initialization phase.
    ///
    /// The address block is computed as G(0, G(0, Z)) where Z contains
    /// the current position parameters and a counter.
    pub(crate) fn generate_address_block(
        pass: u32,
        lane: u32,
        slice: u32,
        total_blocks: u32,
        time: u32,
        counter: u32,
    ) -> Self {
        let mut input = Block::ZERO;
        input.0[0] = pass as u64;
        input.0[1] = lane as u64;
        input.0[2] = slice as u64;
        input.0[3] = total_blocks as u64;
        input.0[4] = time as u64;
        input.0[5] = 2; // Argon2id
        input.0[6] = counter as u64;

        let tmp = Block::compress(&Block::ZERO, &input);
        Block::compress(&Block::ZERO, &tmp)
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|v| *v = 0);
    }
}

/// GB mixing function (Argon2 variant of BLAKE2b's G).
///
/// Unlike the original BLAKE2b G function which adds message words,
/// Argon2's GB function uses multiplication of the lower 32 bits to
/// achieve better diffusion. The formula for each step is:
///
/// ```text
/// a = a + b + 2 × trunc(a) × trunc(b)
/// d = (d ⊕ a) >>> rotation
/// ```
///
/// where trunc() extracts the lower 32 bits. The rotation amounts are
/// 32, 24, 16, and 63 bits respectively.
#[inline(always)]
fn gb(a: u64, b: u64, c: u64, d: u64) -> (u64, u64, u64, u64) {
    let a = a.wrapping_add(b).wrapping_add(
        2u64.wrapping_mul((a as u32) as u64)
            .wrapping_mul((b as u32) as u64),
    );
    let d = (d ^ a).rotate_right(32);

    let c = c.wrapping_add(d).wrapping_add(
        2u64.wrapping_mul((c as u32) as u64)
            .wrapping_mul((d as u32) as u64),
    );
    let b = (b ^ c).rotate_right(24);

    let a = a.wrapping_add(b).wrapping_add(
        2u64.wrapping_mul((a as u32) as u64)
            .wrapping_mul((b as u32) as u64),
    );
    let d = (d ^ a).rotate_right(16);

    let c = c.wrapping_add(d).wrapping_add(
        2u64.wrapping_mul((c as u32) as u64)
            .wrapping_mul((d as u32) as u64),
    );
    let b = (b ^ c).rotate_right(63);

    (a, b, c, d)
}

/// P permutation: one round of the BLAKE2-like mixing.
///
/// Applies GB to a 4×4 matrix of 64-bit words, first along columns,
/// then along diagonals. This is equivalent to one round of the BLAKE2b
/// compression function, but using the modified GB function.
#[inline(always)]
fn permute_p(v: &mut [u64; 16]) {
    (v[0], v[4], v[8], v[12]) = gb(v[0], v[4], v[8], v[12]);
    (v[1], v[5], v[9], v[13]) = gb(v[1], v[5], v[9], v[13]);
    (v[2], v[6], v[10], v[14]) = gb(v[2], v[6], v[10], v[14]);
    (v[3], v[7], v[11], v[15]) = gb(v[3], v[7], v[11], v[15]);

    (v[0], v[5], v[10], v[15]) = gb(v[0], v[5], v[10], v[15]);
    (v[1], v[6], v[11], v[12]) = gb(v[1], v[6], v[11], v[12]);
    (v[2], v[7], v[8], v[13]) = gb(v[2], v[7], v[8], v[13]);
    (v[3], v[4], v[9], v[14]) = gb(v[3], v[4], v[9], v[14]);
}
