/// Internal Poly1305 state.
///
/// This structure implements the low-level Poly1305 message authentication
/// algorithm as specified in RFC 8439.
///
/// It is a stateful accumulator and **must never be reused** across different
/// messages or keys. A fresh instance must be created for each authentication.
///
/// # Security
///
/// - This type must remain internal to the crate.
/// - Reusing a Poly1305 instance or its one-time key breaks security.
/// - All operations are designed to run in constant time.
pub(crate) struct Poly1305 {
    /// Clamped `r` value, split into five 26-bit limbs.
    ///
    /// This value is derived from the first half of the one-time key and
    /// clamped according to RFC 8439 to ensure correct modular arithmetic.
    r: [u32; 5],

    /// Accumulator `h`, represented as five 26-bit limbs.
    ///
    /// This holds the running Poly1305 state while processing message blocks.
    h: [u32; 5],

    /// `s` value (second half of the one-time key), stored as raw bytes.
    ///
    /// This value is added to the final accumulator output modulo 2^128.
    s: [u8; 16],
}

impl Poly1305 {
    /// Creates a new Poly1305 instance from a one-time 32-byte key.
    ///
    /// # Key layout
    ///
    /// The input key is split as follows:
    ///
    /// - `key[0..16]` → `r` (clamped, used for polynomial multiplication)
    /// - `key[16..32]` → `s` (added at finalization)
    ///
    /// # Parameters
    ///
    /// - `one_time_key`: A 32-byte key derived from ChaCha20 block 0
    ///
    /// # Notes
    ///
    /// - The caller must guarantee that this key is never reused.
    /// - This function performs the mandatory Poly1305 clamping on `r`.
    pub(crate) fn new(one_time_key: &[u8; 32]) -> Self {
        let r0 = u32::from_le_bytes([
            one_time_key[0],
            one_time_key[1],
            one_time_key[2],
            one_time_key[3],
        ]);
        let r1 = u32::from_le_bytes([
            one_time_key[4],
            one_time_key[5],
            one_time_key[6],
            one_time_key[7],
        ]);
        let r2 = u32::from_le_bytes([
            one_time_key[8],
            one_time_key[9],
            one_time_key[10],
            one_time_key[11],
        ]);
        let r3 = u32::from_le_bytes([
            one_time_key[12],
            one_time_key[13],
            one_time_key[14],
            one_time_key[15],
        ]);

        let r0 = r0 & 0x0fffffff;
        let r1 = r1 & 0x0ffffffc;
        let r2 = r2 & 0x0ffffffc;
        let r3 = r3 & 0x0ffffffc;

        let r = [
            r0 & 0x3ffffff,
            ((r0 >> 26) | (r1 << 6)) & 0x3ffffff,
            ((r1 >> 20) | (r2 << 12)) & 0x3ffffff,
            ((r2 >> 14) | (r3 << 18)) & 0x3ffffff,
            (r3 >> 8) & 0x3ffffff,
        ];

        let mut s = [0u8; 16];
        s.copy_from_slice(&one_time_key[16..32]);

        Poly1305 { r, h: [0; 5], s }
    }

    /// Absorbs a single message block into the Poly1305 accumulator.
    ///
    /// # Parameters
    ///
    /// - `block`: A message block of at most 16 bytes.
    ///
    /// # Behavior
    ///
    /// - The block is interpreted as a little-endian integer.
    /// - An implicit `1` bit is appended at position `8 * block.len()`,
    ///   as required by the Poly1305 specification.
    /// - The accumulator is updated as:
    ///
    /// ```text
    /// h = (h + block) * r mod (2^130 - 5)
    /// ```
    ///
    /// # Notes
    ///
    /// - This function may be called multiple times per message.
    /// - It handles both full and partial blocks uniformly.
    /// - No heap allocation is performed.
    pub(crate) fn update_block(&mut self, block: &[u8]) {
        let mut padded = [0u8; 17];
        padded[..block.len()].copy_from_slice(block);
        padded[block.len()] = 1;

        let t0 = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]);
        let t1 = u32::from_le_bytes([padded[4], padded[5], padded[6], padded[7]]);
        let t2 = u32::from_le_bytes([padded[8], padded[9], padded[10], padded[11]]);
        let t3 = u32::from_le_bytes([padded[12], padded[13], padded[14], padded[15]]);
        let t4 = padded[16] as u32;

        let m0 = t0 & 0x3ffffff;
        let m1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        let m2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        let m3 = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        let m4 = ((t3 >> 8) | (t4 << 24)) & 0x3ffffff;

        self.h[0] = self.h[0].wrapping_add(m0);
        self.h[1] = self.h[1].wrapping_add(m1);
        self.h[2] = self.h[2].wrapping_add(m2);
        self.h[3] = self.h[3].wrapping_add(m3);
        self.h[4] = self.h[4].wrapping_add(m4);

        let h0 = self.h[0] as u64;
        let h1 = self.h[1] as u64;
        let h2 = self.h[2] as u64;
        let h3 = self.h[3] as u64;
        let h4 = self.h[4] as u64;

        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;

        let r1_5 = r1 * 5;
        let r2_5 = r2 * 5;
        let r3_5 = r3 * 5;
        let r4_5 = r4 * 5;

        let d0 = h0 * r0 + h1 * r4_5 + h2 * r3_5 + h3 * r2_5 + h4 * r1_5;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * r4_5 + h3 * r3_5 + h4 * r2_5;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * r4_5 + h4 * r3_5;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * r4_5;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c: u64;

        c = d0 >> 26;
        self.h[0] = (d0 & 0x3ffffff) as u32;
        d1 += c;

        c = d1 >> 26;
        self.h[1] = (d1 & 0x3ffffff) as u32;
        d2 += c;

        c = d2 >> 26;
        self.h[2] = (d2 & 0x3ffffff) as u32;
        d3 += c;

        c = d3 >> 26;
        self.h[3] = (d3 & 0x3ffffff) as u32;
        d4 += c;

        c = d4 >> 26;
        self.h[4] = (d4 & 0x3ffffff) as u32;
        self.h[0] += (c * 5) as u32;

        c = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x3ffffff;
        self.h[1] += c as u32;
    }

    /// Finalizes the Poly1305 computation and returns the authentication tag.
    ///
    /// # Returns
    ///
    /// A 16-byte authentication tag, encoded in little-endian format.
    ///
    /// # Algorithm
    ///
    /// This function performs the following steps:
    ///
    /// 1. Final carry propagation and full reduction modulo `(2^130 - 5)`
    /// 2. Conditional subtraction of the modulus
    /// 3. Serialization of the accumulator to 128 bits
    /// 4. Addition of `s` modulo `2^128`
    ///
    /// # Security Notes
    ///
    /// - The Poly1305 instance must not be used after calling this function.
    /// - The addition of `s` is performed byte-by-byte with carry propagation.
    /// - All operations are constant-time with respect to secret data.
    pub(crate) fn finalize(mut self) -> [u8; 16] {
        let mut c: u32;

        c = self.h[1] >> 26;
        self.h[1] &= 0x3ffffff;
        self.h[2] += c;

        c = self.h[2] >> 26;
        self.h[2] &= 0x3ffffff;
        self.h[3] += c;

        c = self.h[3] >> 26;
        self.h[3] &= 0x3ffffff;
        self.h[4] += c;

        c = self.h[4] >> 26;
        self.h[4] &= 0x3ffffff;
        self.h[0] += c * 5;

        c = self.h[0] >> 26;
        self.h[0] &= 0x3ffffff;
        self.h[1] += c;

        let mut g = [0u32; 5];
        g[0] = self.h[0].wrapping_add(5);
        c = g[0] >> 26;
        g[0] &= 0x3ffffff;

        for (h_i, g_i) in self.h[1..].iter().zip(&mut g[1..]) {
            *g_i = h_i.wrapping_add(c);
            c = *g_i >> 26;
            *g_i &= 0x3ffffff;
        }

        let mask = 0u32.wrapping_sub(c);

        for (h_i, g_i) in self.h.iter_mut().zip(&g) {
            *h_i = (*h_i & !mask) | (*g_i & mask);
        }

        let h0 = self.h[0] | (self.h[1] << 26);
        let h1 = (self.h[1] >> 6) | (self.h[2] << 20);
        let h2 = (self.h[2] >> 12) | (self.h[3] << 14);
        let h3 = (self.h[3] >> 18) | (self.h[4] << 8);

        let mut h_bytes = [0u8; 16];
        h_bytes[0..4].copy_from_slice(&h0.to_le_bytes());
        h_bytes[4..8].copy_from_slice(&h1.to_le_bytes());
        h_bytes[8..12].copy_from_slice(&h2.to_le_bytes());
        h_bytes[12..16].copy_from_slice(&h3.to_le_bytes());

        let mut tag = [0u8; 16];
        let mut carry = 0u16;
        for i in 0..16 {
            let sum = h_bytes[i] as u16 + self.s[i] as u16 + carry;
            tag[i] = sum as u8;
            carry = sum >> 8;
        }

        tag
    }
}
