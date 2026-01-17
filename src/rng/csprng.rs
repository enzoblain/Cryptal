//! ChaCha20-based CSPRNG
//!
//! This module implements a cryptographically secure pseudorandom number
//! generator (CSPRNG) built on top of the ChaCha20 block function.
//!
//! It is designed as a low-level primitive for the Nebula ecosystem and:
//! - relies on the operating system for initial entropy
//! - uses ChaCha20 as a deterministic random bit generator (DRBG)
//! - avoids heap allocations
//! - provides forward secrecy via periodic rekeying
//!
//! This CSPRNG is suitable for key generation, nonces, identifiers,
//! and other security-critical randomness needs.

use crate::os::sys_random;
use crate::rng::chacha20drbg::chacha20_block;

/// Cryptographically secure pseudorandom number generator.
///
/// The generator is initialized from OS-provided entropy and then expands
/// randomness using the ChaCha20 block function. Internally, it maintains
/// a secret key, a nonce, and a block counter.
///
/// After generating output, the generator rekeys itself to ensure forward
/// secrecy: compromise of the internal state does not reveal past outputs.
pub struct Csprng {
    /// Internal ChaCha20 key (256-bit)
    key: [u8; 32],

    /// Nonce value (96-bit, fixed to zero for DRBG usage)
    nonce: [u8; 12],

    /// Block counter
    counter: u32,
}

impl Csprng {
    /// Creates a new CSPRNG seeded from the operating system.
    ///
    /// This is equivalent to calling [`Csprng::from_os`].
    pub fn new() -> Self {
        Self::from_os()
    }

    /// Creates a new CSPRNG using entropy provided by the operating system.
    ///
    /// The OS is assumed to provide cryptographically secure randomness.
    /// The obtained seed is immediately expanded into the internal state.
    pub fn from_os() -> Self {
        let mut seed = [0u8; 32];
        sys_random(&mut seed);

        Self::from_seed(seed)
    }

    /// Creates a new CSPRNG from a user-provided seed.
    ///
    /// The seed must be uniformly random and unpredictable. After being
    /// consumed, the seed buffer is wiped to avoid lingering sensitive data.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let key = seed;
        seed.fill(0);

        Self {
            key,
            nonce: [0u8; 12],
            counter: 0,
        }
    }

    /// Fills the provided buffer with cryptographically secure random bytes.
    ///
    /// Randomness is generated in 64-byte blocks using ChaCha20 and copied
    /// into the output buffer. Once the buffer is filled, the generator
    /// automatically rekeys itself.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut offset = 0;

        while offset < out.len() {
            let block = chacha20_block(&self.key, self.counter, &self.nonce);

            self.counter = self.counter.wrapping_add(1);

            let to_copy = 64.min(out.len() - offset);
            out[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);

            offset += to_copy;
        }

        self.rekey();
    }

    /// Rekeys the generator to provide forward secrecy.
    ///
    /// A fresh ChaCha20 block is generated and its first 32 bytes are used
    /// as the new internal key. This ensures that previously generated
    /// output cannot be recovered even if the current state is compromised.
    fn rekey(&mut self) {
        let block = chacha20_block(&self.key, self.counter, &self.nonce);

        self.counter = self.counter.wrapping_add(1);
        self.key.copy_from_slice(&block[..32]);
    }
}

impl Default for Csprng {
    /// Creates a default CSPRNG instance seeded from the operating system.
    fn default() -> Self {
        Self::new()
    }
}
