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
//! and other security-critical randomness needs. It is **not** intended
//! to replace a full-featured, externally audited RNG library, but to
//! serve as a predictable and auditable internal primitive.

use crate::primitives::U256;
use crate::rng::chacha20drbg::chacha20_block;
use crate::utils::os::sys_random;

/// Cryptographically secure pseudorandom number generator.
///
/// The generator is initialized from OS-provided entropy and then expands
/// randomness using the ChaCha20 block function in a deterministic manner.
///
/// Internally, it maintains:
/// - a 256-bit secret key (`U256`)
/// - a 96-bit nonce (fixed to zero for DRBG usage)
/// - a 32-bit block counter
///
/// After generating output, the generator rekeys itself to provide forward
/// secrecy: compromise of the current internal state does not allow recovery
/// of previously generated output.
pub struct Csprng {
    /// Internal ChaCha20 key (256-bit secret state)
    ///
    /// The key is treated as opaque key material and is not interpreted
    /// as an arithmetic value.
    key: U256,

    /// Nonce value (96-bit, fixed to zero for DRBG usage)
    ///
    /// In this construction, uniqueness is ensured by the block counter
    /// rather than by varying the nonce.
    nonce: [u8; 12],

    /// Block counter
    ///
    /// This counter is incremented for each generated ChaCha20 block.
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
    /// The operating system is assumed to provide cryptographically secure
    /// randomness. The obtained entropy is immediately expanded into the
    /// internal ChaCha20 state.
    pub fn from_os() -> Self {
        let mut seed = [0u8; 32];
        sys_random(&mut seed);

        Self::from_seed(seed.into())
    }

    /// Creates a new CSPRNG from a user-provided seed.
    ///
    /// The seed **must** be uniformly random and unpredictable. After being
    /// consumed, the seed buffer is wiped to avoid lingering sensitive data
    /// in memory.
    pub fn from_seed(mut seed: U256) -> Self {
        let key = seed;
        seed.0.fill(0);

        Self {
            key,
            nonce: [0u8; 12],
            counter: 0,
        }
    }

    /// Fills the provided buffer with cryptographically secure random bytes.
    ///
    /// Randomness is generated in 64-byte blocks using ChaCha20 and copied
    /// into the output buffer. Once the buffer has been filled, the generator
    /// automatically rekeys itself to preserve forward secrecy.
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
    /// as the new internal key. This ensures that previously generated output
    /// cannot be recovered even if the current internal state is compromised.
    fn rekey(&mut self) {
        let block = chacha20_block(&self.key, self.counter, &self.nonce);

        self.counter = self.counter.wrapping_add(1);
        self.key.0.copy_from_slice(&block[..32]);
    }
}

impl Default for Csprng {
    /// Creates a default CSPRNG instance seeded from the operating system.
    fn default() -> Self {
        Self::new()
    }
}
