use crate::os::sys_random;
use crate::rng::chacha20drbg::chacha20_block;

pub struct Csprng {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
}

impl Csprng {
    pub fn new() -> Self {
        Self::from_os()
    }

    pub fn from_os() -> Self {
        let mut seed = [0u8; 32];
        sys_random(&mut seed);

        Self::from_seed(seed)
    }

    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let key = seed;
        seed.fill(0);

        Self {
            key,
            nonce: [0u8; 12],
            counter: 0,
        }
    }

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

    fn rekey(&mut self) {
        let block = chacha20_block(&self.key, self.counter, &self.nonce);

        self.counter = self.counter.wrapping_add(1);
        self.key.copy_from_slice(&block[..32]);
    }
}

impl Default for Csprng {
    fn default() -> Self {
        Self::new()
    }
}
