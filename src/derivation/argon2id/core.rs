use super::block::Block;
use super::boundary::{finalize, init};
use super::memory::MemoryLayout;
use super::params::{Argon2ParamError, Argon2Params};
use crate::hash::blake2b_long;

/// Errors that can occur during Argon2id computation.
#[derive(Debug)]
pub enum Argon2Error {
    /// Invalid parameter values.
    InvalidParams(Argon2ParamError),
    /// Salt must be at least 8 bytes.
    InvalidSalt,
}

/// Computes an Argon2id hash of the given password.
///
/// # Arguments
///
/// * `password` - The password to hash
/// * `salt` - A random salt (minimum 8 bytes, recommended 16+ bytes)
/// * `params` - Argon2 parameters (memory, time, parallelism, tag length)
///
/// # Returns
///
/// The derived key (tag) as a byte vector, or an error if parameters are invalid.
///
/// # Example
///
/// ```rust, ignore
/// use cryptal::derivation::argon2id::{argon2id, Argon2Params};
///
/// let password = b"my_password";
/// let salt = b"random_salt_16b!";
/// let params = Argon2Params::default();
///
/// let hash = argon2id(password, salt, &params).unwrap();
/// ```
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<Vec<u8>, Argon2Error> {
    params.validate().map_err(Argon2Error::InvalidParams)?;

    if salt.len() < 8 {
        return Err(Argon2Error::InvalidSalt);
    }

    let lanes = params.lanes;
    let sync_points = 4u32;

    // Round m' to be a multiple of 4*p
    let m_min = 8u32.saturating_mul(lanes);
    let mut m_prime = params.mem_kib.max(m_min);
    m_prime = (m_prime / (sync_points * lanes)) * (sync_points * lanes);

    let mut params2 = params.clone();
    params2.mem_kib = m_prime;

    let layout = MemoryLayout::new(&params2);
    let mut memory = vec![Block::ZERO; layout.total_blocks as usize];

    let h0 = init(password, salt, params, m_prime);

    // Initialize first two blocks of each lane: B[i][j] = H'^(1024)(H0 || j || i)
    for i in 0..lanes {
        for j in 0..2u32 {
            let mut input = Vec::with_capacity(72);
            input.extend_from_slice(&h0);
            input.extend_from_slice(&j.to_le_bytes());
            input.extend_from_slice(&i.to_le_bytes());

            let hash = blake2b_long(1024, &input);
            memory[layout.index(i, j)] = Block::from_bytes(hash.try_into().unwrap());
        }
    }

    layout.fill(&mut memory, params2.time);

    let tag = finalize(&memory, lanes, layout.lane_len, params2.tag_len);

    Ok(tag)
}
