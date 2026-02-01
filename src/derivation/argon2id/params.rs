//! Parameter definitions and validation for Argon2.
//!
//! This module defines the configurable parameters for Argon2id and provides
//! validation to ensure they meet the algorithm's requirements.

/// Configuration parameters for the Argon2id algorithm.
///
/// These parameters control the memory and time cost of the hash function,
/// allowing the security level to be tuned for the target hardware and
/// threat model.
///
/// # Recommended Values
///
/// For password hashing in 2024+, OWASP recommends:
/// - `mem_kib`: 19456 (19 MiB) minimum, 47104 (46 MiB) for higher security
/// - `time`: 2 passes minimum
/// - `lanes`: 1 (single-threaded) or number of available cores
/// - `tag_len`: 32 bytes for most applications
#[derive(Clone, Debug)]
pub struct Argon2Params {
    /// Memory size in KiB (minimum 8 × lanes).
    pub mem_kib: u32,
    /// Number of passes over memory (minimum 1).
    pub time: u32,
    /// Degree of parallelism (number of lanes, minimum 1).
    pub lanes: u32,
    /// Length of the output tag in bytes (4..=1024).
    pub tag_len: usize,
    /// Optional secret key for keyed hashing.
    pub secret: Option<Vec<u8>>,
    /// Optional associated data.
    pub associated_data: Option<Vec<u8>>,
}

/// Errors that can occur during parameter validation.
///
/// These errors indicate that the provided parameters do not meet the
/// minimum requirements defined by the Argon2 specification.
#[derive(Debug)]
pub enum Argon2ParamError {
    /// Memory must be at least 8 × lanes KiB.
    MemoryTooSmall,
    /// Memory must be a multiple of 4 × lanes.
    MemoryNotMultipleOfLanes,
    /// Lanes must be at least 1.
    TooFewLanes,
    /// Time (passes) must be at least 1.
    TooFewPasses,
    /// Tag length must be between 4 and 1024 bytes.
    TagLengthInvalid,
}

impl Argon2Params {
    pub(crate) fn validate(&self) -> Result<(), Argon2ParamError> {
        if self.lanes < 1 {
            return Err(Argon2ParamError::TooFewLanes);
        }

        if self.time < 1 {
            return Err(Argon2ParamError::TooFewPasses);
        }

        if self.mem_kib < 8 * self.lanes {
            return Err(Argon2ParamError::MemoryTooSmall);
        }

        if self.tag_len < 4 || self.tag_len > 1024 {
            return Err(Argon2ParamError::TagLengthInvalid);
        }

        Ok(())
    }
}

impl Default for Argon2Params {
    /// Default parameters: 64 MiB memory, 3 passes, 1 lane, 32-byte tag.
    fn default() -> Self {
        Self {
            mem_kib: 64 * 1024,
            time: 3,
            lanes: 1,
            tag_len: 32,
            secret: None,
            associated_data: None,
        }
    }
}
