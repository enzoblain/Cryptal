//! Argon2id password hashing function (RFC 9106).
//!
//! Argon2id is a memory-hard password hashing function designed to resist
//! both GPU-based brute-force attacks and side-channel attacks. It achieves
//! this by combining the features of Argon2i (data-independent addressing)
//! and Argon2d (data-dependent addressing).
//!
//! # Security Properties
//!
//! - **Memory hardness**: requires a configurable amount of memory, making
//!   parallel attacks expensive.
//! - **Time hardness**: supports multiple passes over memory to increase
//!   computation time.
//! - **Side-channel resistance**: the first half of the first pass uses
//!   data-independent addressing to resist timing attacks during the
//!   critical initial phase.
//!
//! # Algorithm Overview
//!
//! 1. **Initialization**: Compute H0 = BLAKE2b(params || password || salt || ...)
//! 2. **Lane initialization**: Generate the first two blocks of each lane
//!    using H' (variable-length BLAKE2b).
//! 3. **Memory filling**: Fill the remaining blocks using the compression
//!    function G, which is based on the BLAKE2b round function with
//!    additional multiplication for diffusion.
//! 4. **Finalization**: XOR the last block of each lane together and apply
//!    H' to produce the final tag.
//!
//! # Memory Organization
//!
//! Memory is organized as a matrix of 1024-byte blocks:
//! - **Lanes**: independent rows that can be processed in parallel.
//! - **Slices**: each lane is divided into 4 slices (sync points).
//! - **Segments**: blocks within a slice.
//!
//! # Addressing Modes
//!
//! - **Data-independent** (first pass, slices 0-1): block addresses are
//!   computed from a counter, providing side-channel resistance.
//! - **Data-dependent** (all other cases): block addresses depend on
//!   previously computed block contents, providing better security against
//!   time-memory trade-off attacks.

pub(crate) mod block;
pub(crate) mod boundary;
pub mod core;
pub(crate) mod memory;
pub(crate) mod params;
pub(crate) mod reference;
