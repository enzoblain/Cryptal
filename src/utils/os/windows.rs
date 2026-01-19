//! Operating system abstraction layer (Windows)
//!
//! This module provides low-level bindings to operating system services
//! required by the Nebula ecosystem.
//!
//! It is intended to act as a thin, explicit abstraction layer over
//! platform-specific system APIs. At the moment, it only exposes access
//! to the operating system’s cryptographically secure random number
//! generator, but it is expected to grow over time.
//!
//! Future responsibilities may include:
//! - secure randomness
//! - system entropy sources
//! - time primitives
//! - platform-specific cryptographic services
//!
//! All functions in this module are low-level, minimal, and unsafe-adjacent
//! by nature, but are exposed through safe Rust interfaces.

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

/// Fills a buffer with data provided by the operating system.
///
/// This function currently forwards to the Windows CNG API to obtain
/// cryptographically secure random bytes. While this is the only exposed
/// capability today, this function lives in the OS abstraction layer
/// and is **not conceptually limited to randomness alone**.
///
/// # Panics
/// Panics if the underlying system call fails. Such a failure indicates
/// a critical operating system error and is considered unrecoverable.
///
/// # Notes
/// - No heap allocation is performed.
/// - The buffer is fully initialized on success.
/// - This function is suitable for seeding cryptographic primitives.
pub(crate) fn sys_random(buf: &mut [u8]) {
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status != 0 {
        panic!("BCryptGenRandom failed with status {status}");
    }
}
