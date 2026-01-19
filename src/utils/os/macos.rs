//! Operating system abstraction layer (macOS)
//!
//! This module provides access to operating system services specific to macOS
//! that are required by the Nebula ecosystem.
//!
//! It currently exposes a function to obtain cryptographically secure random
//! bytes from the system, but it is part of a broader OS abstraction layer
//! that may grow to include additional platform-specific capabilities.
//!
//! On macOS, randomness is provided by `arc4random_buf`, which is backed by
//! the operating system and suitable for cryptographic use.

use libc::arc4random_buf;

/// Fills a buffer with data provided by the operating system.
///
/// This function uses `arc4random_buf`, a macOS-provided interface for
/// generating cryptographically secure random bytes.
///
/// # Safety
/// This function wraps an unsafe system call but exposes a safe API.
/// The caller must provide a valid mutable buffer.
///
/// # Notes
/// - No heap allocation is performed.
/// - The buffer is fully initialized on return.
/// - The output is suitable for seeding cryptographic primitives.
pub(crate) fn sys_random(buf: &mut [u8]) {
    unsafe {
        arc4random_buf(buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    }
}
