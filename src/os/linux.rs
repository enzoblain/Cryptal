//! Operating system abstraction layer (Linux)
//!
//! This module provides access to Linux-specific operating system services
//! required by the Nebula ecosystem.
//!
//! At present, it exposes a function to obtain cryptographically secure
//! random bytes from the kernel using the `getrandom` system call. This
//! functionality is part of a broader OS abstraction layer that may expand
//! over time to include additional system primitives.
//!
//! On Linux, `getrandom` provides direct access to the kernel entropy pool
//! and is suitable for cryptographic seeding and security-critical use cases.

use libc::{c_void, getrandom};

/// Fills a buffer with cryptographically secure random bytes from the OS.
///
/// This function repeatedly calls the Linux `getrandom` system call until
/// the entire buffer is filled. Partial reads are handled transparently,
/// which can occur depending on kernel behavior or signal interruptions.
///
/// # Panics
/// Panics if `getrandom` returns an error. Such a failure indicates a
/// critical operating system issue and is considered unrecoverable in a
/// cryptographic context.
///
/// # Notes
/// - No heap allocation is performed.
/// - The buffer is fully initialized on success.
/// - The output is suitable for seeding cryptographic primitives.
pub(crate) fn sys_random(buf: &mut [u8]) {
    let mut filled = 0;

    while filled < buf.len() {
        let ret = unsafe {
            getrandom(
                buf[filled..].as_mut_ptr() as *mut c_void,
                buf.len() - filled,
                0,
            )
        };

        if ret < 0 {
            panic!("getrandom() failed");
        }

        filled += ret as usize;
    }
}
