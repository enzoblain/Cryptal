use windows_sys::Win32::Security::Cryptography::BCryptGenRandom;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

pub(crate) fn sys_random(buf: &mut [u8]) {
    let status = unsafe {
        BCryptGenRandom(
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status != 0 {
        panic!("BCryptGenRandom failed: {}", status);
    }
}
