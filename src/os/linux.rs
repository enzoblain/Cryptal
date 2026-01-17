use libc::{c_void, getrandom};

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
