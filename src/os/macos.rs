use libc::arc4random_buf;

pub(crate) fn sys_random(buf: &mut [u8]) {
    unsafe {
        arc4random_buf(buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    }
}
