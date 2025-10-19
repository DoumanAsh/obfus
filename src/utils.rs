//!Utilities

use core::{sync, ptr};

///Performs volatile memset to ensure compiler cannot optimize operation away
pub fn secure_memset<T: Copy + Sized + 'static>(data: &mut [T], value: T) {
    let mut ptr = data.as_mut_ptr();

    for _ in 0..data.len() {
        ptr = unsafe {
            ptr::write_volatile(ptr, value);
            ptr.add(1)
        }
    }

    sync::atomic::compiler_fence(sync::atomic::Ordering::SeqCst);
}
