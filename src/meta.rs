#[inline(always)]
pub fn from_range<T: Sized>(
    meta: core::ops::Range<*mut core::ffi::c_void>,
) -> Option<super::Ptr<T>> {
    let pointer = meta.start as *mut T;
    unsafe {
        if pointer.offset(1) > (meta.end as *mut T) {
            return None;
        }

        Some(super::Ptr::new(pointer as *mut T))
    }
}
