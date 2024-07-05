use aya_ebpf::programs::XdpContext;

pub trait HasRange<T>: Sized {
    fn range(&self) -> core::ops::Range<T>;
}

impl HasRange<*const core::ffi::c_void> for &XdpContext {
    #[inline(always)]
    fn range(&self) -> core::ops::Range<*const core::ffi::c_void> {
        return core::ops::Range {
            start: self.data() as *const core::ffi::c_void,
            end: self.data_end() as *const core::ffi::c_void,
        };
    }
}
