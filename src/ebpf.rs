use aya_ebpf::programs::{TcContext, XdpContext};

pub trait HasFrame<T>: Sized {
    fn frame(&self) -> core::ops::Range<T>;
}

impl HasFrame<*mut core::ffi::c_void> for XdpContext {
    #[inline(always)]
    fn frame(&self) -> core::ops::Range<*mut core::ffi::c_void> {
        return core::ops::Range {
            start: self.data() as *mut core::ffi::c_void,
            end: self.data_end() as *mut core::ffi::c_void,
        };
    }
}

impl HasFrame<*mut core::ffi::c_void> for TcContext {
    #[inline(always)]
    fn frame(&self) -> core::ops::Range<*mut core::ffi::c_void> {
        return core::ops::Range {
            start: self.data() as *mut core::ffi::c_void,
            end: self.data_end() as *mut core::ffi::c_void,
        };
    }
}

pub trait HasMetadata<T>: Sized {
    fn meta(&self) -> core::ops::Range<T>;
}

impl HasMetadata<*mut core::ffi::c_void> for XdpContext {
    #[inline(always)]
    fn meta(&self) -> core::ops::Range<*mut core::ffi::c_void> {
        return core::ops::Range {
            start: self.metadata() as *mut core::ffi::c_void,
            end: self.data() as *mut core::ffi::c_void,
        };
    }
}

impl HasMetadata<*mut core::ffi::c_void> for TcContext {
    #[inline(always)]
    fn meta(&self) -> core::ops::Range<*mut core::ffi::c_void> {
        return core::ops::Range {
            start: unsafe { (*self.skb.skb).data_meta } as *mut core::ffi::c_void,
            end: self.data() as *mut core::ffi::c_void,
        };
    }
}
