use aya_ebpf::programs::XdpContext;

pub trait HasRange<T>: Sized {
    fn range(&self) -> core::ops::Range<T>;
}

impl HasRange<usize> for &XdpContext {
    #[inline(always)]
    fn range(&self) -> core::ops::Range<usize> {
        return core::ops::Range {
            start: self.data(),
            end: self.data_end(),
        };
    }
}
