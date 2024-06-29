use aya_ebpf::programs::XdpContext;

pub trait HasRange: Sized {
    fn range(&self) -> core::ops::Range<usize>;
}

impl HasRange for &XdpContext {
    #[inline(always)]
    fn range(&self) -> core::ops::Range<usize> {
        return core::ops::Range {
            start: self.data(),
            end: self.data_end(),
        };
    }
}
