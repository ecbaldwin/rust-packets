#![no_std]

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct be16 {
    val: u16,
}

impl be16 {
    pub const fn new(value: u16) -> Self {
        Self { val: value.to_be() }
    }
}

impl From<u16> for be16 {
    fn from(value: u16) -> Self {
        Self { val: value.to_be() }
    }
}

impl From<be16> for u16 {
    fn from(be: be16) -> Self {
        u16::from_be(be.val)
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct be32 {
    val: u32,
}

impl From<u32> for be32 {
    fn from(value: u32) -> Self {
        Self { val: value.to_be() }
    }
}

impl From<be32> for u32 {
    fn from(be: be32) -> Self {
        u32::from_be(be.val)
    }
}

pub struct Ptr<T: ?Sized> {
    pointer: *const T,
}

impl<T> Ptr<T> {
    pub fn new(pointer: *const T) -> Self {
        Self { pointer }
    }
}

impl<T> core::ops::Deref for Ptr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.pointer }
    }
}

pub enum HeaderPtr {
    Arp(Ptr<arp::Header>),
    Eth(Ptr<eth::Header>),
    Ipv4(Ptr<ipv4::Header>),
    Ipv6(Ptr<ipv6::Header>),
    Tcp(Ptr<tcp::Header>),
    Udp(Ptr<udp::Header>),
    Vxlan(Ptr<vxlan::Header>),
}

pub trait AutoNextHeader: Sized {
    /// Returns the next header where its type can be determined from the current header. For
    /// example, If you have an Ethernet header and its EtherType field indicates that the next
    /// header should be Ipv6 (i.e. `0x86DD`) then calling this method will return an instance of
    /// [`HeaderPtr::Ipv6`] pointing to the correct next header location.
    fn next(&self, ctx: impl ebpf::HasRange<*const core::ffi::c_void>) -> Result<HeaderPtr, ()>;
}

pub trait NextHeader: Sized {
    #[inline(always)]
    /// Returns the next header, interpreted as the given type. For example, if you have a UDP
    /// header (e.g. `udp_hdr`) and you know the next header will be VXLAN, pass T = [`vxlan::Header`]
    /// and it will return a pointer to the VXLAN header:
    ///
    ///     let vxlan_h = udp_h.next_t::<vxlan::Header>(&ctx)?;
    fn next_t<T: NextHeader>(
        &self,
        ctx: impl ebpf::HasRange<*const core::ffi::c_void>,
    ) -> Result<Ptr<T>, ()> {
        let next = unsafe {
            let me = self as *const Self;
            me.offset(1) as *const T
        };

        let next_end = unsafe { next.offset(1) };
        let end = ctx.range().end as *const T;

        match next_end > end {
            false => Ok(Ptr::new(next)),
            true => Err(()),
        }
    }
}

pub mod arp;
pub mod eth;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
pub mod vxlan;

pub mod ebpf;
