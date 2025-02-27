#![no_std]

#[allow(non_camel_case_types)]
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
pub struct be16 {
    val: u16,
}

impl be16 {
    #[inline(always)]
    pub const fn new(value: u16) -> Self {
        Self { val: value.to_be() }
    }
}

impl From<u16> for be16 {
    #[inline(always)]
    fn from(value: u16) -> Self {
        Self { val: value.to_be() }
    }
}

impl From<be16> for u16 {
    #[inline(always)]
    fn from(be: be16) -> Self {
        u16::from_be(be.val)
    }
}

impl From<be16> for [u8; 2] {
    #[inline(always)]
    fn from(value: be16) -> Self {
        value.val.to_ne_bytes()
    }
}

impl From<[u8; 2]> for be16 {
    #[inline(always)]
    fn from(value: [u8; 2]) -> Self {
        be16 {
            val: u16::from_ne_bytes(value),
        }
    }
}

impl core::ops::BitXor for be16 {
    type Output = be16;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self {
            val: self.val ^ rhs.val,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
pub struct be32 {
    val: u32,
}

impl be32 {
    #[inline(always)]
    pub const fn new(value: u32) -> Self {
        Self { val: value.to_be() }
    }
}

impl From<u32> for be32 {
    #[inline(always)]
    fn from(value: u32) -> Self {
        Self { val: value.to_be() }
    }
}

impl From<be32> for u32 {
    #[inline(always)]
    fn from(be: be32) -> Self {
        u32::from_be(be.val)
    }
}

impl From<be32> for [u8; 4] {
    #[inline(always)]
    fn from(value: be32) -> Self {
        value.val.to_ne_bytes()
    }
}

impl From<[u8; 4]> for be32 {
    #[inline(always)]
    fn from(value: [u8; 4]) -> Self {
        be32 {
            val: u32::from_ne_bytes(value),
        }
    }
}

impl core::ops::BitXor for be32 {
    type Output = be32;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self {
            val: self.val ^ rhs.val,
        }
    }
}

pub struct Ptr<T: ?Sized> {
    pointer: *mut T,
}

impl<T> Ptr<T> {
    #[inline(always)]
    pub fn new(pointer: *mut T) -> Self {
        Self { pointer }
    }
    #[inline(always)]
    pub fn offset(&self, frame: core::ops::Range<*mut core::ffi::c_void>) -> i32 {
        (self.pointer as isize - frame.start as isize) as i32
    }
}

impl<T> core::ops::Deref for Ptr<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.pointer }
    }
}

impl<T> core::ops::DerefMut for Ptr<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.pointer }
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
    Unhandled(),
}

pub trait AutoNextHeader: Sized {
    /// Returns the next header where its type can be determined from the current header. For
    /// example, If you have an Ethernet header and its EtherType field indicates that the next
    /// header should be Ipv6 (i.e. `0x86DD`) then calling this method will return an instance of
    /// [`HeaderPtr::Ipv6`] pointing to the correct next header location.
    fn next(&mut self, range: core::ops::Range<*mut core::ffi::c_void>) -> Result<HeaderPtr, ()>;
}

pub trait NextHeader: Sized {
    #[inline(always)]
    /// Returns the next header, interpreted as the given type. For example, if you have a UDP
    /// header (e.g. `udp_hdr`) and you know the next header will be VXLAN, pass T = [`vxlan::Header`]
    /// and it will return a pointer to the VXLAN header:
    ///
    /// let vxlan_h = udp_h.next_t::<vxlan::Header>(&ctx)?;
    fn next_t<T: NextHeader>(
        &mut self,
        range: core::ops::Range<*mut core::ffi::c_void>,
    ) -> Result<Ptr<T>, ()> {
        let next = unsafe {
            let me = self as *mut Self;
            me.offset(1) as *mut T
        };

        let next_end = unsafe { next.offset(1) };
        let end = range.end as *mut T;

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

pub mod meta;
