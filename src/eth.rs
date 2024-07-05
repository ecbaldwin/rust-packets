use core::mem;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Type {
    val: crate::be16,
}

impl Type {
    pub const fn new(val: u16) -> Self {
        Self {
            val: crate::be16::new(val),
        }
    }

    pub const IPV4: Type = Type::new(0x0800);
    pub const ARP: Type = Type::new(0x0806);
    pub const IPV6: Type = Type::new(0x86DD);
}

#[repr(C, packed(2))]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    /// Destination MAC address.
    pub dst_addr: [u8; 6],
    /// Source MAC address.
    pub src_addr: [u8; 6],
    /// Protocol which is encapsulated in the payload of the frame.
    pub ether_type: Type,
}

impl Header {
    pub const LEN: usize = mem::size_of::<Header>();

    #[inline(always)]
    pub fn from_ctx(
        ctx: impl crate::ebpf::HasRange<*const core::ffi::c_void>,
    ) -> Result<super::Ptr<Header>, ()> {
        let range = ctx.range();
        let pointer = range.start as *const Header;
        unsafe {
            if pointer.offset(1) > (range.end as *const Header) {
                return Err(());
            }

            Ok(super::Ptr::new(pointer as *const Header))
        }
    }
}

impl super::NextHeader for Header {}
impl super::AutoNextHeader for Header {
    #[inline(always)]
    fn next(
        &self,
        ctx: impl crate::ebpf::HasRange<*const core::ffi::c_void>,
    ) -> Result<super::HeaderPtr, ()> {
        use super::NextHeader;

        match self.ether_type {
            Type::ARP => Ok(super::HeaderPtr::Arp(
                self.next_t::<super::arp::Header>(ctx)?,
            )),
            Type::IPV4 => Ok(super::HeaderPtr::Ipv4(
                self.next_t::<super::ipv4::Header>(ctx)?,
            )),
            Type::IPV6 => Ok(super::HeaderPtr::Ipv6(
                self.next_t::<super::ipv6::Header>(ctx)?,
            )),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size() {
        assert_eq!(14, Header::LEN);
    }

    #[test]
    fn alignment() {
        assert_eq!(2, mem::align_of::<Header>());
    }
}
