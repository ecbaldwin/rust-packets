use core::mem;

use crate::be16;

/// IPv4 header, which is present after the Ethernet header.
#[repr(C, packed(2))]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    pub _bitfields: u8,
    pub tos: u8,
    pub tot_len: be16,
    pub id: be16,
    pub frag_off: be16, // TODO also has flags
    pub ttl: u8,
    pub proto: super::ip::Proto,
    pub check: be16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

impl Default for Header {
    #[inline(always)]
    fn default() -> Self {
        Self {
            _bitfields: 0x45,
            tos: Default::default(),
            tot_len: Default::default(),
            id: Default::default(),
            frag_off: Default::default(),
            ttl: Default::default(),
            proto: Default::default(),
            check: Default::default(),
            source: Default::default(),
            destination: Default::default(),
        }
    }
}

impl Header {
    pub const LEN: usize = mem::size_of::<Header>();

    #[inline(always)]
    pub fn ihl(&self) -> u8 {
        self._bitfields & 0xf
    }

    #[inline(always)]
    pub fn set_ihl(&mut self, val: u8) {
        self._bitfields = self._bitfields & 0xf0 | val & 0xf
    }

    #[inline(always)]
    pub fn version(&self) -> u8 {
        self._bitfields >> 4
    }

    /// Returns the source address field.
    #[inline(always)]
    pub fn source(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.source)
    }

    /// Returns the destination address field.
    #[inline(always)]
    pub fn destination(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.destination)
    }

    /// Sets the source address field.
    #[inline(always)]
    pub fn set_source(&mut self, src: core::net::Ipv4Addr) {
        self.source = src.octets();
    }

    /// Sets the destination address field.
    #[inline(always)]
    pub fn set_destination(&mut self, dst: core::net::Ipv4Addr) {
        self.destination = dst.octets();
    }
}

impl super::NextHeader for Header {}
impl super::AutoNextHeader for Header {
    #[inline(always)]
    fn next(
        &mut self,
        frame: core::ops::Range<*mut core::ffi::c_void>,
    ) -> Result<super::HeaderPtr, ()> {
        use super::NextHeader;

        match self.proto {
            super::ip::Proto::TCP => Ok(super::HeaderPtr::Tcp(
                self.next_t::<super::tcp::Header>(frame)?,
            )),
            super::ip::Proto::UDP => Ok(super::HeaderPtr::Udp(
                self.next_t::<super::udp::Header>(frame)?,
            )),
            _ => Ok(super::HeaderPtr::Unhandled()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size() {
        assert_eq!(20, Header::LEN);
    }

    #[test]
    fn alignment() {
        assert_eq!(2, mem::align_of::<Header>());
    }
}
