use core::mem;
use network_types::bitfield::BitfieldUnit;

use crate::be16;

/// IPv4 header, which is present after the Ethernet header.
#[repr(C, packed(2))]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,
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

impl Header {
    pub const LEN: usize = mem::size_of::<Header>();

    #[inline(always)]
    pub fn ihl(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }

    #[inline(always)]
    pub fn set_ihl(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }

    #[inline(always)]
    pub fn version(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }

    #[inline(always)]
    pub fn set_version(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }

    #[inline(always)]
    pub fn new_bitfield_1(ihl: u8, version: u8) -> BitfieldUnit<[u8; 1usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 1usize]> = Default::default();
        bitfield_unit.set(0usize, 4u8, {
            let ihl: u8 = unsafe { mem::transmute(ihl) };
            ihl as u64
        });
        bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { mem::transmute(version) };
            version as u64
        });
        bitfield_unit
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
    fn next_mut(
        &mut self,
        frame: core::ops::Range<*mut core::ffi::c_void>,
    ) -> Result<super::HeaderPtr, ()> {
        use super::NextHeader;

        match self.proto {
            super::ip::Proto::TCP => Ok(super::HeaderPtr::Tcp(
                self.next_t_mut::<super::tcp::Header>(frame)?,
            )),
            super::ip::Proto::UDP => Ok(super::HeaderPtr::Udp(
                self.next_t_mut::<super::udp::Header>(frame)?,
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
