use crate::be16;
use core::{fmt::Debug, mem};

/// IPv4 header, which is present after the Ethernet header.
#[repr(C, packed(2))]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    pub _bitfields: [u8; 4],
    pub payload_len: be16,
    pub proto: super::ip::Proto,
    pub hop_limit: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

impl Default for Header {
    #[inline(always)]
    fn default() -> Self {
        Self {
            hop_limit: 64,
            _bitfields: [0x60, 0, 0, 0],
            payload_len: Default::default(),
            proto: Default::default(),
            source: Default::default(),
            destination: Default::default(),
        }
    }
}

impl Header {
    pub const LEN: usize = mem::size_of::<Header>();

    #[inline(always)]
    pub fn from_frame(&self, frame: core::ops::Range<*mut core::ffi::c_void>) -> Self {
        let len = (frame.end as usize - self as *const Header as usize - Self::LEN) as u16;
        Self {
            payload_len: len.into(),
            ..Self::default()
        }
    }

    #[inline(always)]
    pub fn version(&self) -> u8 {
        self._bitfields[0] >> 4
    }

    #[inline(always)]
    pub fn priority(&self) -> u8 {
        let bits = &self._bitfields;
        bits[0] << 4 | bits[1] >> 4
    }

    #[inline(always)]
    pub fn set_priority(&mut self, val: u8) {
        let bits = &mut self._bitfields;
        bits[0] = bits[0] & 0xf0 | val >> 4;
        bits[1] = bits[1] & 0x0f | val << 4;
    }

    #[inline(always)]
    pub fn flow(&self) -> u32 {
        u32::from_be_bytes([
            0,
            self._bitfields[1] & 0xf,
            self._bitfields[2],
            self._bitfields[3],
        ])
    }

    #[inline(always)]
    pub fn set_flow(&mut self, val: u32) {
        let bits = &mut self._bitfields;
        let bytes: [u8; 4] = val.to_be_bytes();
        bits[1] = bits[1] & 0xf0 | bytes[1] & 0xf;
        bits[2] = bytes[2];
        bits[3] = bytes[3];
    }

    /// Returns the source address field.
    #[inline(always)]
    pub fn source(&self) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(self.source)
    }

    /// Returns the destination address field.
    #[inline(always)]
    pub fn destination(&self) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(self.destination)
    }

    /// Sets the source address field.
    #[inline(always)]
    pub fn set_source(&mut self, src: core::net::Ipv6Addr) {
        self.source = src.octets();
    }

    /// Sets the destination address field.
    #[inline(always)]
    pub fn set_destination(&mut self, dst: core::net::Ipv6Addr) {
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
        assert_eq!(40, Header::LEN);
    }

    #[test]
    fn alignment() {
        assert_eq!(2, mem::align_of::<Header>());
    }

    #[test]
    fn version() {
        let ipv6 = Header::default();
        assert_eq!(6, ipv6.version())
    }

    #[test]
    fn priority() {
        let mut ipv6 = Header::default();
        assert_eq!(0, ipv6.priority());
        ipv6.set_priority(29);
        assert_eq!([0x61, 0xd0], ipv6._bitfields[0..2]);
        assert_eq!(0x1d, ipv6.priority());

        ipv6.set_priority(0xe2);
        assert_eq!([0x6e, 0x20], ipv6._bitfields[0..2]);
        assert_eq!(0xe2, ipv6.priority());
    }

    #[test]
    fn flow_label() {
        let mut ipv6 = Header::default();
        assert_eq!(0, ipv6.flow());
        ipv6.set_flow(0x71d11);
        assert_eq!([7, 0x1d, 0x11], ipv6._bitfields[1..4]);
        assert_eq!(0x71d11, ipv6.flow());

        ipv6.set_priority(29);
        assert_eq!(0x1d, ipv6.priority());
        assert_eq!(0x71d11, ipv6.flow());
        assert_eq!([0xd7, 0x1d, 0x11], ipv6._bitfields[1..4]);

        ipv6.set_flow(0x8e2ee);
        assert_eq!(0x8e2ee, ipv6.flow());
        assert_eq!(0x1d, ipv6.priority());
    }
}
