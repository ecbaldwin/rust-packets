use core::mem;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HardwareType {
    val: crate::be16,
}

impl HardwareType {
    pub const fn new(val: u16) -> Self {
        Self {
            val: crate::be16::new(val),
        }
    }

    pub const ETHERNET: HardwareType = HardwareType::new(1);
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Operation {
    val: crate::be16,
}

impl Operation {
    pub const fn new(val: u16) -> Self {
        Self {
            val: crate::be16::new(val),
        }
    }

    pub const REQUEST: Operation = Operation::new(1);
    pub const REPLY: Operation = Operation::new(2);
}

pub type ProtocolType = super::eth::Type;

// NOTE This struct is only useful if hardware length is 6 and protocol length is 4.
#[repr(C, packed(2))]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    /// Hardware Type
    pub h_type: HardwareType,
    /// Protocol Type
    pub p_type: ProtocolType,
    // Hardware Address Length
    pub h_len: u8,
    // Protocol Address Length
    pub p_len: u8,
    /// Operation
    pub oper: Operation,
    /// Sender hardware address.
    pub sha: [u8; 6],
    /// Sender protocol address.
    pub spa: [u8; 4],
    /// Target hardware address.
    pub tha: [u8; 6],
    /// Target protocol address.
    pub tpa: [u8; 4],
}

impl super::NextHeader for Header {}

impl Header {
    pub const LEN: usize = mem::size_of::<Header>();

    /// Returns the source address field.
    #[inline(always)]
    pub fn spa(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.spa)
    }

    /// Returns the destination address field.
    #[inline(always)]
    pub fn tpa(&self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.tpa)
    }

    /// Sets the source address field.
    #[inline(always)]
    pub fn set_spa(&mut self, src: core::net::Ipv4Addr) {
        self.spa = src.octets();
    }

    /// Sets the destination address field.
    #[inline(always)]
    pub fn set_tpa(&mut self, dst: core::net::Ipv4Addr) {
        self.tpa = dst.octets();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size() {
        assert_eq!(28, Header::LEN);
    }

    #[test]
    fn alignment() {
        assert_eq!(2, mem::align_of::<Header>());
    }
}
