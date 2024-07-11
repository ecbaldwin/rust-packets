use core::mem;

use crate::{be16, be32};

pub const TCP_HDR_LEN: usize = mem::size_of::<Header>();

/// TCP header, which is present after the IP header.
#[repr(C, packed(2))]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    pub source: be16,
    pub dest: be16,
    pub seq: be32,
    pub ack_seq: be32,
    pub _bitfields: [u8; 2],
    pub window: be16,
    pub check: be16,
    pub urg_ptr: be16,
}

impl super::NextHeader for Header {}

impl Header {
    pub const LEN: usize = mem::size_of::<Header>();
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
