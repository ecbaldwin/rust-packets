use core::mem;

use crate::be16;

/// UDP header, which is present after the IP header.
#[repr(C, packed(2))]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    pub source: be16,
    pub destination: be16,
    pub len: be16,
    pub check: be16,
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
        assert_eq!(8, Header::LEN);
    }

    #[test]
    fn alignment() {
        assert_eq!(2, mem::align_of::<Header>());
    }
}
