use core::mem;

use crate::{be16, be32};

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct Flags {
    val: u8,
}

impl Flags {
    pub const fn new(val: u8) -> Self {
        Self { val }
    }

    pub const NO_VNI: Flags = Flags::new(0);
    pub const HAS_VNI: Flags = Flags::new(0x08);
}

#[repr(C, packed(1))]
#[derive(Default, Debug, Copy, Clone)]
pub struct Header {
    /// Flags
    flags: Flags,
    /// Reserved
    _reserved3: [u8; 3],
    /// VXLAN Network ID
    vni: [u8; 3],
    /// Reserved
    _reserved: u8,
}

impl Header {
    pub const LEN: usize = mem::size_of::<Header>();

    /// Returns the VNI in the packet if valid, otherwise returns None
    #[inline(always)]
    // TODO check usage
    pub fn vni(&self) -> Option<be32> {
        if self.flags == Flags::NO_VNI {
            None
        } else {
            Some([0, self.vni[0], self.vni[1], self.vni[2]].into())
        }
    }

    /// Sets the VNI to the value given, silently discarding the highest order byte
    #[inline(always)]
    pub fn set_vni(&mut self, vni: be32) {
        self.flags = Flags::HAS_VNI;
        let bytes: [u8; 4] = vni.into();
        self.vni.clone_from_slice(&bytes[1..4]);
    }

    /// Clears the VNI in the packet, setting the flags to mark it invalid
    pub fn clear_vni(&mut self) {
        self.flags = Flags::NO_VNI;
    }

    #[inline(always)]
    pub fn ethernet(
        &mut self,
        frame: core::ops::Range<*mut core::ffi::c_void>,
    ) -> Result<super::Ptr<super::eth::Header>, ()> {
        use super::NextHeader;

        Ok(self.next_t::<super::eth::Header>(frame)?)
    }

    #[inline(always)]
    pub fn source_port(&mut self, frame: core::ops::Range<*mut core::ffi::c_void>) -> be16 {
        use super::NextHeader;

        match self.next_t::<super::eth::Header>(frame) {
            Err(_) => 0.into(),
            Ok(e) => {
                let vals = unsafe {
                    core::slice::from_raw_parts(&*e as *const super::eth::Header as *const be16, 7)
                };
                let zero = be16::from(0);
                let val = vals.iter().fold(zero, |acc, e| acc ^ *e);
                val
            }
        }
    }
}

impl super::NextHeader for Header {}
impl super::AutoNextHeader for Header {
    #[inline(always)]
    fn next(
        &mut self,
        frame: core::ops::Range<*mut core::ffi::c_void>,
    ) -> Result<super::HeaderPtr, ()> {
        Ok(super::HeaderPtr::Eth(self.ethernet(frame)?))
    }
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
        assert_eq!(1, mem::align_of::<Header>());
    }

    #[test]
    fn vni() {
        let mut h = Header::default();
        assert_eq!(None, h.vni());
        h.vni = [1, 2, 3];
        assert_eq!(None, h.vni());
        h.flags = Flags::HAS_VNI;
        assert_eq!(Some(be32::new(0x10203)), h.vni());
    }

    #[test]
    fn set_vni() {
        let mut h = Header::default();
        assert_eq!(None, h.vni());
        h.set_vni(be32::new(0x30201));
        assert_eq!(Some(be32::new(0x30201)), h.vni());
        // Discard the highest order byte
        h.set_vni(be32::new(0x4030201));
        assert_eq!(Some(be32::new(0x30201)), h.vni());
    }

    #[test]
    fn clear_vni() {
        let mut h = Header {
            flags: Flags::HAS_VNI,
            ..Header::default()
        };
        assert_eq!(Some(be32::new(0)), h.vni());
        h.clear_vni();
        assert_eq!(None, h.vni());
    }
}
