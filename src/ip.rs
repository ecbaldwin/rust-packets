#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Proto {
    val: u8,
}

impl Proto {
    pub const fn new(val: u8) -> Self {
        Self { val }
    }

    pub const ICMP: Proto = Proto::new(1);
    pub const TCP: Proto = Proto::new(6);
    pub const UDP: Proto = Proto::new(17);
}
