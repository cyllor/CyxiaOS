//! Pure descriptor encoders, shared by host contract tests and the bare-metal adapter.
pub const KERNEL_CODE: u16 = 0x08;
pub const KERNEL_DATA: u16 = 0x10;
pub const USER_DATA: u16 = 0x1b;
pub const USER_CODE: u16 = 0x23;
pub const TSS_SELECTOR: u16 = 0x28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    Range,
}

fn canonical(address: u64) -> bool {
    address <= 0x0000_7fff_ffff_ffff || address >= 0xffff_8000_0000_0000
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}
impl Gate {
    pub const EMPTY: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };
    pub fn interrupt(handler: u64, privilege: u8, ist: u8) -> Result<Self, Error> {
        if !canonical(handler) {
            return Err(Error::Address);
        }
        if privilege > 3 || ist > 7 {
            return Err(Error::Range);
        }
        Ok(Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE,
            ist,
            attributes: 0x8e | privilege << 5,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        })
    }
    pub fn handler(self) -> u64 {
        self.offset_low as u64 | (self.offset_middle as u64) << 16 | (self.offset_high as u64) << 32
    }
    pub fn selector(self) -> u16 {
        self.selector
    }
    pub fn attributes(self) -> u8 {
        self.attributes
    }
    pub fn ist(self) -> u8 {
        self.ist
    }
}

pub fn tss_descriptor(base: u64, limit: u32) -> Result<[u64; 2], Error> {
    if !canonical(base) {
        return Err(Error::Address);
    }
    if limit >= 1 << 20 {
        return Err(Error::Range);
    }
    Ok([
        (limit as u64 & 0xffff)
            | (base & 0xffff) << 16
            | ((base >> 16) & 0xff) << 32
            | 0x89 << 40
            | ((limit as u64 >> 16) & 0xf) << 48
            | ((base >> 24) & 0xff) << 56,
        base >> 32,
    ])
}
