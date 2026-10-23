//! Fixed first-stage user address space. The guard is never backed or copied through.
use crate::Errno;
pub const BASE: u64 = 0x100000;
pub const CODE_BYTES: usize = 16384;
pub const DATA_BYTES: usize = 8192;
pub const STACK_BASE: u64 = BASE + 0x7000;
pub const STACK_TOP: u64 = BASE + 0x9000;
pub const MAPPED_PAGES: u32 = 8;
pub const MAX_PROCESSES: usize = 8;
pub const POOL_PAGES: u32 = MAPPED_PAGES * MAX_PROCESSES as u32;
#[repr(C, align(4096))]
pub struct Arena {
    bytes: [u8; MAPPED_PAGES as usize * 4096],
}
impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}
impl Arena {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAPPED_PAGES as usize * 4096],
        }
    }
    pub fn clear(&mut self) {
        self.bytes.fill(0);
    }
    pub fn base_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
    fn range(addr: u64, len: usize, write: bool) -> Result<core::ops::Range<usize>, Errno> {
        let end = addr.checked_add(len as u64).ok_or(Errno::Fault)?;
        let low = if write {
            BASE + CODE_BYTES as u64
        } else {
            BASE
        };
        if addr >= low && end <= BASE + (CODE_BYTES + DATA_BYTES) as u64 {
            let start = (addr - BASE) as usize;
            return Ok(start..start + len);
        }
        if addr >= STACK_BASE && end <= STACK_TOP {
            let start = (addr - STACK_BASE) as usize + CODE_BYTES + DATA_BYTES;
            return Ok(start..start + len);
        }
        Err(Errno::Fault)
    }
    pub fn read(&self, addr: u64, len: usize) -> Result<&[u8], Errno> {
        Ok(&self.bytes[Self::range(addr, len, false)?])
    }
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), Errno> {
        let r = Self::range(addr, data.len(), true)?;
        self.bytes[r].copy_from_slice(data);
        Ok(())
    }
    pub fn validate_write(&self, addr: u64, len: usize) -> Result<(), Errno> {
        Self::range(addr, len, true).map(|_| ())
    }
    pub fn cstring(&self, addr: u64, out: &mut [u8]) -> Result<usize, Errno> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.read(addr.checked_add(i as u64).ok_or(Errno::Fault)?, 1)?[0];
            if *b == 0 {
                return Ok(i);
            }
        }
        Err(Errno::Nametoolong)
    }
    pub(crate) fn load_segment(&mut self, addr: u64, data: &[u8]) -> Result<(), Errno> {
        let r = Self::range(addr, data.len(), false)?;
        self.bytes[r].copy_from_slice(data);
        Ok(())
    }
}
