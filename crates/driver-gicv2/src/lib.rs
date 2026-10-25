#![no_std]
use cyxia_contracts::*;
#[derive(Debug, Clone, Copy)]
pub enum IrqAck {
    Spurious,
    Active { token: u32, id: u32 },
}
pub struct Gic {
    dist: usize,
    cpu: usize,
    lines: u32,
}
impl Gic {
    /// # Safety
    /// Both MMIO ranges must be valid, Device-mapped and exclusively controlled by this driver.
    pub unsafe fn new(r: GicResource) -> Result<Self, PlatformError> {
        if r.distributor_len < 4096 || r.cpu_len < 4096 {
            return Err(PlatformError::Invalid);
        }
        let mut g = Self {
            dist: r.distributor.0 as usize,
            cpu: r.cpu.0 as usize,
            lines: 0,
        };
        unsafe {
            g.write(g.dist, 0, 0);
            g.lines = 32 * ((g.read(g.dist, 4) & 31) + 1);
            g.lines = g.lines.min(1020);
            for bank in 0..g.lines.div_ceil(32) {
                g.write(g.dist, 0x180 + bank as usize * 4, u32::MAX);
                g.write(g.dist, 0x280 + bank as usize * 4, u32::MAX);
            }
            g.write(g.cpu, 4, 0xff);
            g.write(g.cpu, 8, 0);
            g.write(g.cpu, 0, 1);
            g.write(g.dist, 0, 1);
        }
        Ok(g)
    }
    /// Attach a secondary CPU without resetting the shared distributor/SPIs.
    /// # Safety
    /// Primary initialization must be complete. This CPU exclusively owns its
    /// banked PPI registers and CPU interface; both MMIO ranges are Device-mapped.
    pub unsafe fn attach_cpu(r: GicResource) -> Result<Self, PlatformError> {
        if r.distributor_len < 4096 || r.cpu_len < 4096 {
            return Err(PlatformError::Invalid);
        }
        let mut g = Self {
            dist: r.distributor.0 as usize,
            cpu: r.cpu.0 as usize,
            lines: 0,
        };
        unsafe {
            g.lines = (32 * ((g.read(g.dist, 4) & 31) + 1)).min(1020);
            g.write(g.dist, 0x180, 0xffff0000); // banked PPIs only
            g.write(g.dist, 0x280, 0xffff0000);
            g.write(g.cpu, 4, 0xff);
            g.write(g.cpu, 8, 0);
            g.write(g.cpu, 0, 1);
        }
        Ok(g)
    }
    unsafe fn read(&self, base: usize, offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
    }
    unsafe fn write(&self, base: usize, offset: usize, v: u32) {
        unsafe { core::ptr::write_volatile((base + offset) as *mut u32, v) }
    }
    pub fn enable(&self, id: u32) -> Result<(), PlatformError> {
        if id >= self.lines {
            return Err(PlatformError::Invalid);
        }
        unsafe {
            core::ptr::write_volatile((self.dist + 0x400 + id as usize) as *mut u8, 0xa0);
            if id >= 32 {
                core::ptr::write_volatile((self.dist + 0x800 + id as usize) as *mut u8, 1);
            }
            let off = 0xc00 + (id / 16) as usize * 4;
            let cfg = self.read(self.dist, off) & !(3 << ((id % 16) * 2));
            self.write(self.dist, off, cfg);
            self.write(self.dist, 0x100 + (id / 32) as usize * 4, 1 << (id % 32));
        }
        Ok(())
    }
    pub fn acknowledge(&self) -> IrqAck {
        let token = unsafe { self.read(self.cpu, 0xc) };
        let id = token & 0x3ff;
        if id >= 1020 {
            IrqAck::Spurious
        } else {
            IrqAck::Active { token, id }
        }
    }
    pub fn end(&self, ack: IrqAck) {
        if let IrqAck::Active { token, .. } = ack {
            unsafe { self.write(self.cpu, 0x10, token) }
        }
    }
    pub fn mask(&self, id: u32) -> Result<(), PlatformError> {
        if id >= self.lines {
            return Err(PlatformError::Invalid);
        }
        unsafe { self.write(self.dist, 0x180 + (id / 32) as usize * 4, 1 << (id % 32)) }
        Ok(())
    }
    pub fn enabled(&self, id: u32) -> bool {
        id < self.lines
            && unsafe { self.read(self.dist, 0x100 + (id / 32) as usize * 4) } & (1 << (id % 32))
                != 0
    }
    pub fn active(&self, id: u32) -> bool {
        id < self.lines
            && unsafe { self.read(self.dist, 0x300 + (id / 32) as usize * 4) } & (1 << (id % 32))
                != 0
    }
    fn routing_barrier() {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("dsb sy", "isb", options(nostack, preserves_flags));
        }
        #[cfg(not(target_arch = "aarch64"))]
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
    pub fn route_masked_spi(&self, id: u32, cpu: u16) -> Result<(), PlatformError> {
        if !(32..self.lines).contains(&id) || cpu >= 8 {
            return Err(PlatformError::Unsupported);
        }
        Self::routing_barrier();
        if self.enabled(id) || self.active(id) {
            return Err(PlatformError::Again);
        }
        let mask = 1u8 << cpu;
        unsafe {
            core::ptr::write_volatile((self.dist + 0x800 + id as usize) as *mut u8, mask);
        }
        Self::routing_barrier();
        if self.spi_target_mask(id)? != mask {
            return Err(PlatformError::Invalid);
        }
        Ok(())
    }
    pub fn spi_target_mask(&self, id: u32) -> Result<u8, PlatformError> {
        if !(32..self.lines).contains(&id) {
            return Err(PlatformError::Unsupported);
        }
        Ok(unsafe { core::ptr::read_volatile((self.dist + 0x800 + id as usize) as *const u8) })
    }
    pub fn unmask(&self, id: u32) -> Result<(), PlatformError> {
        if id >= self.lines {
            return Err(PlatformError::Invalid);
        }
        Self::routing_barrier();
        unsafe {
            self.write(self.dist, 0x100 + (id / 32) as usize * 4, 1 << (id % 32));
        }
        Self::routing_barrier();
        Ok(())
    }
    /// Read this CPU interface's banked target bit. Logical CPU indices must
    /// not be assumed to equal a GICv2 target-list bit.
    pub fn local_target_mask(&self) -> Result<u8, PlatformError> {
        let mask = unsafe { core::ptr::read_volatile((self.dist + 0x800) as *const u8) };
        if mask.count_ones() != 1 {
            return Err(PlatformError::Unsupported);
        }
        Ok(mask)
    }
    /// Publish an SGI to an explicit, previously registered CPU target list.
    /// The return proves the MMIO notification was issued, never that a remote
    /// CPU handled it; the receiver's keyed mailbox owns that completion.
    pub fn send_sgi(&self, id: u8, targets: u8) -> Result<(), PlatformError> {
        if id >= 16 || targets == 0 {
            return Err(PlatformError::Invalid);
        }
        Self::routing_barrier();
        unsafe {
            self.write(self.dist, 0xf00, (u32::from(targets) << 16) | u32::from(id));
        }
        Self::routing_barrier();
        Ok(())
    }
    /// Software-pend an owned interrupt, e.g. the isolated kernel selftest's SPI.
    pub fn pend(&self, id: u32) -> Result<(), PlatformError> {
        if id < 32 || id >= self.lines {
            return Err(PlatformError::Invalid);
        }
        unsafe { self.write(self.dist, 0x200 + (id / 32) as usize * 4, 1 << (id % 32)) }
        Ok(())
    }
}
