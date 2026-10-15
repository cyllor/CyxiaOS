use crate::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    Again,
    Invalid,
    Unsupported,
}
pub trait ClockSource {
    fn now_ns(&self) -> TimeNs;
}
pub trait ClockEvent {
    fn set_deadline(&mut self, deadline: TimeNs) -> Result<(), PlatformError>;
}
pub trait ConsoleOps {
    fn try_write(&mut self, data: &[u8]) -> Result<usize, PlatformError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UartResource {
    pub base: PhysAddr,
    pub len: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GicResource {
    pub distributor: PhysAddr,
    pub cpu: PhysAddr,
    pub distributor_len: u64,
    pub cpu_len: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    pub ram: [MemoryRegion; 8],
    pub ram_count: usize,
    pub reserved: [MemoryRegion; 32],
    pub reserved_count: usize,
    pub uart: Option<UartResource>,
    pub gic: Option<GicResource>,
    pub timer_irq: Option<u32>,
    pub dtb_len: usize,
}
impl BootInfo {
    pub const EMPTY: Self = Self {
        ram: [MemoryRegion::EMPTY; 8],
        ram_count: 0,
        reserved: [MemoryRegion::EMPTY; 32],
        reserved_count: 0,
        uart: None,
        gic: None,
        timer_irq: None,
        dtb_len: 0,
    };
}
