#![no_std]
#![forbid(unsafe_code)]
pub mod fdt;
pub const RAM_BASE: u64 = 0x40000000;
pub const ENTRY: u64 = 0x40200000;
/// End of the pinned boot image/DMA arena (DTB occupies the first 2 MiB).
pub const KERNEL_POOL_END: u64 = 0x44000000;
pub const HIGH_BASE: u64 = 0xffffffc000000000;
/// End of the 256 MiB RAM range pinned by this initial QEMU board.
pub const RAM_MIB: u64 = if cfg!(feature = "large-memory") {
    512
} else {
    256
};
pub const USER_RAM_END: u64 = RAM_BASE + RAM_MIB * 1024 * 1024;

/// Reserve pinned backing beyond the entire kernel/DMA arena. Both user heap
/// and executable pools use this exact allocator, publishing successful ranges
/// to BootInfo before the next pool is considered. Extra firmware reservations
/// or smaller RAM must deny admission rather than overlap an existing owner.
pub fn reserve_user_pool(
    info: &mut cyxia_contracts::BootInfo,
    len: u64,
) -> Result<cyxia_contracts::MemoryRegion, cyxia_contracts::PlatformError> {
    use cyxia_contracts::{MemoryRegion, PhysAddr, PlatformError, RegionKind};
    if len == 0 || !len.is_multiple_of(4096) || info.ram_count > info.ram.len() {
        return Err(PlatformError::Invalid);
    }
    if info.reserved_count >= info.reserved.len() {
        return Err(PlatformError::Again);
    }
    let mut base = KERNEL_POOL_END;
    while base.checked_add(len).is_some_and(|end| end <= USER_RAM_END) {
        let range = MemoryRegion {
            start: PhysAddr(base),
            len,
            kind: RegionKind::Reserved,
        };
        if info.ram[..info.ram_count].iter().any(|ram| {
            ram.kind == RegionKind::Ram
                && ram.start.0 <= base
                && ram.end().is_ok_and(|end| base + len <= end)
        }) && !info.reserved[..info.reserved_count]
            .iter()
            .any(|reserved| reserved.overlaps(range))
        {
            info.reserved[info.reserved_count] = range;
            info.reserved_count += 1;
            return Ok(range);
        }
        base += 4096;
    }
    Err(PlatformError::Again)
}

/// Logical slot map for the bounded native bootstrap. Slot zero is the boot CPU;
/// other slots retain complete affinity values instead of truncating MPIDR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuTopology {
    pub affinity: [u64; cyxia_contracts::BOOT_CPUS],
    pub count: usize,
    pub conduit: cyxia_contracts::PsciConduit,
}
pub fn cpu_topology(
    info: &cyxia_contracts::BootInfo,
    boot: u64,
) -> Result<CpuTopology, cyxia_contracts::PlatformError> {
    use cyxia_contracts::PlatformError;
    if !(2..=cyxia_contracts::BOOT_CPUS).contains(&info.cpu_count)
        || boot & !0x0000_00ff_00ff_ffff != 0
    {
        return Err(PlatformError::Unsupported);
    }
    let conduit = info.psci.ok_or(PlatformError::Unsupported)?;
    let nodes = &info.cpus[..info.cpu_count];
    if !nodes.iter().any(|c| c.affinity == boot) || nodes.iter().any(|c| !c.psci) {
        return Err(PlatformError::Unsupported);
    }
    let mut result = CpuTopology {
        affinity: [0; cyxia_contracts::BOOT_CPUS],
        count: info.cpu_count,
        conduit,
    };
    result.affinity[0] = boot;
    let mut next = 1;
    for (i, cpu) in nodes.iter().enumerate() {
        if cpu.affinity & !0x0000_00ff_00ff_ffff != 0
            || nodes[..i].iter().any(|c| c.affinity == cpu.affinity)
        {
            return Err(PlatformError::Invalid);
        }
        if cpu.affinity != boot {
            result.affinity[next] = cpu.affinity;
            next += 1;
        }
    }
    Ok(result)
}
