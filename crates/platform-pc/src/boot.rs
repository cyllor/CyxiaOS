#![forbid(unsafe_code)]

use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind};

use crate::{BoardResources, RESOURCES};

pub const MULTIBOOT_BOOT_MAGIC: u32 = 0x2bad_b002;
/// The original Multiboot information structure, including the VBE fields.
/// This board does not support the later framebuffer extension.
pub const MB_INFO_BYTES: usize = 88;
pub const MAX_MMAP_BYTES: usize = 4096;
/// The first PC profile deliberately matches the shared pool's 65,536 pages.
/// Larger RAM needs a separate profile and cannot be silently truncated.
pub const MAX_PHYSICAL_MEMORY: u64 = 256 * 1024 * 1024;
const PAGE_SIZE: u64 = 4096;
const LOW_MEMORY_END: u64 = 1024 * 1024;
const MAX_RECORDS: usize = 64;
const FLAG_MEMORY: u32 = 1;
const FLAG_MODULES: u32 = 1 << 3;
const FLAG_MMAP: u32 = 1 << 6;
const SUPPORTED_FLAGS: u32 =
    FLAG_MEMORY | (1 << 1) | (1 << 2) | FLAG_MODULES | FLAG_MMAP | (1 << 9);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootError {
    BadMagic,
    HeaderLength,
    UnsupportedFlags,
    MissingMemoryMap,
    UnsupportedModules,
    MemoryMapLength,
    MemoryMapAddress,
    AddressRange,
    UnsupportedMemory,
    InvalidRecord,
    Overlap,
    Capacity,
    NoUsableMemory,
    KernelOutsideRam,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcBootInfo {
    ram: [MemoryRegion; 8],
    ram_count: usize,
    reserved: [MemoryRegion; 32],
    reserved_count: usize,
    pub resources: BoardResources,
}

impl PcBootInfo {
    pub fn ram_regions(&self) -> &[MemoryRegion] {
        &self.ram[..self.ram_count]
    }

    pub fn reserved_regions(&self) -> &[MemoryRegion] {
        &self.reserved[..self.reserved_count]
    }
}

#[derive(Clone, Copy)]
struct RawRegion {
    start: u64,
    end: u64,
    kind: u32,
}

impl RawRegion {
    const EMPTY: Self = Self {
        start: 0,
        end: 0,
        kind: 0,
    };
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn bounded_range(start: u64, len: u64) -> Result<u64, BootError> {
    let end = start.checked_add(len).ok_or(BootError::AddressRange)?;
    if start == 0 || len == 0 || end > MAX_PHYSICAL_MEMORY {
        return Err(BootError::AddressRange);
    }
    Ok(end)
}

/// Decode without dereferencing physical pointers. The caller must copy the
/// 88-byte header from a mapped, bounded physical range before calling this.
/// The returned map range is nonempty and lies below the 256 MiB boot limit.
/// Ignored command-line/loader strings are never dereferenced or retained.
pub fn memory_map_location(header: &[u8]) -> Result<(u64, usize), BootError> {
    if header.len() != MB_INFO_BYTES {
        return Err(BootError::HeaderLength);
    }
    let flags = u32_at(header, 0);
    if flags & !SUPPORTED_FLAGS != 0 {
        return Err(BootError::UnsupportedFlags);
    }
    if flags & FLAG_MMAP == 0 {
        return Err(BootError::MissingMemoryMap);
    }
    // QEMU sets MODULES even for an empty list; no module payload can be
    // admitted without describing and reserving every module first.
    if flags & FLAG_MODULES != 0 && u32_at(header, 20) != 0 {
        return Err(BootError::UnsupportedModules);
    }
    if flags & FLAG_MEMORY != 0 {
        if u32_at(header, 4) > 1024 {
            return Err(BootError::UnsupportedMemory);
        }
        let upper_end = u64::from(u32_at(header, 8)) * 1024 + LOW_MEMORY_END;
        if upper_end > MAX_PHYSICAL_MEMORY {
            return Err(BootError::UnsupportedMemory);
        }
    }
    let len = u32_at(header, 44) as usize;
    let address = u64::from(u32_at(header, 48));
    if !(24..=MAX_MMAP_BYTES).contains(&len) {
        return Err(BootError::MemoryMapLength);
    }
    bounded_range(address, len as u64).map_err(|_| BootError::MemoryMapAddress)?;
    Ok((address, len))
}

fn overlap(a: u64, a_end: u64, b: u64, b_end: u64) -> bool {
    a < b_end && b < a_end
}

fn insert_region<const N: usize>(
    regions: &mut [MemoryRegion; N],
    count: &mut usize,
    mut start: u64,
    mut end: u64,
    kind: RegionKind,
) -> Result<(), BootError> {
    if start >= end {
        return Ok(());
    }
    // Merge first, so overlapping reservations do not consume extra slots.
    // This also coalesces adjacent RAM, while raw map overlap is rejected
    // separately before any page rounding can hide it.
    let mut i = 0;
    while i < *count {
        let item_end = regions[i].start.0 + regions[i].len;
        if start <= item_end && regions[i].start.0 <= end {
            start = start.min(regions[i].start.0);
            end = end.max(item_end);
            for j in i..*count - 1 {
                regions[j] = regions[j + 1];
            }
            *count -= 1;
        } else {
            i += 1;
        }
    }
    if *count == N {
        return Err(BootError::Capacity);
    }
    let mut index = *count;
    while index > 0 && regions[index - 1].start.0 > start {
        regions[index] = regions[index - 1];
        index -= 1;
    }
    regions[index] = MemoryRegion {
        start: PhysAddr(start),
        len: end - start,
        kind,
    };
    *count += 1;
    Ok(())
}

fn reserve(info: &mut PcBootInfo, start: u64, end: u64) -> Result<(), BootError> {
    let start = start & !(PAGE_SIZE - 1);
    let end = end
        .checked_add(PAGE_SIZE - 1)
        .ok_or(BootError::AddressRange)?
        & !(PAGE_SIZE - 1);
    insert_region(
        &mut info.reserved,
        &mut info.reserved_count,
        start,
        end,
        RegionKind::Reserved,
    )
}

/// Parse copied Multiboot bytes with no physical accesses or allocation.
///
/// Available RAM is rounded inward; reservations are rounded outward. Raw
/// map entries may be unordered but must not overlap (including firmware
/// reservations). Reserved ranges above the managed window are validated and
/// ignored; *available* RAM above 256 MiB rejects this profile. Modules and
/// unimplemented information extensions are rejected rather than left live
/// in memory the allocator could reuse.
pub fn parse_multiboot(
    magic: u32,
    header: &[u8],
    header_pa: u64,
    mmap: &[u8],
    mmap_pa: u64,
    kernel_start: u64,
    kernel_end: u64,
) -> Result<PcBootInfo, BootError> {
    if magic != MULTIBOOT_BOOT_MAGIC {
        return Err(BootError::BadMagic);
    }
    let (expected_pa, expected_len) = memory_map_location(header)?;
    if expected_pa != mmap_pa {
        return Err(BootError::MemoryMapAddress);
    }
    if expected_len != mmap.len() {
        return Err(BootError::MemoryMapLength);
    }
    let header_end = bounded_range(header_pa, MB_INFO_BYTES as u64)?;
    let mmap_end = bounded_range(mmap_pa, mmap.len() as u64)?;
    if kernel_start < LOW_MEMORY_END
        || kernel_start >= kernel_end
        || kernel_end > MAX_PHYSICAL_MEMORY
    {
        return Err(BootError::AddressRange);
    }
    if overlap(header_pa, header_end, mmap_pa, mmap_end)
        || overlap(header_pa, header_end, kernel_start, kernel_end)
        || overlap(mmap_pa, mmap_end, kernel_start, kernel_end)
    {
        return Err(BootError::Overlap);
    }

    let mut raw = [RawRegion::EMPTY; MAX_RECORDS];
    let mut count = 0;
    let mut cursor = 0usize;
    while cursor < mmap.len() {
        if mmap.len() - cursor < 4 {
            return Err(BootError::InvalidRecord);
        }
        let payload_len = u32_at(mmap, cursor) as usize;
        let next = cursor
            .checked_add(4)
            .and_then(|n| n.checked_add(payload_len))
            .ok_or(BootError::InvalidRecord)?;
        if payload_len < 20 || next > mmap.len() {
            return Err(BootError::InvalidRecord);
        }
        let start = u64_at(mmap, cursor + 4);
        let len = u64_at(mmap, cursor + 12);
        let kind = u32_at(mmap, cursor + 20);
        let end = start.checked_add(len).ok_or(BootError::InvalidRecord)?;
        if len == 0 || kind == 0 {
            return Err(BootError::InvalidRecord);
        }
        if kind == 1 && end > MAX_PHYSICAL_MEMORY {
            return Err(BootError::UnsupportedMemory);
        }
        if raw[..count]
            .iter()
            .any(|r| overlap(start, end, r.start, r.end))
        {
            return Err(BootError::Overlap);
        }
        if count == MAX_RECORDS {
            return Err(BootError::Capacity);
        }
        raw[count] = RawRegion { start, end, kind };
        count += 1;
        cursor = next;
    }

    let mut info = PcBootInfo {
        ram: [MemoryRegion::EMPTY; 8],
        ram_count: 0,
        reserved: [MemoryRegion::EMPTY; 32],
        reserved_count: 0,
        resources: RESOURCES,
    };
    for r in &raw[..count] {
        if r.kind == 1 {
            let start = (r.start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let end = r.end & !(PAGE_SIZE - 1);
            insert_region(
                &mut info.ram,
                &mut info.ram_count,
                start,
                end,
                RegionKind::Ram,
            )?;
        } else if r.start < MAX_PHYSICAL_MEMORY {
            reserve(&mut info, r.start, r.end.min(MAX_PHYSICAL_MEMORY))?;
        }
    }
    if info.ram_count == 0 {
        return Err(BootError::NoUsableMemory);
    }
    if !info
        .ram_regions()
        .iter()
        .any(|r| r.start.0 <= kernel_start && kernel_end <= r.start.0 + r.len)
    {
        return Err(BootError::KernelOutsideRam);
    }
    reserve(&mut info, 0, LOW_MEMORY_END)?;
    reserve(&mut info, kernel_start, kernel_end)?;
    reserve(&mut info, header_pa, header_end)?;
    reserve(&mut info, mmap_pa, mmap_end)?;
    if !info.ram_regions().iter().any(|ram| {
        let mut cursor = ram.start.0;
        let end = ram.start.0 + ram.len;
        for reserved in info.reserved_regions() {
            if reserved.start.0 >= end {
                break;
            }
            if cursor < reserved.start.0 {
                return true;
            }
            cursor = cursor.max(reserved.start.0 + reserved.len);
            if cursor >= end {
                return false;
            }
        }
        cursor < end
    }) {
        return Err(BootError::NoUsableMemory);
    }
    Ok(info)
}
