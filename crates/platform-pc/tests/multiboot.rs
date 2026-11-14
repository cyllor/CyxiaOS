use cyxia_contracts::{MemoryRegion, RegionKind};
use cyxia_platform_pc::{
    BootError, MAX_MMAP_BYTES, MAX_PHYSICAL_MEMORY, MB_INFO_BYTES, MULTIBOOT_BOOT_MAGIC, PIT_100HZ,
    PcBootInfo, RESOURCES, memory_map_location, parse_multiboot,
};

const HEADER_PA: u64 = 0x9500;
const MAP_PA: u64 = 0x9000;
const KERNEL_START: u64 = 0x10_0000;
const KERNEL_END: u64 = 0x20_0000;

fn write_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn record(map: &mut Vec<u8>, base: u64, len: u64, kind: u32) {
    map.extend_from_slice(&20u32.to_le_bytes());
    map.extend_from_slice(&base.to_le_bytes());
    map.extend_from_slice(&len.to_le_bytes());
    map.extend_from_slice(&kind.to_le_bytes());
}

fn header(map: &[u8], address: u64) -> [u8; MB_INFO_BYTES] {
    let mut bytes = [0; MB_INFO_BYTES];
    // The flags QEMU's Multiboot loader actually supplies, including an
    // empty module list and strings which this board never dereferences.
    write_u32(&mut bytes, 0, 1 | 2 | 4 | 8 | 64 | 512);
    write_u32(&mut bytes, 4, 639);
    write_u32(&mut bytes, 8, 255 * 1024);
    write_u32(&mut bytes, 44, map.len() as u32);
    write_u32(&mut bytes, 48, address as u32);
    bytes
}

fn pc_map() -> Vec<u8> {
    let mut map = Vec::new();
    record(&mut map, 0, 0x9_fc00, 1);
    record(&mut map, 0x9_fc00, 0x400, 2);
    record(&mut map, 0xf_0000, 0x1_0000, 2);
    record(
        &mut map,
        KERNEL_START,
        MAX_PHYSICAL_MEMORY - KERNEL_START - 0x2_0000,
        1,
    );
    record(&mut map, MAX_PHYSICAL_MEMORY - 0x2_0000, 0x2_0000, 2);
    record(&mut map, 0xfffc_0000, 0x4_0000, 2);
    map
}

fn parse(map: &[u8]) -> Result<PcBootInfo, BootError> {
    parse_multiboot(
        MULTIBOOT_BOOT_MAGIC,
        &header(map, MAP_PA),
        HEADER_PA,
        map,
        MAP_PA,
        KERNEL_START,
        KERNEL_END,
    )
}

fn contains(regions: &[MemoryRegion], start: u64, end: u64) -> bool {
    regions
        .iter()
        .any(|r| r.start.0 <= start && end <= r.start.0 + r.len)
}

#[test]
fn qemu_map_preserves_ram_and_reserves_boot_storage() {
    let map = pc_map();
    let info = parse(&map).unwrap();
    assert_eq!(
        memory_map_location(&header(&map, MAP_PA)),
        Ok((MAP_PA, map.len()))
    );
    assert_eq!(info.resources, RESOURCES);
    assert_eq!(info.ram_regions().len(), 2);
    assert!(info.ram_regions().iter().all(|r| r.kind == RegionKind::Ram));
    assert!(
        info.reserved_regions()
            .iter()
            .all(|r| r.kind == RegionKind::Reserved)
    );
    assert!(contains(info.reserved_regions(), 0, KERNEL_END));
    assert!(contains(
        info.reserved_regions(),
        MAX_PHYSICAL_MEMORY - 0x2_0000,
        MAX_PHYSICAL_MEMORY
    ));
    assert!(!contains(info.ram_regions(), 0xa_0000, 0xf_0000));
    for region in info.ram_regions().iter().chain(info.reserved_regions()) {
        assert_eq!(region.start.0 % 4096, 0);
        assert_eq!(region.len % 4096, 0);
        assert!(region.start.0 + region.len <= MAX_PHYSICAL_MEMORY);
    }
}

#[test]
fn reserves_copied_boot_ranges_above_low_memory_outward() {
    let map = pc_map();
    let map_pa = 0x40_0ff0;
    let header_pa = 0x50_0ff0;
    let info = parse_multiboot(
        MULTIBOOT_BOOT_MAGIC,
        &header(&map, map_pa),
        header_pa,
        &map,
        map_pa,
        KERNEL_START,
        KERNEL_END + 1,
    )
    .unwrap();
    assert!(contains(info.reserved_regions(), 0x40_0000, 0x40_2000));
    assert!(contains(info.reserved_regions(), 0x50_0000, 0x50_2000));
    assert!(contains(
        info.reserved_regions(),
        KERNEL_START,
        KERNEL_END + 4096
    ));
}

#[test]
fn unordered_available_ranges_merge_and_round_inward() {
    let mut map = Vec::new();
    record(&mut map, 0x30_0000, 0x10_0801, 1);
    record(&mut map, 0x10_0001, 0x1f_ffff, 1);
    let info = parse_multiboot(
        MULTIBOOT_BOOT_MAGIC,
        &header(&map, MAP_PA),
        HEADER_PA,
        &map,
        MAP_PA,
        0x10_1000,
        KERNEL_END,
    )
    .unwrap();
    assert_eq!(info.ram_regions().len(), 1);
    assert_eq!(info.ram_regions()[0].start.0, 0x10_1000);
    assert_eq!(
        info.ram_regions()[0].start.0 + info.ram_regions()[0].len,
        0x40_0000
    );
}

#[test]
fn rejects_wrong_magic_every_header_truncation_and_missing_map_flag() {
    let map = pc_map();
    let mut bytes = header(&map, MAP_PA);
    assert_eq!(
        parse_multiboot(0, &bytes, HEADER_PA, &map, MAP_PA, KERNEL_START, KERNEL_END),
        Err(BootError::BadMagic)
    );
    for len in 0..MB_INFO_BYTES {
        assert_eq!(
            memory_map_location(&bytes[..len]),
            Err(BootError::HeaderLength)
        );
    }
    write_u32(&mut bytes, 0, 0);
    assert_eq!(
        memory_map_location(&bytes),
        Err(BootError::MissingMemoryMap)
    );
}

#[test]
fn rejects_extended_boot_structures_and_nonempty_modules() {
    let map = pc_map();
    for unsupported in [
        1 << 4,
        1 << 5,
        1 << 7,
        1 << 8,
        1 << 10,
        1 << 11,
        1 << 12,
        1 << 31,
    ] {
        let mut bytes = header(&map, MAP_PA);
        write_u32(&mut bytes, 0, 64 | unsupported);
        assert_eq!(
            memory_map_location(&bytes),
            Err(BootError::UnsupportedFlags)
        );
    }
    let mut bytes = header(&map, MAP_PA);
    write_u32(&mut bytes, 20, 1);
    assert_eq!(
        memory_map_location(&bytes),
        Err(BootError::UnsupportedModules)
    );
}

#[test]
fn boot_pointers_and_lengths_must_match_the_copied_map() {
    let map = pc_map();
    let bytes = header(&map, MAP_PA);
    assert_eq!(
        parse_multiboot(
            MULTIBOOT_BOOT_MAGIC,
            &bytes,
            HEADER_PA,
            &map,
            MAP_PA + 1,
            KERNEL_START,
            KERNEL_END
        ),
        Err(BootError::MemoryMapAddress)
    );
    for len in 0..map.len() {
        assert_eq!(
            parse_multiboot(
                MULTIBOOT_BOOT_MAGIC,
                &bytes,
                HEADER_PA,
                &map[..len],
                MAP_PA,
                KERNEL_START,
                KERNEL_END
            ),
            Err(BootError::MemoryMapLength)
        );
    }
    for address in [0, MAX_PHYSICAL_MEMORY - 1, 0xffff_fff0] {
        assert_eq!(
            memory_map_location(&header(&map, address)),
            Err(BootError::MemoryMapAddress)
        );
    }
    for address in [0, MAX_PHYSICAL_MEMORY - 1, 1u64 << 32, u64::MAX] {
        assert_eq!(
            parse_multiboot(
                MULTIBOOT_BOOT_MAGIC,
                &bytes,
                address,
                &map,
                MAP_PA,
                KERNEL_START,
                KERNEL_END
            ),
            Err(BootError::AddressRange)
        );
    }
    let mut too_large = bytes;
    write_u32(&mut too_large, 44, MAX_MMAP_BYTES as u32 + 1);
    assert_eq!(
        memory_map_location(&too_large),
        Err(BootError::MemoryMapLength)
    );
}

#[test]
fn rejects_overlapping_boot_storage_and_kernel() {
    let map = pc_map();
    for (header_pa, map_pa) in [
        (MAP_PA, MAP_PA),
        (KERNEL_START, MAP_PA),
        (HEADER_PA, KERNEL_START),
    ] {
        assert_eq!(
            parse_multiboot(
                MULTIBOOT_BOOT_MAGIC,
                &header(&map, map_pa),
                header_pa,
                &map,
                map_pa,
                KERNEL_START,
                KERNEL_END
            ),
            Err(BootError::Overlap)
        );
    }
}

#[test]
fn rejects_oversized_available_memory_even_without_basic_memory_fields() {
    let mut map = Vec::new();
    record(&mut map, KERNEL_START, MAX_PHYSICAL_MEMORY, 1);
    let mut bytes = header(&map, MAP_PA);
    write_u32(&mut bytes, 0, 64);
    assert_eq!(
        parse_multiboot(
            MULTIBOOT_BOOT_MAGIC,
            &bytes,
            HEADER_PA,
            &map,
            MAP_PA,
            KERNEL_START,
            KERNEL_END
        ),
        Err(BootError::UnsupportedMemory)
    );
    let map = pc_map();
    let mut bytes = header(&map, MAP_PA);
    write_u32(&mut bytes, 8, 256 * 1024);
    assert_eq!(
        memory_map_location(&bytes),
        Err(BootError::UnsupportedMemory)
    );
}

#[test]
fn rejects_raw_overlaps_before_rounding_can_hide_them() {
    let mut map = pc_map();
    record(&mut map, 0x30_0001, 1, 2);
    assert_eq!(parse(&map), Err(BootError::Overlap));
    let mut map = Vec::new();
    record(&mut map, 0x10_0001, 1, 1);
    record(&mut map, 0x10_0001, 1, 1);
    assert_eq!(parse(&map), Err(BootError::Overlap));
}

#[test]
fn rejects_truncated_zero_sized_and_overflowing_records() {
    for (start, len, kind) in [
        (KERNEL_START, 0, 1),
        (u64::MAX - 1, 4, 2),
        (KERNEL_START, 4096, 0),
    ] {
        let mut map = Vec::new();
        record(&mut map, start, len, kind);
        assert_eq!(parse(&map), Err(BootError::InvalidRecord));
    }
    for size in [0, 19, 21, u32::MAX] {
        let mut map = Vec::new();
        record(&mut map, KERNEL_START, 0x20_0000, 1);
        write_u32(&mut map, 0, size);
        assert_eq!(parse(&map), Err(BootError::InvalidRecord));
    }
    let mut map = pc_map();
    map.push(0);
    assert_eq!(parse(&map), Err(BootError::InvalidRecord));
}

#[test]
fn accepts_extended_map_records_without_interpreting_unknown_tail() {
    let mut map = Vec::new();
    record(&mut map, KERNEL_START, 0x40_0000, 1);
    write_u32(&mut map, 0, 24);
    map.extend_from_slice(&[0xff; 4]);
    assert!(parse(&map).is_ok());
}

#[test]
fn rejects_absent_ram_kernel_outside_ram_and_fully_reserved_ram() {
    let mut map = Vec::new();
    record(&mut map, 0, MAX_PHYSICAL_MEMORY, 2);
    assert_eq!(parse(&map), Err(BootError::NoUsableMemory));
    let mut map = Vec::new();
    record(&mut map, 0x40_0000, 0x40_0000, 1);
    assert_eq!(parse(&map), Err(BootError::KernelOutsideRam));
    let mut map = Vec::new();
    record(&mut map, KERNEL_START, KERNEL_END - KERNEL_START, 1);
    assert_eq!(parse(&map), Err(BootError::NoUsableMemory));
}

#[test]
fn rejects_excessive_fragmentation_without_truncation() {
    let mut map = Vec::new();
    record(&mut map, KERNEL_START, KERNEL_END - KERNEL_START, 1);
    for i in 0..8 {
        record(&mut map, 0x40_0000 + i * 8192, 4096, 1);
    }
    assert_eq!(parse(&map), Err(BootError::Capacity));
    let mut map = pc_map();
    for i in 0..65 {
        record(&mut map, 0x1_0000_0000 + i * 8192, 4096, 2);
    }
    // This synthetic map is larger than QEMU's 0x500-byte low-memory map
    // arena. Keep its header elsewhere so capacity is the failing condition.
    assert_eq!(
        parse_multiboot(
            MULTIBOOT_BOOT_MAGIC,
            &header(&map, MAP_PA),
            0xb000,
            &map,
            MAP_PA,
            KERNEL_START,
            KERNEL_END,
        ),
        Err(BootError::Capacity)
    );
}

#[test]
fn timer_uses_the_programmed_divisor_for_time_conversion() {
    assert_eq!(PIT_100HZ.divisor, 11932);
    assert_eq!(PIT_100HZ.input_hz, 1_193_182);
    assert_ne!(
        u64::from(PIT_100HZ.divisor) * 100,
        u64::from(PIT_100HZ.input_hz)
    );
}
