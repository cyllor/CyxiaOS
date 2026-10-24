use cyxia_platform_virt::fdt::*;
const DTB: &[u8] = include_bytes!("../../../tests/fixtures/fdt/virt.dtb");
fn set(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
#[test]
fn valid_virt_resources() {
    let i = parse_fdt(DTB).unwrap();
    assert_eq!(i.ram[0].start.0, 0x40000000);
    assert_eq!(i.ram[0].len, 256 * 1024 * 1024);
    assert_eq!(i.uart.unwrap().base.0, 0x09000000);
    assert_eq!(i.gic.unwrap().distributor.0, 0x08000000);
    assert_eq!(i.timer_irq, Some(30));
    assert_eq!(i.rtc.unwrap().base.0, 0x09010000);
}
#[test]
fn rtc_is_optional_but_cannot_alias_another_device() {
    let mut absent = DTB.to_vec();
    let compat = absent.windows(9).position(|b| b == b"arm,pl031").unwrap();
    absent[compat] = b'X';
    assert!(parse_fdt(&absent).unwrap().rtc.is_none());
    let mut overlap = DTB.to_vec();
    let address = 0x09010000u64.to_be_bytes();
    let at = overlap.windows(8).position(|b| b == address).unwrap();
    overlap[at..at + 8].copy_from_slice(&0x09000000u64.to_be_bytes());
    assert_eq!(parse_fdt(&overlap), Err(FdtError::Overlap));
}
#[test]
fn truncated_header() {
    assert!(parse_fdt(&DTB[..30]).is_err());
}
#[test]
fn overflowing_block() {
    let mut b = DTB.to_vec();
    set(&mut b, 8, u32::MAX - 3);
    assert!(parse_fdt(&b).is_err());
}
#[test]
fn unterminated_string() {
    let mut b = DTB.to_vec();
    let s = u32::from_be_bytes(b[12..16].try_into().unwrap()) as usize;
    for x in &mut b[s..] {
        if *x == 0 {
            *x = b'X'
        }
    }
    assert!(parse_fdt(&b).is_err());
}
#[test]
fn missing_timer() {
    let mut b = DTB.to_vec();
    let at = b
        .windows(b"arm,armv8-timer".len())
        .position(|x| x == b"arm,armv8-timer")
        .unwrap();
    b[at] = b'X';
    assert!(parse_fdt(&b).is_err());
}
#[test]
fn every_truncation_rejected_without_panic() {
    for n in 0..DTB.len() {
        assert!(parse_fdt(&DTB[..n]).is_err());
    }
}
fn mini(structure: &[u8], strings: &[u8], reservations: &[(u64, u64)]) -> Vec<u8> {
    let reserve_len = (reservations.len() + 1) * 16;
    let start = 40 + reserve_len;
    let so = start + structure.len();
    let total = so + strings.len();
    let mut b = vec![0; total];
    for (at, value) in [
        (0, 0xd00dfeed),
        (4, total as u32),
        (8, start as u32),
        (12, so as u32),
        (16, 40),
        (20, 17),
        (24, 16),
        (32, strings.len() as u32),
        (36, structure.len() as u32),
    ] {
        set(&mut b, at, value);
    }
    for (i, (a, n)) in reservations.iter().enumerate() {
        b[40 + i * 16..48 + i * 16].copy_from_slice(&a.to_be_bytes());
        b[48 + i * 16..56 + i * 16].copy_from_slice(&n.to_be_bytes());
    }
    b[start..so].copy_from_slice(structure);
    b[so..].copy_from_slice(strings);
    b
}
fn w(v: &mut Vec<u8>, x: u32) {
    v.extend(x.to_be_bytes());
}
#[test]
fn deep_tree() {
    let mut s = vec![];
    for _ in 0..33 {
        w(&mut s, 1);
        w(&mut s, 0);
    }
    assert_eq!(parse_fdt(&mini(&s, &[], &[])), Err(FdtError::Capacity));
}
#[test]
fn reserved_overlap() {
    assert_eq!(
        parse_fdt(&mini(
            &[0; 4],
            &[],
            &[(0x40000000, 8192), (0x40001000, 4096)]
        )),
        Err(FdtError::Overlap)
    );
}
#[test]
fn wrong_cell_width() {
    let mut s = vec![];
    w(&mut s, 1);
    w(&mut s, 0);
    w(&mut s, 3);
    w(&mut s, 4);
    w(&mut s, 0);
    w(&mut s, 3);
    w(&mut s, 1);
    s.extend(b"memory@0\0\0\0\0");
    w(&mut s, 3);
    w(&mut s, 12);
    w(&mut s, 15);
    for v in [0, 0x40000000, 4096] {
        w(&mut s, v)
    }
    w(&mut s, 2);
    assert_eq!(
        parse_fdt(&mini(&s, b"#address-cells\0\0reg\0", &[])),
        Err(FdtError::Cells)
    );
}

#[test]
fn discovers_all_virtio_mmio_slots() {
    let info = parse_fdt(DTB).unwrap();
    assert_eq!(info.virtio_count, 32);
    for resource in &info.virtio[..info.virtio_count] {
        assert_eq!(resource.len, 0x200);
        assert!((0x0a000000..0x0a004000).contains(&resource.base.0));
        assert!((48..80).contains(&resource.irq));
    }
}

#[test]
fn rejects_virtio_overlap_with_ram() {
    let mut blob = DTB.to_vec();
    let address = 0x0a000000u64.to_be_bytes();
    let at = blob.windows(8).position(|bytes| bytes == address).unwrap();
    blob[at..at + 8].copy_from_slice(&0x40000000u64.to_be_bytes());
    assert_eq!(parse_fdt(&blob), Err(FdtError::Overlap));
}

fn devices(count: usize, disabled: bool, nested: bool, irq: u32) -> Vec<u8> {
    fn begin(out: &mut Vec<u8>, name: &[u8]) {
        w(out, 1);
        out.extend(name);
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    fn property(out: &mut Vec<u8>, strings: &mut Vec<u8>, name: &[u8], value: &[u8]) {
        let offset = strings.len();
        strings.extend(name);
        strings.push(0);
        w(out, 3);
        w(out, value.len() as u32);
        w(out, offset as u32);
        out.extend(value);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    fn resource(
        out: &mut Vec<u8>,
        strings: &mut Vec<u8>,
        name: &[u8],
        compat: &[u8],
        registers: &[u64],
        interrupts: &[u32],
    ) {
        begin(out, name);
        if !compat.is_empty() {
            property(out, strings, b"compatible", compat);
        }
        if !registers.is_empty() {
            let data: Vec<u8> = registers.iter().flat_map(|x| x.to_be_bytes()).collect();
            property(out, strings, b"reg", &data);
        }
        if !interrupts.is_empty() {
            let data: Vec<u8> = interrupts.iter().flat_map(|x| x.to_be_bytes()).collect();
            property(out, strings, b"interrupts", &data);
        }
    }
    let (mut s, mut strings) = (vec![], vec![]);
    begin(&mut s, b"");
    property(&mut s, &mut strings, b"#address-cells", &2u32.to_be_bytes());
    property(&mut s, &mut strings, b"#size-cells", &2u32.to_be_bytes());
    resource(
        &mut s,
        &mut strings,
        b"memory@40000000",
        b"",
        &[0x40000000, 0x10000000],
        &[],
    );
    w(&mut s, 2);
    resource(
        &mut s,
        &mut strings,
        b"uart",
        b"arm,pl011\0",
        &[0x09000000, 0x1000],
        &[],
    );
    w(&mut s, 2);
    resource(
        &mut s,
        &mut strings,
        b"gic",
        b"arm,cortex-a15-gic\0",
        &[0x08000000, 0x1000, 0x08010000, 0x1000],
        &[],
    );
    w(&mut s, 2);
    resource(
        &mut s,
        &mut strings,
        b"timer",
        b"arm,armv8-timer\0",
        &[],
        &[1, 13, 4, 1, 14, 4],
    );
    w(&mut s, 2);
    if nested {
        begin(&mut s, b"bus");
    }
    for i in 0..count {
        resource(
            &mut s,
            &mut strings,
            b"virtio",
            b"virtio,mmio\0",
            &[0x0a000000 + i as u64 * 0x200, 0x200],
            &[0, irq, 1],
        );
        if disabled {
            property(&mut s, &mut strings, b"status", b"disabled\0");
        }
        w(&mut s, 2);
    }
    if nested {
        w(&mut s, 2);
    }
    w(&mut s, 2);
    w(&mut s, 9);
    mini(&s, &strings, &[])
}
#[test]
fn disabled_virtio_is_not_enumerated() {
    assert_eq!(
        parse_fdt(&devices(1, true, false, 16))
            .unwrap()
            .virtio_count,
        0
    );
}
#[test]
fn excessive_virtio_devices_fail_closed() {
    assert_eq!(
        parse_fdt(&devices(33, false, false, 16)),
        Err(FdtError::Capacity)
    );
}
#[test]
fn translated_bus_and_invalid_irq_fail_closed() {
    assert_eq!(
        parse_fdt(&devices(1, false, true, 16)),
        Err(FdtError::Unsupported)
    );
    assert_eq!(
        parse_fdt(&devices(1, false, false, 988)),
        Err(FdtError::Unsupported)
    );
}

fn smp_blob(cpus: &[(u64, bool)], method: &[u8], duplicate_reg: bool, width: u32) -> Vec<u8> {
    fn begin(s: &mut Vec<u8>, name: &[u8]) {
        w(s, 1);
        s.extend(name);
        s.push(0);
        while !s.len().is_multiple_of(4) {
            s.push(0);
        }
    }
    fn prop(s: &mut Vec<u8>, names: &mut Vec<u8>, key: &[u8], value: &[u8]) {
        let offset = names.len();
        names.extend(key);
        names.push(0);
        w(s, 3);
        w(s, value.len() as u32);
        w(s, offset as u32);
        s.extend(value);
        while !s.len().is_multiple_of(4) {
            s.push(0);
        }
    }
    let base = devices(0, false, false, 16);
    let so = u32::from_be_bytes(base[8..12].try_into().unwrap()) as usize;
    let sl = u32::from_be_bytes(base[36..40].try_into().unwrap()) as usize;
    let st = u32::from_be_bytes(base[12..16].try_into().unwrap()) as usize;
    let mut s = base[so..so + sl - 8].to_vec();
    let mut names = base[st..].to_vec();
    begin(&mut s, b"cpus");
    prop(&mut s, &mut names, b"#address-cells", &width.to_be_bytes());
    prop(&mut s, &mut names, b"#size-cells", &0u32.to_be_bytes());
    for (affinity, enabled) in cpus {
        begin(&mut s, format!("cpu@{affinity:x}").as_bytes());
        prop(&mut s, &mut names, b"device_type", b"cpu\0");
        prop(&mut s, &mut names, b"enable-method", b"psci\0");
        let value = affinity.to_be_bytes();
        let value = if width == 1 { &value[4..] } else { &value[..] };
        prop(&mut s, &mut names, b"reg", value);
        if duplicate_reg {
            prop(&mut s, &mut names, b"reg", value);
        }
        if !enabled {
            prop(&mut s, &mut names, b"status", b"disabled\0");
        }
        w(&mut s, 2);
    }
    w(&mut s, 2);
    if !method.is_empty() {
        begin(&mut s, b"psci");
        prop(
            &mut s,
            &mut names,
            b"compatible",
            b"arm,psci-1.0\0arm,psci-0.2\0",
        );
        prop(&mut s, &mut names, b"method", method);
        w(&mut s, 2);
    }
    w(&mut s, 2);
    w(&mut s, 9);
    mini(&s, &names, &[])
}
#[test]
fn native_smp_topology_preserves_full_affinities_and_moves_boot_slot_first() {
    let b = smp_blob(
        &[(0x100, true), (0, true), (0x1_00000000, true), (1, true)],
        b"hvc\0",
        false,
        2,
    );
    let info = parse_fdt(&b).unwrap();
    let topo = cyxia_platform_virt::cpu_topology(&info, 0).unwrap();
    assert_eq!(topo.count, 4);
    assert_eq!(&topo.affinity[..4], &[0, 0x100, 0x1_00000000, 1]);
    assert_eq!(info.psci, Some(cyxia_contracts::PsciConduit::Hvc));
}
#[test]
fn disabled_cpu_not_started_and_smc_conduit_is_explicit() {
    let b = smp_blob(&[(0, true), (1, false), (2, true)], b"smc\0", false, 1);
    let info = parse_fdt(&b).unwrap();
    assert_eq!(info.cpu_count, 2);
    assert_eq!(
        &cyxia_platform_virt::cpu_topology(&info, 0)
            .unwrap()
            .affinity[..2],
        &[0, 2]
    );
    assert_eq!(info.psci, Some(cyxia_contracts::PsciConduit::Smc));
}
#[test]
fn duplicate_cpu_affinity_and_property_are_rejected() {
    assert_eq!(
        parse_fdt(&smp_blob(&[(0, true), (0, true)], b"hvc\0", false, 1)),
        Err(FdtError::Overlap)
    );
    assert_eq!(
        parse_fdt(&smp_blob(&[(0, true), (1, true)], b"hvc\0", true, 1)),
        Err(FdtError::Structure)
    );
}
#[test]
fn malformed_cpu_affinity_conduit_or_width_are_rejected() {
    assert!(
        parse_fdt(&smp_blob(
            &[(0, true), (0x1000000, true)],
            b"hvc\0",
            false,
            2
        ))
        .is_err()
    );
    assert!(parse_fdt(&smp_blob(&[(0, true), (1, true)], b"random\0", false, 1)).is_err());
    assert!(parse_fdt(&smp_blob(&[(0, true), (1, true)], b"hvc\0", false, 3)).is_err());
}
#[test]
fn missing_psci_or_boot_cpu_and_excessive_cpu_count_fail_shut() {
    let info = parse_fdt(&smp_blob(&[(0, true), (1, true)], b"", false, 1)).unwrap();
    assert!(cyxia_platform_virt::cpu_topology(&info, 0).is_err());
    let info = parse_fdt(&smp_blob(&[(1, true), (2, true)], b"hvc\0", false, 1)).unwrap();
    assert!(cyxia_platform_virt::cpu_topology(&info, 0).is_err());
    let cpus: Vec<_> = (0..9).map(|i| (i, true)).collect();
    assert_eq!(
        parse_fdt(&smp_blob(&cpus, b"hvc\0", false, 1)),
        Err(FdtError::Capacity)
    );
}
#[test]
fn smp_parser_every_truncation_fails_without_panic() {
    let b = smp_blob(
        &[(0, true), (1, true), (2, true), (3, true)],
        b"hvc\0",
        false,
        1,
    );
    for n in 0..b.len() {
        assert!(parse_fdt(&b[..n]).is_err());
    }
}
