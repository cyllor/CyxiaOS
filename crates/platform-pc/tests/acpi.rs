use cyxia_platform_pc::acpi::{parse_madt, parse_root, parse_rsdp};

fn checksum(bytes: &mut [u8], field: usize) {
    bytes[field] = 0;
    bytes[field] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)));
}
fn table(signature: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 36];
    b[..4].copy_from_slice(signature);
    b.extend_from_slice(payload);
    let len = b.len() as u32;
    b[4..8].copy_from_slice(&len.to_le_bytes());
    b[8] = 1;
    checksum(&mut b, 9);
    b
}
fn madt(ids: &[(u8, u32)]) -> Vec<u8> {
    let mut payload = vec![0, 0, 0xe0, 0xfe, 1, 0, 0, 0];
    for &(id, flags) in ids {
        payload.extend_from_slice(&[0, 8, id, id]);
        payload.extend_from_slice(&flags.to_le_bytes());
    }
    table(b"APIC", &payload)
}

// Break caught: treating the APIC ID as an array index or assuming BSP ID zero.
#[test]
fn sparse_firmware_ids_keep_bsp_in_logical_slot_zero() {
    let topology = parse_madt(&madt(&[(17, 1), (3, 1), (29, 1), (8, 1)]), 29).unwrap();
    assert_eq!(topology.apic_ids, [29, 17, 3, 8]);
    assert_eq!(topology.count, 4);
    assert_eq!(topology.lapic_base, 0xfee0_0000);
}
#[test]
fn disabled_processors_are_not_admitted() {
    let topology = parse_madt(&madt(&[(5, 1), (7, 0), (12, 2), (19, 1)]), 5).unwrap();
    assert_eq!(topology.count, 2);
    assert_eq!(&topology.apic_ids[..2], &[5, 19]);
}
#[test]
fn duplicate_missing_bsp_and_cpu_capacity_fail_closed() {
    for (ids, bsp) in [
        (vec![(5, 1), (5, 1)], 5),
        (vec![(5, 1), (7, 1)], 9),
        (vec![(1, 1), (2, 1), (3, 1), (4, 1), (5, 1)], 1),
    ] {
        assert!(parse_madt(&madt(&ids), bsp).is_err());
    }
}
#[test]
fn damaged_checksum_truncation_and_zero_length_subrecord_are_rejected() {
    let good = madt(&[(5, 1)]);
    let mut bad = good.clone();
    bad[40] ^= 1;
    assert!(parse_madt(&bad, 5).is_err());
    assert!(parse_madt(&good[..good.len() - 1], 5).is_err());
    let mut bad = good;
    bad[45] = 0;
    checksum(&mut bad, 9);
    assert!(parse_madt(&bad, 5).is_err());
}
#[test]
fn enabled_x2apic_cannot_disappear_from_discovery() {
    let mut b = madt(&[(5, 1)]);
    b.extend_from_slice(&[9, 16, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0]);
    let len = b.len() as u32;
    b[4..8].copy_from_slice(&len.to_le_bytes());
    checksum(&mut b, 9);
    assert!(parse_madt(&b, 5).is_err());
}
#[test]
fn root_table_checks_pointer_stride_and_rsdp_checksums() {
    let mut rsdp = [0u8; 20];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[16..20].copy_from_slice(&0x7ff_000u32.to_le_bytes());
    checksum(&mut rsdp, 8);
    assert_eq!(parse_rsdp(&rsdp).unwrap().address, 0x7ff000);
    rsdp[9] ^= 1;
    assert!(parse_rsdp(&rsdp).is_err());
    assert_eq!(
        parse_root(&table(b"RSDT", &0x7fe000u32.to_le_bytes()))
            .unwrap()
            .get(0),
        Some(0x7fe000)
    );
    assert!(parse_root(&table(b"RSDT", &[0, 0, 0])).is_err());
}
