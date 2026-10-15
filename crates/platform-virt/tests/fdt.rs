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
