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
