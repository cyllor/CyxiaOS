use cyxia_contracts::transport::*;
#[test]
fn crc_standard_vector() {
    assert_eq!(crc32(b"123456789"), 0xcbf43926);
}
#[test]
fn wire_is_bounded_and_explicit() {
    let mut b = [0u8; 128];
    let n = encode(1, 1, b"BOOT_ENTRY", &mut b).unwrap();
    assert_eq!(n, 38);
    assert_eq!(&b[..8], b"CYX1\x01\x00\x0a\x00");
    assert_eq!(&b[24..34], b"BOOT_ENTRY");
    assert!(encode(1, 2, &[0; 97], &mut b).is_err());
    assert!(encode(0, 1, b"x", &mut b).is_err());
}
