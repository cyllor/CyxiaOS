use cyxia_arch_aarch64::mmu::*;
use cyxia_contracts::*;
#[test]
fn permissions_and_attributes() {
    let rx = encode_leaf(
        PhysAddr(0x40200000),
        PagePermissions::new(false, true).unwrap(),
        MemoryAttr::Normal,
    )
    .unwrap();
    assert_ne!(rx & (1 << 7), 0);
    assert_eq!(rx & (1 << 53), 0);
    assert_ne!(rx & (1 << 54), 0);
    let d = encode_leaf(
        PhysAddr(0x9000000),
        PagePermissions::new(true, false).unwrap(),
        MemoryAttr::Device,
    )
    .unwrap();
    assert_eq!((d >> 2) & 7, 1);
    assert_ne!(d & (1 << 53), 0);
}
#[test]
fn invalid_pa_rejected() {
    for pa in [1, 0x1001, 1u64 << 48] {
        assert!(
            encode_leaf(
                PhysAddr(pa),
                PagePermissions::new(false, true).unwrap(),
                MemoryAttr::Normal
            )
            .is_err()
        );
    }
}
