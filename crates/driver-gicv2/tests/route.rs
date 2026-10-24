use cyxia_contracts::{GicResource, PhysAddr};
use cyxia_driver_gicv2::Gic;

#[test]
fn real_route_primitive_writes_only_a_masked_inactive_spi_target_register() {
    // Backed register pages verify the exact MMIO address and refusal paths;
    // actual interrupt delivery still requires the native GIC smoke test.
    let mut dist = Box::new([0u32; 1024]);
    let mut interface = Box::new([0u32; 1024]);
    dist[1] = 3; // 128 implemented lines.
    let resource = GicResource {
        distributor: PhysAddr(dist.as_mut_ptr() as u64),
        distributor_len: 4096,
        cpu: PhysAddr(interface.as_mut_ptr() as u64),
        cpu_len: 4096,
    };
    let gic = unsafe { Gic::new(resource) }.unwrap();
    gic.route_masked_spi(40, 3).unwrap();
    assert_eq!(gic.spi_target_mask(40), Ok(8));
    assert_eq!(dist[(0x800 + 40) / 4] & 255, 8);
    for (irq, cpu) in [(27, 3), (15, 0), (128, 0), (40, 8)] {
        assert!(gic.route_masked_spi(irq, cpu).is_err());
    }
    dist[(0x100 + 4) / 4] = 1 << 8;
    assert!(gic.route_masked_spi(40, 0).is_err());
    dist[(0x100 + 4) / 4] = 0;
    dist[(0x300 + 4) / 4] = 1 << 8;
    assert!(gic.route_masked_spi(40, 0).is_err());
    assert_eq!(gic.spi_target_mask(40), Ok(8));
}

#[test]
fn sgi_uses_the_registered_banked_target_mask_without_editing_spi_routing() {
    let mut dist = Box::new([0u32; 1024]);
    let mut interface = Box::new([0u32; 1024]);
    dist[1] = 3;
    dist[0x800 / 4] = 0x04040404;
    let gic = unsafe {
        Gic::new(GicResource {
            distributor: PhysAddr(dist.as_mut_ptr() as u64),
            distributor_len: 4096,
            cpu: PhysAddr(interface.as_mut_ptr() as u64),
            cpu_len: 4096,
        })
    }
    .unwrap();
    assert_eq!(gic.local_target_mask(), Ok(4));
    gic.send_sgi(0, 4).unwrap();
    assert_eq!(dist[0xf00 / 4], 4 << 16);
    assert_eq!(dist[0x800 / 4], 0x04040404);
    assert!(gic.send_sgi(16, 4).is_err());
    assert!(gic.send_sgi(0, 0).is_err());
    assert_eq!(dist[0xf00 / 4], 4 << 16);
    dist[0x800 / 4] = 3;
    assert!(gic.local_target_mask().is_err());
}
