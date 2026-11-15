use cyxia_driver_virtio::{Error, MappedRegion, PciRegions, Transport};

#[repr(C, align(8))]
struct Registers([u8; 256]);
fn region(registers: &mut Registers, len: usize) -> MappedRegion {
    MappedRegion {
        base: registers.0.as_mut_ptr() as usize,
        len,
    }
}
fn registers() -> (
    Box<Registers>,
    Box<Registers>,
    Box<Registers>,
    Box<Registers>,
) {
    (
        Box::new(Registers([0; 256])),
        Box::new(Registers([0; 256])),
        Box::new(Registers([0; 256])),
        Box::new(Registers([0; 256])),
    )
}

#[test]
fn modern_pci_uses_exact_status_and_feature_register_widths() {
    let (mut common, mut notify, mut isr, mut config) = registers();
    common.0[4..8].copy_from_slice(&1u32.to_le_bytes());
    common.0[20..24].copy_from_slice(&[0, 0x87, 0x65, 0x43]);
    let mut t = unsafe {
        Transport::attach_pci(PciRegions {
            device_id: 4,
            common: region(&mut common, 56),
            notify: region(&mut notify, 64),
            isr: region(&mut isr, 1),
            device: Some(region(&mut config, 256)),
            notify_multiplier: 4,
        })
    }
    .unwrap();
    assert_eq!(t.device_id(), 4);
    t.fail();
    assert_eq!(&common.0[20..24], &[128, 0x87, 0x65, 0x43]);
    // PCI ISR read acknowledges in hardware; there is no write-to-ack register.
    isr.0[0..4].copy_from_slice(&[3, 0x12, 0x34, 0x56]);
    assert_eq!(t.acknowledge_interrupt(), 3);
    assert_eq!(&isr.0[..4], &[3, 0x12, 0x34, 0x56]);
}

#[test]
fn pci_attach_rejects_truncated_unaligned_overlapping_and_missing_resources() {
    let (mut common, mut notify, mut isr, mut config) = registers();
    let resources = PciRegions {
        device_id: 2,
        common: region(&mut common, 56),
        notify: region(&mut notify, 64),
        isr: region(&mut isr, 1),
        device: Some(region(&mut config, 8)),
        notify_multiplier: 4,
    };
    let mut cases = Vec::new();
    let mut r = resources;
    r.common.len = 55;
    cases.push(r);
    let mut r = resources;
    r.common.base += 1;
    cases.push(r);
    let mut r = resources;
    r.notify.len = 1;
    cases.push(r);
    let mut r = resources;
    r.isr.base = r.common.base;
    cases.push(r);
    let mut r = resources;
    r.device = None;
    cases.push(r);
    let mut r = resources;
    r.device.as_mut().unwrap().len = 7;
    cases.push(r);
    for r in cases {
        assert!(matches!(
            unsafe { Transport::attach_pci(r) },
            Err(Error::Address)
        ));
    }
}

struct Host;
unsafe impl cyxia_driver_virtio::Platform for Host {
    fn physical(&self, address: usize, _: usize) -> Result<u64, Error> {
        Ok(address as u64)
    }
    unsafe fn sync(&self, _: usize, _: usize) {}
    fn barrier(&self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
    fn now_ms(&self) -> u64 {
        0
    }
}

#[test]
fn queue_configuration_and_notify_obey_pci_field_widths_and_multiplier() {
    use cyxia_driver_virtio::{Queue, QueueMemory};
    let (mut common, mut notify, mut isr, mut config) = registers();
    common.0[4..8].copy_from_slice(&1u32.to_le_bytes());
    common.0[16..20].copy_from_slice(&[0x34, 0x12, 2, 0]);
    common.0[21] = 0x87;
    common.0[24..32].copy_from_slice(&[16, 0, 0x55, 0xaa, 0, 0, 3, 0]);
    notify.0.fill(0xa5);
    let mut t = unsafe {
        Transport::attach_pci(PciRegions {
            device_id: 4,
            common: region(&mut common, 56),
            notify: region(&mut notify, 64),
            isr: region(&mut isr, 1),
            device: Some(region(&mut config, 256)),
            notify_multiplier: 4,
        })
    }
    .unwrap();
    t.negotiate(&Host).unwrap();
    assert_eq!(&common.0[..4], &1u32.to_le_bytes());
    assert_eq!(&common.0[8..16], &[1, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(&common.0[16..20], &[0x34, 0x12, 2, 0]);
    assert_eq!(common.0[21], 0x87);
    let memory = Box::leak(Box::new(QueueMemory::zeroed()));
    let physical = memory as *mut _ as u64;
    let mut queue = Queue::configure(&mut t, memory, 0, &Host).unwrap();
    assert_eq!(&common.0[24..30], &[8, 0, 0x55, 0xaa, 1, 0]);
    for (offset, value) in [(32, physical), (40, physical + 4096), (48, physical + 8192)] {
        assert_eq!(&common.0[offset..offset + 8], &value.to_le_bytes());
    }
    t.start(&Host).unwrap();
    queue.submit(&mut t, b"request", 8, &Host).unwrap();
    assert_eq!(&notify.0[10..16], &[0xa5, 0xa5, 0, 0, 0xa5, 0xa5]);
}

#[test]
fn bad_notify_offset_is_rejected_before_queue_enable_or_dma_publication() {
    use cyxia_driver_virtio::{Queue, QueueMemory};
    let (mut common, mut notify, mut isr, mut config) = registers();
    common.0[24..26].copy_from_slice(&8u16.to_le_bytes());
    common.0[30..32].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut t = unsafe {
        Transport::attach_pci(PciRegions {
            device_id: 4,
            common: region(&mut common, 56),
            notify: region(&mut notify, 64),
            isr: region(&mut isr, 1),
            device: Some(region(&mut config, 256)),
            notify_multiplier: u32::MAX,
        })
    }
    .unwrap();
    assert!(matches!(
        Queue::configure(&mut t, Box::leak(Box::new(QueueMemory::zeroed())), 0, &Host),
        Err(Error::Address)
    ));
    assert_eq!(&common.0[28..30], &[0, 0]);
}

#[test]
fn every_os_device_kind_has_a_real_pci_attach_path() {
    for id in [1, 2, 4, 16, 18] {
        let (mut common, mut notify, mut isr, mut config) = registers();
        let t = unsafe {
            Transport::attach_pci(PciRegions {
                device_id: id,
                common: region(&mut common, 56),
                notify: region(&mut notify, 64),
                isr: region(&mut isr, 1),
                device: Some(region(&mut config, 256)),
                notify_multiplier: 4,
            })
        }
        .unwrap();
        assert_eq!(t.device_id(), id);
    }
}
