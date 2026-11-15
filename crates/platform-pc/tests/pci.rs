use cyxia_platform_pc::pci::{self, Bar, BarKind, Bdf, Error};
fn config() -> [u8; 256] {
    let mut c = [0; 256];
    c[..2].copy_from_slice(&0x1af4u16.to_le_bytes());
    c[2..4].copy_from_slice(&0x1042u16.to_le_bytes());
    c[6] = 0x10;
    c[0x34] = 0x40;
    for (at, next, kind, offset, len) in [
        (0x40, 0x50, 1, 0u32, 0x1000u32),
        (0x50, 0x64, 2, 0x3000, 0x1000),
        (0x64, 0x74, 3, 0x1000, 0x1000),
        (0x74, 0, 4, 0x2000, 0x1000),
    ] {
        c[at..at + 5].copy_from_slice(&[9, next, if kind == 2 { 20 } else { 16 }, kind, 4]);
        c[at + 8..at + 12].copy_from_slice(&offset.to_le_bytes());
        c[at + 12..at + 16].copy_from_slice(&len.to_le_bytes());
    }
    c[0x60..0x64].copy_from_slice(&4u32.to_le_bytes());
    c
}
fn bars() -> [Option<Bar>; 6] {
    let mut b = [None; 6];
    b[4] = Some(Bar {
        base: 0xfe00_0000,
        len: 0x4000,
        kind: BarKind::Memory64,
    });
    b
}
#[test]
fn modern_capabilities_preserve_physical_resource_identity() {
    let device = pci::parse_virtio(Bdf::new(0, 5, 0).unwrap(), &config(), &bars()).unwrap();
    assert_eq!(device.device_id, 2);
    assert_eq!(device.common.base, 0xfe00_0000);
    assert_eq!(device.notify.base, 0xfe00_3000);
    assert_eq!(device.isr.base, 0xfe00_1000);
    assert_eq!(device.device.unwrap().base, 0xfe00_2000);
    assert_eq!(device.notify_multiplier, 4);
}
#[test]
fn malformed_capability_chains_and_bar_ranges_reject() {
    let mut cases = Vec::new();
    let mut c = config();
    c[0x41] = 0x40;
    cases.push(c);
    let mut c = config();
    c[0x41] = 0x41;
    cases.push(c);
    let mut c = config();
    c[0x42] = 15;
    cases.push(c);
    let mut c = config();
    c[0x44] = 6;
    cases.push(c);
    let mut c = config();
    c[0x5c..0x60].copy_from_slice(&0x2000u32.to_le_bytes());
    cases.push(c);
    let mut c = config();
    c[0x54] = 5;
    cases.push(c); // upper half of a 64-bit BAR
    let mut c = config();
    c[0x43] = 7;
    cases.push(c);
    let mut c = config();
    c[0x73] = 0x40;
    cases.push(c);
    for c in cases {
        assert!(pci::parse_virtio(Bdf::new(0, 5, 0).unwrap(), &c, &bars()).is_err());
    }
}
#[test]
fn legacy_only_and_invalid_bdf_are_not_admitted() {
    assert_eq!(Bdf::new(0, 32, 0), Err(Error::Address));
    assert_eq!(Bdf::new(0, 0, 8), Err(Error::Address));
    let mut c = config();
    c[2..4].copy_from_slice(&0x1001u16.to_le_bytes());
    assert_eq!(
        pci::parse_virtio(Bdf::new(0, 5, 0).unwrap(), &c, &bars()),
        Err(Error::Unsupported)
    );
}

#[test]
fn capability_headers_cannot_alias_each_others_bytes() {
    let mut c = config();
    c[0x51] = 0x60;
    c[0x60..0x64].copy_from_slice(&0x00006401u32.to_le_bytes());
    assert!(pci::parse_virtio(Bdf::new(0, 5, 0).unwrap(), &c, &bars()).is_err());
}

struct FakeConfig {
    words: [u32; 64],
    masks: [u32; 6],
    probing: [bool; 6],
    fail_probe_read: Option<u16>,
    writes: Vec<(u16, u32)>,
}
impl FakeConfig {
    fn new() -> Self {
        let c = config();
        let mut words = [0; 64];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes(c[i * 4..i * 4 + 4].try_into().unwrap());
        }
        words[1] = 0xffff0007;
        words[8] = 0xfe00000c;
        let mut masks = [0; 6];
        masks[4] = 0xffffc00c;
        masks[5] = u32::MAX;
        Self {
            words,
            masks,
            probing: [false; 6],
            fail_probe_read: None,
            writes: Vec::new(),
        }
    }
}
impl pci::ConfigAccess for FakeConfig {
    fn read_u32(&mut self, _: Bdf, at: u16) -> Result<u32, Error> {
        if (0x10..0x28).contains(&at) {
            let slot = usize::from((at - 0x10) / 4);
            if self.probing[slot] {
                if self.fail_probe_read == Some(at) {
                    self.fail_probe_read = None;
                    return Err(Error::Access);
                }
                return Ok(self.masks[slot]);
            }
        }
        Ok(self.words[at as usize / 4])
    }
    fn write_u32(&mut self, _: Bdf, at: u16, value: u32) -> Result<(), Error> {
        self.writes.push((at, value));
        if at == 4 {
            assert_eq!(value >> 16, 0, "PCI status W1C bits must never be echoed");
            self.words[1] = (self.words[1] & 0xffff0000) | (value & 0xffff);
        } else if (0x10..0x28).contains(&at) {
            let slot = usize::from((at - 0x10) / 4);
            self.probing[slot] = value == u32::MAX;
            if value != u32::MAX {
                self.words[at as usize / 4] = value;
            }
        } else {
            self.words[at as usize / 4] = value;
        }
        Ok(())
    }
}

#[test]
fn bar_probe_restores_decode_and_both_halves_after_success_and_read_failure() {
    use pci::ConfigAccess;
    let bdf = Bdf::new(0, 5, 0).unwrap();
    for fail in [None, Some(0x24)] {
        let mut fake = FakeConfig::new();
        fake.fail_probe_read = fail;
        let original = fake.words;
        let result = pci::probe_bars(&mut fake, bdf);
        if fail.is_some() {
            assert_eq!(result, Err(Error::Access));
        } else {
            assert_eq!(result.unwrap(), bars());
        }
        assert_eq!(fake.words, original);
        assert!(!fake.probing.iter().any(|p| *p));
        assert_eq!(fake.writes.first(), Some(&(4, 0)));
        assert_eq!(fake.writes.last(), Some(&(4, 7)));
        assert_eq!(fake.read_u32(bdf, 4).unwrap(), 0xffff0007);
    }
}

#[test]
fn polling_enables_actual_memory_and_dma_but_no_interrupt_delivery() {
    let mut fake = FakeConfig::new();
    let mut device = pci::parse_virtio(Bdf::new(0, 5, 0).unwrap(), &config(), &bars()).unwrap();
    device.msix_capability = Some(0x90);
    device.msi_capability = Some(0xa0);
    fake.words[0x90 / 4] = 0x80000011;
    fake.words[0xa0 / 4] = 0x00010005;
    pci::enable_polling(&mut fake, &device).unwrap();
    assert_eq!(fake.words[1], 0xffff0406);
    assert_eq!(fake.words[0x90 / 4] & 0xc0000000, 0x40000000);
    assert_eq!(fake.words[0xa0 / 4] & 0x10000, 0);
}
