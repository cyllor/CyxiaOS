//! Bounded PCI configuration mechanism 1 and modern VirtIO discovery.
//! Discovery reports physical BAR resources; the kernel owns their MMIO mapping,
//! DMA pools and unique device registry. No ARM MMIO descriptions are invented.

pub const MAX_DEVICES: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    Access,
    Unsupported,
    Missing,
    Duplicate,
    Capacity,
    Capability,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}
impl Bdf {
    pub fn new(bus: u8, device: u8, function: u8) -> Result<Self, Error> {
        if device >= 32 || function >= 8 {
            return Err(Error::Address);
        }
        Ok(Self {
            bus,
            device,
            function,
        })
    }
    pub fn identity(self) -> u16 {
        u16::from(self.bus) << 8 | u16::from(self.device) << 3 | u16::from(self.function)
    }
    fn config_address(self, offset: u16) -> Result<u32, Error> {
        Self::new(self.bus, self.device, self.function)?;
        if offset >= 256 || !offset.is_multiple_of(4) {
            return Err(Error::Address);
        }
        Ok(0x8000_0000
            | u32::from(self.bus) << 16
            | u32::from(self.device) << 11
            | u32::from(self.function) << 8
            | u32::from(offset))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarKind {
    Memory32,
    Memory64,
    Io,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    pub base: u64,
    pub len: u64,
    pub kind: BarKind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub bar: u8,
    pub base: u64,
    pub len: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioPciDevice {
    pub bdf: Bdf,
    pub device_id: u32,
    pub bars: [Option<Bar>; 6],
    pub common: Region,
    pub notify: Region,
    pub isr: Region,
    pub device: Option<Region>,
    pub notify_multiplier: u32,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub msix_capability: Option<u8>,
    pub msi_capability: Option<u8>,
}

/// One serialized configuration owner. Implementations must preserve byte order
/// and return failures rather than inventing register contents.
pub trait ConfigAccess {
    fn read_u32(&mut self, bdf: Bdf, offset: u16) -> Result<u32, Error>;
    fn write_u32(&mut self, bdf: Bdf, offset: u16, value: u32) -> Result<(), Error>;
}
fn word(c: &[u8; 256], at: usize) -> u16 {
    u16::from_le_bytes([c[at], c[at + 1]])
}
fn dword(c: &[u8; 256], at: usize) -> u32 {
    u32::from_le_bytes(c[at..at + 4].try_into().unwrap())
}
fn virtio_id(c: &[u8; 256]) -> Result<u32, Error> {
    if word(c, 0) != 0x1af4 || c[0x0e] & 0x7f != 0 {
        return Err(Error::Unsupported);
    }
    let id = u32::from(word(c, 2))
        .checked_sub(0x1040)
        .ok_or(Error::Unsupported)?;
    if !matches!(id, 1 | 2 | 4 | 16 | 18) {
        return Err(Error::Unsupported);
    }
    Ok(id)
}
fn range(bars: &[Option<Bar>; 6], index: u8, offset: u64, len: u64) -> Result<Region, Error> {
    let bar = bars
        .get(index as usize)
        .copied()
        .flatten()
        .ok_or(Error::Address)?;
    if bar.kind == BarKind::Io
        || len == 0
        || offset.checked_add(len).is_none_or(|end| end > bar.len)
    {
        return Err(Error::Address);
    }
    let base = bar.base.checked_add(offset).ok_or(Error::Address)?;
    base.checked_add(len).ok_or(Error::Address)?;
    Ok(Region {
        bar: index,
        base,
        len,
    })
}
fn overlaps(a: Region, b: Region) -> bool {
    a.base < b.base + b.len && b.base < a.base + a.len
}
fn validate_bars(bars: &[Option<Bar>; 6]) -> Result<(), Error> {
    for (i, bar) in bars.iter().enumerate() {
        if let Some(a) = bar {
            if a.base == 0
                || !a.len.is_power_of_two()
                || !a.base.is_multiple_of(a.len)
                || a.base.checked_add(a.len).is_none()
                || (a.kind != BarKind::Memory64 && a.base + a.len > 1 << 32)
                || (a.kind == BarKind::Memory64 && (i == 5 || bars[i + 1].is_some()))
            {
                return Err(Error::Address);
            }
            for b in bars[i + 1..].iter().flatten() {
                if a.kind != BarKind::Io
                    && b.kind != BarKind::Io
                    && a.base < b.base.saturating_add(b.len)
                    && b.base < a.base + a.len
                {
                    return Err(Error::Address);
                }
            }
        }
    }
    Ok(())
}

/// Parse a snapshotted endpoint configuration and independently probed BARs.
/// Lengths, cycles, duplicate required capabilities and all consumed ranges are
/// validated before the kernel may map or attach a transport.
pub fn parse_virtio(
    bdf: Bdf,
    c: &[u8; 256],
    bars: &[Option<Bar>; 6],
) -> Result<VirtioPciDevice, Error> {
    Bdf::new(bdf.bus, bdf.device, bdf.function)?;
    let device_id = virtio_id(c)?;
    validate_bars(bars)?;
    if word(c, 6) & 0x10 == 0 {
        return Err(Error::Missing);
    }
    let mut pointer = c[0x34];
    let mut seen = [false; 64];
    let mut covered = [false; 256];
    let mut regions = [None; 4];
    let mut multiplier = 0;
    let mut msix = None;
    let mut msi = None;
    while pointer != 0 {
        let at = pointer as usize;
        if !(0x40..=0xfc).contains(&at) || !at.is_multiple_of(4) || seen[at / 4] {
            return Err(Error::Capability);
        }
        seen[at / 4] = true;
        // A next pointer may be aligned and acyclic yet point into the previous
        // capability's payload. Do not give the same config bytes two meanings.
        let bytes = match c[at] {
            9 => c[at + 2] as usize,
            0x11 => 12,
            5 => {
                let control = word(c, at + 2);
                let size = if control & 0x80 != 0 { 14usize } else { 10 };
                if control & 0x100 != 0 {
                    size.next_multiple_of(4) + 8
                } else {
                    size
                }
            }
            1 => 8,
            0x10 => 4, // Only the known header is inspected; PCIe is untouched.
            _ => return Err(Error::Unsupported),
        };
        if bytes < 2
            || at.checked_add(bytes).is_none_or(|end| end > 256)
            || covered[at..at + bytes].iter().any(|value| *value)
        {
            return Err(Error::Capability);
        }
        covered[at..at + bytes].fill(true);
        match c[at] {
            9 => {
                let len = c[at + 2] as usize;
                if len < 16 || at.checked_add(len).is_none_or(|end| end > 256) {
                    return Err(Error::Capability);
                }
                let kind = c[at + 3];
                if kind == 5 {
                    // PCI_CFG is a known optional alternate access mechanism.
                    // It is never enabled or used by this MMIO-BAR backend.
                    if len < 20 {
                        return Err(Error::Capability);
                    }
                } else {
                    if !(1..=4).contains(&kind) {
                        return Err(Error::Unsupported);
                    }
                    if kind == 2 && len < 20 {
                        return Err(Error::Capability);
                    }
                    let slot = kind as usize - 1;
                    if regions[slot].is_some() {
                        return Err(Error::Duplicate);
                    }
                    let resource = range(
                        bars,
                        c[at + 4],
                        u64::from(dword(c, at + 8)),
                        u64::from(dword(c, at + 12)),
                    )?;
                    let minimum = match kind {
                        1 => 56,
                        2 => 2,
                        3 => 1,
                        _ => 1,
                    };
                    if resource.len < minimum
                        || (kind != 3
                            && !resource.base.is_multiple_of(if kind == 2 { 2 } else { 4 }))
                    {
                        return Err(Error::Address);
                    }
                    regions[slot] = Some(resource);
                    if kind == 2 {
                        multiplier = dword(c, at + 16);
                    }
                }
            }
            0x11 => {
                if at + 12 > 256 || msix.is_some() {
                    return Err(Error::Capability);
                }
                let count = u64::from(word(c, at + 2) & 0x7ff) + 1;
                let table = dword(c, at + 4);
                let pba = dword(c, at + 8);
                let a = range(bars, (table & 7) as u8, u64::from(table & !7), count * 16)?;
                let b = range(
                    bars,
                    (pba & 7) as u8,
                    u64::from(pba & !7),
                    count.div_ceil(64) * 8,
                )?;
                if overlaps(a, b) {
                    return Err(Error::Address);
                }
                msix = Some(pointer);
            }
            5 => {
                if at + 10 > 256 || msi.is_some() {
                    return Err(Error::Capability);
                }
                let control = word(c, at + 2);
                let minimum = if control & 0x80 != 0 { 14 } else { 10 };
                if at + minimum > 256 {
                    return Err(Error::Capability);
                }
                msi = Some(pointer);
            }
            1 | 0x10 => { /* Known PM/PCIe capabilities, not modified here. */ }
            _ => return Err(Error::Unsupported),
        }
        pointer = c[at + 1];
    }
    let common = regions[0].ok_or(Error::Missing)?;
    let notify = regions[1].ok_or(Error::Missing)?;
    let isr = regions[2].ok_or(Error::Missing)?;
    for (i, first) in regions.iter().enumerate() {
        if let Some(a) = first {
            for b in regions[i + 1..].iter().flatten() {
                if overlaps(*a, *b) {
                    return Err(Error::Address);
                }
            }
        }
    }
    let minimum = match device_id {
        1 => 6,
        2 => 8,
        4 => 0,
        16 => 16,
        18 => 136,
        _ => unreachable!(),
    };
    if minimum != 0 && regions[3].is_none_or(|r| r.len < minimum) {
        return Err(Error::Missing);
    }
    Ok(VirtioPciDevice {
        bdf,
        device_id,
        bars: *bars,
        common,
        notify,
        isr,
        device: regions[3],
        notify_multiplier: multiplier,
        interrupt_line: c[0x3c],
        interrupt_pin: c[0x3d],
        msix_capability: msix,
        msi_capability: msi,
    })
}

fn probe_disabled(config: &mut impl ConfigAccess, bdf: Bdf) -> Result<[Option<Bar>; 6], Error> {
    let mut bars = [None; 6];
    let mut slot = 0;
    while slot < 6 {
        let offset = 0x10 + slot as u16 * 4;
        let original = config.read_u32(bdf, offset)?;
        let io = original & 1 != 0;
        let wide = !io && original & 6 == 4;
        if !io && !matches!(original & 6, 0 | 4) || wide && slot == 5 {
            return Err(Error::Unsupported);
        }
        let high = if wide {
            config.read_u32(bdf, offset + 4)?
        } else {
            0
        };
        let measured = (|| {
            config.write_u32(bdf, offset, u32::MAX)?;
            if wide {
                config.write_u32(bdf, offset + 4, u32::MAX)?;
            }
            let low = config.read_u32(bdf, offset)?;
            let upper = if wide {
                config.read_u32(bdf, offset + 4)?
            } else {
                0
            };
            Ok((low, upper))
        })();
        // Decode and bus-mastering remain disabled throughout both-half restore.
        let restore_high = if wide {
            config.write_u32(bdf, offset + 4, high)
        } else {
            Ok(())
        };
        let restore_low = config.write_u32(bdf, offset, original);
        restore_high?;
        restore_low?;
        let (mask, upper_mask) = measured?;
        let mask_low = mask & if io { !3 } else { !15 };
        if mask_low != 0 || upper_mask != 0 {
            let (base, len, kind) = if wide {
                let bits = u64::from(mask_low) | u64::from(upper_mask) << 32;
                let len = (!bits).checked_add(1).ok_or(Error::Address)?;
                (
                    u64::from(original & !15) | u64::from(high) << 32,
                    len,
                    BarKind::Memory64,
                )
            } else {
                let len = u64::from(!mask_low) + 1;
                (
                    u64::from(original & if io { !3 } else { !15 }),
                    len,
                    if io { BarKind::Io } else { BarKind::Memory32 },
                )
            };
            bars[slot] = Some(Bar { base, len, kind });
        }
        slot += if wide { 2 } else { 1 };
    }
    validate_bars(&bars)?;
    Ok(bars)
}

/// Destructive BAR sizing is permitted only during cold discovery before any
/// driver owns the function. All BARs and command decode bits are restored,
/// including failure paths. W1C PCI status bits are never written back as ones.
pub fn probe_bars(config: &mut impl ConfigAccess, bdf: Bdf) -> Result<[Option<Bar>; 6], Error> {
    bdf.config_address(0)?;
    let command = config.read_u32(bdf, 4)? & 0xffff;
    if let Err(error) = config.write_u32(bdf, 4, command & !7) {
        let _ = config.write_u32(bdf, 4, command);
        return Err(error);
    }
    let result = probe_disabled(config, bdf);
    config.write_u32(bdf, 4, command)?;
    result
}

#[derive(Clone, Debug)]
pub struct PciDevices {
    entries: [Option<VirtioPciDevice>; MAX_DEVICES],
    count: usize,
}
impl PciDevices {
    pub fn iter(&self) -> impl Iterator<Item = &VirtioPciDevice> {
        self.entries[..self.count].iter().flatten()
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    fn push(&mut self, device: VirtioPciDevice) -> Result<(), Error> {
        if self.count == MAX_DEVICES {
            return Err(Error::Capacity);
        }
        for old in self.iter() {
            for a in old.bars.iter().flatten().filter(|b| b.kind != BarKind::Io) {
                for b in device
                    .bars
                    .iter()
                    .flatten()
                    .filter(|b| b.kind != BarKind::Io)
                {
                    if a.base < b.base + b.len && b.base < a.base + a.len {
                        return Err(Error::Address);
                    }
                }
            }
        }
        self.entries[self.count] = Some(device);
        self.count += 1;
        Ok(())
    }
}

/// Enumerate one explicitly selected PCI bus. Bridges are not silently traversed;
/// the platform may enumerate their secondary buses separately. The pinned PC
/// puts its five supported device kinds on bus zero.
pub fn discover_bus(config: &mut impl ConfigAccess, bus: u8) -> Result<PciDevices, Error> {
    let mut devices = PciDevices {
        entries: [None; MAX_DEVICES],
        count: 0,
    };
    for device in 0..32 {
        let first = Bdf::new(bus, device, 0)?;
        if config.read_u32(first, 0)? & 0xffff == 0xffff {
            continue;
        }
        let header = config.read_u32(first, 0x0c)?;
        let functions = if header & 0x0080_0000 != 0 { 8 } else { 1 };
        for function in 0..functions {
            let bdf = Bdf::new(bus, device, function)?;
            let identity = config.read_u32(bdf, 0)?;
            if identity & 0xffff != 0x1af4 {
                continue;
            }
            let id = (identity >> 16).wrapping_sub(0x1040);
            if !matches!(id, 1 | 2 | 4 | 16 | 18) {
                continue;
            }
            let mut snapshot = [0; 256];
            for offset in (0..256).step_by(4) {
                snapshot[offset..offset + 4]
                    .copy_from_slice(&config.read_u32(bdf, offset as u16)?.to_le_bytes());
            }
            if snapshot[0x0e] & 0x7f != 0 {
                return Err(Error::Unsupported);
            }
            let bars = probe_bars(config, bdf)?;
            devices.push(parse_virtio(bdf, &snapshot, &bars)?)?;
        }
    }
    Ok(devices)
}

/// Enable actual memory/BM DMA for a mapped driver operating in polling mode.
/// MSI/MSI-X and INTx remain disabled; this establishes no IRQ routing proof.
pub fn enable_polling(
    config: &mut impl ConfigAccess,
    device: &VirtioPciDevice,
) -> Result<(), Error> {
    if let Some(at) = device.msix_capability {
        let value = config.read_u32(device.bdf, u16::from(at))?;
        config.write_u32(device.bdf, u16::from(at), (value & !(1 << 31)) | (1 << 30))?;
    }
    if let Some(at) = device.msi_capability {
        let value = config.read_u32(device.bdf, u16::from(at))?;
        config.write_u32(device.bdf, u16::from(at), value & !(1 << 16))?;
    }
    let command = config.read_u32(device.bdf, 4)? & 0xffff;
    let command = (command | 6 | (1 << 10)) & !1;
    config.write_u32(device.bdf, 4, command)?;
    if config.read_u32(device.bdf, 4)? & 0x407 != command & 0x407 {
        return Err(Error::Access);
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub struct Mechanism1 {
    _exclusive: (),
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl Mechanism1 {
    /// # Safety
    /// Caller owns CF8/CFC, prevents interrupt/CPU reentry, and keeps all other
    /// configuration users excluded throughout this object's lifetime.
    pub unsafe fn new() -> Self {
        Self { _exclusive: () }
    }
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl ConfigAccess for Mechanism1 {
    fn read_u32(&mut self, bdf: Bdf, offset: u16) -> Result<u32, Error> {
        use cyxia_arch_x86_64::io::{inb, outl};
        let address = bdf.config_address(offset)?;
        let mut bytes = [0; 4];
        unsafe {
            outl(0xcf8, address);
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = inb(0xcfc + i as u16);
            }
        }
        Ok(u32::from_le_bytes(bytes))
    }
    fn write_u32(&mut self, bdf: Bdf, offset: u16, value: u32) -> Result<(), Error> {
        use cyxia_arch_x86_64::io::outl;
        let address = bdf.config_address(offset)?;
        unsafe {
            outl(0xcf8, address);
            outl(0xcfc, value);
        }
        Ok(())
    }
}
