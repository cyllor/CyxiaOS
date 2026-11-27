//! Typed VirtIO register operations shared by modern MMIO and PCI transports.
//! PCI register widths and read-to-clear ISR semantics are preserved here.
use crate::{Error, Platform, reset::RESET_DEADLINE_NS};
use core::ptr::{read_volatile, write_volatile};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedRegion {
    pub base: usize,
    pub len: usize,
}
impl MappedRegion {
    fn validate(self, minimum: usize, alignment: usize) -> Result<(), Error> {
        if self.base == 0
            || !self.base.is_multiple_of(alignment)
            || self.len < minimum
            || self.base.checked_add(self.len).is_none()
        {
            return Err(Error::Address);
        }
        Ok(())
    }
    fn at(self, offset: usize, size: usize) -> Result<usize, Error> {
        if offset.checked_add(size).is_none_or(|end| end > self.len) {
            return Err(Error::Address);
        }
        self.base.checked_add(offset).ok_or(Error::Address)
    }
}

/// Mapped, exclusively owned regions discovered from PCI vendor capabilities.
/// These are separate hardware resources, never an emulated MMIO register page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciRegions {
    pub device_id: u32,
    pub common: MappedRegion,
    pub notify: MappedRegion,
    pub isr: MappedRegion,
    pub device: Option<MappedRegion>,
    pub notify_multiplier: u32,
}

struct PciTransport {
    regions: PciRegions,
}
enum Backend {
    Mmio(MappedRegion),
    Pci(PciTransport),
}
pub struct Transport {
    backend: Backend,
}

/// Created before a queue is enabled; publication never discovers a bad offset.
#[derive(Clone, Copy)]
pub(crate) struct Notification {
    owner: usize,
    address: usize,
    value: u32,
    pci: bool,
}

unsafe fn read8(address: usize) -> u8 {
    unsafe { read_volatile(address as *const u8) }
}
unsafe fn read16(address: usize) -> u16 {
    u16::from_le(unsafe { read_volatile(address as *const u16) })
}
unsafe fn read32(address: usize) -> u32 {
    u32::from_le(unsafe { read_volatile(address as *const u32) })
}
unsafe fn write8(address: usize, value: u8) {
    unsafe { write_volatile(address as *mut u8, value) }
}
unsafe fn write16(address: usize, value: u16) {
    unsafe { write_volatile(address as *mut u16, value.to_le()) }
}
unsafe fn write32(address: usize, value: u32) {
    unsafe { write_volatile(address as *mut u32, value.to_le()) }
}

impl Transport {
    /// Attach the original modern MMIO transport.
    /// # Safety
    /// Caller owns the mapped device resource for the driver's entire lifetime,
    /// including failures, and serializes all queue/configuration accesses.
    pub unsafe fn attach(base: usize, len: usize) -> Result<Self, Error> {
        let region = MappedRegion { base, len };
        region.validate(0x200, 4)?;
        if unsafe { read32(base) } != 0x74726976 || unsafe { read32(base + 4) } != 2 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            backend: Backend::Mmio(region),
        })
    }

    /// # Safety
    /// The caller verified PCI identity and BAR ownership, mapped each region
    /// as ordered device memory, disabled unsupported interrupts, and enabled
    /// memory/bus-master access. These mappings and DMA pools must remain pinned
    /// through every error. No other CPU, IRQ handler or driver may access them.
    pub unsafe fn attach_pci(regions: PciRegions) -> Result<Self, Error> {
        regions.common.validate(56, 4)?;
        regions.notify.validate(2, 2)?;
        regions.isr.validate(1, 1)?;
        let config_minimum = match regions.device_id {
            1 => 6,
            2 => 8,
            4 => 0,
            16 => 16,
            18 => 136,
            _ => return Err(Error::Unsupported),
        };
        if let Some(device) = regions.device {
            device.validate(config_minimum.max(1), 4)?;
        } else if config_minimum != 0 {
            return Err(Error::Address);
        }
        let ranges = [
            Some(regions.common),
            Some(regions.notify),
            Some(regions.isr),
            regions.device,
        ];
        for (i, first) in ranges.iter().enumerate() {
            if let Some(a) = first {
                for b in ranges[i + 1..].iter().flatten() {
                    if a.base < b.base + b.len && b.base < a.base + a.len {
                        return Err(Error::Address);
                    }
                }
            }
        }
        Ok(Self {
            backend: Backend::Pci(PciTransport { regions }),
        })
    }
    fn owner(&self) -> usize {
        match &self.backend {
            Backend::Mmio(r) => r.base,
            Backend::Pci(p) => p.regions.common.base,
        }
    }
    pub fn device_id(&self) -> u32 {
        match &self.backend {
            Backend::Mmio(r) => unsafe { read32(r.base + 8) },
            Backend::Pci(p) => p.regions.device_id,
        }
    }
    pub(crate) fn status(&self) -> u32 {
        match &self.backend {
            Backend::Mmio(r) => unsafe { read32(r.base + 0x70) },
            Backend::Pci(p) => u32::from(unsafe { read8(p.regions.common.base + 20) }),
        }
    }
    pub(crate) fn set_status(&mut self, value: u32) {
        match &self.backend {
            Backend::Mmio(r) => unsafe { write32(r.base + 0x70, value) },
            Backend::Pci(p) => unsafe { write8(p.regions.common.base + 20, value as u8) },
        }
    }
    pub(crate) fn select_device_features(&mut self, bank: u32) {
        match &self.backend {
            Backend::Mmio(r) => unsafe { write32(r.base + 0x14, bank) },
            Backend::Pci(p) => unsafe { write32(p.regions.common.base, bank) },
        }
    }
    pub(crate) fn device_features(&self) -> u32 {
        match &self.backend {
            Backend::Mmio(r) => unsafe { read32(r.base + 0x10) },
            Backend::Pci(p) => unsafe { read32(p.regions.common.base + 4) },
        }
    }
    pub(crate) fn select_driver_features(&mut self, bank: u32) {
        match &self.backend {
            Backend::Mmio(r) => unsafe { write32(r.base + 0x24, bank) },
            Backend::Pci(p) => unsafe { write32(p.regions.common.base + 8, bank) },
        }
    }
    pub(crate) fn set_driver_features(&mut self, value: u32) {
        match &self.backend {
            Backend::Mmio(r) => unsafe { write32(r.base + 0x20, value) },
            Backend::Pci(p) => unsafe { write32(p.regions.common.base + 12, value) },
        }
    }
    pub(crate) fn config_generation(&self) -> u32 {
        match &self.backend {
            Backend::Mmio(r) => unsafe { read32(r.base + 0xfc) },
            Backend::Pci(p) => u32::from(unsafe { read8(p.regions.common.base + 21) }),
        }
    }
    fn config(&self) -> Result<MappedRegion, Error> {
        match &self.backend {
            Backend::Mmio(r) => Ok(MappedRegion {
                base: r.base + 0x100,
                len: r.len - 0x100,
            }),
            Backend::Pci(p) => p.regions.device.ok_or(Error::Address),
        }
    }
    pub(crate) fn read_config_u8(&self, offset: usize) -> Result<u8, Error> {
        Ok(unsafe { read8(self.config()?.at(offset, 1)?) })
    }
    pub(crate) fn read_config_u32(&self, offset: usize) -> Result<u32, Error> {
        if !offset.is_multiple_of(4) {
            return Err(Error::Address);
        }
        Ok(unsafe { read32(self.config()?.at(offset, 4)?) })
    }
    pub(crate) fn select_queue(&mut self, index: u32) -> Result<(), Error> {
        match &self.backend {
            Backend::Mmio(r) => unsafe { write32(r.base + 0x30, index) },
            Backend::Pci(p) => unsafe {
                write16(
                    p.regions.common.base + 22,
                    u16::try_from(index).map_err(|_| Error::Queue)?,
                )
            },
        }
        Ok(())
    }
    pub(crate) fn queue_max_size(&self) -> u32 {
        match &self.backend {
            Backend::Mmio(r) => unsafe { read32(r.base + 0x34) },
            Backend::Pci(p) => u32::from(unsafe { read16(p.regions.common.base + 24) }),
        }
    }
    pub(crate) fn queue_enabled(&self) -> bool {
        match &self.backend {
            Backend::Mmio(r) => unsafe { read32(r.base + 0x44) != 0 },
            Backend::Pci(p) => unsafe { read16(p.regions.common.base + 28) != 0 },
        }
    }
    pub(crate) fn set_queue_size(&mut self, size: u32) -> Result<(), Error> {
        match &self.backend {
            Backend::Mmio(r) => unsafe { write32(r.base + 0x38, size) },
            Backend::Pci(p) => unsafe {
                write16(
                    p.regions.common.base + 24,
                    u16::try_from(size).map_err(|_| Error::Queue)?,
                )
            },
        }
        Ok(())
    }
    pub(crate) fn set_queue_addresses(&mut self, desc: u64, avail: u64, used: u64) {
        for (mmio_offset, pci_offset, value) in
            [(0x80, 32, desc), (0x90, 40, avail), (0xa0, 48, used)]
        {
            let address = match &self.backend {
                Backend::Mmio(r) => r.base + mmio_offset,
                Backend::Pci(p) => p.regions.common.base + pci_offset,
            };
            unsafe {
                write32(address, value as u32);
                write32(address + 4, (value >> 32) as u32);
            }
        }
    }
    pub(crate) fn queue_notification(&self, index: u32) -> Result<Notification, Error> {
        let (address, pci) = match &self.backend {
            Backend::Mmio(r) => (r.base + 0x50, false),
            Backend::Pci(p) => {
                let selected = unsafe { read16(p.regions.common.base + 22) };
                if u32::from(selected) != index {
                    return Err(Error::Queue);
                }
                let offset = usize::from(unsafe { read16(p.regions.common.base + 30) })
                    .checked_mul(p.regions.notify_multiplier as usize)
                    .ok_or(Error::Address)?;
                let address = p.regions.notify.at(offset, 2)?;
                if !address.is_multiple_of(2) {
                    return Err(Error::Address);
                }
                (address, true)
            }
        };
        Ok(Notification {
            owner: self.owner(),
            address,
            value: index,
            pci,
        })
    }
    pub(crate) fn enable_queue(&mut self) {
        match &self.backend {
            Backend::Mmio(r) => unsafe { write32(r.base + 0x44, 1) },
            Backend::Pci(p) => unsafe { write16(p.regions.common.base + 28, 1) },
        }
    }
    pub(crate) fn notify(&mut self, notification: Notification) -> Result<(), Error> {
        if notification.owner != self.owner()
            || notification.pci != matches!(self.backend, Backend::Pci(_))
        {
            return Err(Error::Queue);
        }
        if notification.pci {
            unsafe {
                write16(notification.address, notification.value as u16);
            }
        } else {
            unsafe {
                write32(notification.address, notification.value);
            }
        }
        Ok(())
    }
    /// Serialized foreground owner only. PCI ISR reads clear the device status;
    /// callers must consume these returned facts rather than peek a PCI ISR.
    pub fn acknowledge_interrupt(&mut self) -> u8 {
        match &self.backend {
            Backend::Mmio(r) => {
                let flags = unsafe { read32(r.base + 0x60) } & 3;
                unsafe {
                    write32(r.base + 0x64, flags);
                }
                flags as u8
            }
            Backend::Pci(p) => unsafe { read8(p.regions.isr.base) & 3 },
        }
    }
    pub fn negotiate(&mut self, platform: &impl Platform) -> Result<(), Error> {
        self.set_status(0);
        platform.barrier();
        let start = platform.now_ms();
        while self.status() != 0 {
            if platform.now_ms().wrapping_sub(start) >= 100 {
                return Err(Error::Timeout);
            }
        }
        self.set_status(3);
        self.select_device_features(1);
        if self.device_features() & 1 == 0 {
            self.fail();
            return Err(Error::Features);
        }
        self.select_driver_features(0);
        self.set_driver_features(0);
        self.select_driver_features(1);
        self.set_driver_features(1);
        self.set_status(11);
        platform.barrier();
        if self.status() & (8 | 64 | 128) != 8 {
            self.fail();
            return Err(Error::Features);
        }
        Ok(())
    }
    pub fn start(&mut self, platform: &impl Platform) -> Result<(), Error> {
        self.set_status(15);
        platform.barrier();
        if self.status() != 15 {
            self.fail();
            return Err(Error::Device);
        }
        Ok(())
    }
    pub fn fail(&mut self) {
        self.set_status(self.status() | 128);
    }

    /// Poll a terminal reset after the serialized owner has fenced every old
    /// queue. Use one deadline for status and readiness across all queues.
    pub(crate) fn observe_mmio_reset(
        &mut self,
        device_id: u32,
        queues: &[u16],
        platform: &impl Platform,
    ) -> Result<u64, Error> {
        if !matches!(self.backend, Backend::Mmio(_)) {
            return Err(Error::Unsupported);
        }
        if device_id == 0 || self.device_id() != device_id {
            return Err(Error::Device);
        }
        let started = platform.now_ns();
        let now_within_deadline = || {
            let now = platform.now_ns();
            now.checked_sub(started)
                .filter(|elapsed| *elapsed < RESET_DEADLINE_NS)
                .map(|_| now)
                .ok_or(Error::Timeout)
        };
        self.set_status(0);
        platform.barrier();
        loop {
            now_within_deadline()?;
            if self.device_id() != device_id {
                return Err(Error::Device);
            }
            if self.status() == 0 {
                let mut disabled = true;
                for &queue in queues {
                    self.select_queue(u32::from(queue))?;
                    platform.barrier();
                    disabled &= !self.queue_enabled();
                }
                platform.barrier();
                if disabled && self.status() == 0 && self.device_id() == device_id {
                    return now_within_deadline();
                }
            }
            core::hint::spin_loop();
        }
    }

    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.status() & (64 | 128) != 0 {
            Err(Error::Device)
        } else {
            Ok(())
        }
    }
}
