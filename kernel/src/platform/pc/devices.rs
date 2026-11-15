//! Exclusive PC device discovery and transfer to the shared service drivers.
//! The registry contains actual PCI resources. It never creates ARM MMIO nodes.
use cyxia_driver_virtio::{Error, MappedRegion, PciRegions, Transport};
use cyxia_platform_pc::pci::{self, Mechanism1, PciDevices, Region};

pub struct Devices {
    config: Mechanism1,
    discovered: PciDevices,
    claimed: u32,
}
impl Devices {
    /// # Safety
    /// CPU0 boot owns PCI configuration and every discovered VirtIO function;
    /// no driver or other CPU may access them before this registry transfers it.
    pub unsafe fn discover() -> Result<Self, pci::Error> {
        let mut config = unsafe { Mechanism1::new() };
        let discovered = pci::discover_bus(&mut config, 0)?;
        Ok(Self { config, discovered, claimed: 0 })
    }

    fn region(region: Region) -> Result<MappedRegion, Error> {
        let len = usize::try_from(region.len).map_err(|_| Error::Address)?;
        let base = crate::machine::runtime::map_device(region.base, region.len)
            .map_err(|_| Error::Address)?;
        Ok(MappedRegion { base, len })
    }

    /// Move one hardware function to its unique service owner. A failed attach
    /// quarantines that function; its DMA memory cannot be reused by a retry.
    pub fn take(&mut self, kind: u32) -> Result<Option<Transport>, Error> {
        let found = self.discovered.iter().enumerate()
            .find(|(slot, d)| self.claimed & (1u32 << slot) == 0 && d.device_id == kind)
            .map(|(slot, d)| (slot, *d));
        let Some((slot, device)) = found else { return Ok(None) };
        self.claimed |= 1u32 << slot;
        let regions = PciRegions {
            device_id: device.device_id,
            common: Self::region(device.common)?,
            notify: Self::region(device.notify)?,
            isr: Self::region(device.isr)?,
            device: device.device.map(Self::region).transpose()?,
            notify_multiplier: device.notify_multiplier,
        };
        // This first PC integration deliberately uses bounded foreground polling.
        // Disable real PCI interrupt modes; do not fabricate IRQ completion.
        pci::enable_polling(&mut self.config, &device).map_err(|_| Error::Device)?;
        unsafe { Transport::attach_pci(regions).map(Some) }
    }

    pub fn count(&self) -> usize { self.discovered.len() }
}
