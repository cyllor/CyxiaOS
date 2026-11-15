//! Bounded identity mapping used by the initial PC port.
pub const PAGE_BYTES: u64 = 4096;
pub const MAX_MAPPED_BYTES: u64 = 256 * 1024 * 1024;
pub const PRESENT: u64 = 1;
pub const WRITABLE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const NX: u64 = 1 << 63;
pub const UNCACHED: u64 = (1 << 3) | (1 << 4);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    Permissions,
    Layout,
}

pub fn encode_leaf(
    address: u64,
    writable: bool,
    executable: bool,
    user: bool,
) -> Result<u64, Error> {
    if !address.is_multiple_of(PAGE_BYTES) || address >= 1 << 52 {
        return Err(Error::Address);
    }
    if writable && executable {
        return Err(Error::Permissions);
    }
    Ok(address
        | PRESENT
        | if writable { WRITABLE } else { 0 }
        | if executable { 0 } else { NX }
        | if user { USER } else { 0 })
}

#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub text_start: u64,
    pub text_end: u64,
    pub rodata_start: u64,
    pub rodata_end: u64,
    pub user_text_start: u64,
    pub user_text_end: u64,
    pub user_stack_start: u64,
    pub user_stack_end: u64,
    pub guard_start: u64,
    pub guard_end: u64,
}
impl Layout {
    pub fn validate(self, mapped_bytes: u64) -> Result<(), Error> {
        if mapped_bytes == 0
            || mapped_bytes > MAX_MAPPED_BYTES
            || !mapped_bytes.is_multiple_of(PAGE_BYTES)
        {
            return Err(Error::Layout);
        }
        let ranges = [
            (self.text_start, self.text_end),
            (self.rodata_start, self.rodata_end),
            (self.user_text_start, self.user_text_end),
            (self.user_stack_start, self.user_stack_end),
            (self.guard_start, self.guard_end),
        ];
        for (i, &(start, end)) in ranges.iter().enumerate() {
            if start < PAGE_BYTES
                || start >= end
                || end > mapped_bytes
                || !start.is_multiple_of(PAGE_BYTES)
                || !end.is_multiple_of(PAGE_BYTES)
                || ranges[..i].iter().any(|&(a, b)| start < b && a < end)
            {
                return Err(Error::Layout);
            }
        }
        Ok(())
    }
    pub fn entry(self, address: u64) -> Result<u64, Error> {
        if !address.is_multiple_of(PAGE_BYTES) {
            return Err(Error::Address);
        }
        if address == 0 || (self.guard_start..self.guard_end).contains(&address) {
            return Ok(0);
        }
        if (self.text_start..self.text_end).contains(&address) {
            return encode_leaf(address, false, true, false);
        }
        if (self.rodata_start..self.rodata_end).contains(&address) {
            return encode_leaf(address, false, false, false);
        }
        if (self.user_text_start..self.user_text_end).contains(&address) {
            return encode_leaf(address, false, true, true);
        }
        if (self.user_stack_start..self.user_stack_end).contains(&address) {
            return encode_leaf(address, true, false, true);
        }
        encode_leaf(address, true, false, false)
    }
}

/// Extra mappings installed once before any AP can use the root. Guard ranges
/// describe reserved stacks; no allocation or live page-table mutation occurs.
#[derive(Clone, Copy)]
pub struct SmpLayout<'a> {
    pub trampoline: u64,
    pub mailbox: u64,
    pub lapic: u64,
    pub guards: &'a [(u64, u64)],
}
impl SmpLayout<'_> {
    pub fn validate(self, layout: Layout, mapped_bytes: u64) -> Result<(), Error> {
        layout.validate(mapped_bytes)?;
        if self.trampoline < PAGE_BYTES
            || self.trampoline >= 0xa0000
            || !self.trampoline.is_multiple_of(PAGE_BYTES)
            || self.mailbox < PAGE_BYTES
            || self.mailbox >= 0xa0000
            || !self.mailbox.is_multiple_of(PAGE_BYTES)
            || self.trampoline == self.mailbox
            || self.lapic < mapped_bytes
            || self.lapic >= 1 << 32
            || !self.lapic.is_multiple_of(PAGE_BYTES)
        {
            return Err(Error::Layout);
        }
        let fixed = [
            (layout.text_start, layout.text_end),
            (layout.rodata_start, layout.rodata_end),
            (layout.user_text_start, layout.user_text_end),
            (layout.user_stack_start, layout.user_stack_end),
            (layout.guard_start, layout.guard_end),
            (self.trampoline, self.trampoline + PAGE_BYTES),
            (self.mailbox, self.mailbox + PAGE_BYTES),
        ];
        for (i, &(start, end)) in fixed.iter().enumerate() {
            if fixed[..i].iter().any(|&(a, b)| start < b && a < end) {
                return Err(Error::Layout);
            }
        }
        for (i, &(start, end)) in self.guards.iter().enumerate() {
            if start < PAGE_BYTES
                || start >= end
                || end > mapped_bytes
                || !start.is_multiple_of(PAGE_BYTES)
                || !end.is_multiple_of(PAGE_BYTES)
                || fixed
                    .iter()
                    .chain(self.guards[..i].iter())
                    .any(|&(a, b)| start < b && a < end)
            {
                return Err(Error::Layout);
            }
        }
        Ok(())
    }
    pub fn entry(self, layout: Layout, address: u64) -> Result<u64, Error> {
        if !address.is_multiple_of(PAGE_BYTES) {
            return Err(Error::Address);
        }
        if self.guards.iter().any(|&(a, b)| (a..b).contains(&address)) {
            return Ok(0);
        }
        if address == self.trampoline {
            return encode_leaf(address, false, true, false);
        }
        if address == self.lapic {
            return Ok(encode_leaf(address, true, false, false)? | UNCACHED);
        }
        layout.entry(address)
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod hardware {
    use super::*;
    #[repr(C, align(4096))]
    struct Table([u64; 512]);
    static mut PML4: Table = Table([0; 512]);
    static mut PDPT: Table = Table([0; 512]);
    static mut PD: Table = Table([0; 512]);
    static mut LEAVES: [Table; 128] = [const { Table([0; 512]) }; 128];
    static mut MMIO_PD: Table = Table([0; 512]);
    static mut MMIO_PT: Table = Table([0; 512]);

    /// # Safety
    /// BSP only, interrupts disabled; all kernel code/data/stacks and these page
    /// tables must remain identity-addressable below `mapped_bytes`. NX must be
    /// enabled. No AP, DMA owner or user context may reference the old tables.
    pub unsafe fn install(layout: Layout, mapped_bytes: u64) -> Result<(), Error> {
        unsafe { install_inner(layout, mapped_bytes, None) }
    }
    /// # Safety
    /// Same conditions as `install`; trampoline has already been copied and
    /// every extra guard describes exclusively reserved supervisor stack space.
    pub unsafe fn install_smp(
        layout: Layout,
        mapped_bytes: u64,
        extra: SmpLayout<'_>,
    ) -> Result<(), Error> {
        extra.validate(layout, mapped_bytes)?;
        unsafe { install_inner(layout, mapped_bytes, Some(extra)) }
    }
    unsafe fn install_inner(
        layout: Layout,
        mapped_bytes: u64,
        extra: Option<SmpLayout<'_>>,
    ) -> Result<(), Error> {
        layout.validate(mapped_bytes)?;
        let pml4 = core::ptr::addr_of_mut!(PML4);
        let pdpt = core::ptr::addr_of_mut!(PDPT);
        let pd = core::ptr::addr_of_mut!(PD);
        let leaves = core::ptr::addr_of_mut!(LEAVES).cast::<Table>();
        // The current bootstrap tables use identity translation below 1 GiB.
        let flags = PRESENT | WRITABLE | USER;
        unsafe {
            (*pml4).0 = [0; 512];
            (*pdpt).0 = [0; 512];
            (*pd).0 = [0; 512];
            (*pml4).0[0] = pdpt as u64 | flags;
            (*pdpt).0[0] = pd as u64 | flags;
            for i in 0..128 {
                (*leaves.add(i)).0 = [0; 512];
                if (i as u64) * 512 * PAGE_BYTES >= mapped_bytes {
                    continue;
                }
                (*pd).0[i] = leaves.add(i) as u64 | flags;
                for j in 0..512 {
                    let address = ((i * 512 + j) as u64) * PAGE_BYTES;
                    if address < mapped_bytes {
                        (*leaves.add(i)).0[j] = if let Some(extra) = extra {
                            extra.entry(layout, address)?
                        } else {
                            layout.entry(address)?
                        };
                    }
                }
            }
            if let Some(extra) = extra {
                let mmio_pd = core::ptr::addr_of_mut!(MMIO_PD);
                let mmio_pt = core::ptr::addr_of_mut!(MMIO_PT);
                (*mmio_pd).0 = [0; 512];
                (*mmio_pt).0 = [0; 512];
                let pdpt_index = (extra.lapic >> 30) as usize;
                let target_pd = if pdpt_index == 0 {
                    pd
                } else {
                    (*pdpt).0[pdpt_index] = mmio_pd as u64 | PRESENT | WRITABLE;
                    mmio_pd
                };
                (*target_pd).0[((extra.lapic >> 21) & 511) as usize] =
                    mmio_pt as u64 | PRESENT | WRITABLE;
                (*mmio_pt).0[((extra.lapic >> 12) & 511) as usize] =
                    extra.entry(layout, extra.lapic)?;
            }
            core::arch::asm!("mov cr3, {}", in(reg) pml4 as u64, options(nostack, preserves_flags));
        }
        Ok(())
    }
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hardware::{install, install_smp};
