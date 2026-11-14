//! Bounded identity mapping used by the initial PC port.
pub const PAGE_BYTES: u64 = 4096;
pub const MAX_MAPPED_BYTES: u64 = 256 * 1024 * 1024;
pub const PRESENT: u64 = 1;
pub const WRITABLE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const NX: u64 = 1 << 63;

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

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod hardware {
    use super::*;
    #[repr(C, align(4096))]
    struct Table([u64; 512]);
    static mut PML4: Table = Table([0; 512]);
    static mut PDPT: Table = Table([0; 512]);
    static mut PD: Table = Table([0; 512]);
    static mut LEAVES: [Table; 128] = [const { Table([0; 512]) }; 128];

    /// # Safety
    /// BSP only, interrupts disabled; all kernel code/data/stacks and these page
    /// tables must remain identity-addressable below `mapped_bytes`. NX must be
    /// enabled. No AP, DMA owner or user context may reference the old tables.
    pub unsafe fn install(layout: Layout, mapped_bytes: u64) -> Result<(), Error> {
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
                        (*leaves.add(i)).0[j] = layout.entry(address)?;
                    }
                }
            }
            core::arch::asm!("mov cr3, {}", in(reg) pml4 as u64, options(nostack, preserves_flags));
        }
        Ok(())
    }
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hardware::install;
