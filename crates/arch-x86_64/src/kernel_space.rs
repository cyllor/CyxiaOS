//! Formal-kernel high mapping. Lower-half process tables never inherit boot RAM.
use crate::space::{Error, KERNEL_BASE, KernelMappings};
const P: u64 = 1;
const W: u64 = 2;
const NX: u64 = 1 << 63;
const MASK: u64 = 0x000f_ffff_ffff_f000;
#[repr(C, align(4096))]
struct Table([u64; 512]);
static mut ROOT: Table = Table([0; 512]);
static mut RAM_PDPT: Table = Table([0; 512]);
static mut RAM_PD: Table = Table([0; 512]);
static mut RAM_PT: [Table; 512] = [const { Table([0; 512]) }; 512];
static mut MMIO_PD: Table = Table([0; 512]);
static mut LOW_PDPT: Table = Table([0; 512]);
static mut LOW_PD: Table = Table([0; 512]);
static mut LOW_PT: Table = Table([0; 512]);
pub struct KernelLayout<'a> {
    pub text: (u64, u64),
    pub rodata: (u64, u64),
    pub guards: &'a [(u64, u64)],
    pub ram_bytes: u64,
}
fn physical(pointer: *const Table) -> u64 {
    (pointer as u64)
        .checked_sub(KERNEL_BASE)
        .expect("high table")
}
/// # Safety
/// BSP on temporary high+low identity root, IF clear; all supplied physical
/// ranges valid and exclusively reserved, no AP/user can access these tables.
pub unsafe fn install(layout: KernelLayout<'_>) -> Result<u64, Error> {
    if layout.ram_bytes == 0 || layout.ram_bytes > 1 << 30 || layout.ram_bytes % 4096 != 0 {
        return Err(Error::Address);
    }
    for &(a, b) in core::iter::once(&layout.text)
        .chain(core::iter::once(&layout.rodata))
        .chain(layout.guards)
    {
        if a >= b || a % 4096 != 0 || b % 4096 != 0 || b > layout.ram_bytes {
            return Err(Error::Address);
        }
    }
    let root = core::ptr::addr_of_mut!(ROOT);
    let pdpt = core::ptr::addr_of_mut!(RAM_PDPT);
    let pd = core::ptr::addr_of_mut!(RAM_PD);
    let leaves = core::ptr::addr_of_mut!(RAM_PT).cast::<Table>();
    let mmio = core::ptr::addr_of_mut!(MMIO_PD);
    unsafe {
        (*root).0 = [0; 512];
        (*pdpt).0 = [0; 512];
        (*pd).0 = [0; 512];
        (*root).0[256] = physical(pdpt) | P | W;
        (*pdpt).0[0] = physical(pd) | P | W;
        (*pdpt).0[3] = physical(mmio) | P | W;
        for i in 0..512 {
            (*pd).0[i] = physical(leaves.add(i)) | P | W;
            for j in 0..512 {
                let address = (i * 512 + j) as u64 * 4096;
                let flags = if address == 0
                    || address >= layout.ram_bytes
                    || layout
                        .guards
                        .iter()
                        .any(|&(a, b)| (a..b).contains(&address))
                {
                    0
                } else if (layout.text.0..layout.text.1).contains(&address) {
                    address | P
                } else if (layout.rodata.0..layout.rodata.1).contains(&address) {
                    address | P | NX
                } else {
                    address | P | W | NX
                };
                (*leaves.add(i)).0[j] = flags;
            }
            (*mmio).0[i] = (0xc0000000 + i as u64 * (1 << 21)) | P | W | 0x98 | NX;
        }
        let low_pdpt = core::ptr::addr_of_mut!(LOW_PDPT);
        let low_pd = core::ptr::addr_of_mut!(LOW_PD);
        let low_pt = core::ptr::addr_of_mut!(LOW_PT);
        (*low_pdpt).0 = [0; 512];
        (*low_pd).0 = [0; 512];
        (*low_pt).0 = [0; 512];
        (*root).0[0] = physical(low_pdpt) | P | W;
        (*low_pdpt).0[0] = physical(low_pd) | P | W;
        (*low_pd).0[0] = physical(low_pt) | P | W;
        (*low_pt).0[7] = 0x7000 | P;
        (*low_pt).0[8] = 0x8000 | P | W | NX;
        let root_pa = physical(root);
        core::arch::asm!("mov cr3,{}",in(reg)root_pa,options(nostack));
        Ok(root_pa)
    }
}
pub fn mappings(ram_bytes: u64) -> Result<KernelMappings, Error> {
    let mut upper = [0; 256];
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(ROOT).cast::<u64>().add(256),
            upper.as_mut_ptr(),
            256,
        );
    }
    KernelMappings::new(upper, ram_bytes)
}
/// # Safety
/// Caller owns the frame and prevents all user/reference reuse until its real
/// cross-CPU invalidation completes. Only an existing normal RAM alias changes.
pub unsafe fn set_direct_permissions(physical: u64, writable: bool) -> Result<(), Error> {
    if physical == 0 || physical >= 1 << 30 || physical % 4096 != 0 {
        return Err(Error::Address);
    }
    let entry = unsafe {
        core::ptr::addr_of_mut!(RAM_PT)
            .cast::<u64>()
            .add((physical / 4096) as usize)
    };
    let old = unsafe { entry.read_volatile() };
    if old & P == 0 || old & MASK != physical {
        return Err(Error::Address);
    }
    unsafe {
        entry.write_volatile((old & !W) | NX | if writable { W } else { 0 });
    }
    Ok(())
}
