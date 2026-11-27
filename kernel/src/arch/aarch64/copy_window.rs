//! Software-PAN copies from or to a single authorized, pinned user page.

use core::{arch::asm, ptr};
use cyxia_arch_aarch64::{cpu, mmu};
use cyxia_contracts::{PagePermissions, PhysAddr};
use cyxia_kernel_core::{
    control_plane::Identity,
    security::{
        Error,
        memory::{COPY_SPAN_ALIGN, CopyWindow, PAGE_SIZE, SoftwarePanContext},
    },
};
use cyxia_platform_virt::{RAM_BASE, USER_RAM_END};

const WINDOW_VA: u64 = super::HIGH + 0x8000_0000;
const LOCAL_TLBI: u64 = (WINDOW_VA >> 12) & ((1 << 44) - 1);
const PAGE_MASK: u64 = PAGE_SIZE - 1;
const NON_GLOBAL: u64 = 1 << 11;
const DAIF_MASK: u64 = 0x3c0;
const TCR_A1: u64 = 1 << 22;
const TCR_EPD0: u64 = 1 << 7;
const FATAL_WINDOW: u64 = 0x5732_1657;
const _: () = {
    assert!(WINDOW_VA - super::HIGH >= USER_RAM_END);
    assert!((WINDOW_VA >> 30) & 511 == 258);
};

unsafe extern "C" {
    static empty_l1: u8;
    static high_l1: u8;
    static __copy_window_l3: u8;
    #[cfg(feature = "unified-runtime")]
    static __copy_secondary_l1: u8;
    #[cfg(feature = "unified-runtime")]
    static __copy_secondary_l3: u8;
}

fn slot_path(slot: usize) -> Option<(u64, *mut u64)> {
    let (root, leaf) = match slot {
        0 => (
            ptr::addr_of!(high_l1) as u64,
            ptr::addr_of!(__copy_window_l3) as u64,
        ),
        #[cfg(feature = "unified-runtime")]
        1..=super::SECONDARY_COPY_WINDOWS => {
            let offset = (slot as u64 - 1) * PAGE_SIZE;
            (
                ptr::addr_of!(__copy_secondary_l1) as u64 + offset,
                ptr::addr_of!(__copy_secondary_l3) as u64 + offset,
            )
        }
        _ => return None,
    };
    Some((
        root,
        ptr::without_provenance_mut((super::HIGH + leaf) as usize),
    ))
}

#[cfg(feature = "v020-production-diagnostic")]
pub(crate) fn cpu0_closed() -> bool {
    if cpu::registered_slot() != Some(0) {
        return false;
    }
    let (_, entry) = slot_path(0).expect("CPU0 copy slot");
    // SAFETY: CPU0 callers inspect their own descriptor between copies.
    unsafe { entry.read_volatile() == 0 }
}

struct MaskDaif(u64);

impl MaskDaif {
    fn all() -> Self {
        let saved: u64;
        // SAFETY: only this CPU's DAIF changes. The saved value is restored on
        // every returning path, after any live descriptor has been revoked.
        unsafe {
            asm!("mrs {}, daif", "msr daifset, #15", out(reg) saved,
                 options(nostack, preserves_flags));
        }
        Self(saved)
    }
}

impl Drop for MaskDaif {
    fn drop(&mut self) {
        // SAFETY: restore this CPU's saved masks once the window is closed.
        unsafe {
            asm!("msr daif, {}", in(reg) self.0, options(nostack, preserves_flags));
        }
    }
}

/// # Safety
/// The caller checked this page's actual user mapping and owner and holds its
/// backing stable against reclaim or concurrent writers until return. The
/// output is an independent, initialized EL1 buffer.
pub(crate) unsafe fn copy_in(
    physical: u64,
    owner: Identity,
    user_asid: u8,
    output: &mut [u8],
) -> Result<(), Error> {
    copy_fragment(physical, owner, user_asid, output.len(), false, |mapped| {
        // SAFETY: the caller guarantees that these ranges are disjoint and
        // copy_fragment bounds the mapped input to the checked page.
        unsafe { ptr::copy_nonoverlapping(mapped, output.as_mut_ptr(), output.len()) };
    })
}

/// # Safety
/// The caller checked this page's actual writable user mapping and owner
/// and holds its backing exclusively until return. The input is an
/// independent EL1 buffer.
#[cfg(feature = "unified-runtime")]
pub(crate) unsafe fn copy_out(
    physical: u64,
    owner: Identity,
    user_asid: u8,
    input: &[u8],
) -> Result<(), Error> {
    copy_fragment(physical, owner, user_asid, input.len(), true, |mapped| {
        // SAFETY: the caller guarantees a disjoint EL1 source and the
        // fragment check guarantees the whole destination is mapped.
        unsafe { ptr::copy_nonoverlapping(input.as_ptr(), mapped, input.len()) };
    })
}

/// # Safety
/// Same checked writable span, exclusive custody and disjoint EL1 input as
/// copy_out. The readback takes place before the window closes.
#[cfg(any(
    cyxia_startup_catalog,
    feature = "v020-production-live-control",
    feature = "v020-production-fsync-scratch"
))]
pub(crate) unsafe fn copy_out_and_check(
    physical: u64,
    owner: Identity,
    user_asid: u8,
    input: &[u8],
) -> Result<bool, Error> {
    copy_fragment(physical, owner, user_asid, input.len(), true, |mapped| {
        // SAFETY: both accesses stay inside the checked destination.
        unsafe { ptr::copy_nonoverlapping(input.as_ptr(), mapped, input.len()) };
        input
            .iter()
            .enumerate()
            .all(|(i, &byte)| unsafe { mapped.add(i).read_volatile() == byte })
    })
}

fn copy_fragment<R>(
    physical: u64,
    owner: Identity,
    user_asid: u8,
    length: usize,
    write: bool,
    transfer: impl FnOnce(*mut u8) -> R,
) -> Result<R, Error> {
    let offset = physical & PAGE_MASK;
    if length == 0
        || length as u64 > PAGE_SIZE - offset
        || !(RAM_BASE..USER_RAM_END).contains(&physical)
    {
        return Err(Error::Invalid);
    }
    let permissions = PagePermissions::new(write, false).map_err(|_| Error::Invalid)?;
    let leaf = mmu::encode_leaf(
        PhysAddr(physical & !PAGE_MASK),
        permissions,
        mmu::MemoryAttr::Normal,
    )
    .map_err(|_| Error::Invalid)?
        | NON_GLOBAL;

    let _mask = MaskDaif::all();
    let slot = cpu::registered_slot().ok_or(Error::Unauthorized)?;
    let (root, entry) = slot_path(slot).ok_or(Error::Unauthorized)?;
    let (root0, root1, daif, tcr): (u64, u64, u64, u64);
    // SAFETY: these are read-only observations of the executing CPU.
    unsafe {
        asm!("mrs {}, ttbr0_el1", "mrs {}, ttbr1_el1", "mrs {}, daif", "mrs {}, tcr_el1",
             out(reg) root0, out(reg) root1, out(reg) daif, out(reg) tcr,
             options(nomem, nostack, preserves_flags));
    }
    if tcr & TCR_A1 == 0 {
        return Err(Error::Unauthorized);
    }
    let pan = SoftwarePanContext {
        ttbr0_empty_root: root0 == ptr::addr_of!(empty_l1) as u64,
        ttbr1_asid_zero: root1 == root,
        daif_masked: daif & DAIF_MASK == DAIF_MASK,
        epd0: tcr & TCR_EPD0 != 0,
    };
    let mut window = CopyWindow::open(
        slot as u8,
        WINDOW_VA,
        WINDOW_VA + PAGE_SIZE,
        owner.id,
        owner.generation,
        user_asid,
        pan,
    )?;
    let start = WINDOW_VA + offset;
    let aligned = start & !(COPY_SPAN_ALIGN - 1);
    window.authorize_copy(
        slot as u8,
        owner.id,
        owner.id,
        owner.generation,
        aligned,
        (start - aligned) as usize + length,
    )?;
    // SAFETY: the observed TTBR1 uses this CPU's dedicated descriptor.
    // DAIF is masked and the same CPU cannot re-enter the copy path.
    unsafe {
        if entry.read_volatile() != 0 {
            cyxia_revoke_copy_window(entry);
            crate::smp::fatal(FATAL_WINDOW);
        }
        entry.write_volatile(leaf);
        asm!("dsb ishst", "isb", options(nostack, preserves_flags));
    }
    let result = transfer(ptr::without_provenance_mut(start as usize));
    let invalidating = window.begin_teardown();
    // SAFETY: complete local invalidation before returning to the caller
    // (which still owns the pin) or restoring the interrupt masks.
    unsafe { cyxia_revoke_copy_window(entry) };
    invalidating?;
    window.finish_teardown(true)?;
    Ok(result)
}

#[inline(never)]
#[unsafe(no_mangle)]
unsafe extern "C" fn cyxia_revoke_copy_window(entry: *mut u64) {
    // SAFETY: caller holds the local copy descriptor with DAIF masked.
    // VAE1 targets this high VA and the kernel-reserved ASID 0.
    unsafe {
        entry.write_volatile(0);
        asm!("dsb ishst", "tlbi vae1, {}", "dsb ish", "isb", in(reg) LOCAL_TLBI,
             options(nostack, preserves_flags));
    }
}
