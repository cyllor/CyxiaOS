//! CPU0 copy window for the authorized snapshot endpoint's static role stack.
//! The stack and page tables are pinned in the image for the entire boot.

use super::{
    EFAULT, FATAL_CATALOG, NativeRole, Role, cpu, fatal, mmu, phys, role_asid, root_pa, stack_span,
    trapped_ttbr0,
};
use core::{
    arch::asm,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};
use cyxia_contracts::{PagePermissions, PhysAddr};
use cyxia_kernel_core::{
    control_plane::Identity,
    security::memory::{COPY_SPAN_ALIGN, CopyWindow, PAGE_SIZE, SoftwarePanContext},
};

const WINDOW_VA: u64 = crate::HIGH + 0x8000_0000;
const LOCAL_TLBI: u64 = (WINDOW_VA >> 12) & ((1 << 44) - 1);
const PAGE_MASK: u64 = PAGE_SIZE - 1;
const NON_GLOBAL: u64 = 1 << 11;
const _: () = {
    assert!(WINDOW_VA - crate::HIGH >= cyxia_platform_virt::USER_RAM_END);
    assert!((WINDOW_VA >> 30) & 511 == 258);
};

unsafe extern "C" {
    static high_l1: u8;
    static empty_l1: u8;
    static __copy_window_l3: u8;
}

static READ_CLOSED: AtomicU64 = AtomicU64::new(0);
static WRITE_CLOSED: AtomicU64 = AtomicU64::new(0);

/// A byte range checked against the stopped role's actual table walk and
/// exclusive static stack owner. It carries no pointer usable by its caller.
pub(super) struct StackSpan {
    physical: u64,
    length: usize,
    owner: Identity,
    root_asid: u64,
    write: bool,
}

impl StackSpan {
    pub(super) fn verify(
        index: usize,
        member: NativeRole,
        address: u64,
        length: usize,
        write: bool,
    ) -> Result<Self, i64> {
        if super::ROLES.get(index) != Some(&Role::Supervisor)
            || member.role != Role::Supervisor
            || member.actor.id == 0
            || member.actor.generation == 0
            || member.ttbr0_root != root_pa(index)
        {
            return Err(EFAULT);
        }
        let root_asid = member.ttbr0_root | (u64::from(role_asid(index)) << 48);
        if trapped_ttbr0() != root_asid {
            return Err(EFAULT);
        }
        let physical = phys(stack_span(index, address, length, write).ok_or(EFAULT)?);
        if physical < cyxia_platform_virt::ENTRY
            || physical
                .checked_add(length as u64)
                .is_none_or(|end| end > cyxia_platform_virt::KERNEL_POOL_END)
        {
            return Err(EFAULT);
        }
        Ok(Self {
            physical,
            length,
            owner: member.actor,
            root_asid,
            write,
        })
    }

    pub(super) fn copy_in(&self, buffer: &mut [u8]) -> Result<(), i64> {
        if self.write {
            return Err(EFAULT);
        }
        self.copy(buffer.len(), |mapped, at, count| {
            // Only the exact checked range is used and the kernel buffer is a
            // private endpoint-local array outside the pinned user stack.
            unsafe { ptr::copy_nonoverlapping(mapped, buffer.as_mut_ptr().add(at), count) };
            true
        })
        .map(|_| ())
    }

    pub(super) fn copy_out_and_check(&self, buffer: &[u8]) -> Result<bool, i64> {
        if !self.write {
            return Err(EFAULT);
        }
        self.copy(buffer.len(), |mapped, at, count| {
            let bytes = &buffer[at..at + count];
            // The trusted reply is endpoint-local, independent of the window.
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), mapped, count) };
            bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| unsafe { mapped.add(index).read_volatile() == *byte })
        })
    }

    fn copy(
        &self,
        length: usize,
        mut transfer: impl FnMut(*mut u8, usize, usize) -> bool,
    ) -> Result<bool, i64> {
        if length == 0
            || length > self.length
            || cpu::registered_slot() != Some(0)
            || trapped_ttbr0() != self.root_asid
        {
            return Err(EFAULT);
        }
        let (root0, root1, daif): (u64, u64, u64);
        unsafe {
            asm!("mrs {}, ttbr0_el1", "mrs {}, ttbr1_el1", "mrs {}, daif",
                 out(reg) root0, out(reg) root1, out(reg) daif,
                 options(nomem, nostack, preserves_flags));
        }
        let pan = SoftwarePanContext {
            ttbr0_empty_root: root0 == ptr::addr_of!(empty_l1) as u64,
            // A complete root comparison also identifies the CPU0-only tree.
            ttbr1_asid_zero: root1 == ptr::addr_of!(high_l1) as u64,
            daif_masked: daif & 0x3c0 == 0x3c0,
            epd0: false,
        };
        let entry = window_entry();
        let asid = (self.root_asid >> 48) as u8;
        let perm = PagePermissions::new(self.write, false).map_err(|_| EFAULT)?;
        let mut at = 0;
        while at < length {
            let physical = self.physical + at as u64;
            let offset = physical & PAGE_MASK;
            let count = (length - at).min((PAGE_SIZE - offset) as usize);
            // Contract granularity is 8 bytes. The enclosing aligned fragment
            // is on this same verified page; the copy uses exactly count bytes.
            let start = WINDOW_VA + offset;
            let aligned = start & !(COPY_SPAN_ALIGN - 1);
            let mut window = CopyWindow::open(
                0,
                WINDOW_VA,
                WINDOW_VA + PAGE_SIZE,
                self.owner.id,
                self.owner.generation,
                asid,
                pan,
            )
            .map_err(|_| EFAULT)?;
            window
                .authorize_copy(
                    0,
                    self.owner.id,
                    self.owner.id,
                    self.owner.generation,
                    aligned,
                    (start - aligned) as usize + count,
                )
                .map_err(|_| EFAULT)?;
            let leaf = mmu::encode_leaf(
                PhysAddr(physical & !PAGE_MASK),
                perm,
                mmu::MemoryAttr::Normal,
            )
            .map_err(|_| EFAULT)?
                | NON_GLOBAL;
            // One CPU0 dispatcher owns the slot with interrupts masked.
            // A stale descriptor cannot be reused or survive a return to EL0.
            if unsafe { entry.read_volatile() } != 0 {
                fatal(FATAL_CATALOG + 7);
            }
            unsafe {
                entry.write_volatile(leaf);
                asm!("dsb ishst", "isb", options(nostack, preserves_flags));
            }
            let exact = transfer(ptr::without_provenance_mut(start as usize), at, count);
            let invalidating = window.begin_teardown();
            // Clearing the PTE and completing the local VA+ASID0 invalidation
            // precede release of this fragment and any reuse of the slot.
            unsafe { cyxia_revoke_copy_window(entry) };
            invalidating.map_err(|_| EFAULT)?;
            window.finish_teardown(true).map_err(|_| EFAULT)?;
            let closed = if self.write {
                &WRITE_CLOSED
            } else {
                &READ_CLOSED
            };
            closed.fetch_add(1, Ordering::Relaxed);
            if !exact {
                return Ok(false);
            }
            at += count;
        }
        Ok(true)
    }
}

fn window_entry() -> *mut u64 {
    // This is the only runtime writer of the dedicated third-level table's
    // first descriptor. The table lives in the existing privileged RAM map.
    ptr::without_provenance_mut((crate::HIGH + ptr::addr_of!(__copy_window_l3) as u64) as usize)
}

#[inline(never)]
#[unsafe(no_mangle)]
unsafe extern "C" fn cyxia_revoke_copy_window(entry: *mut u64) {
    unsafe {
        entry.write_volatile(0);
        asm!("dsb ishst", "tlbi vae1, {}", "dsb ish", "isb", in(reg) LOCAL_TLBI,
             options(nostack, preserves_flags));
    }
}

pub(super) fn closed_counts() -> (u64, u64, bool) {
    (
        READ_CLOSED.load(Ordering::Relaxed),
        WRITE_CLOSED.load(Ordering::Relaxed),
        unsafe { window_entry().read_volatile() } == 0,
    )
}
