//! Pinned per-process anonymous RAM. CPU0 foreground owns all metadata and copies.
use super::user::ai::{self, Domain};
use crate::address_space::PageTable as Table;
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_ai_runtime::accounting::Attempt;
#[cfg(target_arch = "aarch64")]
use cyxia_contracts::BootInfo;
use cyxia_contracts::{PageCount, RedemptionId};
use cyxia_kernel_core::grants::{
    AuthorizedGrantRequest, BoundedGrantLedger, Owner, ReleaseReceipt,
};
use cyxia_posix::{
    Errno,
    usermem::MAX_PROCESSES,
    vm::{self, PageBatch, Vm},
};

const BYTES: u64 = (vm::PAGE_COUNT * vm::PAGE_SIZE) as u64;
pub const RESERVED_BYTES: u64 = BYTES * MAX_PROCESSES as u64;
#[cfg(target_arch = "aarch64")]
const _: () = assert!(
    cyxia_platform_virt::KERNEL_POOL_END + RESERVED_BYTES <= cyxia_platform_virt::USER_RAM_END
);
const ALLOCATIONS: usize = 512;
const TABLES: usize = vm::PAGE_COUNT / 512;
static POOL_BASE: AtomicU64 = AtomicU64::new(0);

/// This pinned board already maps all RAM at HIGH+PA. Reserve outside the entire
/// kernel load budget, never inside DTB/firmware reservations. Publish the range
/// back to BootInfo so subsequent services cannot treat it as free RAM.
#[cfg(target_arch = "aarch64")]
pub fn init(info: &mut BootInfo) -> Result<(), Errno> {
    let range =
        cyxia_platform_virt::reserve_user_pool(info, RESERVED_BYTES).map_err(|_| Errno::Nomem)?;
    POOL_BASE.store(range.start.0, Ordering::Relaxed);
    Ok(())
}

#[derive(Clone, Copy)]
struct Allocation {
    start: u64,
    pages: usize,
    redemption: RedemptionId,
}
pub struct Heap {
    vm: Vm,
    // CPU0 owns each Heap while user execution is stopped. Reuse pinned output instead of
    // copying whole-pool page lists through the guarded kernel stack.
    batch: PageBatch,
    tables: [Table; TABLES],
    allocations: [Option<Allocation>; ALLOCATIONS],
    ledger: BoundedGrantLedger<ALLOCATIONS>,
    base: u64,
    owner: Option<Owner>,
    pub model: u64,
}
impl Heap {
    pub const fn new() -> Self {
        Self {
            vm: Vm::new(),
            batch: PageBatch::new(),
            tables: [const { Table::empty() }; TABLES],
            allocations: [None; ALLOCATIONS],
            ledger: BoundedGrantLedger::new(PageCount(vm::PAGE_COUNT as u32)),
            base: 0,
            owner: None,
            model: 0,
        }
    }
    pub fn bind(&mut self, slot: usize, owner: Owner) {
        assert!(slot < MAX_PROCESSES && self.vm.used() == 0);
        let pool = POOL_BASE.load(Ordering::Relaxed);
        self.base = if pool == 0 {
            0
        } else {
            pool + BYTES * slot as u64
        };
        self.owner = Some(owner);
        self.model = 0;
    }
    #[cfg(target_arch = "aarch64")]
    pub fn roots(&self) -> [u64; TABLES] {
        core::array::from_fn(|i| (&self.tables[i] as *const Table as u64 - super::HIGH) | 3)
    }
    pub fn used(&self) -> u32 {
        self.vm.used() as u32
    }
    pub fn free(&self) -> u32 {
        self.ledger.snapshot().free
    }
    fn pointer(&self, slot: usize, offset: usize) -> *mut u8 {
        assert!(self.base != 0 && slot < vm::PAGE_COUNT && offset < vm::PAGE_SIZE);
        (super::HIGH + self.base + (slot * vm::PAGE_SIZE + offset) as u64) as *mut u8
    }
    pub fn allocate(&mut self, pages: usize) -> Result<u64, Errno> {
        let mut attempt = Attempt::default();
        let result = self.allocate_accounted(pages, &mut attempt);
        ai::admission(Domain::Anonymous, attempt, &result);
        result
    }
    fn allocate_accounted(&mut self, pages: usize, attempt: &mut Attempt) -> Result<u64, Errno> {
        if self.base == 0 {
            return Err(Errno::Nodev);
        }
        if pages == 0 || pages > vm::PAGE_COUNT {
            return Err(Errno::Inval);
        }
        // The unchanged model is trained for requests up to 2048 pages.
        // A larger pool does not authorize extrapolating its request domain.
        if pages > 2048 || pages > self.free() as usize {
            return Err(Errno::Nomem);
        }
        let slot = self
            .allocations
            .iter()
            .position(Option::is_none)
            .ok_or(Errno::Nomem)?;
        let owner = self.owner.ok_or(Errno::Perm)?;
        attempt.proposed(8194);
        let (admitted, model) =
            cyxia_ai_runtime::anonymous_memory_policy(self.free(), pages as u32)
                .map_err(|_| Errno::Io)?;
        attempt.decided(admitted, model);
        self.model = model;
        if !admitted {
            return Err(Errno::Nomem);
        }
        // Sole trusted admission path, using current private-pool capacity and
        // authenticated process owner. No user can supply origin or grant IDs.
        let request =
            unsafe { AuthorizedGrantRequest::validated_ai(owner, PageCount(pages as u32), model) }
                .map_err(|_| Errno::Io)?;
        let redemption = self
            .ledger
            .commit_and_redeem(request)
            .map_err(|_| Errno::Nomem)?;
        ai::record(Domain::Anonymous, |c| c.grant(pages as u64));
        if let Err(error) = self.vm.allocate_into(pages, &mut self.batch) {
            // No PTE was published; no CPU or device ever saw these pages.
            self.ledger
                .release_completed(unsafe {
                    ReleaseReceipt::after_revoke(redemption, owner, PageCount(pages as u32))
                })
                .map_err(|_| Errno::Io)?;
            ai::record(Domain::Anonymous, |c| c.release(pages as u64));
            return Err(error);
        }
        for page in self.batch.iter() {
            // Private boot-reserved RAM; not yet user mapped, no DMA aliases.
            unsafe {
                core::ptr::write_bytes(self.pointer(page.slot, 0), 0, vm::PAGE_SIZE);
            }
            let index = ((page.address - vm::BASE) / vm::PAGE_SIZE as u64) as usize;
            self.tables[index / 512]
                .set(
                    index % 512,
                    self.base + (page.slot * vm::PAGE_SIZE) as u64,
                    1 | if true { 2 } else { 0 } | if false { 4 } else { 0 },
                )
                .map_err(|_| Errno::Inval)?;
        }
        self.allocations[slot] = Some(Allocation {
            start: self.batch.start(),
            pages,
            redemption,
        });
        Ok(self.batch.start())
    }
    /// Native first-stage API: unmap exactly one original allocation. Partial or
    /// combined munmap semantics are deliberately not advertised as POSIX yet.
    pub fn unmap(&mut self, start: u64, pages: usize) -> Result<(), Errno> {
        let slot = self
            .allocations
            .iter()
            .position(|a| a.is_some_and(|a| a.start == start && a.pages == pages))
            .ok_or(Errno::Inval)?;
        let allocation = self.allocations[slot].ok_or(Errno::Io)?;
        self.vm.unmap_into(start, pages, &mut self.batch)?;
        for page in self.batch.iter() {
            let index = ((page.address - vm::BASE) / vm::PAGE_SIZE as u64) as usize;
            self.tables[index / 512].remove(index % 512);
        }
        // The backend retired every user alias before this CPU0 syscall;
        // no other CPU/DMA retains these pages while they are cleared.
        for page in self.batch.iter() {
            unsafe {
                core::ptr::write_bytes(self.pointer(page.slot, 0), 0, vm::PAGE_SIZE);
            }
        }
        let owner = self.owner.ok_or(Errno::Io)?;
        self.ledger
            .release_completed(unsafe {
                ReleaseReceipt::after_revoke(allocation.redemption, owner, PageCount(pages as u32))
            })
            .map_err(|_| Errno::Io)?;
        ai::record(Domain::Anonymous, |c| c.release(pages as u64));
        self.allocations[slot] = None;
        Ok(())
    }
    pub fn clear(&mut self) {
        for i in 0..ALLOCATIONS {
            if let Some(a) = self.allocations[i] {
                self.unmap(a.start, a.pages)
                    .expect("owned allocation after user revoke");
            }
        }
        self.owner = None;
    }
    #[cfg(all(feature = "ported", target_arch = "x86_64"))]
    pub fn contains_mapping(&self, address: u64) -> bool {
        self.vm.validate(address, 1).is_ok() // includes allocated PROT_NONE
    }
    pub fn validate_access(&self, address: u64, len: usize, write: bool) -> Result<(), Errno> {
        self.vm.validate_access(address, len, write)
    }
    #[cfg(feature = "ported")]
    pub fn allocate_protected(&mut self, pages: usize, protection: u8) -> Result<u64, Errno> {
        if !matches!(protection, 0 | 1 | 3) {
            return Err(Errno::Access);
        }
        let address = self.allocate(pages)?;
        if let Err(error) = self.protect(address, pages * 4096, protection) {
            self.unmap(address, pages)?;
            return Err(error);
        }
        Ok(address)
    }
    #[cfg(feature = "ported")]
    pub fn protect(&mut self, address: u64, len: usize, protection: u8) -> Result<(), Errno> {
        self.vm.protect(address, len, protection)?;
        let rounded = len.checked_add(4095).ok_or(Errno::Inval)? & !4095;
        for fragment in self.vm.fragments(address, rounded)? {
            let i = ((fragment.address - vm::BASE) / 4096) as usize;
            self.tables[i / 512].set(
                i % 512,
                self.base + fragment.slot as u64 * 4096,
                protection,
            )?;
        }
        // CPU0 owns the stopped process; the retired backend root has no stale
        // user alias. The next entry publishes these desired permissions.
        Ok(())
    }
    pub fn read(&self, address: u64, out: &mut [u8]) -> Result<(), Errno> {
        if out.is_empty() {
            return Ok(());
        }
        self.vm.validate_access(address, out.len(), false)?;
        let mut done = 0;
        for fragment in self.vm.fragments(address, out.len())? {
            // Metadata validates the complete range before any copying. The
            // private physical pages cannot alias the kernel destination buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.pointer(fragment.slot, fragment.offset),
                    out[done..].as_mut_ptr(),
                    fragment.len,
                );
            }
            done += fragment.len;
        }
        Ok(())
    }
    pub fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() {
            return Ok(());
        }
        self.vm.validate_access(address, data.len(), true)?;
        let mut done = 0;
        for fragment in self.vm.fragments(address, data.len())? {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data[done..].as_ptr(),
                    self.pointer(fragment.slot, fragment.offset),
                    fragment.len,
                );
            }
            done += fragment.len;
        }
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
pub fn init_pc() -> Result<(), Errno> {
    if POOL_BASE.load(Ordering::Acquire) != 0 {
        return Err(Errno::Busy);
    }
    let base = crate::os::reserve_pool(RESERVED_BYTES)?;
    POOL_BASE.store(base.0, Ordering::Release);
    Ok(())
}
#[cfg(target_arch = "x86_64")]
impl Heap {
    pub fn publish_space(
        &self,
        space: &mut crate::address_space::ProcessSpace,
    ) -> Result<(), Errno> {
        for (index, table) in self.tables.iter().enumerate() {
            table.publish(space, vm::BASE + index as u64 * 0x200000)?;
        }
        Ok(())
    }
}
