//! Private anonymous mappings. CPU0 owns metadata after all APs return.
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

#[cfg(feature = "full-os")]
#[path = "user_heap/pool.rs"]
mod pool;
#[path = "user_heap/transaction.rs"]
mod transaction;
#[cfg(feature = "full-os")]
use cyxia_kernel_core::frames::FrameHandle;
#[cfg(not(feature = "full-os"))]
const BYTES: u64 = (vm::PAGE_COUNT * vm::PAGE_SIZE) as u64;
#[cfg(not(feature = "full-os"))]
pub const RESERVED_BYTES: u64 = BYTES * MAX_PROCESSES as u64;
#[cfg(feature = "full-os")]
pub const RESERVED_BYTES: u64 = pool::BYTES;
#[cfg(feature = "full-os")]
pub use pool::status as pool_status;
#[cfg(target_arch = "aarch64")]
const _: () = assert!(
    cyxia_platform_virt::KERNEL_POOL_END + RESERVED_BYTES <= cyxia_platform_virt::USER_RAM_END
);
// Real COSMIC keyboard compilation exceeds 512 live small mappings while
// pages remain free. Grow only full-OS metadata; page admission is unchanged.
#[cfg(feature = "full-os")]
const ALLOCATIONS: usize = 1024;
#[cfg(not(feature = "full-os"))]
const ALLOCATIONS: usize = 512;
const TABLES: usize = vm::PAGE_COUNT / 512;
#[cfg(feature = "full-os")]
const MODEL_ID: u64 = cyxia_ai_runtime::FULL_OS_POOL_ANON_MODEL_ID;
#[cfg(not(feature = "full-os"))]
const MODEL_ID: u64 = 8194;
static POOL_BASE: AtomicU64 = AtomicU64::new(0);

/// This pinned board already maps all RAM at HIGH+PA. Reserve outside the entire
/// kernel load budget, never inside DTB/firmware reservations. Publish the range
/// back to BootInfo so subsequent services cannot treat it as free RAM.
#[cfg(target_arch = "aarch64")]
pub fn init(info: &mut BootInfo) -> Result<(), Errno> {
    let range =
        cyxia_platform_virt::reserve_user_pool(info, RESERVED_BYTES).map_err(|_| Errno::Nomem)?;
    #[cfg(feature = "full-os")]
    pool::init(range.start.0)?;
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
    #[cfg(feature = "full-os")]
    frames: [Option<FrameHandle>; vm::PAGE_COUNT],
    tables: [Table; TABLES],
    allocations: [Option<Allocation>; ALLOCATIONS],
    ledger: BoundedGrantLedger<ALLOCATIONS>,
    base: u64,
    owner: Option<Owner>,
    pub model: u64,
    usage: Usage,
}

// Desired PTEs are private staging metadata. Every AP is stopped. New frames
// have no published alias until Heap::publish_space; old frames were revoked
// before release and cannot remain mapped when the pool reuses them.
struct HeapBacking<'a> {
    tables: &'a mut [Table; TABLES],
    #[cfg(feature = "full-os")]
    frames: &'a mut [Option<FrameHandle>; vm::PAGE_COUNT],
    #[cfg(feature = "full-os")]
    owner: cyxia_contracts::TaskId,
    #[cfg(not(feature = "full-os"))]
    base: u64,
}
impl transaction::Backing for HeapBacking<'_> {
    fn stage(&mut self, page: vm::Page) -> Result<(), Errno> {
        #[cfg(feature = "full-os")]
        let physical = {
            let frame = pool::allocate(self.owner)?;
            self.frames[page.slot] = Some(frame);
            frame.address().0
        };
        #[cfg(not(feature = "full-os"))]
        let physical = {
            let physical = self.base + page.slot as u64 * vm::PAGE_SIZE as u64;
            unsafe {
                core::ptr::write_bytes((super::HIGH + physical) as *mut u8, 0, vm::PAGE_SIZE);
            }
            physical
        };
        let index = ((page.address - vm::BASE) / vm::PAGE_SIZE as u64) as usize;
        self.tables[index / 512].set(index % 512, physical, 3)
    }
    fn unstage(&mut self, page: vm::Page) {
        let index = ((page.address - vm::BASE) / vm::PAGE_SIZE as u64) as usize;
        self.tables[index / 512].remove(index % 512);
    }
    fn release(&mut self, page: vm::Page) -> Result<(), Errno> {
        #[cfg(feature = "full-os")]
        if let Some(frame) = self.frames[page.slot] {
            pool::release(frame, self.owner)?;
            self.frames[page.slot] = None;
        }
        #[cfg(not(feature = "full-os"))]
        unsafe {
            let physical = self.base + page.slot as u64 * vm::PAGE_SIZE as u64;
            core::ptr::write_bytes((super::HIGH + physical) as *mut u8, 0, vm::PAGE_SIZE);
        }
        Ok(())
    }
}

/// Lifetime high-water marks survive teardown until the slot is rebound.
#[derive(Clone, Copy)]
pub struct Usage {
    pub peak_pages: u32,
    pub allocations: u32,
    pub peak_allocations: u32,
    pub largest_free: u32,
}
impl Usage {
    const EMPTY: Self = Self {
        peak_pages: 0,
        allocations: 0,
        peak_allocations: 0,
        largest_free: vm::PAGE_COUNT as u32,
    };
}
impl Heap {
    pub const fn new() -> Self {
        Self {
            vm: Vm::new(),
            batch: PageBatch::new(),
            #[cfg(feature = "full-os")]
            frames: [None; vm::PAGE_COUNT],
            tables: [const { Table::empty() }; TABLES],
            allocations: [None; ALLOCATIONS],
            ledger: BoundedGrantLedger::new(PageCount(vm::PAGE_COUNT as u32)),
            base: 0,
            owner: None,
            model: 0,
            usage: Usage::EMPTY,
        }
    }
    pub fn bind(&mut self, slot: usize, owner: Owner) {
        assert!(slot < MAX_PROCESSES && self.vm.used() == 0);
        let pool = POOL_BASE.load(Ordering::Relaxed);
        #[cfg(feature = "full-os")]
        {
            assert!(self.frames.iter().all(Option::is_none));
            self.base = pool;
        }
        #[cfg(not(feature = "full-os"))]
        {
            self.base = if pool == 0 {
                0
            } else {
                pool + BYTES * slot as u64
            };
        }
        self.owner = Some(owner);
        self.model = 0;
        self.usage = Usage::EMPTY;
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
    pub fn usage(&self) -> Usage {
        self.usage
    }
    fn physical(&self, slot: usize) -> u64 {
        #[cfg(feature = "full-os")]
        {
            self.frames[slot].expect("owned physical frame").address().0
        }
        #[cfg(not(feature = "full-os"))]
        {
            self.base + slot as u64 * vm::PAGE_SIZE as u64
        }
    }
    fn pointer(&self, slot: usize, offset: usize) -> *mut u8 {
        assert!(self.base != 0 && slot < vm::PAGE_COUNT && offset < vm::PAGE_SIZE);
        (super::HIGH + self.physical(slot) + offset as u64) as *mut u8
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
        // Both profiles retain the independently validated 2048-page request
        // domain. Pool growth does not authorize larger individual requests.
        if pages > 2048 || pages > self.free() as usize {
            return Err(Errno::Nomem);
        }
        let slot = self
            .allocations
            .iter()
            .position(Option::is_none)
            .ok_or(Errno::Nomem)?;
        let owner = self.owner.ok_or(Errno::Perm)?;
        attempt.proposed(MODEL_ID);
        #[cfg(not(feature = "full-os"))]
        let policy = cyxia_ai_runtime::anonymous_memory_policy;
        #[cfg(feature = "full-os")]
        let policy = cyxia_ai_runtime::full_os_pool_anonymous_memory_policy;
        let effective_free = self.free();
        #[cfg(feature = "full-os")]
        let effective_free = effective_free.min(pool::snapshot()?.free as u32);
        let (admitted, model) = policy(effective_free, pages as u32).map_err(|_| Errno::Io)?;
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
        let redemption = transaction::allocate(
            &mut self.vm,
            &mut self.batch,
            &mut self.ledger,
            request,
            owner,
            pages,
            &mut HeapBacking {
                tables: &mut self.tables,
                #[cfg(feature = "full-os")]
                frames: &mut self.frames,
                #[cfg(feature = "full-os")]
                owner: owner.task,
                #[cfg(not(feature = "full-os"))]
                base: self.base,
            },
            |grant, pages| {
                ai::record(Domain::Anonymous, |c| {
                    if grant {
                        c.grant(pages as u64);
                    } else {
                        c.release(pages as u64);
                    }
                })
            },
        )?;
        self.allocations[slot] = Some(Allocation {
            start: self.batch.start(),
            pages,
            redemption,
        });
        self.usage.allocations += 1;
        self.usage.peak_allocations = self.usage.peak_allocations.max(self.usage.allocations);
        self.usage.peak_pages = self.usage.peak_pages.max(self.used());
        self.usage.largest_free = self.vm.largest_free_run() as u32;
        Ok(self.batch.start())
    }
    /// Native first-stage API: unmap exactly one original allocation. Partial or
    /// combined munmap semantics are deliberately not advertised as POSIX yet.
    pub fn unmap(&mut self, start: u64, pages: usize) -> Result<(), Errno> {
        // Only unpublished allocations or a fully retired process use this
        // entry. Live process owners must supply their hardware revocation.
        self.unmap_with_revoke(start, pages, |_, _| {})
    }
    pub fn unmap_with_revoke(
        &mut self, start: u64, pages: usize, revoke: impl FnOnce(u64, usize),
    ) -> Result<(), Errno> {
        let slot = self
            .allocations
            .iter()
            .position(|a| a.is_some_and(|a| a.start == start && a.pages == pages))
            .ok_or(Errno::Inval)?;
        let allocation = self.allocations[slot].ok_or(Errno::Io)?;
        let owner = self.owner.ok_or(Errno::Io)?;
        #[cfg(feature = "full-os")]
        for fragment in self.vm.fragments(start, pages * vm::PAGE_SIZE)? {
            pool::check_owned(self.frames[fragment.slot].ok_or(Errno::Io)?, owner.task)?;
        }
        // Validation precedes revocation; a rejected munmap preserves the live
        // root. Failure to revoke must stop before any VM/grant/backing release.
        revoke(start, pages);
        self.vm.unmap_into(start, pages, &mut self.batch)?;
        for page in self.batch.iter() {
            let index = ((page.address - vm::BASE) / vm::PAGE_SIZE as u64) as usize;
            self.tables[index / 512].remove(index % 512);
        }
        // The owner revoked every affected user alias before reaching here;
        // no other CPU/DMA retains these pages while they are cleared.
        for page in self.batch.iter() {
            #[cfg(feature = "full-os")]
            {
                let frame = self.frames[page.slot].ok_or(Errno::Io)?;
                pool::release(frame, owner.task)?;
                self.frames[page.slot] = None;
            }
            #[cfg(not(feature = "full-os"))]
            unsafe {
                core::ptr::write_bytes(self.pointer(page.slot, 0), 0, vm::PAGE_SIZE);
            }
        }
        self.ledger
            .release_completed(unsafe {
                ReleaseReceipt::after_revoke(allocation.redemption, owner, PageCount(pages as u32))
            })
            .map_err(|_| Errno::Io)?;
        ai::record(Domain::Anonymous, |c| c.release(pages as u64));
        self.allocations[slot] = None;
        self.usage.allocations -= 1;
        self.usage.largest_free = self.vm.largest_free_run() as u32;
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
    pub fn seal_readonly(&mut self, address: u64, len: usize) -> Result<(), Errno> {
        self.vm.seal_readonly(address, len)?;
        self.protect(address, len, 1)
    }
    #[cfg(feature = "ported")]
    pub fn protect(&mut self, address: u64, len: usize, protection: u8) -> Result<(), Errno> {
        self.vm.protect(address, len, protection)?;
        let rounded = len.checked_add(4095).ok_or(Errno::Inval)? & !4095;
        for fragment in self.vm.fragments(address, rounded)? {
            let i = ((fragment.address - vm::BASE) / 4096) as usize;
            let physical = self.physical(fragment.slot);
            self.tables[i / 512].set(i % 512, physical, protection)?;
        }
        // CPU0 owns the stopped process. The next entry synchronizes these
        // dirty PTEs before any CPU can use the retained root again.
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
    #[cfg(feature = "full-os")]
    pool::init(base.0)?;
    POOL_BASE.store(base.0, Ordering::Release);
    Ok(())
}
#[cfg(target_arch = "x86_64")]
impl Heap {
    pub fn publish_space(
        &mut self,
        space: &mut crate::address_space::ProcessSpace,
        fresh: bool,
    ) -> Result<(), Errno> {
        for (index, table) in self.tables.iter_mut().enumerate() {
            table.synchronize(space, vm::BASE + index as u64 * 0x200000, fresh)?;
        }
        Ok(())
    }
}
