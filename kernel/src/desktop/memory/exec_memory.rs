//! Pinned ELF image pages and initial stack. CPU0 foreground is the sole owner.
use super::user::ai::{self, Domain};
use crate::address_space::PageTable as Table;
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_ai_runtime::accounting::Attempt;
#[cfg(target_arch = "aarch64")]
use cyxia_contracts::BootInfo;
use cyxia_contracts::user_layout::ImageProfile;
use cyxia_contracts::{PageCount, RedemptionId};
use cyxia_kernel_core::grants::{AuthorizedGrantRequest, GrantLedger, Owner, ReleaseReceipt};
use cyxia_posix::{
    Errno,
    executable::{self, Plan, StackConfig},
    usermem::MAX_PROCESSES,
};
#[cfg(feature = "full-os")]
pub const PROFILE: ImageProfile = ImageProfile::FullOsV3;
#[cfg(not(feature = "full-os"))]
pub const PROFILE: ImageProfile = ImageProfile::Legacy;
const LAYOUT: cyxia_contracts::user_layout::ImageLayout = PROFILE.layout();
const PAGES: usize = LAYOUT.exec_pool_pages;
const IMAGE_TABLES: usize = LAYOUT.image_pages() / 512;
const _: () = assert!(LAYOUT.image_pages() <= PAGES && PAGES < u16::MAX as usize);
const _: () = assert!(LAYOUT.stack_pages <= 512 && LAYOUT.stack_base % 0x200000 == 0);
const BYTES: u64 = PAGES as u64 * 4096;
#[cfg(feature = "cosmic-session")]
#[path = "exec_memory/arena.rs"]
mod arena;
#[cfg(feature = "cosmic-session")]
pub const RESERVED_BYTES: u64 = arena::BYTES;
#[cfg(not(feature = "cosmic-session"))]
pub const RESERVED_BYTES: u64 = BYTES * MAX_PROCESSES as u64;
// The session arena must hold at least one full per-image virtual window and
// stays within the reviewed shared budget. The aggregate boot fit against the
// 1 GiB machine is verified by the guest boot loop, not assumed here.
#[cfg(feature = "cosmic-session")]
const _: () = assert!(BYTES <= arena::BYTES && arena::PAGES >= PAGES);
#[cfg(target_arch = "aarch64")]
const _: () = assert!(
    cyxia_platform_virt::KERNEL_POOL_END + super::user_heap::RESERVED_BYTES + RESERVED_BYTES
        <= cyxia_platform_virt::USER_RAM_END
);
pub const STACK_BASE: u64 = LAYOUT.stack_base;
pub const STACK_PAGES: usize = LAYOUT.stack_pages;
static POOL: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "aarch64")]
pub fn init(info: &mut BootInfo) -> Result<(), Errno> {
    let range =
        cyxia_platform_virt::reserve_user_pool(info, RESERVED_BYTES).map_err(|_| Errno::Nomem)?;
    #[cfg(feature = "cosmic-session")]
    arena::init(range.start.0, range.len)?;
    POOL.store(range.start.0, Ordering::Relaxed);
    Ok(())
}
pub struct StackInput<'a> {
    pub random: [u8; 16],
    pub argv: &'a [&'a [u8]],
    pub envp: &'a [&'a [u8]],
    pub execfn: &'a [u8],
}
pub struct ExecMemory {
    tables: [Table; IMAGE_TABLES],
    stack_table: Table,
    slots: [u16; PAGES],
    permissions: [u8; PAGES],
    base: u64,
    pages: u32,
    model: u64,
    ledger: GrantLedger,
    lease: Option<(Owner, RedemptionId)>,
}
impl ExecMemory {
    pub const fn new() -> Self {
        Self {
            tables: [const { Table::empty() }; IMAGE_TABLES],
            stack_table: Table::empty(),
            slots: [0; PAGES],
            permissions: [0; PAGES],
            base: 0,
            pages: 0,
            model: 0,
            ledger: GrantLedger::new(PageCount(PAGES as u32)),
            lease: None,
        }
    }
    pub fn pages(&self) -> u32 {
        self.pages
    }
    pub fn model(&self) -> u64 {
        self.model
    }
    pub fn free(&self) -> u32 {
        self.ledger.snapshot().free
    }
    #[cfg(target_arch = "aarch64")]
    pub fn roots(&self) -> [(usize, u64); 9] {
        core::array::from_fn(|i| {
            if i < 8 {
                (
                    8 + i,
                    (&self.tables[i] as *const Table as u64 - super::HIGH) | 3,
                )
            } else {
                (
                    24,
                    (&self.stack_table as *const Table as u64 - super::HIGH) | 3,
                )
            }
        })
    }
    pub fn load(
        &mut self,
        slot: usize,
        owner: Owner,
        plan: &Plan<'_>,
        stack_input: StackInput<'_>,
    ) -> Result<u64, Errno> {
        let mut attempt = Attempt::default();
        let result = self.load_accounted(slot, owner, plan, stack_input, &mut attempt);
        ai::admission(Domain::Elf, attempt, &result);
        result
    }
    fn load_accounted(
        &mut self,
        slot: usize,
        owner: Owner,
        plan: &Plan<'_>,
        stack_input: StackInput<'_>,
        attempt: &mut Attempt,
    ) -> Result<u64, Errno> {
        if plan.profile != PROFILE {
            return Err(Errno::Inval);
        }
        if self.lease.is_some() || slot >= MAX_PROCESSES {
            return Err(Errno::Busy);
        }
        let pool = POOL.load(Ordering::Relaxed);
        if pool == 0 {
            return Err(Errno::Nodev);
        }
        let count = plan.pages().count() + STACK_PAGES;
        if count > PAGES || plan.pages().any(|p| !p.permissions.read) {
            return Err(Errno::Inval);
        }
        attempt.proposed(match PROFILE {
            ImageProfile::Legacy => 8195,
            ImageProfile::FullOsV1 | ImageProfile::FullOsV2 | ImageProfile::FullOsV3 => {
                cyxia_ai_runtime::FULL_OS_EXEC_MODEL_ID
            }
        });
        let (allowed, model) = match PROFILE {
            ImageProfile::Legacy => {
                cyxia_ai_runtime::executable_memory_policy(PAGES as u32, count as u32)
            }
            ImageProfile::FullOsV1 | ImageProfile::FullOsV2 | ImageProfile::FullOsV3 => {
                cyxia_ai_runtime::full_os_executable_memory_policy(PAGES as u32, count as u32)
            }
        }
        .map_err(|_| Errno::Io)?;
        attempt.decided(allowed, model);
        if !allowed {
            return Err(Errno::Nomem);
        }
        // Trusted model evaluated actual private-pool capacity. No user-provided
        // plan identity or grant receipt is accepted by this mechanism.
        let request =
            unsafe { AuthorizedGrantRequest::validated_ai(owner, PageCount(count as u32), model) }
                .map_err(|_| Errno::Io)?;
        // Reserve the physical run before charging the grant so a backing
        // failure leaves no committed lease; a failed commit returns the run.
        #[cfg(feature = "cosmic-session")]
        let run_base = arena::allocate(count, owner).map_err(|_| Errno::Nomem)?;
        let id = match self.ledger.commit_and_redeem(request) {
            Ok(id) => id,
            Err(_) => {
                #[cfg(feature = "cosmic-session")]
                arena::release(run_base, count, owner).expect("uncommitted exec run");
                return Err(Errno::Nomem);
            }
        };
        self.lease = Some((owner, id));
        ai::record(Domain::Elf, |c| c.grant(count as u64));
        #[cfg(feature = "cosmic-session")]
        {
            self.base = run_base;
        }
        #[cfg(not(feature = "cosmic-session"))]
        {
            self.base = pool + slot as u64 * BYTES;
        }
        self.pages = count as u32;
        self.model = model;
        // Boot-reserved private RAM, no current user-root/DMA aliases; zero before
        // recording final mappings. Tables are not published until load returns.
        unsafe {
            core::ptr::write_bytes((super::HIGH + self.base) as *mut u8, 0, count * 4096);
        }
        let result = (|| {
            for (physical, page) in plan.pages().enumerate() {
                let i = ((page.address - LAYOUT.image_base) / 4096) as usize;
                self.slots[i] = (physical + 1) as u16;
                self.permissions[i] = 1
                    | if page.permissions.write { 2 } else { 0 }
                    | if page.permissions.execute { 4 } else { 0 };
                self.tables[i / 512]
                    .set(
                        i % 512,
                        self.base + physical as u64 * 4096,
                        1 | if page.permissions.write { 2 } else { 0 }
                            | if page.permissions.execute { 4 } else { 0 },
                    )
                    .map_err(|_| Errno::Inval)?;
            }
            for segment in plan.loads() {
                self.copy_into(segment.address, segment.data, false)?;
            }
            let stack_page = count - STACK_PAGES;
            for i in 0..STACK_PAGES {
                self.stack_table
                    .set(
                        i,
                        self.base + (stack_page + i) as u64 * 4096,
                        1 | if true { 2 } else { 0 } | if false { 4 } else { 0 },
                    )
                    .map_err(|_| Errno::Inval)?;
            }
            // The entire initial stack is private, contiguous, pinned and not yet
            // exposed to user code. No Rust alias or DMA pointer refers to this region.
            let stack = unsafe {
                core::slice::from_raw_parts_mut(
                    (super::HIGH + self.base + stack_page as u64 * 4096) as *mut u8,
                    STACK_PAGES * 4096,
                )
            };
            let initial = executable::build_stack_for_profile(
                stack,
                STACK_BASE,
                stack_input.argv,
                stack_input.envp,
                &StackConfig {
                    phdr: plan.phdr_address,
                    phnum: plan.phnum,
                    entry: plan.entry,
                    uid: 0,
                    euid: 0,
                    gid: 0,
                    egid: 0,
                    secure: false,
                    random: stack_input.random,
                },
                stack_input.execfn,
                plan.abi,
                PROFILE,
            )
            .map_err(|_| Errno::Inval)?;
            // Arm requires explicit D/I cache synchronization. x86 coherent
            // instruction publication occurs after each RX page loses RW aliases.
            #[cfg(target_arch = "aarch64")]
            crate::process_arch::publish_code(super::HIGH + self.base, count * 4096)?;
            Ok(initial.sp)
        })();
        if result.is_err() {
            self.clear();
        }
        result
    }
    fn resolve(&self, address: u64, write: bool) -> Result<(u64, usize), Errno> {
        if self.pages == 0 {
            return Err(Errno::Fault);
        }
        let offset = (address % 4096) as usize;
        if (STACK_BASE..STACK_BASE + STACK_PAGES as u64 * 4096).contains(&address) {
            let slot = self.pages as usize - STACK_PAGES + ((address - STACK_BASE) / 4096) as usize;
            return Ok((
                super::HIGH + self.base + (slot * 4096 + offset) as u64,
                4096 - offset,
            ));
        }
        if !(LAYOUT.image_base..LAYOUT.image_end).contains(&address) {
            return Err(Errno::Fault);
        }
        let i = ((address - LAYOUT.image_base) / 4096) as usize;
        if self.slots[i] == 0 || (write && self.permissions[i] & 2 == 0) {
            return Err(Errno::Fault);
        }
        Ok((
            super::HIGH + self.base + (usize::from(self.slots[i] - 1) * 4096 + offset) as u64,
            4096 - offset,
        ))
    }
    pub fn validate(&self, address: u64, len: usize, write: bool) -> Result<(), Errno> {
        let end = address.checked_add(len as u64).ok_or(Errno::Fault)?;
        let mut at = address;
        while at < end {
            let (_, n) = self.resolve(at, write)?;
            at += (end - at).min(n as u64);
        }
        Ok(())
    }
    pub fn read(&self, address: u64, out: &mut [u8]) -> Result<(), Errno> {
        self.validate(address, out.len(), false)?;
        let mut done = 0;
        while done < out.len() {
            let (p, n) = self.resolve(address + done as u64, false)?;
            let n = n.min(out.len() - done);
            // Both buffers are fully validated, disjoint and owned by foreground.
            unsafe {
                core::ptr::copy_nonoverlapping(p as *const u8, out[done..].as_mut_ptr(), n);
            }
            done += n;
        }
        Ok(())
    }
    fn copy_into(&mut self, address: u64, data: &[u8], enforce_write: bool) -> Result<(), Errno> {
        self.validate(address, data.len(), enforce_write)?;
        let mut done = 0;
        while done < data.len() {
            let (p, n) = self.resolve(address + done as u64, enforce_write)?;
            let n = n.min(data.len() - done);
            unsafe {
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), p as *mut u8, n);
            }
            done += n;
        }
        Ok(())
    }
    pub fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Errno> {
        self.copy_into(address, data, true)
    }
    /// Current static-loader path permits only tightening RW to R (RELRO) or
    /// idempotently preserving existing R/RX. No adding W or executable heap.
    pub fn protect(&mut self, address: u64, len: usize, prot: u64) -> Result<(), Errno> {
        if len == 0
            || !address.is_multiple_of(4096)
            || prot & !7 != 0
            || prot & 1 == 0
            || prot & 6 == 6
        {
            return Err(Errno::Inval);
        }
        let len = len.checked_add(4095).ok_or(Errno::Inval)? & !4095;
        self.validate(address, len, false)?;
        let end = address.checked_add(len as u64).ok_or(Errno::Inval)?;
        if address < LAYOUT.image_base || end > LAYOUT.image_end {
            return Err(Errno::Access);
        }
        for at in (address..end).step_by(4096) {
            let i = ((at - LAYOUT.image_base) / 4096) as usize;
            if (prot as u8) & !self.permissions[i] != 0 {
                return Err(Errno::Access);
            }
        }
        for at in (address..end).step_by(4096) {
            let i = ((at - LAYOUT.image_base) / 4096) as usize;
            self.permissions[i] = prot as u8;
            self.tables[i / 512]
                .set(
                    i % 512,
                    self.base + u64::from(self.slots[i] - 1) * 4096,
                    1 | if prot & 2 != 0 { 2 } else { 0 } | if prot & 4 != 0 { 4 } else { 0 },
                )
                .map_err(|_| Errno::Inval)?;
        }
        Ok(())
    }
    pub fn clear(&mut self) {
        if let Some((owner, id)) = self.lease.take() {
            crate::process_arch::make_writable(super::HIGH + self.base, self.pages as usize * 4096)
                .expect("retired executable frames before zero");
            for table in &mut self.tables {
                table.clear();
            }
            self.stack_table.clear();
            // The owner retired this process root, or never published these
            // mappings. No other CPU or DMA can still refer to these pages.
            unsafe {
                core::ptr::write_bytes(
                    (super::HIGH + self.base) as *mut u8,
                    0,
                    self.pages as usize * 4096,
                );
            }
            self.ledger
                .release_completed(unsafe {
                    ReleaseReceipt::after_revoke(id, owner, PageCount(self.pages))
                })
                .expect("owned executable after revocation");
            ai::record(Domain::Elf, |c| c.release(u64::from(self.pages)));
            #[cfg(feature = "cosmic-session")]
            arena::release(self.base, self.pages as usize, owner)
                .expect("owned executable run after revocation");
            self.slots.fill(0);
            self.permissions.fill(0);
            self.pages = 0;
            self.model = 0;
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub fn init_pc(range: cyxia_contracts::MemoryRegion) -> Result<(), Errno> {
    if POOL.load(Ordering::Acquire) != 0 {
        return Err(Errno::Busy);
    }
    #[cfg(not(feature = "cosmic-session"))]
    if range.len != RESERVED_BYTES {
        return Err(Errno::Inval);
    }
    #[cfg(feature = "cosmic-session")]
    arena::init(range.start.0, range.len)?;
    POOL.store(range.start.0, Ordering::Release);
    Ok(())
}
#[cfg(target_arch = "x86_64")]
impl ExecMemory {
    pub fn publish_space(
        &mut self,
        space: &mut crate::address_space::ProcessSpace,
        fresh: bool,
    ) -> Result<(), Errno> {
        if self.pages == 0 {
            return Ok(());
        }
        for (index, table) in self.tables.iter_mut().enumerate() {
            table.synchronize(space, LAYOUT.image_base + index as u64 * 0x200000, fresh)?;
        }
        self.stack_table.synchronize(space, STACK_BASE, fresh)
    }
}
