//! Pinned ELF image pages and initial stack. CPU0 foreground is the sole owner.
use super::user::ai::{self, Domain};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_ai_runtime::accounting::Attempt;
use cyxia_arch_aarch64::mmu;
use cyxia_contracts::{BootInfo, PageCount, PhysAddr, RedemptionId};
use cyxia_kernel_core::grants::{AuthorizedGrantRequest, GrantLedger, Owner, ReleaseReceipt};
use cyxia_posix::{
    Errno,
    executable::{self, Plan, StackConfig},
    usermem::MAX_PROCESSES,
};
const PAGES: usize = 4096;
const BYTES: u64 = PAGES as u64 * 4096;
pub const RESERVED_BYTES: u64 = BYTES * MAX_PROCESSES as u64;
const _: () = assert!(
    cyxia_platform_virt::KERNEL_POOL_END + super::user_heap::RESERVED_BYTES + RESERVED_BYTES
        <= cyxia_platform_virt::USER_RAM_END
);
pub const STACK_BASE: u64 = 0x03000000;
pub const STACK_PAGES: usize = 64;
static POOL: AtomicU64 = AtomicU64::new(0);

pub fn init(info: &mut BootInfo) -> Result<(), Errno> {
    let range =
        cyxia_platform_virt::reserve_user_pool(info, RESERVED_BYTES).map_err(|_| Errno::Nomem)?;
    POOL.store(range.start.0, Ordering::Relaxed);
    Ok(())
}
#[repr(C, align(4096))]
struct Table([u64; 512]);
pub struct StackInput<'a> {
    pub random: [u8; 16],
    pub argv: &'a [&'a [u8]],
    pub envp: &'a [&'a [u8]],
    pub execfn: &'a [u8],
}
pub struct ExecMemory {
    tables: [Table; 8],
    stack_table: Table,
    slots: [u16; PAGES],
    permissions: [u8; PAGES],
    base: u64,
    pages: u32,
    ledger: GrantLedger,
    lease: Option<(Owner, RedemptionId)>,
}
impl ExecMemory {
    pub const fn new() -> Self {
        Self {
            tables: [const { Table([0; 512]) }; 8],
            stack_table: Table([0; 512]),
            slots: [0; PAGES],
            permissions: [0; PAGES],
            base: 0,
            pages: 0,
            ledger: GrantLedger::new(PageCount(PAGES as u32)),
            lease: None,
        }
    }
    pub fn pages(&self) -> u32 {
        self.pages
    }
    pub fn free(&self) -> u32 {
        self.ledger.snapshot().free
    }
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
        attempt.proposed(8195);
        let (allowed, model) =
            cyxia_ai_runtime::executable_memory_policy(PAGES as u32, count as u32)
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
        let id = self
            .ledger
            .commit_and_redeem(request)
            .map_err(|_| Errno::Nomem)?;
        self.lease = Some((owner, id));
        ai::record(Domain::Elf, |c| c.grant(count as u64));
        self.base = pool + slot as u64 * BYTES;
        self.pages = count as u32;
        // Boot-reserved private RAM, no current TTBR0/DMA aliases; zero before
        // recording final mappings. Tables are not published until load returns.
        unsafe {
            core::ptr::write_bytes((super::HIGH + self.base) as *mut u8, 0, count * 4096);
        }
        let result = (|| {
            for (physical, page) in plan.pages().enumerate() {
                let i = ((page.address - executable::IMAGE_BASE) / 4096) as usize;
                self.slots[i] = (physical + 1) as u16;
                self.permissions[i] = 1
                    | if page.permissions.write { 2 } else { 0 }
                    | if page.permissions.execute { 4 } else { 0 };
                self.tables[i / 512].0[i % 512] = mmu::encode_user_leaf(
                    PhysAddr(self.base + physical as u64 * 4096),
                    page.permissions.write,
                    page.permissions.execute,
                )
                .map_err(|_| Errno::Inval)?;
            }
            for segment in plan.loads() {
                self.copy_into(segment.address, segment.data, false)?;
            }
            let stack_page = count - STACK_PAGES;
            for i in 0..STACK_PAGES {
                self.stack_table.0[i] = mmu::encode_user_leaf(
                    PhysAddr(self.base + (stack_page + i) as u64 * 4096),
                    true,
                    false,
                )
                .map_err(|_| Errno::Inval)?;
            }
            // The entire initial stack is private, contiguous, pinned and not yet
            // exposed to EL0. No Rust alias or DMA pointer refers to this region.
            let stack = unsafe {
                core::slice::from_raw_parts_mut(
                    (super::HIGH + self.base + stack_page as u64 * 4096) as *mut u8,
                    STACK_PAGES * 4096,
                )
            };
            let initial = executable::build_stack_with_execfn(
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
            )
            .map_err(|_| Errno::Inval)?;
            // All pages are initialized. Publish instructions through the data
            // cache before the next TTBR0 enable and I-cache invalidation.
            let ctr: u64;
            unsafe {
                core::arch::asm!("mrs {}, ctr_el0",out(reg)ctr);
            }
            let line = 4u64 << ((ctr >> 16) & 15);
            let mut p = super::HIGH + self.base;
            while p < super::HIGH + self.base + count as u64 * 4096 {
                unsafe {
                    core::arch::asm!("dc cvau, {}",in(reg)p);
                }
                p += line;
            }
            unsafe {
                core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
            }
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
        if !(executable::IMAGE_BASE..executable::IMAGE_END).contains(&address) {
            return Err(Errno::Fault);
        }
        let i = ((address - executable::IMAGE_BASE) / 4096) as usize;
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
        if address < executable::IMAGE_BASE || end > executable::IMAGE_END {
            return Err(Errno::Access);
        }
        for at in (address..end).step_by(4096) {
            let i = ((at - executable::IMAGE_BASE) / 4096) as usize;
            if (prot as u8) & !self.permissions[i] != 0 {
                return Err(Errno::Access);
            }
        }
        for at in (address..end).step_by(4096) {
            let i = ((at - executable::IMAGE_BASE) / 4096) as usize;
            self.permissions[i] = prot as u8;
            self.tables[i / 512].0[i % 512] = mmu::encode_user_leaf(
                PhysAddr(self.base + u64::from(self.slots[i] - 1) * 4096),
                prot & 2 != 0,
                prot & 4 != 0,
            )
            .map_err(|_| Errno::Io)?;
        }
        Ok(())
    }
    pub fn clear(&mut self) {
        if let Some((owner, id)) = self.lease.take() {
            for table in &mut self.tables {
                table.0.fill(0);
            }
            self.stack_table.0.fill(0);
            // Caller returned from EL0 with EPD0/TLBI/DSB, or never published
            // these tables. No other CPU or DMA can still refer to the pages.
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
            self.slots.fill(0);
            self.permissions.fill(0);
            self.pages = 0;
        }
    }
}
