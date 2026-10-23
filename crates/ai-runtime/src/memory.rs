use crate::{Error, model};
use cyxia_contracts::{Generation, GrantId, PageCount, RedemptionId, TaskId};
use cyxia_kernel_core::grants::{AuthorizedGrantRequest, GrantLedger, Owner, ReleaseReceipt};
pub const PAGES: usize = 32;
pub const PAGE_BYTES: usize = 4096;
const MAX_ALLOCATION: usize = 8;
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct Page([u8; PAGE_BYTES]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryId(pub u64);
#[derive(Clone, Copy)]
struct Allocation {
    id: MemoryId,
    owner: u32,
    grant: GrantId,
    redemption: RedemptionId,
    pages: [usize; MAX_ALLOCATION],
    count: usize,
}
#[derive(Clone, Copy, Debug)]
pub struct MemoryStatus {
    pub total: usize,
    pub free: usize,
    pub used: usize,
    pub allocations: usize,
    pub decisions: u64,
    pub denied: u64,
}
pub(crate) struct Memory {
    pages: [Page; PAGES],
    used: [bool; PAGES],
    allocations: [Option<Allocation>; PAGES],
    ledger: GrantLedger,
    next: u64,
    pub decisions: u64,
    pub denied: u64,
}
fn owner(id: u32) -> Result<Owner, Error> {
    Ok(Owner {
        task: TaskId::new(id).map_err(|_| Error::Invalid)?,
        generation: Generation::new(1).map_err(|_| Error::Invalid)?,
    })
}
impl Memory {
    pub const fn new() -> Self {
        Self {
            pages: [Page([0; PAGE_BYTES]); PAGES],
            used: [false; PAGES],
            allocations: [None; PAGES],
            ledger: GrantLedger::new(PageCount(PAGES as u32)),
            next: 1,
            decisions: 0,
            denied: 0,
        }
    }
    pub fn status(&self) -> MemoryStatus {
        let s = self.ledger.snapshot();
        MemoryStatus {
            total: PAGES,
            free: s.free as usize,
            used: s.in_use as usize,
            allocations: self.allocations.iter().flatten().count(),
            decisions: self.decisions,
            denied: self.denied,
        }
    }
    pub fn allocate(&mut self, task: u32, count: usize) -> Result<MemoryId, Error> {
        let own = owner(task)?;
        if count == 0 || count > MAX_ALLOCATION {
            return Err(Error::Invalid);
        }
        let free = self.status().free;
        if count > free {
            return Err(Error::Capacity);
        }
        let next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        let slot = self
            .allocations
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.decisions = self.decisions.saturating_add(1);
        if !model::memory(free, count) {
            self.denied = self.denied.saturating_add(1);
            return Err(Error::AiDenied);
        }
        let mut pages = [0; MAX_ALLOCATION];
        let mut found = 0;
        for (i, used) in self.used.iter().enumerate() {
            if !used && found < count {
                pages[found] = i;
                found += 1;
            }
        }
        if found != count {
            return Err(Error::Invariant);
        }
        // Trusted synchronous admission above authenticates the embedded fixed model.
        // The owner is supplied only by Runtime, never a workload or model output.
        let request = unsafe {
            AuthorizedGrantRequest::validated_ai(own, PageCount(count as u32), model::MEMORY_ID)
        }
        .map_err(|_| Error::Invariant)?;
        let grant = self.ledger.commit(request).map_err(|_| Error::Capacity)?;
        let redemption = match self.ledger.redeem(grant, own, PageCount(count as u32)) {
            Ok(r) => r,
            Err(_) => {
                self.ledger
                    .cancel_unused(grant, own)
                    .map_err(|_| Error::Invariant)?;
                return Err(Error::Invariant);
            }
        };
        for i in &pages[..count] {
            self.pages[*i].0.fill(0);
            self.used[*i] = true;
        }
        let id = MemoryId(self.next);
        self.next = next;
        self.allocations[slot] = Some(Allocation {
            id,
            owner: task,
            grant,
            redemption,
            pages,
            count,
        });
        Ok(id)
    }
    fn lookup(&self, task: u32, id: MemoryId) -> Result<(usize, Allocation), Error> {
        let (slot, a) = self
            .allocations
            .iter()
            .enumerate()
            .find_map(|(i, a)| a.filter(|a| a.id == id).map(|a| (i, a)))
            .ok_or(Error::Stale)?;
        if a.owner != task {
            return Err(Error::Owner);
        }
        Ok((slot, a))
    }
    pub fn release(&mut self, task: u32, id: MemoryId) -> Result<(), Error> {
        let (slot, a) = self.lookup(task, id)?;
        let own = owner(task)?;
        // No raw page reference, CPU user mapping or DMA mapping can escape this
        // module. Exclusive &mut access ends all byte operations before reuse.
        let receipt =
            unsafe { ReleaseReceipt::after_revoke(a.redemption, own, PageCount(a.count as u32)) };
        self.ledger
            .release_completed(receipt)
            .map_err(|_| Error::Invariant)?;
        for i in &a.pages[..a.count] {
            self.pages[*i].0.fill(0);
            self.used[*i] = false;
        }
        self.allocations[slot] = None;
        Ok(())
    }
    pub fn read(&self, task: u32, id: MemoryId, offset: usize) -> Result<u8, Error> {
        let (_, a) = self.lookup(task, id)?;
        if offset >= a.count * PAGE_BYTES {
            return Err(Error::Bounds);
        }
        Ok(self.pages[a.pages[offset / PAGE_BYTES]].0[offset % PAGE_BYTES])
    }
    pub fn write(
        &mut self,
        task: u32,
        id: MemoryId,
        offset: usize,
        value: u8,
    ) -> Result<(), Error> {
        let (_, a) = self.lookup(task, id)?;
        if offset >= a.count * PAGE_BYTES {
            return Err(Error::Bounds);
        }
        self.pages[a.pages[offset / PAGE_BYTES]].0[offset % PAGE_BYTES] = value;
        Ok(())
    }
    pub fn records(&self) -> impl Iterator<Item = (MemoryId, u32, usize, u64)> + '_ {
        self.allocations
            .iter()
            .flatten()
            .map(|a| (a.id, a.owner, a.count, a.grant.get()))
    }
}
