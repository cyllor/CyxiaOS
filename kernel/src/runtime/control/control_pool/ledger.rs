//! Fixed boot-lifetime allocation and exact pin ownership for the control pool.
//! Neither a missing reply nor a repeated release makes a live page reusable.
use cyxia_prototype::domains::{Error, ObjectKey};

pub const PAGES: usize = 2048;
pub const MAX_ALLOCATIONS: usize = 64;
pub const MAX_PINS: usize = 128;
const OBJECT_BASE: u64 = 0x4350_4f4f_4c00;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    key: ObjectKey,
    owner: ObjectKey,
    first: u16,
    pages: u16,
}
impl Allocation {
    pub const fn key(self) -> ObjectKey {
        self.key
    }
    pub const fn owner(self) -> ObjectKey {
        self.owner
    }
    pub const fn first(self) -> usize {
        self.first as usize
    }
    pub const fn pages(self) -> usize {
        self.pages as usize
    }
    pub const fn bytes(self) -> usize {
        self.pages as usize * 4096
    }
}
#[derive(Debug)]
pub struct Lease {
    serial: u64,
    allocation: Allocation,
}
#[derive(Clone, Copy)]
struct Entry {
    allocation: Allocation,
    pins: u16,
    sealed: bool,
}
#[derive(Clone, Copy)]
struct Pin {
    serial: u64,
    allocation: Allocation,
}
pub struct Ledger {
    entries: [Option<Entry>; MAX_ALLOCATIONS],
    leases: [Option<Pin>; MAX_PINS],
    count: usize,
    next_page: usize,
    serial: u64,
}
impl Ledger {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_ALLOCATIONS],
            leases: [None; MAX_PINS],
            count: 0,
            next_page: 0,
            serial: 0,
        }
    }
    fn index(&self, allocation: Allocation) -> Result<usize, Error> {
        let index = allocation
            .key
            .id
            .checked_sub(OBJECT_BASE)
            .ok_or(Error::Stale)? as usize;
        if self
            .entries
            .get(index)
            .and_then(|v| *v)
            .is_none_or(|e| e.allocation != allocation)
        {
            return Err(Error::Stale);
        }
        Ok(index)
    }
    pub fn allocate(&mut self, owner: ObjectKey, pages: usize) -> Result<Allocation, Error> {
        if owner.id == 0 || owner.generation == 0 {
            return Err(Error::Auth);
        }
        let end = self.next_page.checked_add(pages).ok_or(Error::Overflow)?;
        if pages == 0 || end > PAGES || self.count == MAX_ALLOCATIONS {
            return Err(Error::Capacity);
        }
        let allocation = Allocation {
            key: ObjectKey {
                id: OBJECT_BASE + self.count as u64,
                generation: 1,
            },
            owner,
            first: self.next_page as u16,
            pages: pages as u16,
        };
        self.entries[self.count] = Some(Entry {
            allocation,
            pins: 0,
            sealed: false,
        });
        self.count += 1;
        self.next_page = end;
        Ok(allocation)
    }
    pub fn find(&self, key: ObjectKey) -> Result<Allocation, Error> {
        let index = key.id.checked_sub(OBJECT_BASE).ok_or(Error::Stale)? as usize;
        self.entries
            .get(index)
            .and_then(|e| *e)
            .filter(|e| e.allocation.key == key)
            .map(|e| e.allocation)
            .ok_or(Error::Stale)
    }
    pub fn validate(&self, allocation: Allocation) -> Result<(), Error> {
        self.index(allocation).map(|_| ())
    }
    pub fn writable(&self, allocation: Allocation) -> Result<(), Error> {
        let entry = self.entries[self.index(allocation)?].ok_or(Error::Stale)?;
        if entry.sealed {
            Err(Error::Auth)
        } else if entry.pins != 0 {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
    pub fn readable(&self, allocation: Allocation) -> Result<(), Error> {
        let entry = self.entries[self.index(allocation)?].ok_or(Error::Stale)?;
        if entry.pins != 0 && !entry.sealed {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
    pub fn sealed(&self, allocation: Allocation) -> Result<bool, Error> {
        Ok(self.entries[self.index(allocation)?]
            .ok_or(Error::Stale)?
            .sealed)
    }
    pub fn seal(&mut self, allocation: Allocation, sealed: bool) -> Result<(), Error> {
        let index = self.index(allocation)?;
        let entry = self.entries[index].as_mut().ok_or(Error::Stale)?;
        if entry.pins != 0 {
            return Err(Error::Busy);
        }
        entry.sealed = sealed;
        Ok(())
    }
    pub fn pin(&mut self, allocation: Allocation) -> Result<Lease, Error> {
        let index = self.index(allocation)?;
        let slot = self
            .leases
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let entry = self.entries[index].as_mut().ok_or(Error::Stale)?;
        entry.pins = entry.pins.checked_add(1).ok_or(Error::Overflow)?;
        self.serial = serial;
        self.leases[slot] = Some(Pin { serial, allocation });
        Ok(Lease { serial, allocation })
    }
    pub fn unpin(&mut self, lease: &Lease) -> Result<(), Error> {
        let index = self.index(lease.allocation)?;
        let slot = self
            .leases
            .iter()
            .position(|p| {
                p.is_some_and(|p| p.serial == lease.serial && p.allocation == lease.allocation)
            })
            .ok_or(Error::Stale)?;
        let entry = self.entries[index].as_mut().ok_or(Error::Stale)?;
        entry.pins = entry.pins.checked_sub(1).ok_or(Error::Conflict)?;
        self.leases[slot] = None;
        Ok(())
    }
    pub fn usage(&self) -> (usize, usize, usize) {
        (
            self.next_page,
            self.count,
            self.leases.iter().filter(|p| p.is_some()).count(),
        )
    }
}
