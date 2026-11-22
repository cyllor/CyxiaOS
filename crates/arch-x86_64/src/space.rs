//! Owned four-level user tables. Allocation policy and frame custody stay with
//! the process owner; this module never silently frees a mapped frame.
use core::marker::PhantomData;

pub const PAGE_BYTES: u64 = 4096;
pub const KERNEL_BASE: u64 = 0xffff800000000000;
/// One-GiB runtime direct-map capacity, also used by physical-page guards.
pub const RUNTIME_RAM_BYTES: u64 = 1 << 30;
const MASK: u64 = 0x000f_ffff_ffff_f000;
const P: u64 = 1;
const W: u64 = 2;
const U: u64 = 4;
const NX: u64 = 1 << 63;
const MAX_TABLE_PAGES: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    Permissions,
    Capacity,
    Conflict,
    Identity,
    Active,
    Unsupported,
    Timeout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceId {
    pub id: u64,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPermissions {
    pub writable: bool,
    pub executable: bool,
}
impl UserPermissions {
    pub const RX: Self = Self {
        writable: false,
        executable: true,
    };
    pub const RO: Self = Self {
        writable: false,
        executable: false,
    };
    pub const RW: Self = Self {
        writable: true,
        executable: false,
    };
}
#[derive(Clone, Copy, Debug)]
pub struct Translation {
    pub physical: u64,
    pub permissions: UserPermissions,
}
#[derive(Clone, Copy, Debug)]
pub struct RetiredMapping {
    pub physical: u64,
    pub space: SpaceId,
    pub epoch: u64,
    pub virtual_address: u64,
}
pub struct KernelMappings {
    upper: [u64; 256],
    ram_bytes: u64,
}
impl KernelMappings {
    pub fn new(upper: [u64; 256], ram_bytes: u64) -> Result<Self, Error> {
        if ram_bytes == 0
            || !ram_bytes.is_multiple_of(PAGE_BYTES)
            || ram_bytes > 1 << 52
            || upper.iter().any(|entry| entry & U != 0)
        {
            return Err(Error::Address);
        }
        Ok(Self { upper, ram_bytes })
    }
    pub fn ram_bytes(&self) -> u64 {
        self.ram_bytes
    }
}
/// A private pinned span of page-table frames. Its raw mapping is valid until
/// every resident CPU has left and all invalidation tickets have completed.
pub struct TableArena<'a> {
    virtual_base: *mut u8,
    physical_base: u64,
    pages: usize,
    used: usize,
    free: u64,
    free_count: u16,
    reclaim_pending: bool,
    _owner: PhantomData<&'a mut [u8]>,
}
impl<'a> TableArena<'a> {
    /// # Safety
    /// The caller exclusively owns `pages` contiguous aligned frames and their
    /// writable kernel mapping. They remain pinned for the arena's lifetime
    /// and cannot serve as user-mapped data or page tables for another root.
    pub unsafe fn from_raw(
        virtual_base: *mut u8,
        physical_base: u64,
        pages: usize,
    ) -> Result<Self, Error> {
        if !(4..=MAX_TABLE_PAGES).contains(&pages)
            || virtual_base.is_null()
            || !(virtual_base as usize).is_multiple_of(4096)
            || physical_base == 0
            || !physical_base.is_multiple_of(PAGE_BYTES)
            || physical_base
                .checked_add(pages as u64 * PAGE_BYTES)
                .is_none_or(|end| end > 1 << 52)
        {
            return Err(Error::Address);
        }
        Ok(Self {
            virtual_base,
            physical_base,
            pages,
            used: 0,
            free: 0,
            free_count: 0,
            reclaim_pending: false,
            _owner: PhantomData,
        })
    }
    fn allocate(&mut self) -> Result<u64, Error> {
        if self.free != 0 {
            let physical = self.free;
            let table = self.table(physical)?;
            self.free = unsafe { table.read_volatile() };
            self.free_count -= 1;
            unsafe { core::ptr::write_bytes(table, 0, 512) };
            return Ok(physical);
        }
        if self.used == self.pages {
            return Err(Error::Capacity);
        }
        let index = self.used;
        self.used += 1;
        unsafe {
            core::ptr::write_bytes(self.virtual_base.add(index * 4096), 0, 4096);
        }
        Ok(self.physical_base + index as u64 * PAGE_BYTES)
    }
    fn index(&self, physical: u64) -> Result<usize, Error> {
        let offset = physical
            .checked_sub(self.physical_base)
            .ok_or(Error::Address)?;
        if !offset.is_multiple_of(PAGE_BYTES) || offset / PAGE_BYTES >= self.used as u64 {
            return Err(Error::Address);
        }
        Ok((offset / PAGE_BYTES) as usize)
    }
    fn table(&self, physical: u64) -> Result<*mut u64, Error> {
        let index = self.index(physical)?;
        Ok(unsafe { self.virtual_base.add(index * 4096).cast() })
    }
    fn mapping_table(&mut self, root: u64, address: u64) -> Result<*mut u64, Error> {
        let result = self.extend_path(root, address);
        if result == Err(Error::Capacity) && self.reclaim_empty(root) {
            // Earlier pointers belonged to the old tree. Walk again after
            // unlinking empty paths, even if this was the path being extended.
            return self.extend_path(root, address);
        }
        result
    }
    fn extend_path(&mut self, root: u64, address: u64) -> Result<*mut u64, Error> {
        let mut table = self.table(root)?;
        for (needed, shift) in [(3, 39), (2, 30), (1, 21)] {
            let entry = unsafe { table.add(((address >> shift) & 511) as usize) };
            let mut value = unsafe { entry.read_volatile() };
            if value & P == 0 {
                // All lower levels would be new. Reject the whole path if
                // it would consume table frames without reaching a leaf.
                if self.pages - self.used + usize::from(self.free_count) < needed {
                    return Err(Error::Capacity);
                }
                value = self.allocate()? | P | W | U;
                unsafe { entry.write_volatile(value) };
            }
            if value & (1 << 7) != 0 {
                return Err(Error::Conflict);
            }
            table = self.table(value & MASK)?;
        }
        Ok(table)
    }
    /// Called only after a failed allocation with the root exclusively owned
    /// and nonresident. An arena never reclaims the root or the kernel half.
    #[cold]
    fn reclaim_empty(&mut self, root: u64) -> bool {
        if !self.reclaim_pending {
            return false;
        }
        let mut visited = [0u64; MAX_TABLE_PAGES / 64];
        let mut free = self.free;
        for _ in 0..self.free_count {
            let Some(table) = self.visit_table(free, &mut visited) else {
                return false;
            };
            free = unsafe { table.read_volatile() };
        }
        if free != 0 || !self.validate_tree(root, 4, &mut visited) {
            return false;
        }
        let before = self.free_count;
        self.reclaim_pending = false;
        self.detach_empty(root, 4);
        self.free_count > before
    }
    fn visit_table(&self, physical: u64, visited: &mut [u64]) -> Option<*mut u64> {
        let index = self.index(physical).ok()?;
        let bit = 1 << (index % 64);
        let word = &mut visited[index / 64];
        if *word & bit != 0 {
            return None;
        }
        *word |= bit;
        Some(unsafe { self.virtual_base.add(index * 4096).cast() })
    }
    fn validate_tree(&self, physical: u64, level: u8, visited: &mut [u64]) -> bool {
        let Some(table) = self.visit_table(physical, visited) else {
            return false;
        };
        if level == 1 {
            return true;
        }
        (0..if level == 4 { 256 } else { 512 }).all(|index| {
            let value = unsafe { table.add(index).read_volatile() };
            value & P == 0
                || (value & (1 << 7) == 0 && self.validate_tree(value & MASK, level - 1, visited))
        })
    }
    fn detach_empty(&mut self, physical: u64, level: u8) -> bool {
        let table = self.table(physical).expect("validated private table");
        if level == 1 {
            return (0..512).all(|index| unsafe { table.add(index).read_volatile() } & P == 0);
        }
        let mut empty = true;
        for index in 0..if level == 4 { 256 } else { 512 } {
            let entry = unsafe { table.add(index) };
            let value = unsafe { entry.read_volatile() };
            if value & P == 0 {
                continue;
            }
            let child = value & MASK;
            if self.detach_empty(child, level - 1) {
                // The previous CPU restores kernel CR3 before clearing its
                // resident bit. User leaves are non-global and PCID is off,
                // so no stale translation or cached walk can reach this page.
                let detached = self.table(child).expect("validated private child table");
                unsafe {
                    entry.write_volatile(0);
                    detached.write_volatile(self.free);
                }
                self.free = child;
                self.free_count += 1;
            } else {
                empty = false;
            }
        }
        empty
    }
}
pub struct AddressSpace<'a> {
    arena: TableArena<'a>,
    root: u64,
    id: SpaceId,
    ram_bytes: u64,
    epoch: core::sync::atomic::AtomicU64,
    residents: core::sync::atomic::AtomicU64,
}
impl<'a> AddressSpace<'a> {
    /// # Safety
    /// Kernel upper entries refer to immutable pinned supervisor tables
    /// outside the arena. This arena is exclusively owned and remains pinned
    /// while contexts can run.
    pub unsafe fn new(
        mut arena: TableArena<'a>,
        kernel: &KernelMappings,
        id: SpaceId,
    ) -> Result<Self, Error> {
        if id.id == 0 || id.generation == 0 {
            return Err(Error::Identity);
        }
        let root = arena.allocate()?;
        unsafe {
            core::ptr::copy_nonoverlapping(kernel.upper.as_ptr(), arena.table(root)?.add(256), 256);
        }
        Ok(Self {
            arena,
            root,
            id,
            ram_bytes: kernel.ram_bytes,
            epoch: core::sync::atomic::AtomicU64::new(1),
            residents: core::sync::atomic::AtomicU64::new(0),
        })
    }
    pub fn id(&self) -> SpaceId {
        self.id
    }
    pub fn root_phys(&self) -> u64 {
        self.root
    }
    pub fn resident_cpus(&self) -> u64 {
        self.residents.load(core::sync::atomic::Ordering::Acquire)
    }
    pub fn epoch(&self) -> u64 {
        self.epoch.load(core::sync::atomic::Ordering::Acquire)
    }
    fn address(address: u64) -> Result<(), Error> {
        if !(PAGE_BYTES..0x0000_8000_0000_0000).contains(&address)
            || !address.is_multiple_of(PAGE_BYTES)
        {
            return Err(Error::Address);
        }
        Ok(())
    }
    fn leaf(&self, address: u64) -> Option<*mut u64> {
        let mut table = self.arena.table(self.root).ok()?;
        for shift in [39, 30, 21] {
            let value = unsafe {
                table
                    .add(((address >> shift) & 511) as usize)
                    .read_volatile()
            };
            if value & P == 0 || value & (1 << 7) != 0 {
                return None;
            }
            table = self.arena.table(value & MASK).ok()?;
        }
        Some(unsafe { table.add(((address >> 12) & 511) as usize) })
    }
    #[inline(always)]
    fn validate_mapping(
        &self,
        address: u64,
        physical: u64,
        permissions: UserPermissions,
    ) -> Result<(), Error> {
        Self::address(address)?;
        if !physical.is_multiple_of(PAGE_BYTES) || physical >= self.ram_bytes {
            return Err(Error::Address);
        }
        if permissions.writable && permissions.executable {
            return Err(Error::Permissions);
        }
        #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
        if permissions.executable || permissions.writable {
            unsafe extern "C" {
                fn x86_runtime_code_sealed(physical: u64) -> bool;
            }
            let sealed = unsafe { x86_runtime_code_sealed(physical) };
            if permissions.executable && !sealed || permissions.writable && sealed {
                return Err(Error::Permissions);
            }
        }
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        Ok(())
    }
    pub fn map(
        &mut self,
        address: u64,
        physical: u64,
        permissions: UserPermissions,
    ) -> Result<(), Error> {
        // Preserve the single-page validation/error boundary before locking.
        self.validate_mapping(address, physical, permissions)?;
        self.map_pages(core::iter::once((address, physical, permissions)))
    }
    /// Publish trusted kernel metadata while this root has no resident CPU.
    /// The iterator must not run services, allocate, seal code, or acquire locks.
    /// Every successful prefix remains owned by this space on a later error.
    pub fn map_pages(
        &mut self,
        pages: impl IntoIterator<Item = (u64, u64, UserPermissions)>,
    ) -> Result<(), Error> {
        let mut pages = pages.into_iter();
        let Some(first) = pages.next() else {
            return Ok(());
        };
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        self.validate_mapping(first.0, first.1, first.2)?;
        let aliases = MappingBatch::acquire()?;
        let mut publication = MappingPublication {
            epoch: &self.epoch,
            published: 0,
            aliases,
        };
        let mut cached_leaf: Option<(u64, *mut u64)> = None;
        for (address, physical, permissions) in core::iter::once(first).chain(pages) {
            self.validate_mapping(address, physical, permissions)?;
            let region = address >> 21;
            let table = if let Some((cached_region, table)) = cached_leaf
                && cached_region == region
            {
                table
            } else {
                let table = self.arena.mapping_table(self.root, address)?;
                cached_leaf = Some((region, table));
                table
            };
            let leaf = unsafe { table.add(((address >> 12) & 511) as usize) };
            if unsafe { leaf.read_volatile() } & P != 0 {
                return Err(Error::Conflict);
            }
            let value = physical
                | P
                | U
                | if permissions.writable { W } else { 0 }
                | if permissions.executable { 0 } else { NX };
            if let Err(error) = publication.aliases.change(physical, None, Some(permissions)) {
                // The new path may now contain an empty table even without an unmap.
                self.arena.reclaim_pending = true;
                return Err(error);
            }
            unsafe { leaf.write_volatile(value) };
            publication.published += 1;
        }
        Ok(())
    }
    /// Publish a fixed contiguous run within one leaf table. Unlike map_pages,
    /// this accepts no caller iterator: validation cannot invoke other services
    /// or unwind between deferred alias updates and leaf publication.
    pub fn map_table_run(
        &mut self,
        address: u64,
        physical: u64,
        permissions: UserPermissions,
        pages: usize,
    ) -> Result<(), Error> {
        if pages == 0 {
            return Ok(());
        }
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        if pages > 512 || address.checked_add((pages as u64 - 1) * PAGE_BYTES)
            .is_none_or(|last| last >> 21 != address >> 21)
        {
            return Err(Error::Address);
        }
        self.validate_mapping(address, physical, permissions)?;
        let aliases = MappingBatch::acquire()?;
        let mut publication = MappingPublication { epoch: &self.epoch, published: 0, aliases };
        let table = self.arena.mapping_table(self.root, address)?;
        let leaf = unsafe { table.add(((address >> 12) & 511) as usize) };
        let mut valid = 0;
        let mut error = None;
        for index in 0..pages {
            let offset = index as u64 * PAGE_BYTES;
            let result = physical.checked_add(offset).ok_or(Error::Address)
                .and_then(|page| self.validate_mapping(address + offset, page, permissions));
            if let Err(failure) = result {
                error = Some(failure);
                break;
            }
            if unsafe { leaf.add(index).read_volatile() } & P != 0 {
                error = Some(Error::Conflict);
                break;
            }
            valid += 1;
        }
        let changed = publication.aliases.change_run(physical, None, Some(permissions), valid);
        for index in 0..changed {
            let value = physical + index as u64 * PAGE_BYTES | P | U
                | if permissions.writable { W } else { 0 }
                | if permissions.executable { 0 } else { NX };
            unsafe { leaf.add(index).write_volatile(value) };
        }
        publication.published = changed as u64;
        if changed != valid {
            self.arena.reclaim_pending |= changed == 0;
            return Err(Error::Permissions);
        }
        error.map_or(Ok(()), Err)
    }
    pub fn translate(&self, address: u64) -> Option<Translation> {
        if address >= 0x0000_8000_0000_0000 {
            return None;
        }
        let value = unsafe { self.leaf(address)?.read_volatile() };
        if value & P == 0 {
            return None;
        }
        Some(Translation {
            physical: (value & MASK) | (address & 4095),
            permissions: UserPermissions {
                writable: value & W != 0,
                executable: value & NX == 0,
            },
        })
    }
    pub fn unmap(&mut self, address: u64) -> Result<RetiredMapping, Error> {
        Self::address(address)?;
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        let leaf = self.leaf(address).ok_or(Error::Address)?;
        let old = unsafe { leaf.read_volatile() };
        if old & P == 0 {
            return Err(Error::Address);
        }
        mapping_change(
            old & MASK,
            Some(UserPermissions {
                writable: old & W != 0,
                executable: old & NX == 0,
            }),
            None,
        )?;
        unsafe {
            leaf.write_volatile(0);
        }
        self.arena.reclaim_pending = true;
        let epoch = self
            .epoch
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel)
            + 1;
        Ok(RetiredMapping {
            physical: old & MASK,
            space: self.id,
            epoch,
            virtual_address: address,
        })
    }
    /// Unmap one page only if it is mapped, walking the table once. Revocation
    /// used translate() followed by unmap(), paying two full walks per page.
    /// Presence is decided before any validation so an absent page stays a
    /// no-op exactly as the translate-then-unmap pair behaved.
    pub fn unmap_present(&mut self, address: u64) -> Result<bool, Error> {
        if address >= 0x0000_8000_0000_0000 {
            return Ok(false);
        }
        let Some(leaf) = self.leaf(address) else {
            return Ok(false);
        };
        let old = unsafe { leaf.read_volatile() };
        if old & P == 0 {
            return Ok(false);
        }
        Self::address(address)?;
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        mapping_change(
            old & MASK,
            Some(UserPermissions {
                writable: old & W != 0,
                executable: old & NX == 0,
            }),
            None,
        )?;
        unsafe {
            leaf.write_volatile(0);
        }
        self.arena.reclaim_pending = true;
        self.epoch
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        Ok(true)
    }
    /// Revoke up to one leaf table under one alias lease. Absent entries are
    /// skipped. If an alias check fails, publish only the successful prefix;
    /// the caller must retain all backing until the whole request succeeds.
    pub fn unmap_table_run(&mut self, address: u64, pages: usize) -> Result<(), Error> {
        if pages == 0 {
            return Ok(());
        }
        Self::address(address)?;
        let leaf_index = ((address / PAGE_BYTES) & 511) as usize;
        if pages > 512 - leaf_index {
            return Err(Error::Address);
        }
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        let Some(leaf) = self.leaf(address) else {
            return Ok(());
        };
        let Some((mut index, mut value)) = (0..pages).find_map(|index| {
            let value = unsafe { leaf.add(index).read_volatile() };
            (value & P != 0).then_some((index, value))
        }) else {
            return Ok(());
        };
        let mut publication = MappingPublication {
            epoch: &self.epoch,
            published: 0,
            aliases: MappingBatch::acquire()?,
        };
        while index < pages {
            if value & P == 0 {
                index += 1;
                if index < pages {
                    value = unsafe { leaf.add(index).read_volatile() };
                }
                continue;
            }
            let physical = value & MASK;
            let flags = value & (P | W | NX);
            let old = UserPermissions {
                writable: flags & W != 0,
                executable: flags & NX == 0,
            };
            let mut end = index + 1;
            // Only physical adjacency and the alias-accounting flags matter.
            // Keep the last decoded entry for the start of the next run.
            while end < pages {
                value = unsafe { leaf.add(end).read_volatile() };
                if value & (P | W | NX) != flags
                    || value & MASK != physical + (end - index) as u64 * PAGE_BYTES
                {
                    break;
                }
                end += 1;
            }
            let changed = publication.aliases.change_run(physical, Some(old), None, end - index);
            for at in index..index + changed {
                unsafe { leaf.add(at).write_volatile(0) };
            }
            // The root is quiescent and the gate still excludes physical
            // permission changes until all cleared entries and the epoch publish.
            publication.published += changed as u64;
            if changed != end - index {
                return Err(Error::Permissions);
            }
            index = end;
        }
        self.arena.reclaim_pending = true;
        Ok(())
    }
    pub fn protect(&mut self, address: u64, permissions: UserPermissions) -> Result<(), Error> {
        Self::address(address)?;
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        if permissions.writable && permissions.executable {
            return Err(Error::Permissions);
        }
        let leaf = self.leaf(address).ok_or(Error::Address)?;
        let old = unsafe { leaf.read_volatile() };
        if old & P == 0 {
            return Err(Error::Address);
        }
        #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
        if permissions.executable || permissions.writable {
            unsafe extern "C" {
                fn x86_runtime_code_sealed(physical: u64) -> bool;
            }
            let sealed = unsafe { x86_runtime_code_sealed(old & MASK) };
            if permissions.executable && !sealed || permissions.writable && sealed {
                return Err(Error::Permissions);
            }
        }
        mapping_change(
            old & MASK,
            Some(UserPermissions {
                writable: old & W != 0,
                executable: old & NX == 0,
            }),
            Some(permissions),
        )?;
        unsafe {
            leaf.write_volatile(
                (old & MASK)
                    | P
                    | U
                    | if permissions.writable { W } else { 0 }
                    | if permissions.executable { 0 } else { NX },
            );
        }
        self.epoch
            .fetch_add(1, core::sync::atomic::Ordering::Release);
        Ok(())
    }
    #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
    pub(crate) fn enter_cpu(&self, slot: usize) -> Result<(), Error> {
        if slot >= 4 {
            return Err(Error::Address);
        }
        self.residents
            .fetch_or(1 << slot, core::sync::atomic::Ordering::AcqRel);
        Ok(())
    }
    #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
    // Resume restores kernel CR3 before publishing departure. Empty table
    // reclamation relies on that invalidation preceding a zero resident mask.
    pub(crate) fn leave_cpu(&self, slot: usize) {
        self.residents
            .fetch_and(!(1 << slot), core::sync::atomic::Ordering::Release);
    }
}

// The guard is neither Clone nor Send: the runtime lease belongs to this CPU.
struct MappingBatch {
    owner: u64,
    _same_cpu: PhantomData<*mut ()>,
}
impl MappingBatch {
    fn acquire() -> Result<Self, Error> {
        #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
        let owner = {
            unsafe extern "C" {
                fn x86_runtime_mapping_batch_begin() -> u64;
            }
            let owner = unsafe { x86_runtime_mapping_batch_begin() };
            if owner == 0 {
                return Err(Error::Active);
            }
            owner
        };
        #[cfg(not(all(feature = "runtime", target_arch = "x86_64", target_os = "none")))]
        let owner = 0;
        Ok(Self { owner, _same_cpu: PhantomData })
    }
    fn change_run(&self, physical: u64, old: Option<UserPermissions>,
                  new: Option<UserPermissions>, pages: usize) -> usize {
        if pages == 0 { return 0; }
        #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
        {
            unsafe extern "C" {
                fn x86_runtime_mapping_batch_run(owner: u64, physical: u64, pages: u64, old: u64, new: u64) -> u64;
            }
            let flags = |p: Option<UserPermissions>| {
                p.map_or(0, |p| 1 | u64::from(p.writable) << 1 | u64::from(p.executable) << 2)
            };
            let changed = unsafe { x86_runtime_mapping_batch_run(
                self.owner, physical, pages as u64, flags(old), flags(new)) } as usize;
            assert!(changed <= pages, "invalid alias prefix; retain backing");
            changed
        }
        #[cfg(not(all(feature = "runtime", target_arch = "x86_64", target_os = "none")))]
        { let _ = (physical, old, new); pages }
    }
    #[inline(always)]
    fn change(
        &self,
        physical: u64,
        old: Option<UserPermissions>,
        new: Option<UserPermissions>,
    ) -> Result<(), Error> {
        #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
        {
            unsafe extern "C" {
                fn x86_runtime_mapping_batch_change(owner: u64, physical: u64, old: u64, new: u64) -> bool;
            }
            let flags = |p: Option<UserPermissions>| {
                p.map_or(0, |p| 1 | u64::from(p.writable) << 1 | u64::from(p.executable) << 2)
            };
            if !unsafe { x86_runtime_mapping_batch_change(self.owner, physical, flags(old), flags(new)) } {
                return Err(Error::Permissions);
            }
        }
        #[cfg(not(all(feature = "runtime", target_arch = "x86_64", target_os = "none")))]
        let _ = (self.owner, physical, old, new);
        Ok(())
    }
}
impl Drop for MappingBatch {
    fn drop(&mut self) {
        #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
        {
            unsafe extern "C" {
                fn x86_runtime_mapping_batch_end(owner: u64) -> bool;
            }
            assert!(unsafe { x86_runtime_mapping_batch_end(self.owner) }, "mapping batch lost owner; retain backing");
        }
    }
}
struct MappingPublication<'a> {
    epoch: &'a core::sync::atomic::AtomicU64,
    published: u64,
    aliases: MappingBatch,
}
impl Drop for MappingPublication<'_> {
    fn drop(&mut self) {
        if self.published != 0 {
            // Exclusive owner, same wrapped final epoch as N one-page changes.
            // Also publish the successful prefix on an error or unwind.
            self.epoch.fetch_add(self.published, core::sync::atomic::Ordering::Release);
        }
    }
}
fn mapping_change(
    physical: u64,
    old: Option<UserPermissions>,
    new: Option<UserPermissions>,
) -> Result<(), Error> {
    MappingBatch::acquire()?.change(physical, old, new)
}
impl Drop for AddressSpace<'_> {
    fn drop(&mut self) {
        assert_eq!(self.resident_cpus(), 0, "dropping an entered address space");
        let aliases = MappingBatch::acquire().expect("retiring mappings requires alias custody");
        fn retire(space: &AddressSpace<'_>, aliases: &MappingBatch, physical: u64, level: u8, entries: usize) {
            let table = space.arena.table(physical).expect("invalid retiring table; retain backing");
            let mut first = 0;
            if level == 1 {
                // Batch only the first present contiguous run. Fragmented tails
                // keep the scalar walk, without a second lookahead per page.
                while first < entries {
                    let value = unsafe { table.add(first).read_volatile() };
                    if value & P == 0 {
                        first += 1;
                        continue;
                    }
                    let physical = value & MASK;
                    assert!(physical < space.ram_bytes, "invalid retiring frame; retain backing");
                    let mut end = first + 1;
                    while end < entries {
                        let next = unsafe { table.add(end).read_volatile() };
                        if next & (P | W | NX) != value & (P | W | NX)
                            || next & MASK != physical + (end - first) as u64 * PAGE_BYTES
                            || next & MASK >= space.ram_bytes
                        {
                            break;
                        }
                        end += 1;
                    }
                    if end - first > 1 {
                        let changed = aliases.change_run(physical,
                            Some(UserPermissions { writable: value & W != 0, executable: value & NX == 0 }),
                            None, end - first);
                        assert_eq!(changed, end - first, "retiring alias count failed; retain backing");
                        first = end;
                    }
                    break;
                }
            }
            for index in first..entries {
                let value = unsafe { table.add(index).read_volatile() };
                if value & P == 0 {
                    continue;
                }
                if level == 1 {
                    assert!(value & MASK < space.ram_bytes, "invalid retiring frame; retain backing");
                    aliases.change(
                        value & MASK,
                        Some(UserPermissions { writable: value & W != 0, executable: value & NX == 0 }),
                        None,
                    ).expect("retiring alias count failed; retain backing");
                } else {
                    assert_eq!(value & (1 << 7), 0, "unexpected large user leaf; retain backing");
                    retire(space, aliases, value & MASK, level - 1, 512);
                }
            }
        }
        retire(self, &aliases, self.root, 4, 256);
    }
}
