//! Per-process desired pages and the owned CPU address-space publication boundary.
//! x86 staging entries are metadata; only arch::space builds real four-level PTEs.
use cyxia_posix::Errno;

#[cfg(target_arch = "aarch64")]
#[repr(C, align(4096))]
pub struct PageTable(pub [u64; 512]);
#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
pub struct PageTable {
    // Aligned physical frames leave the low three bits for desired protection.
    // These indexes describe private staging metadata, never live hardware PTEs.
    pages: [u64; 512],
    present: [u64; 8],
    executable: [u64; 8],
    dirty: [u64; 8],
}
#[cfg(target_arch = "x86_64")]
const _: () = {
    assert!(core::mem::size_of::<PageTable>() == 8192);
    assert!(core::mem::align_of::<PageTable>() == 4096);
};
impl PageTable {
    pub const fn empty() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            Self([0; 512])
        }
        #[cfg(target_arch = "x86_64")]
        {
            Self { pages: [0; 512], present: [0; 8], executable: [0; 8], dirty: [0; 8] }
        }
    }
    pub fn clear(&mut self) {
        #[cfg(target_arch = "aarch64")]
        self.0.fill(0);
        #[cfg(target_arch = "x86_64")]
        {
            for (dirty, present) in self.dirty.iter_mut().zip(self.present) {
                *dirty |= present;
            }
            self.pages.fill(0);
            self.present.fill(0);
            self.executable.fill(0);
        }
    }
    pub fn remove(&mut self, index: usize) {
        #[cfg(target_arch = "aarch64")]
        {
            self.0[index] = 0;
        }
        #[cfg(target_arch = "x86_64")]
        {
            // The first access retains the original bounds-panic boundary.
            self.pages[index] = 0;
            let bit = 1u64 << (index % 64);
            self.present[index / 64] &= !bit;
            self.executable[index / 64] &= !bit;
            self.dirty[index / 64] |= bit;
        }
    }
    pub fn set(&mut self, index: usize, physical: u64, protection: u8) -> Result<(), Errno> {
        if index >= 512 || physical % 4096 != 0 || protection & !7 != 0 || protection & 6 == 6 {
            return Err(Errno::Inval);
        }
        if protection == 0 {
            self.remove(index);
            return Ok(());
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.0[index] = cyxia_arch_aarch64::mmu::encode_user_leaf(
                cyxia_contracts::PhysAddr(physical),
                protection & 2 != 0,
                protection & 4 != 0,
            )
            .map_err(|_| Errno::Inval)?;
        }
        #[cfg(target_arch = "x86_64")]
        {
            // No fallible operation follows validation. Overwrites update both
            // indexes, including RX -> RO/RW, before metadata can be published.
            self.pages[index] = physical | u64::from(protection);
            let bit = 1u64 << (index % 64);
            self.present[index / 64] |= bit;
            self.dirty[index / 64] |= bit;
            if protection & 4 != 0 {
                self.executable[index / 64] |= bit;
            } else {
                self.executable[index / 64] &= !bit;
            }
        }
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    fn indices(bitmap: &[u64; 8]) -> impl Iterator<Item = usize> + '_ {
        bitmap.iter().copied().enumerate().flat_map(|(word, mut bits)| {
            core::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let index = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                Some(index)
            })
        })
    }
    #[cfg(target_arch = "x86_64")]
    fn executable_runs(&self) -> impl Iterator<Item = (u64, usize)> + '_ {
        self.executable_runs_in(&self.executable)
    }
    #[cfg(target_arch = "x86_64")]
    fn executable_runs_in<'a>(
        &'a self, bitmap: &'a [u64; 8],
    ) -> impl Iterator<Item = (u64, usize)> + 'a {
        let mut executable = Self::indices(bitmap).peekable();
        core::iter::from_fn(move || {
            let start = executable.next()?;
            let physical = self.pages[start] & !7;
            let mut previous = physical;
            let mut end = start + 1;
            // Preserve ascending order and the original adjacent virtual AND
            // consecutive physical boundary. Never cross this staging table.
            while let Some(&next) = executable.peek() {
                let next_physical = self.pages[next] & !7;
                if next != end || previous.checked_add(4096) != Some(next_physical) {
                    break;
                }
                let _ = executable.next();
                previous = next_physical;
                end += 1;
            }
            Some((physical, (end - start) * 4096))
        })
    }
    #[cfg(target_arch = "x86_64")]
    fn contiguous_mapping(&self) -> Option<(usize, u64, u8, usize)> {
        let mut indices = Self::indices(&self.present);
        let start = indices.next()?;
        let first = self.pages[start];
        let mut previous = first & !7;
        let mut end = start + 1;
        for index in indices {
            let page = self.pages[index];
            if index != end || page & 7 != first & 7
                || previous.checked_add(4096) != Some(page & !7)
            {
                return None;
            }
            previous = page & !7;
            end += 1;
        }
        Some((start, first & !7, (first & 7) as u8, end - start))
    }
    #[cfg(target_arch = "x86_64")]
    pub fn publish(&self, space: &mut ProcessSpace, base: u64) -> Result<(), Errno> {
        if self.present.iter().all(|&word| word == 0) {
            return Ok(());
        }
        // Sealing acquires ALIAS_GATE and can fence real CPUs. Finish it before
        // the mapping batch takes that gate; failed seals retain their phase.
        for (physical, bytes) in self.executable_runs() {
            crate::process_arch::publish_code(crate::HIGH + physical, bytes)?;
        }
        if let Some((start, physical, protection, pages)) = self.contiguous_mapping()
            && let Some(address) = base.checked_add(start as u64 * 4096)
            && address.checked_add((pages as u64 - 1) * 4096)
                .is_some_and(|last| last >> 21 == address >> 21)
        {
            return space.map_table_run(address, physical, protection, pages);
        }
        space.map_pages(Self::indices(&self.present).map(|index| {
            let page = self.pages[index];
            (base + index as u64 * 4096, page & !7, (page & 7) as u8)
        }))
    }
    /// Reconcile only changed staging entries while every user CPU is stopped.
    /// `fresh` is true for every table in a newly created root, including tables
    /// whose dirty bits were cleared by a previous root. Failed syncs retain
    /// their dirty set and owned successful prefix; the caller must not enter.
    #[cfg(target_arch = "x86_64")]
    pub fn synchronize(&mut self, space: &mut ProcessSpace, base: u64, fresh: bool) -> Result<(), Errno> {
        if fresh {
            self.publish(space, base)?;
            self.dirty.fill(0);
            return Ok(());
        }
        if self.dirty.iter().all(|&bits| bits == 0) {
            return Ok(());
        }
        space.quiescent()?;
        let mut changed = self.dirty;
        for index in Self::indices(&self.dirty) {
            let address = base.checked_add(index as u64 * 4096).ok_or(Errno::Inval)?;
            let desired = self.pages[index];
            let old = space.root()?.translate(address);
            let matches = match old {
                Some(old) => desired & 7 != 0 && old.physical == (desired & !7)
                    && old.permissions.writable == (desired & 2 != 0)
                    && old.permissions.executable == (desired & 4 != 0),
                None => desired & 7 == 0,
            };
            if matches {
                changed[index / 64] &= !(1u64 << (index % 64));
            } else if old.is_some() {
                space.revoke_page(address)?;
            }
        }
        // Remove old aliases before sealing new executable backing. The
        // original W^X/phase transaction and alias gate remain authoritative.
        // Seal consecutive changed executable backing in one range. Each seal
        // acquires the alias gate and can fence every CPU, so a per-page call
        // turned one JIT/module load into one full shootdown per page. Only the
        // executable subset is sealable; `changed` also carries RO/RW edits.
        let sealable = core::array::from_fn::<_, 8, _>(|word| changed[word] & self.executable[word]);
        for (physical, bytes) in self.executable_runs_in(&sealable) {
            crate::process_arch::publish_code(crate::HIGH + physical, bytes)?;
        }
        space.map_pages(Self::indices(&changed).filter_map(|index| {
            let page = self.pages[index];
            (page & 7 != 0).then_some((base + index as u64 * 4096, page & !7, (page & 7) as u8))
        }))?;
        self.dirty.fill(0);
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
pub const TABLE_PAGES_PER_PROCESS: usize = 128;
#[cfg(target_arch = "x86_64")]
pub const TABLE_BYTES_PER_PROCESS: u64 = (TABLE_PAGES_PER_PROCESS * 4096) as u64;
#[cfg(target_arch = "x86_64")]
pub const TABLE_POOL_BYTES: u64 =
    TABLE_BYTES_PER_PROCESS * cyxia_posix::usermem::MAX_PROCESSES as u64;
#[cfg(target_arch = "x86_64")]
static TABLE_POOL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static TABLE_SLOTS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
pub fn process_slots() -> usize {
    TABLE_SLOTS.load(core::sync::atomic::Ordering::Acquire)
}
#[cfg(target_arch = "x86_64")]
pub fn init_pc(range: cyxia_contracts::MemoryRegion) -> Result<(), Errno> {
    use core::sync::atomic::Ordering;
    if TABLE_POOL.load(Ordering::Acquire) != 0 {
        return Err(Errno::Busy);
    }
    if range.len == 0 || range.len > TABLE_POOL_BYTES || range.len % TABLE_BYTES_PER_PROCESS != 0 {
        return Err(Errno::Inval);
    }
    TABLE_SLOTS.store((range.len / TABLE_BYTES_PER_PROCESS) as usize, Ordering::Release);
    TABLE_POOL.store(range.start.0, Ordering::Release);
    Ok(())
}
#[cfg(target_arch = "x86_64")]
pub struct ProcessSpace {
    current: Option<cyxia_arch_x86_64::space::AddressSpace<'static>>,
    slot: usize,
    pid: u32,
    retire_ns: u64,
    revoke_ns: u64,
}
// SAFETY: this owner exclusively reserves its table frames in the globally
// identical HIGH+PA direct map. Transfers occur only while no resume owns the
// space; a published mailbox pins it until the AP has returned and cleared
// residency. This permits ownership transfer, not concurrent table access.
#[cfg(target_arch = "x86_64")]
unsafe impl Send for ProcessSpace {}
#[cfg(target_arch = "x86_64")]
impl ProcessSpace {
    pub const fn new() -> Self {
        Self {
            current: None,
            slot: usize::MAX,
            pid: 0,
            retire_ns: 0,
            revoke_ns: 0,
        }
    }
    pub fn bind(&mut self, slot: usize, pid: u32) {
        assert!(self.current.is_none());
        self.slot = slot;
        self.pid = pid;
        self.retire_ns = 0;
        self.revoke_ns = 0;
    }
    /// Return whether a new root was created. A stopped root keeps its PTEs and
    /// alias ownership across dispatches; CPU departure is not destruction.
    pub fn begin(&mut self) -> Result<bool, Errno> {
        use cyxia_arch_x86_64::space::{AddressSpace, SpaceId, TableArena};
        if self.current.is_some() {
            self.quiescent()?;
            return Ok(false);
        }
        let pool = TABLE_POOL.load(core::sync::atomic::Ordering::Acquire);
        if pool == 0 || self.slot >= process_slots() || self.pid == 0 {
            crate::process_arch::trace_entry_error("begin.owner", self.pid, 0, format_args!(
                "error={:?} slot={} pool={pool:#x}", Errno::Nodev, self.slot,
            ));
            return Err(Errno::Nodev);
        }
        let physical = pool + self.slot as u64 * TABLE_BYTES_PER_PROCESS;
        let arena = unsafe {
            TableArena::from_raw(
                (crate::HIGH + physical) as *mut u8,
                physical,
                TABLE_PAGES_PER_PROCESS,
            )
        }
        .map_err(|error| {
            crate::process_arch::trace_entry_error("begin.arena", self.pid, 0, format_args!(
                "error={error:?} va={:#x} pa={physical:#x} bytes={}",
                crate::HIGH + physical, TABLE_PAGES_PER_PROCESS * 4096,
            ));
            Errno::Nomem
        })?;
        self.current = Some(
            unsafe {
                AddressSpace::new(
                    arena,
                    crate::machine::runtime::kernel_mappings(),
                    SpaceId {
                        id: u64::from(self.pid),
                        generation: 1,
                    },
                )
            }
            .map_err(|error| {
                crate::process_arch::trace_entry_error("begin.root", self.pid, 0, format_args!(
                    "error={error:?} va={:#x} pa={physical:#x} bytes={}",
                    crate::HIGH + physical, TABLE_PAGES_PER_PROCESS * 4096,
                ));
                Errno::Io
            })?,
        );
        Ok(true)
    }
    pub fn map(
        &mut self,
        virtual_address: u64,
        physical: u64,
        protection: u8,
    ) -> Result<(), Errno> {
        if protection & 4 != 0 {
            crate::process_arch::publish_code(crate::HIGH + physical, 4096)?;
        }
        let permissions = cyxia_arch_x86_64::space::UserPermissions {
            writable: protection & 2 != 0,
            executable: protection & 4 != 0,
        };
        let pid = self.pid;
        self.current.as_mut().ok_or_else(|| {
            crate::process_arch::trace_entry_error("map.owner", pid, 0, format_args!(
                "error={:?} va={virtual_address:#x} pa={physical:#x} bytes=4096", Errno::Nodev,
            ));
            Errno::Nodev
        })?.map(virtual_address, physical, permissions).map_err(|error| {
            crate::process_arch::trace_entry_error("map", pid, 0, format_args!(
                "error={error:?} va={virtual_address:#x} pa={physical:#x} bytes=4096",
            ));
            Errno::Io
        })
    }
    /// Trusted staged metadata only; executable pages must be sealed first.
    pub fn map_table_run(&mut self, address: u64, physical: u64, protection: u8, pages: usize) -> Result<(), Errno> {
        let pid = self.pid;
        self.current.as_mut().ok_or(Errno::Nodev)?
            .map_table_run(address, physical, cyxia_arch_x86_64::space::UserPermissions {
                writable: protection & 2 != 0,
                executable: protection & 4 != 0,
            }, pages).map_err(|error| {
                crate::process_arch::trace_entry_error("map_table_run", pid, 0,
                    format_args!("error={error:?} va={address:#x} pa={physical:#x} pages={pages}"));
                Errno::Io
            })
    }
    /// Trusted staged metadata only; executable pages must be sealed first.
    pub fn map_pages(&mut self, pages: impl IntoIterator<Item = (u64, u64, u8)>) -> Result<(), Errno> {
        let pid = self.pid;
        self.current.as_mut().ok_or_else(|| {
            crate::process_arch::trace_entry_error("map_pages.owner", pid, 0, format_args!(
                "error={:?}", Errno::Nodev,
            ));
            Errno::Nodev
        })?.map_pages(pages.into_iter().map(|(address, physical, protection)| {
            (address, physical, cyxia_arch_x86_64::space::UserPermissions {
                writable: protection & 2 != 0,
                executable: protection & 4 != 0,
            })
        })).map_err(|error| {
            crate::process_arch::trace_entry_error("map_pages", pid, 0, format_args!(
                "error={error:?}",
            ));
            Errno::Io
        })
    }
    pub fn root(&self) -> Result<&cyxia_arch_x86_64::space::AddressSpace<'static>, Errno> {
        self.current.as_ref().ok_or(Errno::Nodev)
    }
    pub fn quiescent(&self) -> Result<(), Errno> {
        if self.root()?.resident_cpus() != 0 {
            return Err(Errno::Busy);
        }
        Ok(())
    }
    /// Revoke real PTEs and alias references BEFORE backing is cleared/freed.
    /// All APs have returned to kernel CR3; user mappings are non-global and
    /// PCID is disabled, so no stopped CPU retains a usable user translation.
    pub fn revoke_range(&mut self, address: u64, pages: usize) -> Result<(), Errno> {
        let Some(space) = self.current.as_mut() else {
            return Ok(());
        };
        if space.resident_cpus() != 0 {
            return Err(Errno::Busy);
        }
        if !address.is_multiple_of(4096) || address < 4096 || address >= 0x8000_0000_0000
            || pages.checked_mul(4096).and_then(|bytes| address.checked_add(bytes as u64))
                .is_none_or(|end| end > 0x8000_0000_0000)
        {
            return Err(Errno::Inval);
        }
        let started = crate::process_arch::now_ns();
        let result = (|| {
            let mut address = address;
            let mut remaining = pages;
            while remaining != 0 {
                let leaf_pages = 512 - ((address / 4096) & 511) as usize;
                let count = remaining.min(leaf_pages);
                space.unmap_table_run(address, count).map_err(|_| Errno::Io)?;
                address += count as u64 * 4096;
                remaining -= count;
            }
            Ok(())
        })();
        self.revoke_ns = self.revoke_ns.saturating_add(
            crate::process_arch::now_ns().saturating_sub(started),
        );
        result
    }
    // Called by incremental preparation (already timed in space_prepare_ns),
    // or the separately timed backing-release boundary above. Never count a
    // revocation in both wall-time buckets.
    fn revoke_page(&mut self, address: u64) -> Result<(), Errno> {
        let space = self.current.as_mut().ok_or(Errno::Nodev)?;
        space.unmap_present(address).map_err(|_| Errno::Io)?;
        Ok(())
    }
    pub fn revoked_ns(&self) -> u64 {
        self.revoke_ns
    }
    /// The caller already returned from resume: kernel CR3 is live, no PCID or
    /// global user mappings exist, and no other CPU may enter this process.
    pub fn retire(&mut self) {
        if self.current.is_none() {
            return;
        }
        let started = crate::process_arch::now_ns();
        drop(self.current.take());
        self.retire_ns = self.retire_ns.saturating_add(
            crate::process_arch::now_ns().saturating_sub(started),
        );
    }
    /// Read only after the owned job has returned; no live AP is inspected.
    pub fn retired_ns(&self) -> u64 {
        self.retire_ns
    }
}
