//! Bounded memfd backing metadata. Hardware pages, AI admission and TLB ordering
//! belong to the kernel. An OFD (including SCM in-flight references) and each
//! mapping independently keep a backing alive.
use crate::Errno;

pub const PAGE_SIZE: usize = 4096;
pub const PAGES: usize = 4096;
pub const OBJECTS: usize = 16;
pub const OBJECT_PAGES: usize = 2048;
pub const MAPPINGS: usize = 16;
pub const BASE: u64 = 0x0600_0000;
pub const END: u64 = BASE + (PAGES * PAGE_SIZE) as u64;
pub const SEAL_SEAL: u32 = 1;
pub const SEAL_SHRINK: u32 = 2;
pub const SEAL_GROW: u32 = 4;
pub const SEAL_WRITE: u32 = 8;
const NONE: u16 = u16::MAX;
const MAX_GENERATION: u64 = u64::MAX >> 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub size: usize,
    pub seals: u32,
    pub mappings: usize,
    /// Shared aliases that retain permission to become writable (VM_MAYWRITE).
    pub writable_mappings: usize,
    pub description: bool,
}
struct Object {
    generation: u64,
    live: bool,
    description: bool,
    mappings: u16,
    writable_mappings: u16,
    size: usize,
    seals: u32,
    slots: [u16; OBJECT_PAGES],
}
impl Object {
    const EMPTY: Self = Self {
        generation: 0,
        live: false,
        description: false,
        mappings: 0,
        writable_mappings: 0,
        size: 0,
        seals: 0,
        slots: [NONE; OBJECT_PAGES],
    };
}
/// Caller-owned scratch: never return a multi-kilobyte page list on an exception stack.
pub struct Batch {
    slots: [u16; OBJECT_PAGES],
    count: usize,
}
impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}
impl Batch {
    pub const fn new() -> Self {
        Self {
            slots: [NONE; OBJECT_PAGES],
            count: 0,
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.slots[..self.count].iter().map(|v| usize::from(*v))
    }
    pub fn count(&self) -> usize {
        self.count
    }
}
pub struct Backings {
    objects: [Object; OBJECTS],
    used: [bool; PAGES],
    pages: usize,
}
impl Default for Backings {
    fn default() -> Self {
        Self::new()
    }
}
impl Backings {
    pub const fn new() -> Self {
        Self {
            objects: [const { Object::EMPTY }; OBJECTS],
            used: [false; PAGES],
            pages: 0,
        }
    }
    fn index(&self, handle: u64) -> Result<usize, Errno> {
        let i = (handle & 255) as usize;
        self.objects
            .get(i)
            .filter(|o| o.live && o.generation == handle >> 8)
            .map(|_| i)
            .ok_or(Errno::Badf)
    }
    pub fn free_pages(&self) -> usize {
        PAGES - self.pages
    }
    pub fn free_objects(&self) -> usize {
        self.objects
            .iter()
            .filter(|o| !o.live && o.generation < MAX_GENERATION)
            .count()
    }
    pub fn live_objects(&self) -> usize {
        self.objects.iter().filter(|o| o.live).count()
    }
    pub fn mapping_count(&self) -> usize {
        self.objects.iter().map(|o| usize::from(o.mappings)).sum()
    }
    pub fn description_count(&self) -> usize {
        self.objects
            .iter()
            .filter(|o| o.live && o.description)
            .count()
    }
    pub fn create(&mut self, allow_sealing: bool) -> Result<u64, Errno> {
        let i = self
            .objects
            .iter()
            .position(|o| !o.live && o.generation < MAX_GENERATION)
            .ok_or(Errno::Mfile)?;
        let o = &mut self.objects[i];
        o.generation += 1;
        o.live = true;
        o.description = true;
        o.size = 0;
        o.mappings = 0;
        o.writable_mappings = 0;
        o.seals = if allow_sealing { 0 } else { SEAL_SEAL };
        Ok((o.generation << 8) | i as u64)
    }
    pub fn info(&self, handle: u64) -> Result<Info, Errno> {
        let o = &self.objects[self.index(handle)?];
        Ok(Info {
            size: o.size,
            seals: o.seals,
            mappings: usize::from(o.mappings),
            writable_mappings: usize::from(o.writable_mappings),
            description: o.description,
        })
    }
    pub fn add_seals(&mut self, handle: u64, seals: u32) -> Result<(), Errno> {
        let i = self.index(handle)?;
        if seals & !(SEAL_SEAL | SEAL_SHRINK | SEAL_GROW | SEAL_WRITE) != 0 {
            return Err(Errno::Inval);
        }
        let o = &mut self.objects[i];
        if o.seals & SEAL_SEAL != 0 {
            return Err(Errno::Perm);
        }
        if seals & SEAL_WRITE != 0 && o.writable_mappings != 0 {
            return Err(Errno::Busy);
        }
        o.seals |= seals;
        Ok(())
    }
    pub fn check_write(&self, handle: u64) -> Result<(), Errno> {
        let o = &self.objects[self.index(handle)?];
        if o.seals & SEAL_WRITE != 0 {
            return Err(Errno::Perm);
        }
        Ok(())
    }
    /// Decide future write capability before creating a shared alias. Current
    /// PROT_READ/PROT_NONE does not revoke an unsealed writable OFD's capability.
    /// A read-only alias created after sealing can never be upgraded by mprotect.
    pub fn mapping_permissions(
        &self,
        handle: u64,
        protection: u8,
        fd_writable: bool,
    ) -> Result<bool, Errno> {
        let o = &self.objects[self.index(handle)?];
        if !matches!(protection, 0 | 1 | 3) {
            return Err(Errno::Inval);
        }
        if protection & 2 != 0 {
            if !fd_writable {
                return Err(Errno::Access);
            }
            self.check_write(handle)?;
        }
        Ok(fd_writable && o.seals & SEAL_WRITE == 0)
    }
    /// Eager private snapshots are equivalent to private file pages only when
    /// the complete backing is immutable. Return all source bytes visible in
    /// the rounded mapping, including bytes after the requested byte length.
    pub fn private_snapshot_bytes(
        &self,
        handle: u64,
        offset: usize,
        length: usize,
        protection: u8,
    ) -> Result<usize, Errno> {
        let o = &self.objects[self.index(handle)?];
        let required = SEAL_WRITE | SEAL_SHRINK | SEAL_GROW;
        if length == 0
            || !offset.is_multiple_of(PAGE_SIZE)
            || !matches!(protection, 0 | 1 | 3)
            || offset.checked_add(length).is_none_or(|end| end > o.size)
            || o.seals & required != required
        {
            return Err(Errno::Inval);
        }
        Ok((o.size - offset).min(length.div_ceil(PAGE_SIZE) * PAGE_SIZE))
    }
    pub fn check_resize(&self, handle: u64, size: usize) -> Result<(), Errno> {
        let o = &self.objects[self.index(handle)?];
        if size > OBJECT_PAGES * PAGE_SIZE {
            return Err(Errno::Inval);
        }
        if size < o.size && o.seals & SEAL_SHRINK != 0 || size > o.size && o.seals & SEAL_GROW != 0
        {
            return Err(Errno::Perm);
        }
        if size < o.size && o.mappings != 0 {
            return Err(Errno::Busy);
        }
        let growth = size
            .div_ceil(PAGE_SIZE)
            .saturating_sub(o.size.div_ceil(PAGE_SIZE));
        if growth > self.free_pages() {
            return Err(Errno::Nomem);
        }
        Ok(())
    }
    /// Growth reports newly allocated slots; shrink reports removed slots.
    /// The caller must initialize/revoke these pages before publication/reuse.
    pub fn resize(&mut self, handle: u64, size: usize, batch: &mut Batch) -> Result<(), Errno> {
        batch.count = 0;
        self.check_resize(handle, size)?;
        let i = self.index(handle)?;
        let old = self.objects[i].size.div_ceil(PAGE_SIZE);
        let new = size.div_ceil(PAGE_SIZE);
        if new > old {
            for slot in 0..PAGES {
                if !self.used[slot] {
                    batch.slots[batch.count] = slot as u16;
                    batch.count += 1;
                    if batch.count == new - old {
                        break;
                    }
                }
            }
            if batch.count != new - old {
                batch.count = 0;
                return Err(Errno::Nomem);
            }
            self.objects[i].slots[old..new].copy_from_slice(&batch.slots[..batch.count]);
            for slot in batch.iter() {
                self.used[slot] = true;
            }
            self.pages += new - old;
        } else if new < old {
            batch.slots[..old - new].copy_from_slice(&self.objects[i].slots[new..old]);
            batch.count = old - new;
            self.objects[i].slots[new..old].fill(NONE);
            for slot in batch.iter() {
                self.used[slot] = false;
            }
            self.pages -= old - new;
        }
        self.objects[i].size = size;
        Ok(())
    }
    pub fn page(&self, handle: u64, index: usize) -> Result<usize, Errno> {
        let o = &self.objects[self.index(handle)?];
        o.slots
            .get(index)
            .copied()
            .filter(|v| *v != NONE)
            .map(usize::from)
            .ok_or(Errno::Fault)
    }
    pub fn hold_mapping(
        &mut self,
        handle: u64,
        offset: usize,
        length: usize,
        may_write: bool,
    ) -> Result<(), Errno> {
        let i = self.index(handle)?;
        let o = &mut self.objects[i];
        if length == 0
            || !offset.is_multiple_of(PAGE_SIZE)
            || offset.checked_add(length).is_none_or(|end| end > o.size)
        {
            return Err(Errno::Inval);
        }
        if may_write && o.seals & SEAL_WRITE != 0 {
            return Err(Errno::Perm);
        }
        let mappings = o.mappings.checked_add(1).ok_or(Errno::Overflow)?;
        let writable_mappings = o
            .writable_mappings
            .checked_add(u16::from(may_write))
            .ok_or(Errno::Overflow)?;
        o.mappings = mappings;
        o.writable_mappings = writable_mappings;
        Ok(())
    }
    fn reclaim(&mut self, i: usize, batch: &mut Batch) -> bool {
        batch.count = 0;
        let o = &mut self.objects[i];
        if o.description || o.mappings != 0 {
            return false;
        }
        batch.count = o.size.div_ceil(PAGE_SIZE);
        batch.slots[..batch.count].copy_from_slice(&o.slots[..batch.count]);
        for slot in batch.iter() {
            self.used[slot] = false;
        }
        self.pages -= batch.count;
        o.slots[..batch.count].fill(NONE);
        o.live = false;
        o.size = 0;
        true
    }
    pub fn close_description(&mut self, handle: u64, batch: &mut Batch) -> Result<bool, Errno> {
        batch.count = 0;
        let i = self.index(handle)?;
        if !self.objects[i].description {
            return Err(Errno::Badf);
        }
        self.objects[i].description = false;
        Ok(self.reclaim(i, batch))
    }
    pub fn drop_mapping(
        &mut self,
        handle: u64,
        may_write: bool,
        batch: &mut Batch,
    ) -> Result<bool, Errno> {
        batch.count = 0;
        let i = self.index(handle)?;
        let o = &mut self.objects[i];
        if o.mappings == 0
            || (may_write && o.writable_mappings == 0)
            || (!may_write && o.mappings == o.writable_mappings)
        {
            return Err(Errno::Badf);
        }
        o.mappings -= 1;
        o.writable_mappings -= u16::from(may_write);
        Ok(self.reclaim(i, batch))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub length: usize,
    pub handle: u64,
    pub offset: usize,
    pub protection: u8,
    pub may_write: bool,
}
impl Mapping {
    pub fn pages(self) -> usize {
        self.length.div_ceil(PAGE_SIZE)
    }
}
pub struct Maps {
    slots: [Option<Mapping>; MAPPINGS],
}
impl Default for Maps {
    fn default() -> Self {
        Self::new()
    }
}
impl Maps {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAPPINGS],
        }
    }
    pub fn free(&self) -> usize {
        self.slots.iter().filter(|s| s.is_none()).count()
    }
    pub fn iter(&self) -> impl Iterator<Item = Mapping> + '_ {
        self.slots.iter().flatten().copied()
    }
    pub fn prepare(
        &self,
        handle: u64,
        offset: usize,
        length: usize,
        protection: u8,
        may_write: bool,
    ) -> Result<Mapping, Errno> {
        if length == 0
            || length > (END - BASE) as usize
            || !offset.is_multiple_of(PAGE_SIZE)
            || !matches!(protection, 0 | 1 | 3)
        {
            return Err(Errno::Inval);
        }
        if protection & 2 != 0 && !may_write {
            return Err(Errno::Access);
        }
        if self.free() == 0 {
            return Err(Errno::Nomem);
        }
        let bytes = length.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let mut start = BASE;
        loop {
            let end = start
                .checked_add(bytes as u64)
                .filter(|e| *e <= END)
                .ok_or(Errno::Nomem)?;
            let conflict = self
                .iter()
                .find(|m| start < m.start + (m.pages() * PAGE_SIZE) as u64 && m.start < end);
            match conflict {
                Some(m) => start = m.start + (m.pages() * PAGE_SIZE) as u64,
                None => {
                    return Ok(Mapping {
                        start,
                        length,
                        handle,
                        offset,
                        protection,
                        may_write,
                    });
                }
            }
        }
    }
    pub fn insert(&mut self, mapping: Mapping) -> Result<(), Errno> {
        let expected = self.prepare(
            mapping.handle,
            mapping.offset,
            mapping.length,
            mapping.protection,
            mapping.may_write,
        )?;
        if expected != mapping {
            return Err(Errno::Inval);
        }
        *self
            .slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Errno::Nomem)? = Some(mapping);
        Ok(())
    }
    pub fn whole(&self, start: u64, pages: usize) -> Result<Mapping, Errno> {
        self.iter()
            .find(|m| m.start == start && m.pages() == pages)
            .ok_or(Errno::Inval)
    }
    pub fn remove(&mut self, start: u64, pages: usize) -> Result<Mapping, Errno> {
        let m = self.whole(start, pages)?;
        *self
            .slots
            .iter_mut()
            .find(|s| **s == Some(m))
            .ok_or(Errno::Io)? = None;
        Ok(m)
    }
    pub fn access(&self, address: u64, length: usize, write: bool) -> Result<Mapping, Errno> {
        let end = address.checked_add(length as u64).ok_or(Errno::Fault)?;
        self.iter()
            .find(|m| {
                length != 0
                    && address >= m.start
                    && end <= m.start + (m.pages() * PAGE_SIZE) as u64
                    && m.protection & (if write { 3 } else { 1 }) == if write { 3 } else { 1 }
            })
            .ok_or(Errno::Fault)
    }
    pub fn protect(&mut self, start: u64, length: usize, protection: u8) -> Result<Mapping, Errno> {
        if length == 0 || !matches!(protection, 0 | 1 | 3) {
            return Err(Errno::Inval);
        }
        let m = self.whole(start, length.div_ceil(PAGE_SIZE))?;
        if protection & 2 != 0 && !m.may_write {
            return Err(Errno::Access);
        }
        let replacement = Mapping { protection, ..m };
        *self
            .slots
            .iter_mut()
            .find(|s| **s == Some(m))
            .ok_or(Errno::Io)? = Some(replacement);
        Ok(replacement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn write_seal_without_mappings_is_supported_and_errors_are_atomic() {
        let mut backing = Backings::new();
        let handle = backing.create(true).unwrap();
        assert_eq!(backing.add_seals(handle, 8), Ok(()));
        assert_eq!(backing.info(handle).unwrap().seals, 8);
        assert_eq!(backing.add_seals(handle, 16 | SEAL_GROW), Err(Errno::Inval));
        assert_eq!(backing.info(handle).unwrap().seals, 8);
        assert_eq!(backing.add_seals(handle, SEAL_SEAL | SEAL_GROW), Ok(()));
        assert_eq!(backing.add_seals(handle, SEAL_SHRINK), Err(Errno::Perm));
        assert_eq!(
            backing.info(handle).unwrap().seals,
            8 | SEAL_SEAL | SEAL_GROW
        );
    }
    #[test]
    fn readonly_and_none_aliases_retain_future_write_capability_until_unmap() {
        let mut backing = Backings::new();
        let mut batch = Batch::new();
        let handle = backing.create(true).unwrap();
        backing.resize(handle, PAGE_SIZE, &mut batch).unwrap();
        let mut first_process = Maps::new();
        let mut second_process = Maps::new();
        for (maps, protection) in [(&mut first_process, 1), (&mut second_process, 0)] {
            let may_write = backing
                .mapping_permissions(handle, protection, true)
                .unwrap();
            assert!(may_write);
            let m = maps
                .prepare(handle, 0, PAGE_SIZE, protection, may_write)
                .unwrap();
            backing
                .hold_mapping(handle, 0, PAGE_SIZE, may_write)
                .unwrap();
            maps.insert(m).unwrap();
        }
        let before = backing.info(handle).unwrap();
        assert_eq!(before.writable_mappings, 2);
        assert_eq!(
            backing.add_seals(handle, SEAL_WRITE | SEAL_GROW),
            Err(Errno::Busy)
        );
        assert_eq!(backing.info(handle).unwrap(), before);
        first_process.protect(BASE, PAGE_SIZE, 3).unwrap();
        first_process.protect(BASE, PAGE_SIZE, 1).unwrap();
        assert_eq!(backing.add_seals(handle, SEAL_WRITE), Err(Errno::Busy));
        for maps in [&mut first_process, &mut second_process] {
            let m = maps.remove(BASE, 1).unwrap();
            assert!(
                !backing
                    .drop_mapping(handle, m.may_write, &mut batch)
                    .unwrap()
            );
        }
        backing.add_seals(handle, SEAL_WRITE).unwrap();
        assert_eq!(backing.info(handle).unwrap().writable_mappings, 0);
        assert_eq!(backing.check_write(handle), Err(Errno::Perm));
        // WRITE alone does not imply GROW or SHRINK.
        backing.resize(handle, PAGE_SIZE + 1, &mut batch).unwrap();
        backing.resize(handle, PAGE_SIZE, &mut batch).unwrap();
    }
    #[test]
    fn sealed_readonly_alias_cannot_upgrade_and_survives_description_close() {
        let mut backing = Backings::new();
        let mut maps = Maps::new();
        let mut batch = Batch::new();
        let handle = backing.create(true).unwrap();
        backing.resize(handle, PAGE_SIZE, &mut batch).unwrap();
        backing.add_seals(handle, SEAL_WRITE).unwrap();
        assert_eq!(
            backing.mapping_permissions(handle, 3, true),
            Err(Errno::Perm)
        );
        assert_eq!(
            backing.mapping_permissions(handle, 3, false),
            Err(Errno::Access)
        );
        assert_eq!(
            backing.hold_mapping(handle, 0, PAGE_SIZE, true),
            Err(Errno::Perm)
        );
        assert_eq!(backing.info(handle).unwrap().mappings, 0);
        let may_write = backing.mapping_permissions(handle, 1, true).unwrap();
        assert!(!may_write);
        let m = maps.prepare(handle, 0, PAGE_SIZE, 1, may_write).unwrap();
        backing
            .hold_mapping(handle, 0, PAGE_SIZE, may_write)
            .unwrap();
        maps.insert(m).unwrap();
        backing.add_seals(handle, SEAL_WRITE | SEAL_SEAL).unwrap();
        let before = maps.slots;
        assert_eq!(maps.protect(BASE, PAGE_SIZE, 3), Err(Errno::Access));
        assert_eq!(maps.slots, before);
        maps.protect(BASE, PAGE_SIZE, 0).unwrap();
        assert_eq!(maps.protect(BASE, PAGE_SIZE, 3), Err(Errno::Access));
        maps.protect(BASE, PAGE_SIZE, 1).unwrap();
        assert!(maps.access(BASE, PAGE_SIZE, false).is_ok());
        assert_eq!(maps.access(BASE, 1, true), Err(Errno::Fault));
        assert!(!backing.close_description(handle, &mut batch).unwrap());
        assert!(backing.page(handle, 0).is_ok());
        let m = maps.remove(BASE, 1).unwrap();
        assert!(
            backing
                .drop_mapping(handle, m.may_write, &mut batch)
                .unwrap()
        );
        assert_eq!(backing.free_pages(), PAGES);
        assert_eq!(
            backing.mapping_permissions(handle, 1, true),
            Err(Errno::Badf)
        );
        let replacement = backing.create(true).unwrap();
        assert_ne!(replacement, handle);
        assert_eq!(backing.check_write(replacement), Ok(()));
        assert_eq!(backing.info(replacement).unwrap().writable_mappings, 0);
    }
    #[test]
    fn mapping_capability_counts_and_rejected_holds_are_atomic() {
        let mut backing = Backings::new();
        let mut batch = Batch::new();
        let handle = backing.create(true).unwrap();
        backing.resize(handle, PAGE_SIZE, &mut batch).unwrap();
        assert!(!backing.mapping_permissions(handle, 1, false).unwrap());
        backing.hold_mapping(handle, 0, PAGE_SIZE, false).unwrap();
        let before = backing.info(handle).unwrap();
        assert_eq!(
            backing.drop_mapping(handle, true, &mut batch),
            Err(Errno::Badf)
        );
        assert_eq!(
            backing.hold_mapping(handle, PAGE_SIZE, 1, true),
            Err(Errno::Inval)
        );
        assert_eq!(backing.info(handle).unwrap(), before);
        backing.hold_mapping(handle, 0, PAGE_SIZE, true).unwrap();
        backing.drop_mapping(handle, false, &mut batch).unwrap();
        let before = backing.info(handle).unwrap();
        assert_eq!(before.mappings, 1);
        assert_eq!(before.writable_mappings, 1);
        assert_eq!(
            backing.drop_mapping(handle, false, &mut batch),
            Err(Errno::Badf)
        );
        assert_eq!(backing.info(handle).unwrap(), before);
        assert_eq!(backing.add_seals(handle, SEAL_WRITE), Err(Errno::Busy));
        backing.drop_mapping(handle, true, &mut batch).unwrap();
        backing.add_seals(handle, SEAL_WRITE).unwrap();
        assert!(backing.close_description(handle, &mut batch).unwrap());
        assert_eq!(backing.live_objects(), 0);
    }
    #[test]
    fn private_snapshot_requires_immutable_file_and_includes_rounded_page_contents() {
        let mut backing = Backings::new();
        let mut batch = Batch::new();
        let handle = backing.create(true).unwrap();
        backing.resize(handle, PAGE_SIZE + 37, &mut batch).unwrap();
        for seals in [0, SEAL_WRITE, SEAL_GROW] {
            backing.add_seals(handle, seals).unwrap();
            assert_eq!(
                backing.private_snapshot_bytes(handle, 0, 1, 1),
                Err(Errno::Inval)
            );
        }
        backing.add_seals(handle, SEAL_SHRINK).unwrap();
        let before = backing.info(handle).unwrap();
        for protection in [0, 1, 3] {
            assert_eq!(
                backing.private_snapshot_bytes(handle, 0, 1, protection),
                Ok(PAGE_SIZE)
            );
            assert_eq!(
                backing.private_snapshot_bytes(handle, PAGE_SIZE, 1, protection),
                Ok(37)
            );
        }
        for (offset, length, protection) in [
            (1, 1, 1),
            (0, 0, 1),
            (0, usize::MAX, 1),
            (0, 1, 2),
            (PAGE_SIZE, 38, 1),
        ] {
            assert_eq!(
                backing.private_snapshot_bytes(handle, offset, length, protection),
                Err(Errno::Inval)
            );
        }
        assert_eq!(backing.info(handle).unwrap(), before);
        backing.close_description(handle, &mut batch).unwrap();
        assert_eq!(
            backing.private_snapshot_bytes(handle, 0, 1, 1),
            Err(Errno::Badf)
        );
    }
    #[test]
    fn lifetime_closing_description_preserves_mapped_pages_and_reclaims_last_alias() {
        let mut b = Backings::new();
        let mut batch = Batch::new();
        let h = b.create(true).unwrap();
        b.resize(h, 8192, &mut batch).unwrap();
        let first = b.page(h, 0).unwrap();
        b.hold_mapping(h, 0, 4096, true).unwrap();
        b.hold_mapping(h, 4096, 4096, true).unwrap();
        assert!(!b.close_description(h, &mut batch).unwrap());
        assert_eq!(batch.count(), 0);
        assert_eq!(b.page(h, 0), Ok(first));
        assert!(!b.drop_mapping(h, true, &mut batch).unwrap());
        assert!(b.drop_mapping(h, true, &mut batch).unwrap());
        assert_eq!(batch.count(), 2);
        assert_eq!(b.free_pages(), PAGES);
        assert_eq!(b.info(h), Err(Errno::Badf));
        assert_ne!(b.create(false).unwrap(), h);
    }
    #[test]
    fn resize_seals_and_failures_preserve_existing_pages() {
        let mut b = Backings::new();
        let mut batch = Batch::new();
        let h = b.create(true).unwrap();
        b.resize(h, 4097, &mut batch).unwrap();
        let p = b.page(h, 0).unwrap();
        b.hold_mapping(h, 0, 4097, true).unwrap();
        assert_eq!(b.resize(h, 1, &mut batch), Err(Errno::Busy));
        assert_eq!(b.info(h).unwrap().size, 4097);
        assert_eq!(batch.count(), 0);
        b.resize(h, 8193, &mut batch).unwrap();
        assert_eq!(batch.count(), 1);
        assert_eq!(b.page(h, 0), Ok(p));
        b.drop_mapping(h, true, &mut batch).unwrap();
        b.resize(h, 1, &mut batch).unwrap();
        assert_eq!(batch.count(), 2);
        assert_eq!(b.add_seals(h, 16), Err(Errno::Inval));
        assert_eq!(b.info(h).unwrap().seals, 0);
        b.add_seals(h, SEAL_SHRINK | SEAL_GROW).unwrap();
        assert_eq!(b.resize(h, 0, &mut batch), Err(Errno::Perm));
        assert_eq!(b.resize(h, 2, &mut batch), Err(Errno::Perm));
        b.resize(h, 1, &mut batch).unwrap();
        b.add_seals(h, SEAL_SEAL).unwrap();
        assert_eq!(b.add_seals(h, 0), Err(Errno::Perm));
    }
    #[test]
    fn exhausted_pool_bad_ranges_and_stale_handles_are_atomic() {
        let mut b = Backings::new();
        let mut batch = Batch::new();
        for _ in 0..2 {
            let h = b.create(false).unwrap();
            b.resize(h, OBJECT_PAGES * PAGE_SIZE, &mut batch).unwrap();
        }
        let h = b.create(true).unwrap();
        assert_eq!(b.resize(h, 1, &mut batch), Err(Errno::Nomem));
        assert_eq!(b.info(h).unwrap().size, 0);
        assert_eq!(batch.count(), 0);
        assert_eq!(b.hold_mapping(h, 0, 1, true), Err(Errno::Inval));
        assert_eq!(b.resize(h, usize::MAX, &mut batch), Err(Errno::Inval));
        b.close_description(h, &mut batch).unwrap();
        assert_eq!(b.close_description(h, &mut batch), Err(Errno::Badf));
    }
    #[test]
    fn mappings_are_private_metadata_with_whole_unmap_and_checked_permissions() {
        let mut m = Maps::new();
        let a = m.prepare(256, 0, 4097, 3, true).unwrap();
        m.insert(a).unwrap();
        let b = m.prepare(257, 4096, 4096, 1, true).unwrap();
        m.insert(b).unwrap();
        assert_eq!(b.start, BASE + 8192);
        assert_eq!(m.remove(BASE, 1), Err(Errno::Inval));
        assert_eq!(m.free(), MAPPINGS - 2);
        assert_eq!(m.access(b.start, 1, true), Err(Errno::Fault));
        assert!(m.access(b.start, 1, false).is_ok());
        assert_eq!(m.access(u64::MAX, 2, false), Err(Errno::Fault));
        assert_eq!(m.prepare(1, 1, 4096, 3, true), Err(Errno::Inval));
        assert_eq!(m.protect(BASE, 4097, 7), Err(Errno::Inval));
        m.protect(BASE, 4097, 0).unwrap();
        assert_eq!(m.access(BASE, 1, false), Err(Errno::Fault));
        m.remove(BASE, 2).unwrap();
        assert_eq!(m.prepare(1, 0, 4096, 3, true).unwrap().start, BASE);
    }
    #[test]
    fn metadata_exhaustion_and_generation_retirement_never_replace_live_objects() {
        let mut b = Backings::new();
        let mut batch = Batch::new();
        b.objects[0].generation = MAX_GENERATION - 1;
        let last = b.create(true).unwrap();
        b.close_description(last, &mut batch).unwrap();
        assert_eq!(b.free_objects(), OBJECTS - 1);
        let mut handles = [0; OBJECTS - 1];
        for h in &mut handles {
            *h = b.create(false).unwrap();
        }
        assert_eq!(b.create(true), Err(Errno::Mfile));
        assert_eq!(b.description_count(), OBJECTS - 1);
        assert_eq!(b.info(last), Err(Errno::Badf));
        for h in handles {
            assert!(b.close_description(h, &mut batch).unwrap());
        }
        assert_eq!(b.live_objects(), 0);
    }
    #[test]
    fn repeated_growth_shrink_mapping_and_close_reclaim_every_slot() {
        let mut b = Backings::new();
        let mut batch = Batch::new();
        for cycle in 1..32 {
            let h = b.create(true).unwrap();
            b.resize(h, cycle * PAGE_SIZE + 13, &mut batch).unwrap();
            assert_eq!(batch.count(), cycle + 1);
            b.resize(h, PAGE_SIZE + 1, &mut batch).unwrap();
            assert_eq!(batch.count(), cycle - 1);
            b.hold_mapping(h, 0, PAGE_SIZE + 1, true).unwrap();
            b.resize(h, 4 * PAGE_SIZE, &mut batch).unwrap();
            assert_eq!(batch.count(), 2);
            assert!(!b.close_description(h, &mut batch).unwrap());
            assert_eq!(b.description_count(), 0);
            assert_eq!(b.mapping_count(), 1);
            assert!(b.drop_mapping(h, true, &mut batch).unwrap());
            assert_eq!(batch.count(), 4);
            assert_eq!(b.free_pages(), PAGES);
            assert_eq!(b.live_objects(), 0);
        }
    }
    #[test]
    fn per_process_mapping_limit_has_no_prefix_mutation() {
        let mut maps = Maps::new();
        for _ in 0..MAPPINGS {
            let m = maps.prepare(256, 0, PAGE_SIZE, 3, true).unwrap();
            maps.insert(m).unwrap();
        }
        let before = maps.slots;
        assert_eq!(maps.prepare(256, 0, PAGE_SIZE, 3, true), Err(Errno::Nomem));
        assert_eq!(maps.slots, before);
        assert_eq!(maps.remove(BASE, 2), Err(Errno::Inval));
        assert_eq!(maps.slots, before);
        maps.remove(BASE, 1).unwrap();
        assert_eq!(
            maps.prepare(256, 0, PAGE_SIZE, 1, true).unwrap().start,
            BASE
        );
    }
}
