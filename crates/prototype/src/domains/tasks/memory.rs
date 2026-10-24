use super::{UNSET, valid_key};
use crate::domains::{Action, Error, ObjectKey, PolicyStamp};
pub const PAGE_BYTES: u64 = 4096;
const ORDINARY_OWNERS: usize = 64;
const OWNERS: usize = ORDINARY_OWNERS + 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheHandle {
    pub frame: usize,
    pub generation: u64,
    pub object: ObjectKey,
    pub page: u64,
}
pub trait MemoryBackend {
    fn zero(&mut self, frame: usize) -> Result<(), Error>;
    fn map(
        &mut self,
        owner: ObjectKey,
        address: u64,
        frame: usize,
        writable: bool,
    ) -> Result<(), Error>;
    /// Success certifies all CPU/DMA aliases stopped and required TLB invalidation
    /// completed. It must also succeed when an earlier revoke already completed.
    fn revoke(&mut self, owner: ObjectKey, address: u64, frame: usize) -> Result<(), Error>;
    fn load_cache(&mut self, object: ObjectKey, page: u64, frame: usize) -> Result<(), Error>;
    /// Success proves even an uncertain/failed load has no outstanding writer.
    fn drop_cache(&mut self, handle: CacheHandle) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Free,
    Reserved,
    Retired,
    Committed(ObjectKey),
    Anonymous {
        owner: ObjectKey,
        address: u64,
        mapped: bool,
        uncertain: bool,
    },
    LoadingCache {
        object: ObjectKey,
        page: u64,
    },
    Cache {
        object: ObjectKey,
        page: u64,
        refs: u32,
        dirty: bool,
        pinned: bool,
        stale: bool,
    },
}
#[derive(Clone, Copy)]
struct Frame {
    kind: Kind,
    generation: u64,
    progress: bool,
}
impl Frame {
    const EMPTY: Self = Self {
        kind: Kind::Free,
        generation: 0,
        progress: false,
    };
}
#[derive(Clone, Copy)]
struct Owner {
    key: ObjectKey,
    quota: usize,
    used: usize,
    progress: bool,
    committed: bool,
}
#[derive(Clone, Copy)]
struct Region {
    owner: ObjectKey,
    base: u64,
    pages: usize,
    writable: bool,
    draining: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryStats {
    pub free_pages: usize,
    pub progress_free_pages: usize,
    pub anonymous_pages: usize,
    pub committed_pages: usize,
    pub cache_pages: usize,
    pub dirty_pages: usize,
    pub reserved_pages: usize,
    pub faults: u64,
    pub zeroed_pages: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub reclaim_calls: u64,
    pub reclaimed_pages: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReclaimProgress {
    pub released: usize,
    pub remaining: usize,
    pub blocked: bool,
}
pub struct Memory<const P: usize, const R: usize = 128> {
    frames: [Frame; P],
    owners: [Option<Owner>; OWNERS],
    regions: [Option<Region>; R],
    stamp: PolicyStamp,
    cache_budget: usize,
    cache_grant: usize,
    baseline_grant: usize,
    reclaim_batch: usize,
    reclaim_cursor: usize,
    last_now: u64,
    counters: MemoryStats,
}
impl<const P: usize, const R: usize> Default for Memory<P, R> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const P: usize, const R: usize> Memory<P, R> {
    pub const fn new() -> Self {
        Self {
            frames: [Frame::EMPTY; P],
            owners: [None; OWNERS],
            regions: [None; R],
            stamp: UNSET,
            cache_budget: 256,
            cache_grant: if P < 256 { P } else { 256 },
            baseline_grant: if P < 256 { P } else { 256 },
            reclaim_batch: 16,
            reclaim_cursor: 0,
            last_now: 0,
            counters: MemoryStats {
                free_pages: 0,
                progress_free_pages: 0,
                anonymous_pages: 0,
                committed_pages: 0,
                cache_pages: 0,
                dirty_pages: 0,
                reserved_pages: 0,
                faults: 0,
                zeroed_pages: 0,
                cache_hits: 0,
                cache_misses: 0,
                reclaim_calls: 0,
                reclaimed_pages: 0,
            },
        }
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Stale);
        }
        self.last_now = now;
        Ok(())
    }
    fn owner(&self, key: ObjectKey) -> Result<usize, Error> {
        self.owners
            .iter()
            .position(|o| o.is_some_and(|o| o.key == key))
            .ok_or(Error::Stale)
    }
    fn region(&self, key: ObjectKey, address: u64) -> Result<usize, Error> {
        self.regions
            .iter()
            .position(|r| {
                r.is_some_and(|r| {
                    r.owner == key
                        && address >= r.base
                        && address - r.base < (r.pages as u64) * PAGE_BYTES
                })
            })
            .ok_or(Error::NotFound)
    }
    fn ordinary_backing(&self) -> usize {
        self.frames
            .iter()
            .filter(|f| !f.progress && !matches!(f.kind, Kind::Reserved | Kind::Retired))
            .count()
    }
    fn free_frame(&mut self, progress: bool) -> Result<usize, Error> {
        for (i, f) in self.frames.iter_mut().enumerate() {
            if f.kind == Kind::Free && f.progress == progress {
                if let Some(generation) = f.generation.checked_add(1) {
                    f.generation = generation;
                    return Ok(i);
                }
                f.kind = Kind::Retired;
            }
        }
        Err(Error::Capacity)
    }
    pub fn reserve_frames(&mut self, start: usize, count: usize) -> Result<(), Error> {
        let end = start
            .checked_add(count)
            .filter(|end| *end <= P)
            .ok_or(Error::Range)?;
        if self.frames[start..end]
            .iter()
            .any(|f| f.kind != Kind::Free || f.progress)
        {
            return Err(Error::Busy);
        }
        for f in &mut self.frames[start..end] {
            f.kind = Kind::Reserved;
        }
        Ok(())
    }
    pub fn reserve_progress_frames(&mut self, start: usize, count: usize) -> Result<(), Error> {
        let end = start
            .checked_add(count)
            .filter(|end| *end <= P)
            .ok_or(Error::Range)?;
        if self.frames[start..end]
            .iter()
            .any(|f| f.kind != Kind::Free || f.progress)
        {
            return Err(Error::Busy);
        }
        for f in &mut self.frames[start..end] {
            f.progress = true;
        }
        Ok(())
    }
    fn register(&mut self, key: ObjectKey, quota: usize, progress: bool) -> Result<(), Error> {
        valid_key(key)?;
        if quota == 0 || quota > P {
            return Err(Error::Range);
        }
        if self.owners.iter().flatten().any(|o| o.key.id == key.id) {
            return Err(Error::Exists);
        }
        let range = if progress {
            ORDINARY_OWNERS..OWNERS
        } else {
            0..ORDINARY_OWNERS
        };
        let i = range
            .into_iter()
            .find(|i| self.owners[*i].is_none())
            .ok_or(Error::Capacity)?;
        self.owners[i] = Some(Owner {
            key,
            quota,
            used: 0,
            progress,
            committed: false,
        });
        Ok(())
    }
    pub fn register_owner(&mut self, key: ObjectKey, quota: usize) -> Result<(), Error> {
        self.register(key, quota, false)
    }
    pub fn register_progress_owner(&mut self, key: ObjectKey, quota: usize) -> Result<(), Error> {
        self.register(key, quota, true)
    }
    /// Reserve actual backing before a contract is reported Created. Unmapped
    /// committed pages remain private to this generation until owner teardown.
    pub fn commit_pages(&mut self, key: ObjectKey) -> Result<(), Error> {
        let oi = self.owner(key)?;
        let owner = self.owners[oi].ok_or(Error::Stale)?;
        if owner.used != 0 || owner.committed {
            return Err(Error::Conflict);
        }
        if self
            .frames
            .iter()
            .filter(|f| {
                f.kind == Kind::Free && f.progress == owner.progress && f.generation != u64::MAX
            })
            .count()
            < owner.quota
        {
            return Err(Error::Capacity);
        }
        let mut left = owner.quota;
        for f in &mut self.frames {
            if left != 0
                && f.kind == Kind::Free
                && f.progress == owner.progress
                && f.generation != u64::MAX
            {
                f.kind = Kind::Committed(key);
                left -= 1;
            }
        }
        self.owners[oi].as_mut().ok_or(Error::Stale)?.committed = true;
        Ok(())
    }
    pub fn unregister_owner(&mut self, key: ObjectKey) -> Result<(), Error> {
        let oi = self.owner(key)?;
        if self.owners[oi].is_some_and(|o| o.used != 0)
            || self.regions.iter().flatten().any(|r| r.owner == key)
        {
            return Err(Error::Busy);
        }
        for f in &mut self.frames {
            if f.kind == Kind::Committed(key) {
                f.kind = Kind::Free;
            }
        }
        self.owners[oi] = None;
        Ok(())
    }
    pub fn reserve(
        &mut self,
        key: ObjectKey,
        base: u64,
        pages: usize,
        writable: bool,
    ) -> Result<(), Error> {
        self.owner(key)?;
        if base == 0 || !base.is_multiple_of(PAGE_BYTES) || pages == 0 {
            return Err(Error::Range);
        }
        let bytes = u64::try_from(pages)
            .ok()
            .and_then(|n| n.checked_mul(PAGE_BYTES))
            .ok_or(Error::Range)?;
        let end = base.checked_add(bytes).ok_or(Error::Range)?;
        if self.regions.iter().flatten().any(|r| {
            r.owner == key && base < r.base + (r.pages as u64) * PAGE_BYTES && r.base < end
        }) {
            return Err(Error::Conflict);
        }
        *self
            .regions
            .iter_mut()
            .find(|r| r.is_none())
            .ok_or(Error::Capacity)? = Some(Region {
            owner: key,
            base,
            pages,
            writable,
            draining: false,
        });
        Ok(())
    }
    pub fn fault(
        &mut self,
        key: ObjectKey,
        address: u64,
        write: bool,
        backend: &mut impl MemoryBackend,
    ) -> Result<usize, Error> {
        let oi = self.owner(key)?;
        let r = self.regions[self.region(key, address)?].ok_or(Error::NotFound)?;
        if r.draining {
            return Err(Error::Busy);
        }
        if write && !r.writable {
            return Err(Error::Auth);
        }
        let page = address / PAGE_BYTES * PAGE_BYTES;
        for (i, f) in self.frames.iter().enumerate() {
            if let Kind::Anonymous {
                owner,
                address,
                mapped,
                uncertain,
            } = f.kind
                && owner == key
                && address == page
            {
                return if mapped && !uncertain {
                    Ok(i)
                } else {
                    Err(Error::NotReady)
                };
            }
        }
        let owner = self.owners[oi].ok_or(Error::Stale)?;
        if owner.used >= owner.quota {
            return Err(Error::Budget);
        }
        let frame = if owner.committed {
            let (i, f) = self
                .frames
                .iter_mut()
                .enumerate()
                .find(|(_, f)| f.kind == Kind::Committed(key))
                .ok_or(Error::Capacity)?;
            f.generation = f.generation.checked_add(1).ok_or(Error::Overflow)?;
            i
        } else {
            self.free_frame(owner.progress)?
        };
        backend.zero(frame)?;
        self.counters.zeroed_pages = self.counters.zeroed_pages.saturating_add(1);
        self.frames[frame].kind = Kind::Anonymous {
            owner: key,
            address: page,
            mapped: false,
            uncertain: true,
        };
        self.owners[oi].as_mut().ok_or(Error::Stale)?.used += 1;
        self.counters.faults = self.counters.faults.saturating_add(1);
        backend.map(key, page, frame, r.writable)?;
        self.frames[frame].kind = Kind::Anonymous {
            owner: key,
            address: page,
            mapped: true,
            uncertain: false,
        };
        Ok(frame)
    }
    pub fn resident(&self, key: ObjectKey, address: u64) -> Result<usize, Error> {
        self.owner(key)?;
        let r = self.regions[self.region(key, address)?].ok_or(Error::NotFound)?;
        if r.draining {
            return Err(Error::Busy);
        }
        let page = address / PAGE_BYTES * PAGE_BYTES;
        self.frames.iter().position(|f|matches!(f.kind,Kind::Anonymous{owner,address,mapped:true,uncertain:false} if owner==key && address==page)).ok_or(Error::NotReady)
    }
    pub fn unmap_step(
        &mut self,
        key: ObjectKey,
        base: u64,
        maximum: usize,
        backend: &mut impl MemoryBackend,
    ) -> Result<ReclaimProgress, Error> {
        let oi = self.owner(key)?;
        if maximum == 0 {
            return Err(Error::Range);
        }
        let ri = self
            .regions
            .iter()
            .position(|r| r.is_some_and(|r| r.owner == key && r.base == base))
            .ok_or(Error::NotFound)?;
        self.regions[ri].as_mut().ok_or(Error::NotFound)?.draining = true;
        let r = self.regions[ri].ok_or(Error::NotFound)?;
        let end = base + (r.pages as u64) * PAGE_BYTES;
        let committed = self.owners[oi].ok_or(Error::Stale)?.committed;
        let mut released = 0;
        for i in 0..P {
            if released == maximum {
                break;
            }
            if let Kind::Anonymous { owner, address, .. } = self.frames[i].kind
                && owner == key
                && address >= base
                && address < end
            {
                backend.revoke(key, address, i)?;
                self.frames[i].kind = Kind::Anonymous {
                    owner: key,
                    address,
                    mapped: false,
                    uncertain: true,
                };
                backend.zero(i)?;
                self.counters.zeroed_pages = self.counters.zeroed_pages.saturating_add(1);
                self.frames[i].kind = if committed {
                    Kind::Committed(key)
                } else {
                    Kind::Free
                };
                self.owners[oi].as_mut().ok_or(Error::Stale)?.used -= 1;
                released += 1;
            }
        }
        let remaining=self.frames.iter().filter(|f|matches!(f.kind,Kind::Anonymous{owner,address,..} if owner==key && address>=base && address<end)).count();
        if remaining == 0 {
            self.regions[ri] = None;
        }
        Ok(ReclaimProgress {
            released,
            remaining,
            blocked: false,
        })
    }
    pub fn configure_cache_baseline(&mut self, grant: u32) -> Result<(), Error> {
        if grant as usize > self.ordinary_backing() {
            return Err(Error::Budget);
        }
        self.baseline_grant = grant as usize;
        Ok(())
    }
    pub fn install_cache(
        &mut self,
        pages: u32,
        batch: u16,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        self.install_cache_partition(pages, batch, pages, self.baseline_grant as u32, stamp, now)
    }
    pub fn install_cache_partition(
        &mut self,
        pages: u32,
        batch: u16,
        grant: u32,
        baseline: u32,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        self.validate_cache_partition(pages, batch, grant, baseline, stamp, now)?;
        self.time(now)?;
        self.stamp = stamp;
        self.cache_budget = pages as usize;
        self.cache_grant = grant as usize;
        self.baseline_grant = baseline as usize;
        self.reclaim_batch = usize::from(batch);
        Ok(())
    }
    pub fn validate_cache_partition(
        &self,
        pages: u32,
        batch: u16,
        grant: u32,
        baseline: u32,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Stale);
        }
        Action::Cache { pages, batch }.validate()?;
        self.stamp.accepts(stamp, now)?;
        if stamp.version == self.stamp.version
            && (pages as usize != self.cache_budget
                || grant as usize != self.cache_grant
                || baseline as usize != self.baseline_grant
                || usize::from(batch) != self.reclaim_batch)
        {
            return Err(Error::Conflict);
        }
        if grant > pages
            || grant as usize > self.ordinary_backing()
            || baseline as usize > self.ordinary_backing()
        {
            return Err(Error::Budget);
        }
        Ok(())
    }
    fn cache_limits(&self, now: u64) -> (usize, usize) {
        if self.stamp.live(now) {
            (self.cache_grant, self.reclaim_batch)
        } else {
            (self.baseline_grant, 16)
        }
    }
    fn found_cache(&self, object: ObjectKey, page: u64) -> Result<Option<CacheHandle>, Error> {
        for (i, f) in self.frames.iter().enumerate() {
            match f.kind {
                Kind::Cache {
                    object: o,
                    page: p,
                    stale: false,
                    ..
                } if object == o && page == p => {
                    return Ok(Some(CacheHandle {
                        frame: i,
                        generation: f.generation,
                        object,
                        page,
                    }));
                }
                Kind::LoadingCache { object: o, page: p } if object == o && page == p => {
                    return Err(Error::NotReady);
                }
                _ => {}
            }
        }
        Ok(None)
    }
    pub fn lookup_cache(
        &mut self,
        object: ObjectKey,
        page: u64,
        now: u64,
    ) -> Result<Option<CacheHandle>, Error> {
        self.time(now)?;
        valid_key(object)?;
        let found = self.found_cache(object, page)?;
        if found.is_some() {
            self.counters.cache_hits = self.counters.cache_hits.saturating_add(1);
        } else {
            self.counters.cache_misses = self.counters.cache_misses.saturating_add(1);
        }
        Ok(found)
    }
    pub fn cache_page(
        &mut self,
        object: ObjectKey,
        page: u64,
        now: u64,
        backend: &mut impl MemoryBackend,
    ) -> Result<CacheHandle, Error> {
        self.time(now)?;
        valid_key(object)?;
        if let Some(handle) = self.found_cache(object, page)? {
            self.counters.cache_hits = self.counters.cache_hits.saturating_add(1);
            return Ok(handle);
        }
        self.counters.cache_misses = self.counters.cache_misses.saturating_add(1);
        if self.stats().cache_pages >= self.cache_limits(now).0 {
            return Err(Error::Again);
        }
        let frame = self.free_frame(false)?;
        self.frames[frame].kind = Kind::LoadingCache { object, page };
        let handle = CacheHandle {
            frame,
            generation: self.frames[frame].generation,
            object,
            page,
        };
        backend.load_cache(object, page, frame)?;
        self.frames[frame].kind = Kind::Cache {
            object,
            page,
            refs: 0,
            dirty: false,
            pinned: false,
            stale: false,
        };
        Ok(handle)
    }
    fn cache_mut(&mut self, h: CacheHandle) -> Result<&mut Kind, Error> {
        let f = self.frames.get_mut(h.frame).ok_or(Error::Stale)?;
        if f.generation != h.generation {
            return Err(Error::Stale);
        }
        if !matches!(f.kind,Kind::Cache{object,page,..} if object==h.object && page==h.page) {
            return Err(Error::Stale);
        }
        Ok(&mut f.kind)
    }
    pub fn hold_cache(&mut self, h: CacheHandle) -> Result<(), Error> {
        if let Kind::Cache { refs, stale, .. } = self.cache_mut(h)? {
            if *stale {
                return Err(Error::Stale);
            }
            *refs = refs.checked_add(1).ok_or(Error::Overflow)?;
        }
        Ok(())
    }
    pub fn release_cache(&mut self, h: CacheHandle) -> Result<(), Error> {
        if let Kind::Cache { refs, .. } = self.cache_mut(h)? {
            *refs = refs.checked_sub(1).ok_or(Error::Conflict)?;
        }
        Ok(())
    }
    pub fn dirty_cache(&mut self, h: CacheHandle, dirty: bool) -> Result<(), Error> {
        if let Kind::Cache { dirty: value, .. } = self.cache_mut(h)? {
            *value = dirty;
        }
        Ok(())
    }
    pub fn pin_cache(&mut self, h: CacheHandle, pinned: bool) -> Result<(), Error> {
        if let Kind::Cache { pinned: value, .. } = self.cache_mut(h)? {
            *value = pinned;
        }
        Ok(())
    }
    pub fn invalidate_cache(&mut self, key: ObjectKey) {
        for f in &mut self.frames {
            if let Kind::Cache { object, stale, .. } = &mut f.kind
                && *object == key
            {
                *stale = true;
            }
        }
    }
    pub fn invalidate_all_cache(&mut self) {
        for f in &mut self.frames {
            if let Kind::Cache { stale, .. } = &mut f.kind {
                *stale = true;
            }
        }
    }
    pub fn reclaim_step(
        &mut self,
        pressure_pages: usize,
        now: u64,
        backend: &mut impl MemoryBackend,
    ) -> Result<ReclaimProgress, Error> {
        self.time(now)?;
        let (grant, batch) = self.cache_limits(now);
        let resident = self.stats().cache_pages;
        let stale = self
            .frames
            .iter()
            .filter(|f| matches!(f.kind, Kind::Cache { stale: true, .. }))
            .count();
        let wanted = resident
            .saturating_sub(grant)
            .max(pressure_pages.min(resident))
            .max(stale);
        let limit = wanted.min(batch);
        self.counters.reclaim_calls = self.counters.reclaim_calls.saturating_add(1);
        let mut released = 0;
        for offset in 0..P {
            if released == limit {
                break;
            }
            let i = (self.reclaim_cursor + offset) % P;
            let f = self.frames[i];
            if let Kind::Cache {
                object,
                page,
                refs: 0,
                dirty: false,
                pinned: false,
                ..
            }
            | Kind::LoadingCache { object, page } = f.kind
            {
                backend.drop_cache(CacheHandle {
                    frame: i,
                    generation: f.generation,
                    object,
                    page,
                })?;
                self.frames[i].kind = Kind::Free;
                released += 1;
                self.counters.reclaimed_pages = self.counters.reclaimed_pages.saturating_add(1);
            }
        }
        if P != 0 {
            self.reclaim_cursor = (self.reclaim_cursor + batch) % P;
        }
        Ok(ReclaimProgress {
            released,
            remaining: wanted.saturating_sub(released),
            blocked: released < limit,
        })
    }
    pub fn owner_pages(&self, key: ObjectKey) -> Result<usize, Error> {
        Ok(self.owners[self.owner(key)?].ok_or(Error::Stale)?.used)
    }
    pub fn cache_policy(&self, now: u64) -> (u32, u16) {
        if self.stamp.live(now) {
            (self.cache_budget as u32, self.reclaim_batch as u16)
        } else {
            (256, 16)
        }
    }
    pub fn cache_authorized_pages(&self, now: u64) -> usize {
        self.cache_limits(now).0
    }
    pub fn progress_free_pages(&self) -> usize {
        self.frames
            .iter()
            .filter(|f| f.progress && f.kind == Kind::Free)
            .count()
    }
    pub fn stats(&self) -> MemoryStats {
        let mut s = self.counters;
        for f in &self.frames {
            match f.kind {
                Kind::Free if f.progress => s.progress_free_pages += 1,
                Kind::Free => s.free_pages += 1,
                Kind::Anonymous { .. } => s.anonymous_pages += 1,
                Kind::Committed(_) => s.committed_pages += 1,
                Kind::Reserved | Kind::Retired => s.reserved_pages += 1,
                Kind::LoadingCache { .. } => s.cache_pages += 1,
                Kind::Cache { dirty, .. } => {
                    s.cache_pages += 1;
                    s.dirty_pages += usize::from(dirty);
                }
            }
        }
        s
    }
}
