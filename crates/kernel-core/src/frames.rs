//! Bounded ownership state machine. Clearing and revocation must succeed before reuse.
use cyxia_contracts::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Invalid,
    Capacity,
    Again,
    Exhausted,
    Owner,
    Stale,
    ZeroFailed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Reserved,
    Dirty,
    Clean,
    Owned,
    Revoking,
    Retired,
}
#[derive(Debug, Clone, Copy)]
pub struct FrameMeta {
    address: PhysAddr,
    generation: u64,
    owner: Option<TaskId>,
    state: State,
}
impl FrameMeta {
    pub const EMPTY: Self = Self {
        address: PhysAddr(0),
        generation: 0,
        owner: None,
        state: State::Reserved,
    };
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHandle {
    address: PhysAddr,
    generation: u64,
}
impl FrameHandle {
    pub fn address(self) -> PhysAddr {
        self.address
    }
}
pub struct RevokeComplete(FrameHandle);
impl RevokeComplete {
    /// # Safety
    /// Caller must remove all CPU/DMA mappings to this exact handle and complete synchronization.
    pub unsafe fn after_unmap(handle: FrameHandle) -> Self {
        Self(handle)
    }
}
pub trait PageZeroer {
    fn zero(&mut self, page: PhysAddr) -> Result<(), FrameError>;
}
pub struct FramePool<'a> {
    meta: &'a mut [FrameMeta],
}
impl<'a> FramePool<'a> {
    pub fn from_regions(
        info: &BootInfo,
        reserved: &[MemoryRegion],
        metadata: &'a mut [FrameMeta],
    ) -> Result<Self, FrameError> {
        if info.ram_count > 8 || info.reserved_count > 32 {
            return Err(FrameError::Invalid);
        }
        let mut total = 0usize;
        for (i, r) in info.ram[..info.ram_count].iter().enumerate() {
            if r.len == 0
                || !r.start.0.is_multiple_of(4096)
                || !r.len.is_multiple_of(4096)
                || r.end().is_err()
            {
                return Err(FrameError::Invalid);
            }
            if info.ram[..i].iter().any(|x| x.overlaps(*r)) {
                return Err(FrameError::Invalid);
            }
            total = total
                .checked_add(usize::try_from(r.len / 4096).map_err(|_| FrameError::Capacity)?)
                .ok_or(FrameError::Capacity)?;
        }
        if total > 65536 || total > metadata.len() {
            return Err(FrameError::Capacity);
        }
        for r in reserved
            .iter()
            .chain(info.reserved[..info.reserved_count].iter())
        {
            if r.end().is_err() {
                return Err(FrameError::Invalid);
            }
        }
        let mut i = 0;
        for r in &info.ram[..info.ram_count] {
            for offset in (0..r.len).step_by(4096) {
                let page = MemoryRegion {
                    start: PhysAddr(r.start.0 + offset),
                    len: 4096,
                    kind: RegionKind::Ram,
                };
                let excluded = reserved
                    .iter()
                    .chain(info.reserved[..info.reserved_count].iter())
                    .any(|x| x.overlaps(page));
                metadata[i] = FrameMeta {
                    address: page.start,
                    state: if excluded {
                        State::Reserved
                    } else {
                        State::Dirty
                    },
                    ..FrameMeta::EMPTY
                };
                i += 1;
            }
        }
        Ok(Self {
            meta: &mut metadata[..total],
        })
    }
    pub fn alloc_clean(&mut self, owner: TaskId) -> Result<FrameHandle, FrameError> {
        for m in self.meta.iter_mut() {
            if m.state == State::Clean {
                let Some(g) = m.generation.checked_add(1) else {
                    m.state = State::Retired;
                    continue;
                };
                m.generation = g;
                m.owner = Some(owner);
                m.state = State::Owned;
                return Ok(FrameHandle {
                    address: m.address,
                    generation: g,
                });
            }
        }
        if self
            .meta
            .iter()
            .any(|x| matches!(x.state, State::Dirty | State::Revoking))
        {
            Err(FrameError::Again)
        } else {
            Err(FrameError::Exhausted)
        }
    }
    fn find(&mut self, h: FrameHandle) -> Result<&mut FrameMeta, FrameError> {
        let m = self
            .meta
            .iter_mut()
            .find(|m| m.address == h.address)
            .ok_or(FrameError::Stale)?;
        if m.generation != h.generation {
            return Err(FrameError::Stale);
        }
        Ok(m)
    }
    pub fn begin_revoke(&mut self, h: FrameHandle, owner: TaskId) -> Result<(), FrameError> {
        let m = self.find(h)?;
        if m.owner != Some(owner) {
            return Err(FrameError::Owner);
        }
        if m.state != State::Owned {
            return Err(FrameError::Stale);
        }
        m.state = State::Revoking;
        Ok(())
    }
    pub fn finish_revoke(
        &mut self,
        h: FrameHandle,
        completion: RevokeComplete,
    ) -> Result<(), FrameError> {
        if completion.0 != h {
            return Err(FrameError::Stale);
        }
        let m = self.find(h)?;
        if m.state != State::Revoking {
            return Err(FrameError::Stale);
        }
        m.owner = None;
        m.state = State::Dirty;
        Ok(())
    }
    pub fn clean_one(&mut self, zeroer: &mut impl PageZeroer) -> Result<bool, FrameError> {
        if let Some(m) = self.meta.iter_mut().find(|m| m.state == State::Dirty) {
            zeroer.zero(m.address)?;
            m.state = State::Clean;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
