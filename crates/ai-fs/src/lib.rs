#![no_std]
#![forbid(unsafe_code)]
//! Single-owner RAM filesystem. AI controls write admission and read cache placement.
//! Snapshot serialization is provided; device persistence belongs to the storage
//! service. No user authentication, background threads, or implicit data eviction.
mod brain;
pub mod checkpoint;
#[rustfmt::skip]
mod weights;
pub use brain::{LearningStatus, ValidationStatus};
use cyxia_contracts::DecisionSource;

pub const NODES: usize = 64;
pub const FILE_BYTES: usize = 4096;
pub const PATH_BYTES: usize = 96;
pub const CACHE_LINES: usize = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPath,
    TooLong,
    NotFound,
    Exists,
    NotDirectory,
    IsDirectory,
    NotEmpty,
    Full,
    TooLarge,
    AiDenied,
    InvalidDecision,
    Exhausted,
    NeedSamples,
    CandidateRejected,
    NoCandidate,
    Stale,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path {
    bytes: [u8; PATH_BYTES],
    len: usize,
}
impl Path {
    pub const ROOT: Self = {
        let mut b = [0; PATH_BYTES];
        b[0] = b'/';
        Self { bytes: b, len: 1 }
    };
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("/")
    }
    pub fn resolve(cwd: Self, input: &str) -> Result<Self, Error> {
        if input.is_empty() {
            return Err(Error::InvalidPath);
        }
        let mut out = if input.starts_with('/') {
            Self::ROOT
        } else {
            cwd
        };
        for part in input.split('/') {
            match part {
                "" | "." => continue,
                ".." => {
                    out = out.parent();
                }
                _ => {
                    // Paths are UTF-8 in this VFS. Spaces and Unicode are
                    // ordinary names; NUL is never a pathname byte.
                    if part.as_bytes().contains(&0) {
                        return Err(Error::InvalidPath);
                    }
                    let sep = usize::from(out.len > 1);
                    if out.len + sep + part.len() >= PATH_BYTES {
                        return Err(Error::TooLong);
                    }
                    if sep == 1 {
                        out.bytes[out.len] = b'/';
                        out.len += 1;
                    }
                    out.bytes[out.len..out.len + part.len()].copy_from_slice(part.as_bytes());
                    out.len += part.len();
                }
            }
        }
        // Canonical trailing bytes ensure structural equality after '..'.
        out.bytes[out.len..].fill(0);
        Ok(out)
    }
    pub fn parent(self) -> Self {
        if self.len == 1 {
            return self;
        }
        let mut p = self;
        p.len = self.bytes[..self.len]
            .iter()
            .rposition(|b| *b == b'/')
            .unwrap_or(0)
            .max(1);
        p.bytes[p.len..].fill(0);
        p
    }
    pub fn name(&self) -> &str {
        self.as_str().rsplit('/').next().unwrap_or("")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
}
#[derive(Clone, Copy)]
struct Node {
    path: Path,
    kind: Kind,
    used: bool,
    linked: bool,
    serial: u64,
    pins: u16,
    boot_children: bool,
    mode: u16,
    len: usize,
    data: [u8; FILE_BYTES],
    reads: u8,
    last: u64,
}
impl Node {
    const EMPTY: Self = Self {
        path: Path::ROOT,
        kind: Kind::File,
        used: false,
        linked: false,
        serial: 0,
        pins: 0,
        boot_children: false,
        mode: 0o666,
        len: 0,
        data: [0; FILE_BYTES],
        reads: 0,
        last: 0,
    };
}
#[derive(Clone, Copy)]
struct Cached {
    id: Option<usize>,
    len: usize,
    data: [u8; FILE_BYTES],
}
impl Cached {
    const EMPTY: Self = Self {
        id: None,
        len: 0,
        data: [0; FILE_BYTES],
    };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inode {
    index: usize,
    serial: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub path: Path,
    pub kind: Kind,
    pub len: usize,
    pub reads: u8,
    pub cached: bool,
    pub mode: u16,
}
#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub nodes: usize,
    pub bytes: usize,
    pub revision: u64,
    pub decisions: u64,
    pub denied: u64,
    pub hits: u64,
    pub misses: u64,
    pub last_source: DecisionSource,
    pub model: LearningStatus,
    pub policy: PolicyStatus,
}
/// Independent action counts; ordinary copies with no cache-slot competition
/// are mechanisms and must not inflate the model-selection denominator.
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyStatus {
    pub admission_proposals: u64,
    pub admission_allowed: u64,
    pub admission_denied: u64,
    pub capacity_rejected: u64,
    pub cache_proposals: u64,
    pub cache_selected: u64,
    pub cache_rejected: u64,
    pub cache_mechanisms: u64,
}
impl PolicyStatus {
    const EMPTY: Self = Self {
        admission_proposals: 0,
        admission_allowed: 0,
        admission_denied: 0,
        capacity_rejected: 0,
        cache_proposals: 0,
        cache_selected: 0,
        cache_rejected: 0,
        cache_mechanisms: 0,
    };
}
struct CacheDecision {
    revision: u64,
    model: u64,
    ids: [Option<usize>; CACHE_LINES],
    ai_selected: bool,
}
pub struct FileSystem {
    nodes: [Node; NODES],
    cache: [Cached; CACHE_LINES],
    brain: brain::Brain,
    revision: u64,
    clock: u64,
    decisions: u64,
    denied: u64,
    hits: u64,
    misses: u64,
    last_source: DecisionSource,
    policy: PolicyStatus,
}
impl Default for FileSystem {
    fn default() -> Self {
        Self::new()
    }
}
impl FileSystem {
    pub const fn new() -> Self {
        Self {
            nodes: [Node::EMPTY; NODES],
            cache: [Cached::EMPTY; CACHE_LINES],
            brain: brain::Brain::new(),
            revision: 1,
            clock: 0,
            decisions: 0,
            denied: 0,
            hits: 0,
            misses: 0,
            last_source: DecisionSource::Bootstrap,
            policy: PolicyStatus::EMPTY,
        }
    }
    fn find(&self, p: Path) -> Result<usize, Error> {
        self.nodes
            .iter()
            .position(|n| n.used && n.linked && n.path == p)
            .ok_or(Error::NotFound)
    }
    pub fn stat(&self, p: Path) -> Result<Entry, Error> {
        if p == Path::ROOT {
            return Ok(Entry {
                path: p,
                kind: Kind::Directory,
                len: 0,
                reads: 0,
                cached: false,
                mode: 0o777,
            });
        }
        let i = self.find(p)?;
        let n = &self.nodes[i];
        Ok(Entry {
            path: p,
            kind: n.kind,
            len: n.len,
            reads: n.reads,
            cached: self.cache.iter().any(|c| c.id == Some(i)),
            mode: n.mode,
        })
    }
    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.used && n.linked)
            .map(|(i, n)| Entry {
                path: n.path,
                kind: n.kind,
                len: n.len,
                reads: n.reads,
                cached: self.cache.iter().any(|c| c.id == Some(i)),
                mode: n.mode,
            })
    }
    pub fn status(&self) -> Status {
        Status {
            nodes: self.nodes.iter().filter(|n| n.used).count(),
            bytes: self.nodes.iter().filter(|n| n.used).map(|n| n.len).sum(),
            revision: self.revision,
            decisions: self.decisions,
            denied: self.denied,
            hits: self.hits,
            misses: self.misses,
            last_source: self.last_source,
            model: self.brain.status(),
            policy: self.policy,
        }
    }
    fn directory(&self, p: Path) -> Result<(), Error> {
        if self.stat(p)?.kind != Kind::Directory {
            Err(Error::NotDirectory)
        } else {
            Ok(())
        }
    }
    fn admit(&mut self, new: bool, growth: usize) -> Result<u64, Error> {
        let next = self.revision.checked_add(1).ok_or(Error::Exhausted)?;
        let free = self.nodes.iter().filter(|n| !n.used).count();
        if new && free == 0 {
            self.policy.capacity_rejected = self.policy.capacity_rejected.saturating_add(1);
            self.last_source = DecisionSource::SafetyGuard;
            return Err(Error::Full);
        }
        self.policy.admission_proposals = self.policy.admission_proposals.saturating_add(1);
        self.decisions = self.decisions.saturating_add(1);
        self.last_source = DecisionSource::AiDirect;
        if !self.brain.admit(free - usize::from(new), growth) {
            self.denied = self.denied.saturating_add(1);
            self.policy.admission_denied = self.policy.admission_denied.saturating_add(1);
            return Err(Error::AiDenied);
        }
        self.policy.admission_allowed = self.policy.admission_allowed.saturating_add(1);
        Ok(next)
    }
    fn changed(&mut self, next: u64) {
        self.revision = next;
        self.brain.invalidate_history();
        // Write-through backing store is authoritative. Invalidate all read copies on mutation.
        self.cache = [Cached::EMPTY; CACHE_LINES];
    }
    pub fn mkdir(&mut self, p: Path) -> Result<(), Error> {
        if self.stat(p).is_ok() {
            return Err(Error::Exists);
        }
        self.directory(p.parent())?;
        let next = self.admit(true, 0)?;
        let i = self.nodes.iter().position(|n| !n.used).ok_or(Error::Full)?;
        self.nodes[i] = Node {
            path: p,
            kind: Kind::Directory,
            used: true,
            linked: true,
            serial: next,
            mode: 0o777,
            ..Node::EMPTY
        };
        self.changed(next);
        Ok(())
    }
    /// Atomic bounded write: failed validation/admission leaves existing bytes intact.
    pub fn write(&mut self, p: Path, data: &[u8], append: bool) -> Result<(), Error> {
        if p == Path::ROOT {
            return Err(Error::IsDirectory);
        }
        self.directory(p.parent())?;
        let existing = self.find(p).ok();
        if existing.is_some_and(|i| self.nodes[i].kind == Kind::Directory) {
            return Err(Error::IsDirectory);
        }
        let old = existing.map_or(0, |i| self.nodes[i].len);
        let start = if append { old } else { 0 };
        let len = start.checked_add(data.len()).ok_or(Error::TooLarge)?;
        if len > FILE_BYTES {
            return Err(Error::TooLarge);
        }
        let next = self.admit(existing.is_none(), len.saturating_sub(old))?;
        let i = match existing {
            Some(i) => i,
            None => self.nodes.iter().position(|n| !n.used).ok_or(Error::Full)?,
        };
        if existing.is_none() {
            self.nodes[i] = Node {
                path: p,
                used: true,
                linked: true,
                serial: next,
                ..Node::EMPTY
            };
        }
        let n = &mut self.nodes[i];
        n.data[start..len].copy_from_slice(data);
        n.data[len..].fill(0);
        n.len = len;
        self.changed(next);
        Ok(())
    }
    /// Register an immutable boot-catalog child after ordinary directory
    /// creation. This only records BOOTSTRAP metadata; it never allocates a node
    /// or bypasses the AI policy that admitted the parent directory.
    pub fn register_boot_file(&mut self, path: Path) -> Result<(), Error> {
        if path == Path::ROOT {
            return Err(Error::InvalidPath);
        }
        let parent = path.parent();
        self.directory(parent)?;
        if parent != Path::ROOT {
            let index = self.find(parent)?;
            self.nodes[index].boot_children = true;
        }
        Ok(())
    }
    /// Atomically rename a regular file, retaining both open inode identities
    /// when replacing a destination. Directory/subtree moves are not yet part
    /// of this bounded operation. The syscall adapter checks both parents and
    /// rejects collisions with its separate immutable boot-file catalog.
    pub fn rename_file(&mut self, from: Path, to: Path, no_replace: bool) -> Result<(), Error> {
        let source = self.find(from)?;
        if self.nodes[source].kind != Kind::File || to == Path::ROOT {
            return Err(Error::IsDirectory);
        }
        self.directory(to.parent())?;
        let destination = self.find(to).ok();
        if no_replace && destination.is_some() {
            return Err(Error::Exists);
        }
        if from == to {
            return Ok(());
        }
        if destination.is_some_and(|i| self.nodes[i].kind != Kind::File) {
            return Err(Error::IsDirectory);
        }
        let next = self.admit(false, 0)?;
        if let Some(index) = destination {
            if self.nodes[index].pins == 0 {
                self.nodes[index] = Node::EMPTY;
            } else {
                self.nodes[index].linked = false;
            }
        }
        self.nodes[source].path = to;
        self.changed(next);
        Ok(())
    }
    pub fn remove(&mut self, p: Path, directory: bool) -> Result<(), Error> {
        if p == Path::ROOT {
            return Err(Error::InvalidPath);
        }
        let i = self.find(p)?;
        if directory {
            if self.nodes[i].kind != Kind::Directory {
                return Err(Error::NotDirectory);
            }
            if self.nodes[i].boot_children
                || self
                    .nodes
                    .iter()
                    .any(|n| n.used && n.linked && n.path.parent() == p)
            {
                return Err(Error::NotEmpty);
            }
        } else if self.nodes[i].kind != Kind::File {
            return Err(Error::IsDirectory);
        }
        let next = self.revision.checked_add(1).ok_or(Error::Exhausted)?;
        if self.nodes[i].pins == 0 {
            self.nodes[i] = Node::EMPTY;
        } else {
            self.nodes[i].linked = false;
        }
        self.changed(next);
        self.last_source = DecisionSource::Operator;
        Ok(())
    }
    fn features(&self) -> ([[i32; 4]; NODES], [bool; NODES]) {
        let mut x = [[0; 4]; NODES];
        let mut valid = [false; NODES];
        for (i, n) in self.nodes.iter().enumerate() {
            if n.used && n.kind == Kind::File {
                valid[i] = true;
                x[i] = [
                    1,
                    n.reads as i32,
                    self.clock.saturating_sub(n.last).min(16) as i32,
                    // The cache-ranking model was trained on 1..4 units.
                    n.len.div_ceil(256).clamp(1, 4) as i32,
                ];
            }
        }
        (x, valid)
    }
    fn proposal(&mut self) -> CacheDecision {
        let (x, valid) = self.features();
        let ai_selected = valid.iter().filter(|valid| **valid).count() > CACHE_LINES;
        if ai_selected {
            self.policy.cache_proposals = self.policy.cache_proposals.saturating_add(1);
        }
        let mut ids = [None; CACHE_LINES];
        for slot in 0..CACHE_LINES {
            let mut best = None;
            for i in 0..NODES {
                if valid[i]
                    && !ids.contains(&Some(i))
                    && best.is_none_or(|b: usize| {
                        ai_selected && self.brain.rank(x[i]) > self.brain.rank(x[b])
                    })
                {
                    best = Some(i);
                }
            }
            ids[slot] = best;
        }
        CacheDecision {
            revision: self.revision,
            model: self.brain.status().version,
            ids,
            ai_selected,
        }
    }
    fn commit_cache(&mut self, p: CacheDecision) -> Result<(), Error> {
        if p.revision != self.revision || p.model != self.brain.status().version {
            self.policy.cache_rejected = self.policy.cache_rejected.saturating_add(1);
            self.last_source = DecisionSource::SafetyGuard;
            return Err(Error::InvalidDecision);
        }
        for (slot, id) in p.ids.iter().enumerate() {
            if let Some(i) = id
                && (*i >= NODES
                    || !self.nodes[*i].used
                    || self.nodes[*i].kind != Kind::File
                    || p.ids[..slot].contains(id))
            {
                self.policy.cache_rejected = self.policy.cache_rejected.saturating_add(1);
                self.last_source = DecisionSource::SafetyGuard;
                return Err(Error::InvalidDecision);
            }
        }
        for (c, id) in self.cache.iter_mut().zip(p.ids) {
            *c = match id {
                Some(i) => Cached {
                    id: Some(i),
                    len: self.nodes[i].len,
                    data: self.nodes[i].data,
                },
                None => Cached::EMPTY,
            };
        }
        if p.ai_selected {
            self.policy.cache_selected = self.policy.cache_selected.saturating_add(1);
            self.decisions = self.decisions.saturating_add(1);
            self.last_source = DecisionSource::AiDirect;
        } else {
            self.policy.cache_mechanisms = self.policy.cache_mechanisms.saturating_add(1);
            self.last_source = DecisionSource::Mechanism;
        }
        Ok(())
    }
    pub fn read(&mut self, p: Path, out: &mut [u8]) -> Result<usize, Error> {
        if self.stat(p)?.kind != Kind::File {
            return Err(Error::IsDirectory);
        }
        let i = self.find(p)?;
        self.read_index(i, out)
    }
    fn read_index(&mut self, i: usize, out: &mut [u8]) -> Result<usize, Error> {
        let len = self.nodes[i].len;
        if out.len() < len {
            return Err(Error::TooLarge);
        }
        let next = self.clock.checked_add(1).ok_or(Error::Exhausted)?;
        if let Some(c) = self.cache.iter().find(|c| c.id == Some(i)) {
            out[..c.len].copy_from_slice(&c.data[..c.len]);
            self.hits = self.hits.saturating_add(1);
        } else {
            out[..len].copy_from_slice(&self.nodes[i].data[..len]);
            self.misses = self.misses.saturating_add(1);
        }
        self.clock = next;
        self.nodes[i].reads = self.nodes[i].reads.saturating_add(1).min(16);
        self.nodes[i].last = next;
        let (x, valid) = self.features();
        self.brain.observe_read(i, x, valid);
        let proposal = self.proposal();
        self.commit_cache(proposal)?;
        Ok(len)
    }
    pub fn pin(&mut self, p: Path) -> Result<Inode, Error> {
        let i = self.find(p)?;
        if self.nodes[i].kind != Kind::File {
            return Err(Error::IsDirectory);
        }
        self.nodes[i].pins = self.nodes[i].pins.checked_add(1).ok_or(Error::Full)?;
        Ok(Inode {
            index: i,
            serial: self.nodes[i].serial,
        })
    }
    /// Root has permanent lifetime; other open directories retain an inode
    /// even when removed so a replacement pathname cannot alias the handle.
    pub fn pin_directory(&mut self, p: Path) -> Result<Option<Inode>, Error> {
        if p == Path::ROOT {
            return Ok(None);
        }
        let i = self.find(p)?;
        if self.nodes[i].kind != Kind::Directory {
            return Err(Error::NotDirectory);
        }
        self.nodes[i].pins = self.nodes[i].pins.checked_add(1).ok_or(Error::Full)?;
        Ok(Some(Inode {
            index: i,
            serial: self.nodes[i].serial,
        }))
    }
    /// Stable slot cookies for directory iteration, including deleted holes.
    pub fn directory_entry(&self, directory: Path, index: usize) -> Option<Entry> {
        let node = self.nodes.get(index)?;
        if !node.used || !node.linked || node.path.parent() != directory {
            return None;
        }
        self.stat(node.path).ok()
    }
    fn inode_index(&self, h: Inode) -> Result<usize, Error> {
        let n = self.nodes.get(h.index).ok_or(Error::Stale)?;
        if !n.used || n.serial != h.serial || n.pins == 0 {
            return Err(Error::Stale);
        }
        Ok(h.index)
    }
    pub fn unpin(&mut self, h: Inode) -> Result<(), Error> {
        let i = self.inode_index(h)?;
        self.nodes[i].pins -= 1;
        if self.nodes[i].pins == 0 && !self.nodes[i].linked {
            self.nodes[i] = Node::EMPTY;
            self.cache = [Cached::EMPTY; CACHE_LINES];
            self.brain.invalidate_history();
        }
        Ok(())
    }
    pub fn inode_len(&self, h: Inode) -> Result<usize, Error> {
        Ok(self.nodes[self.inode_index(h)?].len)
    }
    pub fn inode_info(&self, h: Inode) -> Result<(u64, usize, u16, bool), Error> {
        let node = &self.nodes[self.inode_index(h)?];
        Ok((node.serial, node.len, node.mode, node.linked))
    }
    pub fn identity(&self, path: Path) -> Result<u64, Error> {
        if path == Path::ROOT {
            return Ok(1);
        }
        Ok(self.nodes[self.find(path)?].serial + 1)
    }
    pub fn read_at(&mut self, h: Inode, offset: usize, out: &mut [u8]) -> Result<usize, Error> {
        let i = self.inode_index(h)?;
        if self.nodes[i].kind != Kind::File {
            return Err(Error::IsDirectory);
        }
        if out.is_empty() || offset >= self.nodes[i].len {
            return Ok(0);
        }
        let mut bytes = [0; FILE_BYTES];
        let len = self.read_index(i, &mut bytes)?;
        let n = out.len().min(len - offset);
        out[..n].copy_from_slice(&bytes[offset..offset + n]);
        Ok(n)
    }
    /// Positional write preserves the suffix and zero-fills holes. AI rejection is atomic.
    pub fn write_at(&mut self, h: Inode, offset: usize, data: &[u8]) -> Result<usize, Error> {
        let i = self.inode_index(h)?;
        if self.nodes[i].kind != Kind::File {
            return Err(Error::IsDirectory);
        }
        if data.is_empty() {
            return Ok(0);
        }
        if offset >= FILE_BYTES {
            return Err(Error::TooLarge);
        }
        let count = data.len().min(FILE_BYTES - offset);
        let end = offset + count;
        let old = self.nodes[i].len;
        let next = self.admit(false, end.saturating_sub(old))?;
        let n = &mut self.nodes[i];
        if offset > old {
            n.data[old..offset].fill(0);
        }
        n.data[offset..end].copy_from_slice(&data[..count]);
        n.len = old.max(end);
        self.changed(next);
        Ok(count)
    }
    /// Mode metadata for the single-UID compatibility layer; shell remains the trusted operator.
    pub fn set_mode(&mut self, p: Path, mode: u16) -> Result<(), Error> {
        let i = self.find(p)?;
        self.nodes[i].mode = mode & 0o7777;
        Ok(())
    }
    pub fn set_inode_mode(&mut self, inode: Inode, mode: u16) -> Result<(), Error> {
        let i = self.inode_index(inode)?;
        self.nodes[i].mode = mode & 0o7777;
        Ok(())
    }
    pub fn train(&mut self) -> Result<(), Error> {
        self.brain.train()
    }
    pub fn apply(&mut self) -> Result<(), Error> {
        self.brain.apply()?;
        self.cache = [Cached::EMPTY; CACHE_LINES];
        self.last_source = DecisionSource::Operator;
        Ok(())
    }
    pub fn rollback(&mut self) -> Result<(), Error> {
        self.brain.rollback()?;
        self.cache = [Cached::EMPTY; CACHE_LINES];
        self.last_source = DecisionSource::Operator;
        Ok(())
    }
}
#[cfg(test)]
mod tests;
