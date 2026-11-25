//! Snapshot roots and live views have disjoint identities. Historical reads
//! bypass the mutable live cache and pin their slot until the handle closes.
use super::*;
use crate::snapshot::{
    self, FileReqKey, Gate, Request, RequestRecord, RequestState, RestoreMode, SnapshotKey, State,
};

#[derive(Clone, Copy)]
pub(super) struct Frozen {
    key: SnapshotKey,
    inode_id: usize,
    pub(super) inode: Inode,
}
const _: () = assert!(core::mem::size_of::<Frozen>() <= 384);

pub(super) fn snapshot_error<E>(error: snapshot::Error<E>) -> Error {
    use snapshot::Status;
    match error {
        snapshot::Error::Journal(e) => journal_error(e),
        snapshot::Error::Format(_) => Error::Format,
        snapshot::Error::Status(status) => match status {
            Status::Invalid => Error::Range,
            Status::Corrupt => Error::Format,
            Status::NoSpace => Error::Capacity,
            Status::Stale => Error::Stale,
            Status::Conflict | Status::Sequence => Error::Conflict,
            Status::Busy => Error::Busy,
            Status::Frozen => Error::ReadOnly,
            Status::Retention | Status::Permission => Error::Auth,
            Status::Counter => Error::Overflow,
            Status::NotMounted => Error::NotReady,
            Status::Unknown => Error::Io,
        },
    }
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn canonical(path: &str) -> bool {
    path == "/" || (path.starts_with('/') && !path.ends_with('/') && !path.contains("//"))
}

impl<const C: usize> FileSystem<C> {
    pub fn live_view_epoch(&self) -> u64 {
        self.snapshots.control.live_view_epoch
    }
    pub fn snapshot_live_epoch(&self) -> Result<u64, Error> {
        self.check()?;
        Ok(self.live_view_epoch())
    }
    pub fn snapshot_uuid(&self) -> Result<[u8; 16], Error> {
        self.check()?;
        Ok(self.snapshots.control.fs_uuid)
    }
    pub fn snapshot_control(&self) -> Result<snapshot::Control, Error> {
        self.check()?;
        Ok(self.snapshots.control)
    }
    pub fn snapshot_entries(&self) -> Result<[snapshot::Entry; 8], Error> {
        self.check()?;
        Ok(self.snapshots.catalog.entries)
    }
    pub fn snapshot_root_refs(&self, slot: usize) -> Result<u32, Error> {
        self.check()?;
        if slot >= 8 {
            return Err(Error::Range);
        }
        Ok(self
            .frozen
            .iter()
            .flatten()
            .filter(|f| f.key.slot as usize == slot)
            .count() as u32)
    }
    pub fn is_snapshot_handle(&self, h: Handle) -> Result<bool, Error> {
        Ok(self.opened(h)?.frozen.is_some())
    }
    pub fn handle_mode(&self, h: Handle) -> Result<OpenMode, Error> {
        Ok(self.opened(h)?.mode)
    }
    pub fn snapshot_handle_object(&self, h: Handle) -> Result<ObjectKey, Error> {
        let open = self.opened(h)?;
        if open.frozen.is_none() {
            return Err(Error::Auth);
        }
        Ok(ObjectKey {
            id: open.inode as u64,
            generation: open.object_generation,
        })
    }
    pub(super) fn check_writes(&mut self, j: &Journal) -> Result<(), Error> {
        self.check_journal(j)?;
        if self.snapshots.control.business_write_gate != Gate::Open {
            return Err(Error::ReadOnly);
        }
        if !self.snapshots.writes_open() || self.capture_barrier.is_some() {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn flush_all<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        while let Some(id) = self
            .cache
            .iter()
            .find(|p| p.valid && p.dirty)
            .map(|p| p.inode)
        {
            self.flush_inode(id, 32, 0, j, d, s)?
                .ok_or(Error::Conflict)?;
        }
        Ok(())
    }
    fn reload_business<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        validation::load_table(&mut self.inodes, INODE_START, 14, j, d, s, &mut self.tx[0])?;
        for i in 0..BUSINESS_INODE_COUNT as usize {
            self.committed_size[i] = self.inodes[i].size;
            self.write_seq[i] = self.inodes[i].durable_write_seq;
        }
        for map in 0..4 {
            j.read_block(d, BITMAP_START + map as u32, &mut self.tx[0], s)
                .map_err(journal_error)?;
            self.bitmap[map * BLOCK_SIZE..(map + 1) * BLOCK_SIZE].copy_from_slice(&self.tx[0]);
        }
        Ok(())
    }
    fn discard_volatile(&mut self) -> Result<(), Error> {
        if self.cache.iter().any(|p| p.pinned) {
            return Err(Error::Busy);
        }
        for i in 0..C {
            let p = self.cache[i];
            if p.valid && p.dirty {
                self.set_allocated(p.physical, false);
                if p.extent_reservation != 0 {
                    self.set_allocated(p.extent_reservation, false);
                }
            }
            self.cache[i] = Cache::EMPTY;
        }
        self.resident = 0;
        self.metrics.dirty_pages = 0;
        Ok(())
    }
    /// Only use for errors obtained by decoding trusted on-disk roots. Invalid
    /// caller keys/paths/permissions must never be able to freeze the volume.
    pub(super) fn guard_integrity<D: BlockDevice, T>(
        &mut self,
        result: Result<T, Error>,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<T, Error> {
        if let Err(error) = result {
            if matches!(
                error,
                Error::Format | Error::Conflict | Error::Stale | Error::Exists
            ) && let Err(freeze) = self.snapshots.fault_freeze(j, d, s, &mut self.tx)
            {
                self.failed = !j.is_writable();
                return Err(snapshot_error(freeze));
            }
            if !j.is_writable() {
                self.failed = true;
            }
            return Err(error);
        }
        result
    }
    pub(super) fn validate_snapshot_roots<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        let result = self.validate_snapshot_roots_inner(j, d, s);
        self.guard_integrity(result, j, d, s)
    }
    fn validate_snapshot_roots_inner<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        for slot in 0..8 {
            let entry = self.snapshots.catalog.entries[slot];
            if entry.state == State::Free {
                continue;
            }
            if entry.state == State::Active {
                self.snapshots
                    .validate_image(j, d, s, &mut self.tx, slot)
                    .map_err(snapshot_error)?;
            }
            let (ownership, scan) = self.tx[28..36].split_at_mut(4);
            validation::validate_disk_tree(
                entry.inode_first_block,
                &self.bitmap,
                None,
                ownership.as_flattened_mut().try_into().unwrap(),
                scan.try_into().unwrap(),
                j,
                d,
                s,
            )?;
        }
        Ok(())
    }
    fn snapshot_inode<D: BlockDevice>(
        &mut self,
        key: SnapshotKey,
        id: usize,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Inode, Error> {
        if id >= BUSINESS_INODE_COUNT as usize {
            return Err(Error::Auth);
        }
        let entry = self
            .snapshots
            .active(key)
            .map_err(|e| snapshot_error::<D::Error>(e.into()))?;
        j.read_block(
            d,
            entry.inode_first_block + id as u32 / 16,
            &mut self.tx[0],
            s,
        )
        .map_err(journal_error)?;
        Inode::decode(id as u32, &self.tx[0][id % 16 * 256..(id % 16 + 1) * 256])
            .map_err(|_| Error::Format)
    }
    #[allow(clippy::too_many_arguments)]
    fn snapshot_entry<D: BlockDevice>(
        &mut self,
        key: SnapshotKey,
        parent: usize,
        inode: Inode,
        index: usize,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Option<Entry>, Error> {
        if inode.kind != InodeKind::Directory {
            return Err(Error::NotDirectory);
        }
        if index >= inode.size as usize / 128 {
            return Ok(None);
        }
        j.read_block(d, physical(&inode, index as u32 / 32)?, &mut self.tx[0], s)
            .map_err(journal_error)?;
        let raw =
            match DirectoryEntry::decode(&self.tx[0][index % 32 * 128..(index % 32 + 1) * 128]) {
                Ok(entry) => entry,
                Err(_) => return self.guard_integrity(Err(Error::Format), j, d, s),
            };
        if raw == DirectoryEntry::EMPTY {
            return Ok(None);
        }
        let (id, generation) = (raw.inode_id as usize, raw.inode_generation);
        let mut name = [0; 63];
        let length = raw.name.len();
        name[..length].copy_from_slice(raw.name.as_bytes());
        let target = self.snapshot_inode(key, id, j, d, s)?;
        if target.kind == InodeKind::Free
            || target.generation != generation
            || target.parent_inode as usize != parent
            || target.parent_generation != inode.generation
        {
            return Err(Error::Stale);
        }
        Ok(Some(Entry {
            object: ObjectKey {
                id: id as u64,
                generation,
            },
            kind: target.kind,
            name,
            name_len: length as u8,
            next_cookie: index as u16 + 1,
        }))
    }
    fn snapshot_resolve<D: BlockDevice>(
        &mut self,
        key: SnapshotKey,
        path: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(usize, Inode), Error> {
        Self::path(path)?;
        if !canonical(path) {
            return Err(Error::Format);
        }
        let mut id = 0;
        let mut inode = self.snapshot_inode(key, 0, j, d, s)?;
        for part in path.split('/').filter(|v| !v.is_empty()) {
            if inode.kind != InodeKind::Directory {
                return Err(Error::NotDirectory);
            }
            let mut found = None;
            for index in 0..inode.size as usize / 128 {
                if let Some(e) = self.snapshot_entry(key, id, inode, index, j, d, s)?
                    && e.name[..usize::from(e.name_len)] == *part.as_bytes()
                {
                    found = Some(e.object.id as usize);
                    break;
                }
            }
            id = found.ok_or(Error::NotFound)?;
            inode = self.snapshot_inode(key, id, j, d, s)?;
        }
        Ok((id, inode))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot_open<D: BlockDevice>(
        &mut self,
        key: SnapshotKey,
        path: &str,
        prefix: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Handle, Error> {
        self.snapshot_open_partition(key, path, prefix, false, j, d, s)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot_open_recovery<D: BlockDevice>(
        &mut self,
        key: SnapshotKey,
        path: &str,
        prefix: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Handle, Error> {
        self.snapshot_open_partition(key, path, prefix, true, j, d, s)
    }
    #[allow(clippy::too_many_arguments)]
    fn snapshot_open_partition<D: BlockDevice>(
        &mut self,
        key: SnapshotKey,
        path: &str,
        prefix: &str,
        recovery: bool,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Handle, Error> {
        self.check_journal(j)?;
        Self::path(prefix)?;
        if !canonical(prefix)
            || !(prefix == "/"
                || path == prefix
                || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/')))
        {
            return Err(Error::Auth);
        }
        // Resolve the granted prefix in this historical tree. A missing prefix
        // never broadens authority to a surviving parent or the live root.
        self.snapshots
            .active(key)
            .map_err(|e| snapshot_error::<D::Error>(e.into()))?;
        let integrity = self
            .snapshots
            .validate_image(j, d, s, &mut self.tx, key.slot as usize)
            .map_err(snapshot_error);
        self.guard_integrity(integrity, j, d, s)?;
        self.snapshot_resolve(key, prefix, j, d, s)?;
        let (id, inode) = self.snapshot_resolve(key, path, j, d, s)?;
        let handles = if recovery { 112..128 } else { 0..112 };
        let views = if recovery { 56..64 } else { 0..56 };
        let slot = handles
            .into_iter()
            .find(|&i| self.handles[i].is_none())
            .ok_or(Error::Again)?;
        let view = views
            .into_iter()
            .find(|&i| self.frozen[i].is_none())
            .ok_or(Error::Again)?;
        self.handle_generation = self
            .handle_generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.frozen[view] = Some(Frozen {
            key,
            inode_id: id,
            inode,
        });
        self.handles[slot] = Some(Open {
            inode: id,
            object_generation: inode.generation,
            generation: self.handle_generation,
            mode: if inode.kind == InodeKind::Directory {
                OpenMode::Directory
            } else {
                OpenMode::Read
            },
            live_epoch: 0,
            frozen: Some(view),
        });
        Ok(Handle {
            slot: slot as u16,
            generation: self.handle_generation,
        })
    }
    pub(super) fn snapshot_readdir<D: BlockDevice>(
        &mut self,
        view: usize,
        cookie: u16,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Option<Entry>, Error> {
        let frozen = self.frozen[view].ok_or(Error::Stale)?;
        for index in usize::from(cookie)..frozen.inode.size as usize / 128 {
            if let Some(entry) =
                self.snapshot_entry(frozen.key, frozen.inode_id, frozen.inode, index, j, d, s)?
            {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }
    pub(super) fn snapshot_read<D: BlockDevice>(
        &mut self,
        view: usize,
        offset: u64,
        out: &mut [u8],
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<usize, Error> {
        let frozen = self.frozen[view].ok_or(Error::Stale)?;
        if offset >= frozen.inode.size || out.is_empty() {
            return Ok(0);
        }
        let length = out.len().min((frozen.inode.size - offset) as usize);
        let mut map = [0; cow::FILE_BLOCKS];
        let integrity = cow::load_map(frozen.inode_id, &frozen.inode, j, d, s, &mut map);
        self.guard_integrity(integrity, j, d, s)?;
        let mut done = 0;
        while done < length {
            let pos = offset as usize + done;
            j.read_block(d, map[pos / BLOCK_SIZE], &mut self.tx[0], s)
                .map_err(journal_error)?;
            let n = (BLOCK_SIZE - pos % BLOCK_SIZE).min(length - done);
            out[done..done + n]
                .copy_from_slice(&self.tx[0][pos % BLOCK_SIZE..pos % BLOCK_SIZE + n]);
            done += n;
        }
        self.metrics.read_bytes = self.metrics.read_bytes.saturating_add(done as u64);
        Ok(done)
    }
    pub fn snapshot_query_request<D: BlockDevice>(
        &mut self,
        key: FileReqKey,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<RequestRecord, Error> {
        self.check_journal(j)?;
        self.snapshots
            .query_request(j, d, s, &mut self.tx, key)
            .map_err(snapshot_error)
    }
    pub fn snapshot_ack<D: BlockDevice>(
        &mut self,
        key: FileReqKey,
        digest: [u8; 32],
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        self.check_journal(j)?;
        self.snapshots
            .ack(j, d, s, &mut self.tx, key, digest)
            .map_err(snapshot_error)
    }
}

impl<const C: usize> FileSystem<C> {
    fn validate_current_root<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        let (ownership, scan) = self.tx[28..36].split_at_mut(4);
        let integrity = validation::validate_disk_tree(
            INODE_START,
            &self.bitmap,
            None,
            ownership.as_flattened_mut().try_into().unwrap(),
            scan.try_into().unwrap(),
            j,
            d,
            s,
        );
        self.guard_integrity(integrity, j, d, s)
    }
    fn existing_request<D: BlockDevice>(
        &mut self,
        request: Request,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<bool, Error> {
        match self
            .snapshots
            .query_request(j, d, s, &mut self.tx, request.key)
        {
            Ok(_) => Ok(true),
            Err(snapshot::Error::Status(snapshot::Status::Stale)) => Ok(false),
            Err(error) => Err(snapshot_error(error)),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn capture<D: BlockDevice>(
        &mut self,
        request: Request,
        seconds: u64,
        class: snapshot::SlotClass,
        layer: Option<snapshot::PeriodicLayer>,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<RequestRecord, Error> {
        let existing = self.existing_request(request, j, d, s)?;
        let record = self
            .snapshots
            .begin_create(j, d, s, &mut self.tx, request, seconds, class, layer)
            .map_err(snapshot_error)?;
        // Same-key retries return the old result, including an incomplete cut.
        // They never start a fresh drain or select a later capture instant.
        if existing || record.state != RequestState::Pending {
            return Ok(record);
        }
        self.capture_barrier = Some(request.key);
        self.flush_all(j, d, s)?;
        let (ownership, scan) = self.tx[28..36].split_at_mut(4);
        let integrity = validation::validate_disk_tree(
            INODE_START,
            &self.bitmap,
            None,
            ownership.as_flattened_mut().try_into().unwrap(),
            scan.try_into().unwrap(),
            j,
            d,
            s,
        );
        self.guard_integrity(integrity, j, d, s)?;
        let result = self
            .snapshots
            .finish_create(j, d, s, &mut self.tx, request.key)
            .map_err(snapshot_error)?;
        if result.state.terminal() {
            self.capture_barrier = None;
        }
        Ok(result)
    }
    /// The trusted bootstrap opens a newly formatted business namespace only
    /// after both periodic tiers have an initial durable protection point.
    /// A previously frozen or restored volume is never implicitly reopened.
    pub fn initialize_business<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        self.check_journal(j)?;
        let control = self.snapshots.control;
        if control.business_write_gate == Gate::Open {
            return Ok(());
        }
        if control.live_view_epoch != 1
            || control.protection_generation != 1
            || control.cleanup_freeze
            || control.restore_phase != snapshot::RestorePhase::Idle
        {
            return Ok(());
        }
        self.snapshots
            .reap_maintenance_requests(j, d, s, &mut self.tx)
            .map_err(snapshot_error)?;
        for layer in [
            snapshot::PeriodicLayer::Short,
            snapshot::PeriodicLayer::Long,
        ] {
            if layer
                .slots()
                .any(|slot| self.snapshots.catalog.entries[slot].state == State::Active)
            {
                continue;
            }
            let key = self
                .snapshots
                .next_request_key(j, d, s, &mut self.tx, 14)
                .map_err(snapshot_error)?;
            let result = self.capture(
                Request {
                    key,
                    expected_live_view_epoch: 1,
                },
                layer.retention_seconds(),
                snapshot::SlotClass::Periodic,
                Some(layer),
                j,
                d,
                s,
            )?;
            if result.state != RequestState::Done {
                return Err(Error::Busy);
            }
            self.snapshots
                .ack(j, d, s, &mut self.tx, key, result.result_digest)
                .map_err(snapshot_error)?;
        }
        let key = self
            .snapshots
            .next_request_key(j, d, s, &mut self.tx, 15)
            .map_err(snapshot_error)?;
        let generation = self.snapshots.control.protection_generation;
        let result = self
            .snapshots
            .open_writes(
                j,
                d,
                s,
                &mut self.tx,
                Request {
                    key,
                    expected_live_view_epoch: 1,
                },
                generation,
                FileReqKey::ZERO,
            )
            .map_err(snapshot_error)?;
        if result.state != RequestState::Done {
            return Err(Error::Busy);
        }
        self.snapshots
            .ack(j, d, s, &mut self.tx, key, result.result_digest)
            .map_err(snapshot_error)
    }

    /// Typed owner entry used by the versioned broker after capability checks.
    /// Length/reserved-field checks are repeated before any disk side effect.
    // Both automatic rotation and explicit deletion pass the same proof
    // boundary. The exclusive filesystem owner prevents allocation, writes,
    // and new root opens between this validation and the root-drop commit.
    fn delete_with_tree_proof<D: BlockDevice>(
        &mut self,
        request: Request,
        key: SnapshotKey,
        automatic: bool,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<RequestRecord, Error> {
        let refs = self.frozen.iter().flatten().any(|v| v.key == key);
        if key.slot < 6
            && self
                .snapshots
                .periodic_delete_requires_tree_proof(
                    j,
                    d,
                    s,
                    &mut self.tx,
                    request,
                    key,
                    refs,
                    automatic,
                )
                .map_err(snapshot_error)?
        {
            self.validate_snapshot_roots(j, d, s)?;
        }
        self.snapshots
            .delete(j, d, s, &mut self.tx, request, key, refs, automatic)
            .map_err(snapshot_error)
    }

    pub fn snapshot_execute<D: BlockDevice>(
        &mut self,
        request: Request,
        operation: u16,
        payload: &[u8],
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<RequestRecord, Error> {
        self.check_journal(j)?;
        match operation {
            snapshot::OP_CREATE if payload.len() == 16 && u32_at(payload, 12) == 1 => {
                let class =
                    snapshot::SlotClass::try_from(u32_at(payload, 8)).map_err(|_| Error::Schema)?;
                self.capture(request, u64_at(payload, 0), class, None, j, d, s)
            }
            snapshot::OP_EXTEND if payload.len() == 48 => {
                let key = SnapshotKey::decode(&payload[..40]).map_err(|_| Error::Format)?;
                self.snapshots
                    .extend(j, d, s, &mut self.tx, request, key, u64_at(payload, 40))
                    .map_err(snapshot_error)
            }
            snapshot::OP_DELETE if payload.len() == 40 => {
                let key = SnapshotKey::decode(payload).map_err(|_| Error::Format)?;
                self.delete_with_tree_proof(request, key, false, j, d, s)
            }
            snapshot::OP_RESTORE if payload.len() == 48 && u32_at(payload, 44) == 0 => {
                let key = SnapshotKey::decode(&payload[..40]).map_err(|_| Error::Format)?;
                let mode = RestoreMode::try_from(u32_at(payload, 40)).map_err(|_| Error::Format)?;
                if mode == RestoreMode::None {
                    return Err(Error::Range);
                }
                let existing = self.existing_request(request, j, d, s)?;
                let record = self
                    .snapshots
                    .begin_restore(j, d, s, &mut self.tx, request, key, mode)
                    .map_err(snapshot_error)?;
                if existing || record.state != RequestState::Pending {
                    return Ok(record);
                }
                match mode {
                    RestoreMode::PreserveDirty => self.flush_all(j, d, s)?,
                    RestoreMode::DiscardVolatile => self.discard_volatile()?,
                    RestoreMode::None => return Err(Error::Range),
                }
                // Corrupt protected metadata never becomes an empty/replacement
                // root. Keep PREPARING and the write gate frozen on failure.
                self.validate_snapshot_roots(j, d, s)?;
                let result = self
                    .snapshots
                    .finish_restore(j, d, s, &mut self.tx, request.key)
                    .map_err(snapshot_error)?;
                if result.state == RequestState::Done {
                    self.discard_volatile()?;
                    self.reload_business(j, d, s)?;
                    // LIVE handles retain the old epoch and now return ESTALE.
                    // Historical handles keep their own immutable inode image.
                }
                Ok(result)
            }
            snapshot::OP_FREEZE_SET if payload.len() == 16 && u32_at(payload, 12) == 0 => self
                .snapshots
                .freeze(
                    j,
                    d,
                    s,
                    &mut self.tx,
                    request,
                    u64_at(payload, 0),
                    u32_at(payload, 8),
                )
                .map_err(snapshot_error),
            snapshot::OP_FREEZE_CLEAR if payload.len() == 8 => {
                if !self.existing_request(request, j, d, s)? {
                    if request.key.client_slot != 15 {
                        return Err(Error::Auth);
                    }
                    if request.expected_live_view_epoch != 0
                        || u64_at(payload, 0) != self.snapshots.control.protection_generation
                    {
                        return Err(Error::Stale);
                    }
                    if self.capture_barrier.is_some()
                        || self.snapshots.control.restore_phase == snapshot::RestorePhase::Preparing
                    {
                        return Err(Error::Busy);
                    }
                    self.flush_all(j, d, s)?;
                    j.require_quiescent(d).map_err(journal_error)?;
                    self.validate_current_root(j, d, s)?;
                    self.validate_snapshot_roots(j, d, s)?;
                }
                self.snapshots
                    .clear_freeze(j, d, s, &mut self.tx, request, u64_at(payload, 0))
                    .map_err(snapshot_error)
            }
            snapshot::OP_OPEN_WRITES if payload.len() == 48 && u32_at(payload, 44) == 0 => {
                let restored = FileReqKey::decode(&payload[8..44]).map_err(|_| Error::Format)?;
                if !self.existing_request(request, j, d, s)? {
                    if self.capture_barrier.is_some() {
                        return Err(Error::Busy);
                    }
                    let control = self.snapshots.control;
                    if request.key.client_slot != 15 {
                        return Err(Error::Auth);
                    }
                    if request.expected_live_view_epoch != control.live_view_epoch
                        || u64_at(payload, 0) != control.protection_generation
                    {
                        return Err(Error::Stale);
                    }
                    if control.restore_phase == snapshot::RestorePhase::Preparing {
                        return Err(Error::Busy);
                    }
                    self.flush_all(j, d, s)?;
                    j.require_quiescent(d).map_err(journal_error)?;
                    self.validate_current_root(j, d, s)?;
                    self.validate_snapshot_roots(j, d, s)?;
                }
                self.snapshots
                    .open_writes(j, d, s, &mut self.tx, request, u64_at(payload, 0), restored)
                    .map_err(snapshot_error)
            }
            _ => Err(Error::Schema),
        }
    }

    /// Stop-the-world local mark/sweep. The exclusive filesystem owner stops
    /// new writes/opens while this call runs; all BlockDevice calls are joined.
    /// Old blocks are allocatable only after two durable checkpoints.
    pub fn collect_garbage<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<u32, Error> {
        self.check_journal(j)?;
        j.require_quiescent(d).map_err(journal_error)?;
        if self.capture_barrier.is_some() {
            return Err(Error::Busy);
        }
        if self.cache.iter().any(|p| p.pinned) {
            return Err(Error::Busy);
        }
        for frozen in self.frozen.iter().flatten() {
            self.snapshots
                .active(frozen.key)
                .map_err(|e| snapshot_error::<D::Error>(e.into()))?;
        }
        self.flush_all(j, d, s)?;
        self.validate_snapshot_roots(j, d, s)?;
        self.snapshots
            .gc_begin(j, d, s, &mut self.tx)
            .map_err(snapshot_error)?;
        j.checkpoint(d, s).map_err(journal_error)?;
        let (mark_pages, rest) = self.tx[24..36].split_at_mut(4);
        let (ownership, scan) = rest.split_at_mut(4);
        let mark: &mut [u8; MAP_BYTES] = mark_pages.as_flattened_mut().try_into().unwrap();
        let owners: &mut [u8; MAP_BYTES] = ownership.as_flattened_mut().try_into().unwrap();
        let scan: &mut [[u8; BLOCK_SIZE]; 4] = scan.try_into().unwrap();
        mark.fill(0);
        validation::validate_disk_tree(
            INODE_START,
            &self.bitmap,
            Some(mark),
            owners,
            scan,
            j,
            d,
            s,
        )?;
        for entry in self.snapshots.catalog.entries {
            if entry.state != State::Active {
                continue;
            }
            validation::validate_disk_tree(
                entry.inode_first_block,
                &self.bitmap,
                Some(mark),
                owners,
                scan,
                j,
                d,
                s,
            )?;
        }
        let mut released = 0;
        for (&old, &new) in self.bitmap.iter().zip(mark.iter()) {
            released += (old & !new).count_ones();
        }
        self.snapshots
            .gc_publish_pages(j, d, s, &mut self.tx, 24)
            .map_err(snapshot_error)?;
        j.checkpoint(d, s).map_err(journal_error)?;
        j.require_quiescent(d).map_err(journal_error)?;
        self.discard_volatile()?;
        self.snapshots
            .gc_finish(j, d, s, &mut self.tx)
            .map_err(snapshot_error)?;
        self.bitmap.copy_from_slice(self.tx[24..28].as_flattened());
        Ok(released)
    }

    /// Only a trusted monotonic kernel clock calls this method. Wall time,
    /// user requests and AI policy data cannot advance retention age.
    pub fn snapshot_maintenance<D: BlockDevice>(
        &mut self,
        monotonic_now_ns: u64,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        self.check_journal(j)?;
        self.snapshots
            .advance_age(j, d, s, &mut self.tx, monotonic_now_ns)
            .map_err(snapshot_error)?;
        if self.capture_barrier.is_some()
            || self.snapshots.control.restore_phase != snapshot::RestorePhase::Idle
        {
            return Ok(());
        }
        self.snapshots
            .reap_maintenance_requests(j, d, s, &mut self.tx)
            .map_err(snapshot_error)?;
        // Complete previously committed root drops before selecting a new
        // victim. Otherwise one remaining ACTIVE point plus DELETING slots
        // would repeatedly hit last-point retention and starve both tiers.
        if self
            .snapshots
            .catalog
            .entries
            .iter()
            .any(|e| e.state == State::Deleting)
        {
            self.collect_garbage(j, d, s)?;
        }
        for layer in [
            snapshot::PeriodicLayer::Short,
            snapshot::PeriodicLayer::Long,
        ] {
            if !self.snapshots.periodic_due(layer) {
                continue;
            }
            if !layer
                .slots()
                .any(|i| self.snapshots.catalog.entries[i].state == State::Free)
            {
                if self.snapshots.control.cleanup_freeze {
                    continue;
                }
                let candidate = layer
                    .slots()
                    .filter(|&i| {
                        let e = self.snapshots.catalog.entries[i];
                        e.state == State::Active
                            && e.retain_until_ns <= self.snapshots.control.online_age_ns
                            && !self
                                .frozen
                                .iter()
                                .flatten()
                                .any(|v| v.key.slot as usize == i)
                    })
                    .min_by_key(|&i| self.snapshots.catalog.entries[i].created_online_age_ns);
                let Some(slot) = candidate else {
                    continue;
                };
                let key =
                    self.snapshots.catalog.entries[slot].key(self.snapshots.control.fs_uuid, slot);
                let request_key = self
                    .snapshots
                    .next_request_key(j, d, s, &mut self.tx, 14)
                    .map_err(snapshot_error)?;
                let result = self.delete_with_tree_proof(
                    Request {
                        key: request_key,
                        expected_live_view_epoch: 0,
                    },
                    key,
                    true,
                    j,
                    d,
                    s,
                )?;
                self.snapshots
                    .ack(j, d, s, &mut self.tx, request_key, result.result_digest)
                    .map_err(snapshot_error)?;
                self.collect_garbage(j, d, s)?;
            }
            let key = self
                .snapshots
                .next_request_key(j, d, s, &mut self.tx, 14)
                .map_err(snapshot_error)?;
            let result = self.capture(
                Request {
                    key,
                    expected_live_view_epoch: self.live_view_epoch(),
                },
                layer.retention_seconds(),
                snapshot::SlotClass::Periodic,
                Some(layer),
                j,
                d,
                s,
            )?;
            if result.state == RequestState::Done {
                self.snapshots
                    .ack(j, d, s, &mut self.tx, key, result.result_digest)
                    .map_err(snapshot_error)?;
            }
        }
        if self
            .snapshots
            .catalog
            .entries
            .iter()
            .any(|e| e.state == State::Deleting)
        {
            self.collect_garbage(j, d, s)?;
        }
        Ok(())
    }
}
