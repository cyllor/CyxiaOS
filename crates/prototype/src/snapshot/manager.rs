// Every persistent operation explicitly borrows its journal, device, I/O
// scratch and transaction workspace. Bundling these into hidden owned state
// would weaken the single-writer/lifetime boundary; operation parameters stay
// explicit alongside those four owner-provided dependencies.
#![allow(clippy::too_many_arguments)]

use super::codec::*;
use super::requests::*;
use super::*;
use crate::journal::{AfterImage, BlockDevice, CommitReceipt, Journal, Scratch};
use crate::storage::{
    self, BLOCK_SIZE, CATALOG_START, CONTROL_START, INODE_START, SNAPSHOT_REQUEST_START,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
// One bounded request (under 512 bytes) stays on the coordinator stack. The
// no-alloc kernel implementation must not box a lookup result or retain a heap
// allocation merely to equalize the enum's two variants.
#[allow(clippy::large_enum_variant)]
enum Lookup {
    Existing(usize, RequestRecord),
    New(usize, Watermark),
}

/// The owner must serialize this manager with all filesystem transactions.
/// Mount is a cold recovery boundary: old device requests and old references
/// must have been reliably stopped, not merely forgotten by a service restart.
pub struct Manager {
    pub control: Control,
    pub catalog: Catalog,
    mounted: bool,
    age_anchor_ns: Option<u64>,
    // Sample high-water is independent of the conservative charging anchor.
    // Create/extend/commit may clear the latter, never the former.
    age_last_sample_ns: Option<u64>,
    create_token: Option<FileReqKey>,
    restore_token: Option<(FileReqKey, u64)>,
}
impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}
impl Manager {
    pub const fn new() -> Self {
        Self {
            control: Control::initial([0; 16]),
            catalog: Catalog::initial([0; 16]),
            mounted: false,
            age_anchor_ns: None,
            age_last_sample_ns: None,
            create_token: None,
            restore_token: None,
        }
    }
    pub fn control(&self) -> &Control {
        &self.control
    }
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }
    pub fn writes_open(&self) -> bool {
        self.mounted
            && self.control.business_write_gate == Gate::Open
            && self.control.gc_phase == GcPhase::Idle
            && self.control.restore_phase == RestorePhase::Idle
            && self.create_token.is_none()
            && counters_available(&self.control, &self.catalog)
    }
    fn ready<E>(&self, j: &Journal) -> Result<(), Error<E>> {
        if !self.mounted {
            return Err(Status::NotMounted.into());
        }
        if !j.is_writable() {
            return Err(journal::Error::Poisoned.into());
        }
        Ok(())
    }
    pub fn query(&self, key: SnapshotKey) -> Result<Entry, Status> {
        if !self.mounted {
            return Err(Status::NotMounted);
        }
        if key.fs_uuid != self.control.fs_uuid || key.validate().is_err() {
            return Err(Status::Stale);
        }
        let e = self.catalog.entries[key.slot as usize];
        if e.state == State::Free || e.key(self.control.fs_uuid, key.slot as usize) != key {
            return Err(Status::Stale);
        }
        Ok(e)
    }
    pub fn active(&self, key: SnapshotKey) -> Result<Entry, Status> {
        let e = self.query(key)?;
        if e.state != State::Active {
            return Err(Status::Stale);
        }
        Ok(e)
    }

    pub fn mount<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
    ) -> Result<(), Error<D::Error>> {
        let result = self.mount_inner(j, d, s, tx);
        if result.is_err() {
            self.mounted = false;
            self.create_token = None;
            self.restore_token = None;
        }
        result
    }

    fn mount_inner<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
    ) -> Result<(), Error<D::Error>> {
        self.mounted = false;
        self.age_anchor_ns = None;
        self.age_last_sample_ns = None;
        self.create_token = None;
        self.restore_token = None;
        j.require_quiescent(d)?;
        j.read_block(d, CONTROL_START, &mut tx[0], s)?;
        let control = Control::decode(&tx[0])?;
        j.read_block(d, CATALOG_START, &mut tx[1], s)?;
        let catalog = Catalog::decode(&tx[1])?;
        if control.fs_uuid != j.superblock().fs_uuid || catalog.fs_uuid != control.fs_uuid {
            return Err(Status::Corrupt.into());
        }
        self.control = control;
        self.catalog = catalog;
        for slot in 0..8 {
            let e = self.catalog.entries[slot];
            if e.state != State::Free && e.snapshot_id >= self.control.next_snapshot_id {
                return Err(Status::Corrupt.into());
            }
            if e.state == State::Active {
                self.validate_image(j, d, s, tx, slot)?;
            }
        }
        j.read_block(d, SNAPSHOT_REQUEST_START, &mut tx[38], s)?;
        validate_header(&tx[38], self.control.fs_uuid)?;
        // Check every durable record against its fixed account and watermark.
        // Canonical keys borrow an otherwise unused transaction page during
        // this read-only pass instead of adding a 2.5 KiB coordinator array.
        // FREE records retain a zero entry; a valid request key is nonzero.
        const KEY_BYTES: usize = 36;
        tx[2][..RECORDS * KEY_BYTES].fill(0);
        for page in 0..8 {
            j.read_block(d, SNAPSHOT_REQUEST_START + 1 + page as u32, &mut tx[39], s)?;
            for offset in 0..8 {
                let index = page * 8 + offset;
                let record = RequestRecord::decode(&tx[39][record_range(index)])?;
                if record.state == RequestState::Free {
                    d.cpu_progress();
                    continue;
                }
                let wm = watermark(&tx[38], record.key.client_slot as usize)?;
                if record.key.fs_uuid != self.control.fs_uuid
                    || !belongs(index, record.key.client_slot)
                    || record.key.client_generation != wm.client_generation
                    || record.key.request_seq > wm.highest_accepted_seq
                {
                    return Err(Status::Corrupt.into());
                }
                let (previous, current) = tx[2].split_at_mut(index * KEY_BYTES);
                record.key.encode(&mut current[..KEY_BYTES])?;
                if previous
                    .chunks_exact(KEY_BYTES)
                    .any(|key| key == &current[..KEY_BYTES])
                {
                    return Err(Status::Corrupt.into());
                }
                d.cpu_progress();
            }
        }
        // Reserved object pages are not a second, untracked record store.
        for page in 9..16 {
            j.read_block(d, SNAPSHOT_REQUEST_START + page, &mut tx[39], s)?;
            zeros(&tx[39])?;
        }
        if self.control.restore_phase != RestorePhase::Idle {
            let key = self.control.restore_source;
            let entry = self.catalog.entries[key.slot as usize];
            if entry.state != State::Active
                || entry.key(self.control.fs_uuid, key.slot as usize) != key
            {
                return Err(Status::Corrupt.into());
            }
        }
        self.mounted = true;
        // Journal mount has replayed every durable closure and has established
        // the fresh epoch. Remaining PENDING records therefore did not publish.
        for index in 0..RECORDS {
            let mut record = read_record(j, d, s, tx, index, 0)?;
            // The first pass checked every identity and watermark. Release
            // this record's decode cost before advancing its retained state.
            d.cpu_progress();
            if record.state == RequestState::Pending {
                let mut control = self.control;
                if record.operation == OP_RESTORE {
                    if control.restore_phase != RestorePhase::Preparing
                        || control.restore_request != record.key
                    {
                        return Err(Status::Corrupt.into());
                    }
                    control.clear_restore();
                    control.business_write_gate = Gate::Frozen;
                    control.protection_generation = inc(control.protection_generation)?;
                }
                record.state = RequestState::Incomplete;
                record.result_code = -125;
                record.result_payload_len = 0;
                record.result_payload.fill(0);
                control.control_generation = inc(control.control_generation)?;
                prepare(j, d, s, 2)?;
                record.transaction = j.peek_next_commit(2).ok_or(Status::Counter)?.key;
                record.seal_result();
                record.encode(&mut tx[0][record_range(index)])?;
                control.encode(&mut tx[1])?;
                commit_recovery(j, d, s, tx, &[record_page(index), CONTROL_START])?;
                self.control = control;
            } else if record.state == RequestState::Unknown {
                // Unknown external obligations have no safe inferred outcome.
                self.fault_freeze(j, d, s, tx)?;
            }
        }
        if self.control.restore_phase == RestorePhase::Preparing {
            return Err(Status::Corrupt.into());
        }
        match self.control.gc_phase {
            GcPhase::FreeCommitted => {
                j.checkpoint(d, s)?;
                self.gc_finish(j, d, s, tx)?;
            }
            GcPhase::Mark => {
                let mut c = self.control;
                c.gc_phase = GcPhase::Idle;
                self.commit_control(j, d, s, tx, c)?;
            }
            GcPhase::Idle => {}
        }
        Ok(())
    }

    /// Descriptor/image verification is mandatory even before tree validation.
    /// The filesystem owner additionally checks every directory, extent and root.
    pub fn validate_image<D: BlockDevice>(
        &self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        slot: usize,
    ) -> Result<Descriptor, Error<D::Error>> {
        if slot >= 8 {
            return Err(Status::Invalid.into());
        }
        let e = self.catalog.entries[slot];
        if e.state != State::Active {
            return Err(Status::Stale.into());
        }
        j.read_block(d, e.descriptor_block, &mut tx[0], s)?;
        if hash(&tx[0]) != e.descriptor_sha256 {
            return Err(Status::Corrupt.into());
        }
        let descriptor = Descriptor::decode(&tx[0])?;
        if descriptor.key != e.key(self.control.fs_uuid, slot)
            || descriptor.captured_live_view_epoch != e.captured_live_view_epoch
            || descriptor.capture_commit_lsn != e.capture_commit_lsn
            || descriptor.inode_first_block != e.inode_first_block
            || descriptor.created_online_age_ns != e.created_online_age_ns
        {
            return Err(Status::Corrupt.into());
        }
        let mut digest = Sha256::new();
        for page in 0..14 {
            j.read_block(d, e.inode_first_block + page, &mut tx[0], s)?;
            digest.update(tx[0].as_slice());
        }
        let actual: [u8; 32] = digest.finalize().into();
        if actual != descriptor.inode_image_sha256 {
            return Err(Status::Corrupt.into());
        }
        Ok(descriptor)
    }

    fn lookup<D: BlockDevice>(
        &self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        key: FileReqKey,
        digest: Option<[u8; 32]>,
    ) -> Result<Lookup, Error<D::Error>> {
        self.ready(j)?;
        key.validate()?;
        if key.fs_uuid != self.control.fs_uuid {
            return Err(Status::Stale.into());
        }
        j.read_block(d, SNAPSHOT_REQUEST_START, &mut tx[38], s)?;
        validate_header(&tx[38], self.control.fs_uuid)?;
        let wm = watermark(&tx[38], key.client_slot as usize)?;
        if key.client_generation != wm.client_generation {
            return Err(Status::Stale.into());
        }
        let mut empty = None;
        let mut pending = false;
        for index in partition(key.client_slot) {
            let record = read_record(j, d, s, tx, index, 39)?;
            if record.state == RequestState::Free {
                if empty.is_none() {
                    empty = Some(index);
                }
                continue;
            }
            if !belongs(index, record.key.client_slot) {
                return Err(Status::Corrupt.into());
            }
            if record.key == key {
                if digest.is_some_and(|value| value != record.request_digest) {
                    return Err(Status::Conflict.into());
                }
                return Ok(Lookup::Existing(index, record));
            }
            if record.key.client_slot == key.client_slot
                && matches!(record.state, RequestState::Pending | RequestState::Unknown)
            {
                pending = true;
            }
        }
        if digest.is_none() || key.request_seq <= wm.highest_accepted_seq {
            return Err(Status::Stale.into());
        }
        if key.request_seq
            != wm
                .highest_accepted_seq
                .checked_add(1)
                .ok_or(Status::Counter)?
        {
            return Err(Status::Sequence.into());
        }
        if pending {
            return Err(Status::Busy.into());
        }
        Ok(Lookup::New(empty.ok_or(Status::NoSpace)?, wm))
    }
    pub fn query_request<D: BlockDevice>(
        &self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        key: FileReqKey,
    ) -> Result<RequestRecord, Error<D::Error>> {
        match self.lookup(j, d, s, tx, key, None)? {
            Lookup::Existing(_, record) => Ok(record),
            Lookup::New(_, _) => Err(Status::Stale.into()),
        }
    }
    /// Call after authenticating the original principal or registered recovery
    /// supervisor. ACK itself allocates no request slot and preserves watermarks.
    pub fn ack<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        key: FileReqKey,
        result_digest: [u8; 32],
    ) -> Result<(), Error<D::Error>> {
        let (index, record) = match self.lookup(j, d, s, tx, key, None)? {
            Lookup::Existing(i, r) => (i, r),
            Lookup::New(_, _) => return Err(Status::Stale.into()),
        };
        if !record.state.terminal() {
            return Err(Status::Busy.into());
        }
        if record.result_digest != result_digest {
            return Err(Status::Conflict.into());
        }
        read_record(j, d, s, tx, index, 0)?;
        RequestRecord::FREE.encode(&mut tx[0][record_range(index)])?;
        commit_recovery(j, d, s, tx, &[record_page(index)])?;
        Ok(())
    }
    /// The trusted periodic-maintenance owner acknowledges its own verified
    /// terminal results after reboot or a lost reply. This is not an external
    /// ACK shortcut: ordinary and recovery results retain their original owner,
    /// and PENDING/UNKNOWN obligations are never reclaimed here.
    pub fn reap_maintenance_requests<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
    ) -> Result<usize, Error<D::Error>> {
        self.ready(j)?;
        let mut reclaimed = 0;
        let mut loaded_page = None;
        for index in partition(14) {
            let page = record_page(index);
            if loaded_page != Some(page) {
                j.read_block(d, page, &mut tx[39], s)?;
                loaded_page = Some(page);
            }
            let record = RequestRecord::decode(&tx[39][record_range(index)])?;
            if record.state == RequestState::Free {
                d.cpu_progress();
                continue;
            }
            if record.key.client_slot != 14 || record.key.fs_uuid != self.control.fs_uuid {
                return Err(Status::Corrupt.into());
            }
            // A cached page avoids duplicate I/O, but each complete record's
            // CRC/hash/identity work still ends at a bounded CPU boundary.
            // The caller retains the same filesystem and transaction custody.
            d.cpu_progress();
            if record.state.terminal() {
                // decode has already checked the full canonical result digest;
                // ACK rechecks identity/watermark and commits before reuse.
                self.ack(j, d, s, tx, record.key, record.result_digest)?;
                reclaimed += 1;
                // ACK reuses this scratch page and changes the committed view.
                // Reload before decoding the next record, including after a
                // checkpoint performed while closing the acknowledged result.
                loaded_page = None;
            }
        }
        Ok(reclaimed)
    }
    fn pending_exists<D: BlockDevice>(
        &self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        operation: u16,
    ) -> Result<bool, Error<D::Error>> {
        for index in 0..RECORDS {
            let r = read_record(j, d, s, tx, index, 39)?;
            if (operation == 0 || r.operation == operation)
                && matches!(r.state, RequestState::Pending | RequestState::Unknown)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn register<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        index: usize,
        mut wm: Watermark,
        record: RequestRecord,
        control: Option<Control>,
    ) -> Result<(), Error<D::Error>> {
        read_record(j, d, s, tx, index, 0)?;
        record.encode(&mut tx[0][record_range(index)])?;
        j.read_block(d, SNAPSHOT_REQUEST_START, &mut tx[1], s)?;
        validate_header(&tx[1], self.control.fs_uuid)?;
        wm.highest_accepted_seq = record.key.request_seq;
        update_watermark(&mut tx[1], wm)?;
        let mut homes = [record_page(index), SNAPSHOT_REQUEST_START, CONTROL_START];
        let count = if let Some(c) = control {
            c.encode(&mut tx[2])?;
            3
        } else {
            2
        };
        if record.key.client_slot == 15 {
            commit_recovery(j, d, s, tx, &homes[..count])?;
        } else {
            commit(j, d, s, tx, &homes[..count])?;
        }
        if let Some(c) = control {
            self.control = c;
        }
        homes.fill(0);
        Ok(())
    }

    /// Register before the caller's accepted-write barrier. Same-key replay
    /// returns its original state, including a PENDING that must not recapture.
    pub fn begin_create<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        retain_seconds: u64,
        class: SlotClass,
        layer: Option<PeriodicLayer>,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let mut payload = [0u8; 16];
        put64(&mut payload, 0, retain_seconds);
        put32(&mut payload, 8, class as u32);
        put32(&mut payload, 12, 1);
        let digest = request_digest(OP_CREATE, request, &payload)?;
        let (index, wm) = match self.lookup(j, d, s, tx, request.key, Some(digest))? {
            Lookup::Existing(_, r) => return Ok(r),
            Lookup::New(i, w) => (i, w),
        };
        if request.expected_live_view_epoch != self.control.live_view_epoch {
            return Err(Status::Stale.into());
        }
        if self.control.restore_phase != RestorePhase::Idle
            || self.control.gc_phase != GcPhase::Idle
        {
            return Err(Status::Busy.into());
        }
        let seconds = retention_seconds(retain_seconds)?;
        let range = match class {
            SlotClass::OnDemand => {
                if request.key.client_slot >= 14 || layer.is_some() {
                    return Err(Status::Permission.into());
                }
                6..8
            }
            SlotClass::Periodic => {
                if request.key.client_slot != 14 {
                    return Err(Status::Permission.into());
                }
                // FileServiceSchemaV2 carries class and the fixed policy
                // retention, not a separate tier selector. These two values
                // uniquely select the layer for a wire-originated request.
                let layer = match layer {
                    Some(layer) => layer,
                    None if seconds == SHORT_RETENTION_SECONDS => PeriodicLayer::Short,
                    None if seconds == LONG_RETENTION_SECONDS => PeriodicLayer::Long,
                    None => return Err(Status::Retention.into()),
                };
                if seconds != layer.retention_seconds() {
                    return Err(Status::Retention.into());
                }
                layer.slots()
            }
        };
        if self.pending_exists(j, d, s, tx, OP_CREATE)? {
            return Err(Status::Busy.into());
        }
        let slot = range
            .into_iter()
            .find(|i| self.catalog.entries[*i].state == State::Free)
            .ok_or(Status::NoSpace)?;
        let generation = inc(self.catalog.entries[slot].slot_generation)?;
        self.control
            .online_age_ns
            .checked_add(seconds * SECOND_NS)
            .ok_or(Status::Counter)?;
        inc(self.control.next_snapshot_id)?;
        inc(self.control.control_generation)?;
        inc(self.catalog.catalog_generation)?;
        // Both fixed closures fit before starting. Device admission is still
        // checked on each atomic transaction; rejected final admission stays PENDING.
        prepare(j, d, s, 22)?;
        let mut record = RequestRecord::pending(request, OP_CREATE, digest, &payload);
        record.snapshot_key = SnapshotKey {
            fs_uuid: self.control.fs_uuid,
            snapshot_id: self.control.next_snapshot_id,
            slot: slot as u32,
            slot_generation: generation,
        };
        self.register(j, d, s, tx, index, wm, record, None)?;
        self.create_token = Some(record.key);
        Ok(record)
    }
    pub fn finish_create<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        key: FileReqKey,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let (index, mut record) = match self.lookup(j, d, s, tx, key, None)? {
            Lookup::Existing(i, r) => (i, r),
            Lookup::New(_, _) => return Err(Status::Stale.into()),
        };
        if record.state != RequestState::Pending {
            return Ok(record);
        }
        if self.create_token != Some(key) {
            return Err(Status::Busy.into());
        }
        if record.operation != OP_CREATE || record.result_payload_len != 16 {
            return Err(Status::Invalid.into());
        }
        if record.old_live_view_epoch != self.control.live_view_epoch
            || self.control.restore_phase != RestorePhase::Idle
            || self.control.gc_phase != GcPhase::Idle
        {
            return Err(Status::Busy.into());
        }
        let slot = record.snapshot_key.slot as usize;
        let old = self.catalog.entries[slot];
        if old.state != State::Free
            || old.slot_generation.checked_add(1) != Some(record.snapshot_key.slot_generation)
            || record.snapshot_key.snapshot_id != self.control.next_snapshot_id
        {
            return Err(Status::Conflict.into());
        }
        let seconds = retention_seconds(u64_at(record.payload(), 0))?;
        let retain_until = self
            .control
            .online_age_ns
            .checked_add(seconds * SECOND_NS)
            .ok_or(Status::Counter)?;
        let capture_lsn = j.last_commit_lsn();
        let mut digest = Sha256::new();
        for (page, bytes) in tx[1..15].iter_mut().enumerate() {
            j.read_block(d, INODE_START + page as u32, bytes, s)?;
            digest.update(bytes.as_slice());
        }
        let descriptor = Descriptor {
            key: record.snapshot_key,
            captured_live_view_epoch: self.control.live_view_epoch,
            capture_commit_lsn: capture_lsn,
            inode_first_block: descriptor_block(slot) + 1,
            inode_image_sha256: digest.finalize().into(),
            created_online_age_ns: self.control.online_age_ns,
        };
        descriptor.encode(&mut tx[0])?;
        let mut catalog = self.catalog;
        catalog.catalog_generation = inc(catalog.catalog_generation)?;
        catalog.entries[slot] = Entry {
            state: State::Active,
            slot_class: old.slot_class,
            snapshot_id: record.snapshot_key.snapshot_id,
            slot_generation: record.snapshot_key.slot_generation,
            captured_live_view_epoch: self.control.live_view_epoch,
            capture_commit_lsn: capture_lsn,
            created_online_age_ns: self.control.online_age_ns,
            retain_until_ns: retain_until,
            retention_profile: 1,
            scope: 1,
            creator_client_slot: key.client_slot,
            creator_client_generation: key.client_generation,
            creator_request_seq: key.request_seq,
            descriptor_block: descriptor_block(slot),
            inode_first_block: descriptor_block(slot) + 1,
            descriptor_sha256: hash(&tx[0]),
            retention_generation: 1,
            root_drop_commit_lsn: 0,
        };
        let mut control = self.control;
        control.next_snapshot_id = inc(control.next_snapshot_id)?;
        control.control_generation = inc(control.control_generation)?;
        if old.slot_class == SlotClass::Periodic {
            if slot < 3 {
                control.short_last_auto_age_ns = control.online_age_ns;
            } else {
                control.long_last_auto_age_ns = control.online_age_ns;
            }
        }
        catalog.encode(&mut tx[15])?;
        control.encode(&mut tx[16])?;
        read_record(j, d, s, tx, index, 17)?;
        prepare(j, d, s, 18)?;
        record.state = RequestState::Done;
        record.transaction = j.peek_next_commit(18).ok_or(Status::Counter)?.key;
        record.new_live_view_epoch = control.live_view_epoch;
        record.result_payload.fill(0);
        record.result_payload_len = 72;
        record
            .snapshot_key
            .encode(&mut record.result_payload[..40])?;
        put64(&mut record.result_payload, 40, control.live_view_epoch);
        put64(&mut record.result_payload, 48, capture_lsn);
        put64(&mut record.result_payload, 56, control.online_age_ns);
        put64(&mut record.result_payload, 64, retain_until);
        record.seal_result();
        record.encode(&mut tx[17][record_range(index)])?;
        let mut homes = [0u32; 18];
        for (i, home) in homes[..15].iter_mut().enumerate() {
            *home = descriptor_block(slot) + i as u32;
        }
        homes[15] = CATALOG_START;
        homes[16] = CONTROL_START;
        homes[17] = record_page(index);
        commit(j, d, s, tx, &homes)?;
        self.control = control;
        self.catalog = catalog;
        self.create_token = None;
        // Do not later credit pre-creation time against this new retention.
        // A caller with a clock can immediately establish the post-commit anchor.
        self.age_anchor_ns = None;
        Ok(record)
    }
    /// Convenience for a caller already holding the accepted-write barrier.
    /// New callers that must drain dirty pages should use begin/finish_create.
    pub fn create<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        retain_seconds: u64,
        class: SlotClass,
        layer: Option<PeriodicLayer>,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let mut payload = [0u8; 16];
        put64(&mut payload, 0, retain_seconds);
        put32(&mut payload, 8, class as u32);
        put32(&mut payload, 12, 1);
        let digest = request_digest(OP_CREATE, request, &payload)?;
        if let Lookup::Existing(_, r) = self.lookup(j, d, s, tx, request.key, Some(digest))? {
            return Ok(r);
        }
        self.begin_create(j, d, s, tx, request, retain_seconds, class, layer)?;
        self.finish_create(j, d, s, tx, request.key)
    }

    fn single<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        index: usize,
        mut wm: Watermark,
        mut record: RequestRecord,
        control: Option<Control>,
        catalog: Option<Catalog>,
    ) -> Result<RequestRecord, Error<D::Error>> {
        read_record(j, d, s, tx, index, 0)?;
        j.read_block(d, SNAPSHOT_REQUEST_START, &mut tx[1], s)?;
        validate_header(&tx[1], self.control.fs_uuid)?;
        wm.highest_accepted_seq = record.key.request_seq;
        update_watermark(&mut tx[1], wm)?;
        let mut homes = [record_page(index), SNAPSHOT_REQUEST_START, 0, 0];
        let mut count = 2;
        if let Some(c) = control {
            c.encode(&mut tx[count])?;
            homes[count] = CONTROL_START;
            count += 1;
        }
        if let Some(c) = catalog {
            c.encode(&mut tx[count])?;
            homes[count] = CATALOG_START;
            count += 1;
        }
        prepare(j, d, s, count)?;
        record.state = RequestState::Done;
        record.transaction = j.peek_next_commit(count).ok_or(Status::Counter)?.key;
        record.seal_result();
        record.encode(&mut tx[0][record_range(index)])?;
        if record.key.client_slot == 15 {
            commit_recovery(j, d, s, tx, &homes[..count])?;
        } else {
            commit(j, d, s, tx, &homes[..count])?;
        }
        if let Some(c) = control {
            self.control = c;
        }
        if let Some(c) = catalog {
            self.catalog = c;
        }
        Ok(record)
    }
    pub fn extend<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        key: SnapshotKey,
        retain_seconds: u64,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let mut payload = [0u8; 48];
        key.encode(&mut payload[..40])?;
        put64(&mut payload, 40, retain_seconds);
        let digest = request_digest(OP_EXTEND, request, &payload)?;
        let (index, wm) = match self.lookup(j, d, s, tx, request.key, Some(digest))? {
            Lookup::Existing(_, r) => return Ok(r),
            Lookup::New(i, w) => (i, w),
        };
        if request.expected_live_view_epoch != 0 {
            return Err(Status::Invalid.into());
        }
        if self.control.gc_phase != GcPhase::Idle {
            return Err(Status::Busy.into());
        }
        let seconds = retention_seconds(retain_seconds)?;
        let entry = self.active(key)?;
        let deadline = self
            .control
            .online_age_ns
            .checked_add(seconds * SECOND_NS)
            .ok_or(Status::Counter)?
            .max(entry.retain_until_ns);
        let mut catalog = self.catalog;
        catalog.catalog_generation = inc(catalog.catalog_generation)?;
        let e = &mut catalog.entries[key.slot as usize];
        e.retain_until_ns = deadline;
        e.retention_generation = inc(e.retention_generation)?;
        let mut record = RequestRecord::pending(request, OP_EXTEND, digest, &payload);
        record.snapshot_key = key;
        record.result_payload.fill(0);
        record.result_payload_len = 64;
        key.encode(&mut record.result_payload[..40])?;
        put64(&mut record.result_payload, 40, entry.retain_until_ns);
        put64(&mut record.result_payload, 48, deadline);
        put64(&mut record.result_payload, 56, self.control.online_age_ns);
        let result = self.single(j, d, s, tx, index, wm, record, None, Some(catalog))?;
        self.age_anchor_ns = None;
        Ok(result)
    }
    /// `has_refs` covers every root handle, descriptor/image dependency and I/O
    /// obligation. The caller freezes new root opens until this method returns.
    pub fn delete<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        key: SnapshotKey,
        has_refs: bool,
        automatic: bool,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let mut payload = [0u8; 40];
        key.encode(&mut payload)?;
        let digest = request_digest(OP_DELETE, request, &payload)?;
        let (index, wm) = match self.lookup(j, d, s, tx, request.key, Some(digest))? {
            Lookup::Existing(_, r) => return Ok(r),
            Lookup::New(i, w) => (i, w),
        };
        if request.expected_live_view_epoch != 0 {
            return Err(Status::Invalid.into());
        }
        if self.control.cleanup_freeze {
            return Err(Status::Frozen.into());
        }
        if self.control.gc_phase != GcPhase::Idle {
            return Err(Status::Busy.into());
        }
        let entry = self.active(key)?;
        if self.control.online_age_ns < entry.retain_until_ns {
            return Err(Status::Retention.into());
        }
        if has_refs
            || (self.control.restore_phase != RestorePhase::Idle
                && self.control.restore_source == key)
        {
            return Err(Status::Busy.into());
        }
        if automatic && (request.key.client_slot != 14 || entry.slot_class != SlotClass::Periodic) {
            return Err(Status::Permission.into());
        }
        // V0.19.10 candidate: the protection floor applies to every root drop,
        // not only automatic rotation. Explicit delete authority is not a
        // bypass; a second ACTIVE root in the same tier must exist first.
        if entry.slot_class == SlotClass::Periodic {
            let range = if key.slot < 3 { 0..3 } else { 3..6 };
            if range
                .filter(|i| self.catalog.entries[*i].state == State::Active)
                .count()
                < 2
            {
                return Err(Status::Retention.into());
            }
        }
        let mut catalog = self.catalog;
        catalog.catalog_generation = inc(catalog.catalog_generation)?;
        prepare(j, d, s, 3)?;
        let receipt = j.peek_next_commit(3).ok_or(Status::Counter)?;
        let e = &mut catalog.entries[key.slot as usize];
        e.state = State::Deleting;
        e.root_drop_commit_lsn = receipt.commit_lsn;
        let mut record = RequestRecord::pending(request, OP_DELETE, digest, &payload);
        record.snapshot_key = key;
        record.result_payload.fill(0);
        record.result_payload_len = 56;
        key.encode(&mut record.result_payload[..40])?;
        put64(&mut record.result_payload, 40, receipt.commit_lsn);
        put32(&mut record.result_payload, 48, 1);
        self.single(j, d, s, tx, index, wm, record, None, Some(catalog))
    }

    pub fn begin_restore<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        key: SnapshotKey,
        mode: RestoreMode,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let mut payload = [0u8; 48];
        key.encode(&mut payload[..40])?;
        put32(&mut payload, 40, mode as u32);
        let digest = request_digest(OP_RESTORE, request, &payload)?;
        let (index, wm) = match self.lookup(j, d, s, tx, request.key, Some(digest))? {
            Lookup::Existing(_, r) => return Ok(r),
            Lookup::New(i, w) => (i, w),
        };
        if request.key.client_slot != 15 {
            return Err(Status::Permission.into());
        }
        if request.expected_live_view_epoch != self.control.live_view_epoch {
            return Err(Status::Stale.into());
        }
        if mode == RestoreMode::None {
            return Err(Status::Invalid.into());
        }
        if self.control.restore_phase == RestorePhase::Preparing
            || self.control.gc_phase != GcPhase::Idle
            || self.pending_exists(j, d, s, tx, OP_CREATE)?
        {
            return Err(Status::Busy.into());
        }
        self.active(key)?;
        self.validate_image(j, d, s, tx, key.slot as usize)?;
        let mut control = self.control;
        control.control_generation = inc(control.control_generation)?;
        control.restore_phase = RestorePhase::Preparing;
        control.restore_mode = mode;
        control.restore_source = key;
        control.restore_request = request.key;
        control.restore_old_epoch = control.live_view_epoch;
        control.restore_target_epoch = inc(control.live_view_epoch)?;
        control.business_write_gate = Gate::Frozen;
        control.cleanup_freeze = true;
        control.protection_generation = inc(control.protection_generation)?;
        let mut record = RequestRecord::pending(request, OP_RESTORE, digest, &payload);
        record.snapshot_key = key;
        record.restore_mode = mode;
        record.new_live_view_epoch = control.restore_target_epoch;
        prepare(j, d, s, 21)?;
        self.register(j, d, s, tx, index, wm, record, Some(control))?;
        self.restore_token = Some((record.key, control.protection_generation));
        Ok(record)
    }
    /// Caller has resolved all accepted old-view writes according to restore_mode
    /// and has proved their I/O stopped. Unknown commits cannot be discarded.
    pub fn finish_restore<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        key: FileReqKey,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let (index, mut record) = match self.lookup(j, d, s, tx, key, None)? {
            Lookup::Existing(i, r) => (i, r),
            Lookup::New(_, _) => return Err(Status::Stale.into()),
        };
        if record.state != RequestState::Pending {
            return Ok(record);
        }
        if self.restore_token != Some((key, self.control.protection_generation)) {
            return Err(Status::Stale.into());
        }
        if record.operation != OP_RESTORE
            || self.control.restore_phase != RestorePhase::Preparing
            || self.control.restore_request != key
            || self.control.gc_phase != GcPhase::Idle
        {
            return Err(Status::Busy.into());
        }
        let entry = self.active(self.control.restore_source)?;
        self.validate_image(j, d, s, tx, record.snapshot_key.slot as usize)?;
        for (page, bytes) in tx[..14].iter_mut().enumerate() {
            j.read_block(d, entry.inode_first_block + page as u32, bytes, s)?;
        }
        let mut control = self.control;
        control.live_view_epoch = control.restore_target_epoch;
        control.restore_phase = RestorePhase::Published;
        control.control_generation = inc(control.control_generation)?;
        control.protection_generation = inc(control.protection_generation)?;
        control.encode(&mut tx[14])?;
        read_record(j, d, s, tx, index, 15)?;
        prepare(j, d, s, 16)?;
        record.state = RequestState::Done;
        record.transaction = j.peek_next_commit(16).ok_or(Status::Counter)?.key;
        record.new_live_view_epoch = control.live_view_epoch;
        record.result_payload.fill(0);
        record.result_payload_len = 96;
        record
            .snapshot_key
            .encode(&mut record.result_payload[..40])?;
        put64(&mut record.result_payload, 40, record.old_live_view_epoch);
        put64(&mut record.result_payload, 48, record.new_live_view_epoch);
        record.result_payload[56..72].copy_from_slice(&record.transaction.fs_uuid);
        put64(&mut record.result_payload, 72, record.transaction.log_epoch);
        put64(&mut record.result_payload, 80, record.transaction.txid);
        put32(&mut record.result_payload, 88, Gate::Frozen as u32);
        record.seal_result();
        record.encode(&mut tx[15][record_range(index)])?;
        let mut homes = [0u32; 16];
        for (i, h) in homes[..14].iter_mut().enumerate() {
            *h = INODE_START + i as u32;
        }
        homes[14] = CONTROL_START;
        homes[15] = record_page(index);
        commit_recovery(j, d, s, tx, &homes)?;
        self.control = control;
        self.restore_token = None;
        Ok(record)
    }
    pub fn restore<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        key: SnapshotKey,
        mode: RestoreMode,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let mut payload = [0u8; 48];
        key.encode(&mut payload[..40])?;
        put32(&mut payload, 40, mode as u32);
        let digest = request_digest(OP_RESTORE, request, &payload)?;
        if let Lookup::Existing(_, r) = self.lookup(j, d, s, tx, request.key, Some(digest))? {
            return Ok(r);
        }
        self.begin_restore(j, d, s, tx, request, key, mode)?;
        self.finish_restore(j, d, s, tx, request.key)
    }
    pub fn freeze<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        expected_protection_generation: u64,
        reason: u32,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let mut payload = [0u8; 16];
        put64(&mut payload, 0, expected_protection_generation);
        put32(&mut payload, 8, reason);
        self.change_protection(
            j,
            d,
            s,
            tx,
            request,
            OP_FREEZE_SET,
            &payload,
            expected_protection_generation,
            FileReqKey::ZERO,
        )
    }
    pub fn clear_freeze<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        expected_protection_generation: u64,
    ) -> Result<RequestRecord, Error<D::Error>> {
        self.change_protection(
            j,
            d,
            s,
            tx,
            request,
            OP_FREEZE_CLEAR,
            &expected_protection_generation.to_le_bytes(),
            expected_protection_generation,
            FileReqKey::ZERO,
        )
    }
    pub fn open_writes<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        expected_protection_generation: u64,
        completed_restore: FileReqKey,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let mut payload = [0u8; 48];
        put64(&mut payload, 0, expected_protection_generation);
        completed_restore.encode(&mut payload[8..44])?;
        self.change_protection(
            j,
            d,
            s,
            tx,
            request,
            OP_OPEN_WRITES,
            &payload,
            expected_protection_generation,
            completed_restore,
        )
    }
    fn change_protection<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        request: Request,
        operation: u16,
        payload: &[u8],
        expected: u64,
        completed_restore: FileReqKey,
    ) -> Result<RequestRecord, Error<D::Error>> {
        let digest = request_digest(operation, request, payload)?;
        let (index, wm) = match self.lookup(j, d, s, tx, request.key, Some(digest)) {
            Ok(Lookup::Existing(_, r)) => return Ok(r),
            Ok(Lookup::New(i, w)) => (i, w),
            Err(Error::Status(Status::NoSpace))
                if operation == OP_FREEZE_SET
                    && request.key.client_slot == 15
                    && request.expected_live_view_epoch == 0
                    && expected == self.control.protection_generation =>
            {
                // New authorization evidence can be refused when its partition
                // is full; a confirmed protection tightening cannot be blocked
                // by that same pressure. Persist the internal fault guard but
                // do not invent a DONE record for this unaccepted request.
                self.fault_freeze(j, d, s, tx)?;
                return Err(Status::NoSpace.into());
            }
            Err(error) => return Err(error),
        };
        if request.key.client_slot != 15 {
            return Err(Status::Permission.into());
        }
        if self.control.gc_phase != GcPhase::Idle {
            return Err(Status::Busy.into());
        }
        if expected != self.control.protection_generation {
            return Err(Status::Stale.into());
        }
        let required_epoch = if operation == OP_OPEN_WRITES {
            self.control.live_view_epoch
        } else {
            0
        };
        if request.expected_live_view_epoch != required_epoch {
            return Err(Status::Stale.into());
        }
        let mut control = self.control;
        match operation {
            OP_FREEZE_SET => {
                control.cleanup_freeze = true;
                control.business_write_gate = Gate::Frozen;
            }
            OP_FREEZE_CLEAR => {
                if control.restore_phase == RestorePhase::Preparing
                    || self.pending_exists(j, d, s, tx, 0)?
                {
                    return Err(Status::Busy.into());
                }
                control.cleanup_freeze = false;
            }
            OP_OPEN_WRITES => {
                if self.pending_exists(j, d, s, tx, 0)? {
                    return Err(Status::Busy.into());
                }
                if control.business_write_gate != Gate::Frozen {
                    return Err(Status::Busy.into());
                }
                match control.restore_phase {
                    RestorePhase::Preparing => return Err(Status::Busy.into()),
                    RestorePhase::Idle => {
                        if !completed_restore.is_zero() {
                            return Err(Status::Stale.into());
                        }
                    }
                    RestorePhase::Published => {
                        if completed_restore != control.restore_request
                            || control.live_view_epoch != control.restore_target_epoch
                        {
                            return Err(Status::Stale.into());
                        }
                        control.clear_restore();
                    }
                }
                // Initial and recovered operation both require readable coverage
                // in each fixed periodic layer before ordinary writes reopen.
                if !(0..3).any(|i| self.catalog.entries[i].state == State::Active)
                    || !(3..6).any(|i| self.catalog.entries[i].state == State::Active)
                {
                    return Err(Status::Retention.into());
                }
                control.business_write_gate = Gate::Open;
            }
            _ => return Err(Status::Invalid.into()),
        }
        control.control_generation = inc(control.control_generation)?;
        control.protection_generation = inc(control.protection_generation)?;
        // Reopening cannot leave a volume unable to issue its next protection,
        // snapshot, time or GC generation. A historical result was returned
        // before these new-effect predicates, so exhausted counters never
        // turn a completed retry into a second attempt.
        if matches!(operation, OP_FREEZE_CLEAR | OP_OPEN_WRITES)
            && !counters_available(&control, &self.catalog)
        {
            return Err(Status::Counter.into());
        }
        let mut record = RequestRecord::pending(request, operation, digest, payload);
        record.new_live_view_epoch = control.live_view_epoch;
        record.result_payload.fill(0);
        record.result_payload_len = 16;
        put64(&mut record.result_payload, 0, control.protection_generation);
        put32(
            &mut record.result_payload,
            8,
            u32::from(control.cleanup_freeze),
        );
        put32(
            &mut record.result_payload,
            12,
            control.business_write_gate as u32,
        );
        self.single(j, d, s, tx, index, wm, record, Some(control), None)
    }

    fn commit_control<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        mut control: Control,
    ) -> Result<(), Error<D::Error>> {
        control.control_generation = inc(self.control.control_generation)?;
        control.encode(&mut tx[0])?;
        commit_recovery(j, d, s, tx, &[CONTROL_START])?;
        self.control = control;
        Ok(())
    }
    /// Only an authenticated kernel monotonic-clock adapter may call this API.
    /// On each mount the first sample establishes a fresh anchor. No wall-clock,
    /// caller-supplied delta, boot downtime or fractional second receives credit.
    /// Unknown commit poisons the journal; the exact durable target is recovered
    /// on mount rather than recomputed from another sample.
    pub fn advance_age<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        monotonic_now_ns: u64,
    ) -> Result<u64, Error<D::Error>> {
        self.ready(j)?;
        if self.control.gc_phase != GcPhase::Idle {
            return Err(Status::Busy.into());
        }
        if self.age_last_sample_ns.is_some_and(|last| monotonic_now_ns < last) {
            self.fault_freeze(j, d, s, tx)?;
            return Err(Status::Invalid.into());
        }
        self.age_last_sample_ns = Some(monotonic_now_ns);
        let Some(anchor) = self.age_anchor_ns else {
            self.age_anchor_ns = Some(monotonic_now_ns);
            return Ok(self.control.online_age_ns);
        };
        let Some(elapsed) = monotonic_now_ns.checked_sub(anchor) else {
            self.fault_freeze(j, d, s, tx)?;
            return Err(Status::Invalid.into());
        };
        let delta = elapsed / SECOND_NS * SECOND_NS;
        if delta < 60 * SECOND_NS {
            return Ok(self.control.online_age_ns);
        }
        let mut control = self.control;
        let Some(target) = control.online_age_ns.checked_add(delta) else {
            self.fault_freeze(j, d, s, tx)?;
            return Err(Status::Counter.into());
        };
        control.online_age_ns = target;
        let Ok(generation) = inc(control.age_generation) else {
            self.fault_freeze(j, d, s, tx)?;
            return Err(Status::Counter.into());
        };
        control.age_generation = generation;
        self.commit_control(j, d, s, tx, control)?;
        // The next caller's sample begins after this commit; arm it without
        // crediting time spent waiting for this persistence operation.
        self.age_anchor_ns = None;
        Ok(self.control.online_age_ns)
    }
    pub fn periodic_due(&self, layer: PeriodicLayer) -> bool {
        if !self.mounted {
            return false;
        }
        if !layer
            .slots()
            .any(|i| self.catalog.entries[i].state == State::Active)
        {
            return true;
        }
        let last = match layer {
            PeriodicLayer::Short => self.control.short_last_auto_age_ns,
            PeriodicLayer::Long => self.control.long_last_auto_age_ns,
        };
        self.control.online_age_ns.saturating_sub(last) >= layer.period_seconds() * SECOND_NS
    }
    pub fn advance_age_from_clock<D: BlockDevice, C: MonotonicClock>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        clock: &mut C,
    ) -> Result<u64, Error<D::Error>> {
        let Some(before) = clock.monotonic_ns() else {
            self.fault_freeze(j, d, s, tx)?;
            return Err(Status::Invalid.into());
        };
        let age = self.advance_age(j, d, s, tx, before)?;
        if self.age_anchor_ns.is_none() {
            let Some(after) = clock.monotonic_ns() else {
                self.fault_freeze(j, d, s, tx)?;
                return Err(Status::Invalid.into());
            };
            if after < before {
                self.fault_freeze(j, d, s, tx)?;
                return Err(Status::Invalid.into());
            }
            self.age_anchor_ns = Some(after);
            self.age_last_sample_ns = Some(after);
        }
        Ok(age)
    }
    pub fn next_request_key<D: BlockDevice>(
        &self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        client_slot: u32,
    ) -> Result<FileReqKey, Error<D::Error>> {
        self.ready(j)?;
        if client_slot >= 16 {
            return Err(Status::Invalid.into());
        }
        j.read_block(d, SNAPSHOT_REQUEST_START, &mut tx[0], s)?;
        validate_header(&tx[0], self.control.fs_uuid)?;
        let wm = watermark(&tx[0], client_slot as usize)?;
        Ok(FileReqKey {
            fs_uuid: self.control.fs_uuid,
            client_slot,
            client_generation: wm.client_generation,
            request_seq: inc(wm.highest_accepted_seq)?,
        })
    }
    /// Fault tightening has no external request key. Close memory before I/O,
    /// retaining the closed state even when the attempted persistence is unknown.
    pub fn fault_freeze<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
    ) -> Result<(), Error<D::Error>> {
        self.ready(j)?;
        if self.control.cleanup_freeze && self.control.business_write_gate == Gate::Frozen {
            return Ok(());
        }
        self.control.cleanup_freeze = true;
        self.control.business_write_gate = Gate::Frozen;
        let mut control = self.control;
        control.protection_generation = inc(control.protection_generation)?;
        self.commit_control(j, d, s, tx, control)
    }

    /// Caller has frozen allocation, accepted writes, root changes and I/O.
    /// It must checkpoint after this intent and before constructing the mark set.
    pub fn gc_begin<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
    ) -> Result<(), Error<D::Error>> {
        self.ready(j)?;
        if self.control.gc_phase != GcPhase::Idle
            || self.control.restore_phase == RestorePhase::Preparing
            || self.pending_exists(j, d, s, tx, 0)?
        {
            return Err(Status::Busy.into());
        }
        prepare(j, d, s, 1)?;
        let mut control = self.control;
        control.gc_generation = inc(control.gc_generation)?;
        control.gc_phase = GcPhase::Mark;
        control.gc_base_checkpoint_generation = inc(j.superblock().generation)?;
        self.commit_control(j, d, s, tx, control)
    }
    /// Publish only a complete verified mark/sweep bitmap. The caller proves no
    /// reachable block or allocation reservation was cleared. No reuse is allowed
    /// until the subsequent checkpoint, I/O/cache quiescence and gc_finish.
    pub fn gc_publish<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        bitmap: &[u8; 16_384],
    ) -> Result<(), Error<D::Error>> {
        self.ready(j)?;
        if self.control.gc_phase != GcPhase::Mark
            || j.superblock().generation < self.control.gc_base_checkpoint_generation
        {
            return Err(Status::Busy.into());
        }
        for block in 0..storage::FIRST_BUSINESS_BLOCK {
            if bitmap[block as usize / 8] & (1 << (block % 8)) == 0 {
                return Err(Status::Corrupt.into());
            }
        }
        // A sweep may clear allocation bits, never allocate new data blocks.
        for page in 0..4 {
            j.read_block(d, storage::BITMAP_START + page as u32, &mut tx[page], s)?;
            for (new, old) in bitmap[page * BLOCK_SIZE..(page + 1) * BLOCK_SIZE]
                .iter()
                .zip(tx[page].iter())
            {
                if new & !old != 0 {
                    return Err(Status::Corrupt.into());
                }
            }
            tx[page].copy_from_slice(&bitmap[page * BLOCK_SIZE..(page + 1) * BLOCK_SIZE]);
        }
        self.gc_commit_bitmap(j, d, s, tx)
    }

    /// GC's bounded workspace variant: read the four mark pages already in
    /// `tx[first_page..first_page+4]`. Preserve them through publication and
    /// gc_finish, so the allocator can adopt them after the second checkpoint.
    /// Pages 0..=4 are the transaction after-images, hence first_page must be 5+.
    pub fn gc_publish_pages<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
        first_page: usize,
    ) -> Result<(), Error<D::Error>> {
        self.ready(j)?;
        if !(5..=36).contains(&first_page) {
            return Err(Status::Invalid.into());
        }
        if self.control.gc_phase != GcPhase::Mark
            || j.superblock().generation < self.control.gc_base_checkpoint_generation
        {
            return Err(Status::Busy.into());
        }
        let (images, marks) = tx.split_at_mut(first_page);
        for block in 0..storage::FIRST_BUSINESS_BLOCK as usize {
            let byte = block / 8;
            if marks[byte / BLOCK_SIZE][byte % BLOCK_SIZE] & (1 << (block % 8)) == 0 {
                return Err(Status::Corrupt.into());
            }
        }
        for page in 0..4 {
            j.read_block(d, storage::BITMAP_START + page as u32, &mut images[page], s)?;
            for (new, old) in marks[page].iter().zip(images[page].iter()) {
                if new & !old != 0 {
                    return Err(Status::Corrupt.into());
                }
            }
            images[page].copy_from_slice(&marks[page]);
        }
        self.gc_commit_bitmap(j, d, s, tx)
    }

    fn gc_commit_bitmap<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
    ) -> Result<(), Error<D::Error>> {
        prepare(j, d, s, 5)?;
        let mut control = self.control;
        control.gc_phase = GcPhase::FreeCommitted;
        control.control_generation = inc(control.control_generation)?;
        // Store the actual first completed checkpoint, including automatic log
        // checkpoints, so finish requires a strictly later durable checkpoint.
        control.gc_base_checkpoint_generation = j.superblock().generation;
        control.encode(&mut tx[4])?;
        commit_recovery(
            j,
            d,
            s,
            tx,
            &[
                storage::BITMAP_START,
                storage::BITMAP_START + 1,
                storage::BITMAP_START + 2,
                storage::BITMAP_START + 3,
                CONTROL_START,
            ],
        )?;
        self.control = control;
        Ok(())
    }
    pub fn gc_finish<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        tx: &mut Workspace,
    ) -> Result<(), Error<D::Error>> {
        self.ready(j)?;
        if self.control.gc_phase != GcPhase::FreeCommitted
            || j.superblock().generation <= self.control.gc_base_checkpoint_generation
        {
            return Err(Status::Busy.into());
        }
        j.require_quiescent(d)?;
        let mut control = self.control;
        control.gc_phase = GcPhase::Idle;
        control.control_generation = inc(control.control_generation)?;
        let mut catalog = self.catalog;
        let mut changed = false;
        for slot in 0..8 {
            let e = catalog.entries[slot];
            if e.state == State::Deleting {
                catalog.entries[slot] = Entry::free(slot, e.slot_generation);
                changed = true;
            }
        }
        control.encode(&mut tx[0])?;
        if changed {
            catalog.catalog_generation = inc(catalog.catalog_generation)?;
            catalog.encode(&mut tx[1])?;
            commit_recovery(j, d, s, tx, &[CONTROL_START, CATALOG_START])?;
        } else {
            commit_recovery(j, d, s, tx, &[CONTROL_START])?;
        }
        self.control = control;
        self.catalog = catalog;
        Ok(())
    }
}

fn inc(value: u64) -> Result<u64, Status> {
    value.checked_add(1).ok_or(Status::Counter)
}
fn counters_available(control: &Control, catalog: &Catalog) -> bool {
    [
        control.control_generation,
        control.live_view_epoch,
        control.next_snapshot_id,
        control.age_generation,
        control.gc_generation,
        control.protection_generation,
        catalog.catalog_generation,
    ]
    .iter()
    .all(|&value| value != u64::MAX)
        && control.online_age_ns.checked_add(SECOND_NS).is_some()
}
fn retention_seconds(value: u64) -> Result<u64, Status> {
    let value = if value == 0 {
        DEFAULT_RETENTION_SECONDS
    } else {
        value
    };
    if !(MIN_RETENTION_SECONDS..=MAX_RETENTION_SECONDS).contains(&value) {
        return Err(Status::Retention);
    }
    Ok(value)
}
fn prepare<D: BlockDevice>(
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    count: usize,
) -> Result<(), Error<D::Error>> {
    if count == 0 || count > 40 {
        return Err(Status::Invalid.into());
    }
    if j.remaining_log_blocks() < (count as u32 * 2 + 2) {
        j.checkpoint(d, s)?;
    }
    j.peek_next_commit(count).ok_or(Status::Counter)?;
    Ok(())
}
fn commit<D: BlockDevice>(
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    tx: &Workspace,
    homes: &[u32],
) -> Result<CommitReceipt, Error<D::Error>> {
    prepare(j, d, s, homes.len())?;
    commit_prepared(j, d, s, tx, homes)
}
fn commit_recovery<D: BlockDevice>(
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    tx: &Workspace,
    homes: &[u32],
) -> Result<CommitReceipt, Error<D::Error>> {
    // A checkpoint has its own recovery scope. Keep it outside this scope so
    // adapters need not implement nested recovery_enter/recovery_exit hooks.
    prepare(j, d, s, homes.len())?;
    d.recovery_enter();
    let result = commit_prepared(j, d, s, tx, homes);
    d.recovery_exit();
    result
}
fn commit_prepared<D: BlockDevice>(
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    tx: &Workspace,
    homes: &[u32],
) -> Result<CommitReceipt, Error<D::Error>> {
    let mut images = [AfterImage {
        home_block: 0,
        bytes: &tx[0],
    }; 40];
    for (i, &home) in homes.iter().enumerate() {
        images[i] = AfterImage {
            home_block: home,
            bytes: &tx[i],
        };
    }
    Ok(j.commit(d, &images[..homes.len()], s)?)
}
fn read_record<D: BlockDevice>(
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    tx: &mut Workspace,
    index: usize,
    workspace_index: usize,
) -> Result<RequestRecord, Error<D::Error>> {
    if index >= RECORDS {
        return Err(Status::Invalid.into());
    }
    j.read_block(d, record_page(index), &mut tx[workspace_index], s)?;
    Ok(RequestRecord::decode(
        &tx[workspace_index][record_range(index)],
    )?)
}
