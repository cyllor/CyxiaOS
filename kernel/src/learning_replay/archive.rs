//! Bounded native journal export. Capture/history retirement requires a real
//! fsync and readback hash, including excluded trials and their actual timing.
use crate::domain_control::replay::{Preparation, UnpublishedClose};
use crate::{domain_storage as files, learning_evidence as capture, learning_history as history};
use cyxia_prototype::{
    domains::{
        Error, ObjectKey,
        filesystem::{Handle, OpenMode},
    },
    learning::{
        capture::{FrozenRequest, RequestTiming, RunKey, Seal, Source},
        reward::{CpuClass, CpuInterval, RequestResult, WorkRequest},
    },
};
use sha2::{Digest, Sha256};
const HEADER: usize = 2048;
const CPU_ROW: usize = 64;
const REQUEST_ROW: usize = 128;
const CHUNK: usize = super::archive_packet::CHUNK;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    Write,
    Sync,
    Read,
    Close,
    Done,
}
/// Constructed only after this exact journal range has been fsynced, read
/// back with the same digest, and closed. Its fields cannot be forged by a
/// caller asking the root to release an unactivated capture.
#[derive(Clone, Copy)]
pub struct Export {
    unpublished: Option<UnpublishedClose>,
    key: RunKey,
    object: ObjectKey,
    offset: u64,
    bytes: usize,
    digest: [u8; 32],
}
impl Export {
    pub fn unpublished(self) -> Option<UnpublishedClose> {
        self.unpublished
    }
    pub fn key(self) -> RunKey {
        self.key
    }
    pub fn object(self) -> ObjectKey {
        self.object
    }
    pub fn offset(self) -> u64 {
        self.offset
    }
    pub fn bytes(self) -> usize {
        self.bytes
    }
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
}
pub struct Archive {
    scope: history::FrozenScope,
    seal: Seal,
    records: usize,
    header: [u8; HEADER],
    phase: Phase,
    handle: Option<Handle>,
    object: Option<ObjectKey>,
    segment: u16,
    offset: u64,
    cursor: usize,
    total: usize,
    write_hash: Sha256,
    read_hash: Sha256,
    digest: [u8; 32],
    partner: Option<crate::peer_replay::PartnerEvidence>,
    prewarm: usize,
    unpublished: Option<UnpublishedClose>,
    unactivated: Option<Preparation>,
    prepared_peer: Option<Preparation>,
    peer_packet_bytes: usize,
    peer_padded: usize,
}
fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn result(value: RequestResult) -> (u64, u64) {
    match value {
        RequestResult::Completed { finished_ns } => (1, finished_ns),
        RequestResult::Rejected => (2, 0),
        RequestResult::TimedOut => (3, 0),
        RequestResult::Pending => (4, 0),
    }
}
impl Archive {
    pub fn new(
        scope: history::FrozenScope,
        seal: Seal,
        records: usize,
        segment: u16,
        verified: Result<[u8; 32], cyxia_prototype::learning::Error>,
        sources: &[Source],
        partner: Option<crate::peer_replay::PartnerSeal>,
        closing: Option<crate::domain_control::replay::Receipt>,
        unpublished: Option<UnpublishedClose>,
        unactivated: Option<Preparation>,
    ) -> Result<Self, Error> {
        let status = capture::status().map_err(|_| Error::NotReady)?.0;
        if status.sealed != Some(seal) || records > history::RECORDS || sources.len() > 16 {
            return Err(Error::Stale);
        }
        let config = capture::current_config()
            .map_err(|_| Error::NotReady)?
            .ok_or(Error::Stale)?;
        if config.key != scope.key {
            return Err(Error::Stale);
        }
        if let Some(prep) = unactivated {
            crate::domain_control::replay::verify_preparation(prep)?;
            if prep.boot_epoch != scope.key.boot_epoch
                || prep.trial_id != scope.key.trial_id
                || prep.family != scope.family
                || prep.seed != scope.group.seed
                || prep.kind != scope.kind
                || prep.started_ns > scope.first_ns
                || verified.is_ok()
                || seal.exclusion.is_none()
                || closing.is_some()
                || partner.is_some()
                || unpublished.is_none_or(|proof| proof.capture_key() != Some(scope.key))
            {
                return Err(Error::Conflict);
            }
        } else if unpublished.is_some_and(|proof| proof.capture_key().is_some()) {
            return Err(Error::Conflict);
        }
        let prepared_peer = unactivated.filter(|_| matches!(scope.family.domain, 10 | 12 | 16));
        let partner = if prepared_peer.is_some() {
            None
        } else if matches!(scope.family.domain, 10 | 12 | 16) {
            let actual =
                crate::peer_replay::retained_partner(scope.key).map_err(super::domain_error)?;
            if partner.is_some_and(|old| {
                actual.exclusion.is_some()
                    || old.binding != actual.binding
                    || old.seal != actual.seal
            }) {
                return Err(Error::Stale);
            }
            if actual.exclusion.is_some() && verified.is_ok() {
                return Err(Error::Conflict);
            }
            Some(actual)
        } else {
            if partner.is_some() {
                return Err(Error::Conflict);
            }
            None
        };
        let mut header = [0; HEADER];
        header[..17].copy_from_slice(b"CYXIA_REPLAY_1.3\0");
        let values = [
            scope.key.boot_epoch,
            scope.key.trial_id,
            scope.key.generation,
            scope.family.domain as u64,
            scope.family.kind as u64,
            scope.target.id,
            scope.target.generation,
            scope.group.seed,
            scope.first_ns,
            scope.warmed_from_ns,
            scope.observation_ns,
            seal.closing_ns,
            records as u64,
            seal.intervals as u64,
            seal.requests as u64,
            u64::from(scope.kind == history::TrialKind::Candidate),
            seal.exclusion.map_or(0, |e| e as u64 + 1),
            verified.err().map_or(0, |e| e as u64 + 1),
            status.ordinary_warmup_ns,
            status.later_workload_ns,
            status.missing_events,
            status.raw_tagged_ns[0],
            status.raw_tagged_ns[1],
            status.raw_tagged_ns[2],
            status.raw_tagged_ns[3],
        ];
        for (i, v) in values.into_iter().enumerate() {
            put(&mut header, 32 + i * 8, v);
        }
        for (i, hash) in [
            scope.group.workload,
            scope.group.initial_image,
            scope.frozen_other_domains,
            scope.frozen_scope_hash,
            seal.event_hash,
            verified.unwrap_or([0; 32]),
            scope.schemas.feature.hash,
            scope.schemas.action.hash,
            scope.schemas.reward.hash,
            scope.schemas.learning.hash,
        ]
        .into_iter()
        .enumerate()
        {
            header[256 + i * 32..288 + i * 32].copy_from_slice(&hash);
        }
        for (i, version) in [
            scope.schemas.feature.version,
            scope.schemas.action.version,
            scope.schemas.reward.version,
            scope.schemas.learning.version,
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut header, 576 + i * 8, u64::from(version));
        }
        put(
            &mut header,
            608,
            if prepared_peer.is_some() {
                2
            } else {
                u64::from(partner.is_some())
            },
        );
        put(&mut header, 616, sources.len() as u64);
        put(&mut header, 624, partner.map_or(0, |p| p.seal.count));
        put(&mut header, 632, HEADER as u64);
        header[640..672].copy_from_slice(&config.node);
        if let Ok(coverage) = capture::coverage(seal) {
            for (i, v) in [
                coverage.first_ns,
                coverage.observation_ns,
                coverage.observation_end_ns,
                coverage.closing_ns,
                u64::from(coverage.required),
                u64::from(coverage.reported),
            ]
            .into_iter()
            .enumerate()
            {
                put(&mut header, 672 + i * 8, v);
            }
            put(&mut header, 720, 1);
        }
        put(&mut header, 728, status.issued as u64);
        put(&mut header, 736, status.closed_sources as u64);
        for (i, source) in sources.iter().enumerate() {
            for (j, v) in [
                source.owner.id,
                source.owner.generation,
                source.class as u64,
                source.allowed_cores,
            ]
            .into_iter()
            .enumerate()
            {
                put(&mut header, 768 + i * 32 + j * 8, v);
            }
        }
        let peer_count = if let Some(peer) = partner {
            let binding = peer
                .binding
                .encode(&mut header[1280..1564])
                .map_err(|_| Error::Format)?;
            let mut body = [0; cyxia_peer_billing::EXCLUDED_BYTES];
            let sealed = peer.encode(&mut body).map_err(super::domain_error)?;
            if binding != cyxia_peer_billing::BINDING_BYTES
                || sealed
                    != if peer.exclusion.is_some() {
                        cyxia_peer_billing::EXCLUDED_BYTES
                    } else {
                        cyxia_peer_billing::SEAL_BYTES
                    }
            {
                return Err(Error::Format);
            }
            header[1568..1792].copy_from_slice(&body[..cyxia_peer_billing::SEAL_BYTES]);
            // The signed EXCLUDED body retains the exact drained timestamp,
            // which the protocol requires to equal the original closing time.
            // Its raw signed packet is stored in full below.
            put(&mut header, 24, peer.exclusion.map_or(0, |e| e.reasons));
            usize::try_from(peer.seal.count).map_err(|_| Error::Capacity)?
        } else {
            0
        };
        let peer_packet_bytes = if let Some(prep) = prepared_peer {
            let bytes = crate::peer_replay::prepared_packet_bytes(prep)?;
            if bytes > cyxia_peer_billing::PREPARATION_PACKET_BYTES {
                return Err(Error::Capacity);
            }
            bytes
        } else if partner.is_some() {
            crate::peer_replay::seal_packet_bytes(scope.key).map_err(super::domain_error)?
        } else {
            0
        };
        put(&mut header, 744, peer_packet_bytes as u64);
        // Retain the actual signed length, including older decodable packets.
        // The next section begins after its explicit 256-byte alignment.
        let peer_padded = super::archive_packet::padded(peer_packet_bytes)?;
        let prewarm = if let Some(prep) = unactivated {
            let warm = crate::learning_prewarm::summary_prepared(prep)?;
            let rows = warm.map_or(0, |w| w.rows);
            if rows > crate::learning_prewarm::MAX_ROWS
                || warm.is_some_and(|w| w.frozen_ns > seal.closing_ns || w.started_ns > w.frozen_ns)
            {
                return Err(Error::Conflict);
            }
            header[1280..1288].copy_from_slice(b"CYPREPW1");
            for (i, value) in [
                prep.id,
                prep.started_ns,
                u64::from(warm.is_some()),
                warm.map_or(0, |w| w.session),
                warm.map_or(0, |w| w.started_ns),
                warm.map_or(0, |w| w.frozen_ns),
                warm.map_or(0, |w| w.completed),
                u64::from(warm.is_some_and(|w| w.lost)),
            ]
            .into_iter()
            .enumerate()
            {
                put(&mut header, 1288 + i * 8, value);
            }
            rows
        } else {
            crate::learning_prewarm::row_count(scope.key)?
        };
        put(&mut header, 752, prewarm as u64);
        put(&mut header, 760, super::WORKSPACE_PEAK_BYTES as u64);
        // This is the original, terminal root receipt retained before any
        // capture/history retirement. Continuous restoration has its own
        // publication identity; a one-shot close may retain the original
        // terminal receipt. Neither is reconstructed from a closing timestamp.
        // A failed one-shot may close actual custody and be archived as an
        // excluded run; it never gains an accepted label or an invented start.
        if let Some(closing) = closing {
            if unpublished.is_some() {
                return Err(Error::Conflict);
            }
            let terminal = match closing.state {
                cyxia_prototype::policy::ExecutionState::Applied => closing.started_ns.is_some(),
                cyxia_prototype::policy::ExecutionState::Failed(_) => {
                    verified.is_err()
                        && seal.exclusion.is_some()
                        && matches!((scope.family.domain, scope.family.kind), (14, 1) | (16, 2))
                }
                _ => false,
            };
            if !terminal
                || closing.apply.boot_epoch != scope.key.boot_epoch
                || closing.apply.plan_seq == 0
                || closing.action.domain() != scope.family.domain
                || closing.action.kind() != scope.family.kind
                || closing.observed_ns > seal.closing_ns
            {
                return Err(Error::Stale);
            }
            let close = &mut header[1792..2048];
            close[..8].copy_from_slice(b"CYCLOSE1");
            let encoded =
                cyxia_prototype::learning::baseline::encode(closing.action, &mut close[32..48])
                    .map_err(super::domain_error)?;
            let (execution, execution_error) = match closing.state {
                cyxia_prototype::policy::ExecutionState::Pending => (0, 0),
                cyxia_prototype::policy::ExecutionState::Applied => (1, 0),
                cyxia_prototype::policy::ExecutionState::Unknown => (2, 0),
                cyxia_prototype::policy::ExecutionState::Failed(error) => (3, error as u64),
            };
            put(close, 8, u64::from(closing.action.domain()));
            put(close, 16, u64::from(closing.action.kind()));
            put(close, 24, encoded as u64);
            for (i, value) in [
                closing.apply.boot_epoch,
                closing.apply.controller_epoch,
                closing.apply.plan_seq,
                u64::from(closing.apply.action_index),
                closing.apply.target.id,
                closing.apply.target.generation,
                closing.stamp.version,
                closing.stamp.snapshot_ns,
                closing.stamp.installed_until_ns,
                closing.snapshot.sequence,
                closing.snapshot.taken_ns,
                closing.snapshot.ledger_generation,
                closing.snapshot.core_generation,
                execution,
                closing.executor_generation,
                closing.issued_ns,
                closing.accepted_ns,
                u64::from(closing.started_ns.is_some()),
                closing.started_ns.unwrap_or(0),
                closing.observed_ns,
                closing.approved_deadline_ns,
                execution_error,
            ]
            .into_iter()
            .enumerate()
            {
                put(close, 48 + i * 8, value);
            }
        } else {
            let proof = unpublished.ok_or(Error::NotReady)?;
            crate::domain_control::replay::verify_unpublished_close(proof)?;
            let (token, family, target, first, closed_ns) = proof.facts();
            if verified.is_ok()
                || seal.exclusion.is_none()
                || token.boot_epoch != scope.key.boot_epoch
                || family != scope.family
                || target != scope.target
                || first.taken_ns != scope.first_ns
                || closed_ns > seal.closing_ns
            {
                return Err(Error::Conflict);
            }
            let close = &mut header[1792..2048];
            close[..8].copy_from_slice(b"CYNOPUB1");
            for (i, value) in [
                token.id,
                token.boot_epoch,
                token.owner.id,
                token.owner.generation,
                u64::from(family.domain),
                u64::from(family.kind),
                target.id,
                target.generation,
                first.sequence,
                first.taken_ns,
                first.core_generation,
                first.ledger_generation,
                closed_ns,
            ]
            .into_iter()
            .enumerate()
            {
                put(close, 8 + i * 8, value);
            }
            if let Some(prep) = unactivated {
                for (i, value) in [
                    1,
                    scope.key.boot_epoch,
                    scope.key.trial_id,
                    scope.key.generation,
                    prep.id,
                    prep.started_ns,
                    prep.owner.id,
                    prep.owner.generation,
                ]
                .into_iter()
                .enumerate()
                {
                    put(close, 112 + i * 8, value);
                }
            }
        }
        let total = HEADER
            + peer_padded
            + records * history::SLOT_BYTES
            + (seal.intervals as usize + peer_count + prewarm) * CPU_ROW
            + seal.requests as usize * REQUEST_ROW;
        Ok(Self {
            scope,
            seal,
            records,
            header,
            phase: Phase::Open,
            handle: None,
            object: None,
            segment,
            offset: 0,
            cursor: 0,
            total,
            write_hash: Sha256::new(),
            read_hash: Sha256::new(),
            digest: [0; 32],
            partner,
            prewarm,
            unpublished,
            unactivated,
            prepared_peer,
            peer_packet_bytes,
            peer_padded,
        })
    }
    pub fn segment(&self) -> u16 {
        self.segment
    }
    pub fn done(&self) -> bool {
        self.phase == Phase::Done
    }
    pub fn export(&self) -> Result<Export, Error> {
        if !self.done() || self.handle.is_some() || self.digest == [0; 32] {
            return Err(Error::Busy);
        }
        Ok(Export {
            unpublished: self.unpublished,
            key: self.seal.key,
            object: self.object.ok_or(Error::NotReady)?,
            offset: self.offset,
            bytes: self.total,
            digest: self.digest,
        })
    }
    fn path(&self, bytes: &mut [u8; 32]) -> usize {
        bytes[..4].copy_from_slice(b"/lr-");
        let hex = b"0123456789abcdef";
        for i in 0..16 {
            bytes[4 + i] = hex[((self.scope.key.boot_epoch >> (4 * (15 - i))) & 15) as usize];
        }
        bytes[20] = b'-';
        for i in 0..4 {
            bytes[21 + i] = hex[((self.segment >> (4 * (3 - i))) & 15) as usize];
        }
        25
    }
    fn encode(&self, offset: usize, out: &mut [u8; CHUNK]) -> Result<usize, Error> {
        out.fill(0);
        if offset < HEADER {
            let n = (HEADER - offset).min(CHUNK);
            out[..n].copy_from_slice(&self.header[offset..offset + n]);
            return Ok(n);
        }
        let mut at = offset - HEADER;
        if self.peer_padded != 0 {
            if at < self.peer_padded {
                return super::archive_packet::chunk(self.peer_packet_bytes, at, out, |offset, bytes| {
                    if let Some(prep) = self.prepared_peer {
                        crate::peer_replay::copy_prepared_packet(prep, offset, bytes)
                    } else {
                        crate::peer_replay::copy_seal_packet(self.seal.key, offset, bytes)
                            .map_err(super::domain_error)
                    }
                });
            }
            at -= self.peer_padded;
        }
        let journal = self.records * history::SLOT_BYTES;
        if at < journal {
            return history::copy_record(
                self.seal.key,
                at / history::SLOT_BYTES,
                at % history::SLOT_BYTES,
                out,
            )
            .map_err(|_| Error::NotReady);
        }
        at -= journal;
        let cpu_bytes = self.seal.intervals as usize * CPU_ROW;
        if at < cpu_bytes {
            if at % CPU_ROW != 0 {
                return Err(Error::Range);
            }
            let empty = CpuInterval {
                node: [0; 32],
                core: 0,
                start_ns: 0,
                end_ns: 0,
                class: CpuClass::Policy,
            };
            let mut rows = [empty; CHUNK / CPU_ROW];
            let n = capture::copy_intervals(self.seal, at / CPU_ROW, &mut rows)
                .map_err(|_| Error::NotReady)?;
            for (i, r) in rows[..n].iter().enumerate() {
                let b = &mut out[i * CPU_ROW..(i + 1) * CPU_ROW];
                b[..32].copy_from_slice(&r.node);
                put(b, 32, r.core as u64);
                put(b, 40, r.start_ns);
                put(b, 48, r.end_ns);
                put(b, 56, r.class as u64);
            }
            return Ok(n * CPU_ROW);
        }
        at -= cpu_bytes;
        let peer_bytes = self.partner.map_or(0, |p| p.seal.count as usize * CPU_ROW);
        if at < peer_bytes {
            if at % CPU_ROW != 0 {
                return Err(Error::Range);
            }
            let mut rows = [CpuInterval {
                node: [0; 32],
                core: 0,
                start_ns: 0,
                end_ns: 0,
                class: CpuClass::Policy,
            }; CHUNK / CPU_ROW];
            let n = crate::peer_replay::copy_intervals(self.seal.key, at / CPU_ROW, &mut rows)
                .map_err(super::domain_error)?;
            for (i, r) in rows[..n].iter().enumerate() {
                let b = &mut out[i * CPU_ROW..(i + 1) * CPU_ROW];
                b[..32].copy_from_slice(&r.node);
                put(b, 32, r.core as u64);
                put(b, 40, r.start_ns);
                put(b, 48, r.end_ns);
                put(b, 56, r.class as u64);
            }
            return Ok(n * CPU_ROW);
        }
        at -= peer_bytes;
        let request_bytes = self.seal.requests as usize * REQUEST_ROW;
        if at < request_bytes {
            if at % REQUEST_ROW != 0 {
                return Err(Error::Range);
            }
            let empty = WorkRequest {
                id: 0,
                arrived_ns: 0,
                result: RequestResult::Pending,
            };
            let mut rows = [(empty, None); CHUNK / REQUEST_ROW];
            let timing = RequestTiming {
                frozen: FrozenRequest {
                    id: 0,
                    owner: ObjectKey {
                        id: 0,
                        generation: 0,
                    },
                    arrived_ns: 0,
                },
                issued_observed_ns: None,
                scheduled: false,
            };
            let mut timings = [timing; CHUNK / REQUEST_ROW];
            let n = capture::copy_requests(self.seal, at / REQUEST_ROW, &mut rows)
                .map_err(|_| Error::NotReady)?;
            if capture::copy_request_timing(self.seal, at / REQUEST_ROW, &mut timings)
                .map_err(|_| Error::NotReady)?
                != n
            {
                return Err(Error::Stale);
            }
            for i in 0..n {
                let b = &mut out[i * REQUEST_ROW..(i + 1) * REQUEST_ROW];
                let (r, actual) = rows[i];
                let t = timings[i];
                let (code, finished) = result(r.result);
                let (raw, raw_at) = actual.map(result).unwrap_or((0, 0));
                for (j, v) in [
                    r.id,
                    r.arrived_ns,
                    code,
                    finished,
                    raw,
                    raw_at,
                    t.frozen.owner.id,
                    t.frozen.owner.generation,
                    t.frozen.arrived_ns,
                    u64::from(t.issued_observed_ns.is_some()),
                    t.issued_observed_ns.unwrap_or(0),
                    u64::from(t.scheduled),
                ]
                .into_iter()
                .enumerate()
                {
                    put(b, j * 8, v);
                }
            }
            return Ok(n * REQUEST_ROW);
        }
        at -= request_bytes;
        if at % CPU_ROW != 0 || at >= self.prewarm * CPU_ROW {
            return Err(Error::Range);
        }
        let mut rows = [crate::learning_prewarm::RawRow {
            owner: ObjectKey {
                id: 0,
                generation: 0,
            },
            core: 0,
            event: 0,
            first_ns: 0,
            last_ns: 0,
        }; CHUNK / CPU_ROW];
        let n = if let Some(prep) = self.unactivated {
            let first = at / CPU_ROW;
            let count = (self.prewarm - first).min(rows.len());
            for (i, row) in rows[..count].iter_mut().enumerate() {
                *row = crate::learning_prewarm::copy_prepared(prep, first + i)?;
            }
            count
        } else {
            crate::learning_prewarm::copy_rows(self.seal.key, at / CPU_ROW, &mut rows)?
        };
        for (i, row) in rows[..n].iter().enumerate() {
            let bytes = &mut out[i * CPU_ROW..(i + 1) * CPU_ROW];
            for (j, v) in [
                row.owner.id,
                row.owner.generation,
                u64::from(row.core),
                row.event,
                row.first_ns,
                row.last_ns,
            ]
            .into_iter()
            .enumerate()
            {
                put(bytes, j * 8, v);
            }
        }
        Ok(n * CPU_ROW)
    }
    /// One real filesystem operation or one 256-byte write/read per paid CPU0
    /// service turn. A failed/short write keeps the exact offset and custody.
    pub fn step(&mut self, progress: &mut dyn FnMut()) -> Result<bool, Error> {
        match self.phase {
            Phase::Open => {
                let mut name = [0; 32];
                let n = self.path(&mut name);
                let path = core::str::from_utf8(&name[..n]).map_err(|_| Error::Format)?;
                let stat = match files::stat(path, progress) {
                    Ok(stat) => stat,
                    Err(Error::NotFound) => {
                        files::create(path, progress)?;
                        return Ok(true);
                    }
                    Err(error) => return Err(error),
                };
                if stat
                    .size
                    .checked_add(self.total as u64)
                    .is_none_or(|size| size > cyxia_prototype::storage::MAX_FILE_SIZE)
                {
                    self.segment = self.segment.checked_add(1).ok_or(Error::Capacity)?;
                    return Ok(true);
                }
                self.handle = Some(files::open(path, OpenMode::ReadWrite, progress)?);
                self.object = Some(stat.object);
                self.offset = stat.size;
                self.phase = Phase::Write;
            }
            Phase::Write => {
                if self.cursor == self.total {
                    self.digest = self.write_hash.clone().finalize().into();
                    self.phase = Phase::Sync;
                    return Ok(true);
                }
                let mut bytes = [0; CHUNK];
                let n = self.encode(self.cursor, &mut bytes)?;
                if n == 0 {
                    return Err(Error::Range);
                }
                let written = files::write(
                    self.handle.ok_or(Error::NotReady)?,
                    self.offset + self.cursor as u64,
                    &bytes[..n],
                    progress,
                )?;
                // Encoded rows have fixed boundaries. The filesystem currently
                // performs complete small writes; a short write remains a fault
                // and cannot be presented as an exported immutable trace.
                if written != n {
                    return Err(Error::Io);
                }
                self.write_hash.update(&bytes[..n]);
                self.cursor += n;
            }
            Phase::Sync => {
                let receipt = files::fsync(self.handle.ok_or(Error::NotReady)?, progress)?;
                if Some(receipt.object) != self.object || receipt.write_seq == 0 {
                    return Err(Error::Stale);
                }
                self.cursor = 0;
                self.phase = Phase::Read;
            }
            Phase::Read => {
                if self.cursor == self.total {
                    if <[u8; 32]>::from(self.read_hash.clone().finalize()) != self.digest {
                        return Err(Error::Io);
                    }
                    self.phase = Phase::Close;
                    return Ok(true);
                }
                let mut bytes = [0; CHUNK];
                let n = (self.total - self.cursor).min(CHUNK);
                if files::read(
                    self.handle.ok_or(Error::NotReady)?,
                    self.offset + self.cursor as u64,
                    &mut bytes[..n],
                    progress,
                )? != n
                {
                    return Err(Error::Io);
                }
                self.read_hash.update(&bytes[..n]);
                self.cursor += n;
            }
            Phase::Close => {
                files::close(self.handle.ok_or(Error::NotReady)?)?;
                self.handle = None;
                self.phase = Phase::Done;
            }
            Phase::Done => return Ok(false),
        }
        Ok(true)
    }
}
