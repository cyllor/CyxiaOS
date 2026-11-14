//! A negative preparation journal, before any capture RunKey or ApplyId exists.
//! The original failure and warmup rows remain owned until actual fsync,
//! byte-for-byte hash readback, and file close have all completed.
use crate::{
    domain_control::replay::{self as root, PreparationClose},
    domain_storage as files,
    learning_workload::{Prepared, PreparedFailure},
};
use cyxia_prototype::domains::{
    Error, ObjectKey,
    filesystem::{Handle, OpenMode},
};
use sha2::{Digest, Sha256};

const HEADER: usize = 1024;
const CHUNK: usize = super::archive_packet::CHUNK;
const WARM_ROW: usize = 64;
const MANIFEST_ROW: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Open,
    Write,
    Sync,
    Read,
    Close,
    Done,
}
#[derive(Clone, Copy)]
pub struct Export {
    close: PreparationClose,
    object: ObjectKey,
    offset: u64,
    bytes: usize,
    digest: [u8; 32],
}
impl Export {
    pub fn close(self) -> PreparationClose {
        self.close
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
    close: PreparationClose,
    header: [u8; HEADER],
    phase: Phase,
    segment: u16,
    handle: Option<Handle>,
    object: Option<ObjectKey>,
    offset: u64,
    cursor: usize,
    total: usize,
    warm_rows: usize,
    manifest: bool,
    write_hash: Sha256,
    read_hash: Sha256,
    digest: [u8; 32],
    peer_bytes: usize,
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
impl Archive {
    pub fn new(
        close: PreparationClose,
        facts: PreparedFailure,
        prepared: Option<&Prepared>,
        segment: u16,
    ) -> Result<Self, Error> {
        root::verify_preparation_close(close)?;
        let p = close.preparation();
        if facts.drained_at > close.drained_ns()
            || facts.drained_at < p.started_ns
            || facts.queued_at > facts.drained_at
        {
            return Err(Error::Conflict);
        }
        if prepared.is_some_and(|v| {
            v.family != p.family
                || v.group.seed != p.seed
                || facts.target != Some(v.target)
                || facts.group != Some(v.group)
        }) {
            return Err(Error::Conflict);
        }
        let warm = crate::learning_prewarm::summary_prepared(p)?;
        let peer_bytes = if matches!(p.family.domain, 10 | 12 | 16) {
            crate::peer_replay::prepared_packet_bytes(p)?
        } else {
            0
        };
        let warm_rows = warm.map_or(0, |v| v.rows);
        if warm_rows > crate::learning_prewarm::MAX_ROWS
            || warm.is_some_and(|v| v.frozen_ns > close.drained_ns() || v.started_ns > v.frozen_ns)
        {
            return Err(Error::Conflict);
        }
        let mut header = [0; HEADER];
        let magic = b"CYXIA_PREP_1.3\0";
        header[..magic.len()].copy_from_slice(magic);
        let target = facts.target.unwrap_or(ObjectKey {
            id: 0,
            generation: 0,
        });
        let values = [
            p.id,
            p.boot_epoch,
            p.owner.id,
            p.owner.generation,
            p.trial_id,
            u64::from(p.family.domain),
            u64::from(p.family.kind),
            p.seed,
            u64::from(p.kind == root::TrialKind::Candidate),
            p.started_ns,
            close.failed_ns(),
            close.drained_ns(),
            close.error() as u64 + 1,
            facts.queued_at,
            facts.drained_at,
            facts.fault.map_or(0, |e| e as u64 + 1),
            u64::from(facts.target.is_some()),
            target.id,
            target.generation,
            u64::from(facts.group.is_some()),
            facts.group.map_or(0, |g| g.seed),
            warm_rows as u64,
            u64::from(prepared.is_some()),
            warm.map_or(0, |w| w.session),
            warm.map_or(0, |w| w.started_ns),
            warm.map_or(0, |w| w.frozen_ns),
            warm.map_or(0, |w| w.completed),
            u64::from(warm.is_some_and(|w| w.lost)),
        ];
        for (i, value) in values.into_iter().enumerate() {
            put(&mut header, 32 + i * 8, value);
        }
        let hashes = [
            facts.group.map_or([0; 32], |g| g.workload),
            facts.group.map_or([0; 32], |g| g.initial_image),
            close.model_hash(),
            close.observed_model_hash(),
        ];
        for (i, hash) in hashes.into_iter().enumerate() {
            header[288 + i * 32..320 + i * 32].copy_from_slice(&hash);
        }
        if let Some(token) = close.root_token() {
            put(&mut header, 416, 1);
            for (i, v) in [
                token.id,
                token.boot_epoch,
                token.owner.id,
                token.owner.generation,
            ]
            .into_iter()
            .enumerate()
            {
                put(&mut header, 424 + i * 8, v);
            }
        }
        if let Some(prepared) = prepared {
            if prepared.source_count > 16 {
                return Err(Error::Capacity);
            }
            put(&mut header, 456, prepared.source_count as u64);
            for (i, source) in prepared.sources[..prepared.source_count].iter().enumerate() {
                for (j, v) in [
                    source.owner.id,
                    source.owner.generation,
                    source.class as u64,
                    source.allowed_cores,
                ]
                .into_iter()
                .enumerate()
                {
                    put(&mut header, 480 + i * 32 + j * 8, v);
                }
            }
        }
        put(&mut header, 1000, peer_bytes as u64);
        let total = HEADER
            + super::archive_packet::padded(peer_bytes)?
            + warm_rows * WARM_ROW
            + usize::from(prepared.is_some()) * crate::learning_workload::REQUESTS * MANIFEST_ROW;
        put(&mut header, 464, total as u64);
        put(&mut header, 472, 0); // No observation, label, or execution receipt.
        Ok(Self {
            close,
            header,
            phase: Phase::Open,
            segment,
            handle: None,
            object: None,
            offset: 0,
            cursor: 0,
            total,
            warm_rows,
            manifest: prepared.is_some(),
            write_hash: Sha256::new(),
            read_hash: Sha256::new(),
            digest: [0; 32],
            peer_bytes,
        })
    }
    pub fn done(&self) -> bool {
        self.phase == Phase::Done
    }
    pub fn segment(&self) -> u16 {
        self.segment
    }
    pub fn export(&self) -> Result<Export, Error> {
        if !self.done() || self.handle.is_some() || self.digest == [0; 32] {
            return Err(Error::Busy);
        }
        Ok(Export {
            close: self.close,
            object: self.object.ok_or(Error::NotReady)?,
            offset: self.offset,
            bytes: self.total,
            digest: self.digest,
        })
    }
    fn path(&self, bytes: &mut [u8; 32]) -> usize {
        bytes[..4].copy_from_slice(b"/lp-");
        let hex = b"0123456789abcdef";
        for i in 0..16 {
            bytes[4 + i] =
                hex[((self.close.preparation().boot_epoch >> (4 * (15 - i))) & 15) as usize];
        }
        bytes[20] = b'-';
        for i in 0..4 {
            bytes[21 + i] = hex[((self.segment >> (4 * (3 - i))) & 15) as usize];
        }
        25
    }
    fn encode(
        &self,
        offset: usize,
        out: &mut [u8; CHUNK],
        prepared: Option<&Prepared>,
    ) -> Result<usize, Error> {
        out.fill(0);
        if offset < HEADER {
            let n = (HEADER - offset).min(CHUNK);
            out[..n].copy_from_slice(&self.header[offset..offset + n]);
            return Ok(n);
        }
        let mut at = offset - HEADER;
        let peer_padded = super::archive_packet::padded(self.peer_bytes)?;
        if at < peer_padded {
            return super::archive_packet::chunk(self.peer_bytes, at, out, |offset, bytes| {
                crate::peer_replay::copy_prepared_packet(self.close.preparation(), offset, bytes)
            });
        }
        at -= peer_padded;
        if at < self.warm_rows * WARM_ROW {
            if !at.is_multiple_of(WARM_ROW) {
                return Err(Error::Range);
            }
            let first = at / WARM_ROW;
            let count = (self.warm_rows - first).min(CHUNK / WARM_ROW);
            for i in 0..count {
                let row =
                    crate::learning_prewarm::copy_prepared(self.close.preparation(), first + i)?;
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
                    put(out, i * WARM_ROW + j * 8, v);
                }
            }
            return Ok(count * WARM_ROW);
        }
        if !self.manifest {
            return Ok(0);
        }
        let prepared = prepared.ok_or(Error::Stale)?;
        let index = (at - self.warm_rows * WARM_ROW) / MANIFEST_ROW;
        let count = (prepared.requests.len() - index).min(CHUNK / MANIFEST_ROW);
        for (i, request) in prepared.requests[index..index + count].iter().enumerate() {
            for (j, v) in [
                request.id,
                request.owner.id,
                request.owner.generation,
                request.offset_ns,
            ]
            .into_iter()
            .enumerate()
            {
                put(out, i * MANIFEST_ROW + j * 8, v);
            }
        }
        Ok(count * MANIFEST_ROW)
    }
    /// One real filesystem operation per paid service turn, preserving the
    /// original offset and contents through all Busy/Again/I/O retries.
    pub fn step(
        &mut self,
        prepared: Option<&Prepared>,
        progress: &mut dyn FnMut(),
    ) -> Result<bool, Error> {
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
                    Err(e) => return Err(e),
                };
                if stat
                    .size
                    .checked_add(self.total as u64)
                    .is_none_or(|n| n > cyxia_prototype::storage::MAX_FILE_SIZE)
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
                let n = self.encode(self.cursor, &mut bytes, prepared)?;
                if n == 0 {
                    return Err(Error::Range);
                }
                if files::write(
                    self.handle.ok_or(Error::NotReady)?,
                    self.offset + self.cursor as u64,
                    &bytes[..n],
                    progress,
                )? != n
                {
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
