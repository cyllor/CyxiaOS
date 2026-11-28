//! D7 SnapshotRequestStore in the unified v1 system-object map.
//! The caller owns journal reservations, the signed principal map and I/O.

use sha2::{Digest, Sha256};

use super::{
    ENVELOPE_BYTES, Error, SNAP_OP_CREATE, SNAP_OP_OPEN_WRITES, SNAP_OP_RESTORE,
    SNAPSHOT_REQUEST_START, SUPER_BYTES, UnifiedSystemKind, crc32c_zeroed, decode_envelope_header,
    encode_object_envelope, le16, le32, le64, op_needs_live_view_epoch, put16, put32, put64,
    snap_op_durable,
};
use crate::security::{
    file_service_v4::Reply,
    snapshot_service_v4::{
        BOUND, CANCELLED, DONE, FILE_REQ_KEY_BYTES, FileReqKey, Operation, PARTIAL, PRINCIPALS,
        RestoreMode, SNAPSHOT_KEY_BYTES, SnapshotKey, SnapshotRequest, UNKNOWN, request_digest,
        verify_mutation_result, zero,
    },
};

pub const RECORD_BYTES: usize = 512;
pub const RECORDS: usize = 64;
pub const ORDINARY_RECORDS: usize = 48;
pub const MAINTENANCE_RECORDS: usize = 8;
pub const RECOVERY_RECORDS: usize = 8;
pub const WATERMARK_BYTES: usize = 128;
const RECORD_MAGIC: u32 = 0x4359_4652;
const WATERMARK_MAGIC: u32 = 0x4359_574d;
const VERSION: u16 = 1;
const RECORD_CRC: usize = 508;
const WATERMARK_CRC: usize = 124;
const FIRST_WATERMARK: usize = 512;
const END_WATERMARKS: usize = FIRST_WATERMARK + PRINCIPALS as usize * WATERMARK_BYTES;
const PER_PAGE: usize = SUPER_BYTES / RECORD_BYTES;
const END_RECORDS_PAGE: u32 = 1 + (RECORDS / PER_PAGE) as u32;
const OBJECT_PAGES: u32 = UnifiedSystemKind::SnapshotRequest.blocks();
const COUNT_FIELDS: [u16; 8] = [
    VERSION,
    WATERMARK_BYTES as u16,
    RECORD_BYTES as u16,
    RECORDS as u16,
    PRINCIPALS as u16,
    ORDINARY_RECORDS as u16,
    MAINTENANCE_RECORDS as u16,
    RECOVERY_RECORDS as u16,
];
const END_COUNTS: usize = ENVELOPE_BYTES + COUNT_FIELDS.len() * 2;

const _: () = assert!(ORDINARY_RECORDS + MAINTENANCE_RECORDS + RECOVERY_RECORDS == RECORDS);
const _: () = assert!(RECORD_BYTES * PER_PAGE == SUPER_BYTES && END_WATERMARKS <= SUPER_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RequestState {
    Pending = 1,
    Done = 2,
    Failed = 3,
    Incomplete = 4,
    Unknown = 5,
}

impl RequestState {
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Incomplete)
    }

    pub const fn reply_state(self) -> u16 {
        match self {
            Self::Pending => BOUND,
            Self::Done => DONE,
            Self::Failed => CANCELLED,
            Self::Incomplete => PARTIAL,
            Self::Unknown => UNKNOWN,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestRecord {
    pub state: RequestState,
    pub operation: u16,
    pub key: FileReqKey,
    pub request_digest: [u8; 32],
    pub snapshot_key: Option<SnapshotKey>,
    pub old_live_view_epoch: u64,
    pub new_live_view_epoch: u64,
    pub log_epoch: u64,
    pub txid: u64,
    pub result_code: i32,
    pub restore_mode: Option<RestoreMode>,
    pub result_digest: [u8; 32],
    pub commit_lsn: u64,
    payload_len: u32,
    payload: [u8; 128],
}

impl RequestRecord {
    /// Build a pending admission from the exact copied and validated D7 frame.
    /// The owner must persist this record and advance its watermark atomically
    /// before making the admission available for execution.
    pub fn pending(request: &SnapshotRequest<'_>) -> Result<Self, Error> {
        let mut record = Self {
            state: RequestState::Pending,
            operation: request.op,
            key: request.durable_key.ok_or(Error::Invalid)?,
            request_digest: request.digest()?,
            snapshot_key: request.operation.snapshot_key(),
            old_live_view_epoch: request.live_view_epoch,
            new_live_view_epoch: 0,
            log_epoch: 0,
            txid: 0,
            result_code: 0,
            restore_mode: match request.operation {
                Operation::Restore { mode, .. } => Some(mode),
                _ => None,
            },
            result_digest: [0; 32],
            commit_lsn: 0,
            payload_len: 0,
            payload: [0; 128],
        };
        record.replace_payload(request.body())?;
        record.validate()?;
        Ok(record)
    }

    /// Stage a replacement payload on the caller's local copy of the record.
    pub fn replace_payload(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() > self.payload.len() {
            return Err(Error::Invalid);
        }
        self.payload.fill(0);
        self.payload[..data.len()].copy_from_slice(data);
        self.payload_len = data.len() as u32;
        Ok(())
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    pub fn seal_result(&mut self) -> Result<(), Error> {
        if !self.state.terminal() {
            return Err(Error::Invalid);
        }
        self.validate()?;
        self.result_digest = self.computed_result_digest()?;
        Ok(())
    }

    pub fn encode(&self, raw: &mut [u8; RECORD_BYTES]) -> Result<(), Error> {
        self.validate()?;
        self.verify_result_digest()?;
        self.write_fields(raw)?;
        let crc = crc32c_zeroed(raw, RECORD_CRC)?;
        put32(raw, RECORD_CRC, crc);
        Ok(())
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != RECORD_BYTES
            || le32(raw, 0)? != RECORD_MAGIC
            || le16(raw, 4)? != VERSION
            || usize::from(le16(raw, 6)?) != RECORD_BYTES
            || !zero(&raw[14..16])
            || !zero(&raw[84..88])
            || !zero(&raw[356..RECORD_CRC])
            || le32(raw, RECORD_CRC)? != crc32c_zeroed(raw, RECORD_CRC)?
        {
            return Err(Error::Invalid);
        }
        let state = match le32(raw, 8)? {
            1 => RequestState::Pending,
            2 => RequestState::Done,
            3 => RequestState::Failed,
            4 => RequestState::Incomplete,
            5 => RequestState::Unknown,
            _ => return Err(Error::Invalid),
        };
        let key = FileReqKey::decode(&raw[16..16 + FILE_REQ_KEY_BYTES])?;
        let snapshot = &raw[88..88 + SNAPSHOT_KEY_BYTES];
        let snapshot_key = if zero(snapshot) {
            None
        } else {
            Some(SnapshotKey::decode(snapshot)?)
        };
        let restore_mode = match le32(raw, 180)? {
            0 => None,
            mode => Some(RestoreMode::try_from(mode)?),
        };
        let record = Self {
            state,
            operation: le16(raw, 12)?,
            key,
            request_digest: raw[52..84].try_into().unwrap(),
            snapshot_key,
            old_live_view_epoch: le64(raw, 128)?,
            new_live_view_epoch: le64(raw, 136)?,
            log_epoch: le64(raw, 160)?,
            txid: le64(raw, 168)?,
            result_code: le32(raw, 176)? as i32,
            restore_mode,
            result_digest: raw[184..216].try_into().unwrap(),
            commit_lsn: le64(raw, 348)?,
            payload_len: le32(raw, 216)?,
            payload: raw[220..348].try_into().unwrap(),
        };
        let tx_uuid = if record.log_epoch == 0 {
            [0; 16]
        } else {
            key.fs_uuid
        };
        if raw[144..160] != tx_uuid {
            return Err(Error::Conflict);
        }
        record.validate()?;
        record.verify_result_digest()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), Error> {
        self.key.encode()?;
        if !snap_op_durable(self.operation)
            || self.request_digest == [0; 32]
            || self.payload_len as usize > self.payload.len()
            || !zero(&self.payload[self.payload_len as usize..])
            || (self.old_live_view_epoch != 0) != op_needs_live_view_epoch(self.operation)
            || self.restore_mode.is_some() != (self.operation == SNAP_OP_RESTORE)
            || (self.txid != 0) != (self.log_epoch != 0)
            || self.state.terminal() != (self.commit_lsn > 0)
            || self.state.terminal() && self.log_epoch == 0
        {
            return Err(Error::Invalid);
        }
        if let Some(snapshot) = self.snapshot_key {
            snapshot.encode()?;
            if snapshot.fs_uuid != self.key.fs_uuid {
                return Err(Error::Conflict);
            }
        }
        match self.state {
            RequestState::Pending | RequestState::Unknown => {
                if self.new_live_view_epoch != 0
                    || self.state == RequestState::Pending
                        && (self.result_code != 0 || self.log_epoch != 0)
                    || self.state == RequestState::Unknown && self.result_code >= 0
                {
                    return Err(Error::Invalid);
                }
                let body = self.payload();
                let operation = Operation::decode(self.operation, body)?;
                if self.snapshot_key != operation.snapshot_key()
                    || matches!(operation, Operation::Restore { mode, .. }
                        if self.restore_mode != Some(mode))
                    || matches!(operation, Operation::OpenWrites { restore, .. }
                        if restore.fs_uuid != self.key.fs_uuid || restore == self.key)
                    || self.request_digest
                        != request_digest(self.operation, self.key, self.old_live_view_epoch, body)?
                {
                    return Err(Error::Conflict);
                }
            }
            RequestState::Done => {
                if self.result_code != 0 {
                    return Err(Error::Invalid);
                }
                verify_mutation_result(
                    self.operation,
                    self.payload(),
                    self.snapshot_key,
                    &self.reply(1, false),
                )?;
                let epochs = match self.operation {
                    SNAP_OP_CREATE => {
                        self.old_live_view_epoch == self.new_live_view_epoch
                            && self.new_live_view_epoch == le64(self.payload(), 40)?
                    }
                    SNAP_OP_RESTORE => {
                        self.old_live_view_epoch == le64(self.payload(), 40)?
                            && self.new_live_view_epoch == le64(self.payload(), 48)?
                    }
                    SNAP_OP_OPEN_WRITES => self.old_live_view_epoch == self.new_live_view_epoch,
                    _ => self.new_live_view_epoch == 0,
                };
                let needs_snapshot = matches!(self.operation, 0x20..=0x23);
                if !epochs || self.snapshot_key.is_some() != needs_snapshot {
                    return Err(Error::Invalid);
                }
            }
            RequestState::Failed | RequestState::Incomplete => {
                if self.result_code >= 0 || self.new_live_view_epoch != 0 || self.payload_len != 0 {
                    return Err(Error::Invalid);
                }
            }
        }
        Ok(())
    }

    fn write_fields(&self, raw: &mut [u8; RECORD_BYTES]) -> Result<(), Error> {
        raw.fill(0);
        put32(raw, 0, RECORD_MAGIC);
        put16(raw, 4, VERSION);
        put16(raw, 6, RECORD_BYTES as u16);
        put32(raw, 8, self.state as u32);
        put16(raw, 12, self.operation);
        raw[16..52].copy_from_slice(&self.key.encode()?);
        raw[52..84].copy_from_slice(&self.request_digest);
        if let Some(snapshot) = self.snapshot_key {
            raw[88..128].copy_from_slice(&snapshot.encode()?);
        }
        put64(raw, 128, self.old_live_view_epoch);
        put64(raw, 136, self.new_live_view_epoch);
        if self.log_epoch != 0 {
            raw[144..160].copy_from_slice(&self.key.fs_uuid);
        }
        put64(raw, 160, self.log_epoch);
        put64(raw, 168, self.txid);
        put32(raw, 176, self.result_code as u32);
        put32(raw, 180, self.restore_mode.map_or(0, |mode| mode as u32));
        raw[184..216].copy_from_slice(&self.result_digest);
        put32(raw, 216, self.payload_len);
        raw[220..348].copy_from_slice(&self.payload);
        put64(raw, 348, self.commit_lsn);
        Ok(())
    }

    fn computed_result_digest(&self) -> Result<[u8; 32], Error> {
        let mut raw = [0; RECORD_BYTES];
        self.write_fields(&mut raw)?;
        raw[184..216].fill(0);
        Ok(Sha256::digest(raw).into())
    }

    fn verify_result_digest(&self) -> Result<(), Error> {
        let expected = if self.state.terminal() {
            self.computed_result_digest()?
        } else {
            [0; 32]
        };
        if self.result_digest != expected {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Project the original durable outcome. QUERY_REQUEST uses the separately
    /// encoded 512-byte record as output.
    pub fn reply(&self, service_generation: u64, query: bool) -> Reply<'_> {
        let terminal = self.state.terminal();
        Reply {
            request_id: self.key.request_seq,
            service_generation,
            state: self.state.reply_state(),
            result: if self.state == RequestState::Pending {
                -11
            } else {
                self.result_code
            },
            completed_prefix: 0,
            commit_lsn: self.commit_lsn,
            log_epoch: if terminal { self.log_epoch } else { 0 },
            txid: if terminal { self.txid } else { 0 },
            new_cap_selector: 0,
            target_generation: self.new_live_view_epoch,
            result_digest: self.result_digest,
            receipt_ref: self.key.request_seq,
            write_seq: 0,
            output: if !query && self.state == RequestState::Done {
                self.payload()
            } else {
                &[]
            },
        }
    }

    pub(in crate::security) fn verify_reply(
        &self,
        key: FileReqKey,
        reply: &Reply<'_>,
    ) -> Result<(), Error> {
        let expected = self.reply(reply.service_generation, true);
        let actual = Reply {
            output: &[],
            ..*reply
        };
        if self.key != key || actual != expected {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Same-key retries preserve the original outcome. The caller must check
    /// admission/effect evidence before durably publishing a valid successor.
    pub fn permits_transition(&self, next: &Self) -> Result<(), Error> {
        self.validate()?;
        next.validate()?;
        self.verify_result_digest()?;
        next.verify_result_digest()?;
        if self == next {
            return Ok(());
        }
        let created = self.operation == SNAP_OP_CREATE && next.state == RequestState::Done;
        if self.key != next.key
            || self.operation != next.operation
            || self.old_live_view_epoch != next.old_live_view_epoch
            || self.restore_mode != next.restore_mode
            || self.request_digest != next.request_digest
            || !created && self.snapshot_key != next.snapshot_key
        {
            return Err(Error::Conflict);
        }
        if self.state.terminal()
            || next.state == RequestState::Pending
            || self.state == RequestState::Unknown && !next.state.terminal()
        {
            return Err(Error::Stale);
        }
        if self.state == RequestState::Unknown
            && self.log_epoch != 0
            && next.state == RequestState::Done
            && (self.log_epoch, self.txid) != (next.log_epoch, next.txid)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// The owner checks persistent principal identity and keeps any proof
    /// referenced by the current protection state pinned through this check.
    pub fn permits_ack(&self, key: FileReqKey, digest: [u8; 32]) -> Result<(), Error> {
        if !self.state.terminal() {
            return Err(Error::Busy);
        }
        self.validate()?;
        self.verify_result_digest()?;
        if self.key != key || self.result_digest != digest {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Watermark {
    pub client_generation: u64,
    pub highest_accepted_seq: u64,
}

impl Watermark {
    pub const EMPTY: Self = Self {
        client_generation: 0,
        highest_accepted_seq: 0,
    };

    pub fn next(self, key: FileReqKey) -> Result<Self, Error> {
        key.encode()?;
        if key.client_generation != self.client_generation {
            return Err(Error::Stale);
        }
        let sequence = self
            .highest_accepted_seq
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        if sequence != key.request_seq {
            return Err(Error::Conflict);
        }
        Ok(Self {
            highest_accepted_seq: sequence,
            ..self
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestStoreHeader {
    pub fs_uuid: [u8; 16],
    pub generation: u64,
    pub watermarks: [Watermark; PRINCIPALS as usize],
}

impl RequestStoreHeader {
    pub fn encode(&self, raw: &mut [u8; SUPER_BYTES]) -> Result<(), Error> {
        encode_object_envelope(
            UnifiedSystemKind::SnapshotRequest,
            self.fs_uuid,
            self.generation,
            raw,
        )?;
        for (index, count) in COUNT_FIELDS.into_iter().enumerate() {
            put16(raw, ENVELOPE_BYTES + index * 2, count);
        }
        for (slot, (mark, row)) in self.watermarks.iter().zip(watermarks_mut(raw)).enumerate() {
            if mark.client_generation == 0 && mark.highest_accepted_seq != 0 {
                return Err(Error::Invalid);
            }
            put32(row, 0, WATERMARK_MAGIC);
            put16(row, 4, VERSION);
            put16(row, 6, WATERMARK_BYTES as u16);
            put32(row, 8, slot as u32);
            put64(row, 16, mark.client_generation);
            put64(row, 24, mark.highest_accepted_seq);
            put32(row, WATERMARK_CRC, crc32c_zeroed(row, WATERMARK_CRC)?);
        }
        let crc = crc32c_zeroed(raw, 32)?;
        put32(raw, 32, crc);
        Ok(())
    }

    pub fn decode(raw: &[u8; SUPER_BYTES]) -> Result<Option<Self>, Error> {
        let envelope = decode_envelope_header(UnifiedSystemKind::SnapshotRequest, raw)?;
        if zero(&raw[ENVELOPE_BYTES..]) {
            return Ok(None);
        }
        for (index, expected) in COUNT_FIELDS.into_iter().enumerate() {
            if le16(raw, ENVELOPE_BYTES + index * 2)? != expected {
                return Err(Error::Invalid);
            }
        }
        if !zero(&raw[END_COUNTS..FIRST_WATERMARK]) || !zero(&raw[END_WATERMARKS..]) {
            return Err(Error::Invalid);
        }
        let mut watermarks = [Watermark::EMPTY; PRINCIPALS as usize];
        let rows = raw[FIRST_WATERMARK..END_WATERMARKS].chunks_exact(WATERMARK_BYTES);
        for (slot, (mark, row)) in watermarks.iter_mut().zip(rows).enumerate() {
            if le32(row, 0)? != WATERMARK_MAGIC
                || le16(row, 4)? != VERSION
                || usize::from(le16(row, 6)?) != WATERMARK_BYTES
                || le32(row, 8)? != slot as u32
                || !zero(&row[12..16])
                || !zero(&row[32..WATERMARK_CRC])
                || le32(row, WATERMARK_CRC)? != crc32c_zeroed(row, WATERMARK_CRC)?
            {
                return Err(Error::Invalid);
            }
            *mark = Watermark {
                client_generation: le64(row, 16)?,
                highest_accepted_seq: le64(row, 24)?,
            };
            if mark.client_generation == 0 && mark.highest_accepted_seq != 0 {
                return Err(Error::Invalid);
            }
        }
        Ok(Some(Self {
            fs_uuid: envelope.fs_uuid,
            generation: envelope.generation,
            watermarks,
        }))
    }
}

fn watermarks_mut(raw: &mut [u8; SUPER_BYTES]) -> impl Iterator<Item = &mut [u8]> {
    raw[FIRST_WATERMARK..END_WATERMARKS].chunks_exact_mut(WATERMARK_BYTES)
}

pub const fn record_partition(client_slot: u32) -> Option<core::ops::Range<usize>> {
    match client_slot {
        0..=13 => Some(0..ORDINARY_RECORDS),
        14 => Some(ORDINARY_RECORDS..ORDINARY_RECORDS + MAINTENANCE_RECORDS),
        15 => Some(ORDINARY_RECORDS + MAINTENANCE_RECORDS..RECORDS),
        _ => None,
    }
}

pub fn record_location(index: usize) -> Result<(u32, core::ops::Range<usize>), Error> {
    if index >= RECORDS {
        return Err(Error::Invalid);
    }
    let start = (index % PER_PAGE) * RECORD_BYTES;
    Ok((
        SNAPSHOT_REQUEST_START + 1 + (index / PER_PAGE) as u32,
        start..start + RECORD_BYTES,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestStoreEvidence {
    pub generation: u64,
    pub occupied: usize,
    pub nonterminal: usize,
}

pub fn verify_request_store(
    fs_uuid: [u8; 16],
    expected_generation: u64,
    committed_lsn: u64,
    read: impl FnMut(u32, &mut [u8; SUPER_BYTES]) -> Result<(), Error>,
) -> Result<RequestStoreEvidence, Error> {
    inspect_request_store(
        fs_uuid,
        expected_generation,
        committed_lsn,
        read,
        |_| Ok(()),
    )
}

/// Read every physical page with one caller-supplied quiescent view. The
/// visitor may project verified records into scratch state. Its projection
/// becomes authoritative only if the complete scan succeeds.
pub fn inspect_request_store(
    fs_uuid: [u8; 16],
    expected_generation: u64,
    committed_lsn: u64,
    mut read: impl FnMut(u32, &mut [u8; SUPER_BYTES]) -> Result<(), Error>,
    mut visit: impl FnMut(&RequestRecord) -> Result<(), Error>,
) -> Result<RequestStoreEvidence, Error> {
    let mut raw = [0; SUPER_BYTES];
    read(SNAPSHOT_REQUEST_START, &mut raw)?;
    let envelope = decode_envelope_header(UnifiedSystemKind::SnapshotRequest, &raw)?;
    if envelope.fs_uuid != fs_uuid || envelope.generation != expected_generation {
        return Err(Error::Conflict);
    }
    let header = RequestStoreHeader::decode(&raw)?;
    let mut evidence = RequestStoreEvidence {
        generation: expected_generation,
        occupied: 0,
        nonterminal: 0,
    };
    let mut slots = [0; RECORDS];
    let mut sequences = [0; RECORDS];
    for page in 1..OBJECT_PAGES {
        read(SNAPSHOT_REQUEST_START + page, &mut raw)?;
        let Some(header) = header.filter(|_| page < END_RECORDS_PAGE) else {
            if !zero(&raw) {
                return Err(Error::Conflict);
            }
            continue;
        };
        for (offset, row) in raw.chunks_exact(RECORD_BYTES).enumerate() {
            if zero(row) {
                continue;
            }
            let index = (page - 1) as usize * PER_PAGE + offset;
            let record = RequestRecord::decode(row)?;
            let key = record.key;
            let mark = header.watermarks[key.client_slot as usize];
            if key.fs_uuid != fs_uuid
                || key.client_generation != mark.client_generation
                || key.request_seq > mark.highest_accepted_seq
                || record.commit_lsn > committed_lsn
                || !record_partition(key.client_slot).is_some_and(|part| part.contains(&index))
            {
                return Err(Error::Conflict);
            }
            if slots[..evidence.occupied]
                .iter()
                .zip(&sequences)
                .any(|(&slot, &seq)| slot == key.client_slot && seq == key.request_seq)
            {
                return Err(Error::Conflict);
            }
            slots[evidence.occupied] = key.client_slot;
            sequences[evidence.occupied] = key.request_seq;
            evidence.occupied += 1;
            evidence.nonterminal += usize::from(!record.state.terminal());
            visit(&record)?;
        }
    }
    Ok(evidence)
}
