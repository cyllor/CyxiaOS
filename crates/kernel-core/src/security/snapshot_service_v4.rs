//! D7 snapshot endpoint payloads carried by the existing FileService v4 frame.
//! Identity, capability lookup, write admission and proof verification are EL1 work.

use sha2::{Digest, Sha256};

use super::{
    Error,
    file::validate_absolute_path,
    file_media_unified_v1::{
        SNAP_MAX_REPLY_BYTES, SNAP_MAX_REQUEST_BYTES, SNAP_OP_ACK_REQUEST, SNAP_OP_CREATE,
        SNAP_OP_DELETE_EXPIRED, SNAP_OP_EXTEND, SNAP_OP_FREEZE_CLEAR, SNAP_OP_FREEZE_SET,
        SNAP_OP_HISTORY_OPEN, SNAP_OP_LIST, SNAP_OP_OPEN_WRITES, SNAP_OP_QUERY,
        SNAP_OP_QUERY_REQUEST, SNAP_OP_RESTORE, SNAPSHOT_SLOTS, SnapshotEnrollment, enroll_gate,
        op_needs_cap_selector, op_needs_live_view_epoch, request_access_gate,
        required_snapshot_cap, snap_op_durable,
    },
    file_service_v4::{
        REPLY_HEADER, REPLY_MAGIC, REPLY_VERSION, REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION,
        Reply,
    },
    snapshot_list_v4::{ListError, SnapshotFrame, field},
    snapshot_read_v4::history_prefix_digest,
    snapshot_request_store_v1::{RECORD_BYTES, RequestRecord},
};
use crate::control_plane::Identity;

pub const FILE_REQ_KEY_BYTES: usize = 36;
pub const SNAPSHOT_KEY_BYTES: usize = 40;
pub const PRINCIPALS: u32 = 16;
// FileServiceReply v3 states from §9.6.1.
pub(super) const BOUND: u16 = 2;
pub(super) const DONE: u16 = 3;
pub(super) const PARTIAL: u16 = 4;
pub(super) const UNKNOWN: u16 = 5;
pub(super) const CANCELLED: u16 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileReqKey {
    pub fs_uuid: [u8; 16],
    pub client_slot: u32,
    pub client_generation: u64,
    pub request_seq: u64,
}

impl FileReqKey {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FILE_REQ_KEY_BYTES {
            return Err(Error::Invalid);
        }
        let key = Self {
            fs_uuid: field(bytes, 0),
            client_slot: u32::from_le_bytes(field(bytes, 16)),
            client_generation: u64::from_le_bytes(field(bytes, 20)),
            request_seq: u64::from_le_bytes(field(bytes, 28)),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn encode(self) -> Result<[u8; FILE_REQ_KEY_BYTES], Error> {
        self.validate()?;
        let mut raw = [0; FILE_REQ_KEY_BYTES];
        raw[..16].copy_from_slice(&self.fs_uuid);
        raw[16..20].copy_from_slice(&self.client_slot.to_le_bytes());
        raw[20..28].copy_from_slice(&self.client_generation.to_le_bytes());
        raw[28..36].copy_from_slice(&self.request_seq.to_le_bytes());
        Ok(raw)
    }

    fn validate(self) -> Result<(), Error> {
        if self.fs_uuid == [0; 16]
            || self.client_slot >= PRINCIPALS
            || self.client_generation == 0
            || self.request_seq == 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Public slot identity. A root hash and retained reference must come from the
/// mounted catalog owner rather than from a caller's slot key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotKey {
    pub fs_uuid: [u8; 16],
    pub snapshot_id: u64,
    pub slot: u32,
    pub slot_generation: u64,
}

impl SnapshotKey {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SNAPSHOT_KEY_BYTES || bytes[28..32] != [0; 4] {
            return Err(Error::Invalid);
        }
        let key = Self {
            fs_uuid: field(bytes, 0),
            snapshot_id: u64::from_le_bytes(field(bytes, 16)),
            slot: u32::from_le_bytes(field(bytes, 24)),
            slot_generation: u64::from_le_bytes(field(bytes, 32)),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn encode(self) -> Result<[u8; SNAPSHOT_KEY_BYTES], Error> {
        self.validate()?;
        let mut bytes = [0; SNAPSHOT_KEY_BYTES];
        bytes[..16].copy_from_slice(&self.fs_uuid);
        bytes[16..24].copy_from_slice(&self.snapshot_id.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.slot.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.slot_generation.to_le_bytes());
        Ok(bytes)
    }

    fn validate(self) -> Result<(), Error> {
        if self.fs_uuid == [0; 16]
            || self.snapshot_id == 0
            || self.slot >= SNAPSHOT_SLOTS
            || self.slot_generation == 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RestoreMode {
    PreserveDirty = 1,
    DiscardVolatile = 2,
}

impl TryFrom<u32> for RestoreMode {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::PreserveDirty),
            2 => Ok(Self::DiscardVolatile),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation<'a> {
    Create {
        retention_ns: u64,
        slot_class: u32,
    },
    Extend {
        snapshot: SnapshotKey,
        retention_ns: u64,
    },
    DeleteExpired(SnapshotKey),
    Restore {
        snapshot: SnapshotKey,
        mode: RestoreMode,
    },
    List,
    Query(SnapshotKey),
    HistoryOpen {
        snapshot: SnapshotKey,
        path: &'a [u8],
    },
    FreezeSet {
        protection_generation: u64,
        reason: u32,
    },
    FreezeClear {
        protection_generation: u64,
    },
    OpenWrites {
        protection_generation: u64,
        restore: FileReqKey,
    },
    QueryRequest(FileReqKey),
    AckRequest {
        key: FileReqKey,
        terminal_digest: [u8; 32],
    },
}

impl<'a> Operation<'a> {
    pub(super) fn decode(op: u16, body: &'a [u8]) -> Result<Self, Error> {
        match op {
            SNAP_OP_CREATE if body.len() == 16 => {
                let slot_class = u32::from_le_bytes(field(body, 8));
                if !matches!(slot_class, 1 | 2) || u32::from_le_bytes(field(body, 12)) != 1 {
                    return Err(Error::Invalid);
                }
                Ok(Self::Create {
                    retention_ns: nonzero_u64(body, 0)?,
                    slot_class,
                })
            }
            SNAP_OP_EXTEND if body.len() == 48 => Ok(Self::Extend {
                snapshot: SnapshotKey::decode(&body[..40])?,
                retention_ns: nonzero_u64(body, 40)?,
            }),
            SNAP_OP_DELETE_EXPIRED => Ok(Self::DeleteExpired(SnapshotKey::decode(body)?)),
            SNAP_OP_RESTORE if body.len() == 48 && body[44..48] == [0; 4] => Ok(Self::Restore {
                snapshot: SnapshotKey::decode(&body[..40])?,
                mode: RestoreMode::try_from(u32::from_le_bytes(field(body, 40)))?,
            }),
            SNAP_OP_LIST if body.is_empty() => Ok(Self::List),
            SNAP_OP_QUERY => Ok(Self::Query(SnapshotKey::decode(body)?)),
            SNAP_OP_HISTORY_OPEN if body.len() >= 48 => {
                let path = &body[48..];
                if usize::from(u16::from_le_bytes(field(body, 40))) != path.len()
                    || body[42..48] != [0; 6]
                {
                    return Err(Error::Invalid);
                }
                validate_absolute_path(path)?;
                Ok(Self::HistoryOpen {
                    snapshot: SnapshotKey::decode(&body[..40])?,
                    path,
                })
            }
            SNAP_OP_FREEZE_SET if body.len() == 16 && body[12..16] == [0; 4] => {
                Ok(Self::FreezeSet {
                    protection_generation: nonzero_u64(body, 0)?,
                    reason: u32::from_le_bytes(field(body, 8)),
                })
            }
            SNAP_OP_FREEZE_CLEAR if body.len() == 8 => Ok(Self::FreezeClear {
                protection_generation: nonzero_u64(body, 0)?,
            }),
            SNAP_OP_OPEN_WRITES if body.len() == 48 && body[44..48] == [0; 4] => {
                Ok(Self::OpenWrites {
                    protection_generation: nonzero_u64(body, 0)?,
                    restore: FileReqKey::decode(&body[8..44])?,
                })
            }
            SNAP_OP_QUERY_REQUEST => Ok(Self::QueryRequest(FileReqKey::decode(body)?)),
            SNAP_OP_ACK_REQUEST if body.len() == 68 && !zero(&body[36..]) => Ok(Self::AckRequest {
                key: FileReqKey::decode(&body[..36])?,
                terminal_digest: field(body, 36),
            }),
            _ => Err(Error::Invalid),
        }
    }

    pub const fn snapshot_key(self) -> Option<SnapshotKey> {
        match self {
            Self::Extend { snapshot, .. }
            | Self::DeleteExpired(snapshot)
            | Self::Restore { snapshot, .. }
            | Self::Query(snapshot)
            | Self::HistoryOpen { snapshot, .. } => Some(snapshot),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    Format,
    Schema,
    Selector,
}

impl RequestError {
    pub const fn errno(self) -> i64 {
        match self {
            Self::Format => -2,
            Self::Schema => -3,
            Self::Selector => -1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotRequest<'a> {
    pub op: u16,
    pub request_id: u64,
    pub durable_key: Option<FileReqKey>,
    pub live_view_epoch: u64,
    pub operation: Operation<'a>,
    body: &'a [u8],
}

/// Values captured by EL1 before decoding the copied request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallBinding {
    pub holder: Identity,
    pub boot_epoch: u64,
    pub service_generation: u64,
    pub endpoint: u64,
    pub selector: u64,
    pub fs_uuid: [u8; 16],
}

/// Exact protected grant selected from the capability registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotGrant {
    pub binding: CallBinding,
    pub enrollment: SnapshotEnrollment,
    pub capability_word: u32,
    pub principal: Option<(u32, u64)>,
    pub history_prefix_sha256: Option<[u8; 32]>,
}

impl<'a> SnapshotRequest<'a> {
    pub fn decode(frame: &'a [u8], selector: u64) -> Result<Self, RequestError> {
        let frame = SnapshotFrame::decode(frame).map_err(|error| match error {
            ListError::Schema => RequestError::Schema,
            _ => RequestError::Format,
        })?;
        if (selector != 0) != op_needs_cap_selector(frame.op) {
            return Err(RequestError::Selector);
        }
        Self::decode_payload(frame.op, frame.request_id, frame.payload)
            .map_err(|_| RequestError::Format)
    }

    fn decode_payload(op: u16, request_id: u64, payload: &'a [u8]) -> Result<Self, Error> {
        if request_id == 0 {
            return Err(Error::Invalid);
        }
        let (durable_key, payload) = if snap_op_durable(op) {
            let (bytes, payload) = payload
                .split_first_chunk::<FILE_REQ_KEY_BYTES>()
                .ok_or(Error::Invalid)?;
            let key = FileReqKey::decode(bytes)?;
            if request_id != key.request_seq {
                return Err(Error::Invalid);
            }
            (Some(key), payload)
        } else {
            (None, payload)
        };
        let (live_view_epoch, body) = if op_needs_live_view_epoch(op) {
            let (epoch, body) = payload.split_first_chunk::<8>().ok_or(Error::Invalid)?;
            (nonzero_u64(epoch, 0)?, body)
        } else {
            (0, payload)
        };

        let operation = Operation::decode(op, body)?;
        let identity_key = match operation {
            Operation::QueryRequest(key) | Operation::AckRequest { key, .. } => Some(key),
            _ => None,
        };
        if identity_key.is_some_and(|key| key.request_seq != request_id)
            || durable_key.is_some_and(|key| {
                operation
                    .snapshot_key()
                    .is_some_and(|snapshot| snapshot.fs_uuid != key.fs_uuid)
                    || matches!(operation, Operation::OpenWrites { restore, .. }
                        if restore.fs_uuid != key.fs_uuid || restore == key)
            })
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            op,
            request_id,
            durable_key,
            live_view_epoch,
            operation,
            body,
        })
    }

    /// Canonical application payload excluding the durable key and view prefix.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    pub fn digest(&self) -> Result<[u8; 32], Error> {
        request_digest(
            self.op,
            self.durable_key.ok_or(Error::Invalid)?,
            self.live_view_epoch,
            self.body,
        )
    }

    pub const fn required_cap(&self) -> Option<u32> {
        required_snapshot_cap(self.op)
    }

    /// Resolve the exact live grant and inspect only the retained immutable
    /// request bytes. The owner still checks resource and effect custody.
    pub fn verify_grant(
        &self,
        call: CallBinding,
        grant: SnapshotGrant,
        history_prefix: &[u8],
    ) -> Result<(), Error> {
        if !call.holder.valid()
            || call.boot_epoch == 0
            || call.service_generation == 0
            || call.endpoint == 0
            || call.selector == 0
            || call.fs_uuid == [0; 16]
            || call.endpoint != grant.binding.endpoint
            || call.selector != grant.binding.selector
            || call.holder.id != grant.binding.holder.id
            || call.fs_uuid != grant.binding.fs_uuid
        {
            return Err(Error::Unauthorized);
        }
        if call != grant.binding {
            return Err(Error::Stale);
        }
        enroll_gate(grant.enrollment, grant.capability_word)?;
        let required = self.required_cap().ok_or(Error::Unauthorized)?;
        if required & grant.capability_word == 0
            || self
                .operation
                .snapshot_key()
                .is_some_and(|key| key.fs_uuid != call.fs_uuid)
        {
            return Err(Error::Unauthorized);
        }
        if let Some(key) = self.durable_key {
            if key.fs_uuid != call.fs_uuid
                || grant.principal != Some((key.client_slot, key.client_generation))
                || !matches!(
                    (grant.enrollment, key.client_slot),
                    (SnapshotEnrollment::Ordinary, 0..=13)
                        | (SnapshotEnrollment::InternalMaintenance, 14)
                        | (SnapshotEnrollment::RecoverySupervisor, 15)
                )
            {
                return Err(Error::Unauthorized);
            }
        }
        match self.operation {
            Operation::Create { slot_class, .. }
                if (slot_class == 1)
                    != (grant.enrollment == SnapshotEnrollment::InternalMaintenance) =>
            {
                return Err(Error::Unauthorized);
            }
            Operation::HistoryOpen { path, .. } => {
                validate_absolute_path(history_prefix).map_err(|_| Error::Unauthorized)?;
                if grant.history_prefix_sha256 != Some(history_prefix_digest(history_prefix))
                    || !(history_prefix == b"/"
                        || path == history_prefix
                        || path.starts_with(history_prefix)
                            && path.get(history_prefix.len()) == Some(&b'/'))
                {
                    return Err(Error::Unauthorized);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Resolve the durable principal using the authenticated service identity
    /// on the x3=0 QUERY/ACK path. A supervisor must be independently admitted
    /// before the owner supplies `recovery_supervisor=true`.
    pub fn verify_request_access(
        &self,
        fs_uuid: [u8; 16],
        principal: Option<(u32, u64)>,
        recovery_supervisor: bool,
    ) -> Result<(), Error> {
        let key = match self.operation {
            Operation::QueryRequest(key) | Operation::AckRequest { key, .. } => key,
            _ => return Err(Error::Unauthorized),
        };
        if key.fs_uuid != fs_uuid {
            return Err(Error::Unauthorized);
        }
        request_access_gate(
            principal == Some((key.client_slot, key.client_generation)),
            recovery_supervisor,
        )
    }

    /// Apply current-epoch checks to *new* admissions, after exact retries
    /// have been resolved against the retained durable key and digest.
    pub fn verify_new_mutation(
        &self,
        live_view_epoch: u64,
        protection_generation: u64,
    ) -> Result<(), Error> {
        if self.durable_key.is_none() {
            return Err(Error::Invalid);
        }
        let protection = match self.operation {
            Operation::FreezeSet {
                protection_generation,
                ..
            }
            | Operation::FreezeClear {
                protection_generation,
            }
            | Operation::OpenWrites {
                protection_generation,
                ..
            } => Some(protection_generation),
            _ => None,
        };
        if op_needs_live_view_epoch(self.op) && self.live_view_epoch != live_view_epoch
            || protection.is_some_and(|current| current != protection_generation)
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Exact maximum response size to reserve before evaluating mutations.
    pub fn reply_bound(&self) -> usize {
        REPLY_HEADER
            + match self.operation {
                Operation::List => STATUS_BYTES + SNAPSHOT_SLOTS as usize * SUMMARY_BYTES,
                Operation::Query(_) => STATUS_BYTES + SUMMARY_BYTES,
                Operation::HistoryOpen { .. } => 8,
                Operation::QueryRequest(_) => RECORD_BYTES,
                _ => mutation_result_bytes(self.op).unwrap_or(0),
            }
    }

    pub fn encode(&self, selector: u64, out: &mut [u8]) -> Result<usize, Error> {
        encode_request(
            self.op,
            self.request_id,
            self.durable_key,
            self.live_view_epoch,
            self.body,
            selector,
            out,
        )
    }
}

/// Canonical request encoder for a client with an already serialized application body.
pub fn encode_request(
    op: u16,
    request_id: u64,
    key: Option<FileReqKey>,
    live_view_epoch: u64,
    body: &[u8],
    selector: u64,
    out: &mut [u8],
) -> Result<usize, Error> {
    if key.is_some() != snap_op_durable(op)
        || (live_view_epoch != 0) != op_needs_live_view_epoch(op)
    {
        return Err(Error::Invalid);
    }
    if (selector != 0) != op_needs_cap_selector(op) {
        return Err(Error::Unauthorized);
    }
    let mut header = [0; REQUEST_HEADER + FILE_REQ_KEY_BYTES + 8];
    header[..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
    header[6..8].copy_from_slice(&(REQUEST_HEADER as u16).to_le_bytes());
    header[8..10].copy_from_slice(&op.to_le_bytes());
    header[16..24].copy_from_slice(&request_id.to_le_bytes());
    let mut used = REQUEST_HEADER;
    if let Some(key) = key {
        header[used..used + FILE_REQ_KEY_BYTES].copy_from_slice(&key.encode()?);
        used += FILE_REQ_KEY_BYTES;
    }
    if live_view_epoch != 0 {
        header[used..used + 8].copy_from_slice(&live_view_epoch.to_le_bytes());
        used += 8;
    }
    let length = used
        .checked_add(body.len())
        .filter(|&length| length <= SNAP_MAX_REQUEST_BYTES)
        .ok_or(Error::Invalid)?;
    header[12..16].copy_from_slice(&((length - REQUEST_HEADER) as u32).to_le_bytes());
    let raw = out.get_mut(..length).ok_or(Error::Capacity)?;
    raw[..used].copy_from_slice(&header[..used]);
    raw[used..].copy_from_slice(body);
    SnapshotRequest::decode(raw, selector).map_err(|_| Error::Invalid)?;
    Ok(length)
}

pub(super) fn request_digest(
    op: u16,
    key: FileReqKey,
    epoch: u64,
    body: &[u8],
) -> Result<[u8; 32], Error> {
    let mut hash = Sha256::new();
    hash.update(b"CYXIA-SNAP-REQ-V1");
    hash.update(REQUEST_VERSION.to_le_bytes());
    hash.update(op.to_le_bytes());
    hash.update(key.encode()?);
    hash.update(epoch.to_le_bytes());
    hash.update(
        u32::try_from(body.len())
            .map_err(|_| Error::Invalid)?
            .to_le_bytes(),
    );
    hash.update(body);
    Ok(hash.finalize().into())
}

pub(super) const fn mutation_result_bytes(op: u16) -> Option<usize> {
    match op {
        SNAP_OP_CREATE => Some(72),
        SNAP_OP_EXTEND => Some(64),
        SNAP_OP_DELETE_EXPIRED => Some(56),
        SNAP_OP_RESTORE => Some(96),
        SNAP_OP_FREEZE_SET | SNAP_OP_FREEZE_CLEAR | SNAP_OP_OPEN_WRITES => Some(16),
        _ => None,
    }
}

pub const STATUS_BYTES: usize = 48;
pub const SUMMARY_BYTES: usize = 128;

fn verify_summaries(body: &[u8], selected: Option<SnapshotKey>) -> Result<(), Error> {
    let (status, entries) = body
        .split_first_chunk::<STATUS_BYTES>()
        .ok_or(Error::Invalid)?;
    let count = u32::from_le_bytes(field(status, 0)) as usize;
    let gate = u32::from_le_bytes(field(status, 32));
    let phase = u32::from_le_bytes(field(status, 36));
    if count > SNAPSHOT_SLOTS as usize
        || selected.is_some() && count != 1
        || entries.len() != count * SUMMARY_BYTES
        || u32::from_le_bytes(field(status, 4)) > 1
        || gate > 1
        || phase > 2
        || gate == 0 && phase != 0
        || !zero(&status[40..])
    {
        return Err(Error::Invalid);
    }
    nonzero_u64(status, 16)?;
    nonzero_u64(status, 24)?;
    let mut previous: Option<SnapshotKey> = None;
    for entry in entries.chunks_exact(SUMMARY_BYTES) {
        let key = SnapshotKey::decode(&entry[..40])?;
        let class = u32::from_le_bytes(field(entry, 40));
        let state = u32::from_le_bytes(field(entry, 44));
        let capture = u64::from_le_bytes(field(entry, 56));
        let drop_lsn = u64::from_le_bytes(field(entry, 88));
        if previous.is_some_and(|old| old.slot >= key.slot || old.fs_uuid != key.fs_uuid)
            || selected.is_some_and(|want| want != key)
            || class
                != if key.slot < super::file_media_unified_v1::PERIODIC_SLOTS {
                    1
                } else {
                    2
                }
            || !matches!(state, 1 | 2)
            || (state == 1 && drop_lsn != 0 || state == 2 && drop_lsn <= capture)
            || u64::from_le_bytes(field(entry, 72)) <= u64::from_le_bytes(field(entry, 64))
            || u32::from_le_bytes(field(entry, 96)) != 1
            || !zero(&entry[104..])
        {
            return Err(Error::Invalid);
        }
        nonzero_u64(entry, 48)?;
        nonzero_u64(entry, 80)?;
        previous = Some(key);
    }
    Ok(())
}

pub fn decode_reply<'a>(
    request: &SnapshotRequest<'_>,
    bytes: &'a [u8],
) -> Result<Reply<'a>, Error> {
    if bytes.len() > SNAP_MAX_REPLY_BYTES || bytes.len() > request.reply_bound() {
        return Err(Error::Invalid);
    }
    let reply = Reply::decode(bytes)?;
    validate_reply(request, &reply)?;
    Ok(reply)
}

pub fn encode_reply(
    request: &SnapshotRequest<'_>,
    reply: &Reply<'_>,
    out: &mut [u8],
) -> Result<usize, Error> {
    validate_reply(request, reply)?;
    if reply.service_generation == 0 {
        return Err(Error::Invalid);
    }
    let length = REPLY_HEADER + reply.output.len();
    let raw = out.get_mut(..length).ok_or(Error::Capacity)?;
    raw.fill(0);
    raw[..4].copy_from_slice(&REPLY_MAGIC.to_le_bytes());
    raw[4..6].copy_from_slice(&REPLY_VERSION.to_le_bytes());
    raw[6..8].copy_from_slice(&(REPLY_HEADER as u16).to_le_bytes());
    raw[8..16].copy_from_slice(&reply.request_id.to_le_bytes());
    raw[16..24].copy_from_slice(&reply.service_generation.to_le_bytes());
    raw[24..26].copy_from_slice(&reply.state.to_le_bytes());
    raw[28..32].copy_from_slice(&reply.result.to_le_bytes());
    raw[36..40].copy_from_slice(&(reply.output.len() as u32).to_le_bytes());
    raw[40..48].copy_from_slice(&reply.commit_lsn.to_le_bytes());
    raw[48..56].copy_from_slice(&reply.log_epoch.to_le_bytes());
    raw[56..64].copy_from_slice(&reply.txid.to_le_bytes());
    raw[72..80].copy_from_slice(&reply.target_generation.to_le_bytes());
    raw[80..112].copy_from_slice(&reply.result_digest);
    raw[112..120].copy_from_slice(&reply.receipt_ref.to_le_bytes());
    raw[REPLY_HEADER..].copy_from_slice(reply.output);
    Ok(length)
}

fn validate_reply(request: &SnapshotRequest<'_>, reply: &Reply<'_>) -> Result<(), Error> {
    if reply.request_id != request.request_id
        || reply.completed_prefix != 0
        || reply.new_cap_selector != 0
        || reply.write_seq != 0
        || reply.result > 0
        || reply.output.len() > request.reply_bound() - REPLY_HEADER
    {
        return Err(Error::Invalid);
    }
    let durable = request.durable_key.is_some();
    let query = matches!(request.operation, Operation::QueryRequest(_));
    if reply.state == 0 {
        if (durable || query) && reply.result == 0
            || reply.receipt_ref != 0
            || reply.result_digest != [0; 32]
            || reply.commit_lsn != 0
            || reply.log_epoch != 0
            || reply.txid != 0
        {
            return Err(Error::Invalid);
        }
        if reply.result < 0 {
            return if reply.output.is_empty() {
                Ok(())
            } else {
                Err(Error::Invalid)
            };
        }
        return match request.operation {
            Operation::List => verify_summaries(reply.output, None),
            Operation::Query(key) => verify_summaries(reply.output, Some(key)),
            Operation::HistoryOpen { .. } if reply.output.len() == 8 => {
                nonzero_u64(reply.output, 0).map(|_| ())
            }
            Operation::AckRequest { .. } if reply.output.is_empty() => Ok(()),
            _ => Err(Error::Invalid),
        };
    }
    if !(durable || query)
        || reply.receipt_ref != request.request_id
        || !matches!(reply.state, BOUND | DONE | PARTIAL | UNKNOWN | CANCELLED)
        || (reply.state == DONE) != (reply.result == 0)
    {
        return Err(Error::Invalid);
    }
    let terminal = matches!(reply.state, DONE | PARTIAL | CANCELLED);
    if terminal != (reply.result_digest != [0; 32])
        || terminal != (reply.commit_lsn != 0)
        || terminal != (reply.log_epoch != 0)
        || terminal != (reply.txid != 0)
    {
        return Err(Error::Invalid);
    }
    if let Operation::QueryRequest(key) = request.operation {
        let record = RequestRecord::decode(reply.output)?;
        return record.verify_reply(key, reply);
    }
    if reply.state == DONE {
        verify_mutation_result(
            request.op,
            reply.output,
            request.operation.snapshot_key(),
            reply,
        )?;
        let key = request.durable_key.ok_or(Error::Invalid)?;
        if matches!(request.op, SNAP_OP_CREATE..=SNAP_OP_RESTORE)
            && reply.output[..16] != key.fs_uuid
        {
            return Err(Error::Conflict);
        }
        let expected_target = match request.operation {
            Operation::Create { .. } => {
                if u64::from_le_bytes(field(reply.output, 40)) != request.live_view_epoch {
                    return Err(Error::Conflict);
                }
                request.live_view_epoch
            }
            Operation::Restore { .. } => {
                if u64::from_le_bytes(field(reply.output, 40)) != request.live_view_epoch {
                    return Err(Error::Conflict);
                }
                u64::from_le_bytes(field(reply.output, 48))
            }
            Operation::FreezeSet {
                protection_generation,
                ..
            }
            | Operation::FreezeClear {
                protection_generation,
            }
            | Operation::OpenWrites {
                protection_generation,
                ..
            } => {
                if protection_generation.checked_add(1)
                    != Some(u64::from_le_bytes(field(reply.output, 0)))
                {
                    return Err(Error::Conflict);
                }
                request.live_view_epoch
            }
            _ => 0,
        };
        if expected_target != reply.target_generation {
            return Err(Error::Conflict);
        }
    } else if !reply.output.is_empty() || reply.target_generation != 0 {
        return Err(Error::Invalid);
    }
    Ok(())
}

pub(super) fn verify_mutation_result(
    op: u16,
    body: &[u8],
    expected_snapshot: Option<SnapshotKey>,
    reply: &Reply<'_>,
) -> Result<(), Error> {
    if Some(body.len()) != mutation_result_bytes(op) {
        return Err(Error::Invalid);
    }
    if matches!(
        op,
        SNAP_OP_FREEZE_SET | SNAP_OP_FREEZE_CLEAR | SNAP_OP_OPEN_WRITES
    ) {
        nonzero_u64(body, 0)?;
        let cleanup = u32::from_le_bytes(field(body, 8));
        let gate = u32::from_le_bytes(field(body, 12));
        if cleanup > 1
            || gate > 1
            || op == SNAP_OP_FREEZE_SET && (cleanup != 1 || gate != 1)
            || op == SNAP_OP_FREEZE_CLEAR && cleanup != 0
            || op == SNAP_OP_OPEN_WRITES && gate != 0
        {
            return Err(Error::Invalid);
        }
        return Ok(());
    }
    let snapshot = SnapshotKey::decode(&body[..40])?;
    if expected_snapshot.is_some_and(|expected| snapshot != expected) {
        return Err(Error::Conflict);
    }
    let first = nonzero_u64(body, 40)?;
    let valid = match op {
        SNAP_OP_CREATE => {
            u64::from_le_bytes(field(body, 48)) < reply.commit_lsn
                && u64::from_le_bytes(field(body, 64)) > u64::from_le_bytes(field(body, 56))
        }
        SNAP_OP_EXTEND => {
            u64::from_le_bytes(field(body, 48)) > first
                && u64::from_le_bytes(field(body, 48)) > u64::from_le_bytes(field(body, 56))
        }
        SNAP_OP_DELETE_EXPIRED => {
            first == reply.commit_lsn
                && u32::from_le_bytes(field(body, 48)) == 1
                && zero(&body[52..56])
        }
        SNAP_OP_RESTORE => {
            first.checked_add(1) == Some(u64::from_le_bytes(field(body, 48)))
                && body[56..72] == snapshot.fs_uuid
                && u64::from_le_bytes(field(body, 72)) == reply.log_epoch
                && u64::from_le_bytes(field(body, 80)) == reply.txid
                && u32::from_le_bytes(field(body, 88)) == 1
                && zero(&body[92..96])
        }
        _ => false,
    };
    if valid { Ok(()) } else { Err(Error::Invalid) }
}

fn nonzero_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let value = u64::from_le_bytes(field(bytes, offset));
    if value == 0 {
        Err(Error::Invalid)
    } else {
        Ok(value)
    }
}

pub(super) fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == 0)
}
