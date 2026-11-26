//! Wire contract for opt-in LIST of an empty scratch snapshot catalog.
//! The native caller binds the endpoint and selector to an authenticated holder
//! and supplies the catalog identity and confirmed boot epoch from the scratch mount.

use super::{
    Error,
    file_media_unified_v1::{
        SNAP_MAX_REQUEST_BYTES, SNAP_OP_LIST, SUPER_BYTES, UnifiedSystemKind,
        decode_object_envelope, legacy_schema_v2_frame, snap_op_valid,
    },
    file_service_v4::{
        REPLY_HEADER, REPLY_MAGIC, REPLY_VERSION, REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION,
    },
};
use sha2::{Digest, Sha256};

pub const LIST_ENDPOINT: u64 = 0x534e_4150_0000_0011;
pub const LIST_SELECTOR: u64 = 0x534e_4150_0000_0024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListError {
    Format,
    Schema,
    Unsupported,
}

impl ListError {
    pub const fn errno(self) -> i64 {
        match self {
            Self::Format => -2,
            Self::Schema => -3,
            Self::Unsupported => -11,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListRequest {
    pub request_id: u64,
}

impl ListRequest {
    pub fn decode(frame: &[u8]) -> Result<Self, ListError> {
        let frame = SnapshotFrame::decode(frame)?;
        if frame.op != SNAP_OP_LIST {
            return Err(ListError::Unsupported);
        }
        if !frame.payload.is_empty() {
            return Err(ListError::Format);
        }
        Ok(Self {
            request_id: frame.request_id,
        })
    }
}

pub(super) struct SnapshotFrame<'a> {
    pub(super) op: u16,
    pub(super) request_id: u64,
    pub(super) payload: &'a [u8],
}

impl<'a> SnapshotFrame<'a> {
    pub(super) fn decode(frame: &'a [u8]) -> Result<Self, ListError> {
        if frame.len() > SNAP_MAX_REQUEST_BYTES {
            return Err(ListError::Format);
        }
        let (header, payload) = frame
            .split_first_chunk::<REQUEST_HEADER>()
            .ok_or(ListError::Format)?;
        let magic = u32::from_le_bytes(field(header, 0));
        if legacy_schema_v2_frame(magic) {
            return Err(ListError::Schema);
        }
        if magic != REQUEST_MAGIC {
            return Err(ListError::Format);
        }
        if u16::from_le_bytes(field(header, 4)) != REQUEST_VERSION {
            return Err(ListError::Schema);
        }

        let op = u16::from_le_bytes(field(header, 8));
        let declared_len = u32::from_le_bytes(field(header, 12));
        let request_id = u64::from_le_bytes(field(header, 16));
        if u16::from_le_bytes(field(header, 6)) != REQUEST_HEADER as u16
            || u16::from_le_bytes(field(header, 10)) != 0
            || declared_len != payload.len() as u32
            || request_id == 0
            || u64::from_le_bytes(field(header, 24)) != 0
            || !snap_op_valid(op)
        {
            return Err(ListError::Format);
        }
        Ok(Self {
            op,
            request_id,
            payload,
        })
    }
}

// Callers use fixed field offsets within length-checked headers and keys.
pub(super) fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N].try_into().unwrap()
}

/// An empty D1.5 catalog bound to its mounted identity and boot epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyCatalog {
    fs_uuid: [u8; 16],
    boot_epoch: u64,
    generation: u64,
    digest: [u8; 32],
}

impl EmptyCatalog {
    pub fn verify(
        raw: &[u8; SUPER_BYTES],
        expected_uuid: [u8; 16],
        expected_generation: u64,
        confirmed_boot_epoch: u64,
    ) -> Result<Self, Error> {
        if confirmed_boot_epoch == 0 {
            return Err(Error::Invalid);
        }
        let envelope = decode_object_envelope(UnifiedSystemKind::SnapshotCatalog, raw)?;
        if envelope.fs_uuid != expected_uuid || envelope.generation != expected_generation {
            return Err(Error::Conflict);
        }
        Ok(Self {
            fs_uuid: envelope.fs_uuid,
            boot_epoch: confirmed_boot_epoch,
            generation: envelope.generation,
            digest: Sha256::digest(raw).into(),
        })
    }

    pub const fn fs_uuid(&self) -> [u8; 16] {
        self.fs_uuid
    }

    pub const fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn reply(
        &self,
        req: ListRequest,
        service_generation: u64,
    ) -> Result<[u8; REPLY_HEADER], Error> {
        if req.request_id == 0 || service_generation == 0 {
            return Err(Error::Invalid);
        }
        // Zeroed state, result and length encode a volatile success with empty output.
        let mut reply = [0; REPLY_HEADER];
        reply[..4].copy_from_slice(&REPLY_MAGIC.to_le_bytes());
        reply[4..6].copy_from_slice(&REPLY_VERSION.to_le_bytes());
        reply[6..8].copy_from_slice(&(REPLY_HEADER as u16).to_le_bytes());
        reply[8..16].copy_from_slice(&req.request_id.to_le_bytes());
        reply[16..24].copy_from_slice(&service_generation.to_le_bytes());
        reply[72..80].copy_from_slice(&self.generation.to_le_bytes());
        Ok(reply)
    }
}
