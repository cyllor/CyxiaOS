//! Read-side staging for QUERY and HISTORY_OPEN on an empty scratch volume.
//! EL1 binds the selector and scope to the authenticated holder.

use sha2::{Digest, Sha256};

use super::{
    Error,
    file::validate_absolute_path,
    file_media_unified_v1::{
        SNAP_OP_HISTORY_OPEN, SNAP_OP_QUERY, SNAPSHOT_SLOT_START, SNAPSHOT_SLOTS, SUPER_BYTES,
        UnifiedSystemKind, decode_object_envelope,
    },
    snapshot_list_v4::{EmptyCatalog, LIST_SELECTOR, ListError, SnapshotFrame, field},
};

pub const HISTORY_SELECTOR: u64 = 0x534e_4150_0000_0026;

const KEY_BYTES: usize = 40;
const HISTORY_PATH_FIELDS_BYTES: usize = 8;

/// The V18 payload shapes carried within the v4 staging frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRequest<'a> {
    pub request_id: u64,
    pub op: u16,
    fs_uuid: [u8; 16],
    path: Option<&'a [u8]>,
}

impl<'a> ReadRequest<'a> {
    pub fn decode(frame: &'a [u8]) -> Result<Self, ListError> {
        let frame = SnapshotFrame::decode(frame)?;
        let (key, path) = match frame.op {
            SNAP_OP_QUERY => (
                frame.payload.try_into().map_err(|_| ListError::Format)?,
                None,
            ),
            SNAP_OP_HISTORY_OPEN => {
                let (key, history) = frame
                    .payload
                    .split_first_chunk::<KEY_BYTES>()
                    .ok_or(ListError::Format)?;
                let (fields, path) = history
                    .split_first_chunk::<HISTORY_PATH_FIELDS_BYTES>()
                    .ok_or(ListError::Format)?;
                if usize::from(u16::from_le_bytes(field(fields, 0))) != path.len()
                    || fields[2..] != [0; 6]
                    || validate_absolute_path(path).is_err()
                {
                    return Err(ListError::Format);
                }
                (key, Some(path))
            }
            _ => return Err(ListError::Unsupported),
        };

        let fs_uuid = field(key, 0);
        if fs_uuid == [0; 16]
            || u64::from_le_bytes(field(key, 16)) == 0
            || u32::from_le_bytes(field(key, 24)) >= SNAPSHOT_SLOTS
            || u32::from_le_bytes(field(key, 28)) != 0
            || u64::from_le_bytes(field(key, 32)) == 0
        {
            return Err(ListError::Format);
        }
        Ok(Self {
            request_id: frame.request_id,
            op: frame.op,
            fs_uuid,
            path,
        })
    }

    pub const fn path(&self) -> Option<&'a [u8]> {
        self.path
    }

    pub const fn selector_matches(&self, selector: u64) -> bool {
        matches!(
            (self.op, selector),
            (SNAP_OP_QUERY, LIST_SELECTOR) | (SNAP_OP_HISTORY_OPEN, HISTORY_SELECTOR)
        )
    }

    /// Check the mounted UUID and the scope supplied by the authenticated EL1 grant.
    pub fn authorized(
        &self,
        selector: u64,
        view: &EmptySnapshotView,
        prefix: &[u8],
        prefix_digest: &[u8; 32],
    ) -> bool {
        if !self.selector_matches(selector) || self.fs_uuid != view.catalog.fs_uuid() {
            return false;
        }
        match (self.op, self.path) {
            (SNAP_OP_QUERY, None) => true,
            (SNAP_OP_HISTORY_OPEN, Some(path)) => {
                validate_absolute_path(prefix).is_ok()
                    && (prefix == b"/"
                        || path == prefix
                        || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/')))
                    && &history_prefix_digest(prefix) == prefix_digest
            }
            _ => false,
        }
    }
}

/// Bind the exact prefix bytes using the V18 history grant digest.
pub fn history_prefix_digest(prefix: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CyxiaOS:history-prefix:v1\0");
    digest.update((prefix.len() as u64).to_le_bytes());
    digest.update(prefix);
    digest.finalize().into()
}

/// An empty catalog and the verified bytes of its entire reserved slot range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptySnapshotView {
    catalog: EmptyCatalog,
    slot_digest: [u8; 32],
}

impl EmptySnapshotView {
    /// The reader fills one block from the same mounted scratch volume per call.
    pub fn verify(
        catalog: EmptyCatalog,
        mut read: impl FnMut(u64, &mut [u8; SUPER_BYTES]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let kind = UnifiedSystemKind::SnapshotSlot;
        let mut digest = Sha256::new();
        let mut raw = [0; SUPER_BYTES];
        for offset in 0..kind.blocks() {
            read(u64::from(SNAPSHOT_SLOT_START + offset), &mut raw)?;
            if offset == 0 {
                let envelope = decode_object_envelope(kind, &raw)?;
                if envelope.fs_uuid != catalog.fs_uuid()
                    || envelope.generation != catalog.generation()
                {
                    return Err(Error::Conflict);
                }
            } else if raw.iter().any(|&byte| byte != 0) {
                return Err(Error::Conflict);
            }
            digest.update(raw.as_slice());
        }
        Ok(Self {
            catalog,
            slot_digest: digest.finalize().into(),
        })
    }

    pub const fn catalog(&self) -> EmptyCatalog {
        self.catalog
    }

    pub const fn slot_digest(&self) -> [u8; 32] {
        self.slot_digest
    }
}
