//! D7 candidate for the 15-block populated slot. The production mount still
//! accepts only the empty D1.5 envelope and zero continuation blocks.

use sha2::{Digest, Sha256};

use super::{
    BUSINESS_INODES, ENVELOPE_BYTES, Error, INODE_BYTES, SLOT_MIRROR_BLOCKS, SNAPSHOT_SLOT_START,
    SNAPSHOT_SLOTS, SNAPSHOT_STRIDE, SUPER_BYTES, UnifiedSystemKind, crc32c_zeroed,
    decode_envelope_header, encode_object_envelope, le16, le32, le64, put16, put32, put64,
};
use crate::security::file_structure_v1::Inode;

const MAGIC: u32 = 0x4359_5352;
const VERSION: u16 = 3;
const HEADER_BYTES: u16 = 128;
const CRC_OFFSET: usize = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotIdentity {
    pub fs_uuid: [u8; 16],
    pub snapshot_id: u64,
    pub slot: u32,
    pub slot_generation: u64,
    pub captured_live_view_epoch: u64,
    pub capture_commit_lsn: u64,
    pub created_online_age_ns: u64,
}

impl SlotIdentity {
    pub(super) fn descriptor_block(self) -> Result<u32, Error> {
        if self.fs_uuid == [0; 16]
            || self.snapshot_id == 0
            || self.slot >= SNAPSHOT_SLOTS
            || self.slot_generation == 0
            || self.captured_live_view_epoch == 0
        {
            return Err(Error::Invalid);
        }
        Ok(SNAPSHOT_SLOT_START + self.slot * SNAPSHOT_STRIDE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotDescriptor {
    pub identity: SlotIdentity,
    /// The D1.5 SlotStore header resides at the first block of slot 0.
    pub store_generation: Option<u64>,
    pub inode_image_sha256: [u8; 32],
}

impl SlotDescriptor {
    pub fn encode(&self, raw: &mut [u8; SUPER_BYTES]) -> Result<(), Error> {
        let identity = self.identity;
        let first_mirror = identity.descriptor_block()? + 1;
        match (identity.slot, self.store_generation) {
            (0, Some(generation)) => encode_object_envelope(
                UnifiedSystemKind::SnapshotSlot,
                identity.fs_uuid,
                generation,
                raw,
            )?,
            (1..SNAPSHOT_SLOTS, None) => raw.fill(0),
            _ => return Err(Error::Invalid),
        }
        let payload = &mut raw[ENVELOPE_BYTES..];
        put32(payload, 0, MAGIC);
        put16(payload, 4, VERSION);
        put16(payload, 6, HEADER_BYTES);
        payload[8..24].copy_from_slice(&identity.fs_uuid);
        put64(payload, 24, identity.snapshot_id);
        put32(payload, 32, identity.slot);
        put64(payload, 40, identity.slot_generation);
        put64(payload, 48, identity.captured_live_view_epoch);
        put64(payload, 56, identity.capture_commit_lsn);
        put32(payload, 64, BUSINESS_INODES);
        put32(payload, 68, SLOT_MIRROR_BLOCKS);
        put32(payload, 72, first_mirror);
        payload[80..112].copy_from_slice(&self.inode_image_sha256);
        put64(payload, 112, identity.created_online_age_ns);
        let payload_crc = crc32c_zeroed(payload, CRC_OFFSET)?;
        put32(payload, CRC_OFFSET, payload_crc);
        if identity.slot == 0 {
            let envelope_crc = crc32c_zeroed(raw, 32)?;
            put32(raw, 32, envelope_crc);
        }
        Ok(())
    }

    pub fn decode(block: u32, raw: &[u8; SUPER_BYTES]) -> Result<Self, Error> {
        let payload = &raw[ENVELOPE_BYTES..];
        if le32(payload, 0)? != MAGIC
            || le16(payload, 4)? != VERSION
            || le16(payload, 6)? != HEADER_BYTES
            || le32(payload, 36)? != 0
            || le32(payload, 64)? != BUSINESS_INODES
            || le32(payload, 68)? != SLOT_MIRROR_BLOCKS
            || le32(payload, 76)? != 0
            || le32(payload, CRC_OFFSET)? != crc32c_zeroed(payload, CRC_OFFSET)?
            || payload[124..].iter().any(|&byte| byte != 0)
        {
            return Err(Error::Invalid);
        }
        let identity = SlotIdentity {
            fs_uuid: payload[8..24].try_into().unwrap(),
            snapshot_id: le64(payload, 24)?,
            slot: le32(payload, 32)?,
            slot_generation: le64(payload, 40)?,
            captured_live_view_epoch: le64(payload, 48)?,
            capture_commit_lsn: le64(payload, 56)?,
            created_online_age_ns: le64(payload, 112)?,
        };
        if identity.descriptor_block()? != block || le32(payload, 72)? != block + 1 {
            return Err(Error::Conflict);
        }
        let store_generation = if identity.slot == 0 {
            let envelope = decode_envelope_header(UnifiedSystemKind::SnapshotSlot, raw)?;
            if envelope.fs_uuid != identity.fs_uuid {
                return Err(Error::Conflict);
            }
            Some(envelope.generation)
        } else {
            if raw[..ENVELOPE_BYTES].iter().any(|&byte| byte != 0) {
                return Err(Error::Invalid);
            }
            None
        };
        Ok(Self {
            identity,
            store_generation,
            inode_image_sha256: payload[80..112].try_into().unwrap(),
        })
    }
}

/// Verify the exact capture binding and descriptor digest supplied by an
/// external catalog, then read the 14 business inode pages in physical order.
/// This checks inode record structure. Tree, bitmap and data ownership require
/// the corresponding volume data and validation by the filesystem owner.
pub fn verify_slot(
    expected: SlotIdentity,
    store_generation: Option<u64>,
    descriptor_sha256: &[u8; 32],
    mut read: impl FnMut(u32, &mut [u8; SUPER_BYTES]) -> Result<(), Error>,
) -> Result<SlotDescriptor, Error> {
    let block = expected.descriptor_block()?;
    let mut raw = [0; SUPER_BYTES];
    read(block, &mut raw)?;
    let actual: [u8; 32] = Sha256::digest(raw).into();
    if &actual != descriptor_sha256 {
        return Err(Error::Conflict);
    }
    let descriptor = SlotDescriptor::decode(block, &raw)?;
    if descriptor.identity != expected || descriptor.store_generation != store_generation {
        return Err(Error::Conflict);
    }
    let mut digest = Sha256::new();
    for page in 0..SLOT_MIRROR_BLOCKS {
        read(block + 1 + page, &mut raw)?;
        for (index, bytes) in raw.chunks_exact(INODE_BYTES).enumerate() {
            let inode = Inode::decode(bytes)?;
            if (inode.kind != 0 && inode.parent >= BUSINESS_INODES)
                || (page == 0
                    && index == 0
                    && (
                        inode.kind,
                        inode.generation,
                        inode.parent,
                        inode.parent_generation,
                    ) != (2, 1, 0, 1))
            {
                return Err(Error::Invalid);
            }
        }
        digest.update(raw);
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != descriptor.inode_image_sha256 {
        return Err(Error::Conflict);
    }
    Ok(descriptor)
}
