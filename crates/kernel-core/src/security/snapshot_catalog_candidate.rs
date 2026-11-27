//! D7 populated catalog candidate. Verifies capture bindings against
//! a quiescent read view, with volume and counters supplied by the caller.

use super::{
    ENVELOPE_BYTES, Error, SNAPSHOT_CATALOG_BLOCK, SNAPSHOT_SLOT_START, SNAPSHOT_SLOTS,
    SUPER_BYTES, UnifiedSystemKind, crc32c_zeroed, decode_envelope_header, encode_object_envelope,
    le16, le32, le64, put16, put32, put64,
    slot_candidate::{SlotIdentity, verify_slot},
};

const MAGIC: u32 = 0x4359_4344;
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 24;
const ENTRY_BYTES: usize = 96;
const SLOT_COUNT: usize = SNAPSHOT_SLOTS as usize;
const ENTRIES_END: usize = HEADER_BYTES + SLOT_COUNT * ENTRY_BYTES;
const ENVELOPE_CRC_OFFSET: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogBinding {
    pub identity: SlotIdentity,
    pub descriptor_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogEntry {
    Free {
        slot_generation: u64,
    },
    Active(CatalogBinding),
    Deleting {
        binding: CatalogBinding,
        root_drop_commit_lsn: u64,
    },
}

impl CatalogEntry {
    fn binding(self) -> Option<(CatalogBinding, u64)> {
        match self {
            Self::Free { .. } => None,
            Self::Active(binding) => Some((binding, 0)),
            Self::Deleting {
                binding,
                root_drop_commit_lsn,
            } => Some((binding, root_drop_commit_lsn)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogRecord {
    pub fs_uuid: [u8; 16],
    pub generation: u64,
    /// Exclusive high-water mark of allocated snapshot IDs on this volume.
    pub next_snapshot_id: u64,
    /// Fixed physical slot order. FREE entries carry their previous generation.
    pub entries: [CatalogEntry; SLOT_COUNT],
}

impl CatalogRecord {
    pub fn encode(&self, raw: &mut [u8; SUPER_BYTES]) -> Result<(), Error> {
        let occupied = self.validate_entries()?;
        encode_object_envelope(
            UnifiedSystemKind::SnapshotCatalog,
            self.fs_uuid,
            self.generation,
            raw,
        )?;
        let payload = &mut raw[ENVELOPE_BYTES..];
        put32(payload, 0, MAGIC);
        put16(payload, 4, VERSION);
        put16(payload, 6, HEADER_BYTES as u16);
        put16(payload, 8, ENTRY_BYTES as u16);
        put16(payload, 10, SNAPSHOT_SLOTS as u16);
        put32(payload, 12, occupied);
        put64(payload, 16, self.next_snapshot_id);
        let rows = payload[HEADER_BYTES..ENTRIES_END].chunks_exact_mut(ENTRY_BYTES);
        for (slot, (&entry, row)) in self.entries.iter().zip(rows).enumerate() {
            row[1] = slot_class(slot);
            put16(row, 2, slot as u16);
            row[0] = match entry {
                CatalogEntry::Free { slot_generation } => {
                    put64(row, 8, slot_generation);
                    0
                }
                CatalogEntry::Active(binding) => {
                    encode_binding(row, binding, 0)?;
                    1
                }
                CatalogEntry::Deleting {
                    binding,
                    root_drop_commit_lsn,
                } => {
                    encode_binding(row, binding, root_drop_commit_lsn)?;
                    2
                }
            };
        }
        let crc = crc32c_zeroed(raw, ENVELOPE_CRC_OFFSET)?;
        put32(raw, ENVELOPE_CRC_OFFSET, crc);
        Ok(())
    }

    pub fn decode(block: u32, raw: &[u8; SUPER_BYTES]) -> Result<Self, Error> {
        if block != SNAPSHOT_CATALOG_BLOCK {
            return Err(Error::Conflict);
        }
        let envelope = decode_envelope_header(UnifiedSystemKind::SnapshotCatalog, raw)?;
        let payload = &raw[ENVELOPE_BYTES..];
        if le32(payload, 0)? != MAGIC
            || le16(payload, 4)? != VERSION
            || usize::from(le16(payload, 6)?) != HEADER_BYTES
            || usize::from(le16(payload, 8)?) != ENTRY_BYTES
            || u32::from(le16(payload, 10)?) != SNAPSHOT_SLOTS
            || payload[ENTRIES_END..].iter().any(|&byte| byte != 0)
        {
            return Err(Error::Invalid);
        }
        let mut entries = [CatalogEntry::Free { slot_generation: 0 }; SLOT_COUNT];
        let rows = payload[HEADER_BYTES..ENTRIES_END].chunks_exact(ENTRY_BYTES);
        for (slot, (entry, row)) in entries.iter_mut().zip(rows).enumerate() {
            *entry = decode_entry(slot, envelope.fs_uuid, row)?;
        }
        let catalog = Self {
            fs_uuid: envelope.fs_uuid,
            generation: envelope.generation,
            next_snapshot_id: le64(payload, 16)?,
            entries,
        };
        if catalog.validate_entries()? != le32(payload, 12)? {
            return Err(Error::Invalid);
        }
        Ok(catalog)
    }

    fn validate_entries(&self) -> Result<u32, Error> {
        if self.next_snapshot_id == 0 {
            return Err(Error::Invalid);
        }
        let mut seen_ids = [0; SLOT_COUNT];
        let mut occupied = 0;
        for (slot, &entry) in self.entries.iter().enumerate() {
            let Some((binding, root_drop_commit_lsn)) = entry.binding() else {
                continue;
            };
            let identity = binding.identity;
            identity.descriptor_block()?;
            if identity.fs_uuid != self.fs_uuid || identity.slot as usize != slot {
                return Err(Error::Conflict);
            }
            if identity.snapshot_id >= self.next_snapshot_id
                || seen_ids[..slot].contains(&identity.snapshot_id)
                || binding.descriptor_sha256 == [0; 32]
                || (matches!(entry, CatalogEntry::Deleting { .. })
                    && root_drop_commit_lsn <= identity.capture_commit_lsn)
            {
                return Err(Error::Invalid);
            }
            seen_ids[slot] = identity.snapshot_id;
            occupied += 1;
        }
        Ok(occupied)
    }
}

fn slot_class(slot: usize) -> u8 {
    if slot < 6 { 1 } else { 2 }
}

fn encode_binding(
    row: &mut [u8],
    binding: CatalogBinding,
    root_drop_commit_lsn: u64,
) -> Result<(), Error> {
    let identity = binding.identity;
    let descriptor_block = identity.descriptor_block()?;
    for (offset, value) in [
        (8, identity.slot_generation),
        (16, identity.snapshot_id),
        (24, identity.captured_live_view_epoch),
        (32, identity.capture_commit_lsn),
        (40, identity.created_online_age_ns),
        (56, root_drop_commit_lsn),
    ] {
        put64(row, offset, value);
    }
    put32(row, 48, descriptor_block);
    put32(row, 52, descriptor_block + 1);
    row[64..96].copy_from_slice(&binding.descriptor_sha256);
    Ok(())
}

fn decode_entry(slot: usize, fs_uuid: [u8; 16], row: &[u8]) -> Result<CatalogEntry, Error> {
    if row[1] != slot_class(slot) || usize::from(le16(row, 2)?) != slot || le32(row, 4)? != 0 {
        return Err(Error::Invalid);
    }
    let slot_generation = le64(row, 8)?;
    if row[0] == 0 {
        if row[16..].iter().any(|&byte| byte != 0) {
            return Err(Error::Invalid);
        }
        return Ok(CatalogEntry::Free { slot_generation });
    }
    let identity = SlotIdentity {
        fs_uuid,
        slot: slot as u32,
        slot_generation,
        snapshot_id: le64(row, 16)?,
        captured_live_view_epoch: le64(row, 24)?,
        capture_commit_lsn: le64(row, 32)?,
        created_online_age_ns: le64(row, 40)?,
    };
    let descriptor_block = identity.descriptor_block()?;
    if le32(row, 48)? != descriptor_block || le32(row, 52)? != descriptor_block + 1 {
        return Err(Error::Conflict);
    }
    let binding = CatalogBinding {
        identity,
        descriptor_sha256: row[64..96].try_into().unwrap(),
    };
    let root_drop_commit_lsn = le64(row, 56)?;
    match row[0] {
        1 if root_drop_commit_lsn == 0 => Ok(CatalogEntry::Active(binding)),
        2 => Ok(CatalogEntry::Deleting {
            binding,
            root_drop_commit_lsn,
        }),
        _ => Err(Error::Invalid),
    }
}

/// Independently selected volume state for the same quiescent read view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogContext {
    pub fs_uuid: [u8; 16],
    pub catalog_generation: u64,
    pub slot_store_generation: u64,
    pub live_view_epoch: u64,
    pub committed_lsn: u64,
    pub online_age_ns: u64,
}

/// Verify all occupied slots, including descriptors retained by DELETING
/// entries. Success proves storage consistency, with no history-open or GC
/// authority. The caller supplies the catalog block and a read-only slot view.
pub fn verify_catalog(
    block: u32,
    raw: &[u8; SUPER_BYTES],
    context: CatalogContext,
    mut read: impl FnMut(u32, &mut [u8; SUPER_BYTES]) -> Result<(), Error>,
) -> Result<CatalogRecord, Error> {
    let catalog = CatalogRecord::decode(block, raw)?;
    if context.slot_store_generation == 0 || context.live_view_epoch == 0 {
        return Err(Error::Invalid);
    }
    if catalog.fs_uuid != context.fs_uuid || catalog.generation != context.catalog_generation {
        return Err(Error::Conflict);
    }
    let bindings = || catalog.entries.iter().filter_map(|entry| entry.binding());
    for (binding, root_drop_commit_lsn) in bindings() {
        let identity = binding.identity;
        if identity.captured_live_view_epoch > context.live_view_epoch
            || identity.capture_commit_lsn > context.committed_lsn
            || identity.created_online_age_ns > context.online_age_ns
            || root_drop_commit_lsn > context.committed_lsn
        {
            return Err(Error::Conflict);
        }
    }
    if matches!(catalog.entries[0], CatalogEntry::Free { .. }) {
        // The shared envelope still identifies the SlotStore after GC has
        // retired the slot. Its old descriptor has no catalog binding.
        let mut head = [0; SUPER_BYTES];
        read(SNAPSHOT_SLOT_START, &mut head)?;
        let envelope = decode_envelope_header(UnifiedSystemKind::SnapshotSlot, &head)?;
        if envelope.fs_uuid != context.fs_uuid
            || envelope.generation != context.slot_store_generation
        {
            return Err(Error::Conflict);
        }
    }
    for (binding, _) in bindings() {
        let generation = (binding.identity.slot == 0).then_some(context.slot_store_generation);
        verify_slot(
            binding.identity,
            generation,
            &binding.descriptor_sha256,
            &mut read,
        )?;
    }
    Ok(catalog)
}
