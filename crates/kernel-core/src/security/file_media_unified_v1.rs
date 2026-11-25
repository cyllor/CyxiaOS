//! V0.20 G1 unified media contract layer (strategy A, direction RATIFIED).
//!
//! Authority: docs/design/v0.20-g1-media-freeze.md (2026-11-25). The user
//! ratified strategy A: keep the baseline v1 superblock byte base and add
//! snapshot catalog/slots/requests/protection as new signed-manifest system
//! objects; legacy v2 volumes join only through offline read-only export ->
//! all-zero new image rebuild -> import with a continuity proof.
//!
//! Freeze honesty (see the freeze doc status header):
//! - Baseline bytes (superblock v1, region map, the four baseline object block
//!   counts 1/7/4/1, v4/Reply v3 headers) are implemented exactly as frozen in
//!   V0.19.9 §9.2/§9.2.1/§9.6/§9.6.1 and the existing frozen decoders.
//! - Strategy-A additions (8-object map, inode segment 224..231, fixed new
//!   object block ranges, new object envelopes, op/capability tables, budget
//!   carve-out) are RATIFIED direction. Their new bytes are
//!   golden-vector-pending until the D7 deliverables land; G1 overall remains
//!   NOT_READY. New object payloads must stay all-zero until field layouts are
//!   frozen (fail-closed placeholder, not an invented field layout).
//!
//! Contract layer only: no mount, no native boot wiring, no writes to any
//! device. The existing `file_mount_v1` `[SystemObject; 4]` validator is NOT
//! modified; [`unified_map_from_baseline`] bridges it toward the ratified
//! N=8 map, and [`validate_unified_system_map`] is the new unified validator.
//! Host test vectors are fixture-derived and are NOT golden vectors.
use super::Error;
use super::file_media_v0199::{SnapshotMediaKind, crc32c_zeroed, probe_snapshot_media_pair};
use super::file_structure_v1::{INODE_BYTES, INODES, SystemKind, SystemObject};

// Baseline-frozen layout constants, re-exported as the unified contract's
// single source (never re-derived here).
pub use super::file_media_v0199::{
    BITMAP_START, BLOCK_COUNT, DATA_START, INODE_START, SUPER_BYTES, SuperblockV1,
};
// v4/Reply v3 header constants stay owned by file_service_v4 (baseline bytes).
pub use super::file_service_v4::{
    MAX_REPLY, MAX_REQUEST, REPLY_HEADER, REPLY_MAGIC, REPLY_VERSION, REQUEST_HEADER,
    REQUEST_MAGIC, REQUEST_VERSION,
};

// ---------------------------------------------------------------------------
// D1: unified system-object map (4 baseline + 4 new = 8 objects)
// ---------------------------------------------------------------------------

pub const BASELINE_SYSTEM_OBJECTS: usize = 4;
pub const UNIFIED_SYSTEM_OBJECTS: usize = 8;
/// Ratified system inode segment (v2's 224+ segment carried over; root=0).
pub const SYSTEM_INODE_START: u16 = 224;
/// 232..255 must stay empty (generation 0) on unified volumes.
pub const RESERVED_INODE_START: u16 = 232;
/// Business inodes 0..=223 (root inode 0 included), matching the v2 business
/// inode count and the 14-page slot mirror geometry.
pub const BUSINESS_INODES: u32 = 224;
pub const ROOT_INODE: u32 = 0;

pub const CATALOG_INODE: u16 = 224;
pub const BOOT_INODE: u16 = 225;
pub const SLOT_INODE: u16 = 226;
pub const PROTECTION_INODE: u16 = 227;
pub const REQUEST_INODE: u16 = 228;
pub const RECEIPTS_INODE: u16 = 229;
pub const ACL_INODE: u16 = 230;
pub const SECURITY_INODE: u16 = 231;

pub const SNAPSHOT_SLOTS: u32 = 8;
pub const SNAPSHOT_STRIDE: u32 = 15;
pub const SLOT_DESCRIPTOR_BLOCKS: u32 = 1;
pub const SLOT_MIRROR_BLOCKS: u32 = 14;
/// 224 business inodes x 256 B = the first 14 inode-table pages.
pub const SLOT_MIRROR_BYTES: usize = 57344;

// Fixed block ranges of the four NEW objects (ratified; golden-vector-pending
// bytes). Baseline four keep manifest-supplied positions (block counts frozen).
pub const SNAPSHOT_CATALOG_BLOCK: u32 = 4131;
pub const SNAPSHOT_SLOT_START: u32 = 4132;
pub const SNAPSHOT_REQUEST_START: u32 = 4252;
pub const SNAPSHOT_PROTECTION_BLOCK: u32 = 4268;
/// Canonical reference business start (NOT a universal wire constant: the
/// baseline four's manifest positions may differ; ownership is ledger-checked).
pub const CANONICAL_BUSINESS_START: u32 = 4269;

pub const BASELINE_SYSTEM_BLOCKS: u32 = 13;
pub const SNAPSHOT_SYSTEM_BLOCKS: u32 = 138;
pub const UNIFIED_SYSTEM_BLOCKS: u32 = 151;

const _: () = assert!(SLOT_MIRROR_BYTES == BUSINESS_INODES as usize * INODE_BYTES);
const _: () = assert!(SLOT_MIRROR_BLOCKS as usize * SUPER_BYTES == SLOT_MIRROR_BYTES);
const _: () = assert!(SNAPSHOT_SLOTS * SNAPSHOT_STRIDE == 120);
const _: () = assert!(SLOT_DESCRIPTOR_BLOCKS + SLOT_MIRROR_BLOCKS == SNAPSHOT_STRIDE);
const _: () = assert!(SNAPSHOT_CATALOG_BLOCK + 1 == SNAPSHOT_SLOT_START);
const _: () =
    assert!(SNAPSHOT_SLOT_START + SNAPSHOT_SLOTS * SNAPSHOT_STRIDE == SNAPSHOT_REQUEST_START);
const _: () = assert!(SNAPSHOT_REQUEST_START + 16 == SNAPSHOT_PROTECTION_BLOCK);
const _: () = assert!(SNAPSHOT_PROTECTION_BLOCK + 1 == CANONICAL_BUSINESS_START);
const _: () = assert!(SNAPSHOT_CATALOG_BLOCK == DATA_START + BASELINE_SYSTEM_BLOCKS);
const _: () = assert!(BASELINE_SYSTEM_BLOCKS + SNAPSHOT_SYSTEM_BLOCKS == UNIFIED_SYSTEM_BLOCKS);
const _: () = assert!(SNAPSHOT_SYSTEM_BLOCKS == 1 + 120 + 16 + 1);

/// The ratified unified system-object kinds. The four baseline variants map
/// one-to-one onto [`SystemKind`]; the four snapshot variants are new.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnifiedSystemKind {
    BootEpoch,
    Receipts,
    Acl,
    Security,
    SnapshotCatalog,
    SnapshotSlot,
    SnapshotRequest,
    SnapshotProtection,
}
impl UnifiedSystemKind {
    /// Frozen block counts: baseline 1/7/4/1 (§9.2.1), new 1/120/16/1 (D1.2).
    pub const fn blocks(self) -> u32 {
        match self {
            Self::BootEpoch | Self::Security => 1,
            Self::Receipts => 7,
            Self::Acl => 4,
            Self::SnapshotCatalog | Self::SnapshotProtection => 1,
            Self::SnapshotSlot => SNAPSHOT_SLOTS * SNAPSHOT_STRIDE,
            Self::SnapshotRequest => 16,
        }
    }
    /// Ratified fixed inode slot (D1.2). Root stays inode 0.
    pub const fn inode_slot(self) -> u16 {
        match self {
            Self::SnapshotCatalog => CATALOG_INODE,
            Self::BootEpoch => BOOT_INODE,
            Self::SnapshotSlot => SLOT_INODE,
            Self::SnapshotProtection => PROTECTION_INODE,
            Self::SnapshotRequest => REQUEST_INODE,
            Self::Receipts => RECEIPTS_INODE,
            Self::Acl => ACL_INODE,
            Self::Security => SECURITY_INODE,
        }
    }
    pub const fn is_new_snapshot_object(self) -> bool {
        matches!(
            self,
            Self::SnapshotCatalog
                | Self::SnapshotSlot
                | Self::SnapshotRequest
                | Self::SnapshotProtection
        )
    }
    /// New objects have ratified fixed first blocks; baseline objects keep
    /// manifest-supplied positions (None = validated by bounds/uniqueness).
    pub const fn fixed_first_block(self) -> Option<u32> {
        match self {
            Self::SnapshotCatalog => Some(SNAPSHOT_CATALOG_BLOCK),
            Self::SnapshotSlot => Some(SNAPSHOT_SLOT_START),
            Self::SnapshotRequest => Some(SNAPSHOT_REQUEST_START),
            Self::SnapshotProtection => Some(SNAPSHOT_PROTECTION_BLOCK),
            _ => None,
        }
    }
    pub const fn from_baseline(kind: SystemKind) -> Self {
        match kind {
            SystemKind::BootEpoch => Self::BootEpoch,
            SystemKind::Receipts => Self::Receipts,
            SystemKind::Acl => Self::Acl,
            SystemKind::Security => Self::Security,
        }
    }
    /// Envelope magic of the four new objects (D1.5). Baseline objects keep
    /// their own frozen codecs; None means "not a new-envelope object".
    pub const fn envelope_magic(self) -> Option<u32> {
        match self {
            Self::SnapshotCatalog => Some(SNAP_CATALOG_MAGIC),
            Self::SnapshotSlot => Some(SNAP_SLOT_MAGIC),
            Self::SnapshotRequest => Some(SNAP_REQUEST_MAGIC),
            Self::SnapshotProtection => Some(SNAP_PROTECTION_MAGIC),
            _ => None,
        }
    }
}

/// One unified system object: exact location from the authenticated boot
/// catalog, never guessed from old snapshot-v2 offsets. Same shape as the
/// baseline [`SystemObject`], extended to the ratified eight-kind map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnifiedSystemObject {
    pub kind: UnifiedSystemKind,
    pub inode: u16,
    pub generation: u64,
    pub first_block: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnifiedSystemMapEvidence {
    /// Total system data blocks (13 baseline + 138 snapshot = 151).
    pub system_blocks: u32,
    /// Blocks owned by the four new snapshot objects (138).
    pub snapshot_blocks: u32,
}

/// Unified map validator (ratified N=8). Does NOT replace or modify the
/// baseline `file_mount_v1` four-object validator. Checks: each kind exactly
/// once, ratified fixed inode slots, nonzero generations, frozen block counts,
/// data-area bounds, fixed first blocks for the four new objects, and pairwise
/// block-range disjointness across all eight objects. Read-only; a passing
/// result is map evidence, not a mount grant or a content validation.
pub fn validate_unified_system_map(
    system: &[UnifiedSystemObject; UNIFIED_SYSTEM_OBJECTS],
) -> Result<UnifiedSystemMapEvidence, Error> {
    let mut system_blocks = 0u32;
    let mut snapshot_blocks = 0u32;
    for (i, s) in system.iter().enumerate() {
        let count = s.kind.blocks();
        let end = s.first_block.checked_add(count).ok_or(Error::Invalid)?;
        if s.inode != s.kind.inode_slot()
            || s.inode == 0
            || usize::from(s.inode) >= INODES
            || s.generation == 0
            || s.first_block < DATA_START
            || end > BLOCK_COUNT
            || system[..i]
                .iter()
                .any(|old| old.kind == s.kind || old.inode == s.inode)
        {
            return Err(Error::Invalid);
        }
        if let Some(fixed) = s.kind.fixed_first_block()
            && s.first_block != fixed
        {
            return Err(Error::Invalid);
        }
        for old in &system[..i] {
            let old_end = old.first_block + old.kind.blocks();
            if s.first_block < old_end && old.first_block < end {
                return Err(Error::Conflict);
            }
        }
        system_blocks = system_blocks.checked_add(count).ok_or(Error::Capacity)?;
        if s.kind.is_new_snapshot_object() {
            snapshot_blocks = snapshot_blocks.checked_add(count).ok_or(Error::Capacity)?;
        }
    }
    if system_blocks != UNIFIED_SYSTEM_BLOCKS || snapshot_blocks != SNAPSHOT_SYSTEM_BLOCKS {
        return Err(Error::Conflict);
    }
    Ok(UnifiedSystemMapEvidence {
        system_blocks,
        snapshot_blocks,
    })
}

/// Bridge the baseline `[SystemObject; 4]` concept toward the ratified N=8:
/// the four baseline objects keep their manifest-supplied locations (their
/// inode slots must still match the ratified segment), the four new snapshot
/// objects must carry the fixed map. The existing v1 validator is untouched.
pub fn unified_map_from_baseline(
    baseline: &[SystemObject; BASELINE_SYSTEM_OBJECTS],
    snapshot: &[UnifiedSystemObject; 4],
) -> Result<[UnifiedSystemObject; UNIFIED_SYSTEM_OBJECTS], Error> {
    for (i, b) in baseline.iter().enumerate() {
        if baseline[..i].iter().any(|old| old.kind == b.kind) {
            return Err(Error::Invalid);
        }
    }
    for (i, s) in snapshot.iter().enumerate() {
        if !s.kind.is_new_snapshot_object() || snapshot[..i].iter().any(|old| old.kind == s.kind) {
            return Err(Error::Invalid);
        }
    }
    let mut out = [UnifiedSystemObject {
        kind: UnifiedSystemKind::BootEpoch,
        inode: 0,
        generation: 0,
        first_block: 0,
    }; UNIFIED_SYSTEM_OBJECTS];
    for (i, b) in baseline.iter().enumerate() {
        out[i] = UnifiedSystemObject {
            kind: UnifiedSystemKind::from_baseline(b.kind),
            inode: b.inode,
            generation: b.generation,
            first_block: b.first_block,
        };
    }
    out[BASELINE_SYSTEM_OBJECTS..].copy_from_slice(snapshot);
    validate_unified_system_map(&out)?;
    Ok(out)
}

/// Unified superblock pair gate: the baseline §9.5 adjacent-generation pair
/// rules apply unchanged, and ONLY BaselineV1 is accepted. A legacy v2 pair
/// is read-only inventory (Unauthorized here); its sole join path is the D4
/// offline export/rebuild/import proof. The caller must still run the §9.4
/// full redo-area high-epoch preflight before any replay; this gate performs
/// no redo scan, no mount and no writes.
pub fn unified_superblock_pair(first: &[u8], second: &[u8]) -> Result<SuperblockV1, Error> {
    let probe = probe_snapshot_media_pair(first, second)?;
    if probe.kind != SnapshotMediaKind::BaselineV1 {
        return Err(Error::Unauthorized);
    }
    if SuperblockV1::decode(first)?.generation == probe.generation {
        SuperblockV1::decode(first)
    } else {
        SuperblockV1::decode(second)
    }
}

// ---------------------------------------------------------------------------
// D1.5: new-object envelope (golden-vector-pending fields)
// ---------------------------------------------------------------------------

pub const ENVELOPE_BYTES: usize = 40;
pub const ENVELOPE_VERSION: u16 = 1;
// New u32 magics, checked against every existing u32/u64 magic in the repo
// (including ResetProof v1 0x43595250 and ControlRPC 0x43594351/2). The SNAP_
// prefix keeps them distinct from the re-exported v4 REQUEST_MAGIC.
pub const SNAP_CATALOG_MAGIC: u32 = 0x4359_4143;
pub const SNAP_SLOT_MAGIC: u32 = 0x4359_4c53;
pub const SNAP_REQUEST_MAGIC: u32 = 0x4359_5152;
pub const SNAP_PROTECTION_MAGIC: u32 = 0x4359_4450;

/// Envelope of a new snapshot object's first block. Field-level payloads are
/// golden-vector-pending; until frozen, bytes 40..4096 MUST be all zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectEnvelope {
    pub kind: UnifiedSystemKind,
    pub fs_uuid: [u8; 16],
    pub generation: u64,
}

fn le16(b: &[u8], off: usize) -> Result<u16, Error> {
    let s = b.get(off..off + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn le32(b: &[u8], off: usize) -> Result<u32, Error> {
    let s = b.get(off..off + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le64(b: &[u8], off: usize) -> Result<u64, Error> {
    let s = b.get(off..off + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}
fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Strict envelope decode: exact 4 KiB, per-kind magic, version 1,
/// header_len 40, nonzero UUID/generation, reserved zero, all-zero pending
/// payload, CRC32C over the whole block with itself zeroed (baseline pattern).
pub fn decode_object_envelope(
    kind: UnifiedSystemKind,
    bytes: &[u8],
) -> Result<ObjectEnvelope, Error> {
    let magic = kind.envelope_magic().ok_or(Error::Invalid)?;
    if bytes.len() != SUPER_BYTES
        || le32(bytes, 0)? != magic
        || le16(bytes, 4)? != ENVELOPE_VERSION
        || le16(bytes, 6)? != ENVELOPE_BYTES as u16
        || le32(bytes, 36)? != 0
        || bytes[ENVELOPE_BYTES..].iter().any(|v| *v != 0)
        || le32(bytes, 32)? != crc32c_zeroed(bytes, 32)?
    {
        return Err(Error::Invalid);
    }
    let fs_uuid: [u8; 16] = bytes[8..24].try_into().map_err(|_| Error::Invalid)?;
    let generation = le64(bytes, 24)?;
    if fs_uuid == [0; 16] || generation == 0 {
        return Err(Error::Invalid);
    }
    Ok(ObjectEnvelope {
        kind,
        fs_uuid,
        generation,
    })
}

/// Canonical envelope encoder (contract layer; the future golden-vector
/// source). Writes the 40 B header and leaves the pending payload all zero.
pub fn encode_object_envelope(
    kind: UnifiedSystemKind,
    fs_uuid: [u8; 16],
    generation: u64,
    out: &mut [u8],
) -> Result<(), Error> {
    let magic = kind.envelope_magic().ok_or(Error::Invalid)?;
    if out.len() != SUPER_BYTES || fs_uuid == [0; 16] || generation == 0 {
        return Err(Error::Invalid);
    }
    out.fill(0);
    put32(out, 0, magic);
    put16(out, 4, ENVELOPE_VERSION);
    put16(out, 6, ENVELOPE_BYTES as u16);
    out[8..24].copy_from_slice(&fs_uuid);
    put64(out, 24, generation);
    let crc = crc32c_zeroed(out, 32)?;
    put32(out, 32, crc);
    Ok(())
}

// ---------------------------------------------------------------------------
// D2: 0x50 snapshot endpoint ops + capability bits (NOT SchemaV2 / SVC 0x45)
// ---------------------------------------------------------------------------

/// Existing service_call syscall number; no new syscall numbers (I7).
pub const SVC_SERVICE_CALL: u16 = 0x50;
/// Legacy FileServiceSchemaV2 magic — recognized only to reject (E_SCHEMA).
pub const LEGACY_SCHEMA_V2_MAGIC: u32 = 0x4359_4632;

pub const SNAP_OP_CREATE: u16 = 0x20;
pub const SNAP_OP_EXTEND: u16 = 0x21;
pub const SNAP_OP_DELETE_EXPIRED: u16 = 0x22;
pub const SNAP_OP_RESTORE: u16 = 0x23;
pub const SNAP_OP_LIST: u16 = 0x24;
pub const SNAP_OP_QUERY: u16 = 0x25;
pub const SNAP_OP_HISTORY_OPEN: u16 = 0x26;
pub const SNAP_OP_FREEZE_SET: u16 = 0x27;
pub const SNAP_OP_FREEZE_CLEAR: u16 = 0x28;
pub const SNAP_OP_OPEN_WRITES: u16 = 0x29;
pub const SNAP_OP_QUERY_REQUEST: u16 = 0x2a;
pub const SNAP_OP_ACK_REQUEST: u16 = 0x2b;
pub const SNAP_OP_COUNT: usize = 12;

// Independent snapshot_cap word; structurally separate from the file rights
// word (CapabilityRightsSchema v3 bit8..14). Ordinary file rights can never
// imply snapshot management authority (I8).
pub const SNAP_CAP_CREATE: u32 = 1 << 0;
pub const SNAP_CAP_EXTEND: u32 = 1 << 1;
pub const SNAP_CAP_DELETE_EXPIRED: u32 = 1 << 2;
pub const SNAP_CAP_RESTORE: u32 = 1 << 3;
pub const SNAP_CAP_LIST: u32 = 1 << 4;
pub const SNAP_CAP_HISTORY_READ: u32 = 1 << 5;
pub const SNAP_CAP_PROTECTION: u32 = 1 << 6;
pub const SNAP_CAP_MASK: u32 = 0x7f;

pub const fn snap_op_valid(op: u16) -> bool {
    op >= SNAP_OP_CREATE && op <= SNAP_OP_ACK_REQUEST
}

/// Required capability bit per op (V18 authority table carried over).
/// `None` = identity-gated op (QUERY_REQUEST/ACK_REQUEST) OR an invalid op;
/// callers must check [`snap_op_valid`] first.
pub const fn required_snapshot_cap(op: u16) -> Option<u32> {
    match op {
        SNAP_OP_CREATE => Some(SNAP_CAP_CREATE),
        SNAP_OP_EXTEND => Some(SNAP_CAP_EXTEND),
        SNAP_OP_DELETE_EXPIRED => Some(SNAP_CAP_DELETE_EXPIRED),
        SNAP_OP_RESTORE => Some(SNAP_CAP_RESTORE),
        SNAP_OP_LIST | SNAP_OP_QUERY => Some(SNAP_CAP_LIST),
        SNAP_OP_HISTORY_OPEN => Some(SNAP_CAP_HISTORY_READ),
        SNAP_OP_FREEZE_SET | SNAP_OP_FREEZE_CLEAR | SNAP_OP_OPEN_WRITES => {
            Some(SNAP_CAP_PROTECTION)
        }
        _ => None,
    }
}

pub const fn cap_word_valid(mask: u32) -> bool {
    mask & !SNAP_CAP_MASK == 0
}

/// CREATE/RESTORE/OPEN_WRITES carry the current live_view_epoch; all other
/// ops set that field to zero (V18 rule).
pub const fn op_needs_live_view_epoch(op: u16) -> bool {
    matches!(op, SNAP_OP_CREATE | SNAP_OP_RESTORE | SNAP_OP_OPEN_WRITES)
}

/// x3 cap_selector binding (§9.6.1 register layout): management ops require a
/// nonzero caller-private selector; identity-gated query/ACK require x3=0.
pub const fn op_needs_cap_selector(op: u16) -> bool {
    snap_op_valid(op) && !matches!(op, SNAP_OP_QUERY_REQUEST | SNAP_OP_ACK_REQUEST)
}

/// D3.2: the seven mutation classes consume durable request records; the
/// remaining five are read-only/identity-gated and consume no durable ticket.
pub const fn snap_op_durable(op: u16) -> bool {
    matches!(
        op,
        SNAP_OP_CREATE
            | SNAP_OP_EXTEND
            | SNAP_OP_DELETE_EXPIRED
            | SNAP_OP_RESTORE
            | SNAP_OP_FREEZE_SET
            | SNAP_OP_FREEZE_CLEAR
            | SNAP_OP_OPEN_WRITES
    )
}

/// Trusted enrollment classes (EL1-verified roles, never frame self-report).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotEnrollment {
    Ordinary,
    RecoverySupervisor,
    InternalMaintenance,
}

pub const ORDINARY_ENROLL_MASK: u32 = SNAP_CAP_CREATE
    | SNAP_CAP_EXTEND
    | SNAP_CAP_DELETE_EXPIRED
    | SNAP_CAP_LIST
    | SNAP_CAP_HISTORY_READ;
pub const RECOVERY_ENROLL_MASK: u32 =
    SNAP_CAP_LIST | SNAP_CAP_RESTORE | SNAP_CAP_PROTECTION | SNAP_CAP_HISTORY_READ;
pub const MAINTENANCE_ENROLL_MASK: u32 =
    SNAP_CAP_CREATE | SNAP_CAP_EXTEND | SNAP_CAP_DELETE_EXPIRED | SNAP_CAP_LIST;

pub const fn enrollment_mask(enrollment: SnapshotEnrollment) -> u32 {
    match enrollment {
        SnapshotEnrollment::Ordinary => ORDINARY_ENROLL_MASK,
        SnapshotEnrollment::RecoverySupervisor => RECOVERY_ENROLL_MASK,
        SnapshotEnrollment::InternalMaintenance => MAINTENANCE_ENROLL_MASK,
    }
}

/// Enrollment whitelist gate: ordinary principals can never receive RESTORE
/// or PROTECTION; the recovery supervisor can never occupy ordinary creation
/// authority; maintenance has no public issuer. Nonzero subset only.
pub const fn enroll_gate(enrollment: SnapshotEnrollment, mask: u32) -> Result<(), Error> {
    if mask == 0 || !cap_word_valid(mask) || mask & !enrollment_mask(enrollment) != 0 {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

/// QUERY_REQUEST/ACK_REQUEST identity gate: original durable principal or an
/// admitted recovery supervisor; no capability bit substitutes for identity.
pub const fn request_access_gate(
    original_principal: bool,
    recovery_supervisor: bool,
) -> Result<(), Error> {
    if original_principal || recovery_supervisor {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}

/// D6.2: after restore the write gate stays closed; only the conjunction of a
/// real restore-completion proof, the current protection generation and an
/// independent PROTECTION authority may open it. No model/auto-restart path.
pub const fn open_writes_gate(
    completion_proof: bool,
    current_protection_generation: bool,
    independent_authority: bool,
) -> Result<(), Error> {
    if completion_proof && current_protection_generation && independent_authority {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}

/// Legacy SchemaV2 frames are recognized and rejected before side effects
/// (§13.6 E_SCHEMA/E_STALE); they never act as v4/Reply v3.
pub const fn legacy_schema_v2_frame(magic: u32) -> bool {
    magic == LEGACY_SCHEMA_V2_MAGIC
}

// ---------------------------------------------------------------------------
// D3: v4/Reply v3 binding bounds + staging reuse
// ---------------------------------------------------------------------------

/// Snapshot frames ride the v4 32 B header / Reply v3 128 B header (re-exported
/// baseline constants above) with tighter V18-carried total-length bounds.
pub const SNAP_MAX_REQUEST_BYTES: usize = 1024;
pub const SNAP_MAX_REPLY_BYTES: usize = 2048;
/// v4 staging discipline reused, no new pool: 17 pages per slot, <=8 slots
/// globally = 544 KiB accounted to business RAM; failures never consume the
/// completion/recovery pools (I5).
pub const STAGING_SLOT_BYTES: usize = 69632;
pub const STAGING_MAX_SLOTS: usize = 8;
pub const STAGING_TOTAL_BYTES: usize = 544 * 1024;
const _: () = assert!(STAGING_SLOT_BYTES * STAGING_MAX_SLOTS == STAGING_TOTAL_BYTES);
const _: () = assert!(SNAP_MAX_REQUEST_BYTES <= MAX_REQUEST);
const _: () = assert!(SNAP_MAX_REPLY_BYTES <= MAX_REPLY);
const _: () = assert!(REQUEST_HEADER == 32 && REPLY_HEADER == 128);

// ---------------------------------------------------------------------------
// D4: migration continuity proof (offline export -> rebuild -> import)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotContinuity {
    pub slot_generation: u64,
    pub retention_deadline: u64,
}

/// Per-item monotonicity witness for the v2 -> unified import proof (I1/I3/I4).
/// Conservative fail-closed contract: every carried generation/deadline/water-
/// mark must be non-regressing; proven DELETE_EXPIRED discharge records belong
/// to the later full migration protocol deliverable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationWitness {
    pub fs_uuid: [u8; 16],
    pub boot_epoch: u64,
    pub protection_generation: u64,
    pub live_view_epoch: u64,
    pub state_generation: u64,
    pub rule_min_generation: u64,
    pub security_min_generation: u64,
    pub key_generation: u64,
    pub request_watermark: u64,
    pub snapshot_id_hi: u64,
    pub slots: [SlotContinuity; SNAPSHOT_SLOTS as usize],
}

/// Import continuity gate. Identity mismatch or any regression -> Conflict
/// (no writable migration without proof, I2). Zero UUIDs are invalid input.
pub fn check_migration_continuity(
    old: &MigrationWitness,
    new: &MigrationWitness,
) -> Result<(), Error> {
    if old.fs_uuid == [0; 16] || new.fs_uuid == [0; 16] {
        return Err(Error::Invalid);
    }
    if old.fs_uuid != new.fs_uuid {
        return Err(Error::Conflict);
    }
    if new.boot_epoch < old.boot_epoch
        || new.protection_generation < old.protection_generation
        || new.live_view_epoch < old.live_view_epoch
        || new.state_generation < old.state_generation
        || new.rule_min_generation < old.rule_min_generation
        || new.security_min_generation < old.security_min_generation
        || new.key_generation < old.key_generation
        || new.request_watermark < old.request_watermark
        || new.snapshot_id_hi < old.snapshot_id_hi
    {
        return Err(Error::Conflict);
    }
    for (o, n) in old.slots.iter().zip(new.slots.iter()) {
        if n.slot_generation < o.slot_generation {
            return Err(Error::Conflict);
        }
        // An occupied exported slot must survive import with a non-shortened
        // deadline (retention only extends). A vanished slot loses history.
        if o.slot_generation > 0 && n.retention_deadline < o.retention_deadline {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// D5: budget carve-out (68/128/48 KiB -> 8/8/10 MiB unique ownership)
// ---------------------------------------------------------------------------

// Control-pool sub-budget (protected snapshot management), carved from the
// §13.7 uncommitted margin exactly like the existing 64 KiB contract
// sub-budget precedent; the 8 MiB control total never grows.
pub const SNAP_HANDLES_KIB: u32 = 16;
pub const SNAP_FROZEN_VIEWS_KIB: u32 = 24;
pub const SNAP_CONTROL_CACHE_KIB: u32 = 8;
pub const SNAP_COORDINATION_KIB: u32 = 4;
pub const SNAP_MGMT_CONTROL_KIB: u32 = 52;
/// Shared bitmap mirror lives in the file-service transaction workspace
/// (business RAM), not in the control sub-budget.
pub const SNAP_SHARED_BITMAP_KIB: u32 = 16;
/// V18 historical management total = 52 control + 16 business workspace.
pub const SNAP_LEGACY_MGMT_KIB: u32 = 68;
pub const SNAP_COW_VERSION_KIB: u32 = 128;
pub const SNAP_GC_WORKSPACE_KIB: u32 = 48;
pub const FILE_TRANSACTION_WORKSPACE_KIB: u32 = 160;
pub const CONTROL_POOL_KIB: u32 = 8192;
pub const PROGRESS_POOL_KIB: u32 = 8192;
pub const FRAME_META_KIB: u32 = 10240;
/// §13.7 uncommitted margin 1335 KiB minus the 52 KiB carve-out.
pub const CONTROL_UNCOMMITTED_MARGIN_KIB: u32 = 1283;
const _: () = assert!(
    SNAP_HANDLES_KIB + SNAP_FROZEN_VIEWS_KIB + SNAP_CONTROL_CACHE_KIB + SNAP_COORDINATION_KIB
        == SNAP_MGMT_CONTROL_KIB
);
const _: () = assert!(SNAP_MGMT_CONTROL_KIB + SNAP_SHARED_BITMAP_KIB == SNAP_LEGACY_MGMT_KIB);
const _: () = assert!(1335 - SNAP_MGMT_CONTROL_KIB == CONTROL_UNCOMMITTED_MARGIN_KIB);
const _: () = assert!(SNAP_GC_WORKSPACE_KIB <= FILE_TRANSACTION_WORKSPACE_KIB);
const _: () = assert!(CONTROL_POOL_KIB == 8 * 1024 && PROGRESS_POOL_KIB == 8 * 1024);
const _: () = assert!(FRAME_META_KIB == 10 * 1024);

// Parameter-registry candidate carry-over (direction ratified; exact lock
// pending the byte-exact freeze together with layout/ledger/test windows).
pub const PERIODIC_SLOTS: u32 = 6;
pub const ONDEMAND_SLOTS: u32 = 2;
pub const SHORT_TIER_SLOTS: u32 = 3;
pub const LONG_TIER_SLOTS: u32 = 3;
pub const ONLINE_AGE_GRANULARITY_S: u64 = 60;
pub const HANDLES_ORDINARY: u32 = 112;
pub const HANDLES_RECOVERY: u32 = 16;
pub const FROZEN_VIEWS_ORDINARY: u32 = 56;
pub const FROZEN_VIEWS_RECOVERY: u32 = 8;
pub const REQUESTS_ORDINARY: u32 = 48;
pub const REQUESTS_MAINTENANCE: u32 = 8;
pub const REQUESTS_RECOVERY: u32 = 8;
pub const REQUEST_RECORD_BYTES: usize = 512;
pub const SHORT_PERIOD_S: u64 = 6 * 3600;
pub const SHORT_RETENTION_S: u64 = 18 * 3600;
pub const LONG_PERIOD_S: u64 = 48 * 3600;
pub const LONG_RETENTION_S: u64 = 144 * 3600;
pub const ONDEMAND_MIN_S: u64 = 3600;
pub const ONDEMAND_DEFAULT_S: u64 = 24 * 3600;
pub const ONDEMAND_MAX_S: u64 = 7 * 24 * 3600;
const _: () = assert!(PERIODIC_SLOTS + ONDEMAND_SLOTS == SNAPSHOT_SLOTS);
const _: () = assert!(SHORT_TIER_SLOTS + LONG_TIER_SLOTS == PERIODIC_SLOTS);
const _: () = assert!(HANDLES_ORDINARY + HANDLES_RECOVERY == 128);
const _: () = assert!(FROZEN_VIEWS_ORDINARY + FROZEN_VIEWS_RECOVERY == 64);
const _: () = assert!(REQUESTS_ORDINARY + REQUESTS_MAINTENANCE + REQUESTS_RECOVERY == 64);
const _: () = assert!(ONDEMAND_MIN_S <= ONDEMAND_DEFAULT_S && ONDEMAND_DEFAULT_S <= ONDEMAND_MAX_S);
const _: () = assert!(SHORT_RETENTION_S > SHORT_PERIOD_S && LONG_RETENTION_S > LONG_PERIOD_S);

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_map() -> [UnifiedSystemObject; UNIFIED_SYSTEM_OBJECTS] {
        let obj = |kind: UnifiedSystemKind, first_block: u32| UnifiedSystemObject {
            kind,
            inode: kind.inode_slot(),
            generation: 1,
            first_block,
        };
        [
            obj(UnifiedSystemKind::BootEpoch, DATA_START),
            obj(UnifiedSystemKind::Receipts, DATA_START + 1),
            obj(UnifiedSystemKind::Acl, DATA_START + 8),
            obj(UnifiedSystemKind::Security, DATA_START + 12),
            obj(UnifiedSystemKind::SnapshotCatalog, SNAPSHOT_CATALOG_BLOCK),
            obj(UnifiedSystemKind::SnapshotSlot, SNAPSHOT_SLOT_START),
            obj(UnifiedSystemKind::SnapshotRequest, SNAPSHOT_REQUEST_START),
            obj(
                UnifiedSystemKind::SnapshotProtection,
                SNAPSHOT_PROTECTION_BLOCK,
            ),
        ]
    }

    fn baseline_four() -> [SystemObject; BASELINE_SYSTEM_OBJECTS] {
        [
            SystemObject {
                kind: SystemKind::BootEpoch,
                inode: BOOT_INODE,
                generation: 1,
                first_block: 7002,
            },
            SystemObject {
                kind: SystemKind::Receipts,
                inode: RECEIPTS_INODE,
                generation: 1,
                first_block: 7003,
            },
            SystemObject {
                kind: SystemKind::Acl,
                inode: ACL_INODE,
                generation: 1,
                first_block: 7010,
            },
            SystemObject {
                kind: SystemKind::Security,
                inode: SECURITY_INODE,
                generation: 1,
                first_block: 7000,
            },
        ]
    }

    fn snapshot_four() -> [UnifiedSystemObject; 4] {
        let m = canonical_map();
        [m[4], m[5], m[6], m[7]]
    }

    fn super_v1() -> [u8; SUPER_BYTES] {
        let mut b = [0u8; SUPER_BYTES];
        put32(&mut b, 0, super::super::file_media_v0199::SUPER_MAGIC);
        put16(&mut b, 4, 1);
        put16(&mut b, 6, 80);
        put32(&mut b, 8, 4096);
        put32(&mut b, 12, BLOCK_COUNT);
        b[16..32].copy_from_slice(&[1u8; 16]);
        put64(&mut b, 32, 1);
        put64(&mut b, 48, 1);
        put32(&mut b, 56, BITMAP_START);
        put32(&mut b, 60, INODE_START);
        put32(&mut b, 64, DATA_START);
        put32(&mut b, 68, 256);
        let crc = crc32c_zeroed(&b, 76).unwrap();
        put32(&mut b, 76, crc);
        b
    }

    #[test]
    fn canonical_map_validates_with_151_system_blocks() {
        let e = validate_unified_system_map(&canonical_map()).unwrap();
        assert_eq!(e.system_blocks, 151);
        assert_eq!(e.snapshot_blocks, 138);
        assert_eq!(UNIFIED_SYSTEM_OBJECTS, 8);
        assert_eq!(BASELINE_SYSTEM_BLOCKS, 13);
    }

    #[test]
    fn map_rejects_duplicate_or_missing_kind() {
        let mut m = canonical_map();
        m[1].kind = UnifiedSystemKind::BootEpoch;
        m[1].inode = BOOT_INODE;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
        let mut m = canonical_map();
        m[4].kind = UnifiedSystemKind::SnapshotSlot;
        m[4].inode = SLOT_INODE;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
    }

    #[test]
    fn map_rejects_wrong_inode_slot() {
        // Old baseline-fixture slots (2..5) are not the ratified segment.
        let mut m = canonical_map();
        m[0].inode = 2;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
        let mut m = canonical_map();
        m[5].inode = 227;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
        let mut m = canonical_map();
        m[4].inode = 0;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
    }

    #[test]
    fn map_rejects_zero_generation_and_out_of_bounds() {
        let mut m = canonical_map();
        m[2].generation = 0;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
        let mut m = canonical_map();
        m[0].first_block = DATA_START - 1;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
        let mut m = canonical_map();
        m[1].first_block = BLOCK_COUNT - 3;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
    }

    #[test]
    fn map_rejects_moved_snapshot_objects() {
        for i in 4..8 {
            let mut m = canonical_map();
            m[i].first_block += 1;
            assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
            let mut m = canonical_map();
            m[i].first_block -= 1;
            assert_eq!(validate_unified_system_map(&m), Err(Error::Invalid));
        }
    }

    #[test]
    fn map_rejects_overlapping_baseline_range() {
        // A manifest baseline object landing inside the fixed snapshot map.
        let mut m = canonical_map();
        m[0].first_block = SNAPSHOT_CATALOG_BLOCK;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Conflict));
        let mut m = canonical_map();
        m[1].first_block = SNAPSHOT_SLOT_START + 10;
        assert_eq!(validate_unified_system_map(&m), Err(Error::Conflict));
    }

    #[test]
    fn bridge_extends_baseline_four_to_eight_without_moving_them() {
        let baseline = baseline_four();
        let out = unified_map_from_baseline(&baseline, &snapshot_four()).unwrap();
        assert_eq!(out[0].first_block, 7002);
        assert_eq!(out[3].first_block, 7000);
        assert_eq!(out[4].first_block, SNAPSHOT_CATALOG_BLOCK);
        let e = validate_unified_system_map(&out).unwrap();
        assert_eq!(e.system_blocks, 151);
    }

    #[test]
    fn bridge_rejects_wrong_kind_sets() {
        let mut baseline = baseline_four();
        baseline[1].kind = SystemKind::BootEpoch;
        assert_eq!(
            unified_map_from_baseline(&baseline, &snapshot_four()),
            Err(Error::Invalid)
        );
        let mut snap = snapshot_four();
        snap[0].kind = UnifiedSystemKind::BootEpoch;
        assert_eq!(
            unified_map_from_baseline(&baseline_four(), &snap),
            Err(Error::Invalid)
        );
        // Baseline fixture inode slots (2..5) fail the ratified segment.
        let mut baseline = baseline_four();
        baseline[0].inode = 2;
        assert_eq!(
            unified_map_from_baseline(&baseline, &snapshot_four()),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn unified_superblock_gate_accepts_v1_pair_and_rejects_v2() {
        let v1 = super_v1();
        let sb = unified_superblock_pair(&v1, &v1).unwrap();
        assert_eq!(sb.fs_uuid, [1; 16]);
        assert_eq!(sb.generation, 1);
        // Adjacent checkpoint pair selects the higher generation.
        let mut next = v1;
        put64(&mut next, 32, 2);
        put64(&mut next, 40, 19);
        put64(&mut next, 48, 2);
        let crc = crc32c_zeroed(&next, 76).unwrap();
        put32(&mut next, 76, crc);
        assert_eq!(unified_superblock_pair(&v1, &next).unwrap().generation, 2);
        // Legacy v2 encoded by the actual historical encoder: read-only only.
        let old = cyxia_prototype::storage::Superblock {
            fs_uuid: [1; 16],
            generation: 1,
            checkpoint_lsn: 0,
            log_epoch: 1,
        };
        let mut v2 = [0u8; SUPER_BYTES];
        old.encode(&mut v2).unwrap();
        assert_eq!(unified_superblock_pair(&v2, &v2), Err(Error::Unauthorized));
        assert_eq!(unified_superblock_pair(&v1, &v2), Err(Error::Conflict));
    }

    #[test]
    fn envelope_roundtrip_for_all_four_new_kinds() {
        for kind in [
            UnifiedSystemKind::SnapshotCatalog,
            UnifiedSystemKind::SnapshotSlot,
            UnifiedSystemKind::SnapshotRequest,
            UnifiedSystemKind::SnapshotProtection,
        ] {
            let mut b = [0u8; SUPER_BYTES];
            encode_object_envelope(kind, [7; 16], 9, &mut b).unwrap();
            let e = decode_object_envelope(kind, &b).unwrap();
            assert_eq!(e.kind, kind);
            assert_eq!(e.fs_uuid, [7; 16]);
            assert_eq!(e.generation, 9);
            assert!(b[ENVELOPE_BYTES..].iter().all(|v| *v == 0));
        }
    }

    #[test]
    fn envelope_rejects_corruption_and_pending_payload_bytes() {
        let kind = UnifiedSystemKind::SnapshotProtection;
        let mut good = [0u8; SUPER_BYTES];
        encode_object_envelope(kind, [7; 16], 9, &mut good).unwrap();
        let reseal = |b: &mut [u8; SUPER_BYTES]| {
            let crc = crc32c_zeroed(b, 32).unwrap();
            put32(b, 32, crc);
        };
        let mut b = good;
        b[0] ^= 1;
        assert_eq!(decode_object_envelope(kind, &b), Err(Error::Invalid));
        b = good;
        put16(&mut b, 4, 2);
        reseal(&mut b);
        assert_eq!(decode_object_envelope(kind, &b), Err(Error::Invalid));
        b = good;
        put16(&mut b, 6, 48);
        reseal(&mut b);
        assert_eq!(decode_object_envelope(kind, &b), Err(Error::Invalid));
        b = good;
        put32(&mut b, 36, 1);
        reseal(&mut b);
        assert_eq!(decode_object_envelope(kind, &b), Err(Error::Invalid));
        b = good;
        b[32] ^= 1;
        assert_eq!(decode_object_envelope(kind, &b), Err(Error::Invalid));
        // Field layouts are golden-vector-pending: any payload byte denies.
        b = good;
        b[ENVELOPE_BYTES] = 1;
        reseal(&mut b);
        assert_eq!(decode_object_envelope(kind, &b), Err(Error::Invalid));
        b = good;
        b[8..24].fill(0);
        reseal(&mut b);
        assert_eq!(decode_object_envelope(kind, &b), Err(Error::Invalid));
        b = good;
        put64(&mut b, 24, 0);
        reseal(&mut b);
        assert_eq!(decode_object_envelope(kind, &b), Err(Error::Invalid));
        assert_eq!(
            decode_object_envelope(kind, &good[..SUPER_BYTES - 1]),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn envelope_rejects_cross_kind_magic_and_baseline_kinds() {
        let mut b = [0u8; SUPER_BYTES];
        encode_object_envelope(UnifiedSystemKind::SnapshotCatalog, [7; 16], 9, &mut b).unwrap();
        assert_eq!(
            decode_object_envelope(UnifiedSystemKind::SnapshotSlot, &b),
            Err(Error::Invalid)
        );
        for baseline in [
            UnifiedSystemKind::BootEpoch,
            UnifiedSystemKind::Receipts,
            UnifiedSystemKind::Acl,
            UnifiedSystemKind::Security,
        ] {
            assert_eq!(baseline.envelope_magic(), None);
            assert_eq!(decode_object_envelope(baseline, &b), Err(Error::Invalid));
            assert_eq!(
                encode_object_envelope(baseline, [7; 16], 9, &mut b),
                Err(Error::Invalid)
            );
        }
        // Magics must not collide with existing frozen u32 magics.
        for m in [
            SNAP_CATALOG_MAGIC,
            SNAP_SLOT_MAGIC,
            SNAP_REQUEST_MAGIC,
            SNAP_PROTECTION_MAGIC,
        ] {
            assert_ne!(m, super::super::file_media_v0199::SUPER_MAGIC);
            assert_ne!(m, super::super::file_media_v0199::RECEIPT_MAGIC);
            assert_ne!(m, REQUEST_MAGIC); // v4 request magic (re-exported)
            assert_ne!(m, REPLY_MAGIC);
            assert_ne!(m, LEGACY_SCHEMA_V2_MAGIC);
            assert_ne!(m, 0x4359_5250); // ResetProof v1
            assert_ne!(m, 0x4359_4351); // ControlRPC request
            assert_ne!(m, 0x4359_5450); // trial permit
        }
    }

    #[test]
    fn twelve_op_classes_match_v18_authority_table() {
        let table = [
            (SNAP_OP_CREATE, Some(SNAP_CAP_CREATE)),
            (SNAP_OP_EXTEND, Some(SNAP_CAP_EXTEND)),
            (SNAP_OP_DELETE_EXPIRED, Some(SNAP_CAP_DELETE_EXPIRED)),
            (SNAP_OP_RESTORE, Some(SNAP_CAP_RESTORE)),
            (SNAP_OP_LIST, Some(SNAP_CAP_LIST)),
            (SNAP_OP_QUERY, Some(SNAP_CAP_LIST)),
            (SNAP_OP_HISTORY_OPEN, Some(SNAP_CAP_HISTORY_READ)),
            (SNAP_OP_FREEZE_SET, Some(SNAP_CAP_PROTECTION)),
            (SNAP_OP_FREEZE_CLEAR, Some(SNAP_CAP_PROTECTION)),
            (SNAP_OP_OPEN_WRITES, Some(SNAP_CAP_PROTECTION)),
            (SNAP_OP_QUERY_REQUEST, None),
            (SNAP_OP_ACK_REQUEST, None),
        ];
        assert_eq!(table.len(), SNAP_OP_COUNT);
        for (op, cap) in table {
            assert!(snap_op_valid(op));
            assert_eq!(required_snapshot_cap(op), cap);
        }
        assert!(!snap_op_valid(0x1f));
        assert!(!snap_op_valid(0x2c));
        assert!(!snap_op_valid(1)); // baseline FILE_SERVICE op range disjoint
        assert!(!snap_op_valid(15));
        assert_eq!(SVC_SERVICE_CALL, 0x50);
    }

    #[test]
    fn capability_word_and_enrollment_whitelists() {
        assert!(cap_word_valid(SNAP_CAP_MASK));
        assert!(!cap_word_valid(1 << 7));
        assert!(!cap_word_valid(1 << 31));
        // Ordinary enrollment can never carry RESTORE/PROTECTION.
        assert_eq!(
            enroll_gate(SnapshotEnrollment::Ordinary, SNAP_CAP_RESTORE),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            enroll_gate(SnapshotEnrollment::Ordinary, SNAP_CAP_PROTECTION),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            enroll_gate(SnapshotEnrollment::Ordinary, ORDINARY_ENROLL_MASK),
            Ok(())
        );
        // Recovery supervisor can never create; maintenance stays bounded.
        assert_eq!(
            enroll_gate(SnapshotEnrollment::RecoverySupervisor, SNAP_CAP_CREATE),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            enroll_gate(SnapshotEnrollment::RecoverySupervisor, RECOVERY_ENROLL_MASK),
            Ok(())
        );
        assert_eq!(
            enroll_gate(
                SnapshotEnrollment::InternalMaintenance,
                MAINTENANCE_ENROLL_MASK
            ),
            Ok(())
        );
        assert_eq!(
            enroll_gate(SnapshotEnrollment::InternalMaintenance, SNAP_CAP_RESTORE),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            enroll_gate(SnapshotEnrollment::Ordinary, 0),
            Err(Error::Unauthorized)
        );
        // File rights bits (8..14) are not snapshot capability bits.
        for bit in 8..15 {
            assert!(!cap_word_valid(1 << bit));
        }
    }

    #[test]
    fn request_access_and_open_writes_atomic_gates() {
        assert_eq!(request_access_gate(true, false), Ok(()));
        assert_eq!(request_access_gate(false, true), Ok(()));
        assert_eq!(request_access_gate(false, false), Err(Error::Unauthorized));
        assert_eq!(open_writes_gate(true, true, true), Ok(()));
        for flags in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
            (false, false, false),
        ] {
            assert_eq!(
                open_writes_gate(flags.0, flags.1, flags.2),
                Err(Error::Unauthorized)
            );
        }
    }

    #[test]
    fn register_selector_and_live_view_epoch_binding() {
        for op in SNAP_OP_CREATE..=SNAP_OP_OPEN_WRITES {
            assert!(op_needs_cap_selector(op));
        }
        assert!(!op_needs_cap_selector(SNAP_OP_QUERY_REQUEST));
        assert!(!op_needs_cap_selector(SNAP_OP_ACK_REQUEST));
        assert!(!op_needs_cap_selector(0x30));
        for op in SNAP_OP_CREATE..=SNAP_OP_ACK_REQUEST {
            assert_eq!(
                op_needs_live_view_epoch(op),
                matches!(op, SNAP_OP_CREATE | SNAP_OP_RESTORE | SNAP_OP_OPEN_WRITES)
            );
        }
    }

    #[test]
    fn durable_split_is_seven_mutations_five_volatile() {
        let mut durable = 0;
        for op in SNAP_OP_CREATE..=SNAP_OP_ACK_REQUEST {
            if snap_op_durable(op) {
                durable += 1;
            }
        }
        assert_eq!(durable, 7);
        for op in [
            SNAP_OP_LIST,
            SNAP_OP_QUERY,
            SNAP_OP_HISTORY_OPEN,
            SNAP_OP_QUERY_REQUEST,
            SNAP_OP_ACK_REQUEST,
        ] {
            assert!(!snap_op_durable(op));
        }
    }

    fn witness() -> MigrationWitness {
        MigrationWitness {
            fs_uuid: [1; 16],
            boot_epoch: 2,
            protection_generation: 3,
            live_view_epoch: 4,
            state_generation: 5,
            rule_min_generation: 1,
            security_min_generation: 1,
            key_generation: 2,
            request_watermark: 100,
            snapshot_id_hi: 9,
            slots: [SlotContinuity {
                slot_generation: 1,
                retention_deadline: 1000,
            }; SNAPSHOT_SLOTS as usize],
        }
    }

    #[test]
    fn migration_continuity_accepts_extension_rejects_any_regression() {
        let old = witness();
        assert_eq!(check_migration_continuity(&old, &old), Ok(()));
        let mut new = witness();
        new.boot_epoch += 1;
        new.protection_generation += 1;
        new.request_watermark += 10;
        new.slots[0].retention_deadline += 60;
        assert_eq!(check_migration_continuity(&old, &new), Ok(()));
        // Every scalar field is individually monotonic.
        let regressions: [fn(&mut MigrationWitness); 9] = [
            |w| w.boot_epoch -= 1,
            |w| w.protection_generation -= 1,
            |w| w.live_view_epoch -= 1,
            |w| w.state_generation -= 1,
            |w| w.rule_min_generation -= 1,
            |w| w.security_min_generation -= 1,
            |w| w.key_generation -= 1,
            |w| w.request_watermark -= 1,
            |w| w.snapshot_id_hi -= 1,
        ];
        for f in regressions {
            let mut bad = witness();
            f(&mut bad);
            assert_eq!(check_migration_continuity(&old, &bad), Err(Error::Conflict));
        }
        let mut bad = witness();
        bad.fs_uuid = [2; 16];
        assert_eq!(check_migration_continuity(&old, &bad), Err(Error::Conflict));
        let mut bad = witness();
        bad.fs_uuid = [0; 16];
        assert_eq!(check_migration_continuity(&old, &bad), Err(Error::Invalid));
    }

    #[test]
    fn migration_slot_history_cannot_vanish_or_shorten() {
        let old = witness();
        let mut new = witness();
        new.slots[3].retention_deadline -= 1;
        assert_eq!(check_migration_continuity(&old, &new), Err(Error::Conflict));
        let mut new = witness();
        new.slots[3].slot_generation = 0;
        new.slots[3].retention_deadline = 0;
        assert_eq!(check_migration_continuity(&old, &new), Err(Error::Conflict));
        let mut new = witness();
        new.slots[3].slot_generation -= 1;
        assert_eq!(check_migration_continuity(&old, &new), Err(Error::Conflict));
        // Generation advance with a non-shortened deadline is legal reuse.
        let mut new = witness();
        new.slots[3].slot_generation += 1;
        new.slots[3].retention_deadline += 1;
        assert_eq!(check_migration_continuity(&old, &new), Ok(()));
        // An empty exported slot imposes no obligation.
        let mut old_empty = witness();
        old_empty.slots[6] = SlotContinuity {
            slot_generation: 0,
            retention_deadline: 0,
        };
        let mut new = witness();
        new.slots[6] = SlotContinuity {
            slot_generation: 1,
            retention_deadline: 5,
        };
        assert_eq!(check_migration_continuity(&old_empty, &new), Ok(()));
    }

    #[test]
    fn budget_carve_out_and_staging_arithmetic() {
        assert_eq!(
            SNAP_HANDLES_KIB
                + SNAP_FROZEN_VIEWS_KIB
                + SNAP_CONTROL_CACHE_KIB
                + SNAP_COORDINATION_KIB,
            52
        );
        assert_eq!(SNAP_MGMT_CONTROL_KIB + SNAP_SHARED_BITMAP_KIB, 68);
        assert_eq!(1335 - SNAP_MGMT_CONTROL_KIB, CONTROL_UNCOMMITTED_MARGIN_KIB);
        assert_eq!(CONTROL_UNCOMMITTED_MARGIN_KIB, 1283);
        assert_eq!(STAGING_SLOT_BYTES * STAGING_MAX_SLOTS, 544 * 1024);
        assert_eq!(SNAP_COW_VERSION_KIB, 128);
        assert_eq!(SNAP_GC_WORKSPACE_KIB, 48);
        assert!(SNAP_GC_WORKSPACE_KIB <= FILE_TRANSACTION_WORKSPACE_KIB);
        assert_eq!(
            CONTROL_POOL_KIB + PROGRESS_POOL_KIB + FRAME_META_KIB,
            8192 + 8192 + 10240
        );
        assert_eq!(PERIODIC_SLOTS + ONDEMAND_SLOTS, SNAPSHOT_SLOTS);
        assert_eq!(
            REQUESTS_ORDINARY + REQUESTS_MAINTENANCE + REQUESTS_RECOVERY,
            64
        );
        assert_eq!(HANDLES_ORDINARY + HANDLES_RECOVERY, 128);
        assert_eq!(FROZEN_VIEWS_ORDINARY + FROZEN_VIEWS_RECOVERY, 64);
    }

    #[test]
    fn legacy_schema_v2_is_recognized_and_never_acts_as_v4() {
        assert!(legacy_schema_v2_frame(LEGACY_SCHEMA_V2_MAGIC));
        assert!(!legacy_schema_v2_frame(REQUEST_MAGIC));
        assert!(!legacy_schema_v2_frame(REPLY_MAGIC));
        assert_ne!(LEGACY_SCHEMA_V2_MAGIC, REQUEST_MAGIC);
        assert_eq!(REQUEST_VERSION, 4);
        assert_eq!(REPLY_VERSION, 3);
        assert!(SNAP_MAX_REQUEST_BYTES <= MAX_REQUEST);
        assert!(SNAP_MAX_REPLY_BYTES <= MAX_REPLY);
    }

    #[test]
    fn layout_constants_derive_from_baseline_and_ratified_geometry() {
        assert_eq!(DATA_START, 4118);
        assert_eq!(BITMAP_START, 4098);
        assert_eq!(INODE_START, 4102);
        assert_eq!(BLOCK_COUNT, 131072);
        assert_eq!(SLOT_MIRROR_BYTES, 224 * 256);
        assert_eq!(BUSINESS_INODES, 224);
        assert_eq!(SYSTEM_INODE_START, 224);
        assert_eq!(RESERVED_INODE_START, 232);
        assert_eq!(SNAPSHOT_SLOT_START + 8 * 15, SNAPSHOT_REQUEST_START);
        assert_eq!(SNAPSHOT_PROTECTION_BLOCK + 1, CANONICAL_BUSINESS_START);
        assert_eq!(CANONICAL_BUSINESS_START, 4269);
        // v2's hard business start (8354) is deliberately NOT carried over.
        assert_ne!(CANONICAL_BUSINESS_START, 8354);
    }
}
