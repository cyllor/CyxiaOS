//! Baseline-v1 and unified-v1 mount checks join filesystem structure with
//! protected system objects, persistent principal identities and ACLs.
//! These checks consume the exclusive native post-replay disk view.
//! They do not issue file capabilities, clear UNKNOWN receipts or certify
//! that a signed startup catalog or writable production service exists.
use super::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::{FileStreamIndexV4, SecurityStateStoreV2},
    file_media_unified_v1::{
        BASELINE_SYSTEM_BLOCKS, BASELINE_SYSTEM_OBJECTS, UNIFIED_SYSTEM_BLOCKS,
        UNIFIED_SYSTEM_OBJECTS, UnifiedSystemKind, UnifiedSystemObject, decode_object_envelope,
        unified_map_from_baseline,
    },
    file_media_v0199::{SuperblockV1, crc32c_zeroed},
    file_receipt_store_v0199::{self, RECEIPT_STORE_BYTES, ReceiptStoreSummary},
    file_structure_v1::{self, BLOCK, INODES, Inode, StructureEvidence, SystemKind, SystemObject},
    offline_config_v1::{Principal, VerifiedOfflineConfig},
};
use sha2::{Digest, Sha256};
const ACL_BYTES: usize = 64;
const ACL_STORE: usize = INODES * ACL_BYTES;
const FILE_RIGHTS: u32 = (1 << 8) | (1 << 9) | (1 << 13);
const DIR_RIGHTS: u32 = (1 << 10) | (1 << 11) | (1 << 12) | (1 << 14);
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acl {
    pub inode_id: u32,
    pub state: u32,
    pub inode_generation: u64,
    pub principal: Principal,
    pub owner_rights: u32,
    pub system_rights: u32,
    pub acl_generation: u64,
    pub parent: u32,
}
impl Acl {
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != ACL_BYTES
            || u32at(b, 52) != 0
            || u32at(b, 56) != 0
            || u32at(b, 60) != crc32c_zeroed(b, 60)?
        {
            return Err(Error::Invalid);
        }
        let a = Self {
            inode_id: u32at(b, 0),
            state: u32at(b, 4),
            inode_generation: u64at(b, 8),
            principal: Principal {
                id: u64at(b, 16),
                generation: u64at(b, 24),
            },
            owner_rights: u32at(b, 32),
            system_rights: u32at(b, 36),
            acl_generation: u64at(b, 40),
            parent: u32at(b, 48),
        };
        if a.inode_id >= INODES as u32
            || a.state > 2
            || a.parent >= INODES as u32
            || (a.owner_rights | a.system_rights) & !(FILE_RIGHTS | DIR_RIGHTS) != 0
        {
            return Err(Error::Invalid);
        }
        Ok(a)
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub inodes: u32,
    pub blocks: u32,
    pub directory_slots: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountEvidence {
    pub structure: StructureEvidence,
    pub boot: BootEpochStoreV1,
    pub security: SecurityStateStoreV2,
    pub receipts: ReceiptStoreSummary,
    pub usage: [Usage; 16],
    pub system_blocks: u32,
    baseline_system: Option<[SystemObject; 4]>,
}

impl MountEvidence {
    pub(super) const fn baseline_system(&self) -> Option<&[SystemObject; 4]> {
        self.baseline_system.as_ref()
    }
}
pub struct Workspace {
    structure: file_structure_v1::Workspace,
    boot: [u8; BLOCK],
    security: [u8; BLOCK],
    index: [u8; BLOCK],
    receipts: [u8; RECEIPT_STORE_BYTES],
    acl: [u8; ACL_STORE],
}
impl Workspace {
    pub const fn new() -> Self {
        Self {
            structure: file_structure_v1::Workspace::new(),
            boot: [0; BLOCK],
            security: [0; BLOCK],
            index: [0; BLOCK],
            receipts: [0; RECEIPT_STORE_BYTES],
            acl: [0; ACL_STORE],
        }
    }

    /// Check the receipt/query view captured by a successful exclusive mount
    /// after the owner independently verifies the single paired BootEpoch redo.
    /// That transaction changes only the boot and security homes, so the
    /// receipt and index images from the same mount remain valid. This is
    /// read-only custody evidence, not a FILE_RECEIPT_QUERY role qualification.
    pub fn confirmed_receipt_query_digest(
        &self,
        prior: &MountEvidence,
        committed: &SecurityStateStoreV2,
        config: &VerifiedOfflineConfig<'_>,
    ) -> Result<[u8; 32], Error> {
        let old_boot = BootEpochStoreV1::decode(&self.boot)?;
        let old_security = SecurityStateStoreV2::decode(&self.security)?;
        let receipts = file_receipt_store_v0199::scan_receipts_with_index(
            &self.receipts,
            &self.index,
            old_boot.fs_uuid,
        )?;
        if old_boot != prior.boot
            || old_security != prior.security
            || !old_boot.matches(&old_security)
            || receipts != prior.receipts
        {
            return Err(Error::Conflict);
        }
        let expected = SecurityStateStoreV2 {
            state_generation: old_security
                .state_generation
                .checked_add(1)
                .ok_or(Error::Exhausted)?,
            last_boot_epoch: old_security
                .last_boot_epoch
                .checked_add(1)
                .ok_or(Error::Exhausted)?,
            ..old_security
        };
        if committed != &expected {
            return Err(Error::Conflict);
        }
        let _view = super::file_receipt_query_v4::MountedReceiptQuery::new(
            &self.receipts,
            &self.index,
            config,
            committed,
        )?;
        let mut digest = Sha256::new();
        digest.update(self.receipts.as_slice());
        digest.update(self.index.as_slice());
        Ok(digest.finalize().into())
    }
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = assert!(core::mem::size_of::<Workspace>() <= 192 * 1024);
fn blocks(io: &mut impl EpochBlockIo, first: u32, out: &mut [u8]) -> Result<(), Error> {
    if !out.len().is_multiple_of(BLOCK) {
        return Err(Error::Invalid);
    }
    for (i, b) in out.chunks_exact_mut(BLOCK).enumerate() {
        io.read(
            first.checked_add(i as u32).ok_or(Error::Invalid)?,
            b.try_into().unwrap(),
        )?;
    }
    Ok(())
}
fn inspect_acls<K>(
    acl: &[u8; ACL_STORE],
    inodes: &[Inode; INODES],
    principals: &[Principal; 16],
    system_kind: impl Fn(usize) -> Option<K>,
    mut policy: impl FnMut(Acl, Inode, Option<K>) -> Result<(), Error>,
) -> Result<([Usage; 16], u32), Error> {
    let mut usage = [Usage::default(); 16];
    let mut system_blocks = 0u32;
    for (i, raw) in acl.chunks_exact(ACL_BYTES).enumerate() {
        let a = Acl::decode(raw)?;
        let inode = inodes[i];
        if a.inode_id != i as u32 || a.inode_generation != inode.generation {
            return Err(Error::Conflict);
        }
        let owner = principals.iter().position(|p| *p == a.principal);
        let hidden = system_kind(i);
        if inode.kind == 0 {
            // Initial empty and retained tombstone have no access authority.
            // The signed volume policy decides any retained identity fields.
            if a.state == 1
                || a.owner_rights != 0
                || a.system_rights != 0
                || a.state == 0 && inode.generation != 0
                || a.state == 2 && inode.generation == 0
                || (a.principal.id != 0 || a.principal.generation != 0) && owner.is_none()
            {
                return Err(Error::Conflict);
            }
        } else {
            let slot = owner.ok_or(Error::Unauthorized)?;
            let mask = if inode.kind == 1 {
                FILE_RIGHTS
            } else {
                DIR_RIGHTS
            };
            if a.state != 1
                || a.acl_generation == 0
                || a.parent != inode.parent
                || (a.owner_rights | a.system_rights) & !mask != 0
                || hidden.is_some() && a.owner_rights != 0
            {
                return Err(Error::Unauthorized);
            }
            let n = inode.runs[..usize::from(inode.extents)]
                .iter()
                .try_fold(0u32, |sum, r| sum.checked_add(r.count))
                .ok_or(Error::Capacity)?;
            if hidden.is_some() {
                system_blocks = system_blocks.checked_add(n).ok_or(Error::Capacity)?;
            } else {
                let u = &mut usage[slot];
                u.inodes = u.inodes.checked_add(1).ok_or(Error::Capacity)?;
                u.blocks = u.blocks.checked_add(n).ok_or(Error::Capacity)?;
                if inode.kind == 2 {
                    u.directory_slots = u
                        .directory_slots
                        .checked_add((inode.size / 128) as u32)
                        .ok_or(Error::Capacity)?;
                }
            }
        }
        policy(a, inode, hidden)?;
    }
    Ok((usage, system_blocks))
}
struct BaselinePayloads {
    boot: BootEpochStoreV1,
    security: SecurityStateStoreV2,
    receipts: ReceiptStoreSummary,
    system: [SystemObject; 4],
}
fn read_baseline_payloads(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    system: &[SystemObject; 4],
    principals: &[Principal; 16],
    w: &mut Workspace,
) -> Result<BaselinePayloads, Error> {
    for (i, p) in principals.iter().enumerate() {
        if p.id == 0 || p.generation == 0 || principals[..i].iter().any(|old| old.id == p.id) {
            return Err(Error::Invalid);
        }
    }
    for s in system {
        match s.kind {
            SystemKind::BootEpoch => io.read(s.first_block, &mut w.boot)?,
            SystemKind::Security => io.read(s.first_block, &mut w.security)?,
            SystemKind::Receipts => {
                blocks(io, s.first_block, &mut w.receipts)?;
                io.read(s.first_block + 6, &mut w.index)?;
            }
            SystemKind::Acl => blocks(io, s.first_block, &mut w.acl)?,
        }
    }
    let boot = BootEpochStoreV1::decode(&w.boot)?;
    let security = SecurityStateStoreV2::decode(&w.security)?;
    let index = FileStreamIndexV4::decode(&w.index)?;
    if boot.fs_uuid != sb.fs_uuid
        || !boot.matches(&security)
        || index.fs_uuid != sb.fs_uuid
        || index
            .groups
            .iter()
            .zip(principals)
            .any(|(g, p)| g.manifest_principal_id != p.id || g.boot_epoch > boot.boot_epoch)
    {
        return Err(Error::Conflict);
    }
    let receipts =
        file_receipt_store_v0199::scan_receipts_with_index(&w.receipts, &w.index, sb.fs_uuid)?;
    Ok(BaselinePayloads {
        boot,
        security,
        receipts,
        system: *system,
    })
}
impl BaselinePayloads {
    fn mount_evidence(
        self,
        structure: StructureEvidence,
        (usage, system_blocks): ([Usage; 16], u32),
        expected_objects: usize,
        expected_blocks: u32,
    ) -> Result<MountEvidence, Error> {
        if system_blocks != expected_blocks
            || usage.iter().map(|u| u.blocks).sum::<u32>() + system_blocks != structure.data_blocks
            || usage.iter().map(|u| u.inodes).sum::<u32>() + expected_objects as u32
                != u32::from(structure.live_inodes)
        {
            return Err(Error::Conflict);
        }
        Ok(MountEvidence {
            structure,
            boot: self.boot,
            security: self.security,
            receipts: self.receipts,
            usage,
            system_blocks,
            baseline_system: (expected_objects == BASELINE_SYSTEM_OBJECTS).then_some(self.system),
        })
    }
}
/// All four object payloads are copied from the actual stable disk view,
/// then cross-validated with the full inode scan. The trusted ACL policy
/// must accept every inode, including the root and hidden system files.
pub fn validate(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    system: &[SystemObject; 4],
    principals: &[Principal; 16],
    w: &mut Workspace,
    policy: impl FnMut(Acl, Inode, Option<SystemKind>) -> Result<(), Error>,
) -> Result<MountEvidence, Error> {
    file_structure_v1::validate_system_layout(system)?;
    let payloads = read_baseline_payloads(io, sb, system, principals, w)?;
    let structure =
        file_structure_v1::scan_baseline(sb, system, &mut w.structure, |b, out| io.read(b, out))?;
    let counters = inspect_acls(
        &w.acl,
        w.structure.inodes(),
        principals,
        |i| {
            system
                .iter()
                .find(|s| usize::from(s.inode) == i)
                .map(|s| s.kind)
        },
        policy,
    )?;
    payloads.mount_evidence(
        structure,
        counters,
        BASELINE_SYSTEM_OBJECTS,
        BASELINE_SYSTEM_BLOCKS,
    )
}
fn verify_snapshot_objects(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    snapshot: &[UnifiedSystemObject; 4],
    block: &mut [u8; BLOCK],
) -> Result<(), Error> {
    for s in snapshot {
        io.read(s.first_block, block)?;
        let envelope = decode_object_envelope(s.kind, block)?;
        if envelope.fs_uuid != sb.fs_uuid || envelope.generation != s.generation {
            return Err(Error::Conflict);
        }
        for tail in s.first_block + 1..s.first_block + s.kind.blocks() {
            io.read(tail, block)?;
            if block.iter().any(|&byte| byte != 0) {
                return Err(Error::Conflict);
            }
        }
    }
    Ok(())
}
/// Read-only validation of the unified v1 homes under the caller's mount
/// exclusion. The manifest fixes the identity and extents of all eight
/// hidden objects. Snapshot payloads and continuation blocks must be zero
/// while their formats await golden vectors. Every ACL requires the
/// independent trusted policy's acceptance.
pub fn validate_unified(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    baseline: &[SystemObject; 4],
    snapshot: &[UnifiedSystemObject; 4],
    principals: &[Principal; 16],
    w: &mut Workspace,
    policy: impl FnMut(Acl, Inode, Option<UnifiedSystemKind>) -> Result<(), Error>,
) -> Result<MountEvidence, Error> {
    let system = unified_map_from_baseline(baseline, snapshot)?;
    // Use the index buffer only before reading the protected index. The
    // mount's receipt query custody must retain its exact validated bytes
    // across the later paired BootEpoch transaction. No extra workspace or
    // disk reads are required under the same exclusive read-only mount.
    verify_snapshot_objects(io, sb, snapshot, &mut w.index)?;
    let payloads = read_baseline_payloads(io, sb, baseline, principals, w)?;
    let structure =
        file_structure_v1::scan_unified(sb, &system, &mut w.structure, |b, out| io.read(b, out))?;
    let counters = inspect_acls(
        &w.acl,
        w.structure.inodes(),
        principals,
        |i| {
            system
                .iter()
                .find(|s| usize::from(s.inode) == i)
                .map(|s| s.kind)
        },
        policy,
    )?;
    payloads.mount_evidence(
        structure,
        counters,
        UNIFIED_SYSTEM_OBJECTS,
        UNIFIED_SYSTEM_BLOCKS,
    )
}
/// Production callers must obtain the system object locations from an
/// authenticated boot catalog. The exact signed principal table, security
/// minima and configuration digest are then enforced before checkpoint.
pub fn validate_signed(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    system: &[SystemObject; 4],
    config: &VerifiedOfflineConfig<'_>,
    w: &mut Workspace,
    policy: impl FnMut(Acl, Inode, Option<SystemKind>) -> Result<(), Error>,
) -> Result<MountEvidence, Error> {
    let e = validate(io, sb, system, config.principals(), w, policy)?;
    config.check_committed(&e.security)?;
    Ok(e)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::security::{
        file_media_unified_v1::{
            CATALOG_INODE, ENVELOPE_BYTES, RESERVED_INODE_START, SNAPSHOT_CATALOG_BLOCK,
            SNAPSHOT_PROTECTION_BLOCK, SNAPSHOT_SLOT_START, encode_object_envelope,
        },
        file_media_v0199::{BITMAP_START, DATA_START, INODE_START},
        file_structure_v1::INODE_BYTES,
    };
    use std::{boxed::Box, collections::BTreeMap};
    const STATE_HOME: u32 = 7000;
    const BOOT_HOME: u32 = 7002;
    const RECEIPTS: u32 = 7003;
    const ACL: u32 = 7010;
    const ROOT: u32 = 7014;
    fn p16(b: &mut [u8], i: usize, v: u16) {
        b[i..i + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn p32(b: &mut [u8], i: usize, v: u32) {
        b[i..i + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn p64(b: &mut [u8], i: usize, v: u64) {
        b[i..i + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn seal(b: &mut [u8], at: usize) {
        let c = crc32c_zeroed(b, at).unwrap();
        p32(b, at, c);
    }
    fn inode(b: &mut [u8], kind: u16, size: u64, home: u32, n: u32) {
        b.fill(0);
        p32(b, 0, 0x4359494e);
        p16(b, 4, kind);
        if kind != 0 {
            p64(b, 8, 1);
            p64(b, 16, size);
            p64(b, 40, 1);
            if n != 0 {
                p16(b, 32, 1);
                p32(b, 52, home);
                p32(b, 56, n);
            }
        }
        seal(b, 252);
    }
    struct Disk(BTreeMap<u32, Box<[u8; BLOCK]>>);
    impl EpochBlockIo for Disk {
        fn read(&mut self, b: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
            if let Some(v) = self.0.get(&b) {
                *out = **v;
            } else {
                out.fill(0);
            }
            Ok(())
        }
        fn write(&mut self, _: u32, _: &[u8; BLOCK]) -> Result<(), Error> {
            panic!("read-only mount validation")
        }
        fn flush(&mut self) -> Result<(), Error> {
            panic!("read-only mount validation")
        }
    }
    fn systems() -> [SystemObject; 4] {
        [
            SystemObject {
                kind: SystemKind::BootEpoch,
                inode: 2,
                generation: 1,
                first_block: BOOT_HOME,
            },
            SystemObject {
                kind: SystemKind::Receipts,
                inode: 3,
                generation: 1,
                first_block: RECEIPTS,
            },
            SystemObject {
                kind: SystemKind::Acl,
                inode: 4,
                generation: 1,
                first_block: ACL,
            },
            SystemObject {
                kind: SystemKind::Security,
                inode: 5,
                generation: 1,
                first_block: STATE_HOME,
            },
        ]
    }
    fn fixture() -> Disk {
        let mut d = Disk(BTreeMap::new());
        for page in 0..4u32 {
            let mut b = [0; BLOCK];
            let start = page * BLOCK as u32 * 8;
            for at in start..start + BLOCK as u32 * 8 {
                if at < 4118 || (STATE_HOME..=ROOT).contains(&at) {
                    let v = at - start;
                    b[(v / 8) as usize] |= 1 << (v % 8);
                }
            }
            d.0.insert(4098 + page, Box::new(b));
        }
        for page in 0..16u32 {
            let mut b = [0; BLOCK];
            for (j, slot) in b.chunks_exact_mut(256).enumerate() {
                match page * 16 + j as u32 {
                    0 => inode(slot, 2, 128, ROOT, 1),
                    1 => inode(slot, 1, 8, STATE_HOME + 1, 1),
                    2 => inode(slot, 1, 4096, BOOT_HOME, 1),
                    3 => inode(slot, 1, 7 * 4096, RECEIPTS, 7),
                    4 => inode(slot, 1, 4 * 4096, ACL, 4),
                    5 => inode(slot, 1, 4096, STATE_HOME, 1),
                    _ => inode(slot, 0, 0, 0, 0),
                }
            }
            d.0.insert(4102 + page, Box::new(b));
        }
        let mut root = [0; BLOCK];
        p32(&mut root, 0, 1);
        p16(&mut root, 4, 1);
        p64(&mut root, 8, 1);
        root[16] = b'x';
        seal(&mut root[..128], 124);
        d.0.insert(ROOT, Box::new(root));
        for page in 0..4u32 {
            let mut b = [0; BLOCK];
            for (j, slot) in b.chunks_exact_mut(64).enumerate() {
                let id = page * 64 + j as u32;
                p32(slot, 0, id);
                if id < 6 {
                    p32(slot, 4, 1);
                    p64(slot, 8, 1);
                    p64(slot, 16, 1);
                    p64(slot, 24, 1);
                    p64(slot, 40, 1);
                    if id == 0 {
                        p32(slot, 32, 1 << 14);
                    } else if id == 1 {
                        p32(slot, 32, 1 << 8);
                    } else {
                        p32(slot, 36, FILE_RIGHTS);
                    }
                }
                seal(slot, 60);
            }
            d.0.insert(ACL + page, Box::new(b));
        }
        let mut index = [0; BLOCK];
        p32(&mut index, 0, 0x43595349);
        p16(&mut index, 4, 4);
        p16(&mut index, 6, 64);
        index[8..24].fill(1);
        p64(&mut index, 32, 1);
        for i in 0..16 {
            p64(&mut index, 64 + 24 * i + 16, i as u64 + 1);
        }
        seal(&mut index, 4092);
        d.0.insert(RECEIPTS + 6, Box::new(index));
        let boot = BootEpochStoreV1 {
            fs_uuid: [1; 16],
            boot_epoch: 2,
        }
        .encode()
        .unwrap();
        let security = SecurityStateStoreV2 {
            fs_uuid: [1; 16],
            state_generation: 3,
            rule_min_generation: 1,
            security_min_generation: 1,
            key_generation: 1,
            isolated_service_bitmap: 0,
            last_boot_epoch: 2,
            offline_config_generation: 1,
            offline_config_hash: [3; 32],
            service_generations: [1; 16],
        }
        .encode()
        .unwrap();
        d.0.insert(BOOT_HOME, Box::new(boot));
        d.0.insert(STATE_HOME, Box::new(security));
        d
    }

    impl Disk {
        fn inode_slot(&mut self, id: u16) -> &mut [u8] {
            let page = INODE_START + u32::from(id) / 16;
            let offset = (usize::from(id) % 16) * INODE_BYTES;
            &mut self.0.get_mut(&page).unwrap()[offset..offset + INODE_BYTES]
        }

        fn acl_slot(&mut self, id: u16) -> &mut [u8] {
            let page = ACL + u32::from(id) / 64;
            let offset = (usize::from(id) % 64) * ACL_BYTES;
            &mut self.0.get_mut(&page).unwrap()[offset..offset + ACL_BYTES]
        }

        fn set_allocated(&mut self, block: u32, allocated: bool) {
            let byte = (block / 8) as usize;
            let page = BITMAP_START + (byte / BLOCK) as u32;
            let slot = &mut self.0.get_mut(&page).unwrap()[byte % BLOCK];
            let mask = 1 << (block % 8);
            if allocated {
                *slot |= mask;
            } else {
                *slot &= !mask;
            }
        }
    }

    fn unified_fixture() -> (Disk, [SystemObject; 4], [UnifiedSystemObject; 4]) {
        let mut disk = fixture();
        let mut baseline = systems();
        for s in &mut baseline {
            let old = s.inode;
            inode(disk.inode_slot(old), 0, 0, 0, 0);
            let acl = disk.acl_slot(old);
            acl.fill(0);
            p32(acl, 0, u32::from(old));
            seal(acl, 60);
            s.inode = UnifiedSystemKind::from_baseline(s.kind).inode_slot();
        }
        let snapshot = [
            UnifiedSystemKind::SnapshotCatalog,
            UnifiedSystemKind::SnapshotSlot,
            UnifiedSystemKind::SnapshotRequest,
            UnifiedSystemKind::SnapshotProtection,
        ]
        .map(|kind| UnifiedSystemObject {
            kind,
            inode: kind.inode_slot(),
            generation: 1,
            first_block: kind.fixed_first_block().unwrap(),
        });
        for s in unified_map_from_baseline(&baseline, &snapshot).unwrap() {
            let count = s.kind.blocks();
            inode(
                disk.inode_slot(s.inode),
                1,
                u64::from(count) * BLOCK as u64,
                s.first_block,
                count,
            );
            let acl = disk.acl_slot(s.inode);
            p32(acl, 4, 1);
            p64(acl, 8, 1);
            p64(acl, 16, 1);
            p64(acl, 24, 1);
            p32(acl, 36, FILE_RIGHTS);
            p64(acl, 40, 1);
            seal(acl, 60);
            for block in s.first_block..s.first_block + count {
                disk.set_allocated(block, true);
            }
            if s.kind.is_new_snapshot_object() {
                let mut head = Box::new([0; BLOCK]);
                encode_object_envelope(s.kind, [1; 16], s.generation, &mut *head).unwrap();
                disk.0.insert(s.first_block, head);
            }
        }
        // Baseline homes are relocatable, so an ordinary file may use DATA_START.
        disk.set_allocated(STATE_HOME + 1, false);
        disk.set_allocated(DATA_START, true);
        inode(disk.inode_slot(1), 1, 8, DATA_START, 1);
        (disk, baseline, snapshot)
    }

    const CHECKPOINT: SuperblockV1 = SuperblockV1 {
        fs_uuid: [1; 16],
        generation: 2,
        checkpoint_lsn: 4,
        log_epoch: 2,
    };

    fn principals() -> [Principal; 16] {
        core::array::from_fn(|i| Principal {
            id: i as u64 + 1,
            generation: 1,
        })
    }

    #[test]
    fn unified_mount_accounts_for_all_eight_hidden_objects() {
        let (mut disk, baseline, snapshot) = unified_fixture();
        let map = unified_map_from_baseline(&baseline, &snapshot).unwrap();
        let mut seen = 0;
        let e = validate_unified(
            &mut disk,
            CHECKPOINT,
            &baseline,
            &snapshot,
            &principals(),
            &mut Workspace::new(),
            |acl, _, hidden| {
                seen += 1;
                assert_eq!(
                    hidden,
                    map.iter()
                        .find(|s| u32::from(s.inode) == acl.inode_id)
                        .map(|s| s.kind)
                );
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, INODES);
        assert_eq!(e.system_blocks, 151);
        assert_eq!(
            e.structure,
            StructureEvidence {
                live_inodes: 10,
                data_blocks: 153,
                directory_entries: 1,
            }
        );
        assert_eq!(
            e.usage[0],
            Usage {
                inodes: 2,
                blocks: 2,
                directory_slots: 1,
            }
        );
        assert!(e.usage[1..].iter().all(|u| *u == Usage::default()));
    }

    fn signed_fixture(wire: &mut [u8; 577]) -> VerifiedOfflineConfig<'_> {
        use crate::security::offline_config_v1::{CatalogBindings, SIGNATURE_LABEL};
        use ed25519_dalek::{Signer, SigningKey};

        // A host-only signature, using the fixture's actual UUID and principals.
        p32(wire, 0, 0x4359_4f46);
        p16(wire, 4, 1);
        p16(wire, 6, 256);
        p32(wire, 8, 577);
        p32(wire, 12, 257);
        wire[16..32].copy_from_slice(&CHECKPOINT.fs_uuid);
        for at in [32, 40, 48, 56] {
            p64(wire, at, 1);
        }
        wire[64..96].fill(2);
        wire[96..128].fill(3);
        wire[128..160].fill(4);
        for (i, principal) in principals().iter().enumerate() {
            p64(wire, 256 + i * 16, principal.id);
            p64(wire, 264 + i * 16, principal.generation);
        }
        wire[512] = 42;
        let payload_hash = Sha256::digest(&wire[256..513]);
        wire[160..192].copy_from_slice(&payload_hash);
        let signer = SigningKey::from_bytes(&[0x37; 32]);
        let mut message = [0u8; SIGNATURE_LABEL.len() + 513];
        message[..SIGNATURE_LABEL.len()].copy_from_slice(SIGNATURE_LABEL);
        message[SIGNATURE_LABEL.len()..].copy_from_slice(&wire[..513]);
        wire[513..].copy_from_slice(&signer.sign(&message).to_bytes());
        let catalog = CatalogBindings {
            rule_generation: 1,
            security_generation: 1,
            key_generation: 1,
            rule_hash: [2; 32],
            security_hash: [3; 32],
            key_manifest_hash: [4; 32],
        };
        let mut scratch = [0u8; SIGNATURE_LABEL.len() + 513];
        VerifiedOfflineConfig::verify(
            wire,
            &signer.verifying_key().to_bytes(),
            catalog,
            &mut scratch,
            |_, _, payload| {
                if payload == [42] {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            },
        )
        .unwrap()
    }

    #[test]
    fn unified_mount_retains_signed_receipt_query_inputs_after_snapshot_scan() {
        let (mut disk, baseline, snapshot) = unified_fixture();
        let mut wire = [0; 577];
        let config = signed_fixture(&mut wire);
        let mut state =
            SecurityStateStoreV2::decode(disk.0.get(&STATE_HOME).unwrap().as_ref()).unwrap();
        state.offline_config_hash = config.digest();
        disk.0.insert(STATE_HOME, Box::new(state.encode().unwrap()));
        let mut expected = Sha256::new();
        for block in RECEIPTS..RECEIPTS + 7 {
            let mut raw = [0; BLOCK];
            disk.read(block, &mut raw).unwrap();
            expected.update(raw);
        }
        let expected: [u8; 32] = expected.finalize().into();

        let mut w = Workspace::new();
        let prior = validate_unified(
            &mut disk,
            CHECKPOINT,
            &baseline,
            &snapshot,
            config.principals(),
            &mut w,
            |_, _, _| Ok(()),
        )
        .unwrap();
        // The mount owner supplies the independently confirmed paired state.
        let committed = SecurityStateStoreV2 {
            state_generation: state.state_generation + 1,
            last_boot_epoch: state.last_boot_epoch + 1,
            ..state
        };
        assert_eq!(
            w.confirmed_receipt_query_digest(&prior, &committed, &config),
            Ok(expected)
        );
        assert_eq!(
            w.confirmed_receipt_query_digest(&prior, &state, &config),
            Err(Error::Conflict)
        );
    }

    #[test]
    fn signed_fsync_binds_then_recovers_segmented_data_and_receipt() {
        use crate::security::{
            file_admission_flow_v1::FileAdmissionFlowV1,
            file_auth_context_v1::{AdmissionLedgerV1, AuthContextV1, AuthorityFacts},
            file_auth_v3::{
                AdmitRequestV3, CompleteRequestV1, FILE_SERVICE_ROLE, TerminalState, Verdict,
            },
            file_fsync_v1::{FsyncJob, FsyncProgress, FsyncWorkspace, commit_segment},
            file_media_v0199::{BLOCK_COUNT, FileReceiptV4, RECEIPT_BYTES},
            file_receipt_query_v4::ReceiptKey,
            file_service_v4::{REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION},
            recovery_v1::{
                RecoveryWorkspace, RedoWriter, recover_checkpoint_with_evidence,
                retire_checkpointed_log,
            },
        };
        use std::fs::{File, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};

        struct FileDisk(File);
        impl EpochBlockIo for FileDisk {
            fn read(&mut self, block: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
                self.0
                    .seek(SeekFrom::Start(u64::from(block) * BLOCK as u64))
                    .and_then(|_| self.0.read_exact(out))
                    .map_err(|_| Error::Unknown)
            }
            fn write(&mut self, block: u32, data: &[u8; BLOCK]) -> Result<(), Error> {
                self.0
                    .seek(SeekFrom::Start(u64::from(block) * BLOCK as u64))
                    .and_then(|_| self.0.write_all(data))
                    .map_err(|_| Error::Unknown)
            }
            fn flush(&mut self) -> Result<(), Error> {
                self.0.sync_data().map_err(|_| Error::Unknown)
            }
        }
        struct RemoveImage(std::path::PathBuf);
        impl Drop for RemoveImage {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        fn superblock(sb: SuperblockV1) -> [u8; BLOCK] {
            let mut raw = [0; BLOCK];
            p32(&mut raw, 0, 0x4359_4653);
            p16(&mut raw, 4, 1);
            p16(&mut raw, 6, 80);
            p32(&mut raw, 8, BLOCK as u32);
            p32(&mut raw, 12, BLOCK_COUNT);
            raw[16..32].copy_from_slice(&sb.fs_uuid);
            p64(&mut raw, 32, sb.generation);
            p64(&mut raw, 40, sb.checkpoint_lsn);
            p64(&mut raw, 48, sb.log_epoch);
            for (offset, value) in [
                (56, BITMAP_START),
                (60, INODE_START),
                (64, DATA_START),
                (68, 256),
            ] {
                p32(&mut raw, offset, value);
            }
            seal(&mut raw, 76);
            raw
        }
        const DATA: u32 = 9000;
        const PAGES: usize = 121;
        const SIZE: usize = 120 * BLOCK + 17;
        const FSYNC: u64 = 1 << 13;
        const CAP: u64 = 9;
        const BOOT: u64 = 2;
        const RECEIPT_SLOT: usize = 21;
        let mut source = fixture();
        source.set_allocated(STATE_HOME + 1, false);
        for block in DATA..DATA + PAGES as u32 {
            source.set_allocated(block, true);
        }
        inode(source.inode_slot(1), 1, SIZE as u64, DATA, PAGES as u32);
        let acl = source.acl_slot(1);
        p32(acl, 32, FILE_RIGHTS);
        seal(acl, 60);
        let mut wire = [0; 577];
        let config = signed_fixture(&mut wire);
        let mut state = SecurityStateStoreV2::decode(source.0[&STATE_HOME].as_ref()).unwrap();
        state.offline_config_hash = config.digest();
        source
            .0
            .insert(STATE_HOME, Box::new(state.encode().unwrap()));
        let key = ReceiptKey {
            fs_uuid: CHECKPOINT.fs_uuid,
            issued_boot_epoch: BOOT,
            group_id: 0,
            group_generation: 1,
            stream_slot: 0,
            stream_generation: 1,
            request_seq: 1,
        };
        let mut index = FileStreamIndexV4::decode(source.0[&(RECEIPTS + 6)].as_ref()).unwrap();
        index.groups[0].flags = 1;
        index.groups[0].generation = 1;
        index.groups[0].boot_epoch = BOOT;
        index.streams[0].flags = 1;
        index.streams[0].generation = 1;
        index.streams[0].issued_hi = 1;
        index
            .encode_into(source.0.get_mut(&(RECEIPTS + 6)).unwrap())
            .unwrap();
        let issued = FileReceiptV4 {
            fs_uuid: key.fs_uuid,
            issued_boot_epoch: BOOT,
            group_id: 0,
            group_generation: 1,
            stream_slot: 0,
            stream_generation: 1,
            request_seq: 1,
            log_epoch: 0,
            txid: 0,
            commit_lsn: 0,
            write_seq: 0,
            status: 1,
            result: 0,
            completed_prefix: 0,
            operation_digest: [0; 32],
            output_digest: [0; 32],
            request_id: key.request_id().unwrap(),
            owner_principal_id: 1,
        }
        .encode()
        .unwrap();
        let mut first = [0; BLOCK];
        let mut second = [0; BLOCK];
        let receipt_at = RECEIPT_SLOT * RECEIPT_BYTES % BLOCK;
        first[receipt_at..].copy_from_slice(&issued[..BLOCK - receipt_at]);
        second[..RECEIPT_BYTES - (BLOCK - receipt_at)]
            .copy_from_slice(&issued[BLOCK - receipt_at..]);
        source.0.insert(RECEIPTS, Box::new(first));
        source.0.insert(RECEIPTS + 1, Box::new(second));
        source.0.insert(
            0,
            Box::new(superblock(SuperblockV1 {
                generation: 1,
                checkpoint_lsn: 0,
                log_epoch: 1,
                ..CHECKPOINT
            })),
        );
        source.0.insert(1, Box::new(superblock(CHECKPOINT)));

        let path =
            std::env::temp_dir().join(std::format!("cyx-fsync-test-{}.raw", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let image = RemoveImage(path);
        file.set_len(u64::from(BLOCK_COUNT) * BLOCK as u64).unwrap();
        let mut disk = FileDisk(file);
        for (block, data) in source.0 {
            disk.write(block, &data).unwrap();
        }
        disk.flush().unwrap();
        let system = systems();
        let mut mount_workspace = Workspace::new();
        let mounted = validate_signed(
            &mut disk,
            CHECKPOINT,
            &system,
            &config,
            &mut mount_workspace,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(
            (mounted.receipts.occupied, mounted.receipts.unresolved),
            (1, 1)
        );

        let mut frozen = std::vec![0; PAGES * BLOCK];
        frozen[..SIZE].fill(0x59);
        let pages: std::vec::Vec<&[u8; BLOCK]> = frozen
            .chunks_exact(BLOCK)
            .map(|page| page.try_into().unwrap())
            .collect();
        let mut frame = [0; REQUEST_HEADER + 8];
        p32(&mut frame, 0, REQUEST_MAGIC);
        p16(&mut frame, 4, REQUEST_VERSION);
        p16(&mut frame, 6, REQUEST_HEADER as u16);
        p16(&mut frame, 8, 5);
        p32(&mut frame, 12, 8);
        p64(&mut frame, 16, key.request_id().unwrap());
        p64(&mut frame, REQUEST_HEADER, 17);
        let mut flow = FileAdmissionFlowV1::freeze(
            AuthContextV1::new(3, 1, FILE_SERVICE_ROLE, 1, BOOT).unwrap(),
            &frame,
            CAP,
            AdmitRequestV3 {
                auth_context_id: 0,
                target_id: 1,
                target_generation: 1,
                required_rights: FSYNC,
                request_seq: 1,
                prepared_version: 0,
                acl_generation: 1,
                frozen_data_digest: [0; 32],
                operation_digest: [0; 32],
            },
            0,
            &frozen,
        )
        .unwrap();
        let mut ledger = AdmissionLedgerV1::new(BOOT).unwrap();
        flow.admit(
            &mut ledger,
            &AuthorityFacts {
                current_generation: 1,
                verdict: Verdict::Admitted,
                deny_generation: 0,
                accepted_local_ns: 1,
            },
        )
        .unwrap();
        flow.execute(&mut ledger, flow.request().prepared_version, true)
            .unwrap();
        let mut job = FsyncJob {
            config: &config,
            mounted: &mounted,
            admission: &flow,
            ledger: &ledger,
            inode_id: 1,
            cap_selector: CAP,
            frame: &frame,
            key,
            pages: &pages,
        };
        let mut work = FsyncWorkspace::new();
        let mut journal = RecoveryWorkspace::new();
        let mut writer = RedoWriter::open(&mut disk, &mut journal, CHECKPOINT).unwrap();
        let mut committed = |writer: &mut RedoWriter<'_, FileDisk>, job: &FsyncJob<'_>, blocks| {
            let FsyncProgress::Committed { receipt, redo } =
                commit_segment(writer, job, &mut work, |plan| {
                    assert_eq!(plan.log_blocks, blocks);
                    Ok(())
                })
                .unwrap()
            else {
                panic!("expected durable segment");
            };
            assert_eq!(receipt.commit_lsn, redo.transaction().commit_lsn);
            (receipt, redo.ordered_digest())
        };
        let mut raw = [0; BLOCK];
        let (bound, _) = committed(&mut writer, &job, 8);
        assert_eq!((bound.status, bound.completed_prefix), (2, 0));
        writer.read_committed(DATA, &mut raw).unwrap();
        assert!(raw.iter().all(|&byte| byte == 0));
        let (prefix, _) = committed(&mut writer, &job, 248);
        assert_eq!(
            (prefix.status, prefix.completed_prefix as usize),
            (2, 120 * BLOCK)
        );
        writer.read_committed(INODE_START, &mut raw).unwrap();
        assert_eq!(Inode::decode(&raw[256..512]).unwrap().durable_write_seq, 0);
        writer.read_committed(DATA + 120, &mut raw).unwrap();
        assert!(raw.iter().all(|&byte| byte == 0));
        let (before_final, checkpoint) =
            recover_checkpoint_with_evidence(&mut disk, &mut journal, |io, sb| {
                let state =
                    validate_signed(io, sb, &system, &config, &mut mount_workspace, |_, _, _| {
                        Ok(())
                    })?;
                assert_eq!((state.receipts.occupied, state.receipts.unresolved), (1, 1));
                Ok(())
            })
            .unwrap();
        assert_eq!(before_final.transactions, 2);
        assert_eq!(checkpoint.checkpoint_lsn, prefix.commit_lsn);
        assert!(retire_checkpointed_log(&mut disk, &mut journal, checkpoint).unwrap() > 0);
        let mut writer = RedoWriter::open(&mut disk, &mut journal, checkpoint).unwrap();
        let (done, committed_digest) = committed(&mut writer, &job, 12);
        assert_eq!(done.log_epoch, prefix.log_epoch + 1);
        assert_eq!(
            (done.status, done.completed_prefix as usize, done.write_seq),
            (3, SIZE, 17)
        );
        let mut changed = pages.clone();
        changed[0] = &[0; BLOCK];
        job.pages = &changed;
        assert_eq!(
            commit_segment(&mut writer, &job, &mut work, |_| panic!("changed snapshot")).err(),
            Some(Error::Conflict)
        );
        job.pages = &pages;
        assert!(matches!(
            commit_segment(&mut writer, &job, &mut work, |_| panic!("already committed")).unwrap(),
            FsyncProgress::AlreadyDone(receipt) if receipt == done
        ));
        ledger
            .complete(
                FILE_SERVICE_ROLE,
                false,
                &CompleteRequestV1 {
                    admission_id: flow.admission_id(),
                    terminal_state: TerminalState::Done,
                    evidence_digest: committed_digest,
                },
            )
            .unwrap();
        let terminal_job = FsyncJob {
            config: &config,
            mounted: &mounted,
            admission: &flow,
            ledger: &ledger,
            inode_id: 1,
            cap_selector: CAP,
            frame: &frame,
            key,
            pages: &pages,
        };
        assert_eq!(
            commit_segment(&mut writer, &terminal_job, &mut work, |_| panic!(
                "terminal admission"
            ))
            .err(),
            Some(Error::Unauthorized)
        );
        drop(disk);

        let mut disk = FileDisk(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&image.0)
                .unwrap(),
        );
        let mut reopened = RecoveryWorkspace::new();
        let (evidence, next) =
            recover_checkpoint_with_evidence(&mut disk, &mut reopened, |io, sb| {
                let mounted =
                    validate_signed(io, sb, &system, &config, &mut mount_workspace, |_, _, _| {
                        Ok(())
                    })?;
                assert_eq!(
                    (mounted.receipts.occupied, mounted.receipts.unresolved),
                    (1, 0)
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(evidence.transactions, 1);
        assert_eq!(next.checkpoint_lsn, done.commit_lsn);
        disk.read(INODE_START, &mut raw).unwrap();
        assert_eq!(Inode::decode(&raw[256..512]).unwrap().durable_write_seq, 17);
        let mut contents = Sha256::new();
        for block in DATA..DATA + PAGES as u32 {
            disk.read(block, &mut raw).unwrap();
            contents.update(raw);
        }
        assert_eq!(&contents.finalize()[..], &done.output_digest);
        let mut receipt = [0; RECEIPT_BYTES];
        disk.read(RECEIPTS, &mut raw).unwrap();
        receipt[..BLOCK - receipt_at].copy_from_slice(&raw[receipt_at..]);
        disk.read(RECEIPTS + 1, &mut raw).unwrap();
        receipt[BLOCK - receipt_at..].copy_from_slice(&raw[..RECEIPT_BYTES - (BLOCK - receipt_at)]);
        assert_eq!(FileReceiptV4::decode(&receipt).unwrap(), done);
    }

    #[test]
    fn unified_mount_denies_corrupt_homes() {
        #[derive(Debug)]
        enum Fault {
            ReservedTombstone,
            HiddenGeneration,
            SharedExtent,
            MissingAllocation,
            OrphanAllocation,
            HiddenDirectoryEntry,
            EnvelopeUuid,
            EnvelopeGeneration,
            EnvelopePayload,
            ContinuationBlock,
        }
        let mut w = Workspace::new();
        let p = principals();
        for fault in [
            Fault::ReservedTombstone,
            Fault::HiddenGeneration,
            Fault::SharedExtent,
            Fault::MissingAllocation,
            Fault::OrphanAllocation,
            Fault::HiddenDirectoryEntry,
            Fault::EnvelopeUuid,
            Fault::EnvelopeGeneration,
            Fault::EnvelopePayload,
            Fault::ContinuationBlock,
        ] {
            let (mut disk, baseline, snapshot) = unified_fixture();
            let expected = match fault {
                Fault::ReservedTombstone => {
                    let tombstone = disk.inode_slot(RESERVED_INODE_START);
                    p64(tombstone, 8, 1);
                    seal(tombstone, 252);
                    let acl = disk.acl_slot(RESERVED_INODE_START);
                    p32(acl, 4, 2);
                    p64(acl, 8, 1);
                    seal(acl, 60);
                    Error::Conflict
                }
                Fault::HiddenGeneration => {
                    let hidden = disk.inode_slot(CATALOG_INODE);
                    p64(hidden, 8, 2);
                    seal(hidden, 252);
                    Error::Conflict
                }
                Fault::SharedExtent => {
                    inode(disk.inode_slot(1), 1, 8, SNAPSHOT_SLOT_START, 1);
                    Error::Conflict
                }
                Fault::MissingAllocation => {
                    disk.set_allocated(SNAPSHOT_PROTECTION_BLOCK, false);
                    Error::Conflict
                }
                Fault::OrphanAllocation => {
                    disk.set_allocated(DATA_START + 1, true);
                    Error::Conflict
                }
                Fault::HiddenDirectoryEntry => {
                    let root = disk.inode_slot(0);
                    p64(root, 16, 256);
                    seal(root, 252);
                    let entry = &mut disk.0.get_mut(&ROOT).unwrap()[128..256];
                    p32(entry, 0, u32::from(CATALOG_INODE));
                    p16(entry, 4, 1);
                    p64(entry, 8, 1);
                    entry[16] = b'y';
                    seal(entry, 124);
                    Error::Invalid
                }
                Fault::EnvelopeUuid => {
                    let head = disk.0.get_mut(&SNAPSHOT_CATALOG_BLOCK).unwrap();
                    head[8..24].fill(2);
                    seal(&mut **head, 32);
                    Error::Conflict
                }
                Fault::EnvelopeGeneration => {
                    let head = disk.0.get_mut(&SNAPSHOT_CATALOG_BLOCK).unwrap();
                    p64(&mut **head, 24, 2);
                    seal(&mut **head, 32);
                    Error::Conflict
                }
                Fault::EnvelopePayload => {
                    let head = disk.0.get_mut(&SNAPSHOT_CATALOG_BLOCK).unwrap();
                    head[ENVELOPE_BYTES] = 1;
                    seal(&mut **head, 32);
                    Error::Invalid
                }
                Fault::ContinuationBlock => {
                    let mut tail = Box::new([0; BLOCK]);
                    tail[BLOCK - 1] = 1;
                    disk.0.insert(SNAPSHOT_PROTECTION_BLOCK - 1, tail);
                    Error::Conflict
                }
            };
            assert_eq!(
                validate_unified(
                    &mut disk,
                    CHECKPOINT,
                    &baseline,
                    &snapshot,
                    &p,
                    &mut w,
                    |_, _, _| panic!("invalid home reached ACL policy")
                ),
                Err(expected),
                "{fault:?}"
            );
        }
    }

    #[test]
    fn unified_mount_requires_hidden_owner_denial_and_independent_acl_policy() {
        let (mut disk, baseline, snapshot) = unified_fixture();
        let mut w = Workspace::new();
        let p = principals();
        for (owner_rights, deny_policy) in [(0, true), (1 << 8, false)] {
            let hidden = disk.acl_slot(CATALOG_INODE);
            p32(hidden, 32, owner_rights);
            seal(hidden, 60);
            assert_eq!(
                validate_unified(
                    &mut disk,
                    CHECKPOINT,
                    &baseline,
                    &snapshot,
                    &p,
                    &mut w,
                    |_, _, hidden| {
                        if deny_policy && hidden == Some(UnifiedSystemKind::SnapshotCatalog) {
                            return Err(Error::Unauthorized);
                        }
                        Ok(())
                    }
                ),
                Err(Error::Unauthorized)
            );
        }
    }

    #[test]
    fn joined_mount_denies_wrong_acl_principal_hidden_right_and_split_boot() {
        let mut d = fixture();
        let sb = SuperblockV1 {
            fs_uuid: [1; 16],
            generation: 1,
            checkpoint_lsn: 0,
            log_epoch: 1,
        };
        let p = core::array::from_fn(|i| Principal {
            id: i as u64 + 1,
            generation: 1,
        });
        let mut w = Workspace::new();
        let mut seen = 0;
        let v = validate(&mut d, sb, &systems(), &p, &mut w, |_, _, _| {
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, 256);
        assert_eq!(v.system_blocks, 13);
        assert_eq!(v.structure.live_inodes, 6);
        assert_eq!(
            v.usage[0],
            Usage {
                inodes: 2,
                blocks: 2,
                directory_slots: 1
            }
        );
        let mut bad = fixture();
        let b = &mut bad.0.get_mut(&ACL).unwrap()[64..128];
        p64(b, 24, 2);
        seal(b, 60);
        assert_eq!(
            validate(&mut bad, sb, &systems(), &p, &mut w, |_, _, _| Ok(())),
            Err(Error::Unauthorized)
        );
        let mut bad = fixture();
        let b = &mut bad.0.get_mut(&ACL).unwrap()[128..192];
        p32(b, 32, 1 << 8);
        seal(b, 60);
        assert_eq!(
            validate(&mut bad, sb, &systems(), &p, &mut w, |_, _, _| Ok(())),
            Err(Error::Unauthorized)
        );
        let mut bad = fixture();
        bad.0.insert(
            BOOT_HOME,
            Box::new(
                BootEpochStoreV1 {
                    fs_uuid: [1; 16],
                    boot_epoch: 1,
                }
                .encode()
                .unwrap(),
            ),
        );
        assert_eq!(
            validate(&mut bad, sb, &systems(), &p, &mut w, |_, _, _| panic!(
                "split boot stores"
            )),
            Err(Error::Conflict)
        );
        let mut bad = fixture();
        let b = bad.0.get_mut(&(RECEIPTS + 6)).unwrap();
        p64(&mut **b, 80, 99);
        seal(&mut **b, 4092);
        assert_eq!(
            validate(&mut bad, sb, &systems(), &p, &mut w, |_, _, _| panic!(
                "principal mismatch"
            )),
            Err(Error::Conflict)
        );
    }
}
