use super::*;
use crate::storage::{self, BLOCK_SIZE, SNAPSHOT_START, SNAPSHOT_STRIDE};
use sha2::{Digest, Sha256};

pub(super) fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
pub(super) fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
pub(super) fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
pub(super) fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
pub(super) fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub(super) fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
pub(super) fn len(b: &[u8], n: usize) -> Result<(), storage::Error> {
    if b.len() == n {
        Ok(())
    } else {
        Err(storage::Error::Length)
    }
}
pub(super) fn zeros(b: &[u8]) -> Result<(), storage::Error> {
    if b.iter().all(|v| *v == 0) {
        Ok(())
    } else {
        Err(storage::Error::Reserved)
    }
}
pub(super) fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
/// Bind the exact canonical history-prefix bytes without storing a second
/// pathname buffer in each protected capability. The caller checks canonical
/// path syntax and component boundaries before treating a digest as authority.
pub fn history_prefix_digest(prefix: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CyxiaOS:history-prefix:v1\0");
    digest.update((prefix.len() as u64).to_le_bytes());
    digest.update(prefix);
    digest.finalize().into()
}
pub(super) fn crc(b: &[u8], off: usize) -> u32 {
    storage::checksum(b, off)
}
pub(super) fn seal(b: &mut [u8], off: usize) {
    let value = crc(b, off);
    put32(b, off, value);
}
pub(super) fn header(
    b: &[u8],
    n: usize,
    magic: u32,
    version: u16,
    hlen: u16,
    coff: usize,
) -> Result<(), storage::Error> {
    len(b, n)?;
    if u32_at(b, 0) != magic {
        return Err(storage::Error::Magic);
    }
    if u16_at(b, 4) != version {
        return Err(storage::Error::Version);
    }
    if u16_at(b, 6) != hlen {
        return Err(storage::Error::Layout);
    }
    if u32_at(b, coff) != crc(b, coff) {
        return Err(storage::Error::Checksum);
    }
    Ok(())
}
macro_rules! value_enum {
    ($name:ident { $($v:ident = $n:expr),+ $(,)? }) => {
        #[derive(Clone,Copy,Debug,PartialEq,Eq)] #[repr(u32)]
        pub enum $name { $($v=$n),+ }
        impl TryFrom<u32> for $name { type Error=storage::Error;
            fn try_from(v:u32)->Result<Self,Self::Error>{match v{$($n=>Ok(Self::$v),)+_=>Err(storage::Error::Range)}}
        }
    }
}
value_enum!(State{Free=0,Active=1,Deleting=2});
value_enum!(SlotClass{Periodic=1,OnDemand=2});
value_enum!(Gate{Open=0,Frozen=1});
value_enum!(RestorePhase{Idle=0,Preparing=1,Published=2});
value_enum!(RestoreMode{None=0,PreserveDirty=1,DiscardVolatile=2});
value_enum!(GcPhase{Idle=0,Mark=1,FreeCommitted=2});
value_enum!(RequestState{Free=0,Pending=1,Done=2,Failed=3,Incomplete=4,Unknown=5});
impl RequestState {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Incomplete)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeriodicLayer {
    Short,
    Long,
}
impl PeriodicLayer {
    pub const fn slots(self) -> core::ops::Range<usize> {
        match self {
            Self::Short => 0..3,
            Self::Long => 3..6,
        }
    }
    pub const fn period_seconds(self) -> u64 {
        match self {
            Self::Short => SHORT_PERIOD_SECONDS,
            Self::Long => LONG_PERIOD_SECONDS,
        }
    }
    pub const fn retention_seconds(self) -> u64 {
        match self {
            Self::Short => SHORT_RETENTION_SECONDS,
            Self::Long => LONG_RETENTION_SECONDS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotKey {
    pub fs_uuid: [u8; 16],
    pub snapshot_id: u64,
    pub slot: u32,
    pub slot_generation: u64,
}
impl SnapshotKey {
    pub const ZERO: Self = Self {
        fs_uuid: [0; 16],
        snapshot_id: 0,
        slot: 0,
        slot_generation: 0,
    };
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }
    pub fn validate(self) -> Result<(), storage::Error> {
        if self.fs_uuid == [0; 16] || self.snapshot_id == 0 || self.slot_generation == 0 {
            return Err(storage::Error::Identity);
        }
        if self.slot >= 8 {
            return Err(storage::Error::Range);
        }
        Ok(())
    }
    pub fn encode(self, b: &mut [u8]) -> Result<(), storage::Error> {
        len(b, 40)?;
        if !self.is_zero() {
            self.validate()?;
        }
        b.fill(0);
        b[..16].copy_from_slice(&self.fs_uuid);
        put64(b, 16, self.snapshot_id);
        put32(b, 24, self.slot);
        put64(b, 32, self.slot_generation);
        Ok(())
    }
    pub fn decode(b: &[u8]) -> Result<Self, storage::Error> {
        len(b, 40)?;
        zeros(&b[28..32])?;
        let v = Self {
            fs_uuid: b[..16].try_into().unwrap(),
            snapshot_id: u64_at(b, 16),
            slot: u32_at(b, 24),
            slot_generation: u64_at(b, 32),
        };
        if !v.is_zero() {
            v.validate()?;
        }
        Ok(v)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileReqKey {
    pub fs_uuid: [u8; 16],
    pub client_slot: u32,
    pub client_generation: u64,
    pub request_seq: u64,
}
impl FileReqKey {
    pub const ZERO: Self = Self {
        fs_uuid: [0; 16],
        client_slot: 0,
        client_generation: 0,
        request_seq: 0,
    };
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }
    pub fn validate(self) -> Result<(), storage::Error> {
        if self.fs_uuid == [0; 16] || self.client_generation == 0 || self.request_seq == 0 {
            return Err(storage::Error::Identity);
        }
        if self.client_slot >= 16 {
            return Err(storage::Error::Range);
        }
        Ok(())
    }
    pub fn encode(self, b: &mut [u8]) -> Result<(), storage::Error> {
        len(b, 36)?;
        if !self.is_zero() {
            self.validate()?;
        }
        b[..16].copy_from_slice(&self.fs_uuid);
        put32(b, 16, self.client_slot);
        put64(b, 20, self.client_generation);
        put64(b, 28, self.request_seq);
        Ok(())
    }
    pub fn decode(b: &[u8]) -> Result<Self, storage::Error> {
        len(b, 36)?;
        let v = Self {
            fs_uuid: b[..16].try_into().unwrap(),
            client_slot: u32_at(b, 16),
            client_generation: u64_at(b, 20),
            request_seq: u64_at(b, 28),
        };
        if !v.is_zero() {
            v.validate()?;
        }
        Ok(v)
    }
}

/// Canonical management request digest, independent of a capability-table index.
pub fn request_digest(
    operation: u16,
    request: Request,
    payload: &[u8],
) -> Result<[u8; 32], storage::Error> {
    let mut key = [0u8; 36];
    request.key.encode(&mut key)?;
    let mut digest = Sha256::new();
    digest.update(b"CYXIA-SNAP-REQ-V1");
    digest.update(2u16.to_le_bytes());
    digest.update(operation.to_le_bytes());
    digest.update(key);
    digest.update(request.expected_live_view_epoch.to_le_bytes());
    digest.update((payload.len() as u32).to_le_bytes());
    digest.update(payload);
    Ok(digest.finalize().into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub fs_uuid: [u8; 16],
    pub control_generation: u64,
    pub live_view_epoch: u64,
    pub next_snapshot_id: u64,
    pub online_age_ns: u64,
    pub age_generation: u64,
    pub short_last_auto_age_ns: u64,
    pub default_retention_ns: u64,
    pub minimum_retention_ns: u64,
    pub auto_period_ns: u64,
    pub cleanup_freeze: bool,
    pub retention_profile: u32,
    pub gc_generation: u64,
    pub gc_base_checkpoint_generation: u64,
    pub gc_phase: GcPhase,
    pub protection_generation: u64,
    pub restore_phase: RestorePhase,
    pub restore_mode: RestoreMode,
    pub restore_source: SnapshotKey,
    pub restore_request: FileReqKey,
    pub restore_target_epoch: u64,
    pub business_write_gate: Gate,
    pub restore_old_epoch: u64,
    pub long_last_auto_age_ns: u64,
}
impl Control {
    pub const fn initial(fs_uuid: [u8; 16]) -> Self {
        Self {
            fs_uuid,
            control_generation: 1,
            live_view_epoch: 1,
            next_snapshot_id: 1,
            online_age_ns: 0,
            age_generation: 0,
            short_last_auto_age_ns: 0,
            default_retention_ns: DEFAULT_RETENTION_SECONDS * SECOND_NS,
            minimum_retention_ns: MIN_RETENTION_SECONDS * SECOND_NS,
            auto_period_ns: SHORT_PERIOD_SECONDS * SECOND_NS,
            cleanup_freeze: false,
            retention_profile: 1,
            gc_generation: 0,
            gc_base_checkpoint_generation: 0,
            gc_phase: GcPhase::Idle,
            protection_generation: 1,
            restore_phase: RestorePhase::Idle,
            restore_mode: RestoreMode::None,
            restore_source: SnapshotKey::ZERO,
            restore_request: FileReqKey::ZERO,
            restore_target_epoch: 0,
            business_write_gate: Gate::Frozen,
            restore_old_epoch: 0,
            long_last_auto_age_ns: 0,
        }
    }
    fn validate(self) -> Result<(), storage::Error> {
        if self.fs_uuid == [0; 16] {
            return Err(storage::Error::Identity);
        }
        if self.control_generation == 0
            || self.live_view_epoch == 0
            || self.next_snapshot_id == 0
            || self.protection_generation == 0
        {
            return Err(storage::Error::Counter);
        }
        if self.retention_profile != 1
            || self.default_retention_ns != DEFAULT_RETENTION_SECONDS * SECOND_NS
            || self.minimum_retention_ns != MIN_RETENTION_SECONDS * SECOND_NS
            || self.auto_period_ns != SHORT_PERIOD_SECONDS * SECOND_NS
            || !self.online_age_ns.is_multiple_of(SECOND_NS)
            || self.short_last_auto_age_ns > self.online_age_ns
            || self.long_last_auto_age_ns > self.online_age_ns
        {
            return Err(storage::Error::Range);
        }
        if self.gc_phase != GcPhase::Idle
            && (self.gc_generation == 0 || self.gc_base_checkpoint_generation == 0)
        {
            return Err(storage::Error::Counter);
        }
        if self.restore_phase == RestorePhase::Idle {
            if self.restore_mode != RestoreMode::None
                || !self.restore_source.is_zero()
                || !self.restore_request.is_zero()
                || self.restore_target_epoch != 0
                || self.restore_old_epoch != 0
            {
                return Err(storage::Error::Identity);
            }
        } else {
            self.restore_source.validate()?;
            self.restore_request.validate()?;
            if self.restore_source.fs_uuid != self.fs_uuid
                || self.restore_request.fs_uuid != self.fs_uuid
                || self.restore_request.client_slot != 15
                || self.restore_mode == RestoreMode::None
                || self.business_write_gate != Gate::Frozen
                || self.restore_old_epoch == 0
                || self.restore_old_epoch.checked_add(1) != Some(self.restore_target_epoch)
            {
                return Err(storage::Error::Identity);
            }
            let expected = if self.restore_phase == RestorePhase::Preparing {
                self.restore_old_epoch
            } else {
                self.restore_target_epoch
            };
            if self.live_view_epoch != expected {
                return Err(storage::Error::Identity);
            }
        }
        Ok(())
    }
    pub fn encode(&self, b: &mut [u8]) -> Result<(), storage::Error> {
        len(b, BLOCK_SIZE)?;
        self.validate()?;
        b.fill(0);
        put32(b, 0, 0x4359_4643);
        put16(b, 4, 2);
        put16(b, 6, 256);
        b[8..24].copy_from_slice(&self.fs_uuid);
        for (o, v) in [
            (24, self.control_generation),
            (32, self.live_view_epoch),
            (40, self.next_snapshot_id),
            (48, self.online_age_ns),
            (56, self.age_generation),
            (64, self.short_last_auto_age_ns),
            (72, self.default_retention_ns),
            (80, self.minimum_retention_ns),
            (88, self.auto_period_ns),
            (104, self.gc_generation),
            (112, self.gc_base_checkpoint_generation),
            (128, self.protection_generation),
            (220, self.restore_target_epoch),
            (232, self.restore_old_epoch),
            (248, self.long_last_auto_age_ns),
        ] {
            put64(b, o, v);
        }
        put32(b, 96, u32::from(self.cleanup_freeze));
        put32(b, 100, self.retention_profile);
        put32(b, 120, self.gc_phase as u32);
        put32(b, 136, self.restore_phase as u32);
        put32(b, 140, self.restore_mode as u32);
        self.restore_source.encode(&mut b[144..184])?;
        self.restore_request.encode(&mut b[184..220])?;
        put32(b, 228, self.business_write_gate as u32);
        seal(b, 240);
        Ok(())
    }
    pub fn decode(b: &[u8]) -> Result<Self, storage::Error> {
        header(b, BLOCK_SIZE, 0x4359_4643, 2, 256, 240)?;
        zeros(&b[124..128])?;
        zeros(&b[244..248])?;
        zeros(&b[256..])?;
        if u32_at(b, 96) > 1 {
            return Err(storage::Error::Range);
        }
        let v = Self {
            fs_uuid: b[8..24].try_into().unwrap(),
            control_generation: u64_at(b, 24),
            live_view_epoch: u64_at(b, 32),
            next_snapshot_id: u64_at(b, 40),
            online_age_ns: u64_at(b, 48),
            age_generation: u64_at(b, 56),
            short_last_auto_age_ns: u64_at(b, 64),
            default_retention_ns: u64_at(b, 72),
            minimum_retention_ns: u64_at(b, 80),
            auto_period_ns: u64_at(b, 88),
            cleanup_freeze: u32_at(b, 96) != 0,
            retention_profile: u32_at(b, 100),
            gc_generation: u64_at(b, 104),
            gc_base_checkpoint_generation: u64_at(b, 112),
            gc_phase: GcPhase::try_from(u32_at(b, 120))?,
            protection_generation: u64_at(b, 128),
            restore_phase: RestorePhase::try_from(u32_at(b, 136))?,
            restore_mode: RestoreMode::try_from(u32_at(b, 140))?,
            restore_source: SnapshotKey::decode(&b[144..184])?,
            restore_request: FileReqKey::decode(&b[184..220])?,
            restore_target_epoch: u64_at(b, 220),
            business_write_gate: Gate::try_from(u32_at(b, 228))?,
            restore_old_epoch: u64_at(b, 232),
            long_last_auto_age_ns: u64_at(b, 248),
        };
        v.validate()?;
        Ok(v)
    }
    pub(super) fn clear_restore(&mut self) {
        self.restore_phase = RestorePhase::Idle;
        self.restore_mode = RestoreMode::None;
        self.restore_source = SnapshotKey::ZERO;
        self.restore_request = FileReqKey::ZERO;
        self.restore_target_epoch = 0;
        self.restore_old_epoch = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub state: State,
    pub slot_class: SlotClass,
    pub snapshot_id: u64,
    pub slot_generation: u64,
    pub captured_live_view_epoch: u64,
    pub capture_commit_lsn: u64,
    pub created_online_age_ns: u64,
    pub retain_until_ns: u64,
    pub retention_profile: u32,
    pub scope: u32,
    pub creator_client_slot: u32,
    pub creator_client_generation: u64,
    pub creator_request_seq: u64,
    pub descriptor_block: u32,
    pub inode_first_block: u32,
    pub descriptor_sha256: [u8; 32],
    pub retention_generation: u64,
    pub root_drop_commit_lsn: u64,
}
impl Entry {
    pub const fn free(slot: usize, generation: u64) -> Self {
        Self {
            state: State::Free,
            slot_class: if slot < 6 {
                SlotClass::Periodic
            } else {
                SlotClass::OnDemand
            },
            snapshot_id: 0,
            slot_generation: generation,
            captured_live_view_epoch: 0,
            capture_commit_lsn: 0,
            created_online_age_ns: 0,
            retain_until_ns: 0,
            retention_profile: 0,
            scope: 0,
            creator_client_slot: 0,
            creator_client_generation: 0,
            creator_request_seq: 0,
            descriptor_block: 0,
            inode_first_block: 0,
            descriptor_sha256: [0; 32],
            retention_generation: 0,
            root_drop_commit_lsn: 0,
        }
    }
    pub fn key(self, fs_uuid: [u8; 16], slot: usize) -> SnapshotKey {
        SnapshotKey {
            fs_uuid,
            snapshot_id: self.snapshot_id,
            slot: slot as u32,
            slot_generation: self.slot_generation,
        }
    }
    fn validate(self, slot: usize) -> Result<(), storage::Error> {
        if self.slot_class
            != if slot < 6 {
                SlotClass::Periodic
            } else {
                SlotClass::OnDemand
            }
        {
            return Err(storage::Error::Layout);
        }
        if self.state == State::Free {
            if self != Self::free(slot, self.slot_generation) {
                return Err(storage::Error::Reserved);
            }
            return Ok(());
        }
        if self.snapshot_id == 0
            || self.slot_generation == 0
            || self.captured_live_view_epoch == 0
            || self.retention_generation == 0
            || self.creator_client_generation == 0
            || self.creator_request_seq == 0
        {
            return Err(storage::Error::Counter);
        }
        if self.retention_profile != 1
            || self.scope != 1
            || self.creator_client_slot >= 16
            || self.descriptor_block != descriptor_block(slot)
            || self.inode_first_block != descriptor_block(slot) + 1
            || self.retain_until_ns < self.created_online_age_ns
            || (self.state == State::Active && self.root_drop_commit_lsn != 0)
            || (self.state == State::Deleting && self.root_drop_commit_lsn == 0)
        {
            return Err(storage::Error::Layout);
        }
        Ok(())
    }
    fn encode(self, b: &mut [u8], slot: usize) -> Result<(), storage::Error> {
        len(b, 448)?;
        self.validate(slot)?;
        b.fill(0);
        put32(b, 0, self.state as u32);
        put32(b, 4, self.slot_class as u32);
        for (o, v) in [
            (8, self.snapshot_id),
            (16, self.slot_generation),
            (24, self.captured_live_view_epoch),
            (32, self.capture_commit_lsn),
            (40, self.created_online_age_ns),
            (48, self.retain_until_ns),
            (72, self.creator_client_generation),
            (80, self.creator_request_seq),
            (128, self.retention_generation),
            (136, self.root_drop_commit_lsn),
        ] {
            put64(b, o, v);
        }
        put32(b, 56, self.retention_profile);
        put32(b, 60, self.scope);
        put32(b, 64, self.creator_client_slot);
        put32(b, 88, self.descriptor_block);
        put32(b, 92, self.inode_first_block);
        b[96..128].copy_from_slice(&self.descriptor_sha256);
        Ok(())
    }
    fn decode(b: &[u8], slot: usize) -> Result<Self, storage::Error> {
        len(b, 448)?;
        zeros(&b[68..72])?;
        zeros(&b[144..])?;
        let v = Self {
            state: State::try_from(u32_at(b, 0))?,
            slot_class: SlotClass::try_from(u32_at(b, 4))?,
            snapshot_id: u64_at(b, 8),
            slot_generation: u64_at(b, 16),
            captured_live_view_epoch: u64_at(b, 24),
            capture_commit_lsn: u64_at(b, 32),
            created_online_age_ns: u64_at(b, 40),
            retain_until_ns: u64_at(b, 48),
            retention_profile: u32_at(b, 56),
            scope: u32_at(b, 60),
            creator_client_slot: u32_at(b, 64),
            creator_client_generation: u64_at(b, 72),
            creator_request_seq: u64_at(b, 80),
            descriptor_block: u32_at(b, 88),
            inode_first_block: u32_at(b, 92),
            descriptor_sha256: b[96..128].try_into().unwrap(),
            retention_generation: u64_at(b, 128),
            root_drop_commit_lsn: u64_at(b, 136),
        };
        v.validate(slot)?;
        Ok(v)
    }
}
pub const fn descriptor_block(slot: usize) -> u32 {
    SNAPSHOT_START + slot as u32 * SNAPSHOT_STRIDE
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Catalog {
    pub fs_uuid: [u8; 16],
    pub catalog_generation: u64,
    pub entries: [Entry; 8],
}
impl Catalog {
    pub const fn initial(fs_uuid: [u8; 16]) -> Self {
        Self {
            fs_uuid,
            catalog_generation: 1,
            entries: [
                Entry::free(0, 0),
                Entry::free(1, 0),
                Entry::free(2, 0),
                Entry::free(3, 0),
                Entry::free(4, 0),
                Entry::free(5, 0),
                Entry::free(6, 0),
                Entry::free(7, 0),
            ],
        }
    }
    pub fn encode(&self, b: &mut [u8]) -> Result<(), storage::Error> {
        len(b, BLOCK_SIZE)?;
        if self.fs_uuid == [0; 16] {
            return Err(storage::Error::Identity);
        }
        if self.catalog_generation == 0 {
            return Err(storage::Error::Counter);
        }
        for (i, e) in self.entries.iter().enumerate() {
            e.validate(i)?;
        }
        b.fill(0);
        put32(b, 0, 0x4359_5343);
        put16(b, 4, 2);
        put16(b, 6, 512);
        put16(b, 8, 448);
        put16(b, 10, 8);
        b[16..32].copy_from_slice(&self.fs_uuid);
        put64(b, 32, self.catalog_generation);
        for (i, e) in self.entries.iter().enumerate() {
            e.encode(&mut b[512 + i * 448..512 + (i + 1) * 448], i)?;
        }
        seal(b, 40);
        Ok(())
    }
    pub fn decode(b: &[u8]) -> Result<Self, storage::Error> {
        header(b, BLOCK_SIZE, 0x4359_5343, 2, 512, 40)?;
        if u16_at(b, 8) != 448 || u16_at(b, 10) != 8 {
            return Err(storage::Error::Layout);
        }
        zeros(&b[12..16])?;
        zeros(&b[44..512])?;
        let mut v = Self::initial(b[16..32].try_into().unwrap());
        v.catalog_generation = u64_at(b, 32);
        if v.fs_uuid == [0; 16] || v.catalog_generation == 0 {
            return Err(storage::Error::Identity);
        }
        for i in 0..8 {
            v.entries[i] = Entry::decode(&b[512 + i * 448..512 + (i + 1) * 448], i)?;
            if v.entries[i].state != State::Free
                && v.entries[..i]
                    .iter()
                    .any(|e| e.state != State::Free && e.snapshot_id == v.entries[i].snapshot_id)
            {
                return Err(storage::Error::Conflict);
            }
        }
        Ok(v)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub key: SnapshotKey,
    pub captured_live_view_epoch: u64,
    pub capture_commit_lsn: u64,
    pub inode_first_block: u32,
    pub inode_image_sha256: [u8; 32],
    pub created_online_age_ns: u64,
}
impl Descriptor {
    fn validate(self) -> Result<(), storage::Error> {
        self.key.validate()?;
        if self.captured_live_view_epoch == 0
            || self.inode_first_block != descriptor_block(self.key.slot as usize) + 1
        {
            return Err(storage::Error::Layout);
        }
        Ok(())
    }
    pub fn encode(&self, b: &mut [u8]) -> Result<(), storage::Error> {
        len(b, BLOCK_SIZE)?;
        self.validate()?;
        b.fill(0);
        put32(b, 0, 0x4359_5352);
        put16(b, 4, 2);
        put16(b, 6, 128);
        b[8..24].copy_from_slice(&self.key.fs_uuid);
        put64(b, 24, self.key.snapshot_id);
        put32(b, 32, self.key.slot);
        put64(b, 40, self.key.slot_generation);
        put64(b, 48, self.captured_live_view_epoch);
        put64(b, 56, self.capture_commit_lsn);
        put32(b, 64, 224);
        put32(b, 68, 14);
        put32(b, 72, self.inode_first_block);
        b[80..112].copy_from_slice(&self.inode_image_sha256);
        put64(b, 112, self.created_online_age_ns);
        seal(b, 120);
        Ok(())
    }
    pub fn decode(b: &[u8]) -> Result<Self, storage::Error> {
        header(b, BLOCK_SIZE, 0x4359_5352, 2, 128, 120)?;
        zeros(&b[36..40])?;
        zeros(&b[124..])?;
        if u32_at(b, 64) != 224 || u32_at(b, 68) != 14 || u32_at(b, 76) != 0 {
            return Err(storage::Error::Layout);
        }
        let v = Self {
            key: SnapshotKey {
                fs_uuid: b[8..24].try_into().unwrap(),
                snapshot_id: u64_at(b, 24),
                slot: u32_at(b, 32),
                slot_generation: u64_at(b, 40),
            },
            captured_live_view_epoch: u64_at(b, 48),
            capture_commit_lsn: u64_at(b, 56),
            inode_first_block: u32_at(b, 72),
            inode_image_sha256: b[80..112].try_into().unwrap(),
            created_online_age_ns: u64_at(b, 112),
        };
        v.validate()?;
        Ok(v)
    }
}
