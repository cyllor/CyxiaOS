//! Read-only V0.19.9 FileStreamIndex v4 and SecurityStateStore v2 checks.
//!
//! The caller MUST read the *entire* stable 4096-byte block from native
//! storage, validate it together with the superblock/manifest, and reject
//! incompatible legacy v2 media. A checksum is not an authentication root;
//! neither decoding nor generation comparison makes a disk writable.
use super::{Error, file_media_v0199::crc32c_zeroed};

pub const BLOCK_BYTES: usize = 4096;
pub const INDEX_MAGIC: u32 = 0x4359_5349;
pub const INDEX_VERSION: u16 = 4;
pub const INDEX_HEADER: usize = 64;
pub const GROUP_COUNT: usize = 16;
pub const STREAMS_PER_GROUP: usize = 8;
pub const STREAM_COUNT: usize = GROUP_COUNT * STREAMS_PER_GROUP;
pub const STREAM_BASE: usize = 448;
pub const RESERVED_BASE: usize = 3520;
pub const CRC_OFFSET: usize = 4092;
pub const MAX_ISSUED: u64 = (1u64 << 53) - 1;

pub const SECURITY_MAGIC: u32 = 0x4359_5353;
pub const SECURITY_VERSION: u16 = 2;
pub const SECURITY_HEADER: usize = 248;
pub const MAX_ISOLATED_BITMAP: u64 = (1 << 16) - 1;

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    let v = b.get(at..at + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([v[0], v[1]]))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    let v = b.get(at..at + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    let v = b.get(at..at + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]))
}
fn uuid_at(b: &[u8], at: usize) -> Result<[u8; 16], Error> {
    b.get(at..at+16).ok_or(Error::Invalid)?
        .try_into().map_err(|_| Error::Invalid)
}
fn crc_valid(bytes: &[u8]) -> Result<bool, Error> {
    Ok(u32_at(bytes, CRC_OFFSET)? == crc32c_zeroed(bytes, CRC_OFFSET)?)
}
fn flags_ok(flags: u32) -> bool {
    flags & !3 == 0 && flags != 3
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupIndex {
    pub generation: u32,
    pub flags: u32,
    pub boot_epoch: u64,
    pub manifest_principal_id: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamIndex {
    pub generation: u32,
    pub flags: u32,
    pub issued_hi: u64,
    pub retired_through: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStreamIndexV4 {
    pub fs_uuid: [u8; 16],
    pub global_request_id_hi: u64,
    pub generation: u64,
    pub groups: [GroupIndex; GROUP_COUNT],
    pub streams: [StreamIndex; STREAM_COUNT],
}
impl FileStreamIndexV4 {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BLOCK_BYTES
            || u32_at(bytes, 0)? != INDEX_MAGIC
            || u16_at(bytes, 4)? != INDEX_VERSION
            || usize::from(u16_at(bytes, 6)?) != INDEX_HEADER
            || bytes[40..INDEX_HEADER].iter().any(|x| *x != 0)
            || bytes[RESERVED_BASE..CRC_OFFSET].iter().any(|x| *x != 0)
            || !crc_valid(bytes)?
        { return Err(Error::Invalid); }
        let fs_uuid = uuid_at(bytes, 8)?;
        if fs_uuid == [0; 16] { return Err(Error::Invalid); }
        let mut groups = [GroupIndex {
            generation: 0, flags: 0, boot_epoch: 0, manifest_principal_id: 0,
        }; GROUP_COUNT];
        for i in 0..GROUP_COUNT {
            let at = INDEX_HEADER + i * 24;
            let group = GroupIndex {
                generation: u32_at(bytes, at)?,
                flags: u32_at(bytes, at+4)?,
                boot_epoch: u64_at(bytes, at+8)?,
                manifest_principal_id: u64_at(bytes, at+16)?,
            };
            if !flags_ok(group.flags) || group.manifest_principal_id == 0
                || (group.flags == 0
                    && (group.generation != 0 || group.boot_epoch != 0))
                || (group.flags != 0
                    && (group.generation == 0 || group.boot_epoch == 0))
            { return Err(Error::Invalid); }
            // Each group slot is permanently tied to a unique principal.
            for old in 0..i {
                if u64_at(bytes, INDEX_HEADER + old * 24 + 16)?
                    == group.manifest_principal_id
                { return Err(Error::Invalid); }
            }
            groups[i] = group;
        }
        let mut streams = [StreamIndex {
            generation: 0, flags: 0, issued_hi: 0, retired_through: 0,
        }; STREAM_COUNT];
        for i in 0..STREAM_COUNT {
            let at = STREAM_BASE + i * 24;
            let stream = StreamIndex {
                generation: u32_at(bytes, at)?,
                flags: u32_at(bytes, at+4)?,
                issued_hi: u64_at(bytes, at+8)?,
                retired_through: u64_at(bytes, at+16)?,
            };
            if !flags_ok(stream.flags)
                || stream.issued_hi > MAX_ISSUED
                || stream.retired_through > stream.issued_hi
                || (stream.flags == 0 && (
                    stream.generation != 0 || stream.issued_hi != 0
                    || stream.retired_through != 0
                ))
                || (stream.flags != 0 && stream.generation == 0)
            { return Err(Error::Invalid); }
            streams[i] = stream;
        }
        Ok(Self {
            fs_uuid,
            global_request_id_hi: u64_at(bytes, 24)?,
            generation: u64_at(bytes, 32)?,
            groups, streams,
        })
    }

    /// A caller comparing independently authenticated older/newer *committed*
    /// index blocks may forbid rollback. This function does NOT claim redo,
    /// superblock generation or device FLUSH confirmation on its own.
    pub fn no_counter_rollback_from(&self, old: &Self) -> bool {
        if self.fs_uuid != old.fs_uuid
            || self.global_request_id_hi < old.global_request_id_hi
            || self.generation < old.generation
        { return false; }
        for i in 0..GROUP_COUNT {
            if self.groups[i].manifest_principal_id
                != old.groups[i].manifest_principal_id
                || self.groups[i].generation < old.groups[i].generation
                || self.groups[i].boot_epoch < old.groups[i].boot_epoch
            { return false; }
        }
        for i in 0..STREAM_COUNT {
            if self.streams[i].generation < old.streams[i].generation
                || (self.streams[i].generation == old.streams[i].generation
                    && (self.streams[i].issued_hi < old.streams[i].issued_hi
                        || self.streams[i].retired_through
                            < old.streams[i].retired_through))
            { return false; }
        }
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityStateStoreV2 {
    pub fs_uuid: [u8; 16],
    pub state_generation: u64,
    pub rule_min_generation: u64,
    pub security_min_generation: u64,
    pub key_generation: u64,
    pub isolated_service_bitmap: u64,
    pub last_boot_epoch: u64,
    pub offline_config_generation: u64,
    pub offline_config_hash: [u8; 32],
    pub service_generations: [u64; 16],
}
impl SecurityStateStoreV2 {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BLOCK_BYTES
            || u32_at(bytes, 0)? != SECURITY_MAGIC
            || u16_at(bytes, 4)? != SECURITY_VERSION
            || usize::from(u16_at(bytes, 6)?) != SECURITY_HEADER
            || u32_at(bytes, 76)? != 0
            || u64_at(bytes, 56)? & !MAX_ISOLATED_BITMAP != 0
            || bytes[SECURITY_HEADER..].iter().any(|x| *x != 0)
            || u32_at(bytes, 72)? != crc32c_zeroed(bytes, 72)?
        { return Err(Error::Invalid); }
        let fs_uuid = uuid_at(bytes, 8)?;
        let mut config_hash = [0; 32];
        config_hash.copy_from_slice(&bytes[88..120]);
        if fs_uuid == [0; 16]
            || u64_at(bytes, 24)? == 0
            || u64_at(bytes, 80)? == 0
            || config_hash == [0; 32]
        { return Err(Error::Invalid); }
        let mut service_generations = [0u64; 16];
        for (i, generation) in service_generations.iter_mut().enumerate() {
            *generation = u64_at(bytes, 120 + i * 8)?;
        }
        Ok(Self {
            fs_uuid,
            state_generation: u64_at(bytes, 24)?,
            rule_min_generation: u64_at(bytes, 32)?,
            security_min_generation: u64_at(bytes, 40)?,
            key_generation: u64_at(bytes, 48)?,
            isolated_service_bitmap: u64_at(bytes, 56)?,
            last_boot_epoch: u64_at(bytes, 64)?,
            offline_config_generation: u64_at(bytes, 80)?,
            offline_config_hash: config_hash,
            service_generations,
        })
    }

    /// An authenticated new committed generation must never undo durable
    /// security minima, boot epochs, or individual service generations.
    /// Isolation clearance requires separate protected authorization and
    /// cannot be inferred from this monotonic comparison alone.
    pub fn no_rollback_from(&self, old: &Self) -> bool {
        self.fs_uuid == old.fs_uuid
            && self.state_generation >= old.state_generation
            && self.rule_min_generation >= old.rule_min_generation
            && self.security_min_generation >= old.security_min_generation
            && self.key_generation >= old.key_generation
            && self.last_boot_epoch >= old.last_boot_epoch
            && self.offline_config_generation >= old.offline_config_generation
            && self.service_generations.iter().zip(old.service_generations)
                .all(|(new,old)| *new >= old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn finalize_crc(b: &mut [u8; BLOCK_BYTES], at: usize) {
        let crc = crc32c_zeroed(b, at).unwrap();
        b[at..at+4].copy_from_slice(&crc.to_le_bytes());
    }
    fn index() -> [u8; BLOCK_BYTES] {
        let mut b=[0u8; BLOCK_BYTES];
        b[0..4].copy_from_slice(&INDEX_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&INDEX_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(INDEX_HEADER as u16).to_le_bytes());
        b[8..24].copy_from_slice(&[1;16]);
        b[32..40].copy_from_slice(&1u64.to_le_bytes());
        for i in 0..GROUP_COUNT {
            let at = INDEX_HEADER + i*24 + 16;
            b[at..at+8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        }
        finalize_crc(&mut b,CRC_OFFSET);
        b
    }
    fn security() -> [u8; BLOCK_BYTES] {
        let mut b=[0u8;BLOCK_BYTES];
        b[0..4].copy_from_slice(&SECURITY_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&SECURITY_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(SECURITY_HEADER as u16).to_le_bytes());
        b[8..24].copy_from_slice(&[1;16]);
        b[24..32].copy_from_slice(&1u64.to_le_bytes());
        b[80..88].copy_from_slice(&1u64.to_le_bytes());
        b[88..120].copy_from_slice(&[2u8;32]);
        finalize_crc(&mut b,72);
        b
    }
    #[test]
    fn exact_index_v4_and_counter_monotonicity() {
        let raw=index();let baseline=FileStreamIndexV4::decode(&raw).unwrap();
        assert_eq!(baseline.groups.len(),16);
        assert_eq!(baseline.streams.len(),128);
        let mut next=raw;
        next[24..32].copy_from_slice(&1u64.to_le_bytes());
        next[32..40].copy_from_slice(&2u64.to_le_bytes());
        next[64..68].copy_from_slice(&1u32.to_le_bytes());
        next[68..72].copy_from_slice(&1u32.to_le_bytes());
        next[72..80].copy_from_slice(&1u64.to_le_bytes());
        next[448..452].copy_from_slice(&1u32.to_le_bytes());
        next[452..456].copy_from_slice(&1u32.to_le_bytes());
        next[456..464].copy_from_slice(&3u64.to_le_bytes());
        next[464..472].copy_from_slice(&1u64.to_le_bytes());
        finalize_crc(&mut next, CRC_OFFSET);
        let fresh=FileStreamIndexV4::decode(&next).unwrap();
        assert!(fresh.no_counter_rollback_from(&baseline));
        assert!(!baseline.no_counter_rollback_from(&fresh));
        assert_eq!(fresh.streams[0].issued_hi,3);
    }
    #[test]
    fn index_rejects_duplicate_principal_bad_crc_reserved_and_impossible_streams() {
        let mut bad=index();bad[104..112].copy_from_slice(&1u64.to_le_bytes());
        finalize_crc(&mut bad, CRC_OFFSET);
        assert!(FileStreamIndexV4::decode(&bad).is_err());
        bad=index();bad[3520]=1;finalize_crc(&mut bad,CRC_OFFSET);
        assert!(FileStreamIndexV4::decode(&bad).is_err());
        bad=index();bad[0]=0;assert!(FileStreamIndexV4::decode(&bad).is_err());
        bad=index();bad[448..452].copy_from_slice(&1u32.to_le_bytes());
        bad[452..456].copy_from_slice(&1u32.to_le_bytes());
        bad[464..472].copy_from_slice(&1u64.to_le_bytes()); // retired without issued
        finalize_crc(&mut bad,CRC_OFFSET);
        assert!(FileStreamIndexV4::decode(&bad).is_err());
        bad=index();bad[4]=3;finalize_crc(&mut bad,CRC_OFFSET);
        assert!(FileStreamIndexV4::decode(&bad).is_err());
    }
    #[test]
    fn security_state_v2_enforces_crc_reserved_isolation_and_monotonic_minima() {
        let raw=security();let old=SecurityStateStoreV2::decode(&raw).unwrap();
        let mut next=raw;
        next[24..32].copy_from_slice(&2u64.to_le_bytes());
        next[32..40].copy_from_slice(&9u64.to_le_bytes());
        next[64..72].copy_from_slice(&1u64.to_le_bytes());
        next[56..64].copy_from_slice(&1u64.to_le_bytes());
        finalize_crc(&mut next,72);
        let current=SecurityStateStoreV2::decode(&next).unwrap();
        assert!(current.no_rollback_from(&old));
        assert!(!old.no_rollback_from(&current));
        let mut bad=next;bad[56..64].copy_from_slice(&(1u64<<17).to_le_bytes());
        finalize_crc(&mut bad,72);
        assert!(SecurityStateStoreV2::decode(&bad).is_err());
        bad=next;bad[247]=1;finalize_crc(&mut bad,72);
        // Last byte in service_generation[15] is legitimate, so this change
        // must be accepted as a new service generation; it is not reserved.
        assert!(SecurityStateStoreV2::decode(&bad).is_ok());
        bad=next;bad[248]=1;finalize_crc(&mut bad,72);
        assert!(SecurityStateStoreV2::decode(&bad).is_err());
        bad=next;bad[72]^=1;
        assert!(SecurityStateStoreV2::decode(&bad).is_err());
    }
}
