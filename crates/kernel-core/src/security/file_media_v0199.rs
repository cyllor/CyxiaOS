//! V0.19.9 single-device FS media **read-only validation** contracts.
//!
//! New v1 superblock and v4 192-byte persistent receipt formats are not the
//! legacy v2 snapshotted volume and must NEVER be silently reinterpreted as
//! writable/migrated media. CRC32C detects accidental damage, not a malicious
//! storage host or rollback. No mount, root update or redo/FLUSH is performed.
use super::Error;
pub const SUPER_BYTES:usize=4096;
pub const SUPER_MAGIC:u32=0x4359_4653;
pub const SUPER_VERSION:u16=1;
pub const BLOCK_COUNT:u32=131072;
pub const DATA_START:u32=4118;
pub const BITMAP_START:u32=4098;
pub const INODE_START:u32=4102;
pub const RECEIPT_BYTES:usize=192;
pub const RECEIPT_MAGIC:u32=0x4359_5243;
pub const RECEIPT_VERSION:u16=4;
pub const MAX_REQUEST_SEQ:u64=(1u64<<53)-1;

fn le16(b:&[u8],off:usize)->Result<u16,Error>{
    let s=b.get(off..off+2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([s[0],s[1]]))
}
fn le32(b:&[u8],off:usize)->Result<u32,Error>{
    let s=b.get(off..off+4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0],s[1],s[2],s[3]]))
}
fn le64(b:&[u8],off:usize)->Result<u64,Error>{
    let s=b.get(off..off+8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]]))
}
fn uuid(b:&[u8],off:usize)->Result<[u8;16],Error>{
    b.get(off..off+16).ok_or(Error::Invalid)?
        .try_into().map_err(|_|Error::Invalid)
}
// Fixed 1 KiB read-only table, no heap, no mutable global state and no
// architecture-specific instruction requirement. Match the historical
// storage codec's CRC32C polynomial and initial/final XOR.
const fn crc32c_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(value & 1));
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}
static CRC32C_TABLE: [u32; 256] = crc32c_table();

#[inline]
fn crc32c_byte(crc: u32, byte: u8) -> u32 {
    (crc >> 8) ^ CRC32C_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize]
}

/// Reflected CRC32C (Castagnoli); the stored crc32c field itself reads zero.
/// Visit each byte exactly once, with no per-byte bit loop or copied page.
pub fn crc32c_zeroed(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).filter(|end| *end <= bytes.len()).ok_or(Error::Invalid)?;
    let mut crc = u32::MAX;
    for &byte in &bytes[..offset] { crc = crc32c_byte(crc, byte); }
    for _ in 0..4 { crc = crc32c_byte(crc, 0); }
    for &byte in &bytes[end..] { crc = crc32c_byte(crc, byte); }
    Ok(!crc)
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct SuperblockV1 {
    pub fs_uuid:[u8;16],
    pub generation:u64,
    pub checkpoint_lsn:u64,
    pub log_epoch:u64,
}
impl SuperblockV1 {
    pub fn decode(bytes:&[u8])->Result<Self,Error>{
        if bytes.len()!=SUPER_BYTES
            || le32(bytes,0)?!=SUPER_MAGIC || le16(bytes,4)?!=SUPER_VERSION
            || le16(bytes,6)?!=80
            || le32(bytes,8)?!=4096 || le32(bytes,12)?!=BLOCK_COUNT
            || le32(bytes,56)?!=BITMAP_START
            || le32(bytes,60)?!=INODE_START
            || le32(bytes,64)?!=DATA_START
            || le32(bytes,68)?!=256 || le32(bytes,72)?!=0
            || bytes[80..].iter().any(|v|*v!=0)
            || le32(bytes,76)?!=crc32c_zeroed(bytes,76)?
        {return Err(Error::Invalid);}
        let value=Self{
            fs_uuid:uuid(bytes,16)?,
            generation:le64(bytes,32)?,
            checkpoint_lsn:le64(bytes,40)?,
            log_epoch:le64(bytes,48)?,
        };
        if value.fs_uuid==[0;16] || value.generation==0
            || value.log_epoch==0
        {return Err(Error::Invalid);}
        Ok(value)
    }
}
/// Read-only migration inventory. Neither classification authorizes a mount,
/// reformat, write, or migration: the unified snapshot layout is still DRAFT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotMediaKind {
    BaselineV1,
    LegacySnapshotV2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotMediaProbe {
    pub kind: SnapshotMediaKind,
    pub fs_uuid: [u8; 16],
    pub generation: u64,
    pub checkpoint_lsn: u64,
    pub log_epoch: u64,
}

fn probe_snapshot_header(bytes: &[u8]) -> Result<SnapshotMediaProbe, Error> {
    if bytes.len() != SUPER_BYTES || le32(bytes, 0)? != SUPER_MAGIC {
        return Err(Error::Invalid);
    }
    let kind = match le16(bytes, 4)? {
        1 => {
            SuperblockV1::decode(bytes)?;
            SnapshotMediaKind::BaselineV1
        }
        2 => {
            // Historical storage.rs v2: FSControl at 4118, catalog at 4119,
            // eight 15-block slots, system objects start at 4240.
            if le16(bytes, 6)? != 112
                || le32(bytes, 8)? != 4096 || le32(bytes, 12)? != BLOCK_COUNT
                || le32(bytes, 56)? != BITMAP_START
                || le32(bytes, 60)? != INODE_START
                || le32(bytes, 64)? != 4240 || le32(bytes, 68)? != 256
                || le32(bytes, 72)? != 0 || le32(bytes, 76)? != 4118
                || le32(bytes, 80)? != 4119 || le32(bytes, 84)? != 4120
                || le32(bytes, 88)? != 8 || le32(bytes, 92)? != 15
                || le32(bytes, 96)? != 224 || le32(bytes, 100)? != 224
                || le32(bytes, 104)? != 0
                || le32(bytes, 108)? != crc32c_zeroed(bytes, 108)?
                || bytes[112..].iter().any(|v| *v != 0)
            {
                return Err(Error::Invalid);
            }
            SnapshotMediaKind::LegacySnapshotV2
        }
        _ => return Err(Error::Invalid),
    };
    let result = SnapshotMediaProbe {
        kind,
        fs_uuid: uuid(bytes, 16)?,
        generation: le64(bytes, 32)?,
        checkpoint_lsn: le64(bytes, 40)?,
        log_epoch: le64(bytes, 48)?,
    };
    if result.fs_uuid == [0; 16] || result.generation == 0 || result.log_epoch == 0 {
        return Err(Error::Invalid);
    }
    Ok(result)
}

/// Strict offline preflight: both headers must be independently valid.
/// Damaged, mixed-format, mismatched identity, and regressed checkpoint
/// pairs require separate recovery evidence; never choose a format by version
/// number or by which copy happened to parse. No writes are possible here.
pub fn probe_snapshot_media_pair(
    first: &[u8], second: &[u8],
) -> Result<SnapshotMediaProbe, Error> {
    let a = probe_snapshot_header(first)?;
    let b = probe_snapshot_header(second)?;
    if a.kind != b.kind || a.fs_uuid != b.fs_uuid {
        return Err(Error::Conflict);
    }
    if a.generation == b.generation {
        return if a == b { Ok(a) } else { Err(Error::Conflict) };
    }
    let (older, newer) = if a.generation < b.generation { (a, b) } else { (b, a) };
    if newer.checkpoint_lsn < older.checkpoint_lsn || newer.log_epoch <= older.log_epoch {
        return Err(Error::Conflict);
    }
    Ok(newer)
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct FileReceiptV4 {
    pub fs_uuid:[u8;16],
    pub issued_boot_epoch:u64,
    pub group_id:u32,
    pub group_generation:u32,
    pub stream_slot:u64,
    pub stream_generation:u64,
    pub request_seq:u64,
    pub log_epoch:u64,
    pub txid:u64,
    pub commit_lsn:u64,
    pub write_seq:u64,
    pub status:u16,
    pub result:i32,
    pub completed_prefix:u32,
    pub operation_digest:[u8;32],
    pub output_digest:[u8;32],
    pub request_id:u64,
    pub owner_principal_id:u64,
}
impl FileReceiptV4 {
    pub fn decode(bytes:&[u8])->Result<Self,Error>{
        if bytes.len()!=RECEIPT_BYTES
            || le32(bytes,0)?!=RECEIPT_MAGIC
            || le16(bytes,4)?!=RECEIPT_VERSION
            || le16(bytes,6)?!=RECEIPT_BYTES as u16
            || le16(bytes,98)?!=0
            || le32(bytes,188)?!=crc32c_zeroed(bytes,188)?
        {return Err(Error::Invalid);}
        let value=Self {
            fs_uuid:uuid(bytes,8)?,
            issued_boot_epoch:le64(bytes,24)?,
            group_id:le32(bytes,32)?,
            group_generation:le32(bytes,36)?,
            stream_slot:le64(bytes,40)?,
            stream_generation:le64(bytes,48)?,
            request_seq:le64(bytes,56)?,
            log_epoch:le64(bytes,64)?,
            txid:le64(bytes,72)?,
            commit_lsn:le64(bytes,80)?,
            write_seq:le64(bytes,88)?,
            status:le16(bytes,96)?,
            result:le32(bytes,100)? as i32,
            completed_prefix:le32(bytes,104)?,
            operation_digest:bytes[108..140].try_into().map_err(|_|Error::Invalid)?,
            output_digest:bytes[140..172].try_into().map_err(|_|Error::Invalid)?,
            request_id:le64(bytes,172)?,
            owner_principal_id:le64(bytes,180)?,
        };
        if value.fs_uuid==[0;16]
            || value.issued_boot_epoch==0 || value.group_id>=16
            || value.group_generation==0
            || value.stream_slot>=8
            || value.stream_generation==0 || value.stream_generation>u32::MAX as u64
            || value.request_seq==0 || value.request_seq>MAX_REQUEST_SEQ
            || !(1..=6).contains(&value.status)
            || value.request_id==0 || value.owner_principal_id==0
            || (value.status==1
                && (value.log_epoch!=0 || value.txid!=0
                    || value.commit_lsn!=0 || value.write_seq!=0
                    || value.result!=0 || value.completed_prefix!=0
                    || value.operation_digest!=[0;32]
                    || value.output_digest!=[0;32]))
            || (value.status!=1 && value.operation_digest==[0;32])
        {return Err(Error::Invalid);}
        Ok(value)
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    fn super_v1()->[u8;SUPER_BYTES] {
        let mut b=[0u8;SUPER_BYTES];
        b[0..4].copy_from_slice(&SUPER_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&SUPER_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&80u16.to_le_bytes());
        b[8..12].copy_from_slice(&4096u32.to_le_bytes());
        b[12..16].copy_from_slice(&BLOCK_COUNT.to_le_bytes());
        b[16..32].copy_from_slice(&[1u8;16]);
        b[32..40].copy_from_slice(&1u64.to_le_bytes());
        b[48..56].copy_from_slice(&1u64.to_le_bytes());
        b[56..60].copy_from_slice(&BITMAP_START.to_le_bytes());
        b[60..64].copy_from_slice(&INODE_START.to_le_bytes());
        b[64..68].copy_from_slice(&DATA_START.to_le_bytes());
        b[68..72].copy_from_slice(&256u32.to_le_bytes());
        let crc=crc32c_zeroed(&b,76).unwrap();
        b[76..80].copy_from_slice(&crc.to_le_bytes());
        b
    }
    fn receipt()->[u8;RECEIPT_BYTES] {
        let mut b=[0u8;RECEIPT_BYTES];
        b[0..4].copy_from_slice(&RECEIPT_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&RECEIPT_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(RECEIPT_BYTES as u16).to_le_bytes());
        b[8..24].copy_from_slice(&[1u8;16]);
        b[24..32].copy_from_slice(&1u64.to_le_bytes());
        b[36..40].copy_from_slice(&1u32.to_le_bytes());
        b[48..56].copy_from_slice(&1u64.to_le_bytes());
        b[56..64].copy_from_slice(&1u64.to_le_bytes());
        b[96..98].copy_from_slice(&1u16.to_le_bytes());
        b[172..180].copy_from_slice(&1u64.to_le_bytes());
        b[180..188].copy_from_slice(&2u64.to_le_bytes());
        let crc=crc32c_zeroed(&b,188).unwrap();
        b[188..192].copy_from_slice(&crc.to_le_bytes());
        b
    }
    fn super_v2()->[u8;SUPER_BYTES] {
        let mut b=super_v1();
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[6..8].copy_from_slice(&112u16.to_le_bytes());
        for (at,value) in [(64,4240u32),(76,4118),(80,4119),(84,4120),
            (88,8),(92,15),(96,224),(100,224)] {
            b[at..at+4].copy_from_slice(&value.to_le_bytes());
        }
        let crc=crc32c_zeroed(&b,108).unwrap();
        b[108..112].copy_from_slice(&crc.to_le_bytes());
        b
    }
    #[test]
    fn crc_matches_bitwise_reference_and_real_legacy_encoder() {
        // Compare with the independent old bitwise calculation, including
        // offset zero, unaligned fields, the last four bytes and overflow.
        fn reference(b: &[u8], at: usize) -> u32 {
            let mut crc=u32::MAX;
            for (i, &byte) in b.iter().enumerate() {
                crc ^= u32::from(if (at..at+4).contains(&i) {0} else {byte});
                for _ in 0..8 {
                    crc=(crc>>1) ^ (if crc&1!=0 {0x82f6_3b78} else {0});
                }
            }
            !crc
        }
        let bytes: [u8;SUPER_BYTES] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        for (length,offset) in [(4,0),(9,1),(192,188),(4096,0),(4096,76),(4096,108),(4096,4092)] {
            assert_eq!(crc32c_zeroed(&bytes[..length],offset),Ok(reference(&bytes[..length],offset)));
            let mut zeroed=bytes;
            zeroed[offset..offset+4].fill(0);
            assert_eq!(crc32c_zeroed(&bytes[..length],offset),
                Ok(cyxia_prototype::storage::crc32c(&zeroed[..length])));
        }
        assert_eq!(crc32c_zeroed(&bytes,usize::MAX),Err(Error::Invalid));
        assert_eq!(crc32c_zeroed(&bytes,4093),Err(Error::Invalid));

        // Generate the source volume using the *actual* historical encoder,
        // not a duplicate table of layout offsets in the preflight test.
        let old=cyxia_prototype::storage::Superblock {
            fs_uuid:[1;16],generation:1,checkpoint_lsn:0,log_epoch:1
        };
        let mut a=[0u8;SUPER_BYTES];
        old.encode(&mut a).unwrap();
        assert_eq!(a,super_v2());
        let next=cyxia_prototype::storage::Superblock {
            generation:2, checkpoint_lsn:19, log_epoch:2, ..old
        };
        let mut b=[0u8;SUPER_BYTES];
        next.encode(&mut b).unwrap();
        let p=probe_snapshot_media_pair(&a,&b).unwrap();
        assert_eq!(p.kind,SnapshotMediaKind::LegacySnapshotV2);
        assert_eq!(p.fs_uuid,next.fs_uuid);
        assert_eq!((p.generation,p.checkpoint_lsn,p.log_epoch),(2,19,2));
        assert_eq!(probe_snapshot_media_pair(&super_v1(),&a),Err(Error::Conflict));
        b[4095]^=1;
        assert!(probe_snapshot_media_pair(&a,&b).is_err());
    }

    #[test]
    fn snapshot_migration_preflight_rejects_mixed_corrupt_and_regressed_headers() {
        let v1=super_v1();
        let v2=super_v2();
        assert_eq!(probe_snapshot_media_pair(&v1,&v1).unwrap().kind,SnapshotMediaKind::BaselineV1);
        assert_eq!(probe_snapshot_media_pair(&v2,&v2).unwrap().kind,SnapshotMediaKind::LegacySnapshotV2);
        assert_eq!(probe_snapshot_media_pair(&v1,&v2),Err(Error::Conflict));
        assert!(probe_snapshot_media_pair(&v2,&[0;SUPER_BYTES]).is_err());
        let mut other=v2;
        other[16]=2;
        let crc=crc32c_zeroed(&other,108).unwrap();
        other[108..112].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(probe_snapshot_media_pair(&v2,&other),Err(Error::Conflict));
        let mut next=v2;
        next[32..40].copy_from_slice(&2u64.to_le_bytes());
        next[40..48].copy_from_slice(&12u64.to_le_bytes());
        next[48..56].copy_from_slice(&2u64.to_le_bytes());
        let crc=crc32c_zeroed(&next,108).unwrap();
        next[108..112].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(probe_snapshot_media_pair(&next,&v2).unwrap().generation,2);
        next[48..56].copy_from_slice(&1u64.to_le_bytes());
        let crc=crc32c_zeroed(&next,108).unwrap();
        next[108..112].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(probe_snapshot_media_pair(&v2,&next),Err(Error::Conflict));
    }
    #[test]
    fn v0199_superblock_golden_offsets_and_crc_fail_closed(){
        assert!(SuperblockV1::decode(&super_v1()).is_ok());
        let mut b=super_v1();b[4]=2;
        assert!(SuperblockV1::decode(&b).is_err());
        b=super_v1();b[64..68].copy_from_slice(&4240u32.to_le_bytes());
        assert!(SuperblockV1::decode(&b).is_err());
        b=super_v1();b[80]=1;
        assert!(SuperblockV1::decode(&b).is_err());
        b=super_v1();b[16]^=1;
        assert!(SuperblockV1::decode(&b).is_err());
        assert_eq!(crc32c_zeroed(&[0u8;2],0),Err(Error::Invalid));
    }
    #[test]
    fn v0199_receipt_v4_rejects_old_version_crc_and_unbound_forgery(){
        assert_eq!(FileReceiptV4::decode(&receipt()).unwrap().status,1);
        let mut b=receipt();b[4]=3;
        assert!(FileReceiptV4::decode(&b).is_err());
        b=receipt();b[40..48].copy_from_slice(&8u64.to_le_bytes());
        let crc=crc32c_zeroed(&b,188).unwrap();b[188..192].copy_from_slice(&crc.to_le_bytes());
        assert!(FileReceiptV4::decode(&b).is_err());
        b=receipt();b[100..104].copy_from_slice(&0i32.to_le_bytes());b[188]^=1;
        assert!(FileReceiptV4::decode(&b).is_err());
        b=receipt();b[64..72].copy_from_slice(&1u64.to_le_bytes());
        let crc=crc32c_zeroed(&b,188).unwrap();b[188..192].copy_from_slice(&crc.to_le_bytes());
        assert!(FileReceiptV4::decode(&b).is_err());
    }
}
