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

/// CRC32C of an ordinary payload with no embedded checksum field.
pub fn crc32c_payload(bytes:&[u8])->u32{
    let mut crc=u32::MAX;
    for &byte in bytes{crc=crc32c_byte(crc,byte);}
    !crc
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
    // V0.19.9 §9.5: two valid copies are necessary but their generations
    // must also prove exactly one alternating checkpoint transition.
    if older.generation.checked_add(1)!=Some(newer.generation)
        ||older.log_epoch.checked_add(1)!=Some(newer.log_epoch)
        ||newer.checkpoint_lsn<older.checkpoint_lsn {
        return Err(Error::Conflict);
    }
    Ok(newer)
}

/// Read-only verification of one complete baseline-v1 redo transaction.
/// The journal owner supplies the stable records, physical log position,
/// authenticated current superblock and protected state file's home block.
/// A valid chain is NOT proof of actual FLUSH or of latest committed state.
pub fn verify_state_redo_v1(
    superblock:SuperblockV1, first_log_block:u32, state_home:u64,
    begin:&[u8], redos:&[&[u8]], commit:&[u8], expected_state:&[u8],
    txid:u64, commit_lsn:u64,
)->Result<(),Error>{
    use sha2::{Digest,Sha256};
    let n=redos.len();
    if !(1..=128).contains(&n) || !(2..=4097).contains(&first_log_block)
        || first_log_block.checked_add(2+2*n as u32).is_none_or(|end|end>4098)
        || !(u64::from(DATA_START)..u64::from(BLOCK_COUNT)).contains(&state_home)
        || expected_state.len()!=SUPER_BYTES || superblock.fs_uuid==[0;16]
        || superblock.generation==0 || superblock.log_epoch==0 || txid==0
    {return Err(Error::Invalid);}
    fn record(b:&[u8],kind:u16,length:usize,padded:usize,txid:u64,epoch:u64,lsn:u64)->Result<(),Error>{
        if b.len()!=padded || le32(b,0)?!=0x4359_4c47 || le16(b,4)?!=1
            || le16(b,6)?!=kind || le32(b,8)?!=length as u32
            || le64(b,16)?!=txid || le64(b,24)?!=lsn || lsn==0
            || le64(b,32)?!=epoch || le32(b,60)?!=0
            || le32(b,56)?!=crc32c_zeroed(&b[..64],56)?
            || le32(b,12)?!=crc32c_payload(&b[64..length])
            || b[length..].iter().any(|x|*x!=0)
            || (kind!=2 && b[40..56].iter().any(|x|*x!=0))
        {return Err(Error::Invalid);}
        Ok(())
    }
    let begin_lsn=commit_lsn.checked_sub(n as u64+1).ok_or(Error::Invalid)?;
    if begin_lsn<=superblock.checkpoint_lsn{return Err(Error::Stale);}
    record(begin,1,80,4096,txid,superblock.log_epoch,begin_lsn)?;
    record(commit,3,128,4096,txid,superblock.log_epoch,commit_lsn)?;
    if le32(begin,64)?!=n as u32 || le32(begin,68)?!=0
        || le64(begin,72)?!=4096*n as u64 || le64(commit,64)?!=txid
        || le64(commit,72)?!=begin_lsn || le64(commit,80)?!=commit_lsn-1
        || le32(commit,88)?!=n as u32 || le32(commit,92)?!=0
    {return Err(Error::Conflict);}
    let mut homes=[0u64;128];
    let mut ordered=Sha256::new();
    let mut found=false;
    for (i,b) in redos.iter().enumerate(){
        record(b,2,4160,8192,txid,superblock.log_epoch,begin_lsn+i as u64+1)?;
        let home=le64(b,40)?;
        if !(u64::from(BITMAP_START)..u64::from(BLOCK_COUNT)).contains(&home)
            || homes[..i].contains(&home)
            || le32(b,48)?!=i as u32 || le32(b,52)?!=n as u32
        {return Err(Error::Conflict);}
        homes[i]=home;
        let image=&b[64..4160];
        ordered.update(home.to_le_bytes());ordered.update(image);
        if home==state_home{
            if image!=expected_state{return Err(Error::Conflict);}
            found=true;
        }
    }
    let digest:[u8;32]=ordered.finalize().into();
    if !found || digest.as_slice()!=&commit[96..128]{return Err(Error::Conflict);}
    Ok(())
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
/// The local request identity is a deterministic projection of the full key,
/// never a caller-chosen second identifier. This is format, not authority.
pub const fn local_request_id(group_id:u32,stream_slot:u64,request_seq:u64)->Option<u64>{
    if group_id>=16 || stream_slot>=8 || request_seq==0 || request_seq>MAX_REQUEST_SEQ {
        return None;
    }
    Some(((group_id as u64+1)<<56)|(stream_slot<<53)|request_seq)
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
            || local_request_id(value.group_id,value.stream_slot,value.request_seq)!=Some(value.request_id)
            || value.owner_principal_id==0
            // A transaction identity is either absent or complete.
            || ((value.log_epoch==0 || value.txid==0 || value.commit_lsn==0)
                && (value.log_epoch!=0 || value.txid!=0 || value.commit_lsn!=0))
            // CANCEL_UNBOUND may retire a proven no-effect unbound ticket.
            // Zero operation digest is legal only for ISSUED or that
            // cancelled form, and all unbound operation fields stay zero.
            || (value.operation_digest==[0;32]
                && (!matches!(value.status,1|6) || value.log_epoch!=0 || value.txid!=0
                    || value.commit_lsn!=0 || value.write_seq!=0
                    || value.result!=0 || value.completed_prefix!=0
                    || value.output_digest!=[0;32]))
            || (value.status==1 && value.operation_digest!=[0;32])
        {return Err(Error::Invalid);}
        Ok(value)
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn baseline_state_redo_requires_complete_ordered_chain(){
        use sha2::{Digest,Sha256};
        fn put16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
        fn put32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
        fn put64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
        fn seal(b:&mut[u8],kind:u16,len:usize,lsn:u64){
            put32(b,0,0x4359_4c47);put16(b,4,1);put16(b,6,kind);
            put32(b,8,len as u32);put64(b,16,7);put64(b,24,lsn);put64(b,32,2);
            let p=cyxia_prototype::storage::crc32c(&b[64..len]);put32(b,12,p);
            let h=crc32c_zeroed(&b[..64],56).unwrap();put32(b,56,h);
        }
        let sb=SuperblockV1{fs_uuid:[1;16],generation:2,checkpoint_lsn:10,log_epoch:2};
        let state=[0x5au8;4096];
        let home=7000u64;
        let mut begin=[0u8;4096];put32(&mut begin,64,1);put64(&mut begin,72,4096);
        seal(&mut begin,1,80,11);
        let mut redo=[0u8;8192];put64(&mut redo,40,home);put32(&mut redo,52,1);
        redo[64..4160].copy_from_slice(&state);seal(&mut redo,2,4160,12);
        let mut commit=[0u8;4096];put64(&mut commit,64,7);put64(&mut commit,72,11);
        put64(&mut commit,80,12);put32(&mut commit,88,1);
        let mut digest=Sha256::new();digest.update(home.to_le_bytes());digest.update(&state);
        commit[96..128].copy_from_slice(&digest.finalize());seal(&mut commit,3,128,13);
        let check=|sb,first,home,redo:&[u8],commit:&[u8],image:&[u8]|
            verify_state_redo_v1(sb,first,home,&begin,&[redo],commit,image,7,13);
        assert_eq!(check(sb,2,home,&redo,&commit,&state),Ok(()));
        assert_eq!(check(sb,4096,home,&redo,&commit,&state),Err(Error::Invalid));
        assert_eq!(check(SuperblockV1{checkpoint_lsn:11,..sb},2,home,&redo,&commit,&state),Err(Error::Stale));
        assert_eq!(check(sb,2,home+1,&redo,&commit,&state),Err(Error::Conflict));
        let mut bad=redo;bad[64]^=1;
        assert_eq!(check(sb,2,home,&bad,&commit,&state),Err(Error::Invalid));
        let mut bad=commit;bad[96]^=1;seal(&mut bad,3,128,13);
        assert_eq!(check(sb,2,home,&redo,&bad,&state),Err(Error::Conflict));
        assert_eq!(check(sb,2,home,&redo,&commit,&[0u8;4096]),Err(Error::Conflict));
    }
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
        b[172..180].copy_from_slice(&local_request_id(0,0,1).unwrap().to_le_bytes());
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
        assert_eq!(crc32c_payload(b"123456789"),0xe306_9283);
        assert_eq!(crc32c_payload(&[]),0);
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
    fn v0199_checkpoint_requires_adjacent_generation_and_log_epoch(){
        let a=super_v1();let old=SuperblockV1::decode(&a).unwrap();
        let next=|generation:u64,epoch:u64,lsn:u64|{
            let mut b=a;b[32..40].copy_from_slice(&generation.to_le_bytes());
            b[40..48].copy_from_slice(&lsn.to_le_bytes());b[48..56].copy_from_slice(&epoch.to_le_bytes());
            let c=crc32c_zeroed(&b,76).unwrap();b[76..80].copy_from_slice(&c.to_le_bytes());b
        };
        let good=next(old.generation+1,old.log_epoch+1,old.checkpoint_lsn+3);
        assert_eq!(probe_snapshot_media_pair(&good,&a).unwrap().generation,old.generation+1);
        for bad in [next(old.generation+2,old.log_epoch+1,old.checkpoint_lsn+3),
                    next(old.generation+1,old.log_epoch+2,old.checkpoint_lsn+3)]{
            assert_eq!(probe_snapshot_media_pair(&a,&bad),Err(Error::Conflict));
        }
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
    fn receipt_canonical_local_identity_and_unbound_cancel_shape() {
        let mut b=receipt();
        b[96..98].copy_from_slice(&6u16.to_le_bytes());
        let reseal=|b:&mut [u8;RECEIPT_BYTES]| {
            let crc=crc32c_zeroed(b,188).unwrap();
            b[188..192].copy_from_slice(&crc.to_le_bytes());
        };
        reseal(&mut b);
        assert_eq!(FileReceiptV4::decode(&b).unwrap().status,6);
        let cancelled=b;
        for at in [64usize,72,80,88,100,104,140,172] {
            b=cancelled;b[at]^=1;reseal(&mut b);
            assert!(FileReceiptV4::decode(&b).is_err(),"offset {at}");
        }
        b=cancelled;b[96..98].copy_from_slice(&2u16.to_le_bytes());
        reseal(&mut b);assert!(FileReceiptV4::decode(&b).is_err());
        b[108]=1;reseal(&mut b);assert!(FileReceiptV4::decode(&b).is_ok());
        b[64]=1;reseal(&mut b);assert!(FileReceiptV4::decode(&b).is_err());
        b[72]=1;b[80]=1;reseal(&mut b);assert!(FileReceiptV4::decode(&b).is_ok());
        assert_eq!(local_request_id(15,7,MAX_REQUEST_SEQ),Some((16u64<<56)|(7u64<<53)|MAX_REQUEST_SEQ));
        assert_eq!(local_request_id(16,0,1),None);
        assert_eq!(local_request_id(0,8,1),None);
        assert_eq!(local_request_id(0,0,0),None);
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
