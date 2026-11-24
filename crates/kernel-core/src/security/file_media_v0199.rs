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
/// Reflected CRC32C (Castagnoli); the stored crc32c field itself reads zero.
pub fn crc32c_zeroed(bytes:&[u8],offset:usize)->Result<u32,Error>{
    if offset.checked_add(4).is_none_or(|e|e>bytes.len()) {
        return Err(Error::Invalid);
    }
    let mut crc=!0u32;
    for (i,&value) in bytes.iter().enumerate(){
        let byte=if (offset..offset+4).contains(&i){0}else{value};
        crc^=u32::from(byte);
        for _ in 0..8 {
            crc=(crc>>1) ^ (if crc&1!=0{0x82f6_3b78}else{0});
        }
    }
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
