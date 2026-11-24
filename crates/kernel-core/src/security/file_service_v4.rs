//! V0.19.9 FileServiceRequest v4 and Reply v3 strict, bounded LE contracts.
//! This is not the legacy FileService ABI, does not mount or rewrite v2 disks,
//! and does not authorize file operations. The native EL1 caller must perform
//! credential/capability/ACL/admission checks before invoking a real file TCB.
use super::Error;
pub const REQUEST_MAGIC:u32=0x4359_4651;
pub const REQUEST_VERSION:u16=4;
pub const REQUEST_HEADER:usize=32;
pub const MAX_REQUEST:usize=65_580;
pub const REPLY_MAGIC:u32=0x4359_4652;
pub const REPLY_VERSION:u16=3;
pub const REPLY_HEADER:usize=128;
pub const MAX_REPLY:usize=65_664;
pub const MAX_IO_BYTES:usize=65_536;
pub const MAX_NAME_BYTES:usize=63;

fn le16(b:&[u8],at:usize)->Result<u16,Error>{
    let s=b.get(at..at+2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([s[0],s[1]]))
}
fn le32(b:&[u8],at:usize)->Result<u32,Error>{
    let s=b.get(at..at+4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0],s[1],s[2],s[3]]))
}
fn le64(b:&[u8],at:usize)->Result<u64,Error>{
    let s=b.get(at..at+8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]]))
}
pub const fn persistent_op(op:u16)->bool {matches!(op,1|5|7|9)}
pub const fn no_cap_selector(op:u16)->bool {matches!(op,10|11|12|13|14|15)}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Request<'a>{
    pub op:u16,
    pub request_id:u64,
    pub payload:&'a [u8],
}
impl<'a> Request<'a>{
    /// cap_selector is supplied as the independently checked syscall x3,
    /// NOT as a field the file TCB may trust without an EL1 cap lookup.
    pub fn decode(frame:&'a[u8],cap_selector:u64)->Result<Self,Error>{
        if frame.len()<REQUEST_HEADER || frame.len()>MAX_REQUEST
            || le32(frame,0)?!=REQUEST_MAGIC || le16(frame,4)?!=REQUEST_VERSION
            || le16(frame,6)?!=REQUEST_HEADER as u16
            || !(1..=15).contains(&le16(frame,8)?)
            || le16(frame,10)?!=0
            || le64(frame,24)?!=0 // auth_context_id is internal EL1-only
        {return Err(Error::Invalid);}
        let op=le16(frame,8)?;
        let payload_len=usize::try_from(le32(frame,12)?).map_err(|_|Error::Invalid)?;
        if REQUEST_HEADER.checked_add(payload_len)!=Some(frame.len())
            || (no_cap_selector(op) && cap_selector!=0)
            || (!no_cap_selector(op) && cap_selector==0)
        {return Err(Error::Unauthorized);}
        let req_id=le64(frame,16)?;
        if (op==10 && req_id!=0) || (op!=10 && req_id==0)
        {return Err(Error::Invalid);}
        let payload=&frame[REQUEST_HEADER..];
        let valid=match op{
            1|2|7=>{
                // name_len:u16 + exact name + requested_rights:u32 + flags:u32=0
                let n=usize::from(le16(payload,0)?);
                n>0 && n<=MAX_NAME_BYTES && payload.len()==n+10
                    && le32(payload,n+6)?==0
                    && !payload[2..n+2].iter().any(|c|*c==0||*c==b'/')
            }
            3=>{
                payload.len()==12
                    && le32(payload,8)? as usize<=MAX_IO_BYTES
            }
            4=>{
                let len=usize::try_from(le32(payload,8)?).map_err(|_|Error::Invalid)?;
                len<=MAX_IO_BYTES && 12usize.checked_add(len)==Some(payload.len())
            }
            5=>payload.len()==8 && le64(payload,0)?>0,
            6=>payload.len()==4 && le32(payload,0)?==0,
            8=>payload.len()==8 && {
                let limit=le16(payload,4)?;
                limit>=1 && limit<=16 && le16(payload,6)?==0
            },
            9=>{
                let n=usize::from(le16(payload,0)?);
                n>0 && n<=MAX_NAME_BYTES && payload.len()==n+6
                    && le32(payload,n+2)?==0
                    && !payload[2..n+2].iter().any(|c|*c==0||*c==b'/')
            }
            10=>payload.len()==16 && payload[0]<8
                && payload[1..8].iter().all(|x|*x==0)
                && le64(payload,8)?>0,
            11|13=>payload.len()==56,
            12=>payload.len()==88,
            14=>payload.len()==24 && le64(payload,16)?==req_id,
            15=>payload.len()==56 && le64(payload,16)?==req_id,
            _=>false,
        };
        if !valid{return Err(Error::Invalid);}
        Ok(Self{op,request_id:req_id,payload})
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Reply<'a>{
    pub request_id:u64,
    pub service_generation:u64,
    pub state:u16,
    pub result:i32,
    pub completed_prefix:u32,
    pub commit_lsn:u64,
    pub log_epoch:u64,
    pub txid:u64,
    pub new_cap_selector:u64,
    pub target_generation:u64,
    pub result_digest:[u8;32],
    pub receipt_ref:u64,
    pub write_seq:u64,
    pub output:&'a [u8],
}
impl<'a> Reply<'a>{
    pub fn decode(frame:&'a[u8])->Result<Self,Error>{
        if frame.len()<REPLY_HEADER || frame.len()>MAX_REPLY
            || le32(frame,0)?!=REPLY_MAGIC
            || le16(frame,4)?!=REPLY_VERSION
            || le16(frame,6)?!=REPLY_HEADER as u16
            || le16(frame,26)?!=0
        {return Err(Error::Invalid);}
        let n=usize::try_from(le32(frame,36)?).map_err(|_|Error::Invalid)?;
        if REPLY_HEADER.checked_add(n)!=Some(frame.len()){return Err(Error::Invalid);}
        let state=le16(frame,24)?;
        let result=le32(frame,28)? as i32;
        if state>6 || le64(frame,16)?==0
            || (state==5 && result==0) // UNKNOWN must not advertise success
        {return Err(Error::Invalid);}
        let mut digest=[0u8;32];
        digest.copy_from_slice(&frame[80..112]);
        Ok(Self {
            request_id:le64(frame,8)?,
            service_generation:le64(frame,16)?,
            state,result,
            completed_prefix:le32(frame,32)?,
            commit_lsn:le64(frame,40)?,
            log_epoch:le64(frame,48)?,
            txid:le64(frame,56)?,
            new_cap_selector:le64(frame,64)?,
            target_generation:le64(frame,72)?,
            result_digest:digest,
            receipt_ref:le64(frame,112)?,
            write_seq:le64(frame,120)?,
            output:&frame[REPLY_HEADER..],
        })
    }
}

#[cfg(test)]
mod tests{
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;
    fn request(op:u16,payload:&[u8],id:u64)->Vec<u8>{
        let mut b=vec![0u8;REQUEST_HEADER+payload.len()];
        b[0..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(REQUEST_HEADER as u16).to_le_bytes());
        b[8..10].copy_from_slice(&op.to_le_bytes());
        b[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        b[16..24].copy_from_slice(&id.to_le_bytes());
        b[REQUEST_HEADER..].copy_from_slice(payload);
        b
    }
    #[test]
    fn file_v4_exact_15_ops_and_reject_old_header(){
        let mut create=vec![1u8,0u8,b'a'];
        create.extend_from_slice(&1u32.to_le_bytes());
        create.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(Request::decode(&request(1,&create,4),123).unwrap().op,1);
        assert!(Request::decode(&request(1,&create,4),0).is_err());
        let mut old=request(1,&create,4);old[4]=3;
        assert!(Request::decode(&old,123).is_err());
        old=request(1,&create,4);old[24]=1;
        assert!(Request::decode(&old,123).is_err());
        old=request(1,&create,4);old[12]=0;
        assert!(Request::decode(&old,123).is_err());
        old=request(16,&create,4);
        assert!(Request::decode(&old,123).is_err());
        for op in [1u16,2,7]{
            assert!(Request::decode(&request(op,&create,4),123).is_ok());
        }
        let mut unlink=vec![1u8,0u8,b'a'];
        unlink.extend_from_slice(&0u32.to_le_bytes());
        assert!(Request::decode(&request(9,&unlink,4),123).is_ok());
        let empty=[0u8;4];
        assert!(Request::decode(&request(6,&empty,4),123).is_ok());
        for op in [11u16,13]{assert!(Request::decode(&request(op,&[0;56],4),0).is_ok());}
        for op in [12u16]{assert!(Request::decode(&request(op,&[0;88],4),0).is_ok());}
    }
    #[test]
    fn file_read_write_limits_and_wrong_source_rejected(){
        let mut read=[0u8;12];
        read[8..12].copy_from_slice(&(MAX_IO_BYTES as u32).to_le_bytes());
        assert!(Request::decode(&request(3,&read,1),7).is_ok());
        let mut write=vec![0u8;12+MAX_IO_BYTES];
        write[8..12].copy_from_slice(&(MAX_IO_BYTES as u32).to_le_bytes());
        assert_eq!(request(4,&write,1).len(),MAX_REQUEST);
        assert!(Request::decode(&request(4,&write,1),7).is_ok());
        write[8..12].copy_from_slice(&((MAX_IO_BYTES+1) as u32).to_le_bytes());
        assert!(Request::decode(&request(4,&write,1),7).is_err());
        let mut alloc=[0u8;16];alloc[0]=7;alloc[8]=1;
        assert!(Request::decode(&request(10,&alloc,0),0).is_ok());
        alloc[0]=8;assert!(Request::decode(&request(10,&alloc,0),0).is_err());
        let mut query=[0u8;24];query[16]=7;
        assert!(Request::decode(&request(14,&query,7),0).is_ok());
        assert!(Request::decode(&request(14,&query,8),0).is_err());
    }
    #[test]
    fn reply_v3_does_not_invent_durability(){
        let mut b=[0u8;128];
        b[0..4].copy_from_slice(&REPLY_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&REPLY_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(REPLY_HEADER as u16).to_le_bytes());
        b[16..24].copy_from_slice(&5u64.to_le_bytes());
        b[24..26].copy_from_slice(&5u16.to_le_bytes());
        b[28..32].copy_from_slice(&(-1i32).to_le_bytes());
        assert_eq!(Reply::decode(&b).unwrap().state,5);
        b[28..32].copy_from_slice(&0i32.to_le_bytes());
        assert!(Reply::decode(&b).is_err());
        b[4]=2;assert!(Reply::decode(&b).is_err());
    }
}
