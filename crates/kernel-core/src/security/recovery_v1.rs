//! Baseline-v1 mount recovery, §9.3–9.5. No allocations or new wire ABI.
//! The mounted-device owner must exclude all other writers throughout scan,
//! replay, post-replay structural/system validation and checkpoint. A
//! successful scan is not a mount. No ordinary service opens on an I/O
//! error, an ambiguous record, or a failed structural/ACL validation.
use super::{Error,epoch_redo_v0199::EpochBlockIo,file_media_v0199::{
    SUPER_BYTES as BLOCK,BITMAP_START,BLOCK_COUNT,SuperblockV1,crc32c_payload,
    crc32c_zeroed,preflight_baseline_checkpoint}};
use sha2::{Digest,Sha256};

const FIRST:u32=2;
const END:u32=4098;
const MAX_REDO:usize=128;
// Each REDO occupies two physical blocks. Includes metadata afterimages.
const MAX_HOME:usize=((END-FIRST)/2) as usize;
const MAGIC:u32=0x43594c47;
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
struct Header{kind:u16,txid:u64,lsn:u64,epoch:u64}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
struct Row{home:u32,log:u32,commit_lsn:u64,digest:[u8;32]}
const EMPTY:Row=Row{home:0,log:0,commit_lsn:0,digest:[0;32]};
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct RecoveryEvidence{
    pub superblock:SuperblockV1,pub last_commit_lsn:u64,
    pub transactions:u32,pub distinct_home_blocks:u32,pub incomplete_tail:bool,
}
pub struct RecoveryWorkspace{
    rows:[Row;MAX_HOME],pending:[Row;MAX_REDO],count:usize,
    raw:[u8;2*BLOCK],first:[u8;BLOCK],second:[u8;BLOCK],
    evidence:Option<RecoveryEvidence>,selected:u32,
}
impl RecoveryWorkspace{
    pub const fn new()->Self{Self{rows:[EMPTY;MAX_HOME],pending:[EMPTY;MAX_REDO],count:0,
        raw:[0;2*BLOCK],first:[0;BLOCK],second:[0;BLOCK],evidence:None,selected:0}}
    pub fn evidence(&self)->Option<RecoveryEvidence>{self.evidence}
}
const _:()=assert!(core::mem::size_of::<RecoveryWorkspace>()<128*1024);
fn u16at(b:&[u8],i:usize)->u16{u16::from_le_bytes(b[i..i+2].try_into().unwrap())}
fn u32at(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}
fn u64at(b:&[u8],i:usize)->u64{u64::from_le_bytes(b[i..i+8].try_into().unwrap())}
fn hash(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn read_record(io:&mut impl EpochBlockIo,block:u32,raw:&mut[u8;2*BLOCK])
    ->Result<Option<Header>,Error>{
    if !(FIRST..END).contains(&block){return Ok(None);}
    let (left,right)=raw.split_at_mut(BLOCK);
    io.read(block,left.try_into().map_err(|_|Error::Invalid)?)?;
    if u32at(left,0)!=MAGIC{return Ok(None);}
    let kind=u16at(left,6);
    let (length,padded)=match kind{1=>(80,4096),2=>(4160,8192),3=>(128,4096),_=>return Err(Error::Unknown)};
    let h=Header{kind,txid:u64at(left,16),lsn:u64at(left,24),epoch:u64at(left,32)};
    if u16at(left,4)!=1||u32at(left,8) as usize!=length||h.txid==0||h.lsn==0||h.epoch==0
        ||u32at(left,60)!=0||u32at(left,56)!=crc32c_zeroed(&left[..64],56)?
        ||kind!=2&&left[40..56].iter().any(|&v|v!=0){return Err(Error::Unknown);}
    if kind==2{
        if block+1>=END{return Err(Error::Unknown);}
        io.read(block+1,right.try_into().map_err(|_|Error::Invalid)?)?;
    }
    if u32at(raw,12)!=crc32c_payload(&raw[64..length])
        ||raw[length..padded].iter().any(|&v|v!=0){return Err(Error::Unknown);}
    Ok(Some(h))
}
/// A clean/truncated suffix may contain old-epoch residue, but no later
/// selected-epoch record. A malformed aligned candidate fails conservatively
/// in the independent full-area preflight; never infer missing high epochs.
fn no_current_suffix(from:u32,last_current:u32)->Result<(),Error>{
    if last_current>=from{return Err(Error::Conflict);}Ok(())
}
fn current_record(io:&mut impl EpochBlockIo,block:u32,epoch:u64,raw:&mut[u8;2*BLOCK])
    ->Result<Option<Header>,Error>{
    match read_record(io,block,raw)?{
        Some(h) if h.epoch==epoch=>Ok(Some(h)),
        Some(h) if h.epoch>epoch=>Err(Error::Conflict),
        _=>Ok(None),
    }
}
/// Preflight both superblocks and the entire log, then validate a contiguous
/// current-epoch committed prefix. Merge by greatest COMMIT LSN, not physical
/// device completion order. No home or superblock writes occur here.
pub fn scan(io:&mut impl EpochBlockIo,w:&mut RecoveryWorkspace)->Result<RecoveryEvidence,Error>{
    w.evidence=None;w.count=0;
    io.read(0,&mut w.first)?;io.read(1,&mut w.second)?;
    let epoch=super::file_media_v0199::probe_snapshot_media_pair(&w.first,&w.second)?.log_epoch;
    let mut last_current=0u32;
    // Track aligned current-epoch header candidates during the mandatory
    // full area scan. Avoid rescanning 4096 blocks after an empty suffix.
    let sb=preflight_baseline_checkpoint(&w.first,&w.second,&mut w.raw,|b,out|{
        io.read(b,out)?;
        if u32at(out,0)==MAGIC&&u64at(out,32)==epoch{last_current=last_current.max(b);}
        Ok(())
    })?;
    w.selected=if SuperblockV1::decode(&w.first)?==sb{0}else{1};
    let mut at=FIRST;let mut last=sb.checkpoint_lsn;let mut last_tx=0u64;
    let mut transactions=0u32;let mut incomplete=false;
    'chain:while at<END{
        let Some(begin)=current_record(io,at,sb.log_epoch,&mut w.raw)?else{
            no_current_suffix(at+1,last_current)?;break;
        };
        if begin.kind!=1||begin.txid<=last_tx||last.checked_add(1)!=Some(begin.lsn){return Err(Error::Conflict);}
        let n=u32at(&w.raw,64) as usize;
        if !(1..=MAX_REDO).contains(&n)||u32at(&w.raw,68)!=0
            ||u64at(&w.raw,72)!=n as u64*BLOCK as u64{return Err(Error::Conflict);}
        let commit_at=at.checked_add(1+2*n as u32).ok_or(Error::Invalid)?;
        if commit_at>=END{return Err(Error::Conflict);}
        let mut ordered=Sha256::new();
        for i in 0..n{
            let pos=at+1+2*i as u32;
            let Some(redo)=current_record(io,pos,sb.log_epoch,&mut w.raw)?else{
                no_current_suffix(pos+1,last_current)?;incomplete=true;break 'chain;
            };
            if redo.kind!=2||redo.txid!=begin.txid||begin.lsn.checked_add(i as u64+1)!=Some(redo.lsn)
                ||u32at(&w.raw,48)!=i as u32||u32at(&w.raw,52)!=n as u32{return Err(Error::Conflict);}
            let home=u32::try_from(u64at(&w.raw,40)).map_err(|_|Error::Invalid)?;
            if !(BITMAP_START..BLOCK_COUNT).contains(&home)||w.pending[..i].iter().any(|r|r.home==home){
                return Err(Error::Conflict);
            }
            ordered.update(u64::from(home).to_le_bytes());ordered.update(&w.raw[64..4160]);
            w.pending[i]=Row{home,log:pos,commit_lsn:0,digest:hash(&w.raw)};
        }
        let Some(commit)=current_record(io,commit_at,sb.log_epoch,&mut w.raw)?else{
            no_current_suffix(commit_at+1,last_current)?;incomplete=true;break;
        };
        let digest:[u8;32]=ordered.finalize().into();
        if commit.kind!=3||commit.txid!=begin.txid||begin.lsn.checked_add(n as u64+1)!=Some(commit.lsn)
            ||u64at(&w.raw,64)!=begin.txid||u64at(&w.raw,72)!=begin.lsn
            ||u64at(&w.raw,80)!=commit.lsn-1||u32at(&w.raw,88)!=n as u32||u32at(&w.raw,92)!=0
            ||w.raw[96..128]!=digest{return Err(Error::Conflict);}
        for row in &mut w.pending[..n]{
            row.commit_lsn=commit.lsn;
            if let Some(old)=w.rows[..w.count].iter_mut().find(|r|r.home==row.home){*old=*row;}
            else{
                if w.count>=MAX_HOME{return Err(Error::Capacity);}
                w.rows[w.count]=*row;w.count+=1;
            }
        }
        last=commit.lsn;last_tx=commit.txid;transactions+=1;at=commit_at+1;
    }
    let e=RecoveryEvidence{superblock:sb,last_commit_lsn:last,transactions,
        distinct_home_blocks:w.count as u32,incomplete_tail:incomplete};
    w.evidence=Some(e);Ok(e)
}
fn same_superblocks(io:&mut impl EpochBlockIo,w:&mut RecoveryWorkspace)->Result<(),Error>{
    let out:&mut[u8;BLOCK]=(&mut w.raw[..BLOCK]).try_into().unwrap();
    io.read(0,out)?;if *out!=w.first{return Err(Error::Conflict);}
    io.read(1,out)?;if *out!=w.second{return Err(Error::Conflict);}
    Ok(())
}
fn read_exact_image(io:&mut impl EpochBlockIo,row:Row,epoch:u64,raw:&mut[u8;2*BLOCK])->Result<(),Error>{
    let h=read_record(io,row.log,raw)?.ok_or(Error::Conflict)?;
    if h.kind!=2||h.epoch!=epoch||u64at(raw,40)!=u64::from(row.home)||hash(raw)!=row.digest{
        return Err(Error::Conflict);
    }
    Ok(())
}
/// Idempotent home replay while old checkpoint remains selected. Preflight
/// all retained afterimages before first write, then verify again on use.
/// Any I/O uncertainty leaves the old log authoritative. Caller's exclusive
/// I/O ownership is mandatory; no native concurrency assumed in this module.
pub fn replay_home(io:&mut impl EpochBlockIo,w:&mut RecoveryWorkspace)->Result<RecoveryEvidence,Error>{
    let e=w.evidence.ok_or(Error::Busy)?;
    same_superblocks(io,w)?;
    for i in 0..w.count{read_exact_image(io,w.rows[i],e.superblock.log_epoch,&mut w.raw)?;}
    for i in 0..w.count{
        let row=w.rows[i];
        read_exact_image(io,row,e.superblock.log_epoch,&mut w.raw).map_err(|_|Error::Unknown)?;
        io.write(row.home,w.raw[64..4160].try_into().unwrap()).map_err(|_|Error::Unknown)?;
    }
    io.flush().map_err(|_|Error::Unknown)?;
    // Native readback is not a substitute for FLUSH; verify both.
    for i in 0..w.count{
        let row=w.rows[i];
        read_exact_image(io,row,e.superblock.log_epoch,&mut w.raw).map_err(|_|Error::Unknown)?;
        let expected=hash(&w.raw[64..4160]);
        let out:&mut[u8;BLOCK]=(&mut w.raw[..BLOCK]).try_into().unwrap();
        io.read(row.home,out).map_err(|_|Error::Unknown)?;
        if hash(out)!=expected{return Err(Error::Unknown);}
    }
    Ok(e)
}
/// Complete mount recovery under one exclusive file owner. Verify the
/// actual post-replay filesystem structure and protected system/ACL state
/// before advancing the noncurrent superblock. The returned checkpoint is
/// not authority to issue capabilities: the native startup owner verifies
/// the signed config and durable BootEpoch separately.
pub fn recover_checkpoint<I:EpochBlockIo>(io:&mut I,w:&mut RecoveryWorkspace,
    verify_post_replay:impl FnOnce(&mut I,SuperblockV1)->Result<(),Error>)
    ->Result<SuperblockV1,Error>{
    let e=scan(io,w)?;
    let next=SuperblockV1{fs_uuid:e.superblock.fs_uuid,
        generation:e.superblock.generation.checked_add(1).ok_or(Error::Exhausted)?,
        checkpoint_lsn:e.last_commit_lsn,
        log_epoch:e.superblock.log_epoch.checked_add(1).ok_or(Error::Exhausted)?};
    replay_home(io,w)?;
    verify_post_replay(io,e.superblock)?;
    same_superblocks(io,w)?;
    // Exact canonical v1 bytes; no format migration or old-log overwrite.
    let out:&mut[u8;BLOCK]=(&mut w.raw[..BLOCK]).try_into().unwrap();
    *out=if w.selected==0{w.first}else{w.second};
    out[32..40].copy_from_slice(&next.generation.to_le_bytes());
    out[40..48].copy_from_slice(&next.checkpoint_lsn.to_le_bytes());
    out[48..56].copy_from_slice(&next.log_epoch.to_le_bytes());
    let crc=crc32c_zeroed(out,76)?;out[76..80].copy_from_slice(&crc.to_le_bytes());
    if SuperblockV1::decode(out)?!=next{return Err(Error::Conflict);}
    let dest=1-w.selected;
    io.write(dest,out).map_err(|_|Error::Unknown)?;
    io.flush().map_err(|_|Error::Unknown)?;
    io.read(dest,out).map_err(|_|Error::Unknown)?;
    if SuperblockV1::decode(out).map_err(|_|Error::Unknown)?!=next{return Err(Error::Unknown);}
    w.evidence=None;
    Ok(next)
}

#[cfg(test)]
mod tests{
    extern crate std;
    use super::*;
    use std::{boxed::Box,collections::BTreeMap,vec::Vec};
    #[derive(Default)]
    struct Disk{blocks:BTreeMap<u32,Box<[u8;BLOCK]>>,events:Vec<u32>,flushes:u32,fail_flush:u32}
    impl EpochBlockIo for Disk{
        fn read(&mut self,block:u32,out:&mut[u8;BLOCK])->Result<(),Error>{
            if let Some(b)=self.blocks.get(&block){*out=**b;}else{out.fill(0);}Ok(())
        }
        fn write(&mut self,block:u32,data:&[u8;BLOCK])->Result<(),Error>{
            self.events.push(block);self.blocks.insert(block,Box::new(*data));Ok(())
        }
        fn flush(&mut self)->Result<(),Error>{
            self.events.push(u32::MAX);self.flushes+=1;
            if self.flushes==self.fail_flush{return Err(Error::Unknown);}Ok(())
        }
    }
    fn p16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
    fn p32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
    fn p64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
    fn superblock()->[u8;BLOCK]{
        let mut b=[0;BLOCK];p32(&mut b,0,0x43594653);p16(&mut b,4,1);p16(&mut b,6,80);
        p32(&mut b,8,4096);p32(&mut b,12,131072);b[16..32].fill(1);
        p64(&mut b,32,1);p64(&mut b,48,1);p32(&mut b,56,4098);p32(&mut b,60,4102);
        p32(&mut b,64,4118);p32(&mut b,68,256);let c=crc32c_zeroed(&b,76).unwrap();p32(&mut b,76,c);b
    }
    fn seal(b:&mut[u8],kind:u16,len:usize,txid:u64,lsn:u64){
        p32(b,0,MAGIC);p16(b,4,1);p16(b,6,kind);p32(b,8,len as u32);
        p64(b,16,txid);p64(b,24,lsn);p64(b,32,1);
        let c=crc32c_payload(&b[64..len]);p32(b,12,c);
        let c=crc32c_zeroed(&b[..64],56).unwrap();p32(b,56,c);
    }
    fn append(d:&mut Disk,first:u32,txid:u64,lsn:u64,images:&[(u32,u8)],committed:bool)->u32{
        let n=images.len();
        let mut b=[0;BLOCK];p32(&mut b,64,n as u32);p64(&mut b,72,n as u64*BLOCK as u64);
        seal(&mut b,1,80,txid,lsn);d.blocks.insert(first,Box::new(b));
        let mut digest=Sha256::new();
        for(i,&(home,value))in images.iter().enumerate(){
            let mut raw=[0;2*BLOCK];p64(&mut raw,40,u64::from(home));p32(&mut raw,48,i as u32);p32(&mut raw,52,n as u32);
            raw[64..4160].fill(value);
            digest.update(u64::from(home).to_le_bytes());digest.update(&raw[64..4160]);
            seal(&mut raw,2,4160,txid,lsn+i as u64+1);
            d.blocks.insert(first+1+2*i as u32,Box::new(raw[..BLOCK].try_into().unwrap()));
            d.blocks.insert(first+2+2*i as u32,Box::new(raw[BLOCK..].try_into().unwrap()));
        }
        let at=first+1+2*n as u32;
        if committed{
            let mut c=[0;BLOCK];p64(&mut c,64,txid);p64(&mut c,72,lsn);
            p64(&mut c,80,lsn+n as u64);p32(&mut c,88,n as u32);
            c[96..128].copy_from_slice(&digest.finalize());
            seal(&mut c,3,128,txid,lsn+n as u64+1);
            d.blocks.insert(at,Box::new(c));
        }
        at+1
    }
    fn disk()->Disk{
        let mut d=Disk::default();d.blocks.insert(0,Box::new(superblock()));d.blocks.insert(1,Box::new(superblock()));
        let next=append(&mut d,2,1,1,&[(7000,1)],true);
        let next=append(&mut d,next,2,4,&[(7000,2),(7001,3)],true);
        append(&mut d,next,3,8,&[(7001,4)],false);
        d
    }
    #[test]
    fn highest_committed_afterimage_once_then_flush_validate_and_checkpoint(){
        let mut d=disk();let mut w=RecoveryWorkspace::new();
        let e=scan(&mut d,&mut w).unwrap();
        assert_eq!((e.transactions,e.last_commit_lsn,e.distinct_home_blocks,e.incomplete_tail),(2,7,2,true));
        let next=recover_checkpoint(&mut d,&mut w,|io,_|{
            assert_eq!(&io.events[..],&[7000,7001,u32::MAX]);
            assert!(io.blocks[&7000].iter().all(|&v|v==2));
            assert!(io.blocks[&7001].iter().all(|&v|v==3));
            Ok(())
        }).unwrap();
        assert_eq!((next.generation,next.log_epoch,next.checkpoint_lsn),(2,2,7));
        assert_eq!(&d.events[..],&[7000,7001,u32::MAX,1,u32::MAX]);
        // Old incomplete records remain physically present; a fresh
        // scan of the new checkpoint ignores the now older epoch.
        assert_eq!(scan(&mut d,&mut w).unwrap().transactions,0);
    }
    #[test]
    fn holes_and_flush_failure_cannot_advance_checkpoint(){
        let mut w=RecoveryWorkspace::new();let mut broken=disk();
        // Remove the second transaction's first REDO header while its
        // later commit remains. This is not a harmless truncated tail.
        broken.blocks.remove(&7);
        assert!(scan(&mut broken,&mut w).is_err());
        assert!(broken.events.is_empty());assert_eq!(replay_home(&mut broken,&mut w),Err(Error::Busy));
        let mut d=disk();d.fail_flush=1;
        assert_eq!(recover_checkpoint(&mut d,&mut w,|_,_|panic!("home not flushed")),Err(Error::Unknown));
        assert!(!d.events.contains(&1));
        assert_eq!(SuperblockV1::decode(&*d.blocks[&1]).unwrap().generation,1);
        d.fail_flush=0;d.events.clear();
        assert_eq!(recover_checkpoint(&mut d,&mut w,|_,_|Err(Error::Unauthorized)),Err(Error::Unauthorized));
        assert!(!d.events.contains(&1));
        d.events.clear();
        assert_eq!(recover_checkpoint(&mut d,&mut w,|_,_|Ok(())).unwrap().generation,2);
    }
}
