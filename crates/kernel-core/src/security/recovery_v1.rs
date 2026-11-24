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
fn no_current_suffix(io:&mut impl EpochBlockIo,from:u32,epoch:u64,raw:&mut[u8;2*BLOCK])->Result<(),Error>{
    for block in from..END{
        let head:&mut[u8;BLOCK]=(&mut raw[..BLOCK]).try_into().unwrap();
        io.read(block,head)?;
        if u32at(head,0)==MAGIC&&u64at(head,32)>=epoch{return Err(Error::Conflict);}
    }
    Ok(())
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
    let sb=preflight_baseline_checkpoint(&w.first,&w.second,&mut w.raw,|b,out|io.read(b,out))?;
    w.selected=if SuperblockV1::decode(&w.first)?==sb{0}else{1};
    let mut at=FIRST;let mut last=sb.checkpoint_lsn;let mut last_tx=0u64;
    let mut transactions=0u32;let mut incomplete=false;
    'chain:while at<END{
        let Some(begin)=current_record(io,at,sb.log_epoch,&mut w.raw)?else{
            no_current_suffix(io,at+1,sb.log_epoch,&mut w.raw)?;break;
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
                no_current_suffix(io,pos+1,sb.log_epoch,&mut w.raw)?;incomplete=true;break 'chain;
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
            no_current_suffix(io,commit_at+1,sb.log_epoch,&mut w.raw)?;incomplete=true;break;
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
