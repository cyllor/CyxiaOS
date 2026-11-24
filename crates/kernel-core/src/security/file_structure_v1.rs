//! Baseline-v1 filesystem structural mount scan, V0.19.9 §9.2.1/9.5.
//! Caller holds the actual serialized post-replay volume view, not raw
//! untrusted EL0 bytes. This scans every inode, every live directory entry,
//! and the entire allocation bitmap. A pass is not a writable mount:
//! ACL/system payloads and actual durable checkpoint must also be verified.
use super::{Error,file_media_v0199::{crc32c_zeroed,SuperblockV1,DATA_START,BLOCK_COUNT,BITMAP_START,INODE_START}};
pub const BLOCK:usize=4096;
pub const INODES:usize=256;
pub const INODE_BYTES:usize=256;
const MAX_EXTENTS:usize=16;
const BITMAP_BYTES:usize=BLOCK_COUNT as usize/8;
const MAX_FILE:u64=8*1024*1024;
const MAX_DIR:u64=256*128;
fn u16at(b:&[u8],i:usize)->u16{u16::from_le_bytes(b[i..i+2].try_into().unwrap())}
fn u32at(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}
fn u64at(b:&[u8],i:usize)->u64{u64::from_le_bytes(b[i..i+8].try_into().unwrap())}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Extent{pub logical:u32,pub physical:u32,pub count:u32}
const EMPTY_EXTENT:Extent=Extent{logical:0,physical:0,count:0};
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Inode{
    pub kind:u16,pub generation:u64,pub size:u64,pub durable_write_seq:u64,
    pub parent:u32,pub parent_generation:u64,pub extents:u16,pub runs:[Extent;MAX_EXTENTS],
}
const EMPTY:Inode=Inode{kind:0,generation:0,size:0,durable_write_seq:0,parent:0,
    parent_generation:0,extents:0,runs:[EMPTY_EXTENT;MAX_EXTENTS]};
impl Inode{
    pub fn decode(b:&[u8])->Result<Self,Error>{
        if b.len()!=INODE_BYTES||u32at(b,0)!=0x4359494e||u16at(b,6)!=0
            ||u16at(b,34)!=0||b[240..252].iter().any(|&v|v!=0)
            ||u32at(b,252)!=crc32c_zeroed(b,252)?{return Err(Error::Invalid);}
        let kind=u16at(b,4);let generation=u64at(b,8);
        if kind==0{
            if b[16..252].iter().any(|&v|v!=0){return Err(Error::Invalid);}
            return Ok(Inode{generation,..EMPTY});
        }
        let size=u64at(b,16);let n=u16at(b,32);
        if !matches!(kind,1|2)||generation==0||size>MAX_FILE
            ||kind==2&&(size>MAX_DIR||size%128!=0)||usize::from(n)>MAX_EXTENTS
            ||u32at(b,36)>=INODES as u32||u64at(b,40)==0{return Err(Error::Invalid);}
        let mut runs=[EMPTY_EXTENT;MAX_EXTENTS];let mut covered=0u32;
        for (i,run) in runs.iter_mut().enumerate(){
            let at=48+i*12;let r=Extent{logical:u32at(b,at),physical:u32at(b,at+4),count:u32at(b,at+8)};
            if i>=usize::from(n){
                if r!=EMPTY_EXTENT{return Err(Error::Invalid);}
                continue;
            }
            if r.logical!=covered||r.count==0||r.physical<DATA_START
                ||r.physical.checked_add(r.count).is_none_or(|v|v>BLOCK_COUNT){
                return Err(Error::Invalid);
            }
            covered=covered.checked_add(r.count).ok_or(Error::Invalid)?;
            *run=r;
        }
        if u64::from(covered)!=size.div_ceil(BLOCK as u64){return Err(Error::Invalid);}
        Ok(Self{kind,generation,size,durable_write_seq:u64at(b,24),parent:u32at(b,36),
            parent_generation:u64at(b,40),extents:n,runs})
    }
    fn physical(&self,logical:u32)->Result<u32,Error>{
        for r in &self.runs[..usize::from(self.extents)]{
            if logical>=r.logical&&logical-r.logical<r.count{return Ok(r.physical+logical-r.logical);}
        }
        Err(Error::Invalid)
    }
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum SystemKind{BootEpoch,Receipts,Acl,Security}
impl SystemKind{fn blocks(self)->u32{match self{Self::BootEpoch|Self::Security=>1,Self::Receipts=>7,Self::Acl=>4}}}
/// Exact locations from independently authenticated boot catalog, never
/// guessed from old snapshot-v2 offsets or passed by ordinary FileCap.
#[derive(Clone,Copy)]
pub struct SystemObject{pub kind:SystemKind,pub inode:u16,pub generation:u64,pub first_block:u32}
#[derive(Clone,Copy)]
struct Name{len:u8,bytes:[u8;63]}
const EMPTY_NAME:Name=Name{len:0,bytes:[0;63]};
pub struct Workspace{
    inodes:[Inode;INODES],bitmap:[u8;BITMAP_BYTES],owned:[u8;BITMAP_BYTES],
    references:[u8;INODES],names:[Name;INODES],block:[u8;BLOCK],
}
impl Workspace{pub const fn new()->Self{
    Self{inodes:[EMPTY;INODES],bitmap:[0;BITMAP_BYTES],owned:[0;BITMAP_BYTES],
        references:[0;INODES],names:[EMPTY_NAME;INODES],block:[0;BLOCK]}
}}
const _:()=assert!(core::mem::size_of::<Workspace>()<=128*1024);
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct StructureEvidence{pub live_inodes:u16,pub data_blocks:u32,pub directory_entries:u32}
fn mark(bits:&mut[u8;BITMAP_BYTES],block:u32)->Result<(),Error>{
    if block>=BLOCK_COUNT{return Err(Error::Invalid);}
    let at=(block/8) as usize;let bit=1u8<<(block%8);
    if bits[at]&bit!=0{return Err(Error::Conflict);}
    bits[at]|=bit;Ok(())
}
fn is_system(id:usize,system:&[SystemObject;4])->bool{system.iter().any(|v|usize::from(v.inode)==id)}
/// Read from the actual committed/replayed owner view under its mount
/// exclusion. Callback for system contents must validate current schema,
/// identity, generations and ACL against the entire scanned inode table.
/// This returns read-only structural evidence, never a production boot grant.
pub fn scan(
    sb:SuperblockV1,system:&[SystemObject;4],w:&mut Workspace,
    mut read:impl FnMut(u32,&mut[u8;BLOCK])->Result<(),Error>,
    verify_system:impl FnOnce(SuperblockV1,&[SystemObject;4],&[Inode;INODES])->Result<(),Error>,
)->Result<StructureEvidence,Error>{
    if sb.fs_uuid==[0;16]||sb.generation==0||sb.log_epoch==0{return Err(Error::Invalid);}
    for (i,s) in system.iter().enumerate(){
        if s.inode==0||usize::from(s.inode)>=INODES||s.generation==0||s.first_block<DATA_START
            ||s.first_block.checked_add(s.kind.blocks()).is_none_or(|end|end>BLOCK_COUNT)
            ||system[..i].iter().any(|old|old.inode==s.inode||old.kind==s.kind){return Err(Error::Invalid);}
    }
    w.owned.fill(0);w.references.fill(0);
    for i in 0..4{
        read(BITMAP_START+i,&mut w.block)?;
        w.bitmap[i as usize*BLOCK..(i as usize+1)*BLOCK].copy_from_slice(&w.block);
    }
    for block in 0..DATA_START{mark(&mut w.owned,block)?;}
    let mut live=0u16;let mut data=0u32;
    for page in 0..16u32{
        read(INODE_START+page,&mut w.block)?;
        for i in 0..16usize{
            let id=page as usize*16+i;
            let inode=Inode::decode(&w.block[i*INODE_BYTES..(i+1)*INODE_BYTES])?;
            w.inodes[id]=inode;
            if inode.kind!=0{
                live+=1;
                for r in &inode.runs[..usize::from(inode.extents)]{
                    for b in r.physical..r.physical+r.count{mark(&mut w.owned,b)?;}
                    data=data.checked_add(r.count).ok_or(Error::Invalid)?;
                }
            }
        }
    }
    let root=w.inodes[0];
    if root.kind!=2||root.generation!=1||root.parent!=0||root.parent_generation!=1{return Err(Error::Invalid);}
    for s in system{
        let inode=w.inodes[usize::from(s.inode)];
        if inode.kind!=1||inode.generation!=s.generation
            ||inode.size!=u64::from(s.kind.blocks())*BLOCK as u64||inode.extents!=1
            ||inode.runs[0]!=(Extent{logical:0,physical:s.first_block,count:s.kind.blocks()}){
            return Err(Error::Conflict);
        }
    }
    if w.bitmap!=w.owned{return Err(Error::Conflict);}
    let mut entries=0u32;
    for dir in 0..INODES{
        let inode=w.inodes[dir];
        if inode.kind!=2{continue;}
        let mut names=0usize;
        let slots=(inode.size/128) as usize;
        for logical in 0..(slots.div_ceil(32)) {
            read(inode.physical(logical as u32)?,&mut w.block)?;
            for i in 0..(slots-logical*32).min(32){
                let b=&w.block[i*128..(i+1)*128];
                if u32at(b,124)!=crc32c_zeroed(b,124)?||u16at(b,6)!=0{return Err(Error::Invalid);}
                let id=u32at(b,0);
                if id==u32::MAX{
                    if b[4..124].iter().any(|&v|v!=0){return Err(Error::Invalid);}
                    continue;
                }
                let id=id as usize;let len=usize::from(u16at(b,4));
                if id==0||id>=INODES||is_system(id,system)||len==0||len>63
                    ||b[16+len..124].iter().any(|&v|v!=0){return Err(Error::Invalid);}
                let name=&b[16..16+len];
                if core::str::from_utf8(name).is_err()||name==b"."||name==b".."
                    ||name.iter().any(|&v|v==0||v==b'/'){return Err(Error::Invalid);}
                if w.names[..names].iter().any(|v|usize::from(v.len)==len&&&v.bytes[..len]==name){
                    return Err(Error::Conflict);
                }
                let child=w.inodes[id];
                if child.kind==0||child.generation!=u64at(b,8)||child.parent!=dir as u32
                    ||child.parent_generation!=inode.generation||w.references[id]!=0{
                    return Err(Error::Conflict);
                }
                w.references[id]=1;let mut n=EMPTY_NAME;n.len=len as u8;
                n.bytes[..len].copy_from_slice(name);w.names[names]=n;names+=1;entries+=1;
            }
        }
    }
    for id in 1..INODES{
        if w.inodes[id].kind==0||is_system(id,system){
            if w.references[id]!=0{return Err(Error::Conflict);}
            continue;
        }
        if w.references[id]!=1{return Err(Error::Conflict);}
        // Every non-system live object has exactly one reference and
        // a bounded parent walk to root, not a disconnected cycle.
        let mut cur=id;let mut reached=false;
        for _ in 0..INODES{
            let child=w.inodes[cur];let parent=child.parent as usize;
            if parent>=INODES||is_system(parent,system)||w.inodes[parent].kind!=2
                ||w.inodes[parent].generation!=child.parent_generation{return Err(Error::Conflict);}
            if parent==0{reached=true;break;}
            cur=parent;
        }
        if !reached{return Err(Error::Conflict);}
    }
    verify_system(sb,system,&w.inodes)?;
    Ok(StructureEvidence{live_inodes:live,data_blocks:data,directory_entries:entries})
}

#[cfg(test)]
mod tests{
    use super::*;
    fn put16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
    fn put32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
    fn put64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
    fn seal(b:&mut[u8],at:usize){let crc=crc32c_zeroed(b,at).unwrap();put32(b,at,crc);}
    fn inode(b:&mut[u8],kind:u16,generation:u64,size:u64,physical:u32,blocks:u32){
        b.fill(0);put32(b,0,0x4359494e);put16(b,4,kind);put64(b,8,generation);
        if kind!=0{
            put64(b,16,size);put64(b,40,1);
            if blocks!=0{put16(b,32,1);put32(b,52,physical);put32(b,56,blocks);}
        }
        seal(b,252);
    }
    fn sys()->[SystemObject;4]{[
        SystemObject{kind:SystemKind::BootEpoch,inode:2,generation:1,first_block:DATA_START+2},
        SystemObject{kind:SystemKind::Receipts,inode:3,generation:1,first_block:DATA_START+3},
        SystemObject{kind:SystemKind::Acl,inode:4,generation:1,first_block:DATA_START+10},
        SystemObject{kind:SystemKind::Security,inode:5,generation:1,first_block:DATA_START+14},
    ]}
    fn fixture(block:u32,out:&mut[u8;BLOCK],fault:u8)->Result<(),Error>{
        out.fill(0);
        if (BITMAP_START..INODE_START).contains(&block){
            let base=(block-BITMAP_START)*BLOCK as u32*8;
            for b in base..base+BLOCK as u32*8{
                if b<DATA_START+15&&!(fault==1&&b==DATA_START+1){
                    let i=b-base;out[(i/8) as usize]|=1<<(i%8);
                }
            }
        }else if (INODE_START..DATA_START).contains(&block){
            for (i,slot) in out.chunks_exact_mut(256).enumerate(){
                let id=(block-INODE_START)*16+i as u32;
                match id{
                    0=>inode(slot,2,1,128,DATA_START,1),
                    1=>inode(slot,1,1,1,if fault==2{DATA_START}else{DATA_START+1},1),
                    2..=5=>{
                        let s=sys()[(id-2) as usize];
                        inode(slot,1,1,u64::from(s.kind.blocks())*4096,s.first_block,s.kind.blocks());
                    }
                    _=>inode(slot,0,0,0,0,0),
                }
            }
        }else if block==DATA_START{
            let b=&mut out[..128];
            if fault==3{put32(b,0,u32::MAX);}
            else{
                put32(b,0,if fault==4{2}else{1});put16(b,4,1);put64(b,8,1);
                b[16]=if fault==5{0xc0}else{b'x'};
            }
            seal(b,124);
        }
        Ok(())
    }
    #[test]
    fn all_256_inodes_bitmap_and_reachable_directory_entries_are_checked(){
        let mut w=Workspace::new();let sb=SuperblockV1{fs_uuid:[1;16],generation:1,checkpoint_lsn:0,log_epoch:1};
        let evidence=scan(sb,&sys(),&mut w,|block,out|fixture(block,out,0),|_,_,table|{
            assert_eq!(table[1].size,1);assert_eq!(table[5].kind,1);Ok(())
        }).unwrap();
        assert_eq!(evidence,StructureEvidence{live_inodes:6,data_blocks:15,directory_entries:1});
        for fault in 1..=5{
            assert!(scan(sb,&sys(),&mut w,|block,out|fixture(block,out,fault),
                |_,_,_|panic!("corrupt structural view cannot reach system admission")).is_err());
        }
        assert_eq!(scan(sb,&sys(),&mut w,|block,out|fixture(block,out,0),|_,_,_|Err(Error::Unauthorized)),Err(Error::Unauthorized));
    }
}
