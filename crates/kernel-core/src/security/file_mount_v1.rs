//! Baseline-v1 mount: join inode/bitmap/directory structure with all four
//! protected system objects, persistent principal identities and ACLs.
//! These checks consume the exclusive native post-replay disk view.
//! They do not issue file capabilities, clear UNKNOWN receipts or certify
//! that a signed startup catalog or writable production service exists.
use super::{Error,boot_epoch_v1::BootEpochStoreV1,epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::{FileStreamIndexV4,SecurityStateStoreV2},
    file_media_v0199::{SuperblockV1,crc32c_zeroed},
    file_receipt_store_v0199::{self,ReceiptStoreSummary,RECEIPT_STORE_BYTES},
    file_structure_v1::{self,Inode,SystemKind,SystemObject,StructureEvidence,INODES,BLOCK},
    offline_config_v1::{Principal,VerifiedOfflineConfig}};
const ACL_BYTES:usize=64;
const ACL_STORE:usize=INODES*ACL_BYTES;
const FILE_RIGHTS:u32=(1<<8)|(1<<9)|(1<<13);
const DIR_RIGHTS:u32=(1<<10)|(1<<11)|(1<<12)|(1<<14);
fn u32at(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}
fn u64at(b:&[u8],i:usize)->u64{u64::from_le_bytes(b[i..i+8].try_into().unwrap())}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Acl{
    pub inode_id:u32,pub state:u32,pub inode_generation:u64,pub principal:Principal,
    pub owner_rights:u32,pub system_rights:u32,pub acl_generation:u64,pub parent:u32,
}
impl Acl{
    pub fn decode(b:&[u8])->Result<Self,Error>{
        if b.len()!=ACL_BYTES||u32at(b,52)!=0||u32at(b,56)!=0
            ||u32at(b,60)!=crc32c_zeroed(b,60)?{return Err(Error::Invalid);}
        let a=Self{inode_id:u32at(b,0),state:u32at(b,4),inode_generation:u64at(b,8),
            principal:Principal{id:u64at(b,16),generation:u64at(b,24)},
            owner_rights:u32at(b,32),system_rights:u32at(b,36),acl_generation:u64at(b,40),parent:u32at(b,48)};
        if a.inode_id>=INODES as u32||a.state>2||a.parent>=INODES as u32
            ||(a.owner_rights|a.system_rights)&!(FILE_RIGHTS|DIR_RIGHTS)!=0{return Err(Error::Invalid);}
        Ok(a)
    }
}
#[derive(Clone,Copy,Debug,Default,Eq,PartialEq)]
pub struct Usage{pub inodes:u32,pub blocks:u32,pub directory_slots:u32}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct MountEvidence{
    pub structure:StructureEvidence,pub boot:BootEpochStoreV1,pub security:SecurityStateStoreV2,
    pub receipts:ReceiptStoreSummary,pub usage:[Usage;16],pub system_blocks:u32,
}
pub struct Workspace{
    structure:file_structure_v1::Workspace,
    boot:[u8;BLOCK],security:[u8;BLOCK],index:[u8;BLOCK],
    receipts:[u8;RECEIPT_STORE_BYTES],acl:[u8;ACL_STORE],
}
impl Workspace{
    pub const fn new()->Self{Self{structure:file_structure_v1::Workspace::new(),
        boot:[0;BLOCK],security:[0;BLOCK],index:[0;BLOCK],receipts:[0;RECEIPT_STORE_BYTES],acl:[0;ACL_STORE]}}
}
const _:()=assert!(core::mem::size_of::<Workspace>()<=192*1024);
fn system_layout(system:&[SystemObject;4])->Result<(),Error>{
    for (i,s) in system.iter().enumerate(){
        let count=match s.kind{SystemKind::BootEpoch|SystemKind::Security=>1,SystemKind::Receipts=>7,SystemKind::Acl=>4};
        if s.inode==0||usize::from(s.inode)>=INODES||s.generation==0
            ||s.first_block<super::file_media_v0199::DATA_START
            ||s.first_block.checked_add(count).is_none_or(|end|end>super::file_media_v0199::BLOCK_COUNT)
            ||system[..i].iter().any(|old|old.inode==s.inode||old.kind==s.kind){
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn blocks(io:&mut impl EpochBlockIo,first:u32,out:&mut[u8])->Result<(),Error>{
    if !out.len().is_multiple_of(BLOCK){return Err(Error::Invalid);}
    for(i,b)in out.chunks_exact_mut(BLOCK).enumerate(){
        io.read(first.checked_add(i as u32).ok_or(Error::Invalid)?,b.try_into().unwrap())?;
    }
    Ok(())
}
fn inspect_acls(acl:&[u8;ACL_STORE],inodes:&[Inode;INODES],system:&[SystemObject;4],
    principals:&[Principal;16],mut policy:impl FnMut(Acl,Inode,Option<SystemKind>)->Result<(),Error>)
    ->Result<([Usage;16],u32),Error>{
    let mut usage=[Usage::default();16];let mut system_blocks=0u32;
    for (i,raw) in acl.chunks_exact(ACL_BYTES).enumerate(){
        let a=Acl::decode(raw)?;let inode=inodes[i];
        if a.inode_id!=i as u32||a.inode_generation!=inode.generation{return Err(Error::Conflict);}
        let owner=principals.iter().position(|p|*p==a.principal);
        let hidden=system.iter().find(|s|usize::from(s.inode)==i).map(|s|s.kind);
        if inode.kind==0{
            // Initial empty and retained tombstone have no access authority.
            // The signed volume policy decides any retained identity fields.
            if a.state==1||a.owner_rights!=0||a.system_rights!=0
                ||a.state==0&&inode.generation!=0||a.state==2&&inode.generation==0
                ||(a.principal.id!=0||a.principal.generation!=0)&&owner.is_none(){return Err(Error::Conflict);}
        }else{
            let slot=owner.ok_or(Error::Unauthorized)?;
            let mask=if inode.kind==1{FILE_RIGHTS}else{DIR_RIGHTS};
            if a.state!=1||a.acl_generation==0||a.parent!=inode.parent
                ||(a.owner_rights|a.system_rights)&!mask!=0||hidden.is_some()&&a.owner_rights!=0{
                return Err(Error::Unauthorized);
            }
            let n=inode.runs[..usize::from(inode.extents)].iter().try_fold(0u32,|sum,r|sum.checked_add(r.count)).ok_or(Error::Capacity)?;
            if hidden.is_some(){system_blocks=system_blocks.checked_add(n).ok_or(Error::Capacity)?;}
            else{
                let u=&mut usage[slot];
                u.inodes=u.inodes.checked_add(1).ok_or(Error::Capacity)?;
                u.blocks=u.blocks.checked_add(n).ok_or(Error::Capacity)?;
                if inode.kind==2{u.directory_slots=u.directory_slots.checked_add((inode.size/128) as u32).ok_or(Error::Capacity)?;}
            }
        }
        policy(a,inode,hidden)?;
    }
    Ok((usage,system_blocks))
}
/// All four object payloads are copied from the actual stable disk view,
/// then cross-validated with the full inode scan. The supplied policy is
/// the independent trusted ACL/quota authority, not an EL0 callback.
/// Its acceptance is required even for the root and hidden system files.
pub fn validate(io:&mut impl EpochBlockIo,sb:SuperblockV1,system:&[SystemObject;4],
    principals:&[Principal;16],w:&mut Workspace,
    policy:impl FnMut(Acl,Inode,Option<SystemKind>)->Result<(),Error>)
    ->Result<MountEvidence,Error>{
    system_layout(system)?;
    for(i,p)in principals.iter().enumerate(){
        if p.id==0||p.generation==0||principals[..i].iter().any(|old|old.id==p.id){return Err(Error::Invalid);}
    }
    for s in system{
        match s.kind{
            SystemKind::BootEpoch=>io.read(s.first_block,&mut w.boot)?,
            SystemKind::Security=>io.read(s.first_block,&mut w.security)?,
            SystemKind::Receipts=>{
                blocks(io,s.first_block,&mut w.receipts)?;
                io.read(s.first_block+6,&mut w.index)?;
            }
            SystemKind::Acl=>blocks(io,s.first_block,&mut w.acl)?,
        }
    }
    let boot=BootEpochStoreV1::decode(&w.boot)?;
    let security=SecurityStateStoreV2::decode(&w.security)?;
    let index=FileStreamIndexV4::decode(&w.index)?;
    if boot.fs_uuid!=sb.fs_uuid||!boot.matches(&security)||index.fs_uuid!=sb.fs_uuid
        ||index.groups.iter().zip(principals).any(|(g,p)|g.manifest_principal_id!=p.id||g.boot_epoch>boot.boot_epoch){
        return Err(Error::Conflict);
    }
    let receipts=file_receipt_store_v0199::scan_receipts_with_index(&w.receipts,&w.index,sb.fs_uuid)?;
    let mut counters=None;let acl=&w.acl;
    let structure=file_structure_v1::scan(sb,system,&mut w.structure,|b,out|io.read(b,out),|_,sys,inodes|{
        counters=Some(inspect_acls(acl,inodes,sys,principals,policy)?);Ok(())
    })?;
    let (usage,system_blocks)=counters.ok_or(Error::Conflict)?;
    if system_blocks!=13||usage.iter().map(|u|u.blocks).sum::<u32>()+system_blocks!=structure.data_blocks
        ||usage.iter().map(|u|u.inodes).sum::<u32>()+4!=u32::from(structure.live_inodes){
        return Err(Error::Conflict);
    }
    Ok(MountEvidence{structure,boot,security,receipts,usage,system_blocks})
}
/// Production callers must obtain the system object locations from an
/// authenticated boot catalog. The exact signed principal table, security
/// minima and configuration digest are then enforced before checkpoint.
pub fn validate_signed(io:&mut impl EpochBlockIo,sb:SuperblockV1,system:&[SystemObject;4],
    config:&VerifiedOfflineConfig<'_>,w:&mut Workspace,
    policy:impl FnMut(Acl,Inode,Option<SystemKind>)->Result<(),Error>)
    ->Result<MountEvidence,Error>{
    let e=validate(io,sb,system,config.principals(),w,policy)?;
    config.check_committed(&e.security)?;
    Ok(e)
}

#[cfg(test)]
mod tests{
    extern crate std;
    use super::*;
    use std::{boxed::Box,collections::BTreeMap};
    const STATE_HOME:u32=7000;
    const BOOT_HOME:u32=7002;
    const RECEIPTS:u32=7003;
    const ACL:u32=7010;
    const ROOT:u32=7014;
    fn p16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
    fn p32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
    fn p64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
    fn seal(b:&mut[u8],at:usize){let c=crc32c_zeroed(b,at).unwrap();p32(b,at,c);}
    fn inode(b:&mut[u8],kind:u16,size:u64,home:u32,n:u32){
        b.fill(0);p32(b,0,0x4359494e);p16(b,4,kind);
        if kind!=0{
            p64(b,8,1);p64(b,16,size);p64(b,40,1);
            if n!=0{p16(b,32,1);p32(b,52,home);p32(b,56,n);}
        }
        seal(b,252);
    }
    struct Disk(BTreeMap<u32,Box<[u8;BLOCK]>>);
    impl EpochBlockIo for Disk{
        fn read(&mut self,b:u32,out:&mut[u8;BLOCK])->Result<(),Error>{
            if let Some(v)=self.0.get(&b){*out=**v;}else{out.fill(0);}Ok(())
        }
        fn write(&mut self,_:u32,_:&[u8;BLOCK])->Result<(),Error>{panic!("read-only mount validation")}
        fn flush(&mut self)->Result<(),Error>{panic!("read-only mount validation")}
    }
    fn systems()->[SystemObject;4]{[
        SystemObject{kind:SystemKind::BootEpoch,inode:2,generation:1,first_block:BOOT_HOME},
        SystemObject{kind:SystemKind::Receipts,inode:3,generation:1,first_block:RECEIPTS},
        SystemObject{kind:SystemKind::Acl,inode:4,generation:1,first_block:ACL},
        SystemObject{kind:SystemKind::Security,inode:5,generation:1,first_block:STATE_HOME},
    ]}
    fn fixture()->Disk{
        let mut d=Disk(BTreeMap::new());
        for page in 0..4u32{
            let mut b=[0;BLOCK];
            let start=page*BLOCK as u32*8;
            for at in start..start+BLOCK as u32*8{
                if at<4118||(STATE_HOME..=ROOT).contains(&at){let v=at-start;b[(v/8) as usize]|=1<<(v%8);}
            }
            d.0.insert(4098+page,Box::new(b));
        }
        for page in 0..16u32{
            let mut b=[0;BLOCK];
            for (j,slot) in b.chunks_exact_mut(256).enumerate(){
                match page*16+j as u32{
                    0=>inode(slot,2,128,ROOT,1),
                    1=>inode(slot,1,8,STATE_HOME+1,1),
                    2=>inode(slot,1,4096,BOOT_HOME,1),
                    3=>inode(slot,1,7*4096,RECEIPTS,7),
                    4=>inode(slot,1,4*4096,ACL,4),
                    5=>inode(slot,1,4096,STATE_HOME,1),
                    _=>inode(slot,0,0,0,0),
                }
            }
            d.0.insert(4102+page,Box::new(b));
        }
        let mut root=[0;BLOCK];
        p32(&mut root,0,1);p16(&mut root,4,1);p64(&mut root,8,1);root[16]=b'x';
        seal(&mut root[..128],124);d.0.insert(ROOT,Box::new(root));
        for page in 0..4u32{
            let mut b=[0;BLOCK];
            for (j,slot) in b.chunks_exact_mut(64).enumerate(){
                let id=page*64+j as u32;p32(slot,0,id);
                if id<6{
                    p32(slot,4,1);p64(slot,8,1);p64(slot,16,1);p64(slot,24,1);p64(slot,40,1);
                    if id==0{p32(slot,32,1<<14);}
                    else if id==1{p32(slot,32,1<<8);}
                    else{p32(slot,36,FILE_RIGHTS);}
                }
                seal(slot,60);
            }
            d.0.insert(ACL+page,Box::new(b));
        }
        let mut index=[0;BLOCK];p32(&mut index,0,0x43595349);p16(&mut index,4,4);p16(&mut index,6,64);
        index[8..24].fill(1);p64(&mut index,32,1);
        for i in 0..16{p64(&mut index,64+24*i+16,i as u64+1);}
        seal(&mut index,4092);d.0.insert(RECEIPTS+6,Box::new(index));
        let boot=BootEpochStoreV1{fs_uuid:[1;16],boot_epoch:2}.encode().unwrap();
        let security=SecurityStateStoreV2{fs_uuid:[1;16],state_generation:3,rule_min_generation:1,
            security_min_generation:1,key_generation:1,isolated_service_bitmap:0,last_boot_epoch:2,
            offline_config_generation:1,offline_config_hash:[3;32],service_generations:[1;16]}.encode().unwrap();
        d.0.insert(BOOT_HOME,Box::new(boot));d.0.insert(STATE_HOME,Box::new(security));d
    }
    #[test]
    fn joined_mount_denies_wrong_acl_principal_hidden_right_and_split_boot(){
        let mut d=fixture();let sb=SuperblockV1{fs_uuid:[1;16],generation:1,checkpoint_lsn:0,log_epoch:1};
        let p=core::array::from_fn(|i|Principal{id:i as u64+1,generation:1});
        let mut w=Workspace::new();let mut seen=0;
        let v=validate(&mut d,sb,&systems(),&p,&mut w,|_,_,_|{seen+=1;Ok(())}).unwrap();
        assert_eq!(seen,256);assert_eq!(v.system_blocks,13);assert_eq!(v.structure.live_inodes,6);
        assert_eq!(v.usage[0],Usage{inodes:2,blocks:2,directory_slots:1});
        let mut bad=fixture();
        let b=&mut bad.0.get_mut(&ACL).unwrap()[64..128];p64(b,24,2);seal(b,60);
        assert_eq!(validate(&mut bad,sb,&systems(),&p,&mut w,|_,_,_|Ok(())),Err(Error::Unauthorized));
        let mut bad=fixture();
        let b=&mut bad.0.get_mut(&ACL).unwrap()[128..192];p32(b,32,1<<8);seal(b,60);
        assert_eq!(validate(&mut bad,sb,&systems(),&p,&mut w,|_,_,_|Ok(())),Err(Error::Unauthorized));
        let mut bad=fixture();
        bad.0.insert(BOOT_HOME,Box::new(BootEpochStoreV1{fs_uuid:[1;16],boot_epoch:1}.encode().unwrap()));
        assert_eq!(validate(&mut bad,sb,&systems(),&p,&mut w,|_,_,_|panic!("split boot stores")),Err(Error::Conflict));
        let mut bad=fixture();
        let b=bad.0.get_mut(&(RECEIPTS+6)).unwrap();
        p64(&mut **b,80,99);seal(&mut **b,4092);
        assert_eq!(validate(&mut bad,sb,&systems(),&p,&mut w,|_,_,_|panic!("principal mismatch")),Err(Error::Conflict));
    }
}
