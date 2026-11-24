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
