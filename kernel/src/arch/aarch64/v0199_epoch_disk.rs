//! Formatted baseline-v1 mount/recovery fixture on real native VirtIO.
//! Both startup stores, all inodes/bitmap/ACLs/receipts and alternating
//! checkpoints are exercised. A fixed TEST volume/manifest is mandatory.
//! No production signed catalog or ordinary file authority is issued.
use super::*;
use crate::virtio_platform::Board;
use cyxia_driver_virtio::{Transport,QueueMemory,block::{Block,Operation,SECTOR_BYTES}};
use cyxia_kernel_core::security::{
    Error as SecurityError,
    file_media_v0199::{SuperblockV1,BLOCK_COUNT,probe_snapshot_media_pair},
    file_mount_v1::{self,Workspace as MountWorkspace,Acl},
    file_structure_v1::{Inode,SystemObject,SystemKind},
    offline_config_v1::Principal,
    file_index_v0199::{SecurityStateStoreV2,BLOCK_BYTES},
    epoch_redo_v0199::{EpochBlockIo,OneStateRedo},
    recovery_v1::{self,RecoveryWorkspace},
    boot_epoch_v1::{BootEpochStoreV1,BootPairRedo},
    durable_role_epoch_v0199::{DurableEpochGate,SlotBinding,Change,Outcome,StopEvidence},
};
use cyxia_kernel_core::control_plane::role_manifest_v0199::{ROLES,Role};
use sha2::{Digest,Sha256};

const UUID:[u8;16]=*b"CYX-TEST-MOUNT!!";
const MARKER:&[u8]=b"CYXIA_V0199_MOUNT_FIXTURE_ONLY";
const HOME:u32=7000;
const BOOT_HOME:u32=7002;
const RECEIPTS_HOME:u32=7003;
const ACL_HOME:u32=7010;
const ROOT_HOME:u32=7014;
const SYSTEM:[SystemObject;4]=[
    SystemObject{kind:SystemKind::BootEpoch,inode:2,generation:1,first_block:BOOT_HOME},
    SystemObject{kind:SystemKind::Receipts,inode:3,generation:1,first_block:RECEIPTS_HOME},
    SystemObject{kind:SystemKind::Acl,inode:4,generation:1,first_block:ACL_HOME},
    SystemObject{kind:SystemKind::Security,inode:5,generation:1,first_block:HOME},
];
const MAGIC:u64=0x4359_4550_4f43_4831;
static mut QUEUE:QueueMemory=QueueMemory::zeroed();
static mut RECOVERY:RecoveryWorkspace=RecoveryWorkspace::new();
static mut MOUNT:MountWorkspace=MountWorkspace::new();

struct Disk{device:Block,reads:u64,writes:u64,flushes:u64,replay_home_allowed:bool}
impl Disk{
    fn sector(&mut self,operation:Operation,input:&[u8;SECTOR_BYTES],output:&mut[u8;SECTOR_BYTES])
        ->Result<(),SecurityError>{
        self.device.begin(operation,input,&Board).map_err(|_|SecurityError::Unknown)?;
        loop{
            match self.device.poll(output,&Board).map_err(|_|SecurityError::Unknown)?{
                Some(done) if done==operation=>return Ok(()),
                Some(_)=>return Err(SecurityError::Unknown),
                None=>core::hint::spin_loop(),
            }
        }
    }
}
impl EpochBlockIo for Disk{
    fn read(&mut self,block:u32,out:&mut[u8;BLOCK_BYTES])->Result<(),SecurityError>{
        if block>=BLOCK_COUNT{return Err(SecurityError::Invalid);}
        for (i,part) in out.chunks_exact_mut(SECTOR_BYTES).enumerate(){
            let mut data=[0;SECTOR_BYTES];
            self.sector(Operation::Read(u64::from(block)*8+i as u64),&[0;SECTOR_BYTES],&mut data)?;
            part.copy_from_slice(&data);
        }
        self.reads+=1;Ok(())
    }
    fn write(&mut self,block:u32,data:&[u8;BLOCK_BYTES])->Result<(),SecurityError>{
        // This test file owner may write its ten journal blocks and,
        // exclusively during recovery, its two homes and superblocks.
        // Bitmap, ACL, receipts, marker, and every other block stay sealed.
        if !(2..12).contains(&block)&&!(matches!(block,0|1|HOME|BOOT_HOME)&&self.replay_home_allowed){
            return Err(SecurityError::Unauthorized);
        }
        for (i,part) in data.chunks_exact(SECTOR_BYTES).enumerate(){
            self.sector(Operation::Write(u64::from(block)*8+i as u64),
                part.try_into().unwrap(),&mut[0;SECTOR_BYTES])?;
        }
        self.writes+=1;Ok(())
    }
    fn flush(&mut self)->Result<(),SecurityError>{
        self.sector(Operation::Flush,&[0;SECTOR_BYTES],&mut[0;SECTOR_BYTES])?;
        self.flushes+=1;Ok(())
    }
}
fn attach(info:&BootInfo)->Disk{
    let mut selected=None;
    for resource in &info.virtio[..info.virtio_count]{
        if resource.base.0<0x0a000000||resource.base.0.checked_add(resource.len).is_none_or(|e|e>0x0a200000){continue;}
        let Ok(t)=(unsafe{Transport::attach((crate::HIGH+resource.base.0) as usize,resource.len as usize)})else{continue;};
        if t.device_id()==2{assert!(selected.is_none());selected=Some(t);}
    }
    let device=Block::attach(selected.expect("one dedicated scratch block device"),
        unsafe{&mut *core::ptr::addr_of_mut!(QUEUE)},&Board).expect("modern VirtIO FLUSH device");
    assert_eq!(device.sectors(),u64::from(BLOCK_COUNT)*8);
    assert!(!device.read_only());
    Disk{device,reads:0,writes:0,flushes:0,replay_home_allowed:false}
}
// Independent expected sequence for the restricted fixture, not a recovery
// source. Recovered bytes below are copied from the actual verified redo.
fn state(txid:u64)->SecurityStateStoreV2{
    let mut generations=[1;16];generations[1]=1+txid/2;
    SecurityStateStoreV2{fs_uuid:UUID,state_generation:txid+1,rule_min_generation:1,
        security_min_generation:1,key_generation:1,isolated_service_bitmap:0,last_boot_epoch:(txid+1)/2,
        offline_config_generation:1,offline_config_hash:[0x5a;32],service_generations:generations}
}
fn stop_security_package(boot:u64,generation:u64)
    ->(StopEvidence,super::v0199_control_bringup::DiskSecurityRun){
    let stopped=super::v0199_control_bringup::disk_security_run(generation,0,true);
    let mut h=Sha256::new();h.update(b"CYX/V0199/role7-stop/v1");
    h.update(stopped.image_sha256);
    for x in [boot,generation,stopped.root,stopped.esr,stopped.far]{h.update(x.to_le_bytes());}
    let proof=StopEvidence{role:Role::Security,generation,digest:h.finalize().into()};
    (proof,stopped)
}
fn append_restart(disk:&mut Disk,scratch:&mut OneStateRedo,gate:&mut DurableEpochGate,sb:SuperblockV1,
    sb_raw:&[u8],txid:u64,change:Change,stop:Option<StopEvidence>)->Outcome{
    let ticket=gate.prepare(change,|v|{
        if stop==Some(v){Ok(())}else{Err(SecurityError::Unauthorized)}
    }).unwrap();
    let image=gate.after_image(ticket).unwrap();
    assert_eq!(txid%2,0);let first=8;let lsn=7*(txid/2);
    let proof=scratch.append(disk,sb,first,HOME,txid,lsn,ticket,&image).unwrap();
    let receipt=proof.receipt();
    gate.confirm_from_redo(ticket,receipt,scratch.image(),sb_raw,first,u64::from(HOME),
        &scratch.begin,&[&scratch.redo],&scratch.commit,|t,r|proof.verifies(t,r)).unwrap()
}
fn append_boot(disk:&mut Disk,pair:&mut BootPairRedo,gate:&mut DurableEpochGate,sb:SuperblockV1,
    sb_raw:&[u8],txid:u64)->Outcome{
    assert_eq!(txid%2,1);
    let ticket=gate.prepare(Change::AllocateBoot,|_|panic!("boot does not authorize restart")).unwrap();
    let image=gate.after_image(ticket).unwrap();
    let first=2;let lsn=7*(txid/2)+4;
    let proof=pair.append(disk,sb,first,HOME,BOOT_HOME,txid,lsn,ticket,&image).unwrap();
    let receipt=proof.receipt();
    gate.confirm_boot_from_redo(ticket,receipt,pair.state_image(),pair.boot_image(),sb_raw,
        first,HOME,BOOT_HOME,&pair.begin,&[&pair.state_redo,&pair.boot_redo],&pair.commit,
        |t,r,b|proof.verifies(t,r,b)).unwrap()
}
fn fixture_acl(a:Acl,inode:Inode,system:Option<SystemKind>)->Result<(),SecurityError>{
    // Test-only immutable volume ACL policy. No general user may
    // access hidden system objects or obtain recovery authority.
    let expected=match a.inode_id{
        0=>(1,1,1<<14,0,1),
        1=>(1,1,1<<8,0,1),
        2..=5=>(1,1,0,(1<<8)|(1<<9)|(1<<13),1),
        _=>(0,0,0,0,0),
    };
    if (a.principal.id,a.principal.generation,a.owner_rights,a.system_rights,a.acl_generation)!=expected
        ||a.parent!=0||a.state!=u32::from(a.inode_id<6)
        ||(2..=5).contains(&a.inode_id)!=system.is_some()
        ||(a.inode_id==0)!=(inode.kind==2)
        ||a.inode_id==0&&inode.runs[0].physical!=ROOT_HOME
        ||a.inode_id==1&&inode.runs[0].physical!=HOME+1{
        return Err(SecurityError::Unauthorized);
    }
    Ok(())
}
fn check_mount(disk:&mut Disk,sb:SuperblockV1,txid:u64)->Result<file_mount_v1::MountEvidence,SecurityError>{
    let w=unsafe{&mut *core::ptr::addr_of_mut!(MOUNT)};
    let principals=core::array::from_fn(|i|Principal{id:i as u64+1,generation:1});
    let e=file_mount_v1::validate(disk,sb,&SYSTEM,&principals,w,fixture_acl)?;
    if e.security!=state(txid)||e.boot.boot_epoch!=(txid+1)/2||e.structure.live_inodes!=6
        ||e.structure.data_blocks!=15||e.structure.directory_entries!=1||e.system_blocks!=13
        ||e.receipts.occupied!=0||e.usage[0].inodes!=2||e.usage[0].blocks!=2
        ||e.usage[0].directory_slots!=1{return Err(SecurityError::Conflict);}
    Ok(e)
}
pub(super) fn run(info:&BootInfo)->!{
    assert_eq!(cpu::slot(),0);assert_eq!(ONLINE.load(Ordering::Acquire),15);
    let pools=super::v0199_ram_inventory::initialize(info);
    super::v0199_control_bringup::install_disk_control_pool(pools.control_va());
    let mut disk=attach(info);
    let mut sb_raw=[0;BLOCK_BYTES];disk.read(0,&mut sb_raw).unwrap();
    let mut buf=[0;BLOCK_BYTES];disk.read(1,&mut buf).unwrap();
    let probe=probe_snapshot_media_pair(&sb_raw,&buf).unwrap();
    let old_sb=if SuperblockV1::decode(&sb_raw).unwrap().generation==probe.generation{
        SuperblockV1::decode(&sb_raw).unwrap()
    }else{SuperblockV1::decode(&buf).unwrap()};
    assert_eq!(old_sb.fs_uuid,UUID);assert!(matches!(old_sb.generation,1|2));
    assert_eq!(old_sb.log_epoch,old_sb.generation);assert_eq!(old_sb.checkpoint_lsn,0);
    let recovered=2*(old_sb.generation-1);
    // Authenticate the dedicated test volume and original complete
    // formatted structure before permitting any recovery writes.
    disk.read(HOME+1,&mut buf).unwrap();
    assert_eq!(&buf[..MARKER.len()],MARKER);assert!(buf[MARKER.len()..].iter().all(|v|*v==0));
    check_mount(&mut disk,old_sb,0).unwrap();
    // Both types contain only fixed byte arrays. The actual exclusive
    // progress pool was fully cleared by the native inventory owner.
    let scratch=unsafe{&mut *(pools.progress_va() as *mut OneStateRedo)};
    let pair_va=pools.progress_va()+core::mem::size_of::<OneStateRedo>() as u64;
    let pair=unsafe{&mut *(pair_va as *mut BootPairRedo)};
    pair.read(&mut disk,2).unwrap();scratch.read(&mut disk,8).unwrap();
    if recovered==0{assert!(pair.blank()&&scratch.blank());}
    else{
        assert_eq!(pair.verify(old_sb,2,HOME,BOOT_HOME,1,4).unwrap(),state(1));
        assert_eq!(scratch.verify(old_sb,8,HOME,2,7).unwrap(),state(2));
    }
    let workspace=unsafe{&mut *core::ptr::addr_of_mut!(RECOVERY)};
    disk.replay_home_allowed=true;
    let mut mounted=None;
    let (chain,sb)=recovery_v1::recover_checkpoint_with_evidence(&mut disk,workspace,|io,current|{
        mounted=Some(check_mount(io,current,recovered)?);Ok(())
    }).unwrap();
    disk.replay_home_allowed=false;
    let mounted=mounted.unwrap();
    assert_eq!(chain.superblock,old_sb);assert_eq!(u64::from(chain.transactions),recovered);
    assert_eq!(chain.last_commit_lsn,7*(recovered/2));
    assert!(!chain.incomplete_tail);
    assert_eq!(chain.distinct_home_blocks,2*u32::from(recovered!=0));
    assert_eq!((sb.generation,sb.log_epoch,sb.checkpoint_lsn),(old_sb.generation+1,old_sb.log_epoch+1,7*(recovered/2)));
    // Recover_checkpoint has FLUSHed home images then the inactive
    // superblock and read it back. Only now may old log space be reused.
    let checkpoint_slot=if recovered==0{1}else{0};
    disk.read(checkpoint_slot,&mut sb_raw).unwrap();assert_eq!(SuperblockV1::decode(&sb_raw).unwrap(),sb);
    assert_eq!((disk.writes,disk.flushes),(1+u64::from(chain.distinct_home_blocks),2));
    let reset=u64::from(recovered!=0);
    if reset!=0{
        buf.fill(0);
        for block in 2..12{disk.write(block,&buf).unwrap();}
        disk.flush().unwrap();
    }
    report("V0199_EPOCH_REPLAY_HOME",recovered,u64::from(chain.distinct_home_blocks),1);
    report("V0199_MOUNT_CHECKPOINT",sb.generation,sb.log_epoch,sb.checkpoint_lsn);
    report("V0199_MOUNT_STRUCTURE",u64::from(mounted.structure.live_inodes),u64::from(mounted.structure.data_blocks),u64::from(mounted.structure.directory_entries));
    disk.read(HOME,&mut buf).unwrap();assert_eq!(SecurityStateStoreV2::decode(&buf).unwrap(),mounted.security);
    let mut boot_raw=[0;BLOCK_BYTES];disk.read(BOOT_HOME,&mut boot_raw).unwrap();
    assert_eq!(BootEpochStoreV1::decode(&boot_raw).unwrap(),mounted.boot);
    let prior=SecurityStateStoreV2::decode(&buf).unwrap();
    let prior_boot=prior.last_boot_epoch;let old_generation=prior.service_generations[1];
    report("V0199_EPOCH_DISK_RECOVERED",prior_boot,prior.state_generation,old_generation);
    let slots=core::array::from_fn(|i|SlotBinding{role:ROLES[i],slot:i as u8});
    let mut gate=DurableEpochGate::recovered_pair(&buf,&boot_raw,slots,|s|{
        if *s==prior{Ok(())}else{Err(SecurityError::Conflict)}
    }).unwrap();
    let boot=prior_boot+1;
    assert_eq!(append_boot(&mut disk,pair,&mut gate,sb,&sb_raw,recovered+1),
        Outcome::Boot{epoch:boot});
    assert_eq!(gate.boot_epoch(),Some(boot));
    assert_eq!(gate.service_generation(Role::Security),Ok(old_generation));
    // Execute the same independently linked ABI3 role7 package used in
    // eight-role bringup, with the confirmed durable generation.
    gic().enable(TIMER_IRQ.load(Ordering::Acquire) as u32).unwrap();
    let (stop,old)=stop_security_package(boot,old_generation);
    report("V0199_EPOCH_CLIENT_STOPPED",old_generation,old.root,old.esr);
    let new_generation=old_generation+1;
    assert_eq!(append_restart(&mut disk,scratch,&mut gate,sb,&sb_raw,recovered+2,Change::Restart(stop),Some(stop)),
        Outcome::Service{role:Role::Security,generation:new_generation,isolated:false});
    assert_eq!(gate.service_generation(Role::Security),Ok(new_generation));
    let new=super::v0199_control_bringup::disk_security_run(new_generation,1,false);
    assert_ne!(new.root,old.root);assert_eq!(old.image_sha256,new.image_sha256);
    report("V0199_EPOCH_CLIENT_RELOADED",new_generation,new.root,boot);
    super::v0199_d15_fixture::run(boot);
    assert_eq!((disk.writes,disk.flushes),(11+12*reset,6+reset));
    let final_txid=recovered+2;
    let final_state=scratch.verify(sb,8,HOME,final_txid,7*(final_txid/2)).unwrap();
    assert_eq!(final_state,state(final_txid));
    let final_digest:[u8;32]=Sha256::digest(scratch.image()).into();
    disk.read(HOME,&mut buf).unwrap();
    assert_eq!(SecurityStateStoreV2::decode(&buf).unwrap(),state(recovered));
    disk.read(BOOT_HOME,&mut boot_raw).unwrap();
    assert_eq!(BootEpochStoreV1::decode(&boot_raw).unwrap().boot_epoch,recovered/2);
    for gate in GATES.iter().take(REQUIRED).skip(1){close_gate(gate);}
    wait(||(1..REQUIRED).all(|i|GATES[i].quiescent()));
    QUIT.store(true,Ordering::Release);
    wait(||STOPPED.load(Ordering::Acquire)==14);
    check_failures();
    let row=[MAGIC,7,0,prior_boot,boot,prior.state_generation,final_state.state_generation,final_txid,7*(final_txid/2),
        8,disk.flushes,disk.reads,disk.writes,u64::from(HOME)];
    for(i,v)in row.into_iter().enumerate(){SMP_EVIDENCE.words[i].store(v,Ordering::Relaxed);}
    for(i,b)in final_digest.chunks_exact(8).enumerate(){
        SMP_EVIDENCE.words[14+i].store(u64::from_le_bytes(b.try_into().unwrap()),Ordering::Relaxed);
    }
    for (i,v) in [old.generation,new.generation,old.root,new.root,old.esr,old.far,
        old.stack,new.stack,32768,old.clocks,old.snapshots,new.clocks,new.snapshots,
        old.score,old.severity,new.score,new.severity].into_iter().enumerate(){
        SMP_EVIDENCE.words[18+i].store(v,Ordering::Relaxed);
    }
    for(i,part)in old.image_sha256.chunks_exact(8).enumerate(){
        SMP_EVIDENCE.words[35+i].store(u64::from_le_bytes(part.try_into().unwrap()),Ordering::Relaxed);
    }
    report("V0199_EPOCH_ROLE7_OPERATOR",old_generation,old.score,old.severity);
    report("V0199_EPOCH_ROLE7_OPERATOR",new_generation,new.score,new.severity);
    for(i,v)in [recovered,u64::from(chain.distinct_home_blocks),chain.last_commit_lsn,1].into_iter().enumerate(){
        SMP_EVIDENCE.words[39+i].store(v,Ordering::Relaxed);
    }
    let boot_digest:[u8;32]=Sha256::digest(pair.boot_image()).into();
    for(i,v)in boot_digest.chunks_exact(8).enumerate(){
        SMP_EVIDENCE.words[43+i].store(u64::from_le_bytes(v.try_into().unwrap()),Ordering::Relaxed);
    }
    SMP_EVIDENCE.words[47].store(u64::from(BOOT_HOME),Ordering::Relaxed);
    for(i,v)in [sb.generation,sb.log_epoch,sb.checkpoint_lsn,u64::from(checkpoint_slot),reset,
        u64::from(mounted.structure.live_inodes),u64::from(mounted.structure.data_blocks),
        u64::from(mounted.structure.directory_entries),u64::from(mounted.system_blocks),
        mounted.receipts.occupied as u64,u64::from(mounted.usage[0].inodes),u64::from(mounted.usage[0].blocks)].into_iter().enumerate(){
        SMP_EVIDENCE.words[48+i].store(v,Ordering::Relaxed);
    }
    let i=pools.inventory;
    for (index,value) in [262144,pools.metadata_pa,10*1024*1024,pools.control_pa,8*1024*1024,
        pools.progress_pa,8*1024*1024,u64::from(i.arena),u64::from(i.firmware_extra),
        u64::from(i.free),u64::from(i.reserved),u64::from(i.allocated),u64::from(i.quarantined),
        u64::from(i.permanent),pools.sample_pa,pools.sample_generation,
        2,pools.progress_pa,pools.progress_pa+core::mem::size_of::<OneStateRedo>() as u64,
        (core::mem::size_of::<OneStateRedo>()+core::mem::size_of::<BootPairRedo>()) as u64].into_iter().enumerate(){
        SMP_EVIDENCE.words[60+index].store(value,Ordering::Relaxed);
    }
    report("V0199_EPOCH_DISK_COMMITTED",prior_boot,boot,disk.flushes);
    SMP_EVIDENCE.words[2].store(1,Ordering::Release);
    super::super::log(b"V0199_EPOCH_DISK_FIXTURE_PASS production=false\n");
    super::super::halt()
}
