//! Explicit native scratch-disk fixture, NOT a production filesystem mount.
//! It uses the real VirtIO block queue and two ordered FLUSH completions.
//! The immutable fixture UUID/marker and initial state must match before
//! any write. Never run on a real user volume; no control caps are issued.
use super::*;
use crate::virtio_platform::Board;
use cyxia_driver_virtio::{Transport,QueueMemory,block::{Block,Operation,SECTOR_BYTES}};
use cyxia_kernel_core::security::{
    Error as SecurityError,
    file_media_v0199::{SuperblockV1,BLOCK_COUNT},
    file_index_v0199::{SecurityStateStoreV2,BLOCK_BYTES},
    epoch_redo_v0199::{EpochBlockIo,OneStateRedo},
    durable_role_epoch_v0199::{DurableEpochGate,SlotBinding,Change,Outcome},
};
use cyxia_kernel_core::control_plane::role_manifest_v0199::ROLES;

const UUID:[u8;16]=*b"CYX-TEST-EPOCH!!";
const MARKER:&[u8]=b"CYXIA_V0199_EPOCH_SCRATCH_ONLY";
const HOME:u32=7000;
const MAGIC:u64=0x4359_4550_4f43_4831;
static mut QUEUE:QueueMemory=QueueMemory::zeroed();
static mut SCRATCH:OneStateRedo=OneStateRedo::zeroed();

struct Disk{device:Block,reads:u64,writes:u64,flushes:u64}
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
        // An additional fixture-only physical restriction. Never write
        // home, superblocks, bitmap or arbitrary data. Two log appends.
        if !(2..10).contains(&block){return Err(SecurityError::Unauthorized);}
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
    Disk{device,reads:0,writes:0,flushes:0}
}
fn state(epoch:u64)->SecurityStateStoreV2{
    SecurityStateStoreV2{fs_uuid:UUID,state_generation:epoch+1,rule_min_generation:1,
        security_min_generation:1,key_generation:1,isolated_service_bitmap:0,last_boot_epoch:epoch,
        offline_config_generation:1,offline_config_hash:[0x5a;32],service_generations:[1;16]}
}
pub(super) fn run(info:&BootInfo)->!{
    assert_eq!(cpu::slot(),0);assert_eq!(ONLINE.load(Ordering::Acquire),15);
    let mut disk=attach(info);
    let mut sb_raw=[0;BLOCK_BYTES];disk.read(0,&mut sb_raw).unwrap();
    let mut buf=[0;BLOCK_BYTES];disk.read(1,&mut buf).unwrap();assert_eq!(buf,sb_raw);
    let sb=SuperblockV1::decode(&sb_raw).unwrap();
    assert_eq!(sb,SuperblockV1{fs_uuid:UUID,generation:1,checkpoint_lsn:0,log_epoch:1});
    disk.read(HOME+1,&mut buf).unwrap();
    assert_eq!(&buf[..MARKER.len()],MARKER);assert!(buf[MARKER.len()..].iter().all(|v|*v==0));
    disk.read(HOME,&mut buf).unwrap();
    assert_eq!(SecurityStateStoreV2::decode(&buf).unwrap(),state(0));
    let scratch=unsafe{&mut *core::ptr::addr_of_mut!(SCRATCH)};
    let mut recovered=0u64;
    let mut empty_seen=false;
    // This intentionally small scratch journal holds two immutable appends.
    // A partial or inconsistent record is RECOVERY_REQUIRED, not overwritten.
    for i in 0..2u32{
        let first=2+4*i;let txid=u64::from(i)+1;
        scratch.read(&mut disk,first).unwrap();
        if scratch.blank(){empty_seen=true;continue;}
        assert!(!empty_seen);
        let next=scratch.verify(sb,first,HOME,txid,3*txid).unwrap();
        assert_eq!(next,state(txid));
        recovered=txid;
    }
    assert!(recovered<2);
    report("V0199_EPOCH_DISK_RECOVERED",recovered,recovered+1,recovered);
    let raw=state(recovered).encode().unwrap();
    let slots=core::array::from_fn(|i|SlotBinding{role:ROLES[i],slot:i as u8});
    let mut gate=DurableEpochGate::recovered(&raw,slots,|s|{
        if *s==state(recovered){Ok(())}else{Err(SecurityError::Conflict)}
    }).unwrap();
    let ticket=gate.prepare(Change::AllocateBoot,|_|panic!("not a service restart")).unwrap();
    let image=gate.after_image(ticket).unwrap();
    let txid=recovered+1;let first=2+4*recovered as u32;let lsn=3*txid;
    let proof=scratch.append(&mut disk,sb,first,HOME,txid,lsn,ticket,&image).unwrap();
    let receipt=proof.receipt();
    assert_eq!(gate.confirm_from_redo(ticket,receipt,scratch.image(),&sb_raw,first,u64::from(HOME),
        &scratch.begin,&[&scratch.redo],&scratch.commit,|t,r|proof.verifies(t,r)),
        Ok(Outcome::Boot{epoch:txid}));
    assert_eq!(gate.boot_epoch(),Some(txid));
    assert_eq!((disk.writes,disk.flushes),(4,2));
    // Real readback of the old home remains unchanged. The next fresh VM
    // must obtain its latest state from the committed redo, not RAM/home.
    disk.read(HOME,&mut buf).unwrap();
    assert_eq!(SecurityStateStoreV2::decode(&buf).unwrap(),state(0));
    for gate in GATES.iter().take(REQUIRED).skip(1){close_gate(gate);}
    wait(||(1..REQUIRED).all(|i|GATES[i].quiescent()));
    QUIT.store(true,Ordering::Release);
    wait(||STOPPED.load(Ordering::Acquire)==14);
    check_failures();
    let row=[MAGIC,1,0,recovered,txid,recovered+1,txid+1,txid,lsn,
        u64::from(first),disk.flushes,disk.reads,disk.writes,u64::from(HOME)];
    for(i,v)in row.into_iter().enumerate(){SMP_EVIDENCE.words[i].store(v,Ordering::Relaxed);}
    for(i,b)in receipt.after_digest.chunks_exact(8).enumerate(){
        SMP_EVIDENCE.words[14+i].store(u64::from_le_bytes(b.try_into().unwrap()),Ordering::Relaxed);
    }
    report("V0199_EPOCH_DISK_COMMITTED",recovered,txid,disk.flushes);
    SMP_EVIDENCE.words[2].store(1,Ordering::Release);
    super::super::log(b"V0199_EPOCH_DISK_FIXTURE_PASS production=false\n");
    super::super::halt()
}
