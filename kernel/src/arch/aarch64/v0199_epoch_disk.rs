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
    durable_role_epoch_v0199::{DurableEpochGate,SlotBinding,Change,Outcome,StopEvidence},
};
use cyxia_kernel_core::control_plane::role_manifest_v0199::{ROLES,Role};
use sha2::{Digest,Sha256};

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
        // home, superblocks, bitmap or arbitrary data. Four log appends.
        if !(2..18).contains(&block){return Err(SecurityError::Unauthorized);}
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
// Independent expected sequence for the restricted fixture, not a recovery
// source. Recovered bytes below are copied from the actual verified redo.
fn state(txid:u64)->SecurityStateStoreV2{
    let mut generations=[1;16];generations[1]=1+txid/2;
    SecurityStateStoreV2{fs_uuid:UUID,state_generation:txid+1,rule_min_generation:1,
        security_min_generation:1,key_generation:1,isolated_service_bitmap:0,last_boot_epoch:(txid+1)/2,
        offline_config_generation:1,offline_config_hash:[0x5a;32],service_generations:generations}
}
fn root(space:usize)->u64{
    phys(unsafe{core::ptr::addr_of!(ROOTS).cast::<Page>().add(space)} as u64)
}
fn run_client(space:usize)->user::Context{
    let mut ctx=context(space);ctx.regs[2]=4;
    for _ in 0..32{
        execute(&mut ctx,space);
        if ctx.kind==9{continue;}
        assert_eq!(ctx.kind,8);assert_eq!(ctx.esr>>26,0x15);assert_eq!(ctx.esr&0xffff,4);
        let data=unsafe{core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(space)};
        assert!(unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*data).0[1]))}>0);
        return ctx;
    }
    panic!("native epoch fixture client never ran");
}
fn stop_client(space:usize,mut ctx:user::Context,boot:u64,generation:u64)
    ->(StopEvidence,u64,u64,u64){
    let fault=STACK-4096;
    ctx.pc=fault;
    let mut stopped=false;
    for _ in 0..32{
        execute(&mut ctx,space);
        if ctx.kind==9{continue;}
        assert_eq!(ctx.kind,8);assert_eq!(ctx.esr>>26,0x20);
        assert_eq!(ctx.esr&0x3f,7);assert_eq!(ctx.far,fault);
        stopped=true;break;
    }
    assert!(stopped);
    let old_root=root(space);
    // This fixture never grants a capability, DMA reference or a second
    // thread to the client. Disconnect only this stopped root and complete
    // inner-shareable TLBI before scrubbing its exclusively owned pages.
    unsafe{
        let table=core::ptr::addr_of_mut!(ROOTS).cast::<Page>().add(space);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*table).0[0]),0);
        core::arch::asm!("dsb ishst","tlbi vmalle1is","dsb ish","isb",options(nostack));
        assert_eq!(core::ptr::read_volatile(core::ptr::addr_of!((*table).0[0])),0);
        for page in [core::ptr::addr_of_mut!(DATA_PAGES).cast::<Page>().add(space),
            core::ptr::addr_of_mut!(USER_STACKS).cast::<Page>().add(space)]{
            core::ptr::write_bytes(page.cast::<u8>(),0,4096);
            assert!((*page).0.iter().all(|v|*v==0));
        }
    }
    let mut h=Sha256::new();h.update(b"CYX/V0199/fixture-stop/v1");
    for x in [boot,generation,old_root,ctx.esr,ctx.far]{h.update(x.to_le_bytes());}
    let proof=StopEvidence{role:Role::Security,generation,digest:h.finalize().into()};
    (proof,old_root,ctx.esr,ctx.far)
}
fn append(disk:&mut Disk,scratch:&mut OneStateRedo,gate:&mut DurableEpochGate,sb:SuperblockV1,
    sb_raw:&[u8],txid:u64,change:Change,stop:Option<StopEvidence>)->Outcome{
    let ticket=gate.prepare(change,|v|{
        if stop==Some(v){Ok(())}else{Err(SecurityError::Unauthorized)}
    }).unwrap();
    let image=gate.after_image(ticket).unwrap();
    let first=2+4*(txid as u32-1);let lsn=3*txid;
    let proof=scratch.append(disk,sb,first,HOME,txid,lsn,ticket,&image).unwrap();
    let receipt=proof.receipt();
    gate.confirm_from_redo(ticket,receipt,scratch.image(),sb_raw,first,u64::from(HOME),
        &scratch.begin,&[&scratch.redo],&scratch.commit,|t,r|proof.verifies(t,r)).unwrap()
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
    // Recover the exact committed after-image; never derive it from a
    // volatile counter or silently rewrite a partial journal tail.
    for i in 0..4u32{
        let first=2+4*i;let txid=u64::from(i)+1;
        scratch.read(&mut disk,first).unwrap();
        if scratch.blank(){empty_seen=true;continue;}
        assert!(!empty_seen);
        let next=scratch.verify(sb,first,HOME,txid,3*txid).unwrap();
        assert_eq!(next,state(txid));
        buf.copy_from_slice(scratch.image());
        recovered=txid;
    }
    assert!(matches!(recovered,0|2),"fixture requires complete previous boot pair");
    let prior=SecurityStateStoreV2::decode(&buf).unwrap();
    let prior_boot=prior.last_boot_epoch;let old_generation=prior.service_generations[1];
    report("V0199_EPOCH_DISK_RECOVERED",prior_boot,prior.state_generation,old_generation);
    let slots=core::array::from_fn(|i|SlotBinding{role:ROLES[i],slot:i as u8});
    let mut gate=DurableEpochGate::recovered(&buf,slots,|s|{
        if *s==prior{Ok(())}else{Err(SecurityError::Conflict)}
    }).unwrap();
    let boot=prior_boot+1;
    assert_eq!(append(&mut disk,scratch,&mut gate,sb,&sb_raw,recovered+1,Change::AllocateBoot,None),
        Outcome::Boot{epoch:boot});
    assert_eq!(gate.boot_epoch(),Some(boot));
    assert_eq!(gate.service_generation(Role::Security),Ok(old_generation));
    // Two actual distinct, private native diagnostic contexts. The first
    // runs, faults and is retired before durable service generation change.
    // This does not claim a full Security AI service or production recovery.
    gic().enable(TIMER_IRQ.load(Ordering::Acquire) as u32).unwrap();
    let old_space=C*2+1;let new_space=C*2+2;
    assert!(new_space<PRIVATE_SPACES);
    let ctx=run_client(old_space);
    let (stop,old_root,esr,far)=stop_client(old_space,ctx,boot,old_generation);
    report("V0199_EPOCH_CLIENT_STOPPED",old_generation,old_root,esr);
    let new_generation=old_generation+1;
    assert_eq!(append(&mut disk,scratch,&mut gate,sb,&sb_raw,recovered+2,Change::Restart(stop),Some(stop)),
        Outcome::Service{role:Role::Security,generation:new_generation,isolated:false});
    assert_eq!(gate.service_generation(Role::Security),Ok(new_generation));
    let new_root=root(new_space);assert_ne!(new_root,old_root);
    let _=run_client(new_space);
    report("V0199_EPOCH_CLIENT_RELOADED",new_generation,new_root,boot);
    assert_eq!((disk.writes,disk.flushes),(8,4));
    let final_txid=recovered+2;
    let final_state=scratch.verify(sb,2+4*(final_txid as u32-1),HOME,final_txid,3*final_txid).unwrap();
    assert_eq!(final_state,state(final_txid));
    let final_digest:[u8;32]=Sha256::digest(scratch.image()).into();
    disk.read(HOME,&mut buf).unwrap();
    assert_eq!(SecurityStateStoreV2::decode(&buf).unwrap(),state(0));
    for gate in GATES.iter().take(REQUIRED).skip(1){close_gate(gate);}
    wait(||(1..REQUIRED).all(|i|GATES[i].quiescent()));
    QUIT.store(true,Ordering::Release);
    wait(||STOPPED.load(Ordering::Acquire)==14);
    check_failures();
    let row=[MAGIC,2,0,prior_boot,boot,prior.state_generation,final_state.state_generation,final_txid,3*final_txid,
        u64::from(2+4*(final_txid as u32-1)),disk.flushes,disk.reads,disk.writes,u64::from(HOME)];
    for(i,v)in row.into_iter().enumerate(){SMP_EVIDENCE.words[i].store(v,Ordering::Relaxed);}
    for(i,b)in final_digest.chunks_exact(8).enumerate(){
        SMP_EVIDENCE.words[14+i].store(u64::from_le_bytes(b.try_into().unwrap()),Ordering::Relaxed);
    }
    for (i,v) in [old_generation,new_generation,old_root,new_root,esr,far].into_iter().enumerate(){
        SMP_EVIDENCE.words[18+i].store(v,Ordering::Relaxed);
    }
    report("V0199_EPOCH_DISK_COMMITTED",prior_boot,boot,disk.flushes);
    SMP_EVIDENCE.words[2].store(1,Ordering::Release);
    super::super::log(b"V0199_EPOCH_DISK_FIXTURE_PASS production=false\n");
    super::super::halt()
}
