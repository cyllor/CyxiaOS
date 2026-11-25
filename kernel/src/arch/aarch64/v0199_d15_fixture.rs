//! Native D15 effect integration on the dedicated formatted test volume.
//! Real PL011 and PMU, current rule/Plan/ApplyReport/Feedback gates.
//! The test rule catalog and controller/publisher identities are fixture
//! authorities, NOT signed production EL0 service credentials. No model
//! training or formal G4 claim, and no complete CPU0 budget claim.
use super::*;
use cyxia_contracts::{ConsoleOps,PlatformError,UartResource};
 use cyxia_kernel_core::control_plane::{
    Error,Identity,action_schema_v2::ActionV2,
    candidate_registry_v0199::{CatalogEntry,FrozenCandidates},
    d15_owner_v0199::{Clock,Owner,PumpEvidence},
    snapshot_store_v3::{SnapshotStore,Target,DomainObservation},
    apply_report_v1::{ActionStatus,ApplyReportV1,BoundReport,ExecutorBindingV1,ReportOrigin,TrustedApplyScope,MAX_APPLY_REPORT_BYTES},
    registered_gate_v3::{RegisteredDecisionGate,Registration,Publication,TrustedRegistrationScope},
    rule_profile_v2::{Profile,Candidates},feedback_v0199::{FeedbackInbox,CausalLabel},
};
use sha2::{Digest,Sha256};
const CTL:Identity=Identity{id:2,generation:1};
const PUB:Identity=Identity{id:8,generation:1};
const SUP:Identity=Identity{id:11,generation:1};
const LEARN:Identity=Identity{id:10,generation:1};
const TARGET:Identity=Identity{id:15,generation:1};
const BASE_PAYLOAD:&[u8]=b"V0199_D15_BASELINE actual ordinary UART frame 0123456789abcdef\n";
const APPLY_PAYLOAD:&[u8]=b"V0199_D15_APPLIED actual ordinary UART frame 0123456789abcdef\n";
static mut OWNER:Owner=Owner::empty();
static mut SNAPSHOTS:SnapshotStore=SnapshotStore::empty();
static mut FEEDBACK:FeedbackInbox=match FeedbackInbox::new(SUP,LEARN){Ok(x)=>x,Err(_)=>panic!("fixture identity")};
struct NativeClock;
fn now()->u64{
    (u128::from(timer::ticks())*1_000_000_000/u128::from(timer::frequency())).try_into().unwrap()
}
impl Clock for NativeClock{
    fn wall_ns(&mut self)->u64{now()}
    fn cpu_ns(&mut self)->u64{timer::cpu_ns(timer::cpu_ticks())}
}
struct Tx(cyxia_driver_pl011::Pl011);
impl ConsoleOps for Tx{
    fn try_write(&mut self,b:&[u8])->Result<usize,PlatformError>{
        let n=self.0.try_write(b)?;
        if n!=0{
            unsafe{core::arch::asm!("dsb oshst",options(nostack,preserves_flags));}
            crate::interrupts::TEST_PROGRESS.bytes.fetch_add(n as u64,Ordering::Relaxed);
        }
        Ok(n)
    }
}
fn retry_wait(){
    let start=timer::ticks();
    let ticks=(u128::from(timer::frequency())*100_000/1_000_000_000).max(1) as u64;
    let end=start.checked_add(ticks+1).unwrap();
    // Diagnostic orchestrator waits outside the bounded ordinary pump.
    // CPU0 owns the physical timer and IRQs are masked in EL1.
    while timer::ticks()<end{
        unsafe{timer::arm(end);}
        timer::idle();
        unsafe{cpu::disable_timer();}
    }
}
fn drain(owner:&mut Owner,tx:&mut Tx,clock:&mut NativeClock)->(PumpEvidence,u64,u64,u64){
    let until=now().checked_add(2_000_000_000).unwrap();
    let mut first=None;let mut count=0u64;let mut max=0u64;let mut cost=0u64;
    while owner.pending()!=0{
        assert!(now()<until,"native UART drain deadline");
        match owner.pump(tx,clock).unwrap(){
            Some(e)=>{
                if e.chars>0&&first.is_none(){first=Some(e);}
                count+=1;max=max.max(u64::from(e.chars));cost=cost.checked_add(e.cpu_ns).unwrap();
                if e.tx_full{retry_wait();}
            }
            None=>retry_wait(),
        }
    }
    (first.expect("real UART accepted bytes"),count,max,cost)
}
fn p16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
fn p32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
fn p64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
fn sha(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn rule()->[u8;88]{
    // Test catalog: one ordinary D15 rule, queue nonempty, selects 32.
    let mut b=[0;88];p32(&mut b,0,0x43595255);p16(&mut b,4,2);p16(&mut b,6,32);
    p64(&mut b,8,1);p32(&mut b,16,1);p32(&mut b,20,88);
    p32(&mut b,32,1);p16(&mut b,36,15);p16(&mut b,38,1);p64(&mut b,40,TARGET.id);
    p16(&mut b,50,1);p16(&mut b,52,1);p32(&mut b,56,56);
    p16(&mut b,64,1);b[66]=3;p64(&mut b,72,1);p16(&mut b,80,2);
    b
}
fn retain_bytes(at:usize,bytes:&[u8]){
    for (i,part) in bytes.chunks(8).enumerate(){
        let mut word=[0u8;8];word[..part.len()].copy_from_slice(part);
        SMP_EVIDENCE.words[at+i].store(u64::from_le_bytes(word),Ordering::Relaxed);
    }
}
pub(super) fn run(boot:u64,confirmed_boot:Option<u64>){
    assert_eq!(cpu::slot(),0);
    // Diagnostic owner has actual device access; no user cap issuance.
    let base=crate::UART.load(Ordering::Acquire);assert_ne!(base,0);
    let mut tx=Tx(unsafe{cyxia_driver_pl011::Pl011::attach(UartResource{base:PhysAddr(base),len:4096})}.unwrap());
    unsafe{timer::init_cpu_accounting();}
    let mut clock=NativeClock;
    let owner=unsafe{&mut *core::ptr::addr_of_mut!(OWNER)};
    owner.bind(boot,TARGET,1,||if base==super::super::HIGH+0x09000000{Ok(())}else{Err(Error::Denied)}).unwrap();
    let baseline=crate::machine::enqueue_v0199(owner,BASE_PAYLOAD,now()).unwrap();
    let (_,baseline_calls,baseline_max,baseline_cpu)=drain(owner,&mut tx,&mut clock);
    assert_eq!(owner.written(),baseline as u64);assert!(baseline_max>0&&baseline_max<=8);
    let applied=crate::machine::enqueue_v0199(owner,APPLY_PAYLOAD,now()).unwrap();
    let sample=now();let fields=owner.observe(sample).unwrap();
    // The same protected registry used by the current SnapshotReply v3
    // reader now owns this actual HAL observation. The epoch disk caller
    // supplies the confirmed boot from DurableEpochGate, not a model.
    let snapshots=unsafe{&mut *core::ptr::addr_of_mut!(SNAPSHOTS)};
    snapshots.bind_boot(boot,||if confirmed_boot==Some(boot){Ok(())}else{Err(Error::Denied)}).unwrap();
    let target=Target{domain:15,object:TARGET,owner:Identity{id:1,generation:1}};
    snapshots.register_target(target,|t|if t.object==owner.target(){Ok(())}else{Err(Error::Denied)}).unwrap();
    let observation=DomainObservation{target,fields};
    assert_eq!(snapshots.capture(1,1,sample,[None;8],&[observation],|o|
        if o.target==target&&o.fields==owner.observe(sample)?{Ok(())}else{Err(Error::Denied)}),Ok(1));
    let snap=snapshots.frozen_for_owner(target,1,1,now(),|t|
        if t.object==owner.target(){Ok(())}else{Err(Error::Denied)}).unwrap();
    let values=ActionV2::values(15).unwrap();
    let catalog:[CatalogEntry;4]=core::array::from_fn(|i|CatalogEntry{ordinal:i as u16,value:values[i]});
    let catalog_digest=sha(b"CYX/D15-FIXTURE-ORDINALS/0=1,1=8,2=32,3=64");
    let candidates=FrozenCandidates::capture(snap,&catalog,catalog_digest,ActionV2::ConsolePump(8),
        Some(owner.pending() as u64),Some(true),false,
        |r,h|if r==&catalog&&h==catalog_digest{Ok(())}else{Err(Error::Denied)},
        |v|match v{ActionV2::ConsolePump(n)=>Ok(owner.legal(n,sample)),_=>Err(Error::Denied)}).unwrap();
    let rules=rule();let profile=Profile::parse(&rules).unwrap();
    let matched=profile.match_candidates(15,TARGET.id,candidates.rule_fields(),Candidates{static_ordinals:candidates.ordinals()}).unwrap().unwrap();
    let view=candidates.view();let local=view.selected(matched.fallback_index).unwrap();
    assert_eq!(local.action_payload,&[32,0]);
    let expiry=sample+100_000_000;let until=sample+10_000_000_000;
    let mut plan=[0u8;212];
    p32(&mut plan,0,0x43594c31);p16(&mut plan,4,2);p16(&mut plan,6,64);
    p32(&mut plan,8,212);p16(&mut plan,12,1);p64(&mut plan,16,1);
    p64(&mut plan,40,1);p64(&mut plan,48,1);p64(&mut plan,56,until);
    p32(&mut plan,64,0x43595031);p16(&mut plan,68,2);p16(&mut plan,70,144);
    p16(&mut plan,72,15);p16(&mut plan,74,1);p32(&mut plan,76,4);
    for (at,v) in [(80,1),(88,1),(96,1),(104,TARGET.id),(112,TARGET.generation),
        (120,1),(128,1),(136,expiry)]{p64(&mut plan,at,v);}
    plan[176..208].copy_from_slice(&candidates.digest());p16(&mut plan,208,matched.fallback_index);
    plan[210..212].copy_from_slice(local.action_payload);
    let mut record=[0u8;256];p32(&mut record,0,0x43594431);p16(&mut record,4,3);p16(&mut record,6,256);
    for(at,v)in [(8,boot),(16,1),(24,1),(32,1),(40,1),(48,TARGET.id),(56,TARGET.generation),
        (64,1),(72,1),(80,1),(144,expiry)]{p64(&mut record,at,v);}
    p32(&mut record,88,matched.rule_id);p16(&mut record,94,15);p16(&mut record,96,1);
    p16(&mut record,102,matched.fallback_index);p16(&mut record,104,u16::MAX);
    p32(&mut record,108,2);p32(&mut record,152,matched.allowed_mask);
    p16(&mut record,156,matched.fallback_index);p16(&mut record,158,matched.choice_policy);
    record[160..192].copy_from_slice(&sha(&rules));record[192..224].copy_from_slice(&sha(&plan));
    record[224..].copy_from_slice(&candidates.digest());
    let ctx=TrustedRegistrationScope{boot_epoch:boot,controller_epoch:1,rules_generation:1,
        rules_hash:sha(&rules),base_plan_version:owner.installed_version(),ledger_generation:1,core_generation:1,
        snapshot_seq:1,sampled_ns:sample,now_ns:now()};
    // This fixture exercises the actual protected gate, but the test
    // controller and publisher calls are not production EL0 traps.
    let mut gate=RegisteredDecisionGate::new_with_terminal_owner(CTL,PUB,SUP,boot,1).unwrap();
    let actions=[local];let records=[record];
    assert_eq!(gate.register_rule_only(CTL,&plan,&records,&profile,&actions,ctx),Ok(Registration::Frozen));
    let mut desired=None;let pubctx=TrustedRegistrationScope{now_ns:now(),..ctx};
    assert_eq!(gate.publish_once(PUB,&plan,&records,&profile,&actions,pubctx,||{
        if !owner.legal(32,pubctx.now_ns){return Err(Error::Denied);}
        desired=Some((sha(&plan),1u64));Ok(())
    }),Ok(Publication::AdapterAccepted));
    let binding=ExecutorBindingV1{domain:15,role:1,active:true,target:TARGET,
        executor_generation:1,holder:Identity{id:0,generation:0},endpoint_cap_id:0};
    let scope=TrustedApplyScope{boot_epoch:boot,plan_version:1,now_ns:now()};
    let _=gate.claim_apply_work(&plan,0,scope,binding,ReportOrigin::Kernel,|w|{
        owner.accept(w,ctx.base_plan_version,until,scope.now_ns,||
            if desired==Some((sha(&plan),w.plan_version)){Ok(())}else{Err(Error::Denied)})
    }).unwrap();
    let mut report_bytes=[0;MAX_APPLY_REPORT_BYTES];
    assert_eq!(owner.report(now(),&mut report_bytes),Err(Error::NotReady));
    let (first,applied_calls,applied_max,applied_cpu)=drain(owner,&mut tx,&mut clock);
    assert_eq!(owner.written(),(baseline+applied) as u64);
    assert_eq!(first.limit,32);assert!(applied_max>8&&applied_max<=32,"actual batch effect");
    let n=owner.report(now(),&mut report_bytes).unwrap();
    let r=ApplyReportV1::decode(&report_bytes[..n]).unwrap();assert_eq!(r.state,ActionStatus::Applied);
    let inbox=unsafe{&mut *core::ptr::addr_of_mut!(FEEDBACK)};
    let frames=[BoundReport{bytes:&report_bytes[..n],origin:ReportOrigin::Kernel}];
    let summary=gate.settle_verified_apply_reports_with_feedback(SUP,&plan,&frames,&[binding],
        TrustedApplyScope{now_ns:now(),..scope},None,|_,r|owner.verify_report(r),|batch|inbox.retain(SUP,batch)).unwrap();
    let feedback=inbox.read(LEARN,0).unwrap().unwrap();
    assert_eq!(feedback.report_bytes(),&report_bytes[..n]);assert_eq!(feedback.decision,record);
    assert_eq!(feedback.causal_label,CausalLabel::NoAdoption);
    owner.retire(&r,||if summary.plan_seq==1&&inbox.len()==1{Ok(())}else{Err(Error::NotReady)}).unwrap();
    let row=[0x4359443135465831,baseline as u64,baseline_calls,baseline_max,baseline_cpu,
        applied as u64,applied_calls,applied_max,applied_cpu,u64::from(first.limit),u64::from(first.chars),
        u64::from(first.before),u64::from(first.after),first.version,first.start_ns,first.end_ns,first.cpu_ns,
        owner.written(),u64::from(n as u32),inbox.len() as u64,sample,scope.now_ns];
    for(i,v)in row.into_iter().enumerate(){SMP_EVIDENCE.words[80+i].store(v,Ordering::Relaxed);}
    retain_bytes(104,&snap.encode().unwrap());retain_bytes(137,&rules);
    retain_bytes(148,&plan);retain_bytes(175,&record);retain_bytes(207,&report_bytes[..n]);
    report("V0199_D15_EFFECT",baseline_max,applied_max,first.version);
}
