//! Actual native D02 business-context creation and ABI3 exit diagnostic.
//! CPU1 owns the dormant private fixture slot 3, including its root,
//! data and stack. CPU0 orchestrates the test through the protected D02
//! component and shared desired bank. No production package catalog,
//! global scheduler or hard WCET claim is made by this restricted backend.
use super::*;
use cyxia_kernel_core::{
    control_plane::{
        Error,Identity,action_schema_v2::ActionV2,
        candidate_registry_v0199::{CatalogEntry,FrozenCandidates},
        d02_owner_v0199::{Owner,Request,State,Outcome,Completion},
        apply_report_v1::{ActionStatus,ApplyReportV1,BoundReport,ExecutorBindingV1,ReportOrigin,TrustedApplyScope,MAX_APPLY_REPORT_BYTES},
        registered_gate_v3::{RegisteredDecisionGate,Registration,Publication,TrustedRegistrationScope},
        rule_profile_v2::{Profile,Candidates},feedback_v0199::{FeedbackInbox,CausalLabel},
        snapshot_store_v3::{SnapshotStore,Target,DomainObservation},desired_plan_v0199::DesiredBank,
    },
    security::{syscall::Syscall,syscall_v3::decode_aarch64_svc_v3},
};
use sha2::{Digest,Sha256};
const CTL:Identity=Identity{id:2,generation:1};
const PUB:Identity=Identity{id:8,generation:1};
const SUP:Identity=Identity{id:11,generation:1};
const LEARN:Identity=Identity{id:10,generation:1};
const TARGET:Identity=Identity{id:2,generation:1};
const CALLER:Identity=Identity{id:0xd0201,generation:1};
const PACKAGE:Identity=Identity{id:0xd0202,generation:1};
const TASK:u64=0xd0203;
const WINDOW:u64=100_000_000;
const SLOT:usize=3;
const ROW_BYTES:usize=128;
pub(super) const PROOF_BYTES:usize=2048;
static REQUEST:AtomicU64=AtomicU64::new(0);
static DONE:AtomicU64=AtomicU64::new(0);
static RESULT:[AtomicU64;16]=[const{AtomicU64::new(0)};16];

fn now()->u64{
    (u128::from(timer::ticks())*1_000_000_000/u128::from(timer::frequency())).try_into().unwrap()
}
fn sha(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn p16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
fn p32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
fn p64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
fn invalidate(){
    unsafe{core::arch::asm!("dsb ishst","tlbi vmalle1is","dsb ish","isb",options(nostack));}
}
/// Called only by CPU1 while holding its existing fixed Business permit.
/// Rebuild real private translations and a fresh EL0 context, run the
/// immutable local diagnostic package, then revoke and scrub before DONE.
pub(super) fn worker_step()->bool{
    assert_eq!(cpu::slot(),1);
    let serial=REQUEST.load(Ordering::Acquire);
    let prior=DONE.load(Ordering::Relaxed);
    if serial==prior{return false;}
    assert_eq!(serial,prior+1);assert!((1..=6).contains(&serial));
    let began=now();let cpu_began=timer::cpu_ticks();
    let (root,mid,leaf,data,stack)=unsafe{(
        core::ptr::addr_of_mut!(ROOTS).cast::<Page>().add(SLOT),
        core::ptr::addr_of_mut!(MIDDLES).cast::<Page>().add(SLOT),
        core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(SLOT),
        core::ptr::addr_of_mut!(DATA_PAGES).cast::<Page>().add(SLOT),
        core::ptr::addr_of_mut!(USER_STACKS).cast::<Page>().add(SLOT))};
    let pages=[root,mid,leaf,data,stack];
    let marker=0xd0200000+serial;
    // The dormant slot has no entered context. Disconnect even its initial
    // boot mappings, invalidate before reusing pages, and scrub all five.
    unsafe{core::ptr::write_volatile(core::ptr::addr_of_mut!((*root).0[0]),0);}
    invalidate();
    for p in pages{unsafe{core::ptr::write_bytes(p.cast::<u8>(),0,4096);}}
    let code=phys(core::ptr::addr_of!(smp_user_start) as u64);
    unsafe{
        (*root).0[0]=phys(mid as u64)|3;
        (*mid).0[0]=phys(leaf as u64)|3;
        (*leaf).0[(CODE/4096) as usize]=mmu::encode_user_leaf(PhysAddr(code),false,true).unwrap();
        (*leaf).0[(DATA/4096) as usize]=mmu::encode_user_leaf(PhysAddr(phys(data as u64)),true,false).unwrap();
        (*leaf).0[(STACK/4096) as usize]=mmu::encode_user_leaf(PhysAddr(phys(stack as u64)),true,false).unwrap();
        (*data).0[0]=marker;
    }
    invalidate();
    let mut ctx=user::Context::empty();ctx.pc=CODE;ctx.sp=STACK+4096;
    ctx.regs[0]=marker;ctx.regs[1]=DATA;ctx.regs[2]=7;
    // Each timer-only preemption returns the full saved context. The
    // bounded program must eventually exit through actual ABI3 SVC #0.
    let mut exited=false;
    for _ in 0..64{
        execute(&mut ctx,SLOT);
        if ctx.kind==9{continue;}
        let call=decode_aarch64_svc_v3(3,ctx.esr,&ctx.regs).expect("D02 actual ABI3 exit");
        assert_eq!(ctx.kind,8);assert_eq!(call.operation,Syscall::Exit);
        assert_eq!(call.args,[0;6]);exited=true;break;
    }
    assert!(exited);
    let observed=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*data).0[0]))};
    let count=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*data).0[1]))};
    assert_eq!((observed,count),(marker,16));
    let row_kind=ctx.kind;let row_esr=ctx.esr;let row_syscall=ctx.regs[8];
    // No old live mappings, task context or data survive the generation.
    unsafe{core::ptr::write_volatile(core::ptr::addr_of_mut!((*root).0[0]),0);}
    invalidate();
    for p in pages{
        unsafe{
            core::ptr::write_bytes(p.cast::<u8>(),0,4096);
            assert!(core::slice::from_raw_parts(p.cast::<u8>(),4096).iter().all(|&v|v==0));
        }
    }
    // All CPU0 reads occur after the worker's release of the completion.
    let cost=timer::cpu_elapsed_ns(cpu_began);let done=now();
    let row=[serial,TASK,cpu::slot() as u64,phys(root as u64),phys(mid as u64),phys(leaf as u64),
        phys(data as u64),phys(stack as u64),observed,count,row_kind,row_esr,row_syscall,began,done,cost];
    for(i,v)in row.into_iter().enumerate(){RESULT[i].store(v,Ordering::Relaxed);}
    DONE.store(serial,Ordering::Release);
    true
}
fn request_digest(boot:u64,id:u64,package:[u8;32])->[u8;32]{
    let mut h=Sha256::new();h.update(b"CYX/D02-NATIVE-FIXTURE/v0199");
    h.update(boot.to_le_bytes());h.update(id.to_le_bytes());h.update(package);h.finalize().into()
}
fn package_hash()->[u8;32]{
    let start=core::ptr::addr_of!(smp_user_start) as usize;
    let end=core::ptr::addr_of!(smp_user_end) as usize;
    assert!(end>start&&end-start<=4096);
    sha(unsafe{core::slice::from_raw_parts(start as *const u8,end-start)})
}
fn req(boot:u64,id:u64,package:[u8;32])->Request{
    Request{caller:CALLER,request_id:id,package:PACKAGE,group:TARGET,digest:request_digest(boot,id,package)}
}
fn next_window()->u64{
    let next=(now()/WINDOW+1)*WINDOW;
    let f=timer::frequency();
    let cmp=u64::try_from((u128::from(next)*u128::from(f)).div_ceil(1_000_000_000)).unwrap();
    while now()<next{
        unsafe{timer::arm(cmp);}
        timer::idle();
        unsafe{cpu::disable_timer();}
    }
    next/WINDOW
}
fn service(owner:&mut Owner,boot:u64,package:[u8;32],serial:u64,window:u64,proof:&mut[u8;PROOF_BYTES]){
    let began=now();assert_eq!(began/WINDOW,window);
    let mut captured=None;
    let state=owner.service_one(began,3,|r|{
        if *r==req(boot,serial,package){Ok(())}else{Err(Error::Denied)}
    },|r|{
        assert_eq!(r.request_id,serial);
        assert_eq!(DONE.load(Ordering::Acquire),serial-1);
        assert_eq!(REQUEST.load(Ordering::Relaxed),serial-1);
        REQUEST.store(serial,Ordering::Release);
        wait(||DONE.load(Ordering::Acquire)==serial);
        let row:[u64;16]=core::array::from_fn(|i|RESULT[i].load(Ordering::Relaxed));
        assert_eq!((row[0],row[1],row[2]),(serial,TASK,1));
        assert!(began<=row[13]&&row[13]<=row[14]&&row[14]<=now());
        captured=Some(row);
        Completion{outcome:Outcome::Created(Identity{id:TASK,generation:serial}),completed_ns:row[14]}
    }).unwrap();
    let task=Identity{id:TASK,generation:serial};
    assert_eq!(state,Some(State::Created(task)));
    let row=captured.expect("actual CPU1 creation");
    assert_eq!(row[14]/WINDOW,window,"real construction crossed token window");
    for(i,v)in row.into_iter().enumerate(){p64(proof,(serial as usize-1)*ROW_BYTES+i*8,v);}
    owner.exited(task,now(),||{
        if DONE.load(Ordering::Acquire)==serial{Ok(())}else{Err(Error::NotReady)}
    }).unwrap();
    assert_eq!(owner.submit(req(boot,serial,package),now(),|_|Ok(())).unwrap(),State::Created(task));
}
pub(super) fn run(boot:u64,gate:&mut RegisteredDecisionGate<'_>,snapshots:&mut SnapshotStore,
    inbox:&mut FeedbackInbox,desired:&mut DesiredBank,owner:&mut Owner,proof:&mut[u8;PROOF_BYTES]){
    assert_eq!(cpu::slot(),0);assert_eq!(ONLINE.load(Ordering::Acquire),15);
    assert_eq!(desired.version(),2);
    let package=package_hash();
    owner.bind(boot,1,||if GATES[1].view().enabled{Ok(())}else{Err(Error::Denied)}).unwrap();
    owner.register_group(TARGET,||Ok(())).unwrap();
    for id in 1..=7{
        let r=req(boot,id,package);
        assert_eq!(owner.submit(r,now(),|v|if *v==r{Ok(())}else{Err(Error::Denied)}),Ok(State::Queued));
    }
    let base_window=next_window();
    for id in 1..=2{service(owner,boot,package,id,base_window,proof);}
    let t=now();assert_eq!(t/WINDOW,base_window);
    assert_eq!(owner.service_one(t,3,|_|panic!("baseline token limit"),|_|panic!("baseline over-admission")),Ok(None));
    assert_eq!(owner.counts(),(5,0,0));
    let sample=now();let fields=owner.observation(TARGET,3,sample).unwrap();
    let target=Target{domain:2,object:TARGET,owner:Identity{id:1,generation:1}};
    snapshots.register_target(target,|t|if t==target{Ok(())}else{Err(Error::Denied)}).unwrap();
    assert_eq!(snapshots.capture(1,1,sample,[None;8],&[DomainObservation{target,fields}],|o|
        if o.target==target&&o.fields==owner.observation(TARGET,3,sample)?{Ok(())}else{Err(Error::Denied)}),Ok(3));
    let snap=snapshots.frozen_for_owner(target,1,1,now(),|t|if t==target{Ok(())}else{Err(Error::Denied)}).unwrap();
    let values=ActionV2::values(2).unwrap();
    let catalog:[CatalogEntry;4]=core::array::from_fn(|i|CatalogEntry{ordinal:i as u16,value:values[i]});
    let catalog_digest=sha(b"CYX/D02-FIXTURE-ORDINALS/0=1,1=2,2=4,3=8");
    let candidates=FrozenCandidates::capture(snap,&catalog,catalog_digest,ActionV2::SpawnTokens(2),Some(5),Some(true),false,
        |r,h|if r==&catalog&&h==catalog_digest{Ok(())}else{Err(Error::Denied)},
        |v|match v{ActionV2::SpawnTokens(n)=>Ok(owner.legal(TARGET,n,sample)),_=>Err(Error::Denied)}).unwrap();
    let mut rules=[0u8;88];p32(&mut rules,0,0x43595255);p16(&mut rules,4,2);p16(&mut rules,6,32);
    p64(&mut rules,8,3);p32(&mut rules,16,1);p32(&mut rules,20,88);
    p32(&mut rules,32,3);p16(&mut rules,36,2);p16(&mut rules,38,1);p64(&mut rules,40,TARGET.id);
    p16(&mut rules,50,1);p16(&mut rules,52,1);p32(&mut rules,56,56);
    // D02 pending field is the fourth domain field (raw rule field 4).
    p16(&mut rules,64,4);rules[66]=3;p64(&mut rules,72,1);p16(&mut rules,80,2);
    let profile=Profile::parse(&rules).unwrap();
    let matched=profile.match_candidates(2,TARGET.id,candidates.rule_fields(),Candidates{static_ordinals:candidates.ordinals()}).unwrap().unwrap();
    let view=candidates.view();let local=view.selected(matched.fallback_index).unwrap();
    assert_eq!(local.action_payload,&[4,0]);
    let expiry=sample+100_000_000;let until=sample+10_000_000_000;
    let mut plan=[0u8;212];p32(&mut plan,0,0x43594c31);p16(&mut plan,4,2);p16(&mut plan,6,64);
    p32(&mut plan,8,212);p16(&mut plan,12,1);p64(&mut plan,16,3);p64(&mut plan,24,2);
    p64(&mut plan,40,1);p64(&mut plan,48,3);p64(&mut plan,56,until);
    p32(&mut plan,64,0x43595031);p16(&mut plan,68,2);p16(&mut plan,70,144);
    p16(&mut plan,72,2);p16(&mut plan,74,1);p32(&mut plan,76,4);
    for(at,v)in [(80,1),(88,3),(96,3),(104,TARGET.id),(112,TARGET.generation),(120,1),(128,1),(136,expiry)]{p64(&mut plan,at,v);}
    plan[176..208].copy_from_slice(&candidates.digest());p16(&mut plan,208,matched.fallback_index);
    plan[210..].copy_from_slice(local.action_payload);
    let mut record=[0u8;256];p32(&mut record,0,0x43594431);p16(&mut record,4,3);p16(&mut record,6,256);
    for(at,v)in [(8,boot),(16,1),(24,3),(32,3),(40,3),(48,TARGET.id),(56,TARGET.generation),
        (64,1),(72,1),(80,3),(144,expiry)]{p64(&mut record,at,v);}
    p32(&mut record,88,matched.rule_id);p16(&mut record,94,2);p16(&mut record,96,1);
    p16(&mut record,102,matched.fallback_index);p16(&mut record,104,u16::MAX);p32(&mut record,108,2);
    p32(&mut record,152,matched.allowed_mask);p16(&mut record,156,matched.fallback_index);p16(&mut record,158,matched.choice_policy);
    record[160..192].copy_from_slice(&sha(&rules));record[192..224].copy_from_slice(&sha(&plan));record[224..].copy_from_slice(&candidates.digest());
    let ctx=TrustedRegistrationScope{boot_epoch:boot,controller_epoch:1,rules_generation:3,
        rules_hash:sha(&rules),base_plan_version:2,ledger_generation:1,core_generation:1,
        snapshot_seq:3,sampled_ns:sample,now_ns:now()};
    let records=[record];let actions=[local];
    assert_eq!(gate.register_rule_only(CTL,&plan,&records,&profile,&actions,ctx),Ok(Registration::Frozen));
    let binding=ExecutorBindingV1{domain:2,role:1,active:true,target:TARGET,executor_generation:1,
        holder:Identity{id:0,generation:0},endpoint_cap_id:0};
    desired.register_target(binding,|b|if b==binding&&owner.version(TARGET)?==0{Ok(())}else{Err(Error::Denied)}).unwrap();
    let pubctx=TrustedRegistrationScope{now_ns:now(),..ctx};
    assert_eq!(gate.publish_once(PUB,&plan,&records,&profile,&actions,pubctx,||{
        desired.publish_registered(PUB,cpu::slot(),&plan,pubctx,|a|{
            let a=a[0].ok_or(Error::Denied)?;
            if a.binding==binding&&a.value==ActionV2::SpawnTokens(4)&&owner.legal(TARGET,4,pubctx.now_ns)
                &&a.prior_target_version==owner.version(TARGET)?{Ok(())}else{Err(Error::Denied)}
        }).map(|_|())
    }),Ok(Publication::AdapterAccepted));
    let scope=TrustedApplyScope{boot_epoch:boot,plan_version:desired.version(),now_ns:now()};
    assert_eq!(scope.plan_version,3);
    gate.claim_apply_work(&plan,0,scope,binding,ReportOrigin::Kernel,|w|
        desired.accept(w,ReportOrigin::Kernel,scope.now_ns,|a|
            owner.accept(w,a.prior_target_version,a.until_ns,scope.now_ns,||Ok(())))).unwrap();
    let mut out=[0;MAX_APPLY_REPORT_BYTES];assert_eq!(owner.report(TARGET,&mut out),Err(Error::NotReady));
    let approved_window=next_window();assert!(approved_window>base_window);
    for id in 3..=6{service(owner,boot,package,id,approved_window,proof);}
    let t=now();assert_eq!(t/WINDOW,approved_window);
    assert_eq!(owner.service_one(t,3,|_|panic!("approved token limit"),|_|panic!("approved over-admission")),Ok(None));
    assert_eq!(owner.counts(),(1,0,0));owner.cancel_queued(CALLER,7,now(),|r|{
        if *r==req(boot,7,package)&&DONE.load(Ordering::Acquire)==6{Ok(())}else{Err(Error::Denied)}
    }).unwrap();
    assert_eq!(owner.counts(),(0,0,0));
    let n=owner.report(TARGET,&mut out).unwrap();let r=ApplyReportV1::decode(&out[..n]).unwrap();
    assert_eq!(r.state,ActionStatus::Applied);
    let frames=[BoundReport{bytes:&out[..n],origin:ReportOrigin::Kernel}];
    let summary=gate.settle_verified_apply_reports_with_feedback(SUP,&plan,&frames,&[binding],
        TrustedApplyScope{now_ns:now(),..scope},None,|_,r|owner.verify_report(r),|batch|inbox.retain(SUP,batch)).unwrap();
    let feedback=inbox.read(LEARN,2).unwrap().unwrap();
    assert_eq!(feedback.decision,record);assert_eq!(feedback.report_bytes(),&out[..n]);
    assert_eq!(feedback.causal_label,CausalLabel::NoAdoption);
    desired.finish(&r,ReportOrigin::Kernel,now(),|a|{
        if a.key.plan_seq==summary.plan_seq&&inbox.len()==3{owner.verify_report(&r)}else{Err(Error::NotReady)}
    }).unwrap();
    owner.retire(TARGET,&out[..n],||if summary.plan_seq==3&&inbox.len()==3{Ok(())}else{Err(Error::NotReady)}).unwrap();
    let mut at=6*ROW_BYTES;
    for bytes in [&snap.encode().unwrap()[..],&rules,&plan,&record,&out[..n],&package]{
        proof[at..at+bytes.len()].copy_from_slice(bytes);at+=bytes.len();
    }
    let row=[0x4359443032465831,base_window,approved_window,2,4,scope.plan_version,
        sample,scope.now_ns,r.completed_ns,n as u64,inbox.len() as u64,at as u64];
    for(i,v)in row.into_iter().enumerate(){SMP_EVIDENCE.words[379+i].store(v,Ordering::Relaxed);}
    for(i,p)in sha(proof).chunks_exact(8).enumerate(){SMP_EVIDENCE.words[391+i].store(u64::from_le_bytes(p.try_into().unwrap()),Ordering::Relaxed);}
    let code=core::ptr::addr_of!(smp_user_start) as u64;
    let end=core::ptr::addr_of!(smp_user_end) as u64;
    SMP_EVIDENCE.words[395].store(phys(code),Ordering::Relaxed);
    SMP_EVIDENCE.words[396].store(end-code,Ordering::Relaxed);
    report("V0199_D02_EFFECT",2,4,3);
}
