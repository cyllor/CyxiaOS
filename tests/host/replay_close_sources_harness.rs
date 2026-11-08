// Controlled hardware/Core capture fixture; never native acceptance evidence.
mod learning_replay {
use super::*;
use super::learning_replay as owner;
type DomainError = super::Error;
use cyxia_prototype::learning::{Error,capture::Seal};
static GATE:AtomicBool=AtomicBool::new(false);
static ADDRESS:AtomicUsize=AtomicUsize::new(0);
pub static CLOSED:AtomicU64=AtomicU64::new(0);
pub static BUSY:AtomicBool=AtomicBool::new(false);
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum Phase{Drain,CloseSources,Seal,Verify,Run}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct Scope{key:u64,observation:u64,cleanup_deadline:u64}
#[derive(Clone,Copy)]struct Source{owner:u64,class:u64}
#[derive(Clone,Copy)]struct Prepared{source_count:usize,sources:[Source;4]}
struct Activation(bool);impl Activation{fn entered(&self)->bool{self.0}}
struct State{phase:Phase,scope:Option<Scope>,token:Option<u64>,cursor:usize,prepared:Option<Prepared>,work_activation:Activation,last_error:Option<DomainError>,seal:Option<Seal>,records:usize,retained:usize,export_index:usize,record_started:bool,verification:Option<u64>,partner:Option<u64>,peer_staged:usize}
mod diagnostic{pub struct Attempt;impl Attempt{pub fn new(_:u64)->Self{Self}}}
fn retain_error(_:DomainError,_:Option<&mut diagnostic::Attempt>){let _=with(|_|Ok(()));}
fn publish_evidence(){let _=with(|_|Ok(()));}
fn evidence_error(e:capture::Error)->Error{match e{capture::Error::Capture(e)=>e}}
fn domain_error(e:Error)->DomainError{match e{Error::Unknown=>DomainError::Busy,Error::Deadline=>DomainError::Expired,_=>DomainError::Conflict}}
mod root{use super::*;pub fn rejected(_:u64)->Result<Option<u64>,DomainError>{Ok(None)}}
mod history{use super::*;pub fn record_rejected(_:u64,_:&u64)->Result<(),capture::Error>{Ok(())}
 pub mod replay{pub fn seal(_:super::Seal)->Result<(),super::capture::Error>{Ok(())}}
 pub struct Status{pub records:usize}pub fn status()->Result<Status,capture::Error>{Ok(Status{records:0})}
}
mod capture{
use super::*;
use cyxia_prototype::learning::{Family,reward::CpuClass,capture::{Capture,Config,RunKey,FrozenRequest,Source,SourceToken,Status}};
#[derive(Debug)]pub enum Error{Capture(super::Error)}
static BANK:std::sync::Mutex<Capture<32,100>>=std::sync::Mutex::new(Capture::empty());
fn class(value:u64)->CpuClass{match value{0=>CpuClass::Policy,1=>CpuClass::ExecutorAction,2=>CpuClass::ExecutorWork,_=>unreachable!()}}
pub fn reset(){
 let mut bank=BANK.lock().unwrap();*bank=Capture::empty();
 let sources=std::array::from_fn::<_,4,_>(|i|Source{owner:group(i as u64+1),class:class([0,1,2,0][i]),allowed_cores:1});
 let observation=86_127_750_992;
 let requests=std::array::from_fn::<_,100,_>(|i|FrozenRequest{id:i as u64+1,owner:group(9),arrived_ns:observation+i as u64*1_000_000});
 bank.start(Config{key:RunKey{boot_epoch:1,trial_id:1,generation:1},family:Family{domain:1,kind:2},node:[1;32],first_ns:observation-1_000_000_000,observation_ns:observation,frozen_scope_hash:[2;32]},&sources,&requests).unwrap();
 for request in requests{bank.issued(request.owner,request.id,request.arrived_ns).unwrap();}
}
pub fn source(owner:u64,class_value:u64)->Result<SourceToken,Error>{BANK.lock().unwrap().source(group(owner),class(class_value)).map_err(Error::Capture)}
pub fn close_source(token:SourceToken)->Result<(),Error>{
 assert_eq!(CREDIT_KIND[0].load(Ordering::Acquire),5,"source close escaped fresh paid credit");
 assert!(!COMPLETE_READY[0].load(Ordering::Acquire),"source close reused old bill");
 if BUSY.load(Ordering::Acquire){return Err(Error::Capture(super::Error::Unknown))}
 BANK.lock().unwrap().close_source(token,now_ns()).map_err(Error::Capture)?;CLOSED.fetch_add(1,Ordering::AcqRel);Ok(())
}
pub fn prepare_seal(){let mut bank=BANK.lock().unwrap();for i in 0..4{let token=bank.source(group(i+1),class([0,1,2,0][i as usize])).unwrap();bank.close_source(token,now_ns()).unwrap();}CLOSED.store(4,Ordering::Release);}
pub fn status()->Result<(Status,),Error>{Ok((BANK.lock().unwrap().status(),))}
pub fn seal(incomplete:bool)->Result<Seal,Error>{
 assert_eq!(CREDIT_KIND[0].load(Ordering::Acquire),5,"seal escaped fresh paid credit");assert!(!COMPLETE_READY[0].load(Ordering::Acquire));
 let mut bank=BANK.lock().unwrap();if incomplete{bank.seal_incomplete(now_ns())}else{bank.seal(now_ns())}.map_err(Error::Capture)
}
}
struct Guard;
// ACTUAL_OWNER_DROP
// ACTUAL_OWNER_LOCK
// ACTUAL_OWNER_WITH
// ACTUAL_OWNER_HINT
// ACTUAL_OWNER_DRAIN
// ACTUAL_OWNER_STEP
// ACTUAL_DRAIN_PENDING
// ACTUAL_SERVICE_PENDING
// ACTUAL_OWNER_SERVICE
// ACTUAL_FACADE_PENDING
// ACTUAL_FACADE_DRAIN
// ACTUAL_FACADE_ADMISSION
fn service(_: &mut diagnostic::Attempt)->Result<bool,DomainError>{
    // Controlled source/hardware cost; not a native latency or WCET claim.
    work(100_000);
    let phase=with(|s|Ok(s.phase))?;
    match phase{// ACTUAL_CLOSE
// ACTUAL_SEAL
 _=>{}}
    Ok(true)
}
pub fn reset(){
    GATE.store(false,Ordering::Release);CLOSED.store(0,Ordering::Release);BUSY.store(false,Ordering::Release);
    let state=Box::leak(Box::new(State{phase:Phase::CloseSources,scope:Some(Scope{key:1,observation:86_127_750_992,cleanup_deadline:101_127_750_992}),token:Some(2),cursor:0,
        prepared:Some(Prepared{source_count:4,sources:std::array::from_fn(|i|Source{owner:i as u64+1,class:[0,1,2,0][i]})}),work_activation:Activation(true),last_error:None,seal:None,records:0,retained:0,export_index:0,record_started:false,verification:None,partner:None,peer_staged:0}));
    ADDRESS.store(state as *mut State as usize,Ordering::Release);NOW.store(98_819_226_000,Ordering::Release);capture::reset();with(|_|Ok(())).unwrap();
}
pub fn invalidate(mode:u8){with(|s|{match mode{0=>s.phase=Phase::Verify,1=>s.scope=None,2=>s.token=None,3=>s.work_activation.0=false,_=>unreachable!()}Ok(())}).unwrap();}
pub fn context(mode:u8){with(|s|{match mode{0=>{capture::prepare_seal();s.phase=Phase::Seal},1=>s.phase=Phase::Verify,2=>s.phase=Phase::Run,3=>s.scope=None,4=>s.token=None,5=>s.work_activation.0=false,6=>s.phase=Phase::Drain,_=>unreachable!()}Ok(())}).unwrap();}
pub fn identity()->(Option<(u64,u64,u64)>,Option<u64>,bool){with(|s|Ok((s.scope.map(|v|(v.key,v.observation,v.cleanup_deadline)),s.token,s.work_activation.entered()))).unwrap()}
pub fn sealed()->Option<Seal>{with(|s|Ok(s.seal)).unwrap()}
pub fn facts()->(usize,u64,u64,bool){with(|s|Ok((s.cursor,s.scope.unwrap().key,s.token.unwrap(),s.phase==Phase::CloseSources))).unwrap()}
}
#[test]fn already_owned_source_gets_real_paid_progress(){
    reset();HINT.store(false,Ordering::Release);
    assert!(!learning_replay::owned_drain_pending(),"close must not authorize lifecycle");
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(learning_replay::CLOSED.load(Ordering::Acquire),1,"real paid helper lost already-owned CloseSources progress");
    assert_eq!(learning_replay::facts(),(1,1,2,true));
    assert_eq!(bills().iter().map(|b|b.1).sum::<u64>(),100_000,"close cost escaped real Scheduler debit");
    assert!(!COMPLETE_READY[0].load(Ordering::Acquire));
}
#[test]fn denied_credit_cannot_close_or_create_a_bill(){
    reset();HINT.store(false,Ordering::Release);assert!(learning_replay::baseline_activation_pending());READY.store(false,Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(learning_replay::CLOSED.load(Ordering::Acquire),0);
    assert_eq!(learning_replay::facts(),(0,1,2,true));assert!(bills().is_empty());
}
#[test]fn busy_source_keeps_original_custody_and_pays_attempt(){
    reset();HINT.store(false,Ordering::Release);learning_replay::BUSY.store(true,Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(learning_replay::CLOSED.load(Ordering::Acquire),0);
    assert_eq!(learning_replay::facts(),(0,1,2,true));
    assert_eq!(bills().iter().map(|b|b.1).sum::<u64>(),100_000,"busy source attempt lost paid scheduling custody");
    assert!(!learning_replay::owned_drain_pending());
}
#[test]fn unsettled_old_bill_prevents_source_close(){
    reset();HINT.store(false,Ordering::Release);
    assert!(learning_replay::baseline_activation_pending());assert!(begin_service_segment().is_some());work(71_000);
    DENY_SETTLE.store(true,Ordering::Release);complete_service(71_000,now_ns()).unwrap();
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(learning_replay::CLOSED.load(Ordering::Acquire),0);
    assert_eq!(learning_replay::facts(),(0,1,2,true));assert!(bills().is_empty());
    assert!(COMPLETE_READY[0].load(Ordering::Acquire));
    assert_eq!(COMPLETE_ACTUAL[0].load(Ordering::Acquire),71_000);
}

#[test]fn completed_or_unowned_source_grants_no_extra_turn(){
    for invalid in 0..4 {
        reset();HINT.store(false,Ordering::Release);learning_replay::invalidate(invalid);
        assert!(!learning_replay::baseline_activation_pending());assert!(!learning_replay::owned_drain_pending());
        mechanism_progress(&mut smp::prototype_runtime::Coordinator);
        assert_eq!(learning_replay::CLOSED.load(Ordering::Acquire),0);assert!(bills().is_empty());
    }
}

#[test]fn seal_gets_paid_service_without_deadline_renewal(){
    reset();HINT.store(false,Ordering::Release);learning_replay::context(0);
    let identity=learning_replay::identity();assert!(learning_replay::baseline_activation_pending());assert!(!learning_replay::owned_drain_pending());
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(bills().iter().map(|b|b.1).sum::<u64>(),100_000);
    assert_eq!(learning_replay::identity(),identity,"scheduling opportunity renewed original cleanup identity/deadline");
    assert_eq!(WORK.load(Ordering::Acquire),130_000,"controlled30us polls plus paid100us owner CPU must remain accounted");
}
#[test]fn close_and_seal_do_not_grant_ordinary_admission(){
    for phase in [None,Some(0)]{
        reset();HINT.store(false,Ordering::Release);if let Some(phase)=phase{learning_replay::context(phase);}
        service_segment(queue_warm).unwrap();let before=bills().len();let identity=learning_replay::identity();
        mechanism_progress(&mut smp::prototype_runtime::Coordinator);
        assert_eq!(CONSTRUCTIONS.load(Ordering::Acquire),0,"CloseSources/Seal service hint granted extra ordinary admission");
        assert_eq!(bills().len(),before+1,"CloseSources/Seal acquired a second admission credit");
        assert_eq!(learning_replay::identity(),identity,"pending service extended original scope/token/deadline");
    }
}
#[test]fn close_seal_require_scope_token_and_entered_activation(){
    for mode in 0..7{
        reset();HINT.store(false,Ordering::Release);learning_replay::context(mode);
        let service=learning_replay::baseline_activation_pending();let drain=learning_replay::owned_drain_pending();
        assert_eq!(service,matches!(mode,0|6));assert_eq!(drain,mode==6);
    }
}

#[test]fn four_actual_sources_seal_inside_unchanged_original_tail(){
 reset();HINT.store(false,Ordering::Release);let identity=learning_replay::identity();
 for _ in 0..6{mechanism_progress(&mut smp::prototype_runtime::Coordinator);}
 assert_eq!(learning_replay::CLOSED.load(Ordering::Acquire),4);
 let seal=learning_replay::sealed().expect("paid CloseSources/Seal never completed");
 assert!(seal.closing_ns<=101_127_750_992,"cleanup lost original five-second tail");assert_eq!(seal.exclusion,None);
 assert_eq!(learning_replay::identity(),identity);assert!(!learning_replay::baseline_activation_pending());
 let before=bills().len();mechanism_progress(&mut smp::prototype_runtime::Coordinator);assert_eq!(bills().len(),before,"already sealed capture received another service credit");
}
#[test]fn expired_tail_is_excluded_without_deadline_renewal(){
 reset();HINT.store(false,Ordering::Release);learning_replay::context(0);let identity=learning_replay::identity();
 NOW.store(101_127_750_993,Ordering::Release);mechanism_progress(&mut smp::prototype_runtime::Coordinator);
 let seal=learning_replay::sealed().expect("late capture must retain excluded seal");
 assert_eq!(seal.exclusion,Some(cyxia_prototype::learning::Error::Deadline),"late original tail was silently renewed");
 assert_eq!(learning_replay::identity(),identity);assert!(!learning_replay::baseline_activation_pending());
}
