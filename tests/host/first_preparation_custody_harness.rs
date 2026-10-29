//! Actual normal prefix, retry/retirement and Root first logic. Target owners,
//! model gate, activation callbacks and final encoding are controlled boundaries.
#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use std::sync::atomic::{AtomicU64,Ordering};
use cyxia_prototype::{domains::{Action,ApplyId,Error,ObjectKey},policy::{self,ModelBinding,Snapshot}};
static NOW:AtomicU64=AtomicU64::new(100_000_000);static ELAPSED:AtomicU64=AtomicU64::new(11);
static MODE:AtomicU64=AtomicU64::new(0);static BLOCKED:AtomicU64=AtomicU64::new(0);
fn now()->u64{NOW.load(Ordering::Acquire)}
pub mod cpu{pub fn slot()->usize{1}}
mod timer{pub fn cpu_ticks()->u64{0}pub fn cpu_elapsed_ns(_:u64)->u64{super::ELAPSED.load(super::Ordering::Acquire)}}
mod domain_platform{pub fn now_ns()->u64{super::now()}}
fn key(id:u64)->ObjectKey{ObjectKey{id,generation:1}}
// PREPARATION_MODULE
// ACTUAL_REJECTION_BANK
#[derive(Clone,Copy)]struct Family{domain:u16,kind:u16,target_source:()}
struct Context{core_generation:u64,ledger_generation:u64}
struct Owner{context:Context,families:[Option<Family>;18]}
struct Registry{model:ModelBinding}impl Registry{fn model(&self)->ModelBinding{self.model}}
struct Gate;impl Gate{fn check_active_publication(&self,_:ModelBinding,_:ObjectKey)->Result<(),Error>{if MODE.load(Ordering::Acquire)==1{Err(Error::Busy)}else{Ok(())}}}
struct State{boot:u64,sequence:u64,preparation:Option<preparation::Pending>,owner:Owner,registry:Registry,model_gate:Option<Gate>,family_cursor:usize,due:[u64;18],cursor:[usize;18],job:bool}
mod target_batch{pub struct Query;impl Query{pub fn fallback(_:u16,_:u16,_:usize)->Self{Self}pub fn exact(_:u16,_:u16,_:usize)->Self{Self}}}
fn read_target_batch(_:(),_:&[target_batch::Query],out:&mut[Option<ObjectKey>;2])->Result<(),Error>{*out=[Some(key(12)),None];Ok(())}
fn preparation_entry_detail(_:usize){}fn preparation_detail(_:usize){}fn preparation_prefix_detail(_:usize){}
fn preparation_lookup(_:usize,_:Family,_:usize,_:u64){}fn preparation_context(_:usize,_:Family,_:ObjectKey,_:u64){}
mod learning_canary{pub fn blocks_active()->bool{false}}
mod core_replay{use super::*;pub struct PaidWorkWitness;#[derive(Clone,Copy)]pub struct WorkId;impl WorkId{pub fn identity(self)->[u64;4]{[0;4]}}
 pub struct Measurement;impl Measurement{pub fn new<T>(_:T,_:&PaidWorkWitness)->Result<Self,Error>{Ok(Self)}}
 pub fn reject_preparation(_:[u64;4],_:u64,_:Error,_:u64)->Result<(),Error>{panic!("read-only retirement outside fixture")}}
struct JobSource{owner:ObjectKey,class:learning::reward::CpuClass,work:Option<core_replay::WorkId>}
mod learning{pub mod reward{pub enum CpuClass{Policy}}}
mod learning_evidence{pub struct OwnerAttempt;pub fn attempt(_:super::ObjectKey,_:super::learning::reward::CpuClass)->Result<Option<OwnerAttempt>,super::Error>{Ok(None)}pub fn finish_attempt(_: &mut OwnerAttempt,_:u64,_:u64)->Result<(),super::Error>{Ok(())}}
mod domain_tasks{pub fn finish_cpu_interval(_:u64)->(u64,u64,u64){(0,0,0)}}
const WINDOW_NS:u64=100_000_000;
// ACTUAL_PREPARATION_FUNCTIONS
fn next_locked_inner(s:&mut State,controller:u64,w:Option<&core_replay::PaidWorkWitness>,wall:u64,cpu:u64,input:&mut[u64;512])->Result<bool,Error>{
 if BLOCKED.load(Ordering::Acquire)!=0{return Ok(false)}
 next_normal(s,controller,w,wall,cpu,input)
}
// ACTUAL_NORMAL_PREFIX
mod replay{
 use super::*;use cyxia_prototype::learning::Family as LearningFamily;
 #[derive(Clone,Copy,PartialEq,Eq)]enum TrialKind{Baseline,Candidate}
 #[derive(Clone,Copy,PartialEq,Eq)]enum Phase{Running,Faulted,Complete}
 #[derive(Clone,Copy)]struct Token{id:u64,boot_epoch:u64,owner:ObjectKey}
 #[derive(Clone,Copy)]struct Request{family:LearningFamily,target:ObjectKey,kind:TrialKind,baseline:Action,not_before_ns:u64,owner:ObjectKey,on_first:fn(Token,Snapshot)->Result<(),Error>}
 #[derive(Clone,Copy)]struct Checks{owner:ObjectKey,before_first:fn(Token,Snapshot)->Result<(),Error>}
 struct Lifecycle;impl Lifecycle{fn closing(&self)->Option<()>{None}}
 #[derive(Clone,Copy)]struct Preparing{gate:bool,bound:Option<()>,failure:Option<Error>}
 struct Root{token:Option<Token>,request:Option<Request>,phase:Phase,first:Option<Snapshot>,first_ready:bool,initial:Option<ApplyId>,fault:Option<Error>,preparing:Option<Preparing>,spectator:Option<()>,lifecycle:Lifecycle,renew_after:u64,registered:[Option<Checks>;1]}
 static mut ROOT:Root=Root{token:None,request:None,phase:Phase::Complete,first:None,first_ready:false,initial:None,fault:None,preparing:None,spectator:None,lifecycle:Lifecycle,renew_after:0,registered:[None]};
 static ACTIVATION_TOKEN:AtomicU64=AtomicU64::new(0);static ACTIVATION_ATTEMPTS:AtomicU64=AtomicU64::new(0);static ACTIVATING:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
 fn root()->&'static Root{unsafe{&*core::ptr::addr_of!(ROOT)}}fn root_mut()->&'static mut Root{unsafe{&mut *core::ptr::addr_of_mut!(ROOT)}}
 // ACTUAL_ROOT_FUNCTIONS
 pub fn reset(){let r=root_mut();r.token=Some(Token{id:1,boot_epoch:1,owner:key(7)});r.request=Some(Request{family:LearningFamily{domain:1,kind:1},target:key(12),kind:TrialKind::Candidate,baseline:Action::CpuWeight(1),not_before_ns:0,owner:key(7),on_first:|_,_|if MODE.load(Ordering::Acquire)==2{Err(Error::Busy)}else{Ok(())}});r.phase=Phase::Running;r.first=None;r.first_ready=false;r.initial=None;r.fault=None;r.registered=[Some(Checks{owner:key(7),before_first:|_,_|if MODE.load(Ordering::Acquire)==3{Err(Error::Busy)}else{Ok(())}})];}
 pub fn first_snapshot()->Option<Snapshot>{root().first}pub fn error()->Option<Error>{root().fault}
 pub fn change(mode:u64){let r=root_mut();match mode{1=>r.request.as_mut().unwrap().kind=TrialKind::Baseline,2=>r.initial=Some(ApplyId::default()),3=>r.token.as_mut().unwrap().boot_epoch=2,4=>r.request.as_mut().unwrap().target.generation=2,5=>r.request.as_mut().unwrap().not_before_ns=now()+1_000_000_000,6=>r.phase=Phase::Faulted,7=>r.first=Some(Snapshot{sequence:41,taken_ns:99_000_000,core_generation:2,ledger_generation:3}),_=>()}}
}
fn fixture(mode:u64)->State{NOW.store(100_000_000,Ordering::Release);ELAPSED.store(11,Ordering::Release);MODE.store(mode,Ordering::Release);BLOCKED.store(0,Ordering::Release);replay::reset();unsafe{PREPARATION_REJECTIONS=preparation::Rejections::new()};State{boot:1,sequence:40,preparation:None,owner:Owner{context:Context{core_generation:2,ledger_generation:3},families:core::array::from_fn(|i|(i==0).then_some(Family{domain:1,kind:1,target_source:()}))},registry:Registry{model:ModelBinding::default()},model_gate:Some(Gate),family_cursor:0,due:[0;18],cursor:[0;18],job:false}}
fn step(s:&mut State)->Result<bool,Error>{next_locked(s,1,None,now(),0,&mut[0;512])}
#[test]fn first_preparation_custody_precedes_capture_callback_and_model_refusal(){
 for mode in [1,2,3,4]{let mut s=fixture(mode);let _=step(&mut s);let pending=s.preparation.expect("first preparation escaped without custody");assert_eq!(s.sequence,41);assert_eq!(pending.snapshot.sequence,41);assert_eq!(pending.snapshot.taken_ns,100_000_000);assert!(!s.job);assert_eq!(replay::first_snapshot().is_some(),mode!=3);
  MODE.store(4,Ordering::Release);NOW.fetch_add(1,Ordering::AcqRel);let _=step(&mut s);assert_eq!(s.sequence,41);assert_eq!(s.preparation.unwrap().snapshot,pending.snapshot);assert_eq!(s.preparation.unwrap().carried(pending.identity,0),Ok(22));
  NOW.store(150_000_001,Ordering::Release);BLOCKED.store(1,Ordering::Release);assert_eq!(step(&mut s),Err(Error::Expired),"blocked candidate first ignored its original deadline");assert!(s.preparation.is_none());assert_eq!(replay::error(),Some(Error::Expired));}
}
#[test]fn first_preparation_custody_preserves_terminal_stale_and_cpu_priority(){
 for cpu_overrun in [false,true]{let mut s=fixture(4);let _=step(&mut s);let p=s.preparation.expect("first preparation escaped without custody");s.owner.context.ledger_generation+=1;NOW.store(150_000_001,Ordering::Release);if cpu_overrun{ELAPSED.store(2_000_001,Ordering::Release)}let error=if cpu_overrun{Error::Budget}else{Error::Stale};assert_eq!(step(&mut s),Err(error));assert_eq!(replay::error(),Some(error));assert_eq!(replay::first_snapshot(),Some(p.snapshot));assert!(!s.job);assert!(s.preparation.is_none());}
}
#[test]fn first_preparation_custody_scope_excludes_baseline_published_foreign_and_not_before(){
 for change in 1..=7{let mut s=fixture(4);replay::change(change);assert!(!replay::first_preparation(1,Snapshot{sequence:41,taken_ns:now(),core_generation:2,ledger_generation:3},1,1,key(12)),"foreign first predicate accepted: {change}");let _=step(&mut s);assert!(s.preparation.is_none(),"foreign first acquired custody: {change}");assert_eq!(s.sequence,40);}
}
#[test]fn first_preparation_custody_success_carries_once_and_clears_before_outer_debit(){
 let mut s=fixture(4);let _=step(&mut s);let original=s.preparation.expect("first preparation escaped without custody");MODE.store(0,Ordering::Release);NOW.fetch_add(1,Ordering::AcqRel);assert_eq!(step(&mut s),Ok(true));assert!(s.job);assert!(s.preparation.is_none());assert_eq!(s.sequence,41);assert_eq!(replay::first_snapshot(),Some(original.snapshot));assert_eq!(replay::error(),None);
}

#[test]fn first_preparation_custody_before_capture_expiration_is_not_a_fabricated_root_first(){
 let mut s=fixture(3);let _=step(&mut s);let pending=s.preparation.unwrap();assert_eq!(replay::first_snapshot(),None);
 NOW.store(150_000_001,Ordering::Release);BLOCKED.store(1,Ordering::Release);assert_eq!(step(&mut s),Err(Error::Expired));assert_eq!(replay::first_snapshot(),None);assert_eq!(replay::error(),None);assert!(s.preparation.is_none());
 let journal=unsafe{&*core::ptr::addr_of!(PREPARATION_REJECTIONS)};assert_eq!(journal.total,1);let rejected=journal.rows[0].unwrap();assert_eq!(rejected.pending.snapshot,pending.snapshot);assert_eq!(rejected.reason,Error::Expired);assert!(rejected.pending.is_first_candidate());
}
#[test]fn first_preparation_custody_leaves_ordinary_and_readonly_blocked_pending_behavior_unchanged(){
 for readonly in [false,true]{let mut s=fixture(4);let identity=preparation::Identity{boot:1,controller:1,sequence:41,domain:1,kind:1,target:key(12),model:s.registry.model(),core_generation:2,ledger_generation:3,work:readonly.then_some([1;4])};
  s.preparation=Some(preparation::Pending::new(identity,Snapshot{sequence:41,taken_ns:100_000_000,core_generation:2,ledger_generation:3},0,0));s.sequence=41;BLOCKED.store(1,Ordering::Release);NOW.store(150_000_001,Ordering::Release);assert_eq!(step(&mut s),Ok(false));assert!(!s.preparation.unwrap().is_first_candidate());assert_eq!(replay::error(),None);}
 let mut s=fixture(4);let _=step(&mut s);s.registry.model.generation+=1;NOW.fetch_add(1,Ordering::AcqRel);assert_eq!(step(&mut s),Err(Error::Stale));assert_eq!(replay::error(),Some(Error::Stale));assert!(!s.job);
}
