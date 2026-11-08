#![allow(dead_code)]
use std::sync::atomic::{AtomicU64,Ordering};
// BANK_MODULE
#[derive(Clone,Copy,PartialEq,Eq,Debug)]enum Error{Stale=2}
#[derive(Clone,Copy,PartialEq,Eq,Debug)]enum ExecutionState{Pending,Applied,Failed(Error),Unknown}
impl ExecutionState{fn terminal(self)->bool{matches!(self,Self::Applied|Self::Failed(_))}}
#[derive(Clone,Copy)]struct Family{domain:u16,kind:u16}
#[derive(Clone,Copy)]struct Request{trial_id:u64,family:Family,target:ObjectKey}
#[derive(Clone,Copy)]struct Token{boot_epoch:u64,id:u64}
#[derive(Clone,Copy)]struct ObjectKey{id:u64,generation:u64}
#[derive(Clone,Copy)]struct ApplyId{boot_epoch:u64,controller_epoch:u64,plan_seq:u64,action_index:u16,target:ObjectKey}
#[derive(Clone,Copy)]struct PolicyStamp{version:u64,snapshot_ns:u64,installed_until_ns:u64}
static LIVE_CALLS:AtomicU64=AtomicU64::new(0);
impl PolicyStamp{fn live(self,at:u64)->bool{LIVE_CALLS.fetch_add(1,Ordering::Relaxed);at<self.installed_until_ns}}
#[derive(Clone,Copy)]struct Action{one:bool}
impl Action{fn one_shot(self)->bool{self.one}fn domain(self)->u16{1}fn kind(self)->u16{1}}
#[derive(Clone,Copy)]struct Desired{action:Action,apply:ApplyId,stamp:PolicyStamp,state:ExecutionState,execution_observed:bool,started:bool,first_entry_ns:Option<u64>,observed_ns:u64,published:u64,job:u64}
#[derive(Clone,Copy)]struct Job{sequence:u64,controller:u64,cpu:usize,started:u64,completion:Option<()>}
struct Owner{desired:[Option<Desired>;16]}
struct State{job:Option<Job>,owner:Owner,registry:Registry}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum Phase{Quiescing,Scanning}
struct Root{phase:Phase,cursor:usize,hashing:Option<Sha256>}
struct Registry;impl Registry{fn model(&self)->Model{Model{model_hash:[0;32]}}}struct Model{model_hash:[u8;32]}
struct Sha256;impl Sha256{fn new()->Self{Self}fn update(&mut self,_:impl AsRef<[u8]>){}}
static READY:AtomicU64=AtomicU64::new(1);static READY_CALLS:AtomicU64=AtomicU64::new(0);static SKIP_CALLS:AtomicU64=AtomicU64::new(0);
mod fixture{use super::*;pub fn ready(_:&Root)->bool{READY_CALLS.fetch_add(1,Ordering::Relaxed);READY.load(Ordering::Relaxed)>0}pub fn skip_wait(_:&Root,_:&Desired)->bool{SKIP_CALLS.fetch_add(1,Ordering::Relaxed);false}}
// ACTUAL_PREDICATE
fn status(_:&State,r:&Root)->Result<Phase,Error>{Ok(r.phase)}
fn poll(s:&mut State,r:&mut Root,at:u64)->Result<Phase,Error>{let token=Token{boot_epoch:7,id:99};let q=Some(Request{trial_id:2,family:Family{domain:1,kind:1},target:ObjectKey{id:12,generation:3}});match r.phase{// ACTUAL_ARM
_=>{}}status(s,r)}
fn setup()->(State,Root){READY.store(1,Ordering::Relaxed);READY_CALLS.store(0,Ordering::Relaxed);SKIP_CALLS.store(0,Ordering::Relaxed);LIVE_CALLS.store(0,Ordering::Relaxed);(State{job:None,owner:Owner{desired:[None;16]},registry:Registry},Root{phase:Phase::Quiescing,cursor:0,hashing:None})}
fn desired(state:ExecutionState,observed:bool,one:bool)->Desired{Desired{action:Action{one},apply:ApplyId{boot_epoch:7,controller_epoch:2,plan_seq:51,action_index:0,target:ObjectKey{id:12,generation:3}},stamp:PolicyStamp{version:41,snapshot_ns:80,installed_until_ns:120},state,execution_observed:observed,started:true,first_entry_ns:Some(90),observed_ns:95,published:85,job:51}}
#[test]fn job_stops_before_any_owner_predicate(){let(mut s,mut r)=setup();s.job=Some(Job{sequence:23,controller:4,cpu:2,started:91,completion:None});assert_eq!(poll(&mut s,&mut r,100),Ok(Phase::Quiescing));let b=quiescing_diagnostic::snapshot();assert_eq!(b[16],1,"actual job gate was not retained");assert_eq!(&b[43..49],&[1,23,4,2,91,0]);assert_eq!(READY_CALLS.load(Ordering::Relaxed),0);assert_eq!(LIVE_CALLS.load(Ordering::Relaxed),0);}
#[test]fn actual_execution_and_live_lease_remain_blocking(){for(state,observed,reason)in[(ExecutionState::Pending,false,1),(ExecutionState::Unknown,false,1),(ExecutionState::Applied,false,2),(ExecutionState::Applied,true,4)]{let(mut s,mut r)=setup();s.owner.desired[3]=Some(desired(state,observed,false));assert_eq!(poll(&mut s,&mut r,100),Ok(Phase::Quiescing));let b=quiescing_diagnostic::snapshot();assert_eq!(b[21],4,"actual desired gate was not retained");assert_eq!(b[22],reason);assert_eq!(&b[23..29],&[7,2,51,0,12,3]);assert_eq!(&b[29..32],&[41,80,120]);assert_eq!(r.cursor,0);assert_eq!(READY_CALLS.load(Ordering::Relaxed),0);assert_eq!(LIVE_CALLS.load(Ordering::Relaxed),u64::from(reason==4));assert_eq!(SKIP_CALLS.load(Ordering::Relaxed),u64::from(reason==4));}}
#[test]fn eight_slots_then_fixture_and_scanning(){let(mut s,mut r)=setup();s.owner.desired[9]=Some(desired(ExecutionState::Applied,true,true));assert_eq!(poll(&mut s,&mut r,130),Ok(Phase::Quiescing));assert_eq!(r.cursor,8);assert_eq!(READY_CALLS.load(Ordering::Relaxed),0);READY.store(0,Ordering::Relaxed);assert_eq!(poll(&mut s,&mut r,131),Ok(Phase::Quiescing));let b=quiescing_diagnostic::snapshot();assert_eq!(b[16],5,"actual fixture wait was not retained");assert_eq!(r.cursor,16);READY.store(1,Ordering::Relaxed);assert_eq!(poll(&mut s,&mut r,132),Ok(Phase::Scanning));assert_eq!(quiescing_diagnostic::snapshot()[16],6);assert_eq!(READY_CALLS.load(Ordering::Relaxed),2);assert_eq!(LIVE_CALLS.load(Ordering::Relaxed),0);}
