#![allow(dead_code, unused_imports)]
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicBool,AtomicU64,Ordering};
use std::sync::Mutex;
use cyxia_prototype::{domains::{Action,ApplyId,Error,ObjectKey,PolicyStamp,tasks::*},learning::{Family,capture::RunKey,reward::{CpuClass,RequestResult}},policy::ExecutionState};
const fn key(id:u64)->ObjectKey {ObjectKey{id,generation:1}}
const RUN:RunKey=RunKey{boot_epoch:7,trial_id:9,generation:3};
const CALLER:ObjectKey=key(88);
static WALL:AtomicU64=AtomicU64::new(200_000_000);
pub mod cpu {pub fn slot()->usize{0}}
fn now()->u64{WALL.load(Ordering::Acquire)}
mod timer{pub fn ticks()->u64{super::now()}pub fn frequency()->u64{1_000_000_000}}
// TRACE_MODULE
fn arm(){
 trace::reset_for_host();WALL.store(200_000_000,Ordering::Release);
 trace::begin(RUN,Family{domain:1,kind:1},key(12),100_000_000);
 trace::closing(key(12),100_000_000,ApplyId{boot_epoch:7,controller_epoch:2,plan_seq:51,action_index:0,target:key(12)},PolicyStamp{version:42,snapshot_ns:190_000_000,installed_until_ns:10_190_000_000},190_001_000,240_001_000,190_002_000);
 assert_eq!(trace::closing_identity_for_host(),(42,42),"each fixture must publish its own closing identity");
}
fn wait(id:u64){trace::drain_work(RUN,trace::WorkWait{counts:[0,1,0],request:[id,2,1,4,0],warm:[0;3],background_done:true},false,now());}
mod evidence {
 pub(crate) use super::trace as execution_trace;
 pub fn measure<R>(_:super::ObjectKey,_:super::CpuClass,f:impl FnOnce()->R)->R{f()}
 pub fn request(_:super::ObjectKey,id:u64)->Result<u64,super::Error>{Ok(id)}
 pub fn arm_scheduled(_:u64)->Result<(),super::Error>{Ok(())}
 pub fn result(_:u64,_:super::RequestResult)->Result<(),super::Error>{Ok(())}
}
mod learning_evidence {pub(crate) use super::trace as execution_trace;pub use super::evidence::measure;}
mod learning_prewarm {pub fn poll(_:super::RunKey)->Result<bool,super::Error>{Ok(true)}}
mod domain_platform {pub mod irq_replay {pub fn poll(_:crate::RunKey)->Result<(),crate::Error>{Ok(())}}}
mod domain_tasks {pub mod replay {pub fn within_work<R>(f:impl FnOnce()->R)->R{f()}}}
mod work {
 use super::*;
 const OWNER:ObjectKey=key(44);const REQUESTS:usize=100;const REQUEST_DEADLINE_NS:u64=5_000_000_000;
 #[derive(Clone,Copy,PartialEq,Eq)] enum Phase{Queued,Active,Settled}
 #[derive(Clone,Copy)]struct Request{phase:Phase,outcome:RequestResult,reported:bool,armed:bool}
 #[derive(Clone,Copy)]struct Scope{key:RunKey,family:Family,observation_ns:u64}
 #[derive(Clone,Copy)]struct Warm{id:u64,deadline:u64,active:bool}
 struct Background;impl Background{fn settled(&self)->bool{true}fn poll(&mut self,_:u64,_:u64,_:u64,_:&mut OptionalEcho)->Result<(),Error>{Ok(())}}
 struct OptionalEcho;
 struct State{run:Option<RunKey>,activated:bool,family:Option<Family>,scope:Option<Scope>,requests:[Request;100],fault:Option<Error>,warm:Option<Warm>,seed:u64,cursor:usize,background:Background}
 const DONE:Request=Request{phase:Phase::Settled,outcome:RequestResult::TimedOut,reported:true,armed:true};
 static STATE:Mutex<State>=Mutex::new(State{run:Some(RUN),activated:true,family:Some(Family{domain:1,kind:1}),scope:Some(Scope{key:RUN,family:Family{domain:1,kind:1},observation_ns:100_000_000}),requests:[DONE;100],fault:None,warm:None,seed:1,cursor:0,background:Background});
 fn with<R>(f:impl FnOnce(&mut State)->Result<R,Error>)->Result<R,Error>{let mut guard=STATE.try_lock().map_err(|_|Error::Busy)?;f(&mut guard)}
 fn owner()->Result<(),Error>{Ok(())}fn one_shot(_:Family)->bool{false}fn uses_file(_:Family)->bool{false}
 fn warm(_: &mut State,_:Family,_:u64,_:u64)->Result<(),Error>{Ok(())}
 fn transient(e:Error)->bool{matches!(e,Error::Again|Error::Busy|Error::NotReady|Error::Budget|Error::Capacity)}
 fn poll_native(_:RunKey,_:u64,e:Error)->Error{e}
 fn submit(_:Family,_:u64,_:u64,_:u64,_:u64)->Result<(),Error>{Err(Error::Again)}
 static OUTCOMES:AtomicU64=AtomicU64::new(0);
 fn outcome(_:Family,_:u64)->Result<Option<Result<u64,Error>>,Error>{OUTCOMES.fetch_add(1,Ordering::Relaxed);Err(Error::Busy)}
 // WORK_POLL
 pub fn scenario(){
  {let mut s=STATE.lock().unwrap();s.requests=[DONE;100];s.requests[4]=Request{phase:Phase::Queued,outcome:RequestResult::Pending,reported:false,armed:true};s.requests[6]=Request{phase:Phase::Active,outcome:RequestResult::Pending,reported:false,armed:true};s.requests[8]=Request{reported:false,..DONE};s.warm=Some(Warm{id:107,deadline:5_100_000_000,active:true});}
  OUTCOMES.store(0,Ordering::Relaxed);
  assert_eq!(poll(RUN),Ok(false));
  let (w,_)=trace::drain_snapshots();
  assert_eq!(&w[9..12],&[1,1,0],"actual Work wait facts were absent");
  assert_eq!(&w[12..17],&[5,1,1,4,0]);
  assert_eq!(&w[17..20],&[107,5_100_000_000,1]);
  assert_eq!(OUTCOMES.load(Ordering::Relaxed),4,"diagnostics performed extra outcome queries");
  {let mut s=STATE.lock().unwrap();s.requests=[DONE;100];}
  WALL.fetch_add(1_000,Ordering::AcqRel);assert_eq!(poll(RUN),Ok(false));
  let (w,_)=trace::drain_snapshots();assert_eq!(w[45],107,"warm-only blocker lost its original request identity");
  {STATE.lock().unwrap().warm=None;}WALL.fetch_add(1_000,Ordering::AcqRel);assert_eq!(poll(RUN),Ok(true));
  assert_eq!(trace::drain_snapshots().0[7],now());
 }
}
mod task {
 use super::*;
 // OWNER_GATE
 static READY:AtomicBool=AtomicBool::new(true);
 static RETURN_PENDING:[AtomicBool;2]=[const{AtomicBool::new(false)};2];
 static FILE_BUSY:[AtomicBool;2]=[const{AtomicBool::new(false)};2];
 static FILE_DONE:[AtomicBool;2]=[const{AtomicBool::new(false)};2];
 static FILE_PENDING:[AtomicBool;2]=[const{AtomicBool::new(false)};2];
 #[derive(Clone,Copy,PartialEq,Eq)]enum Life{Free,Ready,Running,Waiting,Exiting}
 #[derive(Clone,Copy)]struct Task{key:ObjectKey,parent:ObjectKey,spawn_id:u64,life:Life,deadline:u64,exit_code:u64,recipe:u16}
 #[derive(Clone,Copy)]struct ExitRecord{key:ObjectKey,parent:ObjectKey,code:u64,value:u64,finished_ns:u64}
 #[derive(Clone,Copy)]struct Active{dispatch:Dispatch}
 struct Replay{run:Option<RunKey>,actor:ObjectKey,delivered:[Option<Result<u64,Error>>;256],expected:[u64;256],deadlines:[u64;256]}
 static mut REPLAY:Replay=Replay{run:Some(RUN),actor:CALLER,delivered:[None;256],expected:[55;256],deadlines:[5_000_000_000;256]};
 struct State{tasks:[Task;2],exits:[Option<ExitRecord>;2],active:[Option<Active>;4],admission:SpawnAdmission}
 const EMPTY:Task=Task{key:key(0),parent:key(0),spawn_id:0,life:Life::Free,deadline:0,exit_code:0,recipe:0};
 static mut STATE:State=State{tasks:[EMPTY;2],exits:[None;2],active:[None;4],admission:SpawnAdmission::new()};
 const TASKS:usize=2;const ZERO:ObjectKey=key(0);
 static CLEANUP_BUSY:AtomicBool=AtomicBool::new(false);static CLEANS:AtomicU64=AtomicU64::new(0);
 pub struct Context;impl Context{const fn empty()->Self{Self}}
 static mut CONTEXTS:[Context;2]=[Context::empty(),Context::empty()];
 mod user{pub use super::Context;}
 fn now_ns()->u64{now()}fn group(id:u64)->ObjectKey{key(id)}fn owner()->Result<(),Error>{Ok(())}fn index(id:u64)->Result<usize,Error>{usize::try_from(id).map_err(|_|Error::Range)}
 fn state()->&'static mut Replay{unsafe{&mut *core::ptr::addr_of_mut!(REPLAY)}}
 fn wake_task(_: &mut State,_:usize){}
 unsafe fn process_return(s:&mut State,i:usize,_:&mut Context){RETURN_PENDING[i].store(false,Ordering::Release);s.tasks[i].life=Life::Exiting;}
 fn cleanup_inner(s:&mut State,i:usize)->Result<(),Error>{
  CLEANS.fetch_add(1,Ordering::Relaxed);
  if CLEANUP_BUSY.load(Ordering::Relaxed)||FILE_BUSY[i].load(Ordering::Relaxed)||s.active.iter().flatten().any(|a|a.dispatch.thread==s.tasks[i].key){return Err(Error::Busy)}
  let t=s.tasks[i];s.exits[0]=Some(ExitRecord{key:t.key,parent:t.parent,code:0,value:55,finished_ns:now()});s.tasks[i]=EMPTY;Ok(())
 }
 mod replay{use super::*;pub fn work_source(_:ObjectKey,_:u64,_:u16)->Option<ObjectKey>{Some(key(44))}pub(super)use super::drain_task_facts;}
 // TASK_BODIES
 // SPAWN_QUERY
 struct Creator;impl TaskBackend for Creator{
  fn authorize(&mut self,_:&SpawnRequest)->Result<(),Error>{Ok(())}
  fn create(&mut self,_:&SpawnRequest)->CreateOutcome{CreateOutcome::Created(key(4096))}
 }
 pub fn prepare(){locked(|s|{
  *s=State{tasks:[Task{key:key(4096),parent:CALLER,spawn_id:7,life:Life::Waiting,deadline:5_000_000_000,exit_code:0,recipe:0},EMPTY],exits:[None;2],active:[None;4],admission:SpawnAdmission::new()};
  let r=state();r.delivered=[None;256];r.run=Some(RUN);r.actor=CALLER;
  s.admission.register_group(key(12))?;
  s.admission.submit(SpawnRequest{caller:CALLER,request_id:7,package:key(2),group:key(12),payload_hash:[0;32],recovery:false},now(),&mut Creator)?;
  s.admission.service_one(now(),&mut Creator)?;Ok(())}).unwrap();CLEANS.store(0,Ordering::Relaxed);RETURN_PENDING[0].store(false,Ordering::Release);FILE_BUSY[0].store(false,Ordering::Release);CLEANUP_BUSY.store(false,Ordering::Release);}
 pub fn query_scenario(){
  RETURN_PENDING[0].store(true,Ordering::Release);FILE_BUSY[0].store(true,Ordering::Release);
  assert_eq!(spawn_result(7),Ok(None));let (_,t)=trace::drain_snapshots();
  assert_eq!(&t[16..21],&[now(),7,88,1,2],"actual spawn query facts were absent");
  assert_eq!(&t[21..25],&[4096,1,4,3]);
  let mut scheduler=Scheduler::new();scheduler.register_group(key(12)).unwrap();
  let layout=CpuLayout{business_mask:9,healthy_mask:15,generation:1};
  scheduler.admit(ThreadSpec{key:key(4096),group:key(12),cpu:3,allowed_mask:8,minimum_ns:0,budget_ns:20_000_000},layout,now()).unwrap();
  let dispatch=scheduler.dispatch(3,layout,now(),1_000_000).unwrap().unwrap();
  locked(|s|{s.active[3]=Some(Active{dispatch});Ok(())}).unwrap();
  FILE_BUSY[0].store(false,Ordering::Release);assert_eq!(spawn_result(7),Ok(None));
  assert_eq!(trace::drain_snapshots().1[24],5,"a real active dispatch disappeared from query facts");
  scheduler.complete(dispatch,10_000,RunState::Runnable,now()+10_000).unwrap();
  locked(|s|{s.active[3]=None;Ok(())}).unwrap();
  locked(|s|{s.exits[0]=Some(ExitRecord{key:key(4096),parent:CALLER,code:0,value:55,finished_ns:190_000_000});Ok(())}).unwrap();
  assert_eq!(spawn_result(7),Ok(Some(Ok(190_000_000))));
  assert!(locked(|s|Ok(s.exits[0].is_none())).unwrap(),"query did not consume its one actual exit");
  assert_eq!(spawn_result(7),Ok(Some(Ok(190_000_000))));
  let (_,t)=trace::drain_snapshots();assert_eq!(t[20],6,"cached delivery manufactured a new queue query");assert_eq!(t[29],190_000_000);
  wait(11);assert_eq!(spawn_result(11),Err(Error::NotFound));
  assert_eq!(trace::drain_snapshots().1[36],7|((Error::NotFound as u64+1)<<8),"query error lost its original domain code");
 }
 pub fn lifecycle_scenario(){
  locked(|s|{s.tasks[0].life=Life::Exiting;Ok(())}).unwrap();CLEANUP_BUSY.store(true,Ordering::Release);
  locked(|s|{lifecycle_piece(s,0);Ok(())}).unwrap();let (_,t)=trace::drain_snapshots();
  assert_eq!(t[51],4096,"actual lifecycle selection facts were absent");
  assert_eq!(t[91],5|((Error::Busy as u64+1)<<8),"actual cleanup result facts were absent");
  assert_eq!(spawn_result(7),Ok(None));CLEANUP_BUSY.store(false,Ordering::Release);WALL.fetch_add(1_000,Ordering::AcqRel);
  locked(|s|{lifecycle_piece(s,0);Ok(())}).unwrap();
  assert_eq!(CLEANS.load(Ordering::Relaxed),2);assert_eq!(spawn_result(7),Ok(Some(Ok(now()))));
  let (_,t)=trace::drain_snapshots();assert_eq!(t[91],2);assert_eq!(t[92],1,"cleanup lost post-operation Free state");
 }
}
#[test]fn work_poll_distinguishes_request_and_warm_custody(){arm();work::scenario();}
#[test]fn actual_spawn_query_keeps_identity_and_never_consumes_an_extra_outcome(){arm();wait(7);task::prepare();task::query_scenario();}
#[test]fn actual_lifecycle_and_cleanup_keep_the_original_child(){arm();wait(7);task::prepare();task::lifecycle_scenario();}
#[test]fn watches_keep_scope_first_blocker_and_even_publication(){
 arm();wait(7);let first=trace::drain_watch(RUN,7);assert!(first.is_some(),"first watch was not retained");
 WALL.fetch_add(1_000,Ordering::AcqRel);wait(8);assert!(trace::drain_watch(RUN,7).is_some());assert!(trace::drain_watch(RUN,8).is_some());
 trace::interrupted_work_publication(true);assert!(trace::drain_watch(RUN,8).is_none(),"an odd Work publication was accepted");trace::interrupted_work_publication(false);
 assert!(trace::drain_watch(RunKey{trial_id:10,..RUN},7).is_none());
 trace::close(RUN,now());let frozen=trace::drain_snapshots();wait(9);assert_eq!(trace::drain_snapshots(),frozen);assert!(trace::drain_watch(RUN,7).is_none());
 assert_eq!(frozen.0[63]&1,0);assert_eq!(frozen.1[127]&1,0);
}
