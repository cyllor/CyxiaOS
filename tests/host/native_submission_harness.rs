#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use std::sync::atomic::{AtomicU64,Ordering};
use cyxia_prototype::{domains::*,features::*,policy::{self,*},policy_wire::{self,*}};
// WIRE_FIXTURES
// FACTS_MODULE
static CPU:AtomicU64=AtomicU64::new(0);static WALL:AtomicU64=AtomicU64::new(10);static READS:AtomicU64=AtomicU64::new(0);
static MODE:AtomicU64=AtomicU64::new(0);static SELECTIONS:AtomicU64=AtomicU64::new(0);static EFFECTS:AtomicU64=AtomicU64::new(0);
pub mod cpu{pub fn slot()->usize{1}}
mod timer{pub fn cpu_ticks()->u64{super::CPU.load(super::Ordering::Acquire)}pub fn cpu_ns(v:u64)->u64{v}}
fn now()->u64{READS.fetch_add(1,Ordering::AcqRel);CPU.fetch_add(1,Ordering::AcqRel);WALL.fetch_add(1,Ordering::AcqRel)+1}
mod domain_platform{pub fn now_ns()->u64{super::now()}}
struct NativeClock;
// NATIVE_CLOCK
#[derive(Clone,Copy)]struct Family{legal:fn(Action,ObjectKey,u64)->Result<(),Error>}
#[derive(Clone,Copy)]struct Desired{state:ExecutionState,execution_observed:bool}
#[derive(Clone,Copy)]struct Context{core_generation:u64,ledger_generation:u64}
struct Owner{context:Context,families:[Option<Family>;1],prepared:[usize;16],prepared_count:usize,desired:[Option<Desired>;1]}
fn require_control(_:&Owner)->Result<(),Error>{Ok(())} // Protected-role boundary.
fn family_index(_:u16,_:u16)->Result<usize,Error>{Ok(0)}
fn locate(_:&Owner,_:Action,_:ObjectKey)->Option<usize>{Some(0)}
fn bind_dependencies(_:&Owner,_:Action,_:ObjectKey,_:u64)->Result<[Option<BoundDependency>;2],Error>{Ok([None;2])}
fn validate_selection(_:&Owner,_:Family,_:Action,_:ObjectKey,_:u64)->Result<(),Error>{Ok(())}
// REPLACEMENT_PREDICATE
// SCOPE_TRAIT
struct Scope;
impl PublicationScope for Scope{
 fn authorize(&mut self,_:ModelBinding,_:&RegisteredSet,_:u64)->Result<(),Error>{if MODE.load(Ordering::Acquire)==5{Err(Error::Busy)}else{Ok(())}}
 fn legal(&self,_:Family,_:Action,_:ObjectKey,_:u64)->Result<(),Error>{if MODE.load(Ordering::Acquire)==1{Err(Error::Busy)}else{Ok(())}}
 fn dependencies(&self,_:&Owner,_:Action,_:ObjectKey,_:u64)->Result<[Option<BoundDependency>;2],Error>{if MODE.load(Ordering::Acquire)==6{Err(Error::Busy)}else{Ok([None;2])}}
 fn selection(&self,_:&Owner,_:Family,_:Action,_:ObjectKey,_:u64)->Result<(),Error>{let n=SELECTIONS.fetch_add(1,Ordering::AcqRel)+1;
  match MODE.load(Ordering::Acquire){2=>return Err(Error::Busy),7 if n==4=>{CPU.fetch_add(500001,Ordering::AcqRel);},8 if n==3=>{CPU.fetch_add(500001,Ordering::AcqRel);},_=>()};Ok(())}
 fn commit(&mut self,_:&Owner,_:ModelBinding,_:&Plan,_:&[PolicyStamp],_:u64,_:u64)->Result<(),Error>{if MODE.load(Ordering::Acquire)==4{Err(Error::Busy)}else{Ok(())}}
}
// NATIVE_EXECUTOR
// NATIVE_IMPL
// GET_FACTS
fn setup(mode:u64)->(policy::Registry,Vec<u8>,Owner){MODE.store(mode,Ordering::Release);CPU.store(0,Ordering::Release);WALL.store(10,Ordering::Release);READS.store(0,Ordering::Release);SELECTIONS.store(0,Ordering::Release);EFFECTS.store(0,Ordering::Release);
 let set=candidates();let mut registry=policy::Registry::new(11,publisher(),binding()).unwrap();registry.register(publisher(),&set).unwrap();
 let owner=Owner{context:Context{core_generation:2,ledger_generation:3},families:[Some(Family{legal:|_,_,_|Ok(())})],prepared:[0;16],prepared_count:0,
  desired:[(mode==3).then_some(Desired{state:ExecutionState::Pending,execution_observed:false})]};(registry,frame(&set,1,0),owner)}
fn run(mode:u64)->(policy::PlanReceipt,[u64;27],u64,bool){let(mut registry,wire,mut owner)=setup(mode);
 let start=policy::PublicationTime{wall_ns:10,cpu:policy::CpuTime{cpu:1,ns:0}};
 let mut executor=Executor{owner:&mut owner,scope:Scope,model:binding(),evidence:Some(0),job:1,boot:11,publication_started:start,wall_deadline:50_000_010,dependencies:[None;2],scores:[0;32],score_count:4,
 // FACTS_INITIALIZER
 };
 let receipt=registry.submit_job(publisher(),&wire,start,50_000_010,&mut NativeClock,&mut executor).unwrap();let facts=get_facts(&executor);
 (receipt,facts.words(Ok(receipt.version).and_then(|v|if v==0{match receipt.state(){ExecutionState::Failed(e)=>Err(e),_=>Err(Error::Conflict)}}else{Ok(v)}),false),READS.load(Ordering::Acquire),registry.optimization_stopped())}
#[test]fn native_submission_keeps_original_callback_failure_and_registry_stage(){
 for (mode,callback,stage,registry_stage) in [(1,4,6,2),(2,4,9,2),(3,4,8,2),(4,7,17,14),(5,1,3,2),(6,4,7,2)]{
  let(r,w,_,_)=run(mode);assert_eq!(r.version,0);assert_eq!(r.state(),ExecutionState::Failed(Error::Busy));
  assert_eq!(w[0],0x43595355424d0001,"native completion lost original submission provenance");assert_eq!(w[6],1);assert_eq!(w[7],registry_stage);assert_eq!(w[8],2);assert_eq!(w[9],Error::Busy as u64+1);
  assert_eq!(w[14],callback);assert_eq!(w[15],stage);assert_eq!(w[16],3);assert_eq!(w[17],Error::Busy as u64+1);assert_eq!(w[20],1);
  if mode==4{assert_eq!(w[19],1,"cleanup did not retain its separate cancellation fact");}
 }
}
#[test]fn native_submission_uses_original_precommit_cpu_sample_without_extra_clock(){
 let(r,w,reads,stopped)=run(7);assert_eq!(r.state(),ExecutionState::Failed(Error::Budget));assert!(stopped);assert_eq!(reads,6);
 assert_eq!(w[0],0x43595355424d0001,"native completion lost original submission provenance");assert_eq!((w[7],w[14],w[15],w[16],w[17]),(14,7,15,3,Error::Budget as u64+1));assert_eq!(EFFECTS.load(Ordering::Acquire),0);
}
#[test]fn native_submission_does_not_blame_successful_callback_for_registry_cpu_failure(){
 let(r,w,reads,stopped)=run(8);assert_eq!(r.state(),ExecutionState::Failed(Error::Budget));assert!(stopped);assert_eq!(reads,4);
 assert_eq!(w[0],0x43595355424d0001,"native completion lost original submission provenance");assert_eq!((w[7],w[9],w[14],w[15],w[16],w[17]),(9,Error::Budget as u64+1,6,7,2,0));assert_eq!(w[19],1);assert_eq!(EFFECTS.load(Ordering::Acquire),0);
}
