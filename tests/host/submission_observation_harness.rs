#![allow(dead_code)]
use cyxia_prototype::{domains::*,features::*,policy::{self,*},policy_wire::*};
// ACTUAL_WIRE_FIXTURES
fn moment(wall_ns:u64,ns:u64)->PublicationTime{PublicationTime{wall_ns,cpu:CpuTime{cpu:1,ns}}}
struct Script{samples:Vec<PublicationTime>,reads:usize}
impl Clock for Script{fn read(&mut self)->PublicationTime{let value=*self.samples.get(self.reads).expect("extra protected clock read");self.reads+=1;value}}
#[derive(Clone,Debug)]struct Seen{stage:u8,result:Result<(),Error>,id:PlanId,version:u64,published:u64,prepared:bool}
#[derive(Default)]struct Owner{mode:u8,checks:usize,prepares:usize,revalidates:usize,publish_calls:usize,effects:usize,cancels:usize,authorizes:usize,seen:Vec<Seen>}
impl Executor for Owner{
 fn authorize_model(&mut self,active:ModelBinding,set:&RegisteredSet,_:u64)->Result<(),Error>{
  self.authorizes+=1;if self.mode==7||self.mode==8&&self.authorizes==3{return Err(Error::Busy)}
  if set.model==active{Ok(())}else{Err(Error::Stale)}}
 fn check(&mut self,_:Decision,_:&RegisteredSet,_:u64)->Result<(),Error>{self.checks+=1;if self.mode==1{Err(Error::Busy)}else{Ok(())}}
 fn prepare(&mut self,_:&Plan,_:u64)->Result<(),Error>{self.prepares+=1;if self.mode==2{Err(Error::Busy)}else{Ok(())}}
 fn revalidate(&mut self,_:&Plan,_:u64)->Result<(),Error>{self.revalidates+=1;if self.mode==3{Err(Error::Busy)}else{Ok(())}}
 fn publish(&mut self,_:&Plan,_:u64,_:u64)->Result<(),Error>{self.publish_calls+=1;if self.mode==4{return Err(Error::Busy)}self.effects+=1;Ok(())}
 fn cancel_prepared(&mut self,_:&Plan){self.cancels+=1;self.mode=9;}
 // ACTUAL_OBSERVER_OVERRIDE
}
fn setup(mode:u8)->(Registry,Vec<u8>,Owner,Script){let set=candidates();let mut r=Registry::new(11,publisher(),binding()).unwrap();r.register(publisher(),&set).unwrap();
 let cpus=match mode{5=>vec![1,2,500001,500002],6=>vec![1,2,3,4,500001],_=>vec![1,2,3,4,5]};
 let clock=Script{samples:cpus.into_iter().enumerate().map(|(i,c)|moment(11+i as u64,c)).collect(),reads:0};
 (r,frame(&set,1,0),Owner{mode,..Owner::default()},clock)}
fn observed(o:&Owner)->&Seen{o.seen.first().expect("Registry submit did not report its original result stage")}
#[test]fn submission_observer_keeps_original_callback_failure_stage_before_cleanup(){
 for (mode,stage,reads,checks,prepares,revalidates,publishes,cancels) in [
  (1,2,2,1,0,0,0,0),(2,4,2,1,1,0,0,1),(3,7,3,2,1,1,0,1),(4,14,5,2,1,1,1,1),(7,2,2,0,0,0,0,0),(8,10,4,2,1,1,0,1)]{
  let(mut r,wire,mut o,mut clock)=setup(mode);let receipt=r.submit_job(publisher(),&wire,moment(10,0),50_000_010,&mut clock,&mut o).unwrap();
  assert_eq!(receipt.version,0);assert_eq!(receipt.state(),ExecutionState::Failed(Error::Busy));
  assert_eq!((clock.reads,o.checks,o.prepares,o.revalidates,o.publish_calls,o.cancels),(reads,checks,prepares,revalidates,publishes,cancels));
  let seen=observed(&o);assert_eq!(seen.stage,stage,"cleanup replaced the failed submission phase");assert_eq!(seen.result,Err(Error::Busy));
  assert_eq!(seen.id,receipt.id);assert_eq!(seen.version,0);assert_eq!(seen.published,0);assert_eq!(seen.prepared,prepares!=0);assert_eq!(o.seen.len(),1);
 }
}
#[test]fn submission_observer_distinguishes_registry_budget_from_successful_callbacks(){
 let(mut r,wire,mut o,mut c)=setup(5);let receipt=r.submit_job(publisher(),&wire,moment(10,0),50_000_010,&mut c,&mut o).unwrap();
 assert_eq!(receipt.state(),ExecutionState::Failed(Error::Budget));assert!(r.optimization_stopped());assert_eq!(c.reads,4);
 assert_eq!((o.checks,o.prepares,o.revalidates,o.publish_calls,o.cancels),(2,1,1,0,1));
 let seen=observed(&o);assert_eq!(seen.stage,9);assert_eq!(seen.result,Err(Error::Budget));assert!(seen.prepared);
}
#[test]fn submission_observer_preserves_committed_receipt_after_final_cpu_overrun_and_duplicates(){
 let(mut r,wire,mut o,mut c)=setup(6);let receipt=r.submit_job(publisher(),&wire,moment(10,0),50_000_010,&mut c,&mut o).unwrap();
 assert_eq!(receipt.version,1);assert_eq!(receipt.published_ns,14);assert_eq!(receipt.state(),ExecutionState::Pending);assert!(r.optimization_stopped());
 assert_eq!((o.effects,o.cancels,c.reads),(1,0,5));let seen=observed(&o);assert_eq!(seen.stage,15);assert_eq!(seen.result,Ok(()));assert_eq!(seen.version,1);assert_eq!(seen.published,14);
 let same=r.submit_job(publisher(),&wire,moment(10,0),50_000_010,&mut c,&mut o).unwrap();assert_eq!(same,receipt);
 assert_eq!((o.effects,o.cancels,c.reads,o.seen.len()),(1,0,5,1),"cached receipt repeated observer or effects");
}
#[test]fn submission_observer_does_not_invent_evidence_for_early_or_stopped_rejection(){
 let(mut r,wire,mut o,mut c)=setup(0);let mut foreign=publisher();foreign.controller_epoch+=1;
 assert_eq!(r.submit_job(foreign,&wire,moment(10,0),50_000_010,&mut c,&mut o),Err(Error::Auth));assert!(o.seen.is_empty());assert_eq!(c.reads,0);
 r.stop_optimization();assert_eq!(r.submit_job(publisher(),&wire,moment(10,0),50_000_010,&mut c,&mut o),Err(Error::Budget));assert!(o.seen.is_empty());assert_eq!((c.reads,o.checks,o.effects),(0,0,0));
}
struct Plain{publishes:usize}
impl Executor for Plain{fn check(&mut self,_:Decision,_:&RegisteredSet,_:u64)->Result<(),Error>{Ok(())}fn prepare(&mut self,_:&Plan,_:u64)->Result<(),Error>{Ok(())}fn revalidate(&mut self,_:&Plan,_:u64)->Result<(),Error>{Ok(())}fn publish(&mut self,_:&Plan,_:u64,_:u64)->Result<(),Error>{self.publishes+=1;Ok(())}fn cancel_prepared(&mut self,_:&Plan){panic!("successful plain owner cancelled")}}
#[test]fn submission_observer_default_empty_backend_preserves_original_clock_and_result(){
 let(mut r,wire,_o,mut c)=setup(0);let mut owner=Plain{publishes:0};let receipt=r.submit_job(publisher(),&wire,moment(10,0),50_000_010,&mut c,&mut owner).unwrap();
 assert_eq!((receipt.version,owner.publishes,c.reads),(1,1,5));assert!(!r.optimization_stopped());
}
