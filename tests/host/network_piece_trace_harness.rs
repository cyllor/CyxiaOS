#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicBool,AtomicU64,AtomicUsize,Ordering};
use std::sync::Mutex;
use cyxia_prototype::domains::{Error,ObjectKey,WINDOW_NS,tasks::*,maintenance::{BackgroundBudgets,CpuDebit}};
static CPU:AtomicUsize=AtomicUsize::new(0);
static NOW:AtomicU64=AtomicU64::new(100_000_000);
static WORK:AtomicU64=AtomicU64::new(0);
static READY:AtomicBool=AtomicBool::new(true);
static DEFER:AtomicBool=AtomicBool::new(false);
static CORRUPT:AtomicU64=AtomicU64::new(0);
static CALLBACKS:AtomicU64=AtomicU64::new(0);
static OBSERVED:Mutex<Vec<[u64;64]>>=Mutex::new(Vec::new());
pub mod cpu{pub fn slot()->usize{super::CPU.load(super::Ordering::Relaxed)}}
mod timer{pub fn ticks()->u64{super::NOW.load(super::Ordering::Relaxed)}pub fn frequency()->u64{1_000_000_000}pub fn cpu_ticks()->u64{super::WORK.load(super::Ordering::Relaxed)}pub fn cpu_elapsed_ns(s:u64)->u64{cpu_ticks()-s}}
fn work(ns:u64){WORK.fetch_add(ns,Ordering::Relaxed);NOW.fetch_add(ns,Ordering::Relaxed);}
fn now_ns()->u64{timer::ticks()}
fn group(id:u64)->ObjectKey{ObjectKey{id,generation:1}}
struct Board;impl Board{fn now_ns(&self)->u64{now_ns()}fn now_ms(&self)->u64{now_ns()/1_000_000}}
const BUILTIN_WINDOW_HEADROOM_NS:u64=20_000_000;
static CREDIT_KIND:[AtomicU64;1]=[AtomicU64::new(0)];static CREDIT_NS:[AtomicU64;1]=[AtomicU64::new(0)];
static COMPLETE_READY:[AtomicBool;1]=[AtomicBool::new(false)];static COMPLETE_AT:[AtomicU64;1]=[AtomicU64::new(0)];static COMPLETE_ACTUAL:[AtomicU64;1]=[AtomicU64::new(0)];
struct Bank{words:[AtomicU64;32]}static DOMAIN_TASK_EVIDENCE:Bank=Bank{words:[const{AtomicU64::new(0)};32]};static TASK_OVERRUN_EVIDENCE:Bank=Bank{words:[const{AtomicU64::new(0)};32]};
#[derive(Clone,Copy)]struct Active{dispatch:Dispatch,state:RunState,optional:Option<CpuDebit>,cpu_started:Option<u64>}
struct Counter;impl Counter{fn add(&mut self,_:u64,_:u64){}}
struct Facts{cpu:[Counter;1]}
struct State{scheduler:Scheduler,active:[Option<Active>;1],layout:CpuLayout,draining:u64,service_admitted:bool,background:BackgroundBudgets,facts:Facts}
impl State{const fn new()->Self{Self{scheduler:Scheduler::new(),active:[None],layout:CpuLayout{business_mask:9,healthy_mask:15,generation:4},draining:0,service_admitted:false,background:BackgroundBudgets::new(),facts:Facts{cpu:[Counter]}}}}
static mut STATE:State=State::new();
struct ResettableGate(core::cell::UnsafeCell<owner_gate::Gate>);unsafe impl Sync for ResettableGate{}
impl core::ops::Deref for ResettableGate{type Target=owner_gate::Gate;fn deref(&self)->&Self::Target{unsafe{&*self.0.get()}}}
static mut HELD:Option<Guard>=None;
fn group_index(_: &State,_:ObjectKey)->Result<usize,Error>{Err(Error::NotFound)}
fn publish_evidence(_: &State){}
fn finish_cpu_interval(s:u64)->(u64,u64,u64){let at=now_ns();let n=timer::cpu_elapsed_ns(s);(at-n,at,n)}
fn track_credit(_:usize,r:Result<Option<Credit>,Error>)->Result<Option<Credit>,Error>{r}
fn finish_capture(_:usize,_:u64,_:u64){}
mod replay{pub fn service_admitted(){}}
mod baseline_diagnostics{pub fn failure(_:usize,_:u64){}}
mod capture_credit{pub fn retire(_:usize)->bool{true}pub fn available(_:usize)->bool{true}pub fn cancelled(_:usize,_:super::Dispatch,_:Option<super::CpuDebit>){}}
mod storage_fault_capture{pub const PROFILE:bool=false;}
mod learning_evidence{pub mod execution_trace{
 use super::super::{Dispatch,Error};
 pub fn cancelled(_:Dispatch,_:u64){}pub fn tracks_dispatch(_:Dispatch)->bool{false}
 pub struct Settlement{pub dispatch:Dispatch,pub actual_ns:u64,pub physical_finished_ns:u64,pub settled_ns:u64,pub before_version:Result<u64,Error>,pub after_version:Result<u64,Error>,pub still_active:bool,pub result:Result<(),Error>}
 pub fn settled(_:Settlement){}
}}
// DIAGNOSTIC_MODULE
pub mod domain_tasks{pub use super::{Credit,begin_service_segment,revalidate_service_segment,complete_service};pub fn service_baseline_progress(){super::service_segment(||{super::network_diagnostics::stage(62);super::work(17_000);});}}
mod unified_task{pub fn transport(_:bool){}}
fn service_stage(_:u64){}
fn fail(n:u64)->!{panic!("unexpected fail {n}")}
mod smp{pub mod prototype_runtime{#[derive(Default)]pub struct Coordinator;impl Coordinator{pub fn poll(&mut self){
 unsafe{if (&*core::ptr::addr_of!(super::super::HELD)).is_some(){
  assert!(super::super::COMPLETE_READY[0].load(super::super::Ordering::Relaxed));
  let before=super::super::network_diagnostics::snapshots().0;
  assert_ne!(before[8],0,"submitted network identity was absent during deferred settlement");
  super::super::CPU.store(1,super::super::Ordering::Relaxed);super::super::network_diagnostics::stage(63);super::super::CPU.store(0,super::super::Ordering::Relaxed);
  assert_eq!(super::super::network_diagnostics::snapshots().0,before);
  let mode=super::super::CORRUPT.load(super::super::Ordering::Relaxed);
  if mode==1{super::super::network_diagnostics::corrupt_pending(63,before[63]|1);}else if mode==2{super::super::network_diagnostics::corrupt_pending(9,before[9]+1);}else if mode==3{super::super::network_diagnostics::corrupt_pending(0,0);}else if mode==4{super::super::network_diagnostics::corrupt_pending(1,99);}
  let held=(&mut *core::ptr::addr_of_mut!(super::super::HELD)).take();drop(held);
  super::super::locked(|s|super::super::complete_locked(s,0)).unwrap();
  if mode!=0{for i in [0,1,9,63]{super::super::network_diagnostics::corrupt_pending(i,before[i]);}}
 }}super::super::work(11_000);
}}}}
mod domain_platform{pub fn poll(_:u64)->Result<(),super::Error>{super::work(13_000);Ok(())}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum TcpState{Closed,Established}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum TcpError{Device}
struct NativeTcp<'a>{mode:u8,_p:core::marker::PhantomData<&'a mut()>}
impl NativeTcp<'_>{fn state(&self)->Result<TcpState,TcpError>{Ok(TcpState::Closed)}fn poll_with_checkpoints(&mut self,_:u64,cp:&mut dyn FnMut())->Result<TcpState,TcpError>{
 network_diagnostics::stage(1);CPU.store(1,Ordering::Relaxed);network_diagnostics::stage(63);CPU.store(0,Ordering::Relaxed);work(if self.mode==2{2_603_169}else{100_000});
 if self.mode==3{network_diagnostics::stage(2);network_diagnostics::stage(2);}
 if self.mode==2{return Err(TcpError::Device)}
 if DEFER.load(Ordering::Relaxed){unsafe{HELD=Some(acquire_guard().unwrap());}}
 CALLBACKS.fetch_add(1,Ordering::Relaxed);cp();OBSERVED.lock().unwrap().push(network_diagnostics::snapshots().1);
 if self.mode==1{return Err(TcpError::Device)} // New continuation has Unknown stage, not the helper's stage.
 network_diagnostics::stage(2);work(80_000);CALLBACKS.fetch_add(1,Ordering::Relaxed);cp();OBSERVED.lock().unwrap().push(network_diagnostics::snapshots().1);
 network_diagnostics::stage(3);work(66_000);Ok(TcpState::Established)
}}
fn drain_network(_: &mut NativeTcp<'_>,_:u64){OBSERVED.lock().unwrap().push(network_diagnostics::snapshots().1);work(55_000);}
// PRODUCTION_BODIES
fn setup(){
 CPU.store(0,Ordering::Relaxed);NOW.store(100_000_000,Ordering::Relaxed);WORK.store(0,Ordering::Relaxed);READY.store(true,Ordering::Relaxed);DEFER.store(false,Ordering::Relaxed);CORRUPT.store(0,Ordering::Relaxed);CALLBACKS.store(0,Ordering::Relaxed);OBSERVED.lock().unwrap().clear();
 unsafe{drop((&mut *core::ptr::addr_of_mut!(HELD)).take());*LOCK.0.get()=owner_gate::Gate::new();*core::ptr::addr_of_mut!(STATE)=State::new();}
 for a in [&CREDIT_KIND,&CREDIT_NS,&COMPLETE_AT,&COMPLETE_ACTUAL]{a[0].store(0,Ordering::Relaxed);}COMPLETE_READY[0].store(false,Ordering::Relaxed);network_diagnostics::reset();locked(|s|s.scheduler.register_group(group(14))).unwrap();
}
fn run(mode:u8)->Result<TcpState,TcpError>{network_turn(&mut smp::prototype_runtime::Coordinator,&mut Some(NativeTcp{mode,_p:core::marker::PhantomData}),1)}
fn row(b:&[u64;64])->&[u64]{&b[8..31]}
#[test]fn actual_pieces_have_exact_original_identity_cpu_and_finish(){setup();assert_eq!(run(0),Ok(TcpState::Established));let mut rows=OBSERVED.lock().unwrap().clone();rows.push(network_diagnostics::snapshots().1);assert_eq!(rows.len(),4);let mut prior=0;
 for(i,(b,actual))in rows.iter().zip([100_000,80_000,66_000,55_000]).enumerate(){let r=row(b);let stage=if i==3{27}else{i as u64+1};assert_ne!(r[0],0,"actual network settlement identity was absent");assert!(r[0]>prior,"new reservation reused prior network diagnostic");prior=r[0];assert_eq!(&r[1..3],&[257,1]);assert_eq!(r[5],0);assert_eq!(r[6],4);assert_eq!(r[9],2_500_000);assert_eq!(r[14],i as u64);assert_eq!(r[15],stage);assert_eq!(r[16],stage,"foreign CPU or helper relabeled network piece");assert_eq!(r[17],1<<stage,"foreign CPU or helper relabeled network piece");assert_eq!(r[19],actual);assert_eq!(r[20],r[8]+actual,"network finish absorbed nested progress");assert_eq!(r[21],1);assert_eq!(r[22],0);assert_eq!(b[63]&1,0);}
 assert_eq!(CALLBACKS.load(Ordering::Relaxed),2);assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(group(257))).unwrap(),352_000);
}
#[test]fn deferred_bill_keeps_the_original_network_piece_across_nested_helper(){setup();DEFER.store(true,Ordering::Relaxed);assert_eq!(run(0),Ok(TcpState::Established));let b=OBSERVED.lock().unwrap()[0];assert_eq!(row(&b)[19],100_000);assert_eq!(row(&b)[15],1);assert_eq!(row(&b)[17],2);assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(group(257))).unwrap(),352_000);}
#[test]fn multiple_operations_share_one_bill_and_the_next_piece_starts_empty(){setup();assert_eq!(run(3),Ok(TcpState::Established));let records=OBSERVED.lock().unwrap();assert_eq!(&row(&records[0])[15..19],&[1,2,6,3]);assert_eq!(&row(&records[1])[15..19],&[2,2,4,1],"new continuation inherited the prior stage set");assert_eq!(row(&records[0])[19],100_000);assert_eq!(row(&records[1])[19],80_000);}
#[test]fn error_after_checkpoint_does_not_inherit_the_helper_stage(){setup();assert_eq!(run(1),Err(TcpError::Device));let b=network_diagnostics::snapshots().1;assert_ne!(row(&b)[0],0,"error continuation lost its real bill");assert_eq!(row(&b)[14],1);assert_eq!(&row(&b)[15..19],&[0,0,0,0]);assert_eq!(row(&b)[19],0);assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(group(257))).unwrap(),117_000);}
#[test]fn corrupt_pending_is_ignored_without_changing_real_settlement(){for mode in [1,2,3,4]{setup();DEFER.store(true,Ordering::Relaxed);CORRUPT.store(mode,Ordering::Relaxed);assert_eq!(run(0),Ok(TcpState::Established));let b=network_diagnostics::snapshots().1;assert!(b[3]+b[4]>0,"invalid pending snapshot was silently accepted");assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(group(257))).unwrap(),352_000);}}
#[test]fn sticky_overrun_comes_from_the_real_scheduler_completion(){setup();assert_eq!(run(2),Err(TcpError::Device));let b=network_diagnostics::snapshots().1;assert_ne!(b[36],0,"actual network overrun was not retained");assert_eq!(&b[55..57],&[2_603_169,102_603_169]);assert_eq!(b[57],2|((Error::Budget as u64+1)<<8));assert_eq!(b[58],0);assert_eq!(locked(|s|Ok(s.scheduler.stats().quarantine_mask)).unwrap(),1);assert_eq!(TASK_OVERRUN_EVIDENCE.words[6].load(Ordering::Relaxed),2_603_169);
 NOW.store(200_000_000,Ordering::Relaxed);locked(|s|{s.layout.generation+=1;s.scheduler.recover_cpu(0,s.layout,now_ns())}).unwrap();assert_eq!(run(0),Ok(TcpState::Established));assert_eq!(&network_diagnostics::snapshots().1[36..59],&b[36..59],"later success overwrote first physical overrun");
 assert_eq!(run(2),Err(TcpError::Device));assert_eq!(&network_diagnostics::snapshots().1[36..59],&b[36..59],"later overrun overwrote first physical overrun");assert_eq!(network_diagnostics::snapshots().1[5],2);
}
#[test]fn no_fresh_credit_and_bad_binding_do_not_create_authority(){setup();locked(|s|{s.draining=1;Ok(())}).unwrap();assert_eq!(run(0),Ok(TcpState::Closed));assert_eq!(WORK.load(Ordering::Relaxed),0);assert_eq!(network_diagnostics::snapshots().0[8],0);
 locked(|s|{s.draining=0;Ok(())}).unwrap();let c=begin_service_segment().unwrap();assert!(revalidate_service_segment());assert!(network_diagnostics::begin(c.sequence+1,c.thread,c.reserved_ns,9,0).is_none());assert_eq!(network_diagnostics::snapshots().0[3],1,"binding mismatch was not explicit");work(17_000);complete_service(17_000,now_ns()).unwrap();assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(group(257))).unwrap(),17_000);assert_eq!(network_diagnostics::snapshots().1[8],0);
}
#[test]fn retained_active_budget_error_is_not_a_physical_overrun(){for actual in [100_000,2_603_169]{setup();let c=begin_service_segment().unwrap();assert!(revalidate_service_segment());let d=locked(|s|Ok(s.active[0].unwrap().dispatch)).unwrap();let ticket=network_diagnostics::begin(c.sequence,c.thread,c.reserved_ns,1,0);network_diagnostics::stage(6);work(actual);network_diagnostics::finish(ticket,actual,now_ns());
 // Controlled scheduler-result boundaries test serialization; the subsequent
 // complete_service executes the real Scheduler result without alteration.
 network_diagnostics::settled(d,actual,now_ns(),Err(Error::Budget),true);let b=network_diagnostics::snapshots().1;assert_eq!(b[30],1);assert_eq!(b[36],0,"retained Budget attempt became a physical overrun");
 if actual<d.reserved_ns{network_diagnostics::settled(d,actual,now_ns(),Err(Error::Budget),false);assert_eq!(network_diagnostics::snapshots().1[36],0,"Budget code without excess CPU became physical overrun");}
 assert_eq!(complete_service(actual,now_ns()),if actual>d.reserved_ns{Err(Error::Budget)}else{Ok(())});let b=network_diagnostics::snapshots().1;assert_eq!(b[30],0);assert_eq!(b[29],if actual>d.reserved_ns{2|((Error::Budget as u64+1)<<8)}else{1});assert_eq!(b[36]!=0,actual>d.reserved_ns);
}}
