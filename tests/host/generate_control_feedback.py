from pathlib import Path
import hashlib
import json

import sys
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
SOURCES = {}

def extract(rel, signature):
    source = (ROOT / rel).read_text()
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    for at in range(opening + 1, len(source)):
        depth += (source[at] == '{') - (source[at] == '}')
        if depth == 0:
            body = source[start:at + 1]
            SOURCES[f'{rel}::{signature}'] = hashlib.sha256(body.encode()).hexdigest()
            return body
    raise ValueError(signature)

network = ROOT / 'kernel/src/domain_network.rs'
nsrc = network.read_text()
network_code = '''use super::*;
use abi::{DomainFeedback,PolicyReceiptWire,PolicyWire,Shared};
use core::sync::atomic::AtomicBool;
#[derive(Clone,Copy)] struct ReadView {ready:bool,feedback:DomainFeedback}
#[derive(Clone,Copy)]
'''+extract('kernel/src/domain_network.rs','struct Desired {')+'''
static READY:AtomicBool=AtomicBool::new(true);
static mut DESIRED:[Option<Desired>;4]=[None;4];
static mut EFFECTIVE:[Option<Desired>;3]=[None;3];
fn publish_view() {} // CPU0-only fixture: no concurrent read-snapshot consumer.
fn inspect_view<R>(f:impl FnOnce(&ReadView)->Result<R,Error>)->Result<R,Error>{
  f(&ReadView{ready:READY.load(Ordering::Acquire),feedback:unsafe{*core::ptr::addr_of!(FEEDBACK)}})
}
mod placement_legal { pub fn legal(_:u16,_:ObjectKey,_:&abi::DomainFeedback,_:u64)->Result<(),Error>{panic!("D16 not part of this probe")} use super::*; }
mod replay {pub fn release_target(_:super::ObjectKey)->Result<(),super::Error>{panic!("D16 not part of this probe")}}
mod quote_stop {pub fn observe(_:super::abi::QuoteStopReceiptWire){}}
'''
network_code += nsrc[nsrc.index('static mut FEEDBACK:'):nsrc.index('fn owner()')]
network_functions = ['fn owner()', 'fn index(', 'fn value(', 'fn wire(', 'fn matching_receipt(',
                     'fn applied_value(', 'fn target_in(', 'fn legal(', 'fn legal_in(',
                     'fn apply(', 'fn reconcile(', 'pub fn observe(']
network_code += '\n'.join(extract('kernel/src/domain_network.rs', f) for f in network_functions)
network_code += '''
pub fn apply_entry(a:Action,id:ApplyId,s:PolicyStamp,at:u64)->Result<ExecutionState,Error>{
 APPLIES.fetch_add(1,Ordering::AcqRel); apply(a,id,s,at)
}
pub fn query(a:Action,id:ApplyId,s:PolicyStamp,at:u64)->Result<ExecutionState,Error>{reconcile(a,id,s,at)}
pub fn policy()->PolicyWire {wire(unsafe{(*core::ptr::addr_of!(DESIRED))[0]})}
pub fn receive(receipt:PolicyReceiptWire, foreign_generation:bool){
 let mut shared:Box<Shared>=unsafe { Box::from_raw(std::alloc::alloc_zeroed(std::alloc::Layout::new::<Shared>()).cast()) };
 shared.magic=abi::MAGIC;shared.version=abi::VERSION;shared.boot_epoch=11;
 shared.service_generation=if foreign_generation {2}else{1};shared.feedback_sequence=2;
 shared.domain_feedback.tx=receipt;
 observe(&shared,11,1);
}
'''
(OUT/'network.rs').write_text(network_code)

hsrc=(ROOT/'kernel/src/learning_history.rs').read_text()
history_code=hsrc[:hsrc.index('#[path = "learning_history/rejection.rs"]')]
history_code+=hsrc[hsrc.index('pub const RECORDS:'):hsrc.index('pub fn install(')]
SOURCES['kernel/src/learning_history.rs::prelude_and_storage_helpers']=hashlib.sha256(history_code.encode()).hexdigest()
for f in ['pub fn install(', 'pub fn begin_run(', 'fn begin_inner(', 'pub fn record_proposal(',
          'pub fn record_publish(', 'pub fn record_execution(', 'pub fn status(', 'pub fn copy_record(']:
    history_code+='\n'+extract('kernel/src/learning_history.rs',f)
history_code+='''
pub fn init(set:&CandidateSet,id:ApplyId,stamp:PolicyStamp){
 let storage=Box::leak(Box::new(Storage{bytes:[0;STORAGE_BYTES]}));
 install(storage,[7;32],11,ObjectKey{id:99,generation:1},|_,_,_|Ok(())).map_err(|(e,_)|e).unwrap();
 let key=RunKey{boot_epoch:11,trial_id:1,generation:1};
 let scope=FrozenScope{key,kind:TrialKind::Candidate,family:Family{domain:10,kind:1},target:set.target,
 group:ReplayGroup{seed:1,workload:[1;32],initial_image:[2;32]},
 schemas:Schemas{feature:learning::SchemaBinding{version:13,hash:[3;32]},action:learning::SchemaBinding{version:13,hash:[4;32]},reward:learning::reward_schema(),learning:learning::learning_config()},
 frozen_other_domains:[8;32],frozen_scope_hash:[9;32],first_ns:crate::SNAP_NS,warmed_from_ns:crate::SNAP_NS-1_000_000_000,observation_ns:crate::SNAP_NS};
 *crate::learning_evidence::CONFIG.lock().unwrap()=Some(learning::capture::Config{key,family:scope.family,node:[7;32],first_ns:scope.first_ns,observation_ns:scope.observation_ns,frozen_scope_hash:scope.frozen_scope_hash});
 let checks=ReplayChecks{frozen:|_|Ok(()),issued:|_,_|Ok(()),baseline:|_,_|Ok(()),closing:|_,_|Ok(())};
 begin_run(scope,checks).unwrap();
 crate::SLOT.store(1,Ordering::Release);
 let input=[0u8;INPUT_BYTES];let hash=Sha256::digest(input).into();
 assert_eq!(record_proposal(1,set,&input,hash),Ok(true));
 assert_eq!(record_publish(Publish{decision_seq:1,apply:id,plan_version:stamp.version,stamp,model:set.model,selected:0,scores:&[1],received_ns:crate::PUB_NS,published_ns:crate::PUB_NS,
 expires_local_ns:crate::SNAP_NS+100_000_000,active_until_local_ns:stamp.installed_until_ns,approved_deadline_ns:crate::PUB_NS+50_000_000,concurrent:&[id]}),Ok(true));
 crate::SLOT.store(0,Ordering::Release);
}
pub fn recorded()->(u64,u64,u64,u64){
 let mut bytes=[0u8;64];
 assert_eq!(copy_record(RunKey{boot_epoch:11,trial_id:1,generation:1},0,392,&mut bytes),Ok(64));
 (u64_at(&bytes,0),u64_at(&bytes,8),u64_at(&bytes,16),u64_at(&bytes,32))
}
'''
(OUT/'history.rs').write_text(history_code)

main='''//! Production-bound R02 feedback regression.
//! Executes extracted, byte-identical production poll/apply/reconcile/history functions,
//! the actual TlsEgress receipt producer, Registry, stability Guard and AdmissionView.
//! Host boundaries: clock/CPU slot, initialized D05 prerequisite, pool/replay authority,
//! coordinator gate, and instrumentation sinks. It is not a native guest execution.
#![allow(dead_code,unused_imports)]
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicU64,AtomicUsize,Ordering};
use std::sync::Mutex;
use cyxia_prototype::{domains::{Action,ApplyId,Error,ObjectKey,PolicyStamp},policy::{self,ExecutionState,Prerequisite,BoundDependency},learning};
use cyxia_prototype_cluster::abi;
const SNAP_NS:u64=1_010_000_000;
const PUB_NS:u64=1_012_000_000;
static WALL:AtomicU64=AtomicU64::new(PUB_NS);
static SLOT:AtomicUsize=AtomicUsize::new(0);
static APPLIES:AtomicUsize=AtomicUsize::new(0);
static PROGRESS:AtomicUsize=AtomicUsize::new(0);
fn now()->u64{WALL.load(Ordering::Acquire)}
pub mod cpu{pub fn slot()->usize{super::SLOT.load(super::Ordering::Acquire)}}
pub mod sha256{pub fn digest_page(_:&[u8;4096])->Option<[u8;32]>{None}}
mod domain_platform{pub fn now_ns()->u64{super::now()}}
mod timer{pub fn cpu_ticks()->u64{0}}
mod domain_tasks{pub fn finish_cpu_interval(_:u64)->(u64,u64,u64){(super::now(),super::now(),0)}}
mod domain_evidence{pub fn progress(_:usize,_:u64,_:u64,_:super::ExecutionState,_:u64){super::PROGRESS.fetch_add(1,super::Ordering::AcqRel);}pub fn stability_failed(_:u16,_:u64,_:super::Error){panic!("unexpected stability failure")}}
mod learning_evidence{
 use super::learning;
 #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum Error{NotReady,Busy,Owner,Stale,Capacity,Capture(learning::Error)}
 impl From<learning::Error> for Error{fn from(e:learning::Error)->Self{Self::Capture(e)}}
 pub type PoolCheck=fn(super::ObjectKey,usize,usize)->Result<(),Error>;
 pub static CONFIG:std::sync::Mutex<Option<learning::capture::Config>>=std::sync::Mutex::new(None);
 pub fn current_config()->Result<Option<learning::capture::Config>,Error>{Ok(*CONFIG.lock().unwrap())}
 pub fn attempt(_:super::ObjectKey,_:learning::reward::CpuClass)->Result<Option<()>,Error>{Ok(None)}
 pub fn finish_attempt(_:&mut (),_:u64,_:u64)->Result<(),Error>{Ok(())}
 pub mod execution_trace{
  use super::super::*;
  pub struct ControlDenial{pub action:Action,pub apply:ApplyId,pub stamp:PolicyStamp,pub observed_ns:u64,pub expected_core:u64,pub current_core:u64,pub expected_ledger:u64,pub current_ledger:u64,pub flags:u64,pub error:Error}
  pub struct ControlEvent{pub action:Action,pub apply:ApplyId,pub stamp:PolicyStamp,pub was_started:bool,pub entered_ns:u64,pub finished_ns:u64,pub cpu_ns:u64,pub published_ns:u64,pub result:Result<ExecutionState,Error>}
  pub fn control_denied(_:ControlDenial){}pub fn control(_:ControlEvent){}
 }
}
#[path="history.rs"]mod learning_history;
#[path="network.rs"]mod network;
'''
admission_source=(ROOT/'kernel/src/domain_control/dependencies.rs').read_text()
(OUT/'admission.rs').write_text(admission_source+"\npub fn state_tag(view:&AdmissionView)->u64{view.entries[0].state.load(Ordering::Acquire)}\n")
SOURCES['kernel/src/domain_control/dependencies.rs']=hashlib.sha256(admission_source.encode()).hexdigest()
main+='#[path="admission.rs"]mod admission;\n'
main+='''
mod control{
 use super::*;
 use cyxia_prototype::domains::stability::Guard as Stability;
 #[derive(Clone,Copy)]struct Desired{action:Action,apply:ApplyId,stamp:PolicyStamp,state:ExecutionState,started:bool,first_entry_ns:Option<u64>,observed_ns:u64,published:u64,evidence:Option<usize>,job:u64,dependencies:[Option<BoundDependency>;2],core_generation:u64,ledger_generation:u64,execution_observed:bool}
 #[derive(Clone,Copy)]struct FamilyEntry{apply:fn(Action,ApplyId,PolicyStamp,u64)->Result<ExecutionState,Error>,reconcile:fn(Action,ApplyId,PolicyStamp,u64)->Result<ExecutionState,Error>,current:fn(u16,u16,ObjectKey)->Result<Action,Error>}
 struct Context{core_generation:u64,ledger_generation:u64}
 struct Owner{desired:[Option<Desired>;1],stability:[Option<Stability>;1],families:[Option<FamilyEntry>;1],family_epochs:[u64;1],stability_high:usize,poll_cursor:usize,context:Context}
 struct State{owner:Owner,registry:policy::Registry}
 static STATE:Mutex<Option<State>>=Mutex::new(None);
 static ADMISSION:admission::AdmissionView=admission::AdmissionView::new();
 fn with<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{let mut s=STATE.lock().unwrap();f(s.as_mut().unwrap())}
 fn family_index(domain:u16,kind:u16)->Result<usize,Error>{assert_eq!((domain,kind),(10,1));Ok(0)}
 fn prerequisite()->Prerequisite{Prerequisite{domain:5,target:ObjectKey{id:55,generation:1}}}
 fn bind_dependencies(_:&Owner,a:Action,_:ObjectKey,at:u64)->Result<[Option<BoundDependency>;2],Error>{
  assert_eq!(a.domain(),10);let p=prerequisite();Ok([Some(BoundDependency{prerequisite:p,version:ADMISSION.admit(p,10,at)?}),None])
 }
 fn observe_execution(_:&mut State,d:&mut Desired){if d.state==ExecutionState::Applied{d.execution_observed=true;}}
 mod replay{pub fn candidate_stale<T>(_:&T){}pub fn candidate_execution(_:super::ApplyId,_:super::PolicyStamp,_:super::ExecutionState){}}
'''
for f in ['fn execution_blocks_replacement(', 'fn execution_limit(', 'pub fn poll(']:
    main+='\n'+extract('kernel/src/domain_control.rs',f)
main+='''
 fn views(publisher:policy::Publisher,id:ApplyId)->(ExecutionState,ExecutionState,bool){
  with(|s|{let d=s.owner.desired[0].unwrap();Ok((d.state,s.registry.query(publisher,policy::PlanId{boot_epoch:id.boot_epoch,controller_epoch:id.controller_epoch,plan_seq:id.plan_seq})?.state(),d.started))}).unwrap()
 }
 pub fn run(mode:&str){
  let (registry,id,stamp,publisher,set)=fixture::ready();let action=Action::TxBatch(4);
  learning_history::init(&set,id,stamp);
  ADMISSION.publish(1,prerequisite(),7,SNAP_NS+cyxia_prototype::domains::POLICY_NS,ExecutionState::Applied);
  let deps=[Some(BoundDependency{prerequisite:prerequisite(),version:7}),None];
  *STATE.lock().unwrap()=Some(State{owner:Owner{desired:[Some(Desired{action,apply:id,stamp,state:ExecutionState::Pending,started:false,first_entry_ns:None,observed_ns:PUB_NS,published:PUB_NS,evidence:Some(0),job:1,dependencies:deps,core_generation:2,ledger_generation:3,execution_observed:false})],
   stability:[Some(Stability::new(id.target,action,SNAP_NS).unwrap())],families:[Some(FamilyEntry{apply:network::apply_entry,reconcile:network::query,current:|_,_,_|Ok(Action::TxBatch(4))})],family_epochs:[1],stability_high:1,poll_cursor:0,context:Context{core_generation:2,ledger_generation:3}},registry});
  ADMISSION.publish(0,Prerequisite{domain:10,target:id.target},stamp.version,stamp.installed_until_ns,ExecutionState::Pending);
  WALL.store(PUB_NS+1_000_000,Ordering::Release);assert_eq!(poll(now()),Ok(()));
  assert_eq!(APPLIES.load(Ordering::Acquire),1);assert_eq!(views(publisher,id),(ExecutionState::Pending,ExecutionState::Pending,true));
  assert_eq!(learning_history::recorded(),(1,PUB_NS+1_000_000,PUB_NS+1_000_000,0));
  println!("real_apply: target={:?}; views={:?}; history={:?}; progress={}",id.target,views(publisher,id),learning_history::recorded(),PROGRESS.load(Ordering::Acquire));
  if mode!="early_pending"{
   WALL.store(PUB_NS+2_000_000,Ordering::Release);assert_eq!(poll(now()),Ok(()));
   assert_eq!(views(publisher,id),(ExecutionState::Unknown,ExecutionState::Unknown,true));assert_eq!(learning_history::recorded().3,2);
  }
  let progress_before=PROGRESS.load(Ordering::Acquire);
  WALL.store(if mode=="deadline"{PUB_NS+50_000_000}else{PUB_NS+3_000_000},Ordering::Release);
  let mut egress=cyxia_prototype_cluster::domain_ingress::TlsEgress::new(1).unwrap();
  egress.install_at(network::policy(),now()).unwrap();assert_eq!(egress.receipt.outcome,abi::DOMAIN_PENDING);
  assert_eq!(egress.receipt.request_id,abi::TX_SERVICE_ID);
  network::receive(egress.receipt,mode=="foreign_service");
  let result=poll(now());let v=views(publisher,id);let row=learning_history::recorded();let status=learning_history::status().unwrap();
  let expected=if mode=="early_pending"{(Ok(()),ExecutionState::Pending,ExecutionState::Pending,0)}else if mode=="late_pending"{(Ok(()),ExecutionState::Unknown,ExecutionState::Unknown,2)}else{(Ok(()),ExecutionState::Unknown,ExecutionState::Unknown,2)};
  assert_eq!((result,v.0,v.1,row.3),expected);assert_eq!(admission::state_tag(&ADMISSION),if mode=="early_pending"{1}else{4});assert!(v.2);assert_eq!(status.fault,None);assert_eq!(status.unresolved,1);
  assert_eq!(APPLIES.load(Ordering::Acquire),1);
  with(|s|{assert_eq!(s.owner.desired[0].unwrap().published,PUB_NS);Ok(())}).unwrap();
  if mode=="late_pending"{assert_eq!(PROGRESS.load(Ordering::Acquire),progress_before+1);}
  println!("mode={mode}: poll={result:?}; desired={:?}; registry={:?}; started={}; actual_history_tag={}; history_fault={:?}; unresolved={}; actual_applies={}; progress_before={progress_before}; progress_after={}",v.0,v.1,v.2,row.3,status.fault,status.unresolved,APPLIES.load(Ordering::Acquire),PROGRESS.load(Ordering::Acquire));
  // Actual production expire_at creates the matching terminal receipt.
  WALL.store(stamp.installed_until_ns,Ordering::Release);egress.expire_at(now());assert_eq!(egress.receipt.outcome,abi::DOMAIN_EXPIRED);
  network::receive(egress.receipt,false);assert_eq!(poll(now()),Ok(()));
  assert_eq!(admission::state_tag(&ADMISSION),3);
  let expected=ExecutionState::Failed(Error::Expired);assert_eq!(views(publisher,id),(expected,expected,true));assert_eq!(learning_history::recorded().3,3);
  assert_eq!(APPLIES.load(Ordering::Acquire),1);
  let before=learning_history::recorded();
  let rejected=learning_history::record_execution(learning_history::Execution{apply:id,stamp,state:ExecutionState::Pending,observed_ns:now(),started_ns:None,executor_generation:None});
  assert_eq!(rejected,Err(learning_evidence::Error::Capture(learning::Error::Conflict)));assert_eq!(learning_history::recorded(),before);
  println!("terminal_control: actual_expired_feedback converged all views; applies=1; history terminal->Pending rejected={rejected:?}");
  let gate=admission::AdmissionView::new();let pre=prerequisite();
  gate.publish(0,pre,7,now()+1_000_000,ExecutionState::Unknown);assert_eq!(gate.admit(pre,10,now()),Err(Error::NotReady));
  gate.publish(0,pre,7,now()+1_000_000,ExecutionState::Pending);assert_eq!(gate.admit(pre,10,now()),Err(Error::Busy));
  for consumer in 1..=16{assert!(!policy::dependency_allowed(10,consumer));}
  let actual_d10_gate=ADMISSION.admit(Prerequisite{domain:10,target:id.target},4,now());assert_eq!(actual_d10_gate,Err(Error::Unsupported));
  println!("admission_control: generic Unknown=NotReady and Pending=Busy both deny; D10 has no valid prerequisite consumer; actual_d10={actual_d10_gate:?}");
 }
}
mod fixture{
 use super::*;
 use cyxia_prototype::{policy::*,features::RawFeatures,policy_wire::*,domains::{POLICY_NS,WINDOW_NS}};
 struct ClockStub;impl Clock for ClockStub{fn read(&mut self)->PublicationTime{PublicationTime{wall_ns:PUB_NS,cpu:CpuTime{cpu:1,ns:PUB_NS}}}}
 struct ExecutorStub;impl Executor for ExecutorStub{
 fn check(&mut self,_:Decision,_:&RegisteredSet,_:u64)->Result<(),Error>{Ok(())}
 fn prepare(&mut self,_:&Plan,_:u64)->Result<(),Error>{Ok(())}
 fn revalidate(&mut self,_:&Plan,_:u64)->Result<(),Error>{Ok(())}
 fn publish(&mut self,_:&Plan,_:u64,_:u64)->Result<(),Error>{Ok(())}
 fn cancel_prepared(&mut self,_:&Plan){}
 }
 pub fn ready()->(Registry,ApplyId,PolicyStamp,Publisher,CandidateSet){
  let publisher=Publisher{object:ObjectKey{id:7,generation:1},controller_epoch:9};
  let model=ModelBinding{generation:1,model_hash:[3;32],schema_hash:[5;32]};
  let set=CandidateSet::new(Snapshot{sequence:1,taken_ns:SNAP_NS,ledger_generation:3,core_generation:2},ObjectKey{id:abi::TX_SERVICE_ID,generation:1},model,&[Candidate{action:Action::TxBatch(4),features:RawFeatures::default()}],Some(Action::TxBatch(4))).unwrap();
  let header=PlanHeader{plan_seq:1,base_plan_version:0,active_model_generation:model.generation,controller_epoch:publisher.controller_epoch,snapshot_seq:1,active_until_local_ns:SNAP_NS+POLICY_NS};
  let d=Decision{action:Action::TxBatch(4),candidate_index:0,envelope:Envelope{controller_epoch:9,decision_seq:1,snapshot_seq:1,target:set.target,ledger_generation:3,core_generation:2,expires_local_ns:SNAP_NS+WINDOW_NS,model_hash:model.model_hash,candidate_set_hash:set.hash()}};
  let mut bytes=[0;MAX_PLAN_BYTES];let n=encode_plan(header,&[d],&mut bytes).unwrap();
  let mut registry=Registry::new(11,publisher,model).unwrap();registry.register(publisher,&set).unwrap();
  let receipt=registry.submit(publisher,&bytes[..n],&mut ClockStub,&mut ExecutorStub).unwrap();assert_eq!(receipt.state(),ExecutionState::Pending);
  let id=ApplyId{boot_epoch:receipt.id.boot_epoch,controller_epoch:receipt.id.controller_epoch,plan_seq:receipt.id.plan_seq,action_index:0,target:set.target};
  (registry,id,PolicyStamp{version:receipt.version,snapshot_ns:SNAP_NS,installed_until_ns:SNAP_NS+POLICY_NS},publisher,set)
 }
}
fn main(){let mode=std::env::args().nth(1).unwrap_or("late_pending".into());assert!(["early_pending","late_pending","deadline","foreign_service"].contains(&mode.as_str()));control::run(&mode);}
'''
(OUT/'main.rs').write_text(main)
(OUT/'Cargo.toml').write_text('''[package]
name="independent-control-recheck"
version="0.1.0"
edition="2024"
[[bin]]
name="independent-control-recheck"
path="main.rs"
[dependencies]
cyxia-prototype={path="'''+str(ROOT/'crates/prototype')+'''"}
cyxia-prototype-cluster={path="'''+str(ROOT/'user/prototype-cluster')+'''"}
sha2="=0.10.9"
[patch.crates-io]
ring={path="'''+str(ROOT/'user/prototype-cluster/vendor/ring')+'''"}
[workspace]
''')
(OUT/'source-binding.json').write_text(json.dumps({'source_root':str(ROOT),'production_functions':SOURCES,'host_boundaries':['CPU slot and wall/CPU clocks','initialized D05 prerequisite owner','coordinator gate and Registry publication callback fixture','pool/capture/replay authority checks','evidence instrumentation sinks and CPU0-only read view'],'scope':'host control-flow and actual in-memory history, not native guest execution or disk persistence'},indent=2)+'\n')
print(f'Generated {OUT}: {len(SOURCES)} source bindings')
