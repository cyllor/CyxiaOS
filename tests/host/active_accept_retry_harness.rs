use sha2::{Digest,Sha256};
use std::sync::atomic::AtomicBool;
fn pay(n:u64){CPU.fetch_update(Ordering::AcqRel,Ordering::Acquire,|v|Some(v.saturating_add(n))).unwrap();}
static FAULT:AtomicU64=AtomicU64::new(0);static ACQUIRE_WALL:AtomicU64=AtomicU64::new(0);
static BORROWS:AtomicU64=AtomicU64::new(0);
static ACQUIRES:AtomicU64=AtomicU64::new(0);static HASHES:AtomicU64=AtomicU64::new(0);
static VERIFY:AtomicU64=AtomicU64::new(0);static RELEASE_WALL:AtomicU64=AtomicU64::new(0);
static RELEASE_CPU:AtomicU64=AtomicU64::new(0);
static FINISHES:AtomicU64=AtomicU64::new(0);static DELIVERY_BUSY:AtomicBool=AtomicBool::new(false);
static ELIGIBLE:AtomicBool=AtomicBool::new(true);static ACQUIRE_CPU:AtomicU64=AtomicU64::new(100_000);
static TAIL:std::sync::Mutex<[u64;27]>=std::sync::Mutex::new([0;27]);
static FINISHED:std::sync::Mutex<Option<(u64,u64,u64,[u8;32])>>=std::sync::Mutex::new(None);
pub mod sha256{use sha2::Digest;pub fn digest_page(bytes:&[u8;4096])->Option<[u8;32]>{super::HASHES.fetch_add(1,super::Ordering::AcqRel);super::pay(20);Some(super::Sha256::digest(bytes).into())}}
// REPLY_MODULE
mod reply{pub(super) use super::actual_reply::Expected;pub fn verify(e:Expected<'_>,o:&[u64;512])->Result<super::actual_reply::Verified,super::Error>{super::VERIFY.fetch_add(1,super::Ordering::AcqRel);super::pay(30);super::actual_reply::verify(e,o)}}
mod abi{pub const OUTPUT_MAGIC:u64=77;}
// OWNER_GATE_MODULE
static TASK_GATE:owner_gate::Gate=owner_gate::Gate::new();
mod domain_tasks{
 use super::*;
 pub struct SchedulerPublication{permit:Option<owner_gate::Permit<'static>>}
 impl Drop for SchedulerPublication{fn drop(&mut self){self.permit.take().unwrap().release(WALL.load(Ordering::Acquire));BORROWS.fetch_sub(1,Ordering::AcqRel);WALL.fetch_add(RELEASE_WALL.load(Ordering::Acquire),Ordering::AcqRel);pay(RELEASE_CPU.load(Ordering::Acquire));}}
 pub fn scheduler_publication_matches(_:&Family,_:Option<&Family>,_:Option<fn(ObjectKey)->Result<[Option<Prerequisite>;2],Error>>,custom:bool)->bool{ELIGIBLE.load(Ordering::Acquire)&&!custom}
 pub fn reserve_scheduler_publication(action:Action)->Result<Option<SchedulerPublication>,Error>{assert!(matches!(action,Action::CpuWeight(_)));ACQUIRES.fetch_add(1,Ordering::AcqRel);pay(ACQUIRE_CPU.load(Ordering::Acquire));WALL.fetch_add(ACQUIRE_WALL.load(Ordering::Acquire),Ordering::AcqRel);match FAULT.load(Ordering::Acquire){1=>CPU.store(0,Ordering::Release),2=>CPU.store(u64::MAX-100,Ordering::Release),_=>()};let permit=TASK_GATE.try_acquire(1,WALL.load(Ordering::Acquire),1).ok_or(Error::Busy)?;BORROWS.fetch_add(1,Ordering::AcqRel);Ok(Some(SchedulerPublication{permit:Some(permit)}))}
}
// Explicit resource/model/Root scope boundary: real composition tested separately.
struct Gate;impl Gate{fn check_active_publication(&self,_:ModelBinding,_:ObjectKey)->Result<(),Error>{Ok(())}}
struct ActiveScope<'a>(&'a Gate);
struct ActivePublication<'a>{active:ActiveScope<'a>,task_publication:Option<domain_tasks::SchedulerPublication>}
macro_rules! scope_facade{($name:ident)=>{impl PublicationScope for $name<'_>{fn authorize(&mut self,m:ModelBinding,s:&RegisteredSet,t:u64)->Result<(),Error>{Scope.authorize(m,s,t)}fn legal(&self,f:Family,a:Action,k:ObjectKey,t:u64)->Result<(),Error>{Scope.legal(f,a,k,t)}fn dependencies(&self,o:&Owner,a:Action,k:ObjectKey,t:u64)->Result<[Option<BoundDependency>;2],Error>{Scope.dependencies(o,a,k,t)}fn selection(&self,o:&Owner,f:Family,a:Action,k:ObjectKey,t:u64)->Result<(),Error>{Scope.selection(o,f,a,k,t)}fn commit(&mut self,o:&Owner,m:ModelBinding,p:&Plan,s:&[PolicyStamp],b:u64,t:u64)->Result<(),Error>{Scope.commit(o,m,p,s,b,t)}}}}
scope_facade!(ActiveScope);scope_facade!(ActivePublication);
pub mod core_replay{#[derive(Clone,Copy)]pub struct WorkId;pub struct PaidWorkWitness;pub fn evaluated(_:WorkId,_:u64,_:Result<u64,super::Error>,_:[u8;32])->Result<(),super::Error>{if super::DELIVERY_BUSY.load(super::Ordering::Acquire){Err(super::Error::Busy)}else{Ok(())}}}
mod replay{pub fn reject_first_job(_:u64,_:u64,_:&super::CandidateSet,_:super::Error){}}
mod domain_evidence{use super::*;pub fn submission(_:usize,_:u64,w:[u64;27]){*TAIL.lock().unwrap()=w;}pub fn optimization_stop(_:[u64;20]){}pub fn aborted(){}pub fn finish(_:usize,_:u64,_:u64,_:u64,decoded:u64,elapsed:u64,version:u64,_:ExecutionState,_:u64,output:Option<&[u64;512]>){assert_eq!(BORROWS.load(Ordering::Acquire),0,"delivery retained Task guard");FINISHES.fetch_add(1,Ordering::AcqRel);*FINISHED.lock().unwrap()=Some((decoded,elapsed,version,output.map_or([0;32],|o|Sha256::digest(unsafe{&*((o as *const [u64;512]).cast::<[u8;4096]>())}).into())));}}
// ACTUAL_JOB
// ACTUAL_COMPLETION
struct State{owner:Owner,job:Option<Job>,registry:Registry,model_gate:Option<Gate>,sequence:u64,boot:u64}
thread_local!{static STATE:std::cell::RefCell<Option<State>>=const{std::cell::RefCell::new(None)};}
fn with<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{STATE.with(|s|f(s.borrow_mut().as_mut().unwrap()))}
fn publisher(_:u64)->Publisher{publisher_fixture()}
// ACTUAL_ACCEPT
// ACTUAL_FINISH_JOB
// ACTUAL_PENDING_JOB
// ACTUAL_ABORT
mod domain_control{pub use super::{accept,abort,pending_job};pub use super::core_replay;}
use Error as DomainError;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum Completion{Fault,ReadOnly,Reply(u64)}
#[derive(Clone,Copy)]struct Source{class:cyxia_prototype::learning::reward::CpuClass}
struct Native{returned:Option<Completion>,abort_pending:bool,publish_pending:bool,cpu_ns:u64,source:Option<Source>}
impl Native{fn phase(&mut self,_:u64){}}
struct Worker{native:Native}
struct Page([u64;512]);static mut PAGE:Page=Page([0;512]);
fn output_ptr(_:usize)->*const Page{core::ptr::addr_of!(PAGE)}
fn finish_root_return(_:&mut Worker,_:&core_replay::PaidWorkWitness){}
// ACTUAL_ROOT_RETURN
fn debit(j:&Job)->u64{// GET_DEBIT
}
fn setup(mode:u64)->[u64;512]{FAULT.store(0,Ordering::Release);ACQUIRE_WALL.store(0,Ordering::Release);MODE.store(mode,Ordering::Release);CPU.store(0,Ordering::Release);WALL.fetch_add(100_000_000,Ordering::AcqRel);READS.store(0,Ordering::Release);SELECTIONS.store(0,Ordering::Release);EFFECTS.store(0,Ordering::Release);ACQUIRES.store(0,Ordering::Release);HASHES.store(0,Ordering::Release);VERIFY.store(0,Ordering::Release);RELEASE_CPU.store(0,Ordering::Release);RELEASE_WALL.store(0,Ordering::Release);FINISHES.store(0,Ordering::Release);DELIVERY_BUSY.store(false,Ordering::Release);ELIGIBLE.store(true,Ordering::Release);ACQUIRE_CPU.store(100_000,Ordering::Release);*FINISHED.lock().unwrap()=None;*TAIL.lock().unwrap()=[0;27];
 let mut set=candidates();let started=WALL.load(Ordering::Acquire);set=CandidateSet::new(Snapshot{taken_ns:started,..set.snapshot},set.target,set.model,&[8,2,4,1].map(|n|Candidate{action:Action::CpuWeight(n),features:RawFeatures::default()}),Some(Action::CpuWeight(2))).unwrap();let mut registry=Registry::new(11,publisher_fixture(),binding()).unwrap();registry.register(publisher_fixture(),&set).unwrap();let owner=Owner{context:Context{core_generation:2,ledger_generation:3},dependencies:[None;16],dependency_binders:[None;16],families:[Some(Family{legal:|_,_,_|Ok(())})],prepared:[0;16],prepared_count:0,desired:[None]};
 let job=Job{cpu:1,set,sequence:1,controller:9,base_version:0,started,encode_ns:1,evidence:Some(0),dependencies:[None;2],work:None,read_only:false,completion:None,// JOB_DEBIT_INIT
 };
 STATE.with(|s|*s.borrow_mut()=Some(State{owner,job:Some(job),registry,model_gate:Some(Gate),sequence:1,boot:11}));
 let wire=frame(&set,1,0);let mut out=[0;512];out[..8].copy_from_slice(&[77,3,1,9,1,wire.len() as u64,4,11]);out[8]=1<<16;for (i,chunk) in wire.chunks(8).enumerate(){let mut b=[0;8];b[..chunk.len()].copy_from_slice(chunk);out[16+i]=u64::from_le_bytes(b);}out
}
#[test]fn active_accept_busy_twice_reuses_original_job_then_publishes_without_reverification(){let out=setup(0);let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();
 for expected in [100_001,200_002]{assert_eq!(accept(&out,10),Err(Error::Busy),"Task acquisition Busy was not retained");with(|s|{let j=s.job.as_ref().expect("Task acquisition Busy retired original Job");assert!(j.completion.is_none(),"preflight Busy invented Registry completion");assert_eq!((j.sequence,j.controller,j.base_version,s.sequence,s.registry.version()),(1,9,0,1,0));assert_eq!(debit(j),expected,"failed preflight actual CPU was lost");Ok(())}).unwrap();assert_eq!(HASHES.load(Ordering::Acquire),0,"Busy preflight hashed stopped output");assert_eq!(VERIFY.load(Ordering::Acquire),0);assert_eq!(*TAIL.lock().unwrap(),[0;27],"preflight Busy forged Registry submission");}
 held.release(WALL.load(Ordering::Acquire));assert_eq!(accept(&out,10),Ok(1));assert!(!pending_job().unwrap());assert_eq!(EFFECTS.load(Ordering::Acquire),1);assert_eq!(HASHES.load(Ordering::Acquire),1);assert_eq!(ACQUIRES.load(Ordering::Acquire),3);let(d,p,v,_)=FINISHED.lock().unwrap().unwrap();assert_eq!(d,50);assert_eq!(p,300_011,"completion lost or duplicated prior publication cost");assert_eq!(v,1);
}
#[test]fn active_accept_root_return_keeps_stopped_output_and_source_on_acquisition_busy(){let out=setup(0);unsafe{(*core::ptr::addr_of_mut!(PAGE)).0=out;}let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();let mut w=Worker{native:Native{returned:None,abort_pending:false,publish_pending:true,cpu_ns:10,source:Some(Source{class:cyxia_prototype::learning::reward::CpuClass::Policy})}};root_return(&mut w,1,&core_replay::PaidWorkWitness);assert!(w.native.returned.is_none());assert!(!w.native.abort_pending);assert!(w.native.publish_pending);assert!(w.native.source.is_some());assert_eq!(unsafe{(*output_ptr(1)).0},out);held.release(WALL.load(Ordering::Acquire));root_return(&mut w,1,&core_replay::PaidWorkWitness);assert_eq!(w.native.returned,Some(Completion::Reply(1)));}
fn id()->PlanId{PlanId{boot_epoch:11,controller_epoch:9,plan_seq:1}}
#[test]fn active_accept_abort_keeps_failed_preflight_cost_without_registry_identity(){let out=setup(0);let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();assert_eq!(accept(&out,10),Err(Error::Busy));held.release(WALL.load(Ordering::Acquire));with(|s|{assert_eq!(s.registry.query(publisher_fixture(),id()).err(),Some(Error::Stale));Ok(())}).unwrap();assert_eq!(abort(99),Ok(()));assert_eq!(FINISHED.lock().unwrap().unwrap().1,100_001,"abort dropped prior actual publication CPU");assert_eq!(HASHES.load(Ordering::Acquire),0);}
#[test]fn active_accept_registry_budget_includes_prior_attempts_and_keeps_terminal_version_zero(){let out=setup(0);let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();for _ in 0..4{assert_eq!(accept(&out,10),Err(Error::Busy));}held.release(WALL.load(Ordering::Acquire));assert_eq!(accept(&out,10),Err(Error::Budget));assert!(!pending_job().unwrap());assert_eq!(EFFECTS.load(Ordering::Acquire),0);with(|s|{assert!(s.registry.optimization_stopped());let r=s.registry.query(publisher_fixture(),id())?;assert_eq!(r.version,0);assert_eq!(r.state(),ExecutionState::Failed(Error::Budget));Ok(())}).unwrap();assert_eq!(accept(&out,10),Err(Error::Stale));assert_eq!(ACQUIRES.load(Ordering::Acquire),5,"terminal Registry result was retried");assert_eq!(TAIL.lock().unwrap()[7],3,"Registry initial cap ignored carried CPU");}
#[test]fn active_accept_only_acquisition_busy_is_retryable(){for mode in [1,2,4,5,6]{let out=setup(mode);assert_eq!(accept(&out,10),Err(Error::Busy));assert!(!pending_job().unwrap(),"completed resource/model/Root/selection Busy was retried: {mode}");with(|s|{assert_eq!(s.registry.query(publisher_fixture(),id())?.state(),ExecutionState::Failed(Error::Busy));Ok(())}).unwrap();assert_eq!(ACQUIRES.load(Ordering::Acquire),1);}}
#[test]fn active_accept_release_overrun_retains_real_receipt_and_releases_before_delivery(){let out=setup(0);RELEASE_CPU.store(500_000,Ordering::Release);assert_eq!(accept(&out,10),Ok(1));with(|s|{assert!(s.registry.optimization_stopped(),"release CPU escaped final publication cap");assert_eq!(s.registry.query(publisher_fixture(),id())?.version,1);Ok(())}).unwrap();let(d,p,v,_)=FINISHED.lock().unwrap().unwrap();assert_eq!((d,p,v),(50,600_009,1));}
#[test]fn active_accept_delivery_busy_reuses_completed_result_without_resubmit_or_recharge(){let out=setup(0);with(|s|{s.job.as_mut().unwrap().work=Some(core_replay::WorkId);Ok(())}).unwrap();DELIVERY_BUSY.store(true,Ordering::Release);assert_eq!(accept(&out,10),Err(Error::Busy));let original=with(|s|{let c=s.job.unwrap().completion.unwrap();assert_eq!(c.result,Ok(1));assert_eq!(c.output_hash,<[u8;32]>::from(Sha256::digest(unsafe{&*((&out as *const [u64;512]).cast::<[u8;4096]>())})));Ok((c.decoded_ns,c.elapsed_ns,c.cpu_ns))}).unwrap();DELIVERY_BUSY.store(false,Ordering::Release);assert_eq!(accept(&out,999),Ok(1));assert_eq!(ACQUIRES.load(Ordering::Acquire),1,"delivery retried completed publication");assert_eq!(HASHES.load(Ordering::Acquire),1);assert_eq!(EFFECTS.load(Ordering::Acquire),1);let(d,p,_,_)=FINISHED.lock().unwrap().unwrap();assert_eq!((d,p,10),original);}
#[test]fn active_accept_original_wall_context_and_work_checks_precede_task_acquisition(){for mode in 0..4{let out=setup(0);let cpu=if mode==2{2_000_000}else{10};with(|s|{match mode{0=>{WALL.fetch_add(50_000_001,Ordering::AcqRel);},1=>s.owner.context.core_generation+=1,3=>s.job.as_mut().unwrap().encode_ns=u64::MAX,_=>()};Ok(())}).unwrap();assert_eq!(accept(&out,cpu),Err(match mode{1=>Error::Stale,3=>Error::Overflow,_=>Error::Expired}));assert_eq!(ACQUIRES.load(Ordering::Acquire),0);assert_eq!(VERIFY.load(Ordering::Acquire),0);assert_eq!(HASHES.load(Ordering::Acquire),1,"terminal preflight did not retain output hash");assert!(!pending_job().unwrap());if mode==3{assert!(with(|s|Ok(s.registry.optimization_stopped())).unwrap());}}}
#[test]fn active_accept_exact_preflight_cap_and_sixth_attempt_terminate_without_registry_identity(){let out=setup(0);ACQUIRE_CPU.store(99_999,Ordering::Release);let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();for expected in [100_000,200_000,300_000,400_000,500_000]{assert_eq!(accept(&out,10),Err(Error::Busy));assert_eq!(with(|s|Ok(debit(s.job.as_ref().unwrap()))).unwrap(),expected);}held.release(WALL.load(Ordering::Acquire));ACQUIRE_CPU.store(0,Ordering::Release);assert_eq!(accept(&out,10),Err(Error::Budget));assert_eq!(EFFECTS.load(Ordering::Acquire),0);assert!(with(|s|Ok(s.registry.optimization_stopped())).unwrap());}
#[test]fn active_accept_contract_fallback_never_takes_task_guard(){let out=setup(0);ELIGIBLE.store(false,Ordering::Release);assert_eq!(accept(&out,10),Ok(1));assert_eq!(ACQUIRES.load(Ordering::Acquire),0,"unmatched registration acquired Task guard");}

#[test]fn active_accept_native_precommit_uses_carried_cpu_before_any_effect(){let out=setup(0);let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();for _ in 0..2{assert_eq!(accept(&out,10),Err(Error::Busy));}held.release(WALL.load(Ordering::Acquire));MODE.store(7,Ordering::Release);assert_eq!(accept(&out,10),Err(Error::Budget),"Native precommit forgot same Job debit");assert_eq!(EFFECTS.load(Ordering::Acquire),0);let tail=*TAIL.lock().unwrap();assert_eq!((tail[7],tail[15]),(14,15));}
#[test]fn active_accept_busy_does_not_renew_original_wall_deadline(){let out=setup(0);let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();assert_eq!(accept(&out,10),Err(Error::Busy));WALL.fetch_add(50_000_000,Ordering::AcqRel);held.release(WALL.load(Ordering::Acquire));assert_eq!(accept(&out,10),Err(Error::Expired));assert_eq!(ACQUIRES.load(Ordering::Acquire),1);assert_eq!(FINISHED.lock().unwrap().unwrap().1,100_003);}
// FAULT_TESTS

#[test]fn active_accept_release_cap_includes_prior_busy_cost(){let out=setup(0);let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();for _ in 0..2{assert_eq!(accept(&out,10),Err(Error::Busy));}held.release(WALL.load(Ordering::Acquire));RELEASE_CPU.store(300_000,Ordering::Release);assert_eq!(accept(&out,10),Ok(1));assert!(with(|s|Ok(s.registry.optimization_stopped())).unwrap(),"release cap forgot earlier actual CPU");assert_eq!(FINISHED.lock().unwrap().unwrap().1,600_011);}
#[test]fn active_accept_guard_releases_on_reply_decode_and_model_precommit_errors(){for mode in 0..3{let mut out=setup(0);let cpu=if mode==1{1_999_980}else{10};if mode==0{out[0]=0;}if mode==2{with(|s|{s.model_gate=None;Ok(())}).unwrap();}assert_eq!(accept(&out,cpu),Err(match mode{0=>Error::Format,1=>Error::Budget,_=>Error::NotReady}));assert_eq!(BORROWS.load(Ordering::Acquire),0);assert_eq!(EFFECTS.load(Ordering::Acquire),0);let permit=TASK_GATE.try_acquire(1,WALL.load(Ordering::Acquire),1).expect("terminal error leaked Task gate");permit.release(WALL.load(Ordering::Acquire));}}
#[test]fn active_accept_release_overrun_keeps_original_failed_registry_receipt(){let out=setup(1);RELEASE_CPU.store(500_000,Ordering::Release);assert_eq!(accept(&out,10),Err(Error::Busy),"release cap replaced completed Registry failure");assert!(!pending_job().unwrap());assert!(with(|s|Ok(s.registry.optimization_stopped())).unwrap());with(|s|{assert_eq!(s.registry.query(publisher_fixture(),id())?.state(),ExecutionState::Failed(Error::Busy));Ok(())}).unwrap();}

#[test]fn active_accept_release_wall_overrun_keeps_real_receipt_and_stops(){let out=setup(0);RELEASE_WALL.store(50_000_000,Ordering::Release);assert_eq!(accept(&out,10),Ok(1));assert!(with(|s|Ok(s.registry.optimization_stopped())).unwrap(),"release escaped original wall deadline");}
