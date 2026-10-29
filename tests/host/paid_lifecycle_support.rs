const TASKS:usize=4;
const CLUSTER_CALLER:ObjectKey=ObjectKey{id:999,generation:1};
static FILE_BUSY:[AtomicBool;TASKS]=[const{AtomicBool::new(false)};TASKS];
static FILE_DONE:[AtomicBool;TASKS]=[const{AtomicBool::new(false)};TASKS];
static FILE_PENDING:[AtomicBool;TASKS]=[const{AtomicBool::new(false)};TASKS];
static RETURN_PENDING:[AtomicBool;TASKS]=[const{AtomicBool::new(false)};TASKS];
static CTOR_COST:AtomicU64=AtomicU64::new(80_000);
static DENY_ON_CTOR:AtomicBool=AtomicBool::new(false);
static CLEAR_DRAIN_ON_CTOR:AtomicBool=AtomicBool::new(false);
static REENTER_ON_FRAME:AtomicBool=AtomicBool::new(false);
static ZERO_BUSY_FRAME:AtomicUsize=AtomicUsize::new(usize::MAX);
static RETIRED:AtomicU64=AtomicU64::new(0);
static FILE_EXITS:AtomicU64=AtomicU64::new(0);
static RELEASES:std::sync::Mutex<Vec<(ObjectKey,u64,usize)>>=std::sync::Mutex::new(Vec::new());
struct Bank{words:[AtomicU64;32]}
static DOMAIN_TASK_EVIDENCE:Bank=Bank{words:[const{AtomicU64::new(0)};32]};
static TASK_OVERRUN_EVIDENCE:Bank=Bank{words:[const{AtomicU64::new(0)};32]};
fn group_index(_: &State,_:ObjectKey)->Result<usize,Error>{Err(Error::NotFound)}
fn publish_evidence(_: &State){}
struct Counter;impl Counter{fn add(&self,_:u64,_:u64){}}
// Actual complete_locked reads this out-of-scope metrics projection only when
// group_index succeeds; the real Scheduler still charges every actual bill.
impl Facts { const CPU:[Counter;16]=[const{Counter};16]; }
mod domain_file_abi{pub fn exit(_:super::ObjectKey)->Result<(),super::Error>{
    assert_eq!(super::CREDIT_KIND[0].load(super::Ordering::Acquire),5,"cleanup escaped fresh credit");
    super::FILE_EXITS.fetch_add(1,super::Ordering::Relaxed);Ok(())}}
mod abi{
 use super::*;
 pub fn release_vector_leases(s:&mut State,i:usize)->Result<(),Error>{assert!(s.vectors[i].is_none());Ok(())}
 pub struct Mailbox<'a>{pub tasks:&'a [Task;TASKS],pub wake:&'a mut u64,pub received:&'a mut [()],pub used:usize}
 impl IpcBackend<64> for Mailbox<'_>{
  fn authorize(&mut self,_:ObjectKey,_:ObjectKey,_:IpcOperation)->Result<(),Error>{Ok(())}
  fn notify(&mut self,_:ObjectKey,_:ObjectKey)->Result<(),Error>{Ok(())}
  fn deliver(&mut self,_:ObjectKey,_:ObjectKey,_:&Message<64>)->Result<(),Error>{panic!("empty IPC fixture delivered a message")}
 }
}
struct Pages<'a>{tasks:&'a [Task;TASKS],remote:(),load:Option<()>}
impl MemoryBackend for Pages<'_>{
 fn zero(&mut self,frame:usize)->Result<(),Error>{
  if CREDIT_KIND[0].load(Ordering::Acquire)==5{
   work(1_000);
   if ZERO_BUSY_FRAME.load(Ordering::Acquire)==frame{return Err(Error::Busy)}
  }Ok(())
 }
 fn map(&mut self,_:ObjectKey,_:u64,_:usize,_:bool)->Result<(),Error>{Ok(())}
 fn revoke(&mut self,key:ObjectKey,address:u64,frame:usize)->Result<(),Error>{
  assert_eq!(CREDIT_KIND[0].load(Ordering::Acquire),5);assert!(!COMPLETE_READY[0].load(Ordering::Acquire));
  RELEASES.lock().unwrap().push((key,address,frame));Ok(())
 }
 fn load_cache(&mut self,_:ObjectKey,_:u64,_:usize)->Result<(),Error>{Err(Error::Unsupported)}
 fn drop_cache(&mut self,_:CacheHandle)->Result<(),Error>{Ok(())}
}
mod user{#[derive(Clone,Copy)]pub struct Context;impl Context{pub const fn empty()->Self{Self}}}
static mut CONTEXTS:[user::Context;TASKS]=[user::Context::empty();TASKS];
static mut FRAME_BYTES:[u8;TASKS*3*4096]=[0xaa;TASKS*3*4096];
unsafe fn frame_ptr(frame:usize)->Result<*mut u8,Error>{
 if frame>=TASKS*3{return Err(Error::Range)}
 assert_eq!(CREDIT_KIND[0].load(Ordering::Acquire),5);work(20_000);
 if REENTER_ON_FRAME.swap(false,Ordering::AcqRel){
  let ticket=TICKETS.load(Ordering::Acquire);service_baseline_progress();
  assert_eq!(TICKETS.load(Ordering::Acquire),ticket,"lifecycle progress recursively replaced the outer ticket");
 }
 Ok(unsafe{core::ptr::addr_of_mut!(FRAME_BYTES).cast::<u8>().add(frame*4096)})
}
fn synchronize(){work(5_000);}
fn wake_task(_: &mut State,_:usize){}
unsafe fn process_return(s:&mut State,i:usize,_:&mut user::Context){s.tasks[i].life=Life::Exiting;RETURN_PENDING[i].store(false,Ordering::Release);}
fn setup(){
 reset();CTOR_COST.store(80_000,Ordering::Release);DENY_ON_CTOR.store(false,Ordering::Release);CLEAR_DRAIN_ON_CTOR.store(false,Ordering::Release);
 REENTER_ON_FRAME.store(false,Ordering::Release);
 ZERO_BUSY_FRAME.store(usize::MAX,Ordering::Release);RETIRED.store(0,Ordering::Release);FILE_EXITS.store(0,Ordering::Release);RELEASES.lock().unwrap().clear();replay::reset();
 for i in 0..TASKS{FILE_BUSY[i].store(false,Ordering::Release);FILE_DONE[i].store(false,Ordering::Release);FILE_PENDING[i].store(false,Ordering::Release);RETURN_PENDING[i].store(false,Ordering::Release);COMPLETE_READY[i].store(false,Ordering::Release);CREDIT_KIND[i].store(0,Ordering::Release);}
 locked(|s|{s.tasks=[Task::EMPTY;TASKS];s.exits=[None;16];s.memory=Memory::new();s.services=ServiceBatch::new();s.ipc=Ipc::new();s.lifecycle_cursor=0;s.vectors=[None;TASKS];s.probe_key=None;s.probe_exit=None;s.admission.register_group(group(11))?;s.scheduler.register_group(group(11))?;Ok(())}).unwrap();
 KEEP_HINT.store(true,Ordering::Release);learning_replay::own_drain(Ok(())).unwrap();
}
struct Existing(ObjectKey);impl TaskBackend for Existing{
 fn authorize(&mut self,_:&SpawnRequest)->Result<(),Error>{Ok(())}
 fn create(&mut self,_:&SpawnRequest)->CreateOutcome{CreateOutcome::Created(self.0)}
}
fn child(slot:usize,id:u64,pages:usize)->ObjectKey{
 let key=group(4096+slot as u64);
 locked(|s|{
  s.scheduler.admit(ThreadSpec{key,group:group(11),cpu:3,allowed_mask:8,minimum_ns:0,budget_ns:1_000_000},s.layout,now_ns())?;
  s.admission.submit(SpawnRequest{caller:request().caller,request_id:id,package:PACKAGE,group:group(11),payload_hash:[0;32],recovery:false},now_ns(),&mut Existing(key))?;
  s.admission.service_one(now_ns(),&mut Existing(key))?;
  s.memory.register_owner(key,pages.max(1))?;
  s.memory.reserve(key,0x10000,pages.max(1),true)?;
  let mut backend=Pages{tasks:&s.tasks,remote:(),load:None};
  for page in 0..pages{s.memory.fault(key,0x10000+page as u64*4096,true,&mut backend)?;}
  s.tasks[slot]=Task{key,parent:request().caller,spawn_id:id,group:group(11),life:Life::Exiting,deadline:PROBE_DEADLINE,cpu:3,terminal_seen:true,response:55,regions:[0x10000,0,0,0,0,0,0,0],region_count:1,..Task::EMPTY};
  Ok(())
 }).unwrap();key
}
fn advance(){service_baseline_progress();}
fn cpu_bills()->Vec<u64>{bills().iter().map(|v|v.1).collect()}
#[test]fn paid_lifecycle_three_separate_bills_and_one_original_delivery(){
 for error in [0,1]{
 setup();let key=child(2,7,1);
 locked(|s|{let d=s.scheduler.dispatch(3,s.layout,now_ns(),1_000_000)?.unwrap();assert_eq!(d.thread,key);s.scheduler.complete(d,35_000,RunState::Runnable,now_ns())?;assert_eq!(s.scheduler.thread_cpu_ns(key)?,35_000);Ok(())}).unwrap();
 QUEUE_ON_STEP.store(true,Ordering::Release);STEP_ERROR.store(error,Ordering::Release);
 REENTER_ON_FRAME.store(true,Ordering::Release);
 advance();assert_eq!(RETIRED.load(Ordering::Acquire),1,"owned Exiting child never reached actual cleanup");
 assert_eq!(cpu_bills(),[100_000,80_000,66_000]);let b=bills();assert!(b.windows(2).all(|v|v[0].0!=v[1].0));
 let finished=now_ns()-5_000; // Exit is published after synchronize, not backdated.
 let result=replay::spawn_result(7).unwrap().unwrap();assert_eq!(result,Ok(now_ns()));assert!(now_ns()>finished);
 assert_eq!(replay::spawn_result(7),Ok(Some(result)));assert!(locked(|s|Ok(s.exits.iter().all(Option::is_none))).unwrap());
 assert_eq!(locked(|s|s.memory.owner_pages(key)),Err(Error::Stale));assert_eq!(locked(|s|s.admission.request(request().caller,7)).unwrap().request_id,7);
 assert_eq!(learning_replay::snapshot(),100_000_000);assert_eq!(locked(|s|Ok(s.scheduler.thread_cpu_ns(group(0x101))?)),Ok(246_000));
 }
}
#[test]fn paid_lifecycle_selects_only_one_and_rotates_past_busy(){
 setup();child(0,7,1);child(1,8,1);FILE_BUSY[0].store(true,Ordering::Release);
 advance();assert_eq!(FILE_EXITS.load(Ordering::Acquire),0,"one paid lifecycle piece processed two items");assert_eq!(locked(|s|Ok(s.lifecycle_cursor)),Ok(1));assert_eq!(replay::spawn_result(7),Ok(None));
 advance();assert_eq!(RETIRED.load(Ordering::Acquire),1,"one paid lifecycle piece processed two items");assert_eq!(replay::spawn_result(7),Ok(None));assert!(replay::spawn_result(8).unwrap().is_some());
 setup();child(0,7,1);child(1,8,1);advance();
 assert_eq!(RETIRED.load(Ordering::Acquire),1,"one paid lifecycle piece processed two items");assert!(replay::spawn_result(7).unwrap().is_some());assert_eq!(replay::spawn_result(8),Ok(None));
}
#[test]fn paid_lifecycle_preserves_active_and_file_custody_then_settles_published_bill(){
 setup();let key=child(0,7,1);
 let dispatch=locked(|s|{let d=s.scheduler.dispatch(3,s.layout,now_ns(),1_000_000)?.unwrap();s.active[3]=Some(Active{dispatch:d,state:RunState::Runnable,optional:None,cpu_started:None});Ok(d)}).unwrap();
 advance();assert_eq!(replay::spawn_result(7),Ok(None));assert_eq!(FILE_EXITS.load(Ordering::Acquire),0);
 FILE_BUSY[0].store(true,Ordering::Release);COMPLETE_ACTUAL[3].store(35_000,Ordering::Release);COMPLETE_AT[3].store(now_ns(),Ordering::Release);COMPLETE_READY[3].store(true,Ordering::Release);
 advance();assert!(!COMPLETE_READY[3].load(Ordering::Acquire));assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(key)),Ok(35_000));assert_eq!(FILE_EXITS.load(Ordering::Acquire),0);
 FILE_BUSY[0].store(false,Ordering::Release);advance();assert!(replay::spawn_result(7).unwrap().is_some());assert_eq!(RETIRED.load(Ordering::Acquire),1);let _=dispatch;
}
#[test]fn paid_lifecycle_real_unmap_busy_keeps_remaining_pages_and_retries_once(){
 setup();let key=child(2,7,66);advance();
 assert_eq!(locked(|s|s.memory.owner_pages(key)),Ok(2),"bounded unmap did not stop after sixty-four pages");assert_eq!(replay::spawn_result(7),Ok(None));assert_eq!(RETIRED.load(Ordering::Acquire),0);
 let frame=locked(|s|s.memory.resident(key,0x10000+64*4096)).err();assert_eq!(frame,Some(Error::Busy));
 ZERO_BUSY_FRAME.store(64,Ordering::Release);advance();assert_eq!(locked(|s|s.memory.owner_pages(key)),Ok(2));assert_eq!(replay::spawn_result(7),Ok(None));
 ZERO_BUSY_FRAME.store(usize::MAX,Ordering::Release);advance();assert!(replay::spawn_result(7).unwrap().is_some());assert_eq!(RETIRED.load(Ordering::Acquire),1);
 let released=RELEASES.lock().unwrap();for frame in 0..64{assert_eq!(released.iter().filter(|v|v.2==frame).count(),1,"already freed page was revoked again");}assert_eq!(released.iter().filter(|v|v.2==64).count(),2,"uncertain revoke was not retried idempotently");
}
#[test]fn paid_lifecycle_requires_owned_drain_and_allowed_root_result(){
 for mode in 0..6{setup();child(2,7,1);if mode==0{learning_replay::change_phase(0);}else{STEP_ERROR.store(mode+1,Ordering::Release);}advance();assert_eq!(RETIRED.load(Ordering::Acquire),0,"unowned or disallowed Root result ran lifecycle");assert_eq!(replay::spawn_result(7),Ok(None));}
 setup();child(2,7,1);QUEUE_ON_STEP.store(true,Ordering::Release);CLEAR_DRAIN_ON_CTOR.store(true,Ordering::Release);advance();assert_eq!(RETIRED.load(Ordering::Acquire),0,"cleared owned Drain hint was not revalidated");
}
#[test]fn paid_lifecycle_never_reuses_retained_first_or_second_bill(){
 for second in [false,true]{setup();child(2,7,1);QUEUE_ON_STEP.store(true,Ordering::Release);if second{DENY_ON_CTOR.store(true,Ordering::Release);}else{DENY_SETTLE.store(true,Ordering::Release);}advance();assert_eq!(RETIRED.load(Ordering::Acquire),0);assert!(COMPLETE_READY[0].load(Ordering::Acquire));assert_eq!(COMPLETE_ACTUAL[0].load(Ordering::Acquire),if second{80_000}else{100_000});assert_eq!(bills().len(),usize::from(second));}
}
#[test]fn paid_lifecycle_third_fresh_credit_can_be_denied_after_two_real_bills(){
 setup();HINT.store(false,Ordering::Release);for _ in 0..22{assert!(service_segment(||work(2_500_000)).is_some());}
 learning_replay::first_at(now_ns());HINT.store(true,Ordering::Release);child(2,7,1);QUEUE_ON_STEP.store(true,Ordering::Release);CTOR_COST.store(2_450_000,Ordering::Release);advance();
 assert_eq!(RETIRED.load(Ordering::Acquire),0);assert_eq!(&cpu_bills()[22..],&[100_000,2_450_000]);assert_eq!(replay::spawn_result(7),Ok(None));
}
