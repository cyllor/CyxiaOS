// Existing fixture supplies real Gate, service credits, Scheduler, Memory, IPC
// and cleanup. ELF construction/EL0 return and vector completion are boundaries.
use cyxia_prototype::{domains::{PolicyStamp,maintenance::*},policy::ExecutionState};
static VECTOR_READY:AtomicBool=AtomicBool::new(true);
static VECTOR_QUERIES:AtomicU64=AtomicU64::new(0);
struct SubmitVector;impl SubmitVector{fn complete(_: &())->bool{VECTOR_QUERIES.fetch_add(1,Ordering::Relaxed);VECTOR_READY.load(Ordering::Acquire)}}
struct RecoveryMailbox;
impl IpcBackend<64> for RecoveryMailbox{
 fn authorize(&mut self,_:ObjectKey,_:ObjectKey,_:IpcOperation)->Result<(),Error>{Ok(())}
 fn notify(&mut self,_:ObjectKey,_:ObjectKey)->Result<(),Error>{Ok(())}
 fn deliver(&mut self,_:ObjectKey,_:ObjectKey,m:&Message<64>)->Result<(),Error>{assert_eq!(m.request_id,77);Ok(())}
}
mod domain_platform{pub fn now_ns()->u64{super::now_ns()}}
// EVIDENCE_MODULE
// ACTUAL_RECOVERY_TASK_BODIES
// KERNEL_RECOVERY_BACKEND
fn recovery_identity(key:ObjectKey)->ApplyId{ApplyId{boot_epoch:1,controller_epoch:1,plan_seq:443,action_index:0,target:key}}
fn recovery_fixture()->(RecoverySupervisor,ObjectKey,ApplyId){
 setup();domain_evidence::clear_recovery();VECTOR_READY.store(true,Ordering::Release);VECTOR_QUERIES.store(0,Ordering::Release);
 let key=child(2,7,66);let apply=recovery_identity(key);
 locked(|s|{let endpoint=s.ipc.open(key,true)?;
  s.ipc.send(group(9),endpoint,77,&77u64.to_le_bytes(),now_ns(),&mut RecoveryMailbox)?;
  let t=&mut s.tasks[2];t.recipe=2;t.life=Life::Ready;t.pending=true;t.terminal_seen=false;t.deadline=u64::MAX;t.endpoint=endpoint;Ok(())}).unwrap();
 let mut r=RecoverySupervisor::new();r.register(key,2).unwrap();
 r.begin_policy(apply,2,PolicyStamp{version:406,snapshot_ns:100_000_000,installed_until_ns:0},100_000_000).unwrap();
 (r,key,apply)
}
fn recovery_poll(r:&mut RecoverySupervisor,apply:ApplyId)->RecoveryReceipt{
 service_segment(||r.poll(apply,now_ns(),&mut Recovery{apply})).unwrap().unwrap()
}
fn recovery_task_latest()->[u64;48]{let w=domain_evidence::header();w[456..504].try_into().unwrap()}
fn construct_recovery_generation(old:ObjectKey,generation:u64,apply:ApplyId)->Result<(),Error>{
 // The ELF/context boundary is controlled; actual Memory/Scheduler ownership
 // below prevents this facade from claiming cleanup merely by changing a key.
 locked(|s|{
  if s.tasks[2].life!=Life::Free||s.tasks[2].stop_apply!=Some(apply){return Err(Error::Conflict)}
  assert_eq!(s.memory.owner_pages(old),Err(Error::Stale));
  let key=ObjectKey{id:old.id,generation};s.memory.register_owner(key,1)?;
  let endpoint=s.ipc.open(key,true)?;
  s.scheduler.admit(ThreadSpec{key,group:group(11),cpu:3,allowed_mask:8,minimum_ns:0,budget_ns:1_000_000},s.layout,now_ns())?;
  s.tasks[2]=Task{key,group:group(11),recipe:2,life:Life::Ready,pending:true,start_apply:Some(apply),deadline:u64::MAX,cpu:3,endpoint,..Task::EMPTY};
  Ok(())
 })
}
#[test]fn recovery_predicates_retain_real_pending_vector_active_and_partial_cleanup(){
 let(mut r,key,apply)=recovery_fixture();recovery_poll(&mut r,apply);recovery_poll(&mut r,apply);
 let w=domain_evidence::header();assert_eq!(w[448],0x4359_5254_534b_0001,"actual TaskGuard predicate has no recovery evidence");
 let a=recovery_task_latest();assert_eq!(&a[..8],&[1,1,443,0,key.id,1,key.id,1]);assert_eq!((a[8],a[9],a[10]),(1,2,2));
 locked(|s|{s.tasks[2].pending=false;Ok(())}).unwrap();
 FILE_BUSY[2].store(true,Ordering::Release);recovery_poll(&mut r,apply);assert_eq!(recovery_task_latest()[9],3);
 FILE_BUSY[2].store(false,Ordering::Release);locked(|s|{s.vectors[2]=Some(());Ok(())}).unwrap();
 VECTOR_READY.store(false,Ordering::Release);recovery_poll(&mut r,apply);assert_eq!(recovery_task_latest()[9],4);assert_eq!(VECTOR_QUERIES.load(Ordering::Acquire),1);
 locked(|s|{s.vectors[2]=None;Ok(())}).unwrap();VECTOR_READY.store(true,Ordering::Release);
 recovery_poll(&mut r,apply);assert_eq!((recovery_task_latest()[9],recovery_task_latest()[21]),(5,1),"queued readonly IPC was reported drained");
 locked(|s|{let endpoint=s.tasks[2].endpoint;assert_eq!(s.ipc.receive_batch(key,endpoint,now_ns(),&mut RecoveryMailbox)?,1);Ok(())}).unwrap();
 let dispatch=locked(|s|{let d=s.scheduler.dispatch(3,s.layout,now_ns(),1_000_000)?.unwrap();s.active[3]=Some(Active{dispatch:d,state:RunState::Runnable,optional:None,cpu_started:None});Ok(d)}).unwrap();
 recovery_poll(&mut r,apply);let a=recovery_task_latest();assert_eq!((a[9],a[24],a[25],a[26],a[27]),(6,1,dispatch.sequence,key.id,1));
 COMPLETE_ACTUAL[3].store(35_000,Ordering::Release);COMPLETE_AT[3].store(now_ns(),Ordering::Release);COMPLETE_READY[3].store(true,Ordering::Release);
 locked(|s|complete_locked(s,3)).unwrap();assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(key)),Ok(35_000));
 recovery_poll(&mut r,apply);assert_eq!(recovery_task_latest()[10],1); // real readonly drain succeeds
 recovery_poll(&mut r,apply); // request_stop changes actual Life
 recovery_poll(&mut r,apply);assert_eq!((recovery_task_latest()[8],recovery_task_latest()[9]),(2,1));
 let partial=service_segment(||locked(|s|cleanup(s,2))).unwrap();assert_eq!(partial,Err(Error::Busy));
 assert_eq!(locked(|s|s.memory.owner_pages(key)),Ok(2));recovery_poll(&mut r,apply);assert_eq!(r.query(apply).unwrap().state,ExecutionState::Pending);
 service_segment(||locked(|s|cleanup(s,2))).unwrap().unwrap();assert_eq!(locked(|s|s.memory.owner_pages(key)),Err(Error::Stale));
 recovery_poll(&mut r,apply);assert_eq!((recovery_task_latest()[8],recovery_task_latest()[10]),(2,1));
 recovery_poll(&mut r,apply); // controlled ELF construction uses real owners
 recovery_poll(&mut r,apply);assert_eq!((recovery_task_latest()[8],recovery_task_latest()[9]),(3,2));
 locked(|s|{assert_eq!(s.tasks[2].start_apply,Some(apply));s.tasks[2].heartbeat_ns=now_ns();s.tasks[2].pending=false;Ok(())}).unwrap(); // controlled EL0 return
 assert_eq!(recovery_poll(&mut r,apply).state,ExecutionState::Applied);
 assert_eq!(domain_evidence::header()[384],0,"recipe2 overwrote recipe1 predicate lane");
 assert_eq!(domain_evidence::header()[511]%2,0);
 let next=ObjectKey{id:key.id,generation:2};let next_apply=ApplyId{plan_seq:444,target:next,..apply};
 close_admission(next,next_apply).unwrap();assert_eq!(readonly_drained(next),Ok(true));
 let h=domain_evidence::header();assert_eq!((h[460],h[461],h[453]),(next.id,2,0),"new Task ApplyId inherited first blocker");
 assert!(h[504..510].iter().all(|v|*v==0));
}
#[test]fn recovery_predicates_do_not_advance_on_gate_busy_or_denied_or_retained_credit(){
 let(mut r,_key,apply)=recovery_fixture();recovery_poll(&mut r,apply);
 let before=domain_evidence::header();let guard=acquire_guard().unwrap();
 let receipt=r.poll(apply,now_ns(),&mut Recovery{apply}).unwrap();assert_eq!(receipt.state,ExecutionState::Pending);
 assert_eq!(&domain_evidence::header()[448..512],&before[448..512],"Busy fabricated a TaskGuard observation");drop(guard);
 READY.store(false,Ordering::Release);let before=domain_evidence::header();
 assert!(service_segment(||r.poll(apply,now_ns(),&mut Recovery{apply})).is_none());assert_eq!(domain_evidence::header(),before);READY.store(true,Ordering::Release);
 begin_service_segment().unwrap();work(60_000);DENY_SETTLE.store(true,Ordering::Release);complete_service(60_000,now_ns()).unwrap();
 let before=domain_evidence::header();assert!(service_segment(||r.poll(apply,now_ns(),&mut Recovery{apply})).is_none());
 assert_eq!(domain_evidence::header(),before);assert_eq!(COMPLETE_ACTUAL[0].load(Ordering::Acquire),60_000);
 DENY_SETTLE.store(false,Ordering::Release);recovery_poll(&mut r,apply);assert!(bills().iter().any(|v|v.1==60_000));
 let(mut r,key,apply)=recovery_fixture();recovery_poll(&mut r,apply);
 locked(|s|{s.tasks[2].pending=false;s.tasks[2].endpoint=ObjectKey{id:999,generation:1};Ok(())}).unwrap();
 assert_eq!(service_segment(||readonly_drained(key)),Some(Err(Error::Stale)),"IPC query error was collapsed into drain progress");
 let a=recovery_task_latest();assert_eq!((a[9],a[10],a[11],a[18]),(8,3,Error::Stale as u64+1,7));
 assert_eq!(a[24],0,"failed IPC query scanned or invented an active dispatch");
}
