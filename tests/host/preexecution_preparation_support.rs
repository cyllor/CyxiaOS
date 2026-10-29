static PREP_CHECKS:AtomicU64=AtomicU64::new(0);
static BINDS:AtomicU64=AtomicU64::new(0);
static BIND_MODE:AtomicU64=AtomicU64::new(0);
static APPLY_CALLS:AtomicU64=AtomicU64::new(0);
impl Registry{fn model(&self)->u64{prep::MODEL_READS.fetch_add(1,Ordering::Relaxed);1}}
pub fn denial_scenarios(){
 for mode in 0..3{
  trace::test_reset();trace::begin(RUN,Family{domain:1,kind:1},key(12),100_000_000);WALL.store(100_001_000,Ordering::Release);
  BINDS.store(0,Ordering::Relaxed);APPLY_CALLS.store(0,Ordering::Relaxed);BIND_MODE.store(mode,Ordering::Relaxed);
  with(|s|{let d=s.owner.desired[0].as_mut().unwrap();d.apply=ID;d.stamp=STAMP;d.state=ExecutionState::Pending;d.started=false;d.execution_observed=false;d.core_generation=if mode==0{9}else{1};d.ledger_generation=1;d.dependencies=[None;2];Ok(())}).unwrap();
  poll(now()).unwrap();let c=trace::test_snapshots().0;
  assert_eq!(c[208],1,"pre-executor rejection was not retained");assert_eq!(&c[209..216],&[7,2,51,0,12,1,41]);assert_eq!(c[216],STAMP.snapshot_ns);
  assert_eq!(c[222]&255,1<<mode,"pre-executor branches were conflated");
  assert_eq!(c[222]>>8,(if mode==1{Error::Busy}else{Error::Stale}) as u64+1);
  assert_eq!(c[8],0,"denial manufactured an executor callback");assert_eq!(APPLY_CALLS.load(Ordering::Relaxed),0);assert_eq!(BINDS.load(Ordering::Relaxed),u64::from(mode!=0));
  if mode==1{
   with(|s|{assert_eq!(s.owner.desired[0].unwrap().state,ExecutionState::Pending);Ok(())}).unwrap();
   BIND_MODE.store(0,Ordering::Relaxed);poll(now()).unwrap();assert_eq!(APPLY_CALLS.load(Ordering::Relaxed),1,"Busy became a permanent refusal");assert_eq!(trace::test_snapshots().0[208],1);
  }else{
   with(|s|{let d=s.owner.desired[0].as_mut().unwrap();d.apply.plan_seq=52;d.stamp.version=42;d.state=ExecutionState::Pending;d.started=false;d.first_entry_ns=None;Ok(())}).unwrap();poll(now()).unwrap();
   let again=trace::test_snapshots().0;assert_eq!(again[208],2);assert_eq!(&again[209..216],&c[209..216],"a later denial replaced the original identity");
  }
  trace::close(RUN,110_000_000);let frozen=trace::test_snapshots().0;
  with(|s|{let d=s.owner.desired[0].as_mut().unwrap();d.state=ExecutionState::Pending;d.started=false;d.core_generation=9;d.apply.plan_seq=99;Ok(())}).unwrap();poll(now()).unwrap();assert_eq!(trace::test_snapshots().0,frozen,"later control replaced closed-scope facts");
 }
 trace::test_reset();trace::begin(RUN,Family{domain:1,kind:1},key(12),100_000_000);BIND_MODE.store(1,Ordering::Relaxed);BINDS.store(0,Ordering::Relaxed);
 with(|s|{let d=s.owner.desired[0].as_mut().unwrap();d.state=ExecutionState::Pending;d.started=true;d.core_generation=9;Ok(())}).unwrap();poll(now()).unwrap();assert_eq!(BINDS.load(Ordering::Relaxed),0,"started reconciliation repeated dependency admission");assert_eq!(trace::test_snapshots().0[208],0);
}
// ROOT_PREP_SUPPORT
