pub mod prep{
 use super::*;
 pub static MODEL_READS:AtomicU64=AtomicU64::new(0);
 static NOW_READS:AtomicU64=AtomicU64::new(0);
 static AUTH_READS:AtomicU64=AtomicU64::new(0);
 fn now()->u64{NOW_READS.fetch_add(1,Ordering::Relaxed);super::now()}
 #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum TrialKind{Baseline,Candidate}
 #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub struct Preparation{pub id:u64,pub boot_epoch:u64,pub owner:ObjectKey,pub trial_id:u64,pub family:Family,pub seed:u64,pub kind:TrialKind,pub started_ns:u64}
 #[derive(Clone,Copy)]struct Preparing{identity:Preparation,failure:Option<Error>,model:u64,ready:bool,cursor:usize}
 struct Root{preparing:Option<Preparing>}
 static mut ROOT:Root=Root{preparing:None};
 fn root_mut()->&'static mut Root{unsafe{&mut *core::ptr::addr_of_mut!(ROOT)}}
 fn root()->&'static Root{unsafe{&*core::ptr::addr_of!(ROOT)}}
 fn authorized(_: &State)->Result<(),Error>{AUTH_READS.fetch_add(1,Ordering::Relaxed);Ok(())}
 pub fn identity(trial:u64)->Preparation{Preparation{id:trial+10,boot_epoch:7,owner:key(88),trial_id:trial,family:Family{domain:1,kind:1},seed:1,kind:TrialKind::Baseline,started_ns:90_000_000}}
 pub fn setup(trial:u64){
  trace::test_reset();BIND_MODE.store(0,Ordering::Relaxed);PREP_CHECKS.store(0,Ordering::Relaxed);MODEL_READS.store(0,Ordering::Relaxed);NOW_READS.store(0,Ordering::Relaxed);AUTH_READS.store(0,Ordering::Relaxed);WALL.store(100_001_000,Ordering::Release);
  with(|s|{s.job=None;s.owner.prepared_count=0;s.owner.desired=[None;16];root_mut().preparing=Some(Preparing{identity:identity(trial),failure:None,model:1,ready:false,cursor:0});Ok(())}).unwrap();
 }
 pub fn blocker(state:ExecutionState,observed:bool,one_shot:bool){with(|s|{s.owner.desired[3]=Some(Desired{action:if one_shot{Action::ControlSet(3)}else{Action::CpuWeight(2)},apply:ID,stamp:STAMP,state,started:true,first_entry_ns:Some(100_000_000),observed_ns:100_000_000,published:100_000_000,evidence:None,job:51,dependencies:[None;2],core_generation:1,ledger_generation:1,execution_observed:observed});Ok(())}).unwrap();}
 pub fn ready(){with(|_|{root_mut().preparing.as_mut().unwrap().ready=true;Ok(())}).unwrap();}
 // PREP_IDENTITY
 // ROOT_PREPARATION
 pub fn call(p:Preparation,at:u64)->Result<bool,Error>{// POLL_CALL
 }
 pub fn scenarios(){
  for mode in 0..3{
   setup(2);let state=if mode==0{ExecutionState::Pending}else{ExecutionState::Applied};blocker(state,mode==2,false);
   assert_eq!(call(identity(2),101),Ok(false));let (_,r,_)=trace::test_snapshots();
   assert_eq!(r[2],1,"actual preparation blocker was not retained");assert_eq!(r[3],101);assert_eq!(r[4],2);assert_eq!(r[14],6);assert_eq!(r[21],4);assert_eq!(r[22],1<<mode);
   assert_eq!(&r[23..29],&[7,2,51,0,12,1]);assert_eq!(r[29],41);assert_eq!(r[34],u64::from(mode==2));
   assert_eq!(PREP_CHECKS.load(Ordering::Relaxed),1);assert_eq!(NOW_READS.load(Ordering::Relaxed),u64::from(mode==2));assert_eq!(MODEL_READS.load(Ordering::Relaxed),1);
  }
  setup(3);with(|s|{s.job=Some(());Ok(())}).unwrap();assert_eq!(call(identity(3),102),Ok(false));let (_,r,_)=trace::test_snapshots();assert_eq!((r[4],r[14],r[16]),(3,5,1));assert_eq!(PREP_CHECKS.load(Ordering::Relaxed),0);assert_eq!(NOW_READS.load(Ordering::Relaxed),0);
  setup(4);blocker(ExecutionState::Failed(Error::Stale),true,true);assert_eq!(call(identity(4),103),Ok(false));let (_,r,_)=trace::test_snapshots();assert_eq!(r[14],7);assert_eq!(r[20],8);assert_eq!(NOW_READS.load(Ordering::Relaxed),0);assert_eq!(call(identity(4),104),Ok(true));assert_eq!(trace::test_snapshots().1[14],8);
  // A new trial replaces the latest record, not a permanent failure latch.
  with(|_|{root_mut().preparing=Some(Preparing{identity:identity(5),failure:None,model:1,ready:true,cursor:0});Ok(())}).unwrap();assert_eq!(call(identity(5),105),Ok(true));let (_,r,_)=trace::test_snapshots();assert_eq!((r[4],r[5],r[14],r[21]),(5,15,4,0));assert_eq!(r[63]&1,0);
  setup(6);blocker(ExecutionState::Pending,false,false);with(|s|{s.owner.desired[9]=s.owner.desired[3].take();Ok(())}).unwrap();
  assert_eq!(call(identity(6),106),Ok(false));assert_eq!(PREP_CHECKS.load(Ordering::Relaxed),0,"preparation scanned beyond eight slots");assert_eq!(trace::test_snapshots().1[20],8);
  assert_eq!(call(identity(6),107),Ok(false));assert_eq!(PREP_CHECKS.load(Ordering::Relaxed),1);assert_eq!(NOW_READS.load(Ordering::Relaxed),0);assert_eq!(trace::test_snapshots().1[21],10);
 }
 pub fn new_identity(trial:u64){with(|_|{root_mut().preparing=Some(Preparing{identity:identity(trial),failure:None,model:1,ready:true,cursor:0});Ok(())}).unwrap();}
 pub fn with_gate_held(f:impl FnOnce()){let guard=STATE.lock().unwrap();f();drop(guard);}
 pub fn begin_preparation(_:ObjectKey,trial:u64,_:Family,_:u64,_:TrialKind)->Result<Preparation,Error>{Ok(identity(trial))}
 pub fn claim_preparation(_:Preparation)->Result<(),Error>{Ok(())}
 pub fn withdraw_preparation(_:Preparation)->Result<(),Error>{Ok(())}
}
