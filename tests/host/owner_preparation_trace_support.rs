mod domain_platform{pub fn now_ns()->u64{super::now()}}
mod service_windows{pub fn register_replay(_:super::Family,_:super::ObjectKey,_:u64)->Result<(),super::Error>{Ok(())}}
mod owner_prepare{
 use super::*;use super::control::prep as root;
 type DomainError=Error;use root::TrialKind;
 const SECOND:u64=1_000_000_000;
 const FAMILIES:[Family;1]=[Family{domain:1,kind:1}];
 static PAUSED:AtomicBool=AtomicBool::new(false);static WORK_READY:AtomicBool=AtomicBool::new(false);static STEPS:AtomicU64=AtomicU64::new(0);
 #[derive(Clone,Copy)]enum Phase{Prepare,Reserve}
 struct Schemas{ready:bool}impl Schemas{fn ready(&self)->Option<()>{self.ready.then_some(())}fn step(&mut self){STEPS.fetch_add(1,Ordering::Relaxed);}}
 struct State{preparation:Option<root::Preparation>,prepare_claimed:bool,schemas:Schemas,family:usize,group:u8,kind:TrialKind,trial_id:u64,prepared:Option<work::Prepared>,permit:Option<u64>,not_before:u64,phase:Phase}
 static STATE:Mutex<State>=Mutex::new(State{preparation:None,prepare_claimed:false,schemas:Schemas{ready:false},family:0,group:0,kind:TrialKind::Baseline,trial_id:1,prepared:None,permit:None,not_before:0,phase:Phase::Prepare});
 fn with<R>(f:impl FnOnce(&mut State)->Result<R,Error>)->Result<R,Error>{let mut s=STATE.try_lock().map_err(|_|Error::Busy)?;f(&mut s)}
 mod diagnostic{pub struct Attempt{pub words:[u64;32]}pub enum Site{Prepare}impl Attempt{pub fn site(&mut self,_:Site){}}}
 use diagnostic::Site;
 mod work{use super::*;pub const OWNER:ObjectKey=key(88);#[derive(Clone,Copy)]pub struct Prepared{pub target:ObjectKey,pub boundary:u64,pub baseline:Action}
  pub fn quiescent()->bool{true}pub fn bind_preparation(_:root::Preparation)->Result<(),Error>{Ok(())}pub fn prepare(_:Family,_:u64,_:TrialKind)->Result<Option<Prepared>,Error>{Ok(WORK_READY.load(Ordering::Relaxed).then_some(Prepared{target:key(12),boundary:0,baseline:Action::CpuWeight(1)}))}}
 mod capture{pub(crate)use crate::trace as execution_trace;pub fn prepare_start(_:super::ObjectKey,_:u64,_:super::Family)->Result<u64,super::Error>{Ok(7)}}
 mod service_windows{pub fn register_replay(_:super::Family,_:super::ObjectKey,_:u64)->Result<(),super::Error>{Ok(())}}
 fn domain_error(e:Error)->Error{e}fn evidence_error(e:Error)->Error{e}
 // PREP_IDENTITY
 // OWNER_PREP_STEP
 fn dispatch(trace:&mut diagnostic::Attempt)->Result<bool,DomainError>{let phase=with(|s|Ok(s.phase))?;match phase{
 // OWNER_DISPATCH
 Phase::Reserve=>(),
 }Ok(true)}
 pub fn scenarios(){
  for mode in 0..5{
   root::setup(9);PAUSED.store(mode==0,Ordering::Relaxed);WORK_READY.store(mode==4,Ordering::Relaxed);STEPS.store(0,Ordering::Relaxed);
   {let mut s=STATE.lock().unwrap();s.preparation=Some(root::identity(9));s.prepare_claimed=false;s.schemas.ready=mode!=1;s.permit=None;s.prepared=None;s.phase=Phase::Prepare;}
   if mode==2{root::blocker(ExecutionState::Pending,false,false);}else{root::ready();}
   let mut trace=diagnostic::Attempt{words:[0;32]};trace.words[10]=9;trace.words[14]=1;trace.words[15]=1;trace.words[16]=2;trace.words[31]=1000+mode;
   assert_eq!(dispatch(&mut trace),Ok(mode==4));let (_,_,o)=crate::trace::test_snapshots();
   assert_eq!(o[2],1,"outer preparation result was not retained");assert_eq!(o[3],1000+mode);assert_eq!(o[4],9);assert_eq!(o[14],[1,2,4,7,10][mode as usize]);assert_eq!(o[15],if mode==4{2}else{1});assert_eq!(o[63]&1,0);
   assert_eq!(STEPS.load(Ordering::Relaxed),u64::from(mode==1));
  }
  // Distinguish a new owner attempt that never entered Root's gate from an
  // earlier Root blocker. Do not attribute the previous Root row to trial10.
  root::new_identity(10);{let mut s=STATE.lock().unwrap();s.preparation=Some(root::identity(10));s.schemas.ready=true;s.phase=Phase::Prepare;s.prepare_claimed=false;}
  let root_calls=crate::trace::test_snapshots().1[2];let mut trace=diagnostic::Attempt{words:[0;32]};trace.words[10]=10;trace.words[14]=1;trace.words[15]=1;trace.words[16]=2;trace.words[31]=2000;
  root::with_gate_held(||assert_eq!(dispatch(&mut trace),Err(Error::Busy)));
  let (_,r,o)=crate::trace::test_snapshots();assert_eq!(r[2],root_calls);assert_eq!(o[4],10);assert_eq!(o[14],4);assert_eq!(o[15],3|((Error::Busy as u64+1)<<8));assert_ne!(r[4],o[4]);
  trace.words[31]=2001;assert_eq!(dispatch(&mut trace),Ok(true));let (_,r,o)=crate::trace::test_snapshots();assert_eq!(r[4],10);assert_eq!(o[4],10);assert_eq!(o[15],2,"Busy became a permanent preparation latch");
 }
}
