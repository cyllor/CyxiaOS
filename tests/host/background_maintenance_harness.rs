// Host hardware ports surround real Timers and exact production service bodies.
// Console/supervision are empty; root byte/DMA and physical CPU accounting are
// outside this timer-owner seam. Full client mode uses the real FS/Journal below.
static MAINTENANCE_CALLS:AtomicU64=AtomicU64::new(0);
static MAINTENANCE_FLUSH:AtomicU64=AtomicU64::new(0);
static ADVANCE:AtomicBool=AtomicBool::new(true);
static PROGRESS_CALLS:AtomicU64=AtomicU64::new(0);
static LOCK_ON_SECOND:AtomicBool=AtomicBool::new(false);
static LAST_ARM_NOW:AtomicU64=AtomicU64::new(0);
static LAST_ARM_DEADLINE:AtomicU64=AtomicU64::new(0);
struct Board;impl Board{fn now_ns(&self)->u64{clock()}}
mod smp{pub mod prototype_runtime{pub struct Coordinator;impl Coordinator{pub fn poll(&mut self){if super::super::ADVANCE.load(super::super::Ordering::Relaxed){super::super::NOW.fetch_add(1_000_000,super::super::Ordering::Relaxed);}}}}}
mod actual_mechanism{use super::Board; // PRODUCTION_MECHANISM
 pub fn invoke(){mechanism_progress(&mut crate::smp::prototype_runtime::Coordinator);}}
fn maintenance_progress(){actual_mechanism::invoke();if PROGRESS_CALLS.fetch_add(1,Ordering::Relaxed)==1&&LOCK_ON_SECOND.load(Ordering::Relaxed){domain_services::set_locked(true);}}
mod domain_platform {
 use super::*;use cyxia_prototype::domains::platform::{Timers,TimerBackend,TimerArm,TimerClass};
 thread_local!{static TIMERS:RefCell<Timers>=const{RefCell::new(Timers::new())};}
 struct Events;
 impl TimerBackend for Events {
  fn arm(&mut self,_:TimerArm)->Result<(),Error>{Ok(())}
  fn cancel(&mut self,_:ObjectKey)->Result<(),Error>{Ok(())}
  fn fire(&mut self,key:ObjectKey)->Result<(),Error>{super::domain_services::due(key,clock());Ok(())}
 }
 pub fn now_ns()->u64{clock()}
 pub fn remove_fired_timer(){TIMERS.with(|t|t.borrow_mut().unregister(key()).unwrap());}
 pub fn register_missing_timer(){TIMERS.with(|t|t.borrow_mut().register(key(),TimerClass::Soft,1_000_000).unwrap());}
 pub fn key()->ObjectKey{ObjectKey{id:30,generation:1}}
 pub fn setup(){TIMERS.with(|t|{let mut t=t.borrow_mut();t.register(key(),TimerClass::Soft,1_000_000).unwrap();t.arm(key(),10_000_000,clock(),&mut Events).unwrap();});}
 pub fn poll(now:u64)->Result<(),Error>{TIMERS.with(|t|t.borrow_mut().poll(now,256,&mut Events).map(|_|()))}
 pub fn arm_timer(key:ObjectKey,deadline:u64,now:u64)->Result<TimerArm,Error>{let result=TIMERS.with(|t|t.borrow_mut().arm(key,deadline,now,&mut Events));LAST_ARM_NOW.store(now,Ordering::Relaxed);LAST_ARM_DEADLINE.store(deadline,Ordering::Relaxed);result}
}
mod domain_services {
 use super::*;use cyxia_prototype::policy::ExecutionState;
 static READY:AtomicBool=AtomicBool::new(true);static LOCK:AtomicBool=AtomicBool::new(false);static BACKGROUND_DUE:AtomicBool=AtomicBool::new(false);
 // PRODUCTION_BACKGROUND_PERIOD
 #[derive(Clone,Copy)]struct CoreRecord{state:ExecutionState,started:u64}
 struct State{core_records:[Option<CoreRecord>;0]}
 static mut STATE:State=State{core_records:[]};
 fn service_detail(_:usize){}
 fn publish_view(_:&State){}
 fn poll_services(_:&mut State,_:u64)->Result<(),Error>{Ok(())}
 fn pump_console(_:&mut State,_:u64)->Result<(),Error>{Ok(())}
 fn timer_key(_:&State)->ObjectKey{super::domain_platform::key()}
 pub fn due_now()->bool{BACKGROUND_DUE.load(Ordering::Acquire)}
 pub fn set_locked(value:bool){LOCK.store(value,Ordering::Release);}
 pub fn mark_due(){due(super::domain_platform::key(),clock());}
 // PRODUCTION_SERVICE_BODIES
}
