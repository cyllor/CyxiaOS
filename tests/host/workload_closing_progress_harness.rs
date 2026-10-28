#![allow(dead_code)]
extern crate self as cyxia_prototype;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error { NotReady=19, Busy=9, Capacity=4, Overflow=18, Conflict=6 }
pub mod policy {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum ExecutionState { Pending, Applied, Unknown, Failed }
    impl ExecutionState { pub fn terminal(self) -> bool { matches!(self, Self::Applied | Self::Failed) } }
}
use policy::ExecutionState;
type RunKey = u64;
const OWNER: u64 = 1;
const REQUEST_DEADLINE_NS: u64 = 5_000_000_000;
#[derive(Clone, Copy)]
struct Family { domain: u16 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Warm { id: u64, deadline: u64, active: bool }
struct Work { token: Option<u64>, family: Option<Family>, closing_version: u64,
    next_close: u64, close_probe: Option<Warm>, seed: u64, drained_at: Option<u64> }
static mut WORK: Work = Work { token: Some(9), family: Some(Family { domain: 1 }),
    closing_version: 0, next_close: 251, close_probe: None, seed: 7, drained_at: None };
static POLL_DONE: AtomicBool = AtomicBool::new(false);
static POLL_ERROR: AtomicBool = AtomicBool::new(false);
static POLL_ERRORS: AtomicUsize = AtomicUsize::new(0);
static PROBE_CREATES: AtomicUsize = AtomicUsize::new(0);
static PROBE_SUBMITS: AtomicUsize = AtomicUsize::new(0);
static PROBE_RESULTS: AtomicUsize = AtomicUsize::new(0);
static POLL_ORIGIN: std::sync::Mutex<Option<(u64,u64)>> = std::sync::Mutex::new(None);
static NOW: AtomicU64 = AtomicU64::new(100);
static CLOSING: AtomicUsize = AtomicUsize::new(0);
static VERSION: AtomicU64 = AtomicU64::new(4);
static BUSY: AtomicBool = AtomicBool::new(false);
static OUTCOME: AtomicBool = AtomicBool::new(false);
static CONSUMED: AtomicUsize = AtomicUsize::new(0);
static DRAINS: AtomicUsize = AtomicUsize::new(0);
static mut SUBMITS: Vec<(u64, u64, u64)> = Vec::new();
fn now() -> u64 { NOW.load(Ordering::Acquire) }
fn owner() -> Result<(), Error> { Ok(()) }
fn poll(run: RunKey) -> Result<bool, Error> { assert_eq!(run, 9);
    if POLL_ERROR.load(Ordering::Acquire){Err(Error::Busy)}else{Ok(POLL_DONE.load(Ordering::Acquire))} }
fn with<T>(f: impl FnOnce(&mut Work) -> Result<T, Error>) -> Result<T, Error> {
    // Single-threaded fixture. The production drain body controls borrowing and
    // every resource retirement; clocks, outcomes and external gates are spies.
    unsafe { f(&mut *core::ptr::addr_of_mut!(WORK)) }
}
fn control_work(f: Family) -> bool { f.domain == 4 }
fn uses_file(_: Family) -> bool { false }
fn uses_echo(_: Family) -> bool { false }
fn one_shot(f: Family) -> bool { f.domain == 14 }
enum CpuClass { ExecutorWork }
mod evidence {
    #[derive(Clone,Copy)] pub enum CaptureError {Deadline=15,DataIncomplete=6}
    #[derive(Clone,Copy)] pub enum Error {NotReady,Busy,Owner,Stale,Capacity,Capture(CaptureError)}
    pub fn measure<T>(_: u64, _: super::CpuClass, body: impl FnOnce() -> Result<T, super::Error>) -> Result<T, super::Error> { body() }
    pub mod execution_trace {
        use super::super::*;
        pub enum ClosingWork {
            DrainStart,PollReturned{result:Result<bool,Error>},PollOrigin{stage:u64,code:u64},
            ClosingObserved{version:u64,state:ExecutionState},
            ProbeCreated{version:u64,id:u64,deadline:u64},
            ProbeSubmit{id:u64,entered_ns:u64,result:Result<(),Error>},
            ProbeOutcome{id:u64,result:Result<u64,Error>},Block{reason:u64},Drained,
        }
        pub fn closing_work(run:u64,event:ClosingWork,_:u64){
            assert_eq!(run,9);
            match event {
                ClosingWork::PollReturned{result:Err(_)}=>{POLL_ERRORS.fetch_add(1,Ordering::AcqRel);}
                ClosingWork::PollOrigin{stage,code}=>{*POLL_ORIGIN.lock().unwrap()=Some((stage,code));}
                ClosingWork::ProbeCreated{version,id,deadline}=>{
                    assert_eq!((version,id,deadline),(4,251,5_000_000_100));PROBE_CREATES.fetch_add(1,Ordering::AcqRel);
                }
                ClosingWork::ProbeSubmit{id,entered_ns,result}=>{
                    assert_eq!(id,251);assert!(entered_ns>=100);let _=result;PROBE_SUBMITS.fetch_add(1,Ordering::AcqRel);
                }
                ClosingWork::ProbeOutcome{id,result}=>{
                    assert_eq!(id,251);assert_eq!(result,Ok(777));PROBE_RESULTS.fetch_add(1,Ordering::AcqRel);
                }
                _=>(),
            }
        }
    }
}
// POLL_NATIVE
struct Stamp { version: u64 }
struct Receipt { state: ExecutionState, stamp: Stamp }
struct Status { closing: Option<Receipt> }
mod root {
    use super::*;
    pub fn poll(token: u64) -> Result<Status, Error> {
        assert_eq!(token, 9);
        let state = match CLOSING.load(Ordering::Acquire) {
            0 => ExecutionState::Pending, 1 => ExecutionState::Applied,
            2 => ExecutionState::Unknown, _ => ExecutionState::Failed,
        };
        Ok(Status { closing: Some(Receipt { state, stamp: Stamp { version: VERSION.load(Ordering::Acquire) } }) })
    }
}
fn submit(_: Family, seed: u64, id: u64, _: u64, deadline: u64) -> Result<(), Error> {
    unsafe { (&mut *core::ptr::addr_of_mut!(SUBMITS)).push((seed, id, deadline)); }
    if BUSY.load(Ordering::Acquire) { Err(Error::Busy) } else { Ok(()) }
}
fn outcome(_: Family, id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    assert_eq!(id, 251);
    Ok(if OUTCOME.load(Ordering::Acquire) { CONSUMED.fetch_add(1, Ordering::AcqRel); Some(Ok(777)) } else { None })
}
fn retire() -> Result<bool, Error> { DRAINS.fetch_add(1, Ordering::AcqRel); Ok(true) }
mod domain_tasks { pub mod replay {
    pub fn within_work<T>(f: impl FnOnce() -> Result<T, super::super::Error>) -> Result<T, super::super::Error> { f() }
    pub fn drain(run: u64) -> Result<bool, super::super::Error> { assert_eq!(run, 9); super::super::retire() }
} }
mod core_work { pub fn drain() -> Result<bool, super::Error> { super::retire() } }
mod domain_storage { pub mod replay { pub fn drain() -> Result<bool, super::super::Error> { super::super::retire() } } }
mod domain_platform {
    pub mod irq_replay { pub fn drain(_: u64) -> Result<bool, super::super::Error> { super::super::retire() } }
    pub mod replay { pub fn drain(_: u64) -> Result<bool, super::super::Error> { super::super::retire() } }
}
mod domain_services { pub mod replay { pub fn drain(_: u64) -> Result<bool, super::super::Error> { super::super::retire() } } }
mod learning_prewarm { pub fn drain(_: u64) -> Result<bool, super::Error> { super::retire() } }
// PRODUCTION_DRAIN
fn reset(domain: u16) {
    unsafe { WORK = Work { token: Some(9), family: Some(Family { domain }),
        closing_version: 0, next_close: 251, close_probe: None, seed: 7, drained_at: None };
        (&mut *core::ptr::addr_of_mut!(SUBMITS)).clear(); }
    POLL_DONE.store(false, Ordering::Release); NOW.store(100, Ordering::Release);
    CLOSING.store(0, Ordering::Release); VERSION.store(4, Ordering::Release);
    BUSY.store(false, Ordering::Release); OUTCOME.store(false, Ordering::Release);
    DRAINS.store(0, Ordering::Release); CONSUMED.store(0, Ordering::Release);
    POLL_ERROR.store(false,Ordering::Release);POLL_ERRORS.store(0,Ordering::Release);
    PROBE_CREATES.store(0,Ordering::Release);PROBE_SUBMITS.store(0,Ordering::Release);PROBE_RESULTS.store(0,Ordering::Release);
    *POLL_ORIGIN.lock().unwrap()=None;
}
fn submissions() -> Vec<(u64, u64, u64)> { unsafe { (&*core::ptr::addr_of!(SUBMITS)).clone() } }
#[test]
fn closing_probe_can_progress_before_measurement_wait_all() {
    reset(1); assert_eq!(drain(9), Ok(false));
    assert_eq!(submissions(), [(7, 251, 5_000_000_100)], "closing demand blocked behind measurement wait-all");
    assert_eq!(PROBE_CREATES.load(Ordering::Acquire),1,"actual probe creation hook was absent");
    assert_eq!(PROBE_SUBMITS.load(Ordering::Acquire),1,"actual probe submit hook was absent");
    assert_eq!(DRAINS.load(Ordering::Acquire), 0);
}
#[test]
fn busy_retry_keeps_the_original_probe_identity_and_deadline() {
    reset(1); BUSY.store(true, Ordering::Release);
    assert_eq!(drain(9), Err(Error::Busy));
    let original = with(|s| Ok(s.close_probe)).unwrap().unwrap();
    NOW.store(300, Ordering::Release); VERSION.store(5, Ordering::Release);
    assert_eq!(drain(9), Err(Error::Busy));
    BUSY.store(false, Ordering::Release); assert_eq!(drain(9), Ok(false));
    assert_eq!(submissions(), vec![(7, original.id, original.deadline); 3]);
    assert_eq!(with(|s| Ok(s.next_close)), Ok(252));
    assert_eq!(DRAINS.load(Ordering::Acquire), 0);
}
#[test]
fn applied_receipt_does_not_retire_unfinished_probe_or_measurement() {
    reset(1); assert_eq!(drain(9), Ok(false));
    CLOSING.store(1, Ordering::Release);
    assert_eq!(drain(9), Ok(false)); assert_eq!(DRAINS.load(Ordering::Acquire), 0);
    OUTCOME.store(true, Ordering::Release);
    assert_eq!(drain(9), Ok(false));
    assert_eq!(CONSUMED.load(Ordering::Acquire), 1, "real closing result was not consumed");
    assert_eq!(PROBE_RESULTS.load(Ordering::Acquire),1,"probe actual result hook was absent");
    assert_eq!(DRAINS.load(Ordering::Acquire), 0, "resources retired before measurement wait-all");
    assert_eq!(with(|s| Ok(s.drained_at)), Ok(None));
    POLL_DONE.store(true, Ordering::Release);
    assert_eq!(drain(9), Ok(true)); assert_eq!(DRAINS.load(Ordering::Acquire), 1);
    assert_eq!(CONSUMED.load(Ordering::Acquire), 1);
}
#[test]
fn core_set_uses_only_its_real_transition_and_retains_wait_all() {
    reset(4); assert_eq!(drain(9), Ok(false));
    assert!(submissions().is_empty()); assert_eq!(DRAINS.load(Ordering::Acquire), 0);
    CLOSING.store(1, Ordering::Release); assert_eq!(drain(9), Ok(false));
    assert_eq!(DRAINS.load(Ordering::Acquire), 0);
    POLL_DONE.store(true, Ordering::Release); assert_eq!(drain(9), Ok(true));
    assert_eq!(DRAINS.load(Ordering::Acquire), 1); assert!(submissions().is_empty());
}
#[test]
fn recovery_preserves_one_shot_drain_without_synthetic_closing_work() {
    reset(14); assert_eq!(drain(9), Ok(false)); assert_eq!(DRAINS.load(Ordering::Acquire), 0);
    POLL_DONE.store(true, Ordering::Release); assert_eq!(drain(9), Ok(true));
    assert_eq!(DRAINS.load(Ordering::Acquire), 2); assert!(submissions().is_empty());
}
#[test]
fn terminal_failed_closing_cannot_construct_a_probe() {
    reset(1); CLOSING.store(3, Ordering::Release);
    assert_eq!(drain(9), Err(Error::Conflict)); assert!(submissions().is_empty());
    assert_eq!(DRAINS.load(Ordering::Acquire), 0);
}
#[test]
fn poll_failure_is_observed_before_return_without_new_probe_effects(){
    reset(1);POLL_ERROR.store(true,Ordering::Release);
    assert_eq!(drain(9),Err(Error::Busy));
    assert_eq!(POLL_ERRORS.load(Ordering::Acquire),1,"poll failure vanished before original error propagation");
    assert!(submissions().is_empty());assert_eq!(DRAINS.load(Ordering::Acquire),0);
}
#[test]
fn native_mapping_retains_the_original_evidence_error_and_stage(){
    reset(1);
    assert_eq!(poll_native(9,2,evidence::Error::Capture(evidence::CaptureError::Deadline)),Error::NotReady);
    assert_eq!(*POLL_ORIGIN.lock().unwrap(),Some((2,0x110)),"native mapping erased the evidence failure origin");
}
