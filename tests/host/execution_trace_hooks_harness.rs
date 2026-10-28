//! Non-test production hook bodies; hardware, transport, history and stability
//! callbacks are explicit host boundaries. No native latency claim is made.
#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use cyxia_prototype::{domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp, tasks::*, maintenance::{BackgroundBudgets,CpuDebit}}, learning::{self, Family, capture::RunKey}, policy::ExecutionState};
static CPU: AtomicUsize = AtomicUsize::new(0);
static WALL: AtomicU64 = AtomicU64::new(100_001_000);
static WORK: AtomicU64 = AtomicU64::new(0);
static FINISHED: AtomicU64 = AtomicU64::new(0);
const fn key(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
const RUN: RunKey = RunKey { boot_epoch: 7, trial_id: 9, generation: 3 };
const STAMP: PolicyStamp = PolicyStamp { version: 41, snapshot_ns: 100_000_000, installed_until_ns: 10_100_000_000 };
const ID: ApplyId = ApplyId { boot_epoch:7, controller_epoch:2, plan_seq:51, action_index:0, target:key(12) };
pub mod cpu { pub fn slot() -> usize { super::CPU.load(super::Ordering::Acquire) } }
mod timer {
    pub fn ticks() -> u64 { super::WALL.load(super::Ordering::Acquire) }
    pub fn frequency() -> u64 { 1_000_000_000 }
    pub fn cpu_ticks() -> u64 { super::WORK.load(super::Ordering::Acquire) }
}
fn now() -> u64 { timer::ticks() }
// TRACE_MODULE
mod learning_evidence {
    pub(crate) use super::trace as execution_trace;
    pub fn attempt(_: super::ObjectKey, _: cyxia_prototype::learning::reward::CpuClass) -> Result<Option<()>, super::Error> { Ok(None) }
    pub fn finish_attempt(_: &mut (), _: u64, _: u64) -> Result<(), super::Error> { Ok(()) }
}
mod storage_fault_capture { pub const PROFILE: bool = false; }
mod domain_tasks {
    pub fn finish_cpu_interval(start: u64) -> (u64,u64,u64) {
        let actual = super::timer::cpu_ticks() - start; let last = super::now(); (last-actual,last,actual)
    }
}
mod domain_evidence {
    pub fn progress(_: usize,_: u64,_: u64,_: super::ExecutionState,_: u64) {}
    pub fn stability_failed(_: u16,_: u64,_: super::Error) {}
}
mod learning_history {
    pub struct Execution { pub apply: super::ApplyId, pub stamp: super::PolicyStamp, pub state: super::ExecutionState,
        pub observed_ns:u64, pub started_ns:Option<u64>, pub executor_generation:Option<u64> }
    pub fn record_execution(_: Execution) -> Result<bool,super::Error> { Ok(false) }
}
mod task {
    use super::*;
    static READY: AtomicBool = AtomicBool::new(true);
    static COMPLETE_READY: [AtomicBool;64] = [const { AtomicBool::new(false) };64];
    static COMPLETE_ACTUAL: [AtomicU64;64] = [const { AtomicU64::new(0) };64];
    static COMPLETE_AT: [AtomicU64;64] = [const { AtomicU64::new(0) };64];
    static CREDIT_KIND: [AtomicU64;64] = [const { AtomicU64::new(0) };64];
    struct Bank { words:[AtomicU64;32] }
    static DOMAIN_TASK_EVIDENCE: Bank = Bank { words:[const { AtomicU64::new(0) };32] };
    static TASK_OVERRUN_EVIDENCE: Bank = Bank { words:[const { AtomicU64::new(0) };32] };
    #[derive(Clone,Copy)] struct Active { dispatch:Dispatch,state:RunState,optional:Option<CpuDebit> }
    struct Counter; impl Counter { fn add(&mut self,_:u64,_:u64) {} }
    struct Facts { cpu:[Counter;16] }
    struct State { scheduler:Scheduler,active:[Option<Active>;64],background:BackgroundBudgets,facts:Facts }
    static mut STATE: State = State { scheduler:Scheduler::new(),active:[None;64],background:BackgroundBudgets::new(),facts:Facts { cpu:[const { Counter };16] } };
    fn now_ns() -> u64 { now() }
    fn group(id:u64) -> ObjectKey { key(id) }
    fn group_index(_: &State,_:ObjectKey) -> Result<usize,Error> { Err(Error::NotFound) }
    fn publish_evidence(_: &State) {}
    // TASK_BODIES
    pub fn initialize() {
        locked(|s| { s.scheduler.register_group(key(12))?;
            s.scheduler.admit(ThreadSpec { key:key(99),group:key(12),cpu:3,allowed_mask:8,minimum_ns:0,budget_ns:20_000_000 },
                CpuLayout { business_mask:9,healthy_mask:15,generation:1 },now()) }).unwrap();
    }
    pub fn install() -> Result<(),Error> {
        locked(|s| { s.scheduler.install_weight(key(12),2,STAMP,now())?;
            trace::installed(key(12),STAMP,now()); Ok(()) })
    }
    pub fn version() -> Result<u64,Error> { locked(|s| s.scheduler.policy_receipt(key(12))) }
    pub fn execute_and_settle() {
        CPU.store(3,Ordering::Release); WALL.store(100_010_000,Ordering::Release);
        let d = locked(|s| {
            let d=s.scheduler.dispatch_with_window_headroom(3,CpuLayout { business_mask:9,healthy_mask:15,generation:1 },now(),2_000_000,20_000_000)?.unwrap();
            s.active[3]=Some(Active { dispatch:d,state:RunState::Runnable,optional:None });
            trace::selected(d); Ok(d)
        }).unwrap();
        assert_eq!(d.policy_version,41);
        COMPLETE_AT[3].store(100_030_000,Ordering::Relaxed);
        COMPLETE_ACTUAL[3].store(20_000,Ordering::Relaxed);
        COMPLETE_READY[3].store(true,Ordering::Release);
        WALL.store(100_500_000,Ordering::Release);
        locked(|s| complete_locked(s,3)).unwrap();
        assert_eq!(version(),Ok(41));
        FINISHED.store(100_030_000,Ordering::Release);
        CPU.store(0,Ordering::Release);
    }
    pub fn execute_closing() {
        WALL.store(210_000_000,Ordering::Release);
        let stamp=PolicyStamp{version:42,snapshot_ns:210_000_000,installed_until_ns:10_210_000_000};
        trace::closing(key(12),100_000_000,ApplyId{plan_seq:52,..ID},stamp,now(),260_000_000,now());
        locked(|s| {s.scheduler.install_weight(key(12),1,stamp,now())?;
            trace::installed(key(12),stamp,now());Ok(())}).unwrap();
        CPU.store(3,Ordering::Release);WALL.store(210_010_000,Ordering::Release);
        let d=locked(|s| {
            let d=s.scheduler.dispatch_with_window_headroom(3,CpuLayout{business_mask:9,healthy_mask:15,generation:1},now(),2_000_000,20_000_000)?.unwrap();
            s.active[3]=Some(Active{dispatch:d,state:RunState::Runnable,optional:None});trace::selected(d);Ok(d)
        }).unwrap();
        assert_eq!(d.policy_version,42);
        COMPLETE_AT[3].store(210_030_000,Ordering::Relaxed);
        COMPLETE_ACTUAL[3].store(20_000,Ordering::Relaxed);
        COMPLETE_READY[3].store(true,Ordering::Release);
        WALL.store(210_500_000,Ordering::Release);
        locked(|s|complete_locked(s,3)).unwrap();
        assert_eq!(version(),Ok(42));CPU.store(0,Ordering::Release);
    }
}
mod control {
    use super::*;
    #[derive(Clone,Copy)] struct Desired { action:Action,apply:ApplyId,stamp:PolicyStamp,state:ExecutionState,
        started:bool,first_entry_ns:Option<u64>,observed_ns:u64,published:u64,evidence:Option<usize>,job:u64,
        dependencies:[Option<u8>;2],core_generation:u64,ledger_generation:u64,execution_observed:bool }
    #[derive(Clone,Copy)] struct FamilyEntry {
        apply:fn(Action,ApplyId,PolicyStamp,u64)->Result<ExecutionState,Error>,
        reconcile:fn(Action,ApplyId,PolicyStamp,u64)->Result<ExecutionState,Error>,
        current:fn(u16,u16,ObjectKey)->Result<Action,Error>,
    }
    struct Stability;
    impl Stability {
        fn observe_execution(&mut self,_:u64,_:Action,_:ExecutionState,_:u64)->Result<(),Error>{Ok(())}
        fn family(&self)->(u16,u16){(1,1)} fn target(&self)->ObjectKey{key(12)}
    }
    struct Context {core_generation:u64,ledger_generation:u64}
    struct Owner { desired:[Option<Desired>;1],stability:[Option<Stability>;1],families:[Option<FamilyEntry>;1],
        family_epochs:[u64;1],stability_high:usize,poll_cursor:usize,context:Context }
    struct Registry; impl Registry {
        fn reconcile(&mut self,_:ApplyId,_:u64,_:ExecutionState)->Result<(),Error>{Ok(())}
        fn stop_optimization(&mut self){}
    }
    struct Admission; impl Admission {fn publish(&self,_:usize,_:Prerequisite,_:u64,_:u64,_:ExecutionState){} fn retire(&self,_:usize){} }
    static ADMISSION: Admission=Admission;
    struct Prerequisite {domain:u16,target:ObjectKey}
    struct State {owner:Owner,registry:Registry}
    static STATE:Mutex<State>=Mutex::new(State {owner:Owner {
        desired:[Some(Desired {action:Action::CpuWeight(2),apply:ID,stamp:STAMP,state:ExecutionState::Pending,
            started:false,first_entry_ns:None,observed_ns:100_000_500,published:100_000_500,evidence:None,job:51,
            dependencies:[None;2],core_generation:1,ledger_generation:1,execution_observed:false})],
        stability:[Some(Stability)],families:[Some(FamilyEntry {apply,reconcile,current:|_,_,_|Ok(Action::CpuWeight(2))})],
        family_epochs:[1],stability_high:1,poll_cursor:0,context:Context {core_generation:1,ledger_generation:1}},registry:Registry});
    fn with<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{let mut guard=STATE.try_lock().map_err(|_|Error::Busy)?;f(&mut guard)}
    fn family_index(_:u16,_:u16)->Result<usize,Error>{Ok(0)}
    fn bind_dependencies(_: &Owner,_:Action,_:ObjectKey,_:u64)->Result<[Option<u8>;2],Error>{Ok([None;2])}
    fn observe_execution(_: &mut State,d:&mut Desired){if d.state==ExecutionState::Applied {d.execution_observed=true;}}
    fn apply(_:Action,_:ApplyId,_:PolicyStamp,_:u64)->Result<ExecutionState,Error>{
        task::install()?; WORK.fetch_add(37,Ordering::AcqRel); WALL.fetch_add(1_000,Ordering::AcqRel); Ok(ExecutionState::Pending)
    }
    fn reconcile(_:Action,_:ApplyId,_:PolicyStamp,_:u64)->Result<ExecutionState,Error>{
        WORK.fetch_add(41,Ordering::AcqRel); WALL.fetch_add(2_000,Ordering::AcqRel);
        Ok(if task::version()?==41 {ExecutionState::Applied}else{ExecutionState::Pending})
    }
    // CONTROL_BODIES
    pub fn observe(){poll(now()).unwrap();}
}
mod warm {
    use super::*;
    use super::learning_evidence as evidence;
    const REQUEST_DEADLINE_NS:u64=1_000_000_000;
    #[derive(Clone,Copy)] struct Scope {key:RunKey}
    #[derive(Clone,Copy)] struct Warm {id:u64,deadline:u64,active:bool}
    struct State {warm:Option<Warm>,seed:u64,warm_at:u64,next_warm:u64,scope:Option<Scope>}
    static STATE:Mutex<State>=Mutex::new(State {warm:None,seed:1,warm_at:0,next_warm:101,scope:Some(Scope {key:RUN})});
    static CALLS:AtomicU64=AtomicU64::new(0);
    fn transient(e:Error)->bool {matches!(e,Error::Busy|Error::Again|Error::NotReady)}
    fn submit(_:Family,_:u64,_:u64,_:u64,_:u64)->Result<(),Error>{
        WALL.fetch_add(1_000,Ordering::AcqRel);
        if CALLS.fetch_add(1,Ordering::AcqRel)==0 {Err(Error::Busy)}else{Ok(())}
    }
    fn outcome(_:Family,_:u64)->Result<Option<Result<u64,Error>>,Error>{
        WALL.fetch_add(2_000,Ordering::AcqRel); let at=FINISHED.load(Ordering::Acquire);
        Ok((at!=0).then_some(Ok(at)))
    }
    // WARM_BODY
    pub fn advance(){let at=now(); warm(&mut STATE.lock().unwrap(),Family {domain:1,kind:1},2_000_000_000,at).unwrap();}
}
fn main(){
    trace::begin(RUN,Family {domain:1,kind:1},key(12),100_000_000);
    task::initialize(); control::observe();
    assert_eq!(trace::snapshots().0[8],1,"actual control poll did not retain its execution hook");
    WALL.store(100_004_000,Ordering::Release); warm::advance();
    WALL.store(100_005_000,Ordering::Release); warm::advance();
    WALL.store(100_006_000,Ordering::Release); warm::advance();
    let (_,_,w)=trace::snapshots();
    assert_eq!(w[14],2,"actual warm submit hook was absent");
    assert_eq!((w[16],w[29],w[18]),(100_005_000,100_006_000,100_007_000),"warm hook replaced submit return with entry time");
    task::execute_and_settle();
    WALL.store(200_000_000,Ordering::Release); control::observe();
    WALL.store(200_003_000,Ordering::Release); warm::advance();
    let (c,t,w)=trace::snapshots();
    assert_eq!((t[37],t[43]),(100_030_000,100_500_000),"actual settlement hook lost physical or observed time");
    assert_eq!((c[27],c[28],c[31],c[32]),(1,1,200_002_000,78));
    assert_eq!((w[20],w[30]),(200_005_000,100_030_000),"actual warm outcome hook lost completion/observation distinction");
    task::execute_closing();
    let (_,t,_)=trace::snapshots();
    assert_eq!((t[109],t[111]),(210_030_000,210_500_000),"production closing settlement hook was gated out");
    assert_eq!(t[10],1,"closing settlement polluted first-policy counters");
    println!("production execution hooks passed");
}
