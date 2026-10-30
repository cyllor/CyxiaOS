//! Actual native collector ingress with host clocks. These are contention
//! counterexamples, not native samples or accepted learning evidence.
extern crate self as cyxia_arch_aarch64;
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_tasks/cancellation.rs"]
mod cancellation;
mod domain_tasks {
    pub(crate) use super::cancellation::Cancellation;
}

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        self, Family,
        capture::{FrozenRequest, RunKey, Source},
        reward::{CpuClass, CpuInterval, OBSERVATION_NS, RequestResult},
    },
};

pub mod cpu {
    use core::cell::Cell;
    std::thread_local! { static CORE: Cell<usize> = const { Cell::new(0) }; }
    pub fn slot() -> usize {
        CORE.with(Cell::get)
    }
    pub fn at(core: usize) {
        CORE.with(|value| value.set(core));
    }
}
pub mod domain_platform {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    static CLOCK: AtomicU64 = AtomicU64::new(0);
    static READS: AtomicUsize = AtomicUsize::new(0);
    pub fn now_ns() -> u64 {
        READS.fetch_add(1, Ordering::Relaxed);
        CLOCK.load(Ordering::Acquire)
    }
    pub fn reads() -> usize {
        READS.load(Ordering::Relaxed)
    }
    pub fn at(value: u64) {
        CLOCK.store(value, Ordering::Release);
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_evidence.rs"]
mod bridge;

static ALLOCATION: AtomicUsize = AtomicUsize::new(0);
static CLASSIFIER_BUSY: AtomicBool = AtomicBool::new(false);
static CHILD_LIVE: AtomicBool = AtomicBool::new(true);
const FIRST: u64 = 1_000_000_000;
const OBS: u64 = FIRST + 6_000_000_000;
const END: u64 = OBS + OBSERVATION_NS;
const fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn pool_check(owner: ObjectKey, address: usize, bytes: usize) -> Result<(), bridge::Error> {
    if owner == key(44)
        && address == ALLOCATION.load(Ordering::Acquire)
        && bytes == bridge::STORAGE_BYTES
    {
        Ok(())
    } else {
        Err(bridge::Error::Owner)
    }
}
fn classify(
    _: RunKey,
    owner: ObjectKey,
    _: CpuClass,
) -> Result<bridge::SourceDisposition, learning::Error> {
    if CLASSIFIER_BUSY.load(Ordering::Acquire) {
        return Err(learning::Error::Unknown);
    }
    match owner.id {
        99 if CHILD_LIVE.load(Ordering::Acquire) => Ok(bridge::SourceDisposition::Measure(key(13))),
        // Even a classifier that calls a roster member outside cannot hide
        // that actual registered source. The collector must check first.
        13 | 100 => Ok(bridge::SourceDisposition::Outside),
        _ => Err(learning::Error::DataIncomplete),
    }
}
fn sources() -> [Source; 3] {
    [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
    ]
    .map(|class| Source {
        owner: key(11 + class as u64),
        class,
        allowed_cores: 1,
    })
}
fn begin(trial: u64) -> RunKey {
    cpu::at(0);
    domain_platform::at(FIRST);
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        owner: key(20),
        id: i as u64 + 1,
        arrived_ns: OBS + i as u64 * 1_000_000,
    });
    let run = bridge::start(
        trial,
        Family { domain: 1, kind: 1 },
        FIRST,
        OBS,
        [7; 32],
        &sources(),
        &requests,
    )
    .unwrap();
    for request in requests {
        domain_platform::at(request.arrived_ns);
        let token = bridge::request(request.owner, request.id).unwrap();
        bridge::issued(token).unwrap();
        domain_platform::at(request.arrived_ns + 100);
        bridge::result(
            token,
            RequestResult::Completed {
                finished_ns: request.arrived_ns + 100,
            },
        )
        .unwrap();
    }
    run
}
fn close_and_export(incomplete: bool) -> cyxia_prototype::learning::capture::Seal {
    domain_platform::at(END + 1000);
    for source in sources() {
        let token = bridge::source(source.owner, source.class).unwrap();
        let mut closed = false;
        for _ in 0..64 {
            match bridge::close_source(token) {
                Ok(()) => {
                    closed = true;
                    break;
                }
                Err(bridge::Error::Busy) => {}
                result => panic!("unexpected source close: {result:?}"),
            }
        }
        assert!(closed, "original completed producers must eventually drain");
    }
    cpu::at(0);
    bridge::seal(incomplete).unwrap()
}


mod timer {
    pub fn cpu_ticks()->u64 { crate::domain_platform::now_ns() }
    pub fn cpu_elapsed_ns(first:u64)->u64 { crate::domain_platform::now_ns()-first }
}
fn recorder_cost() { domain_platform::at(domain_platform::now_ns()+17); }
mod paid {
    use cyxia_prototype::domains::{Error,ObjectKey,tasks::{Scheduler,Dispatch,ThreadSpec,CpuLayout,RunState}};
    use crate::timer;
    struct Task { parent:ObjectKey,spawn_id:u64,key:ObjectKey,recipe:u16 }
    struct State { tasks:[Task;1] }
    mod replay {
        use super::*;
        pub fn work_source(parent:ObjectKey,id:u64,recipe:u16)->Option<ObjectKey> {
            (parent==ObjectKey{id:70,generation:8} && id==9 && recipe==2)
                .then_some(ObjectKey{id:13,generation:1})
        }
    }
    static DEBIT:std::sync::Mutex<Option<(Scheduler,Dispatch)>>=std::sync::Mutex::new(None);
    static ACTUAL:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);
    fn now_ns()->u64 { crate::domain_platform::now_ns() }
    fn begin_service_segment()->Option<Dispatch> {
        let mut held=DEBIT.lock().unwrap();assert!(held.is_none());
        let mut s=Scheduler::new();let group=ObjectKey{id:999,generation:1};
        s.register_group(group).unwrap();
        let layout=CpuLayout{business_mask:1,healthy_mask:15,generation:1};
        s.admit(ThreadSpec{key:crate::key(13),group,cpu:0,allowed_mask:1,minimum_ns:0,budget_ns:10_000_000},layout,now_ns()).unwrap();
        let d=s.dispatch_with_window_headroom(0,layout,now_ns(),2_500_000,20_000_000).unwrap().unwrap();
        *held=Some((s,d));Some(d)
    }
    fn revalidate_service_segment()->bool { DEBIT.lock().unwrap().is_some() }
    fn complete_service(actual:u64,finished:u64)->Result<(),Error> {
        let (mut s,d)=DEBIT.lock().unwrap().take().unwrap();
        let result=s.complete(d,actual,RunState::Runnable,finished);
        ACTUAL.fetch_add(s.stats().actual_ns,std::sync::atomic::Ordering::AcqRel);result
    }
    // ACTUAL_PAID_BODIES
    fn cleanup_inner(_: &mut State,_:usize)->Result<(),Error> {
        crate::domain_platform::at(now_ns()+37);Ok(())
    }
    pub fn cleanup_case() {
        let mut s=State{tasks:[Task{parent:ObjectKey{id:70,generation:8},spawn_id:9,
            key:ObjectKey{id:4097,generation:6},recipe:2}]};
        assert_eq!(service_segment(||cleanup(&mut s,0)),Some(Ok(())));
    }
    pub fn io_case() {
        assert_eq!(service_io_piece(Some(crate::key(13)),&mut ||{},|_| {
            crate::domain_platform::at(now_ns()+37);37
        }),Some(37));
    }
    pub fn io_resume_case() {
        assert_eq!(service_io_piece(Some(crate::key(13)),&mut ||{crate::domain_platform::at(now_ns()+63)},|progress| {
            crate::domain_platform::at(now_ns()+37);progress();
            crate::domain_platform::at(now_ns()+37);74
        }),Some(74));
    }
    pub fn actual()->u64 {ACTUAL.load(std::sync::atomic::Ordering::Acquire)}
}
#[test]
fn recorder_instructions_are_inside_original_physical_and_ledger_samples() {
 std::thread::Builder::new().stack_size(8*1024*1024).spawn(|| {
    let storage=Box::leak(Box::new(bridge::Storage::empty()));
    ALLOCATION.store(storage as *mut bridge::Storage as usize,Ordering::Release);
    bridge::install(storage,[1;32],7,key(44),pool_check).map_err(|(e,_)|e).unwrap();
    bridge::register_source_classifier(classify).unwrap();begin(1);
    domain_platform::at(OBS+200_000_000);
    let case=std::env::var("CYXIA_SOURCE_COST_CASE").unwrap();
    if case=="generic" {
        bridge::measure(key(13),CpuClass::ExecutorWork,||domain_platform::at(OBS+200_000_037));
        assert_eq!(domain_platform::now_ns(),OBS+200_000_037,"unproved generic path added diagnostic CPU");
        assert_eq!(bridge::test_support::source_snapshot(),[0;128],"unproved generic path published a diagnostic");
        return;
    }
    if case=="completion" {
        let mut a=bridge::attempt_work(key(13),false).unwrap().unwrap();
        domain_platform::at(OBS+200_000_037);
        bridge::finish_attempt(&mut a,OBS+200_000_000,OBS+200_000_037).unwrap();
        assert_eq!(domain_platform::now_ns(),OBS+200_000_037,"completion added uncharged diagnostic CPU");
        assert_eq!(bridge::test_support::source_snapshot(),[0;128],"completion published a diagnostic");
        return;
    }
    if case=="import" {
        bridge::test_support::with_gate(||bridge::measure(key(99),CpuClass::ExecutorWork,||domain_platform::at(OBS+200_000_037)));
        assert_eq!(bridge::test_support::handoff_status()[28],1);
        let seal=close_and_export(false);assert_eq!(seal.intervals,1);
        assert_eq!(domain_platform::now_ns(),END+1000,"import added uncharged diagnostic CPU");
        assert_eq!(bridge::test_support::source_snapshot(),[0;128],"import published a diagnostic");
        return;
    }
    match case.as_str() {
        "cleanup"=>paid::cleanup_case(),
        "io"=>paid::io_case(),
        "io_resume"=>paid::io_resume_case(),
        _=>panic!("unknown fixture case"),
    }
    let expected=if case=="io_resume" {108}else{54};
    assert_eq!(domain_platform::now_ns(),OBS+200_000_000+expected+if case=="io_resume" {63}else{0},"controlled body37 + recorder17 cost changed");
    assert_eq!(paid::actual(),expected,"recorder17ns escaped the actual submitted Scheduler debit");
    let seal=close_and_export(false);
    let mut rows=[CpuInterval{node:[0;32],core:0,start_ns:0,end_ns:0,class:CpuClass::Policy};2];
    assert_eq!(bridge::copy_intervals(seal,0,&mut rows).unwrap(),if case=="io_resume" {2}else{1});
    assert_eq!((rows[0].start_ns,rows[0].end_ns),(OBS+200_000_000,OBS+200_000_054),"recorder17ns escaped original physical capture interval");
    if case=="io_resume" {
        assert_eq!((rows[1].start_ns,rows[1].end_ns),(OBS+200_000_117,OBS+200_000_171),"original progress gap was filled");
    }
 }).unwrap().join().unwrap();
}
