#![allow(dead_code, non_upper_case_globals)]
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::domains::{
    Error, ObjectKey,
    tasks::{CpuLayout, Dispatch, RunState, Scheduler, ThreadSpec},
};
static NOW: AtomicU64 = AtomicU64::new(0);
static CPU: AtomicU64 = AtomicU64::new(0);
static WAIT: AtomicU64 = AtomicU64::new(0);
static DISCONNECT: AtomicU64 = AtomicU64::new(0);
struct Clock;
static Board: Clock = Clock;
impl Clock {
    fn now_ms(&self) -> u64 {
        NOW.load(Ordering::Acquire)
    }
    fn now_ns(&self) -> u64 {
        self.now_ms() * 1_000_000
    }
}
mod timer {
    pub fn cpu_ticks() -> u64 {
        super::CPU.load(super::Ordering::Acquire)
    }
    pub fn cpu_elapsed_ns(start: u64) -> u64 {
        cpu_ticks() - start
    }
}
mod smp {
    pub mod prototype_runtime {
        pub struct Coordinator;
    }
}
#[derive(PartialEq, Debug)]
enum TcpState {
    Established,
    Closed,
}
struct NativeTcp<'a> {
    live: bool,
    marker: core::marker::PhantomData<&'a ()>,
}
impl NativeTcp<'_> {
    fn state(&self) -> Result<TcpState, ()> {
        Ok(if self.live {
            TcpState::Established
        } else {
            TcpState::Closed
        })
    }
}
fn network_turn(
    _: &mut smp::prototype_runtime::Coordinator,
    _: &mut Option<NativeTcp<'_>>,
    _: u64,
) {
}
fn progress(_: &mut smp::prototype_runtime::Coordinator, tcp: &mut Option<NativeTcp<'_>>, _: u64) {
    NOW.store(WAIT.swap(0, Ordering::AcqRel), Ordering::Release);
    if DISCONNECT.swap(0, Ordering::AcqRel) != 0 {
        tcp.as_mut().unwrap().live = false;
    }
}
fn fail(code: u64) -> ! {
    panic!("native failure {code}")
}
mod domain_tasks {
    use super::*;
    static HELD: std::sync::Mutex<Option<(Scheduler, Dispatch)>> = std::sync::Mutex::new(None);
    pub static ACTUAL: AtomicU64 = AtomicU64::new(0);
    pub fn begin_service_segment() -> Option<Dispatch> {
        if WAIT.load(Ordering::Acquire) != 0 {
            return None;
        }
        let mut held = HELD.lock().unwrap();
        assert!(held.is_none());
        let mut s = Scheduler::new();
        let group = ObjectKey {
            id: 999,
            generation: 1,
        };
        let layout = CpuLayout {
            business_mask: 1,
            healthy_mask: 15,
            generation: 1,
        };
        s.register_group(group).unwrap();
        s.admit(
            ThreadSpec {
                key: ObjectKey {
                    id: 1,
                    generation: 1,
                },
                group,
                cpu: 0,
                allowed_mask: 1,
                minimum_ns: 0,
                budget_ns: 10_000_000,
            },
            layout,
            Board.now_ns(),
        )
        .unwrap();
        let d = s
            .dispatch_with_window_headroom(0, layout, Board.now_ns(), 2_500_000, 20_000_000)
            .unwrap()
            .unwrap();
        *held = Some((s, d));
        Some(d)
    }
    pub fn revalidate_service_segment() -> bool {
        HELD.lock().unwrap().is_some()
    }
    pub fn complete_service(actual: u64, finished: u64) -> Result<(), Error> {
        let (mut s, d) = HELD.lock().unwrap().take().unwrap();
        let result = s.complete(d, actual, RunState::Runnable, finished);
        ACTUAL.store(s.stats().actual_ns, Ordering::Release);
        result
    }
}
// SAMPLES
mod unified_task {
    use super::*;
    use cyxia_kernel_core::control_plane::task_admission::Authority;
    static mut AUTHORITY: Authority = Authority::new();
    pub fn reset() {
        let a = unsafe { &mut *core::ptr::addr_of_mut!(AUTHORITY) };
        *a = Authority::new();
        a.session(1, 1, 0).unwrap();
    }
    pub fn request(
        phase: u64,
        token: u64,
        offset: u64,
        _: &mut [u8],
        _: usize,
        now: u64,
        connected: bool,
        epoch: u64,
    ) -> (u64, usize, u64) {
        assert!(
            domain_tasks::revalidate_service_segment(),
            "activity outside physical service sample"
        );
        // Controlled instruction cost inside the actual dispatch. No timing claim.
        CPU.fetch_add(37, Ordering::AcqRel);
        // PHASE9
        panic!("fixture only covers phase9");
    }
    pub fn counts() -> (u64, u64) {
        (0, 0)
    }
    pub fn budget() -> (u64, u64, u64) {
        (0, 0, 0)
    }
    pub fn promote(now: u64) -> bool {
        unsafe {
            (&mut *core::ptr::addr_of_mut!(AUTHORITY))
                .session(1, 2, now)
                .is_ok()
        }
    }
}
mod abi {
    pub const OP_TASK: u64 = 7;
}
struct Evidence {
    words: [AtomicU64; 13],
}
static UNIFIED_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 13],
};
struct Packet {
    arg0: u64,
    arg1: u64,
    arg2: u64,
    payload: [u8; 0],
    status: u64,
    len: u64,
}
fn dispatch(token: u64, connection_epoch: u64) -> u64 {
    let mut coordinator = smp::prototype_runtime::Coordinator;
    let mut tcp = Some(NativeTcp {
        live: true,
        marker: core::marker::PhantomData,
    });
    let stream_epoch = 1;
    let len = 0;
    let mut p = Packet {
        arg0: 9,
        arg1: token,
        arg2: 1,
        payload: [],
        status: 99,
        len: 0,
    };
    match abi::OP_TASK {
        // OP_TASK
        _ => unreachable!(),
    }
    assert_eq!(
        domain_tasks::ACTUAL.load(Ordering::Acquire),
        37,
        "activity escaped original Scheduler debit"
    );
    p.status
}
#[test]
fn fresh_admission_guards_and_actual_activity_cost() {
    for wait in [1500, 1501] {
        unified_task::reset();
        NOW.store(1000, Ordering::Release);
        WAIT.store(wait, Ordering::Release);
        assert_eq!(dispatch(3, 1), 3, "stale activity after broker wait");
        assert!(!unified_task::promote(wait));
    }
    unified_task::reset();
    NOW.store(1000, Ordering::Release);
    assert_eq!(dispatch(3, 1), 0);
    assert!(unified_task::promote(2000));
    unified_task::reset();
    NOW.store(1000, Ordering::Release);
    assert_eq!(dispatch(3, 2), 3, "changed transport admitted activity");
    assert!(!unified_task::promote(1000));
    unified_task::reset();
    NOW.store(999, Ordering::Release);
    WAIT.store(1000, Ordering::Release);
    DISCONNECT.store(1, Ordering::Release);
    assert_eq!(dispatch(3, 1), 3, "changed transport admitted activity");
    assert!(!unified_task::promote(1000));
}
