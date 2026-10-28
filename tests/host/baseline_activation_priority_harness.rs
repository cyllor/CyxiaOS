#![allow(dead_code)]
use std::sync::{Mutex, atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}};
#[derive(Clone, Copy, Debug, Eq, PartialEq)] enum Error { Busy, Again, Auth, NotReady, Stale }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Snapshot { sequence: u64, taken_ns: u64 }
#[derive(Clone, Copy, Eq, PartialEq)] enum TrialKind { Baseline, Candidate }
struct State;
static mut STATE: State = State;
static CLAIMED: AtomicBool = AtomicBool::new(false);
static CALLBACK_MODE: AtomicUsize = AtomicUsize::new(0);
static CAPTURE_FIRST: AtomicU64 = AtomicU64::new(0);
static SEEN: Mutex<Vec<(u64, Snapshot)>> = Mutex::new(Vec::new());
mod cyxia_arch_aarch64 {
    pub mod cpu { pub fn slot() -> usize { 0 } }
    pub mod timer { pub fn cpu_ticks() -> u64 { 1000 } }
}
mod learning { pub mod reward { pub enum CpuClass { Policy } } }
mod learning_evidence {
    pub fn attempt(_: u64, _: super::learning::reward::CpuClass) -> Result<Option<()>, ()> { Ok(None) }
}
// CONTROL_GATE_BODIES
mod replay {
    use super::*;
    #[derive(Clone, Copy, Eq, PartialEq)] pub enum Phase { Frozen, Running, Complete }
    #[derive(Clone, Copy)] pub struct Token { pub id: u64 }
    #[derive(Clone, Copy)] pub struct Request {
        pub owner: u64, pub target: u64, pub kind: TrialKind,
        pub on_first: fn(Token, Snapshot) -> Result<(), Error>,
    }
    pub struct Checks { pub owner: u64, pub before_first: fn(Token, Snapshot) -> Result<(), Error> }
    pub struct Lifecycle { pub close: bool }
    impl Lifecycle { pub fn closing(&self) -> Option<()> { self.close.then_some(()) } }
    pub struct Root {
        pub registered: [Option<Checks>; 1], pub token: Option<Token>, pub request: Option<Request>,
        pub first: Option<Snapshot>, pub first_ready: bool, pub phase: Phase, pub initial: Option<u64>,
        pub baseline_count: usize, pub fault: Option<Error>, pub unpublished: Option<()>, pub lifecycle: Lifecycle,
    }
    static mut ROOT: Root = Root { registered: [None], token: None, request: None,
        first: None, first_ready: false, phase: Phase::Complete, initial: None,
        baseline_count: 0, fault: None, unpublished: None, lifecycle: Lifecycle { close: false } };
    fn root() -> &'static Root { unsafe { &*core::ptr::addr_of!(ROOT) } }
    pub fn root_mut() -> &'static mut Root { unsafe { &mut *core::ptr::addr_of_mut!(ROOT) } }
    static ACTIVATION_TOKEN: AtomicU64 = AtomicU64::new(0);
    static ACTIVATION_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
    static ACTIVATING: AtomicUsize = AtomicUsize::new(0);
    struct Prefix { cpu_started: u64, attempt: Option<()> }
    fn fail(root: &mut Root, error: Error) -> Error { root.fault = Some(error); error }
    // ROOT_HINT_BODIES
    pub fn try_activation(snapshot: Snapshot) -> Result<(), Error> {
        activate(root().token.unwrap(), root().request.unwrap(), snapshot).map(|_| ())
    }
    pub fn reset() {
        let r = root_mut();
        r.registered = [Some(Checks { owner: 7, before_first: |_, _| Ok(()) })];
        r.token = Some(Token { id: 9 }); r.request = Some(Request { owner: 7, target: 12,
            kind: TrialKind::Baseline, on_first: callback });
        r.first = None; r.first_ready = false; r.phase = Phase::Frozen; r.initial = None;
        r.baseline_count = 0; r.fault = None; r.unpublished = None; r.lifecycle.close = false;
        BASELINE_ACTIVATION_PENDING.store(false, Ordering::Release);
    }
}
fn callback(token: replay::Token, snapshot: Snapshot) -> Result<(), Error> {
    SEEN.lock().unwrap().push((token.id, snapshot));
    match CALLBACK_MODE.load(Ordering::Acquire) {
        0 => Err(Error::Busy), // Before the replay owner can acquire its own gate.
        1 => { CAPTURE_FIRST.store(snapshot.taken_ns, Ordering::Release); Err(Error::Busy) },
        _ => Ok(()),
    }
}
fn reset() {
    CLAIMED.store(false, Ordering::Release); CALLBACK_MODE.store(0, Ordering::Release);
    CAPTURE_FIRST.store(0, Ordering::Release); SEEN.lock().unwrap().clear(); replay::reset();
}
const FIRST: Snapshot = Snapshot { sequence: 2, taken_ns: 100_000_000 };
#[test]
fn busy_before_owner_gate_acquisition_still_retains_an_urgent_original_snapshot() {
    reset();
    assert_eq!(with(|_| replay::try_activation(FIRST)), Err(Error::Busy));
    assert!(replay::baseline_activation_pending(), "partial first activation waits for general phase9");
    assert_eq!(replay::root_mut().first, Some(FIRST));
    assert!(!replay::root_mut().first_ready);
    assert_eq!(CAPTURE_FIRST.load(Ordering::Acquire), 0);
}
#[test]
fn binding_busy_retries_the_actual_activate_body_with_the_same_token_and_snapshot() {
    reset(); CALLBACK_MODE.store(1, Ordering::Release);
    assert_eq!(with(|_| replay::try_activation(FIRST)), Err(Error::Busy));
    assert!(replay::baseline_activation_pending(), "captured partial activation lost its retry");
    assert_eq!(CAPTURE_FIRST.load(Ordering::Acquire), FIRST.taken_ns);
    CALLBACK_MODE.store(2, Ordering::Release);
    with(|_| replay::try_activation(Snapshot { sequence: 3, taken_ns: 101_000_000 })).unwrap();
    assert_eq!(*SEEN.lock().unwrap(), vec![(9, FIRST), (9, FIRST)]);
    assert!(replay::root_mut().first_ready); assert!(replay::baseline_activation_pending());
    with(|_| { let r = replay::root_mut(); r.initial = Some(2); r.baseline_count = 1;
        r.phase = replay::Phase::Running; Ok(()) }).unwrap();
    assert!(!replay::baseline_activation_pending());
    assert_eq!(replay::root_mut().first, Some(FIRST));
}
#[test]
fn pre_snapshot_candidate_and_terminal_states_do_not_request_extra_service() {
    reset(); with(|_| Ok(())).unwrap(); assert!(!replay::baseline_activation_pending());
    with(|_| { let r = replay::root_mut(); r.first = Some(FIRST);
        r.request.as_mut().unwrap().kind = TrialKind::Candidate; Ok(()) }).unwrap();
    assert!(!replay::baseline_activation_pending());
    for terminal in 0..3 {
        reset(); with(|_| { let r = replay::root_mut(); r.first = Some(FIRST);
            match terminal { 0 => r.fault = Some(Error::Stale), 1 => r.lifecycle.close = true,
                _ => r.unpublished = Some(()) }; Ok(()) }).unwrap();
        assert!(!replay::baseline_activation_pending());
    }
}
#[test]
fn a_contested_root_borrow_cannot_consume_or_clear_the_existing_retry() {
    reset(); assert_eq!(with(|_| replay::try_activation(FIRST)), Err(Error::Busy));
    CLAIMED.store(true, Ordering::Release);
    let mut executed = false;
    assert_eq!(with(|_| { executed = true; Ok(()) }), Err(Error::Busy));
    assert!(!executed); assert!(replay::baseline_activation_pending());
    CLAIMED.store(false, Ordering::Release);
}
