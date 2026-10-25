//! Execute the production CoreSet queue owner with explicit host clock, pool,
//! credit and root fixtures. These tests do not create learning labels or claim
//! that an actual native CACP trial has run.
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey, tasks::ControlCredit},
    features::{DomainObservation, RawFeatures, TargetFeatures},
    learning::{self, capture::RunKey, reward::CpuClass},
    policy::{BoundDependency, Candidate, CandidateSet, ModelBinding, Snapshot},
};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
pub mod cpu {
    use super::*;
    static CPU: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize {
        CPU.load(Ordering::Acquire)
    }
    pub fn set(v: usize) {
        CPU.store(v, Ordering::Release);
    }
}
static CLOCK: AtomicU64 = AtomicU64::new(1_000_000_000);
fn now() -> u64 {
    CLOCK.load(Ordering::Acquire)
}
fn at(v: u64) {
    assert!(v >= now());
    CLOCK.store(v, Ordering::Release);
}
pub mod domain_tasks {
    use super::*;
    static CURRENT: Mutex<Option<ControlCredit>> = Mutex::new(None);
    pub fn authorize_service_turn() -> Result<(), Error> {
        if cpu::slot() == 0 {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
    pub fn verify_control_credit(credit: &ControlCredit) -> Result<(), Error> {
        if !matches!(cpu::slot(), 1 | 2) || usize::from(credit.cpu) != cpu::slot() {
            return Err(Error::Auth);
        }
        if *CURRENT.lock().unwrap() == Some(*credit) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    pub fn begin(sequence: u64) -> ControlCredit {
        let credit = ControlCredit {
            sequence,
            cpu: cpu::slot() as u16,
            core_generation: 1,
            window: now() / 100_000_000,
            started_ns: now(),
            reserved_ns: 2_500_000,
            control_total_ns: 2_500_000,
            physical_total_ns: 2_500_000,
        };
        let mut current = CURRENT.lock().unwrap();
        assert!(current.is_none());
        *current = Some(credit);
        credit
    }
    pub fn settle(credit: ControlCredit) {
        let mut current = CURRENT.lock().unwrap();
        assert_eq!(*current, Some(credit));
        *current = None;
    }
}
pub mod control_pool {
    use super::*;
    #[derive(Clone, Copy)]
    pub struct Allocation {
        base: usize,
        bytes: usize,
    }
    pub struct Lease;
    pub fn allocate(owner: ObjectKey, pages: usize) -> Result<Allocation, Error> {
        assert_eq!(owner, core_replay::CORE_OWNER);
        assert_eq!(pages, 3);
        let layout = std::alloc::Layout::from_size_align(pages * 4096, 4096).unwrap();
        let base = unsafe { std::alloc::alloc(layout) } as usize;
        assert_ne!(base, 0);
        Ok(Allocation {
            base,
            bytes: pages * 4096,
        })
    }
    pub fn pin(_: Allocation) -> Result<Lease, Error> {
        Ok(Lease)
    }
    pub fn span(a: Allocation) -> Result<(usize, usize, usize), Error> {
        Ok((a.base, a.base, a.bytes))
    }
}
pub mod learning_history {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TrialKind {
        Baseline,
        Candidate,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FrozenScope {
        pub key: RunKey,
        pub kind: TrialKind,
        pub family: learning::Family,
        pub target: ObjectKey,
        pub group: learning::ReplayGroup,
        pub first_ns: u64,
        pub observation_ns: u64,
    }
}
pub mod learning_evidence {
    use super::*;
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Error {
        Busy,
    }
    pub struct OwnerAttempt {
        owner: ObjectKey,
        class: CpuClass,
        core: usize,
    }
    pub static ROWS: Mutex<Vec<(ObjectKey, CpuClass, usize, u64, u64)>> = Mutex::new(Vec::new());
    pub fn attempt(owner: ObjectKey, class: CpuClass) -> Result<Option<OwnerAttempt>, Error> {
        Ok(Some(OwnerAttempt {
            owner,
            class,
            core: cpu::slot(),
        }))
    }
    pub fn finish_attempt(a: &mut OwnerAttempt, first: u64, last: u64) -> Result<(), Error> {
        assert_eq!(cpu::slot(), a.core);
        assert!(first <= last && last <= now());
        ROWS.lock()
            .unwrap()
            .push((a.owner, a.class, a.core, first, last));
        Ok(())
    }
}
pub mod learning_prewarm {
    use super::*;
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    pub static COMPLETED: AtomicUsize = AtomicUsize::new(0);
    pub static SERVICE: AtomicUsize = AtomicUsize::new(0);
    pub struct Attempt {
        core: usize,
    }
    pub fn begin() {
        ACTIVE.store(true, Ordering::Release);
    }
    pub fn active() -> bool {
        ACTIVE.load(Ordering::Acquire)
    }
    pub fn attempt_control(w: &core_replay::PaidWorkWitness) -> Option<Attempt> {
        domain_tasks::verify_control_credit(w.credit()).unwrap();
        active().then_some(Attempt { core: cpu::slot() })
    }
    pub fn attempt_service() -> Option<Attempt> {
        assert_eq!(cpu::slot(), 0);
        active().then_some(Attempt { core: 0 })
    }
    pub fn finish(a: &mut Attempt, first: u64, last: u64) -> Result<(), Error> {
        assert_eq!(a.core, cpu::slot());
        assert!(first <= last && last <= now());
        if a.core == 0 {
            SERVICE.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
    pub fn completed_control(w: &core_replay::PaidWorkWitness) -> Result<(), Error> {
        domain_tasks::verify_control_credit(w.credit())?;
        COMPLETED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    pub fn freeze(_: u64) -> Result<(), Error> {
        ACTIVE.store(false, Ordering::Release);
        Ok(())
    }
}
const TARGET: ObjectKey = ObjectKey {
    id: 40,
    generation: 9,
};
const MODEL: ModelBinding = ModelBinding {
    generation: 4,
    model_hash: [3; 32],
    schema_hash: [4; 32],
};
#[derive(Clone, Copy)]
struct Family {
    target: fn(u16, u16, usize) -> Option<ObjectKey>,
    current: fn(u16, u16, ObjectKey) -> Result<Action, Error>,
    observe: fn(u16, ObjectKey) -> Result<DomainObservation, Error>,
    legal: fn(Action, ObjectKey, u64) -> Result<(), Error>,
    target_features: fn(Action, ObjectKey) -> Result<TargetFeatures, Error>,
}
const FAMILY: Family = Family {
    target: |_, _, n| (n == 0).then_some(TARGET),
    current: |_, _, _| Ok(Action::ControlSet(2)),
    observe: |_, _| Ok(DomainObservation::complete([0; 4])),
    legal: |_, _, _| Ok(()),
    target_features: |_, _| Ok(TargetFeatures::default()),
};
struct Context {
    common: [u64; 8],
    ledger_generation: u64,
    core_generation: u64,
}
struct Owner {
    families: [Option<Family>; 18],
    context: Context,
}
struct Registry;
impl Registry {
    fn model(&self) -> ModelBinding {
        MODEL
    }
}
struct State {
    owner: Owner,
    registry: Registry,
    sequence: u64,
    encoded: Option<JobSource>,
}
#[derive(Clone, Copy)]
struct JobSource {
    owner: ObjectKey,
    class: CpuClass,
    work: Option<core_replay::WorkId>,
}
fn state() -> State {
    let mut families = [None; 18];
    families[1] = Some(FAMILY);
    State {
        owner: Owner {
            families,
            context: Context {
                common: [0; 8],
                ledger_generation: 1,
                core_generation: 1,
            },
        },
        registry: Registry,
        sequence: 0,
        encoded: None,
    }
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    f(&mut state())
}
fn tiers(_: Action) -> ([Option<Action>; 32], usize) {
    let mut out = [None; 32];
    out[0] = Some(Action::ControlSet(2));
    out[1] = Some(Action::ControlSet(6));
    (out, 2)
}
fn queued_control_wcet_us(_: &State, _: usize, _: u64) -> u64 {
    2500
}
fn encode_job(
    s: &mut State,
    _: u64,
    _: u64,
    snapshot: Snapshot,
    set: CandidateSet,
    _: Action,
    _: [Option<BoundDependency>; 2],
    work: Option<core_replay::WorkId>,
    read_only: bool,
) -> Result<[u64; 512], Error> {
    assert!(
        read_only,
        "ordinary work must request the root read-only path"
    );
    let id = work.unwrap();
    core_replay::bind(id, snapshot.sequence, cpu::slot(), set.hash())?;
    s.sequence = snapshot.sequence;
    s.encoded = Some(JobSource {
        owner: core_replay::CORE_OWNER,
        class: CpuClass::ExecutorWork,
        work,
    });
    Ok([0; 512]) // Root ABI encoding is exercised separately by native_control.
}
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_control/core_replay.rs"]
mod core_replay;
fn scope(
    seed: u64,
    kind: learning_history::TrialKind,
    first: u64,
) -> learning_history::FrozenScope {
    learning_history::FrozenScope {
        key: RunKey {
            boot_epoch: 1,
            trial_id: seed,
            generation: 1,
        },
        kind,
        family: learning::Family { domain: 1, kind: 2 },
        target: TARGET,
        group: learning::ReplayGroup {
            seed,
            workload: [1; 32],
            initial_image: [2; 32],
        },
        first_ns: first,
        observation_ns: first,
    }
}
fn relative(id: u64) -> u64 {
    ((id - 1) / 10) * 1_000_000_000 + ((id - 1) % 10) * 1000
}
#[test]
fn real_queue_waits_for_runtime_retirement_and_never_expires_owned_work() {
    cpu::set(0);
    assert_eq!(core_replay::abort_prepared(), Ok(true));
    core_replay::release_prepared().unwrap();
    core_replay::prepare(1).unwrap();
    learning_prewarm::begin();
    core_replay::prewarm_step(1).unwrap();
    assert_eq!(learning_prewarm::SERVICE.load(Ordering::Acquire), 1);
    let mut root = state();
    cpu::set(1);
    let credit = domain_tasks::begin(1);
    let witness = core_replay::PaidWorkWitness::new(credit).unwrap();
    assert!(core_replay::next(&mut root, 1, &witness).unwrap().is_some());
    let warm = root.encoded.unwrap().work.unwrap();
    assert_eq!(core_replay::freeze(now()), Err(Error::Busy));
    cpu::set(0);
    assert_eq!(core_replay::abort_prepared(), Ok(false));
    assert_eq!(core_replay::release_prepared(), Err(Error::Busy));
    cpu::set(1);
    core_replay::evaluated(warm, root.sequence, Err(Error::Expired), [9; 32]).unwrap();
    core_replay::report_completed(warm, &witness).unwrap();
    domain_tasks::settle(credit);
    core_replay::retired(warm).unwrap();
    assert_eq!(learning_prewarm::COMPLETED.load(Ordering::Acquire), 0);
    cpu::set(0);
    assert_eq!(core_replay::abort_prepared(), Ok(true));
    core_replay::release_prepared().unwrap();

    at(2_000_000_000);
    let baseline_image = core_replay::prepare(2).unwrap();
    core_replay::freeze(now()).unwrap();
    let base = scope(2, learning_history::TrialKind::Baseline, now());
    core_replay::bind_scope(&base).unwrap();
    core_replay::activate(base.key).unwrap();
    assert_eq!(core_replay::abort_unactivated(&base), Err(Error::Conflict));
    assert_eq!(
        core_replay::submit(
            1,
            base.observation_ns + 1,
            base.observation_ns + 5_000_000_001
        ),
        Err(Error::Stale)
    );
    assert_eq!(core_replay::drain(), Ok(false));
    for id in 1..=100 {
        let release = base.observation_ns + relative(id);
        at(now().max(release));
        cpu::set(0);
        core_replay::submit(id, release, release + 5_000_000_000).unwrap();
        cpu::set(1 + id as usize % 2);
        let credit = domain_tasks::begin(10 + id);
        let witness = core_replay::PaidWorkWitness::new(credit).unwrap();
        assert!(core_replay::next(&mut root, 1, &witness).unwrap().is_some());
        let work = root.encoded.unwrap().work.unwrap();
        assert!(core_replay::result(id).unwrap().is_none());
        at(now() + 1_000);
        if id == 100 {
            at(base.observation_ns + 20_000_000_000);
            cpu::set(0);
            // An actual running context is not a timeout, even after all SLOs.
            assert_eq!(core_replay::drain(), Ok(false));
            cpu::set(1 + id as usize % 2);
        }
        core_replay::evaluated(work, root.sequence, Ok(0), [7; 32]).unwrap();
        assert_eq!(
            core_replay::evaluated(work, root.sequence, Err(Error::Expired), [7; 32]),
            Err(Error::Conflict)
        );
        core_replay::report_completed(work, &witness).unwrap();
        assert!(
            core_replay::result(id).unwrap().is_none(),
            "root verification is not runtime retirement"
        );
        domain_tasks::settle(credit);
        at(now() + 1_000);
        core_replay::retired(work).unwrap();
        assert_eq!(core_replay::result(id).unwrap(), Some(Ok(now())));
    }
    cpu::set(0);
    assert_eq!(core_replay::drain(), Ok(true));
    core_replay::release(base.key).unwrap();
    let rows = learning_evidence::ROWS.lock().unwrap();
    assert!(
        rows.iter()
            .any(|(_, c, cpu, _, _)| *c == CpuClass::ExecutorWork && *cpu == 1)
    );
    assert!(
        rows.iter()
            .any(|(_, c, cpu, _, _)| *c == CpuClass::ExecutorWork && *cpu == 2)
    );
    assert!(
        rows.iter()
            .all(|(owner, _, _, _, _)| *owner == core_replay::CORE_OWNER)
    );
    drop(rows);

    // The candidate's first request is the actual policy job. It cannot be
    // replaced by a second read-only evaluation; later arrivals stay queued.
    at(now() + 1_000_000_000);
    let candidate_image = core_replay::prepare(2).unwrap();
    assert_eq!(baseline_image.digest, candidate_image.digest);
    core_replay::freeze(now()).unwrap();
    let candidate = scope(2, learning_history::TrialKind::Candidate, now());
    core_replay::bind_scope(&candidate).unwrap();
    core_replay::activate(candidate.key).unwrap();
    cpu::set(2);
    let credit = domain_tasks::begin(200);
    let witness = core_replay::PaidWorkWitness::new(credit).unwrap();
    assert!(core_replay::next(&mut root, 1, &witness).unwrap().is_none());
    let choice = Candidate {
        action: Action::ControlSet(2),
        features: RawFeatures {
            control_capacity: Some(1000),
            ..RawFeatures::default()
        },
    };
    let set = CandidateSet::new(
        Snapshot {
            sequence: 500,
            taken_ns: candidate.first_ns,
            ledger_generation: 1,
            core_generation: 1,
        },
        TARGET,
        MODEL,
        &[choice],
        Some(choice.action),
    )
    .unwrap();
    let primary = core_replay::primary(&set).unwrap().unwrap();
    core_replay::bind(primary, 500, 2, set.hash()).unwrap();
    at(now() + 16_000_000_000);
    cpu::set(0);
    assert_eq!(core_replay::drain(), Ok(false));
    assert_eq!(core_replay::result(2).unwrap(), Some(Err(Error::Expired)));
    cpu::set(2);
    core_replay::evaluated(primary, 500, Err(Error::Budget), [8; 32]).unwrap();
    core_replay::report_completed(primary, &witness).unwrap();
    domain_tasks::settle(credit);
    core_replay::retired(primary).unwrap();
    cpu::set(0);
    assert_eq!(core_replay::drain(), Ok(true));
    core_replay::release(candidate.key).unwrap();
    assert_ne!(
        core_replay::request_digest(2, 1),
        core_replay::request_digest(2, 2)
    );
    // The actual capture may have bound its immutable scope before a later
    // startup check failed. That does not activate any of its 100 CACP jobs.
    at(now() + 1_000_000_000);
    core_replay::prepare(9).unwrap();
    core_replay::freeze(now()).unwrap();
    let partial = scope(9, learning_history::TrialKind::Baseline, now());
    core_replay::bind_scope(&partial).unwrap();
    assert_eq!(core_replay::abort_unactivated(&partial), Ok(true));
    assert_eq!(core_replay::result(1).unwrap(), None);
    assert_eq!(core_replay::result(100).unwrap(), None);
    assert_eq!(core_replay::activate(partial.key), Err(Error::Conflict));
    let foreign = RunKey {
        generation: partial.key.generation + 1,
        ..partial.key
    };
    assert_eq!(core_replay::release_unactivated(foreign), Err(Error::Busy));
    core_replay::release_unactivated(partial.key).unwrap();
}
