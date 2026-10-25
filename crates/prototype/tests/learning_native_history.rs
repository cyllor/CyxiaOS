//! Host execution of the actual protected history/collector sources. CPU,
//! time, pool and replay-owner witnesses here are explicitly synthetic.
extern crate self as cyxia_arch_aarch64;
pub mod cpu {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CPU: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize { CPU.load(Ordering::Acquire) }
    pub fn set(value: usize) { CPU.store(value, Ordering::Release); }
}
pub mod domain_platform {
    use core::sync::atomic::{AtomicU64, Ordering};
    static CLOCK: AtomicU64 = AtomicU64::new(0);
    pub fn now_ns() -> u64 { CLOCK.load(Ordering::Acquire) }
    pub fn set(value: u64) { CLOCK.store(value, Ordering::Release); }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_evidence.rs"]
mod learning_evidence;
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_history.rs"]
mod history;
#[path = "support/learning.rs"]
mod support;
use core::sync::atomic::{AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::{ApplyId, ObjectKey, PolicyStamp},
    learning::{Error, Family, ReplayGroup, capture::{CaptureInit, FrozenRequest, InitValue, Source},
        manifest::UntrainedSeed, reward::{Adoption, BaselineAdoption, CpuClass}},
    model::Model, policy::ExecutionState,
};
use sha2::{Digest, Sha256};
const FIRST: u64 = 1_000_000_000;
const OBS: u64 = 3_000_000_000;
fn key(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
static CAPTURE: AtomicUsize = AtomicUsize::new(0);
static HISTORY: AtomicUsize = AtomicUsize::new(0);
fn pool_check(k: ObjectKey, address: usize, bytes: usize) -> Result<(), learning_evidence::Error> {
    let correct = if k == key(44) { address == CAPTURE.load(Ordering::Acquire) && bytes == learning_evidence::STORAGE_BYTES }
        else if k == key(45) { address == HISTORY.load(Ordering::Acquire) && bytes == history::STORAGE_BYTES } else { false };
    if correct { Ok(()) } else { Err(learning_evidence::Error::Owner) }
}
fn capture_storage() -> &'static mut learning_evidence::Storage {
    let mut storage = Box::<learning_evidence::Storage>::new_uninit();
    let base = storage.as_mut_ptr().cast::<u8>();
    let mut init = CaptureInit::<8192, 4096>::new().unwrap();
    while let Some(piece) = init.peek() {
        unsafe {
            let p = base.add(piece.offset);
            macro_rules! w { ($v:expr) => { core::ptr::write(p.cast(), $v) }; }
            match piece.value {
                InitValue::Config(v) => w!(v), InitValue::U64(v) => w!(v), InitValue::Usize(v) => w!(v),
                InitValue::Raw(v) => w!(v), InitValue::Source(v) => w!(v), InitValue::Open(v) => w!(v),
                InitValue::Cpu(v) => w!(v), InitValue::Request(v) => w!(v), InitValue::Work(v) => w!(v),
                InitValue::Fault(v) => w!(v), InitValue::Hash(v) => w!(v), InitValue::Seal(v) => w!(v),
            }
        }
        init.commit(piece.sequence).unwrap();
    }
    init.finish().unwrap();
    Box::leak(unsafe { storage.assume_init() })
}
fn history_storage() -> &'static mut history::Storage {
    let mut storage = Box::<history::Storage>::new_uninit();
    // History has only a byte array. No enum/niche is initialized by raw zero.
    unsafe { storage.as_mut_ptr().cast::<u8>().write_bytes(0, history::STORAGE_BYTES); }
    Box::leak(unsafe { storage.assume_init() })
}
fn frozen(scope: &history::FrozenScope) -> Result<(), Error> {
    if scope.group.workload == [6; 32] && scope.frozen_other_domains == [8; 32] { Ok(()) } else { Err(Error::DataIncomplete) }
}
fn issued(_: cyxia_prototype::learning::capture::RunKey, adoption: &Adoption<'_>) -> Result<(), Error> {
    if adoption.issued_ns == FIRST + 1_000_000 && adoption.target_request_id.is_none() { Ok(()) } else { Err(Error::Evidence) }
}
fn no_baseline(_: cyxia_prototype::learning::capture::RunKey, _: &BaselineAdoption) -> Result<(), Error> { Err(Error::DataIncomplete) }
fn no_closing(_: &history::FrozenScope, _: &cyxia_prototype::learning::reward::Trial<'_>) -> Result<(), Error> { Err(Error::DataIncomplete) }

#[test]
fn native_history_keeps_actual_first_entry_receipts_raw_inputs_and_bounded_failures() {
    cpu::set(0); domain_platform::set(FIRST);
    let capture = capture_storage(); CAPTURE.store(capture as *mut _ as usize, Ordering::Release);
    learning_evidence::install(capture, [1; 32], 7, key(44), pool_check).map_err(|(e, _)| e).unwrap();
    let storage = history_storage(); HISTORY.store(storage as *mut _ as usize, Ordering::Release);
    history::install(storage, [1; 32], 7, key(45), pool_check).map_err(|(e, _)| e).unwrap();
    let sources = [CpuClass::Policy, CpuClass::ExecutorAction, CpuClass::ExecutorWork].map(|class| Source {
        owner: key(class as u64 + 1), class, allowed_cores: 3,
    });
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: i as u64 + 1, owner: key(10), arrived_ns: OBS + i as u64 * 1_000_000,
    });
    let family = Family { domain: 15, kind: 1 };
    let run = learning_evidence::start(31, family, FIRST, OBS, [7; 32], &sources, &requests).unwrap();
    let scope = history::FrozenScope {
        key: run, kind: history::TrialKind::Candidate, family, target: key(1),
        group: ReplayGroup { seed: 17, workload: [6; 32], initial_image: [9; 32] },
        schemas: support::schemas(), frozen_other_domains: [8; 32], frozen_scope_hash: [7; 32],
        first_ns: FIRST, warmed_from_ns: OBS - 1_000_000_000, observation_ns: OBS,
    };
    let checks = history::ReplayChecks { frozen, issued, baseline: no_baseline, closing: no_closing };
    let mut wrong = scope; wrong.frozen_other_domains = [0; 32];
    assert!(history::begin_run(wrong, checks).is_err());
    history::begin_run(scope, checks).unwrap();
    let seed = UntrainedSeed::new(0);
    let set = support::set(seed.bytes(), family, FIRST, 1);
    let scores: Vec<i16> = set.iter().map(|c| Model::parse(seed.bytes()).unwrap().score(
        &cyxia_prototype::features::encode(c.action, c.features).unwrap().values)).collect();
    let selected = scores.iter().enumerate().max_by_key(|(i, v)| (**v, usize::MAX - i)).unwrap().0;
    let actual = set.get(selected).unwrap().action;
    let mut input = [0u8; 4096]; input[0] = 42;
    cpu::set(1); domain_platform::set(FIRST + 1_000_000);
    let input_hash = Sha256::digest(input).into();
    assert_eq!(history::record_proposal(1, &set, &input, input_hash), Ok(true));
    assert_eq!(history::record_proposal(1, &set, &input, input_hash), Ok(true));
    let apply = ApplyId { boot_epoch: 7, controller_epoch: 2, plan_seq: 3, action_index: 0, target: key(1) };
    let concurrent = [apply];
    let accepted = FIRST + 1_100_000;
    let stamp = PolicyStamp::for_action(actual, 1, FIRST, accepted).unwrap();
    domain_platform::set(accepted);
    history::record_publish(history::Publish {
        decision_seq: 1, apply, plan_version: 1, stamp, model: set.model,
        selected: selected as u16, scores: &scores, received_ns: FIRST + 1_000_000,
        published_ns: accepted, expires_local_ns: FIRST + 100_000_000,
        active_until_local_ns: stamp.installed_until_ns, approved_deadline_ns: accepted + 50_000_000,
        concurrent: &concurrent,
    }).unwrap();
    cpu::set(0); let started = accepted + 1_000; domain_platform::set(started);
    history::record_execution(history::Execution { apply, stamp, state: ExecutionState::Pending,
        observed_ns: started, started_ns: Some(started), executor_generation: Some(7) }).unwrap();
    let finished = started + 20_000;
    let adoption = Adoption {
        decision_seq: 1, apply, plan_version: 1, executor_generation: 7, candidates: &set,
        model: seed.bytes(), scores: &scores, selected: selected as u16, actual, executed: ExecutionState::Applied,
        issued_ns: FIRST + 1_000_000, accepted_ns: accepted, expires_local_ns: FIRST + 100_000_000,
        active_until_local_ns: stamp.installed_until_ns, target_request_id: None,
        started_ns: started, finished_ns: finished, installed_until_ns: stamp.installed_until_ns,
        approved_deadline_ns: accepted + 50_000_000, concurrent: &concurrent, shared_policy_intervals: &[],
    };
    assert_eq!(history::verify_adoption(run, &adoption), Err(Error::DataIncomplete));
    domain_platform::set(started + 10_000);
    history::record_execution(history::Execution { apply, stamp, state: ExecutionState::Unknown,
        observed_ns: started + 10_000, started_ns: Some(started + 10_000), executor_generation: Some(7) }).unwrap();
    domain_platform::set(finished);
    history::record_execution(history::Execution { apply, stamp, state: ExecutionState::Applied,
        observed_ns: finished, started_ns: None, executor_generation: None }).unwrap();
    history::verify_adoption(run, &adoption).unwrap();
    domain_platform::set(finished + 1_000);
    history::record_execution(history::Execution { apply, stamp, state: ExecutionState::Applied,
        observed_ns: finished + 1_000, started_ns: None, executor_generation: None }).unwrap();
    history::verify_adoption(run, &adoption).unwrap();
    let mut corrupt = adoption; corrupt.selected ^= 1;
    assert_eq!(history::verify_adoption(run, &corrupt), Err(Error::Evidence));
    let mut raw = [0u8; 8];
    history::copy_record(run, 0, 400, &mut raw).unwrap();
    assert_eq!(u64::from_le_bytes(raw), started); // Busy retry did not restart time.
    history::copy_record(run, 0, 416, &mut raw).unwrap();
    assert_eq!(u64::from_le_bytes(raw), finished); // Repeated poll kept the first actual APPLIED ack.
    cpu::set(1);
    for id in 2..=64 { let set = support::set(seed.bytes(), family, FIRST, id);
        assert_eq!(history::record_proposal(id, &set, &input, input_hash), Ok(true)); }
    assert_eq!(history::record_proposal(65, &set, &input, input_hash), Err(learning_evidence::Error::Capacity));
    assert_eq!(history::status().unwrap().records, 64);
    assert_eq!(history::status().unwrap().fault, Some(Error::DataIncomplete));
    history::copy_record(run, 0, 2048, &mut raw).unwrap();
    assert_eq!(raw[0], 42); // A full journal did not overwrite old raw input.
    cpu::set(0); domain_platform::set(OBS);
    let mut segment = learning_evidence::attempt_work(key(3), true).unwrap().unwrap();
    domain_platform::set(OBS + 37);
    learning_evidence::test_support::with_gate(|| {
        assert_eq!(learning_evidence::finish_attempt(&mut segment, OBS, OBS + 37), Err(learning_evidence::Error::Busy));
    });
    drop(segment);
    let measured = learning_evidence::status().unwrap().0;
    assert_eq!(measured.raw_tagged_ns[CpuClass::ExecutorWork as usize], 37);
    assert_eq!(measured.raw_tagged_ns[CpuClass::Optional as usize], 0);
    assert_eq!(measured.fault, Some(Error::DataIncomplete));

    // A control/service owner may still execute after closure won its CAS.
    // The exact public entry API must return a token, not an Err that a native
    // .ok().flatten() could silently turn into absent instrumentation.
    learning_evidence::test_support::admission_closed(false);
    let mut closing = learning_evidence::attempt(key(2), CpuClass::ExecutorAction).ok().flatten().unwrap();
    assert!(closing.pending());
    domain_platform::set(OBS + 90);
    assert_eq!(learning_evidence::finish_attempt(&mut closing, OBS + 40, OBS + 90),
        Err(learning_evidence::Error::Capture(Error::DataIncomplete)));
    assert!(!closing.pending());
    drop(closing);
    assert_eq!(learning_evidence::status().unwrap().0.raw_tagged_ns[CpuClass::ExecutorAction as usize], 50);

    learning_evidence::test_support::admission_closed(true);
    let mut frozen = learning_evidence::attempt(key(1), CpuClass::Policy).ok().flatten().unwrap();
    assert_eq!(learning_evidence::unrecorded_status().pending, 1);
    assert_eq!(learning_evidence::seal(true), Err(learning_evidence::Error::Busy));
    domain_platform::set(OBS + 140);
    assert_eq!(learning_evidence::finish_attempt(&mut frozen, OBS + 100, OBS + 140),
        Err(learning_evidence::Error::Capture(Error::DataIncomplete)));
    drop(frozen);
    let raw = learning_evidence::unrecorded_status();
    assert_eq!(raw.first_generation, run.generation);
    assert_eq!(raw.last_generation, run.generation);
    assert_eq!(raw.pending, 0);
    assert_eq!(raw.counts[CpuClass::Policy as usize], 1);
    assert_eq!(raw.raw_ns[CpuClass::Policy as usize], 40);
    assert_eq!(learning_evidence::status().unwrap().0.raw_tagged_ns[CpuClass::Policy as usize], 40);
    assert_eq!(learning_evidence::status().unwrap().0.raw_tagged_ns[CpuClass::Policy as usize], 40);
    assert!(learning_evidence::attempt_work(key(3), false).unwrap().is_none()); // seal stopped new entry.
}
