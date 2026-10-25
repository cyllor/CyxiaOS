//! Host execution of the actual protected history/collector sources. CPU,
//! time, pool and replay-owner witnesses here are explicitly synthetic.
extern crate self as cyxia_arch_aarch64;
pub mod sha256 {
    pub fn digest_page(_: &[u8; 4096]) -> Option<[u8; 32]> {
        None
    }
}
pub mod cpu {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CPU: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize {
        CPU.load(Ordering::Acquire)
    }
    pub fn set(value: usize) {
        CPU.store(value, Ordering::Release);
    }
}
pub mod domain_platform {
    use core::sync::atomic::{AtomicU64, Ordering};
    static CLOCK: AtomicU64 = AtomicU64::new(0);
    pub fn now_ns() -> u64 {
        CLOCK.load(Ordering::Acquire)
    }
    pub fn set(value: u64) {
        CLOCK.store(value, Ordering::Release);
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_history.rs"]
mod history;
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_evidence.rs"]
mod learning_evidence;
#[path = "support/learning.rs"]
mod support;
use core::sync::atomic::{AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::{Action, ApplyId, ObjectKey, PolicyStamp},
    learning::{
        Error, Family, ReplayGroup,
        capture::{CaptureInit, FrozenRequest, InitValue, Source},
        manifest::UntrainedSeed,
        reward::{Adoption, BaselineAdoption, CpuClass},
    },
    model::Model,
    policy::ExecutionState,
};
use sha2::{Digest, Sha256};
const FIRST: u64 = 50_000_000_000;
const OBS: u64 = 52_000_000_000;
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
static CAPTURE: AtomicUsize = AtomicUsize::new(0);
static HISTORY: AtomicUsize = AtomicUsize::new(0);
fn pool_check(k: ObjectKey, address: usize, bytes: usize) -> Result<(), learning_evidence::Error> {
    let correct = if k == key(44) {
        address == CAPTURE.load(Ordering::Acquire) && bytes == learning_evidence::STORAGE_BYTES
    } else if k == key(45) {
        address == HISTORY.load(Ordering::Acquire) && bytes == history::STORAGE_BYTES
    } else {
        false
    };
    if correct {
        Ok(())
    } else {
        Err(learning_evidence::Error::Owner)
    }
}
fn capture_storage() -> &'static mut learning_evidence::Storage {
    let mut storage = Box::<learning_evidence::Storage>::new_uninit();
    let base = storage.as_mut_ptr().cast::<u8>();
    let mut init = CaptureInit::<8192, 4096>::new().unwrap();
    while let Some(piece) = init.peek() {
        unsafe {
            let p = base.add(piece.offset);
            macro_rules! w {
                ($v:expr) => {
                    core::ptr::write(p.cast(), $v)
                };
            }
            match piece.value {
                InitValue::Config(v) => w!(v),
                InitValue::U64(v) => w!(v),
                InitValue::Usize(v) => w!(v),
                InitValue::Raw(v) => w!(v),
                InitValue::Source(v) => w!(v),
                InitValue::Open(v) => w!(v),
                InitValue::Cpu(v) => w!(v),
                InitValue::Request(v) => w!(v),
                InitValue::Work(v) => w!(v),
                InitValue::Fault(v) => w!(v),
                InitValue::Hash(v) => w!(v),
                InitValue::Seal(v) => w!(v),
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
    unsafe {
        storage
            .as_mut_ptr()
            .cast::<u8>()
            .write_bytes(0, history::STORAGE_BYTES);
    }
    Box::leak(unsafe { storage.assume_init() })
}
fn frozen(scope: &history::FrozenScope) -> Result<(), Error> {
    if scope.group.workload == [6; 32] && scope.frozen_other_domains == [8; 32] {
        Ok(())
    } else {
        Err(Error::DataIncomplete)
    }
}
fn issued(
    _: cyxia_prototype::learning::capture::RunKey,
    adoption: &Adoption<'_>,
) -> Result<(), Error> {
    if adoption.issued_ns == FIRST + 1_000_000 && adoption.target_request_id.is_none() {
        Ok(())
    } else {
        Err(Error::Evidence)
    }
}
fn no_baseline(
    _: cyxia_prototype::learning::capture::RunKey,
    _: &BaselineAdoption,
) -> Result<(), Error> {
    Err(Error::DataIncomplete)
}
fn no_closing(
    _: &history::FrozenScope,
    _: &cyxia_prototype::learning::reward::Trial<'_>,
) -> Result<(), Error> {
    Err(Error::DataIncomplete)
}

static BASELINE_CHECK_MODE: AtomicUsize = AtomicUsize::new(0);
static BASELINE_CHECK_CALLS: AtomicUsize = AtomicUsize::new(0);
static BASELINE_GATE_HELD: AtomicUsize = AtomicUsize::new(0);
static BASELINE_GATE_RELEASE: AtomicUsize = AtomicUsize::new(0);
static BASELINE_GATE_THREAD: std::sync::Mutex<Option<std::thread::JoinHandle<()>>> =
    std::sync::Mutex::new(None);
const BASELINE_FIRST: u64 = 38_000_000_000;
fn baseline_receipt() -> BaselineAdoption {
    BaselineAdoption {
        owner_boot: 7,
        receipt_sequence: 99,
        target: key(1),
        executor_generation: 9,
        snapshot: cyxia_prototype::policy::Snapshot {
            sequence: 77,
            taken_ns: BASELINE_FIRST,
            ledger_generation: 4,
            core_generation: 3,
        },
        actual: Action::ConsoleBatch(8),
        executed: ExecutionState::Applied,
        issued_ns: BASELINE_FIRST + 1_000,
        accepted_ns: BASELINE_FIRST + 2_000,
        target_request_id: None,
        started_ns: BASELINE_FIRST + 3_000,
        finished_ns: BASELINE_FIRST + 4_000,
        installed_until_ns: BASELINE_FIRST + 10_000_000_000,
        approved_deadline_ns: BASELINE_FIRST + 50_002_000,
    }
}
fn baseline_witness(
    run: cyxia_prototype::learning::capture::RunKey,
    receipt: &BaselineAdoption,
) -> Result<(), Error> {
    BASELINE_CHECK_CALLS.fetch_add(1, Ordering::AcqRel);
    if run.trial_id != 34 || receipt.receipt_sequence != 99 {
        return Err(Error::Evidence);
    }
    match BASELINE_CHECK_MODE.load(Ordering::Acquire) {
        1 => Err(Error::Unknown),
        2 => {
            let thread = std::thread::spawn(|| {
                history::test_support::with_gate(|| {
                    BASELINE_GATE_HELD.store(1, Ordering::Release);
                    while BASELINE_GATE_RELEASE.load(Ordering::Acquire) == 0 {
                        std::thread::yield_now();
                    }
                })
            });
            *BASELINE_GATE_THREAD.lock().unwrap() = Some(thread);
            while BASELINE_GATE_HELD.load(Ordering::Acquire) == 0 {
                std::thread::yield_now();
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
fn baseline_retry_preserves_the_original_row_and_only_retries_missing_custody() {
    cpu::set(0);
    domain_platform::set(BASELINE_FIRST);
    let family = Family {
        domain: 15,
        kind: 1,
    };
    let observation = BASELINE_FIRST + 1_000_000_000;
    let sources = [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
    ]
    .map(|class| Source {
        owner: key(class as u64 + 1),
        class,
        allowed_cores: 3,
    });
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: i as u64 + 1,
        owner: key(10),
        arrived_ns: observation + i as u64 * 1_000_000,
    });
    let run = learning_evidence::start(
        34,
        family,
        BASELINE_FIRST,
        observation,
        [7; 32],
        &sources,
        &requests,
    )
    .unwrap();
    history::begin_run(
        history::FrozenScope {
            key: run,
            kind: history::TrialKind::Baseline,
            family,
            target: key(1),
            group: ReplayGroup {
                seed: 34,
                workload: [6; 32],
                initial_image: [9; 32],
            },
            schemas: support::schemas(),
            frozen_other_domains: [8; 32],
            frozen_scope_hash: [7; 32],
            first_ns: BASELINE_FIRST,
            warmed_from_ns: BASELINE_FIRST,
            observation_ns: observation,
        },
        history::ReplayChecks {
            frozen,
            issued,
            baseline: baseline_witness,
            closing: no_closing,
        },
    )
    .unwrap();
    domain_platform::set(BASELINE_FIRST + 5_000);
    let receipt = baseline_receipt();
    // The authoritative witness can succeed while C1 acquires the journal
    // gate before insertion. The caller still owns every original fact.
    BASELINE_CHECK_MODE.store(2, Ordering::Release);
    let retry = history::record_baseline(run, &receipt);
    BASELINE_GATE_RELEASE.store(1, Ordering::Release);
    BASELINE_GATE_THREAD
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(retry, Err(learning_evidence::Error::Busy));
    assert_eq!(history::status().unwrap().records, 0);
    assert_eq!(
        history::status().unwrap().fault,
        None,
        "retryable baseline custody was marked lost"
    );
    BASELINE_CHECK_MODE.store(1, Ordering::Release);
    assert_eq!(
        history::record_baseline(run, &receipt),
        Err(learning_evidence::Error::Capture(Error::Unknown))
    );
    assert_eq!(history::status().unwrap().fault, None);
    BASELINE_CHECK_MODE.store(0, Ordering::Release);
    assert_eq!(history::record_baseline(run, &receipt), Ok(true));
    let mut original = vec![0; history::SLOT_BYTES];
    for offset in (0..original.len()).step_by(256) {
        history::copy_record(run, 0, offset, &mut original[offset..offset + 256]).unwrap();
    }
    let checks = BASELINE_CHECK_CALLS.load(Ordering::Acquire);
    BASELINE_CHECK_MODE.store(1, Ordering::Release);
    // A producer marker can lose its own CAS after the row was stored. An
    // exact retry must not depend on revalidating a later root configuration.
    assert_eq!(history::record_baseline(run, &receipt), Ok(false));
    assert_eq!(BASELINE_CHECK_CALLS.load(Ordering::Acquire), checks);
    assert_eq!(history::status().unwrap().records, 1);
    assert_eq!(history::status().unwrap().fault, None);
    BASELINE_CHECK_MODE.store(0, Ordering::Release);
    history::test_support::with_gate(|| {
        assert_eq!(history::verify_baseline(run, &receipt), Err(Error::Unknown));
    });
    assert_eq!(history::status().unwrap().fault, None);
    history::verify_baseline(run, &receipt).unwrap();
    let changes: &[fn(&mut BaselineAdoption)] = &[
        |b| b.owner_boot += 1,
        |b| b.target.generation += 1,
        |b| b.executor_generation += 1,
        |b| b.snapshot.sequence += 1,
        |b| b.snapshot.taken_ns += 1,
        |b| b.snapshot.ledger_generation += 1,
        |b| b.snapshot.core_generation += 1,
        |b| b.actual = Action::ConsoleBatch(16),
        |b| b.executed = ExecutionState::Unknown,
        |b| b.issued_ns += 1,
        |b| b.accepted_ns += 1,
        |b| b.target_request_id = Some(0),
        |b| b.started_ns += 1,
        |b| b.finished_ns += 1,
        |b| b.installed_until_ns += 1,
        |b| b.approved_deadline_ns += 1,
    ];
    for change in changes {
        let mut changed = baseline_receipt();
        change(&mut changed);
        assert_eq!(
            history::record_baseline(run, &changed),
            Err(learning_evidence::Error::Capture(Error::Conflict))
        );
    }
    let mut retained = vec![0; history::SLOT_BYTES];
    for offset in (0..retained.len()).step_by(256) {
        history::copy_record(run, 0, offset, &mut retained[offset..offset + 256]).unwrap();
    }
    assert_eq!(retained, original);
    assert_eq!(history::status().unwrap().records, 1);
    domain_platform::set(observation + 10_000_000_000);
    for source in sources {
        learning_evidence::close_source(
            learning_evidence::source(source.owner, source.class).unwrap(),
        )
        .unwrap();
    }
    let seal = learning_evidence::seal(true).unwrap();
    history::replay::seal(seal).unwrap();
    learning_evidence::retire_exported(seal).unwrap();
    history::replay::retire_exported(seal).unwrap();
}

fn native_input(set: &cyxia_prototype::policy::CandidateSet, current: Action) -> [u8; 4096] {
    let mut words = [0u64; 512];
    words[0] = 42;
    words[1] = 3;
    words[2] = set.snapshot.sequence;
    words[3] = 2;
    words[4] = set.snapshot.taken_ns;
    words[5] = 1_000_000_000;
    words[6] = set.snapshot.core_generation;
    words[7] = set.snapshot.ledger_generation;
    words[8] = current.domain() as u64;
    words[9] = current.kind() as u64;
    words[10] = set.target.id;
    words[11] = set.target.generation;
    words[12] = 1;
    words[13] = set.model.generation;
    words[14] = 7;
    words[15] = set.len() as u64;
    for (at, hash) in [(16, set.model.model_hash), (20, set.hash())] {
        for i in 0..4 {
            words[at + i] = u64::from_le_bytes(hash[i * 8..i * 8 + 8].try_into().unwrap());
        }
    }
    let first = set.get(0).unwrap().features;
    words[24..32].copy_from_slice(&first.common);
    words[32..36].copy_from_slice(&first.domain);
    words[40] = u64::from(first.domain_present);
    for (i, c) in set.iter().enumerate() {
        let at = 64 + i * 10;
        let mut payload = [0; 16];
        words[at] = cyxia_prototype::policy_wire::encode_payload(c.action, i as u16, &mut payload)
            .unwrap() as u64;
        words[at + 1] = u64::from_le_bytes(payload[..8].try_into().unwrap());
        words[at + 2] = u64::from_le_bytes(payload[8..].try_into().unwrap());
        for j in 0..4 {
            if let Some(v) = c.features.target.values[j] {
                words[at + 3 + j] = v;
                words[at + 7] |= 1 << j;
            }
        }
        words[at + 8] = c.features.control_capacity.unwrap_or(0);
    }
    let mut prior = [0; 16];
    words[404] = cyxia_prototype::learning::baseline::encode(current, &mut prior).unwrap() as u64;
    words[405] = u64::from_le_bytes(prior[..8].try_into().unwrap());
    words[406] = u64::from_le_bytes(prior[8..].try_into().unwrap());
    let mut bytes = [0; 4096];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

const ONESHOT: u64 = 1_000_000_000;
fn scheduled_oneshot(
    run: cyxia_prototype::learning::capture::RunKey,
    owner: ObjectKey,
    id: u64,
    at: u64,
) -> Result<u64, Error> {
    if run.trial_id == 30
        && owner == key(10)
        && (1..=100).contains(&id)
        && at == ONESHOT + (id - 1) * 1_000_000
    {
        Ok(ONESHOT - 1)
    } else {
        Err(Error::Evidence)
    }
}
fn issued_oneshot(
    _: cyxia_prototype::learning::capture::RunKey,
    adoption: &Adoption<'_>,
) -> Result<(), Error> {
    if adoption.issued_ns == ONESHOT && adoption.target_request_id == Some(1) {
        Ok(())
    } else {
        Err(Error::Evidence)
    }
}
static INCREMENTAL_CLOSING_UNKNOWN: AtomicUsize = AtomicUsize::new(0);
fn closing_oneshot(
    scope: &history::FrozenScope,
    trial: &cyxia_prototype::learning::reward::Trial<'_>,
) -> Result<(), Error> {
    if INCREMENTAL_CLOSING_UNKNOWN.load(Ordering::Acquire) != 0 {
        return Err(Error::Unknown);
    }
    if scope.key.trial_id == 30
        && trial.id == 30
        && trial.requests.len() == 100
        && trial.closing_ns == ONESHOT + 10_000_000_000
    {
        Ok(())
    } else {
        Err(Error::Evidence)
    }
}
fn one_shot_trigger_and_real_publication_keep_distinct_times() {
    use cyxia_prototype::learning::reward::RequestResult;
    cpu::set(0);
    domain_platform::set(ONESHOT);
    learning_evidence::register_schedule_owner_at(key(10), scheduled_oneshot).unwrap();
    let family = Family { domain: 1, kind: 2 };
    let sources = [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
    ]
    .map(|class| Source {
        owner: key(class as u64 + 1),
        class,
        allowed_cores: 3,
    });
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: i as u64 + 1,
        owner: key(10),
        arrived_ns: ONESHOT + i as u64 * 1_000_000,
    });
    let run = learning_evidence::start(30, family, ONESHOT, ONESHOT, [7; 32], &sources, &requests)
        .unwrap();
    history::begin_run(
        history::FrozenScope {
            key: run,
            kind: history::TrialKind::Candidate,
            family,
            target: key(1),
            group: ReplayGroup {
                seed: 16,
                workload: [6; 32],
                initial_image: [9; 32],
            },
            schemas: support::schemas(),
            frozen_other_domains: [8; 32],
            frozen_scope_hash: [7; 32],
            first_ns: ONESHOT,
            warmed_from_ns: 0,
            observation_ns: ONESHOT,
        },
        history::ReplayChecks {
            frozen,
            issued: issued_oneshot,
            baseline: no_baseline,
            closing: closing_oneshot,
        },
    )
    .unwrap();
    let seed = UntrainedSeed::new(0);
    let set = support::set(seed.bytes(), family, ONESHOT, 11);
    let input = native_input(&set, set.get(0).unwrap().action);
    let scores: Vec<i16> = set
        .iter()
        .map(|c| {
            Model::parse(seed.bytes()).unwrap().score(
                &cyxia_prototype::features::encode(c.action, c.features)
                    .unwrap()
                    .values,
            )
        })
        .collect();
    let selected = scores
        .iter()
        .enumerate()
        .max_by_key(|(i, v)| (**v, usize::MAX - i))
        .unwrap()
        .0;
    let action = set.get(selected).unwrap().action;
    cpu::set(1);
    history::record_proposal(11, &set, &input, Sha256::digest(input).into()).unwrap();
    let received = ONESHOT + 1_000_000;
    let accepted = received + 100_000;
    let apply = ApplyId {
        boot_epoch: 7,
        controller_epoch: 2,
        plan_seq: 11,
        action_index: 0,
        target: key(1),
    };
    let stamp = PolicyStamp::for_action(action, 1, ONESHOT, accepted).unwrap();
    domain_platform::set(accepted);
    history::record_publish(history::Publish {
        decision_seq: 11,
        apply,
        plan_version: 1,
        stamp,
        model: set.model,
        selected: selected as u16,
        scores: &scores,
        received_ns: received,
        published_ns: accepted,
        expires_local_ns: ONESHOT + 100_000_000,
        active_until_local_ns: 0,
        approved_deadline_ns: accepted + 200_000_000,
        concurrent: &[apply],
    })
    .unwrap();
    let started = accepted + 1_000;
    let finished = started + 20_000;
    cpu::set(0);
    domain_platform::set(finished);
    history::record_execution(history::Execution {
        apply,
        stamp,
        state: ExecutionState::Applied,
        observed_ns: finished,
        started_ns: Some(started),
        executor_generation: Some(7),
    })
    .unwrap();
    // The native owner initializes this row directly in its borrowed input
    // bank. An incompletely copied in-place row must retain the same Busy
    // gate as the value constructor, then export the actual native journal.
    let mut slot = Box::<history::replay::Record>::new_uninit();
    unsafe { history::replay::Record::init_at(slot.as_mut_ptr(), run, 0) };
    let mut exported = unsafe { slot.assume_init() };
    assert!(!exported.complete());
    assert!(matches!(exported.candidates(), Err(history::Error::Busy)));
    while exported.copy_piece().unwrap() {}
    let rebuilt = exported.candidates().unwrap();
    let mut adopted = exported
        .adoption(&rebuilt, seed.bytes(), Some(1), &[])
        .unwrap();
    assert_eq!(adopted.issued_ns, ONESHOT);
    assert_eq!(adopted.accepted_ns, accepted);
    history::verify_adoption(run, &adopted).unwrap();
    let mut raw = [0; 8];
    history::copy_record(run, 0, 352, &mut raw).unwrap();
    assert_eq!(u64::from_le_bytes(raw), received); // No backdating of actual publication ingress.
    history::copy_record(run, 0, 488, &mut raw).unwrap();
    assert_eq!(u64::from_le_bytes(raw), ONESHOT);
    history::copy_record(run, 0, 496, &mut raw).unwrap();
    assert_eq!(u64::from_le_bytes(raw), 1);
    adopted.issued_ns = received;
    assert_eq!(
        history::verify_adoption(run, &adopted),
        Err(Error::Evidence)
    );
    adopted.issued_ns = ONESHOT;
    adopted.target_request_id = Some(2);
    assert_eq!(
        history::verify_adoption(run, &adopted),
        Err(Error::Evidence)
    );
    adopted.target_request_id = Some(1);
    for request in requests {
        let registered = learning_evidence::request(request.owner, request.id).unwrap();
        learning_evidence::arm_scheduled(registered).unwrap();
        let actual = finished.max(request.arrived_ns + 10);
        domain_platform::set(actual);
        learning_evidence::result(
            registered,
            RequestResult::Completed {
                finished_ns: actual,
            },
        )
        .unwrap();
    }
    domain_platform::set(ONESHOT + 10_000_000_000);
    for (index, source) in sources.iter().enumerate() {
        let first = ONESHOT + 1_000 + index as u64 * 1_000;
        learning_evidence::record(
            learning_evidence::source(source.owner, source.class).unwrap(),
            first,
            first + 100,
        )
        .unwrap();
    }
    for source in sources {
        learning_evidence::close_source(
            learning_evidence::source(source.owner, source.class).unwrap(),
        )
        .unwrap();
    }
    let seal = learning_evidence::seal(false).unwrap();
    history::replay::seal(seal).unwrap();
    learning_evidence::with_sealed_trace(seal, |trace| {
        use cyxia_prototype::learning::reward::{
            self, IncrementalAuthority, ReplayKind, ReplayPiece, ReplayVerification, Trial,
        };
        let scope = history::replay::scope().unwrap();
        let coverage = [trace.coverage()];
        let nodes = [coverage[0].node];
        let adoptions = [adopted];
        let trial = Trial {
            id: run.trial_id,
            family: scope.family,
            group: scope.group,
            frozen_other_domains: scope.frozen_other_domains,
            schemas: scope.schemas,
            local_node: nodes[0],
            controlled_nodes: &nodes,
            observation_ns: scope.observation_ns,
            observation_end_ns: scope.observation_ns + 10_000_000_000,
            warmed_from_ns: scope.warmed_from_ns,
            closing_ns: seal.closing_ns,
            requests: trace.requests(),
            adoptions: &adoptions,
            coverage: &coverage,
            cpu: trace.intervals(),
            baseline: &[],
            joint_policy: &[],
            correct: true,
            frozen: true,
            closing: ExecutionState::Applied,
            ordinary_warmup_cpu_ns: trace.status().ordinary_warmup_ns,
            later_workload_cpu_ns: trace.status().later_workload_ns,
            peak_workspace_bytes: 512 * 1024,
        };
        let native = history::replay::Incremental::for_test(&trace, seed.bytes(), rebuilt.model);
        let binding = native.begin(&trial)?.unwrap();
        assert!(native.attest_piece(
            &trial,
            binding,
            ReplayPiece::Requests { start: 0, end: 16 }
        )?);
        assert!(native.attest_piece(
            &trial,
            binding,
            ReplayPiece::Requests { start: 0, end: 16 }
        )?);
        let mut wrong_cpu = trial.cpu.to_vec();
        wrong_cpu[0].end_ns += 1;
        let changed = Trial {
            cpu: &wrong_cpu,
            ..trial
        };
        assert_eq!(
            native.attest_piece(&changed, binding, ReplayPiece::Cpu { start: 0, end: 1 }),
            Err(Error::Evidence)
        );
        let mut wrong_requests = trial.requests.to_vec();
        wrong_requests[0].id += 1;
        let changed = Trial {
            requests: &wrong_requests,
            ..trial
        };
        assert_eq!(
            native.attest_piece(
                &changed,
                binding,
                ReplayPiece::Requests { start: 0, end: 16 }
            ),
            Err(Error::Evidence)
        );
        let authority = history::replay::Authority::from_trace(&trace).unwrap();
        let mut workspace = Box::new(reward::RewardWorkspace::new());
        let golden =
            reward::verify_replay(&trial, ReplayKind::Candidate, &authority, &mut workspace)?;
        let mut incremental = ReplayVerification::new(ReplayKind::Candidate);
        history::test_support::with_gate(|| {
            assert!(
                incremental
                    .step(&trial, &native, &mut workspace)
                    .unwrap()
                    .is_none()
            );
        });
        let checked = (0..10_000)
            .find_map(|_| {
                incremental
                    .step(&trial, &native, &mut workspace)
                    .transpose()
            })
            .expect("bounded walk must finish")?;
        assert_eq!(checked.evidence_hash(), golden.evidence_hash());
        assert_eq!(checked.cpu(), golden.cpu());
        assert_eq!(checked.performance(), golden.performance());
        assert_eq!(checked.schedule_hash(), golden.schedule_hash());
        assert!(matches!(
            incremental.step(&trial, &native, &mut workspace),
            Err(Error::Stale)
        ));

        // A real Unknown from the protected closing witness is terminal even
        // though an actual history-gate contention above was resumable.
        INCREMENTAL_CLOSING_UNKNOWN.store(1, Ordering::Release);
        let mut rejected = ReplayVerification::new(ReplayKind::Candidate);
        let error = (0..10_000)
            .find_map(|_| match rejected.step(&trial, &native, &mut workspace) {
                Ok(None) => None,
                Ok(Some(_)) => panic!("unknown closing produced an accepted replay"),
                Err(error) => Some(error),
            })
            .expect("closing must be checked");
        assert_eq!(error, Error::Unknown);
        INCREMENTAL_CLOSING_UNKNOWN.store(0, Ordering::Release);
        assert!(matches!(
            rejected.step(&trial, &native, &mut workspace),
            Err(Error::Unknown)
        ));
        Ok(())
    })
    .unwrap();
    learning_evidence::retire_exported(seal).unwrap();
    history::replay::retire_exported(seal).unwrap();
}

fn partial_start_keeps_real_capture_and_cannot_cancel_unknown_history() {
    use cyxia_prototype::learning::capture::RunKey;
    let family = Family {
        domain: 15,
        kind: 1,
    };
    let sources = [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
    ]
    .map(|class| Source {
        owner: key(class as u64 + 1),
        class,
        allowed_cores: 3,
    });
    let good = history::ReplayChecks {
        frozen,
        issued,
        baseline: no_baseline,
        closing: no_closing,
    };
    let bad = history::ReplayChecks {
        frozen: |_| Err(Error::Evidence),
        ..good
    };
    for (trial, first, begun) in [(32, 12_000_000_000, false), (33, 25_000_000_000, true)] {
        cpu::set(0);
        domain_platform::set(first);
        let observation = first + 1_000_000_000;
        let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
            id: i as u64 + 1,
            owner: key(10),
            arrived_ns: observation + i as u64 * 1_000_000,
        });
        let permit = learning_evidence::prepare_start(key(46), trial, family).unwrap();
        cpu::set(1);
        let run = learning_evidence::start_authorized(
            &permit,
            first,
            observation,
            [7; 32],
            &sources,
            &requests,
        )
        .unwrap();
        let scope = history::FrozenScope {
            key: run,
            kind: history::TrialKind::Candidate,
            family,
            target: key(1),
            group: ReplayGroup {
                seed: trial,
                workload: [6; 32],
                initial_image: [9; 32],
            },
            schemas: support::schemas(),
            frozen_other_domains: [8; 32],
            frozen_scope_hash: [7; 32],
            first_ns: first,
            warmed_from_ns: first,
            observation_ns: observation,
        };
        let (mut apply, mut stamp) = (None, None);
        let mut original = [0; 256];
        if begun {
            history::begin_authorized(scope, good, &permit).unwrap();
            let seed = UntrainedSeed::new(0);
            let set = support::set(seed.bytes(), family, first, 77);
            let input = native_input(&set, set.get(0).unwrap().action);
            history::record_proposal(77, &set, &input, Sha256::digest(input).into()).unwrap();
            let id = ApplyId {
                boot_epoch: 7,
                controller_epoch: 2,
                plan_seq: 77,
                action_index: 0,
                target: key(1),
            };
            let accepted = first + 1000;
            domain_platform::set(accepted);
            let actual_stamp =
                PolicyStamp::for_action(set.get(0).unwrap().action, 1, first, accepted).unwrap();
            history::record_publish(history::Publish {
                decision_seq: 77,
                apply: id,
                plan_version: 1,
                stamp: actual_stamp,
                model: set.model,
                selected: 0,
                scores: &[0; 32][..set.len()],
                received_ns: first,
                published_ns: accepted,
                expires_local_ns: first + 100_000_000,
                active_until_local_ns: actual_stamp.installed_until_ns,
                approved_deadline_ns: accepted + 50_000_000,
                concurrent: &[id],
            })
            .unwrap();
            history::copy_record(run, 0, 2048, &mut original).unwrap();
            apply = Some(id);
            stamp = Some(actual_stamp);
        } else {
            assert_eq!(
                history::begin_authorized(scope, bad, &permit),
                Err(learning_evidence::Error::Capture(Error::Evidence))
            );
            assert_eq!(history::status().unwrap().run, None);
        }
        cpu::set(0);
        let mut mismatched = scope;
        mismatched.key = RunKey {
            generation: run.generation + 1,
            ..run
        };
        assert!(history::begin_excluded_authorized(mismatched, &permit, Error::Evidence).is_err());
        history::begin_excluded_authorized(scope, &permit, Error::Evidence).unwrap();
        history::begin_excluded_authorized(scope, &permit, Error::Conflict).unwrap();
        let status = history::status().unwrap();
        assert_eq!(status.run, Some(run));
        assert_eq!(status.fault, Some(Error::Evidence));
        assert_eq!(status.records, usize::from(begun));
        assert_eq!(status.published, usize::from(begun));
        assert_eq!(status.applied, 0);
        assert_eq!(learning_evidence::status().unwrap().0.issued, 0); // No invented business arrivals/completions.
        if !begun {
            assert!(history::begin_authorized(scope, good, &permit).is_err());
        } else {
            let mut retained = [0; 256];
            history::copy_record(run, 0, 2048, &mut retained).unwrap();
            assert_eq!(retained, original); // Actual proposal bytes survive exclusion.
        }
        domain_platform::set(observation + 10_000_000_000);
        for source in sources {
            learning_evidence::close_source(
                learning_evidence::source(source.owner, source.class).unwrap(),
            )
            .unwrap();
        }
        let seal = learning_evidence::seal(true).unwrap();
        assert!(seal.exclusion.is_some());
        if let (Some(apply), Some(stamp)) = (apply, stamp) {
            assert_eq!(
                history::replay::seal(seal),
                Err(learning_evidence::Error::Capture(Error::Unknown))
            );
            assert!(history::replay::retire_exported(seal).is_err());
            // Only the real terminal-owner callback in this explicit host
            // fixture settles the pending publication; the deadline did not.
            history::record_execution(history::Execution {
                apply,
                stamp,
                state: ExecutionState::Failed(cyxia_prototype::domains::Error::Expired),
                observed_ns: observation + 10_000_000_000,
                started_ns: None,
                executor_generation: Some(7),
            })
            .unwrap();
        }
        history::replay::seal(seal).unwrap();
        learning_evidence::retire_exported(seal).unwrap();
        history::replay::retire_exported(seal).unwrap();
        learning_evidence::release_start(&permit).unwrap();
    }
}

#[test]
fn native_history_keeps_actual_first_entry_receipts_raw_inputs_and_bounded_failures() {
    cpu::set(0);
    domain_platform::set(ONESHOT);
    let capture = capture_storage();
    CAPTURE.store(capture as *mut _ as usize, Ordering::Release);
    learning_evidence::install(capture, [1; 32], 7, key(44), pool_check)
        .map_err(|(e, _)| e)
        .unwrap();
    let storage = history_storage();
    HISTORY.store(storage as *mut _ as usize, Ordering::Release);
    history::install(storage, [1; 32], 7, key(45), pool_check)
        .map_err(|(e, _)| e)
        .unwrap();
    one_shot_trigger_and_real_publication_keep_distinct_times();
    partial_start_keeps_real_capture_and_cannot_cancel_unknown_history();
    baseline_retry_preserves_the_original_row_and_only_retries_missing_custody();
    domain_platform::set(FIRST);
    let sources = [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
    ]
    .map(|class| Source {
        owner: key(class as u64 + 1),
        class,
        allowed_cores: 3,
    });
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: i as u64 + 1,
        owner: key(10),
        arrived_ns: OBS + i as u64 * 1_000_000,
    });
    let family = Family {
        domain: 15,
        kind: 1,
    };
    let permit = learning_evidence::prepare_start(key(46), 31, family).unwrap();
    cpu::set(3);
    assert_eq!(
        learning_evidence::start_authorized(&permit, FIRST, OBS, [7; 32], &sources, &requests),
        Err(learning_evidence::Error::Owner)
    );
    cpu::set(2);
    assert_eq!(
        learning_evidence::start(31, family, FIRST, OBS, [7; 32], &sources, &requests),
        Err(learning_evidence::Error::Owner)
    );
    let run =
        learning_evidence::start_authorized(&permit, FIRST, OBS, [7; 32], &sources, &requests)
            .unwrap();
    let scope = history::FrozenScope {
        key: run,
        kind: history::TrialKind::Candidate,
        family,
        target: key(1),
        group: ReplayGroup {
            seed: 17,
            workload: [6; 32],
            initial_image: [9; 32],
        },
        schemas: support::schemas(),
        frozen_other_domains: [8; 32],
        frozen_scope_hash: [7; 32],
        first_ns: FIRST,
        warmed_from_ns: OBS - 1_000_000_000,
        observation_ns: OBS,
    };
    let checks = history::ReplayChecks {
        frozen,
        issued,
        baseline: no_baseline,
        closing: no_closing,
    };
    assert_eq!(
        history::begin_run(scope, checks),
        Err(learning_evidence::Error::Owner)
    );
    history::begin_authorized(scope, checks, &permit).unwrap();
    cpu::set(0);
    let mut wrong = scope;
    wrong.frozen_other_domains = [0; 32];
    assert!(history::begin_run(wrong, checks).is_err());
    history::begin_run(scope, checks).unwrap();
    let seed = UntrainedSeed::new(0);
    let template = support::set(seed.bytes(), family, FIRST, 1);
    let choices: Vec<_> = template
        .iter()
        .map(|c| cyxia_prototype::policy::Candidate {
            action: c.action,
            features: cyxia_prototype::features::RawFeatures {
                control_capacity: None,
                ..c.features
            },
        })
        .collect();
    let set = cyxia_prototype::policy::CandidateSet::new(
        template.snapshot,
        template.target,
        template.model,
        &choices,
        Some(Action::ConsoleBatch(64)),
    )
    .unwrap();
    let scores: Vec<i16> = set
        .iter()
        .map(|c| {
            Model::parse(seed.bytes()).unwrap().score(
                &cyxia_prototype::features::encode(c.action, c.features)
                    .unwrap()
                    .values,
            )
        })
        .collect();
    let selected = scores
        .iter()
        .enumerate()
        .max_by_key(|(i, v)| (**v, usize::MAX - i))
        .unwrap()
        .0;
    let actual = set.get(selected).unwrap().action;
    let input = native_input(&set, Action::ConsoleBatch(64));
    cpu::set(1);
    domain_platform::set(FIRST + 1_000_000);
    let input_hash = Sha256::digest(input).into();
    assert_eq!(
        history::record_proposal(1, &set, &input, input_hash),
        Ok(true)
    );
    let mut exported = history::replay::Record::new(run, 0);
    while exported.copy_piece().unwrap() {}
    assert_eq!(exported.candidates().unwrap().hash(), set.hash());
    assert_eq!(
        history::record_proposal(1, &set, &input, input_hash),
        Ok(true)
    );
    let apply = ApplyId {
        boot_epoch: 7,
        controller_epoch: 2,
        plan_seq: 3,
        action_index: 0,
        target: key(1),
    };
    let concurrent = [apply];
    let accepted = FIRST + 1_100_000;
    let stamp = PolicyStamp::for_action(actual, 1, FIRST, accepted).unwrap();
    domain_platform::set(accepted);
    history::record_publish(history::Publish {
        decision_seq: 1,
        apply,
        plan_version: 1,
        stamp,
        model: set.model,
        selected: selected as u16,
        scores: &scores,
        received_ns: FIRST + 1_000_000,
        published_ns: accepted,
        expires_local_ns: FIRST + 100_000_000,
        active_until_local_ns: stamp.installed_until_ns,
        approved_deadline_ns: accepted + 50_000_000,
        concurrent: &concurrent,
    })
    .unwrap();
    cpu::set(0);
    let started = accepted + 1_000;
    domain_platform::set(started);
    history::record_execution(history::Execution {
        apply,
        stamp,
        state: ExecutionState::Pending,
        observed_ns: started,
        started_ns: Some(started),
        executor_generation: Some(7),
    })
    .unwrap();
    let finished = started + 20_000;
    let adoption = Adoption {
        decision_seq: 1,
        apply,
        plan_version: 1,
        executor_generation: 7,
        candidates: &set,
        model: seed.bytes(),
        scores: &scores,
        selected: selected as u16,
        actual,
        executed: ExecutionState::Applied,
        issued_ns: FIRST + 1_000_000,
        accepted_ns: accepted,
        expires_local_ns: FIRST + 100_000_000,
        active_until_local_ns: stamp.installed_until_ns,
        target_request_id: None,
        started_ns: started,
        finished_ns: finished,
        installed_until_ns: stamp.installed_until_ns,
        approved_deadline_ns: accepted + 50_000_000,
        concurrent: &concurrent,
        shared_policy_intervals: &[],
    };
    assert_eq!(
        history::verify_adoption(run, &adoption),
        Err(Error::DataIncomplete)
    );
    domain_platform::set(started + 10_000);
    history::record_execution(history::Execution {
        apply,
        stamp,
        state: ExecutionState::Unknown,
        observed_ns: started + 10_000,
        started_ns: Some(started + 10_000),
        executor_generation: Some(7),
    })
    .unwrap();
    domain_platform::set(finished);
    history::record_execution(history::Execution {
        apply,
        stamp,
        state: ExecutionState::Applied,
        observed_ns: finished,
        started_ns: None,
        executor_generation: None,
    })
    .unwrap();
    history::verify_adoption(run, &adoption).unwrap();
    domain_platform::set(finished + 1_000);
    history::record_execution(history::Execution {
        apply,
        stamp,
        state: ExecutionState::Applied,
        observed_ns: finished + 1_000,
        started_ns: None,
        executor_generation: None,
    })
    .unwrap();
    history::verify_adoption(run, &adoption).unwrap();
    let mut corrupt = adoption;
    corrupt.selected ^= 1;
    assert_eq!(
        history::verify_adoption(run, &corrupt),
        Err(Error::Evidence)
    );
    let mut raw = [0u8; 8];
    history::copy_record(run, 0, 400, &mut raw).unwrap();
    assert_eq!(u64::from_le_bytes(raw), started); // Busy retry did not restart time.
    history::copy_record(run, 0, 416, &mut raw).unwrap();
    assert_eq!(u64::from_le_bytes(raw), finished); // Repeated poll kept the first actual APPLIED ack.
    cpu::set(1);
    // The final physical slot is reserved for the first terminal root rejection.
    for id in 2..=63 {
        let set = support::set(seed.bytes(), family, FIRST, id);
        assert_eq!(
            history::record_proposal(id, &set, &input, input_hash),
            Ok(true)
        );
    }
    assert_eq!(
        history::record_proposal(64, &set, &input, input_hash),
        Err(learning_evidence::Error::Capacity)
    );
    assert_eq!(history::status().unwrap().records, 63);
    assert_eq!(
        history::status().unwrap().fault,
        Some(Error::DataIncomplete)
    );
    history::copy_record(run, 0, 2048, &mut raw).unwrap();
    assert_eq!(raw[0], 42); // A full journal did not overwrite old raw input.
    cpu::set(0);
    domain_platform::set(OBS);
    let mut segment = learning_evidence::attempt_work(key(3), true)
        .unwrap()
        .unwrap();
    domain_platform::set(OBS + 37);
    learning_evidence::test_support::with_gate(|| {
        assert_eq!(
            learning_evidence::finish_attempt(&mut segment, OBS, OBS + 37),
            Err(learning_evidence::Error::Busy)
        );
    });
    drop(segment);
    let measured = learning_evidence::status().unwrap().0;
    // A validated real exit now keeps its original producer lease until a
    // later paid owner turn can append it. It is neither lost nor yet counted.
    assert_eq!(measured.raw_tagged_ns[CpuClass::ExecutorWork as usize], 0);
    assert_eq!(measured.raw_tagged_ns[CpuClass::Optional as usize], 0);
    assert_eq!(measured.fault, None);
    assert_eq!(learning_evidence::test_support::handoff_status()[28], 1);

    // A control/service owner may still execute after closure won its CAS.
    // The exact public entry API must return a token, not an Err that a native
    // .ok().flatten() could silently turn into absent instrumentation.
    learning_evidence::test_support::admission_closed(false);
    let mut closing = learning_evidence::attempt(key(2), CpuClass::ExecutorAction)
        .ok()
        .flatten()
        .unwrap();
    assert_eq!(learning_evidence::test_support::handoff_status()[28], 0);
    assert_eq!(
        learning_evidence::status().unwrap().0.raw_tagged_ns[CpuClass::ExecutorWork as usize],
        37
    );
    assert!(closing.pending());
    domain_platform::set(OBS + 90);
    assert_eq!(
        learning_evidence::finish_attempt(&mut closing, OBS + 40, OBS + 90),
        Err(learning_evidence::Error::Capture(Error::DataIncomplete))
    );
    assert!(!closing.pending());
    drop(closing);
    assert_eq!(
        learning_evidence::status().unwrap().0.raw_tagged_ns[CpuClass::ExecutorAction as usize],
        50
    );

    learning_evidence::test_support::admission_closed(true);
    let mut frozen = learning_evidence::attempt(key(1), CpuClass::Policy)
        .ok()
        .flatten()
        .unwrap();
    assert_eq!(learning_evidence::unrecorded_status().pending, 1);
    assert_eq!(
        learning_evidence::seal(true),
        Err(learning_evidence::Error::Busy)
    );
    domain_platform::set(OBS + 140);
    assert_eq!(
        learning_evidence::finish_attempt(&mut frozen, OBS + 100, OBS + 140),
        Err(learning_evidence::Error::Capture(Error::DataIncomplete))
    );
    drop(frozen);
    let raw = learning_evidence::unrecorded_status();
    assert_eq!(raw.first_generation, run.generation);
    assert_eq!(raw.last_generation, run.generation);
    assert_eq!(raw.pending, 0);
    assert_eq!(raw.counts[CpuClass::Policy as usize], 1);
    assert_eq!(raw.raw_ns[CpuClass::Policy as usize], 40);
    assert_eq!(
        learning_evidence::status().unwrap().0.raw_tagged_ns[CpuClass::Policy as usize],
        40
    );
    assert_eq!(
        learning_evidence::status().unwrap().0.raw_tagged_ns[CpuClass::Policy as usize],
        40
    );
    assert!(
        learning_evidence::attempt_work(key(3), false)
            .unwrap()
            .is_none()
    ); // seal stopped new entry.
}
