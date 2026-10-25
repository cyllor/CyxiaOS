//! Host integration of the production window owner, 8 MiB pool ledger,
//! capture bridge, aggregation and stability Guard. Only CPU/time and the
//! root callback boundary are supplied by this harness. These deterministic
//! request events are fault-injection tests, never native replay samples.
extern crate self as cyxia_arch_aarch64;
pub const HIGH: u64 = 0;
pub mod cpu {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static SLOT: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize {
        SLOT.load(Ordering::Acquire)
    }
    pub fn set(slot: usize) {
        SLOT.store(slot, Ordering::Release);
    }
}
pub mod domain_platform {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(0);
    pub fn now_ns() -> u64 {
        NOW.load(Ordering::Acquire)
    }
    pub fn set(now: u64) {
        assert!(
            now >= NOW.load(Ordering::Acquire),
            "the test clock never rewinds"
        );
        NOW.store(now, Ordering::Release);
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/control_pool.rs"]
pub mod control_pool;
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_evidence.rs"]
mod learning_evidence;
#[allow(dead_code)]
#[path = "../../../kernel/src/service_windows.rs"]
mod service_windows;

use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_prototype::{
    domains::{
        Action, Error, ObjectKey,
        stability::{Boundary, FreezeReason, Guard, ServiceStatus, ServiceWindow, WindowOutcome},
    },
    learning::{
        Family,
        capture::{CaptureInit, FrozenRequest, InitValue, RunKey, Seal, Source},
        reward::{CpuClass, OBSERVATION_NS, RequestResult, WorkRequest},
    },
    policy::ExecutionState,
};
use std::sync::Mutex;

const SECOND: u64 = 1_000_000_000;
const IO: Family = Family { domain: 9, kind: 1 };
const SERVICE: Family = Family { domain: 8, kind: 1 };
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}

struct Root {
    guards: Vec<Guard>,
    attempts: Vec<ServiceWindow>,
    windows: Vec<(ServiceWindow, WindowOutcome)>,
    registrations: usize,
    objects: Vec<(Family, ObjectKey, Result<(), Error>, ExecutionState)>,
}
static ROOT: Mutex<Root> = Mutex::new(Root {
    guards: Vec::new(),
    attempts: Vec::new(),
    windows: Vec::new(),
    registrations: 0,
    objects: Vec::new(),
});
static REGISTER_BUSY: AtomicBool = AtomicBool::new(false);
static OBSERVE_BUSY: AtomicBool = AtomicBool::new(false);

// This is the host root boundary, not an alternative window implementation.
// It retains the actual production Guard and its exact immutable registration
// and monotonic observation checks, just as domain_control does.
pub mod domain_control {
    use super::*;
    pub fn register_service_boundary(
        domain: u16,
        kind: u16,
        target: ObjectKey,
        boundary: Boundary,
        origin: u64,
    ) -> Result<(), Error> {
        if REGISTER_BUSY.swap(false, Ordering::AcqRel) {
            return Err(Error::Busy);
        }
        let action = match (domain, kind) {
            (9, 1) => Action::IoShare(100),
            (8, 1) => Action::ServiceBatch(1),
            _ => return Err(Error::Unsupported),
        };
        let mut root = ROOT.lock().unwrap();
        let i = if let Some(i) = root
            .guards
            .iter()
            .position(|g| g.target() == target && g.family() == (domain, kind))
        {
            i
        } else {
            root.guards
                .push(Guard::new(target, action, domain_platform::now_ns())?);
            root.guards.len() - 1
        };
        root.guards[i].register_boundary(boundary, origin, domain_platform::now_ns())?;
        root.registrations += 1;
        if !root.objects.iter().any(|(family, key, _, _)|
            *family == Family { domain, kind } && *key == target) {
            root.objects.push((Family { domain, kind }, target, Ok(()), ExecutionState::Applied));
        }
        Ok(())
    }
    pub fn service_target_retired(domain: u16, kind: u16, target: ObjectKey) -> Result<bool, Error> {
        let root = ROOT.lock().unwrap();
        let (_, _, current, execution) = root.objects.iter().find(|(family, key, _, _)|
            *family == Family { domain, kind } && *key == target).ok_or(Error::NotReady)?;
        if !execution.terminal() { return Err(Error::Busy); }
        match current {
            Ok(()) => Ok(false),
            Err(Error::Stale | Error::NotFound) => Ok(true),
            Err(error) => Err(*error),
        }
    }
    pub fn observe_service_window(window: ServiceWindow) -> Result<WindowOutcome, Error> {
        let mut root = ROOT.lock().unwrap();
        root.attempts.push(window);
        if OBSERVE_BUSY.swap(false, Ordering::AcqRel) {
            return Err(Error::Busy);
        }
        let guard = root
            .guards
            .iter_mut()
            .find(|g| g.target() == window.target && g.family() == (window.domain, window.kind))
            .ok_or(Error::NotFound)?;
        let outcome = guard.observe_service(window, domain_platform::now_ns())?;
        root.windows.push((window, outcome));
        Ok(outcome)
    }
}

fn pool_check(key: ObjectKey, base: usize, bytes: usize) -> Result<(), learning_evidence::Error> {
    control_pool::validate_span(key, base, bytes).map_err(|error| match error {
        Error::Busy => learning_evidence::Error::Busy,
        _ => learning_evidence::Error::Owner,
    })
}
fn install_capture() -> control_pool::Lease {
    let bytes = learning_evidence::STORAGE_BYTES;
    let allocation = control_pool::allocate(key(800), bytes.div_ceil(4096)).unwrap();
    let pin = control_pool::pin(allocation).unwrap();
    let (base, _, capacity) = control_pool::span(allocation).unwrap();
    assert!(capacity >= bytes);
    assert_eq!(
        base % core::mem::align_of::<learning_evidence::Storage>(),
        0
    );
    let mut init = CaptureInit::<8192, 4096>::new().unwrap();
    while let Some(piece) = init.peek() {
        // The real exclusive mutable loan is initialized field by field using
        // the production recipe; no invalid zeroed enums or giant stack value.
        assert!(piece.offset + piece.value.byte_len() <= bytes);
        unsafe {
            let p = (base as *mut u8).add(piece.offset);
            macro_rules! write {
                ($v:expr) => {
                    core::ptr::write(p.cast(), $v)
                };
            }
            match piece.value {
                InitValue::Config(v) => write!(v),
                InitValue::U64(v) => write!(v),
                InitValue::Usize(v) => write!(v),
                InitValue::Raw(v) => write!(v),
                InitValue::Source(v) => write!(v),
                InitValue::Open(v) => write!(v),
                InitValue::Cpu(v) => write!(v),
                InitValue::Request(v) => write!(v),
                InitValue::Work(v) => write!(v),
                InitValue::Fault(v) => write!(v),
                InitValue::Hash(v) => write!(v),
                InitValue::Seal(v) => write!(v),
            }
        }
        init.commit(piece.sequence).unwrap();
    }
    assert_eq!(init.finish().unwrap().bytes(), bytes);
    let storage = unsafe { &mut *(base as *mut learning_evidence::Storage) };
    learning_evidence::install(
        storage,
        [7; 32],
        3,
        control_pool::allocation_key(allocation),
        pool_check,
    )
    .map_err(|(error, _)| error)
    .unwrap();
    assert_eq!(
        control_pool::read(allocation, 0, &mut [0; 8]),
        Err(Error::Busy)
    );
    pin // retained for the entire collector lifetime
}
fn sources() -> [Source; 3] {
    [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
    ]
    .map(|class| Source {
        owner: key(900 + class as u64),
        class,
        allowed_cores: 1,
    })
}
fn requests(observation: u64, counts: [usize; 10]) -> Vec<FrozenRequest> {
    let mut out = Vec::new();
    for (second, count) in counts.into_iter().enumerate() {
        for i in 0..count {
            out.push(FrozenRequest {
                id: out.len() as u64 + 1,
                owner: key(500),
                arrived_ns: observation + second as u64 * SECOND + 10_000 + i as u64 * 1_000,
            });
        }
    }
    assert_eq!(out.len(), 100);
    out
}
fn start(
    trial: u64,
    family: Family,
    first: u64,
    observation: u64,
    hash: [u8; 32],
    requests: &[FrozenRequest],
) -> RunKey {
    domain_platform::set(first);
    learning_evidence::start(
        trial,
        family,
        first,
        observation,
        hash,
        &sources(),
        requests,
    )
    .unwrap()
}
fn issue(request: FrozenRequest, result: Option<RequestResult>) {
    let registered = learning_evidence::request(request.owner, request.id).unwrap();
    domain_platform::set(request.arrived_ns);
    learning_evidence::issued(registered).unwrap();
    if let Some(result) = result {
        if let RequestResult::Completed { finished_ns } = result {
            domain_platform::set(finished_ns);
        }
        learning_evidence::result(registered, result).unwrap();
    }
}
fn finish_capture(end: u64, incomplete: bool) -> Seal {
    domain_platform::set(end);
    for source in sources() {
        let token = learning_evidence::source(source.owner, source.class).unwrap();
        learning_evidence::close_source(token).unwrap();
    }
    learning_evidence::seal(incomplete).unwrap()
}
fn boundary(metric: u16, minimum: u64, maximum: u64, samples: u64) -> Boundary {
    Boundary {
        id: 17,
        metric,
        minimum,
        maximum,
        min_samples: samples,
    }
}
fn entry(target: ObjectKey, start: u64) -> (ServiceWindow, WindowOutcome) {
    ROOT.lock()
        .unwrap()
        .windows
        .iter()
        .copied()
        .find(|(window, _)| window.target == target && window.start_ns == start)
        .unwrap()
}
fn other_consumer(_: RunKey) -> Result<(), learning_evidence::Error> {
    Ok(())
}
fn owner_state(family: Family, target: ObjectKey, current: Result<(), Error>, state: ExecutionState) {
    let mut root = ROOT.lock().unwrap();
    let object = root.objects.iter_mut().find(|(f, key, _, _)| *f == family && *key == target).unwrap();
    object.2 = current;
    object.3 = state;
}

// Production modules have one boot-lifetime owner. Keep the whole multi-run
// integration in one test instead of adding a non-production reset backdoor.
#[test]
fn native_windows_bind_real_pool_capture_requests_guard_and_retirement() {
    cpu::set(0);
    domain_platform::set(SECOND);
    assert_eq!(control_pool::usage(), Ok((0, 0, 0)));
    service_windows::init().unwrap();
    assert_eq!(control_pool::usage(), Ok((4, 1, 1)));
    service_windows::init().unwrap();
    assert_eq!(control_pool::usage(), Ok((4, 1, 1)));
    assert_eq!(service_windows::poll(), Ok(false)); // no fabricated default SLO
    let _capture_pin = install_capture();
    let usage = control_pool::usage().unwrap();
    assert_eq!((usage.1, usage.2), (2, 2));
    assert_eq!(
        learning_evidence::register_service_consumer(other_consumer),
        Err(learning_evidence::Error::Capture(
            cyxia_prototype::learning::Error::Conflict
        ))
    );

    let target = key(101);
    let registration = service_windows::Registration {
        family: IO,
        target,
        boundary: boundary(service_windows::COMPLETED_REQUESTS, 2, 100, 1),
        origin_ns: 3 * SECOND,
    };
    cpu::set(1);
    assert_eq!(service_windows::register(registration), Err(Error::Auth));
    assert_eq!(service_windows::poll(), Err(Error::Auth));
    assert!(matches!(
        learning_evidence::service_snapshot(&mut []),
        Err(learning_evidence::Error::Owner)
    ));
    cpu::set(0);
    REGISTER_BUSY.store(true, Ordering::Release);
    assert_eq!(service_windows::register(registration), Err(Error::Busy));
    assert_eq!(
        service_windows::prepare(IO, target, [1; 32], SECOND, 3 * SECOND),
        Err(Error::NotReady)
    );
    service_windows::register(registration).unwrap();
    service_windows::register(registration).unwrap();
    assert_eq!(ROOT.lock().unwrap().registrations, 1);
    let mut changed = registration;
    changed.boundary.maximum += 1;
    assert_eq!(service_windows::register(changed), Err(Error::Conflict));
    changed = registration;
    changed.origin_ns += 1;
    assert_eq!(service_windows::register(changed), Err(Error::Conflict));
    let mut late = registration;
    late.target = key(102);
    late.origin_ns = SECOND - 1;
    assert_eq!(service_windows::register(late), Err(Error::Stale));
    assert_eq!(
        service_windows::prepare(IO, target, [1; 32], SECOND - 1, 3 * SECOND),
        Err(Error::Stale)
    );
    service_windows::prepare(IO, target, [1; 32], SECOND, 3 * SECOND).unwrap();
    assert_eq!(service_windows::poll(), Ok(false));
    assert_eq!(
        service_windows::prepare(IO, target, [2; 32], SECOND, 3 * SECOND),
        Err(Error::Busy)
    );

    let observation = 3 * SECOND;
    let frozen = requests(observation, [10, 10, 10, 10, 10, 10, 0, 10, 10, 20]);
    let run = start(1, IO, SECOND, observation, [1; 32], &frozen);
    let mut raw = [(
        WorkRequest {
            id: 0,
            arrived_ns: 0,
            result: RequestResult::Pending,
        },
        None,
    ); 128];
    assert!(matches!(
        learning_evidence::service_snapshot(&mut raw[..99]),
        Err(learning_evidence::Error::Capacity)
    ));
    assert_eq!(
        learning_evidence::service_snapshot(&mut raw).unwrap().count,
        100
    );
    assert!(raw[..100].iter().all(|row| row.1.is_none()));
    for second in 0..10u64 {
        let begin = observation + second * SECOND;
        let end = begin + SECOND;
        let current: Vec<_> = frozen
            .iter()
            .copied()
            .filter(|r| r.arrived_ns >= begin && r.arrived_ns < end)
            .collect();
        // The missing issue at second 2 is genuinely absent from Capture,
        // rather than a fabricated metric supplied to Guard.
        if second != 2 {
            for (i, request) in current.iter().copied().enumerate() {
                let result = if i == 0 || second == 7 {
                    Some(RequestResult::Completed {
                        finished_ns: request.arrived_ns + 100 + i as u64,
                    })
                } else if i % 2 == 0 {
                    Some(RequestResult::Rejected)
                } else {
                    None
                };
                issue(request, result);
            }
        }
        domain_platform::set(end);
        if second == 0 {
            learning_evidence::test_support::with_gate(|| {
                assert_eq!(service_windows::poll(), Err(Error::Busy))
            });
            assert!(ROOT.lock().unwrap().windows.is_empty());
            OBSERVE_BUSY.store(true, Ordering::Release);
            assert_eq!(service_windows::poll(), Err(Error::Busy));
            assert!(ROOT.lock().unwrap().windows.is_empty());
        }
        if second == 9 {
            break;
        }
        assert_eq!(service_windows::poll(), Ok(true));
        assert_eq!(service_windows::poll(), Ok(false)); // no repeated advancement
        let (window, outcome) = entry(target, begin);
        assert_eq!(window.samples, current.len() as u64);
        let breaches = match second {
            0 => 1,
            1 => 2,
            2 => 0,
            3 => 1,
            4 => 2,
            5 => 3,
            8 => 1,
            _ => 0,
        };
        assert_eq!(outcome.consecutive_breaches, breaches);
        if matches!(second, 2 | 6) {
            assert_eq!(outcome.status, ServiceStatus::Incomplete);
            assert_eq!(window.value, None);
        } else if second == 7 {
            assert_eq!(outcome.status, ServiceStatus::WithinBoundary);
            assert_eq!(window.value, Some(10));
        } else {
            assert_eq!(window.value, Some(1));
        }
        assert_eq!(
            outcome.frozen,
            (second >= 5).then_some(FreezeReason::ServiceBoundary)
        );
    }
    let end = observation + OBSERVATION_NS;
    let seal = finish_capture(end, true);
    assert_eq!(seal.key, run);
    assert_eq!(
        learning_evidence::retire_exported(seal),
        Err(learning_evidence::Error::Busy)
    );
    OBSERVE_BUSY.store(true, Ordering::Release);
    assert_eq!(service_windows::poll(), Err(Error::Busy));
    assert_eq!(
        learning_evidence::retire_exported(seal),
        Err(learning_evidence::Error::Busy)
    );
    assert_eq!(service_windows::poll(), Ok(true));
    assert_eq!(
        entry(target, end - SECOND).1.status,
        ServiceStatus::Incomplete
    );
    assert_eq!(service_windows::poll(), Ok(false));
    learning_evidence::retire_exported(seal).unwrap();
    assert!(matches!(
        learning_evidence::service_snapshot(&mut raw),
        Err(learning_evidence::Error::NotReady)
    ));
    assert_eq!(
        ROOT.lock()
            .unwrap()
            .windows
            .iter()
            .filter(|(w, _)| w.target == target)
            .count(),
        10
    );
    let root = ROOT.lock().unwrap();
    assert_eq!(root.attempts[0], root.attempts[1]); // exact first window survived callback Busy
    drop(root);

    // Prepare a future scope, then let a different actual run finish. The
    // retirement guard must inspect the complete binding and leave that
    // unrelated Capture free to retire rather than deadlocking the replay.
    let next_target = key(201);
    let next_registration = service_windows::Registration {
        family: SERVICE,
        target: next_target,
        boundary: boundary(service_windows::PENALIZED_P99_NS, 0, 500, 1),
        origin_ns: 42 * SECOND,
    };
    service_windows::register(next_registration).unwrap();
    service_windows::prepare(SERVICE, next_target, [4; 32], 40 * SECOND, 42 * SECOND).unwrap();
    let foreign = requests(17 * SECOND, [10; 10]);
    let foreign_run = start(2, SERVICE, 15 * SECOND, 17 * SECOND, [9; 32], &foreign);
    for request in foreign.iter().copied() {
        issue(
            request,
            Some(RequestResult::Completed {
                finished_ns: request.arrived_ns + 100,
            }),
        );
    }
    let foreign_seal = finish_capture(27 * SECOND, false);
    assert_eq!(foreign_seal.key, foreign_run);
    learning_evidence::retire_exported(foreign_seal).unwrap();

    let final_rows = requests(42 * SECOND, [10; 10]);
    let final_run = start(3, SERVICE, 40 * SECOND, 42 * SECOND, [4; 32], &final_rows);
    for request in final_rows.iter().copied() {
        let second = (request.arrived_ns - 42 * SECOND) / SECOND;
        let i = (request.id - 1) % 10;
        let result = if (1..=3).contains(&second) && i == 9 {
            match second {
                1 => Some(RequestResult::TimedOut),
                2 => Some(RequestResult::Rejected),
                _ => None,
            }
        } else {
            Some(RequestResult::Completed {
                finished_ns: request.arrived_ns + 100 + i,
            })
        };
        issue(request, result);
    }
    let final_seal = finish_capture(52 * SECOND, false);
    assert_eq!(final_seal.key, final_run);
    // No poll has yet bound scope.run. The guard still recognizes this exact
    // manifest and prevents destroying its only issue/result table.
    assert_eq!(
        learning_evidence::retire_exported(final_seal),
        Err(learning_evidence::Error::Busy)
    );
    assert_eq!(
        learning_evidence::retire_exported(foreign_seal),
        Err(learning_evidence::Error::Capture(
            cyxia_prototype::learning::Error::Stale
        ))
    );
    learning_evidence::test_support::with_gate(|| {
        assert_eq!(
            learning_evidence::retire_exported(final_seal),
            Err(learning_evidence::Error::Busy)
        )
    });
    OBSERVE_BUSY.store(true, Ordering::Release);
    assert_eq!(service_windows::poll(), Err(Error::Busy));
    for second in 0..10 {
        assert_eq!(service_windows::poll(), Ok(true));
        let (window, outcome) = entry(next_target, (42 + second) * SECOND);
        assert_eq!((window.samples, window.covered_ns), (10, SECOND));
        assert_eq!(
            window.value,
            Some(if (1..=3).contains(&second) {
                OBSERVATION_NS
            } else {
                109
            })
        );
        assert_eq!(
            outcome.frozen,
            (second >= 3).then_some(FreezeReason::ServiceBoundary)
        );
        if second != 9 {
            assert_eq!(
                learning_evidence::retire_exported(final_seal),
                Err(learning_evidence::Error::Busy)
            );
        }
    }
    learning_evidence::retire_exported(final_seal).unwrap();
    assert_eq!(service_windows::poll(), Ok(false));
    assert_eq!(control_pool::usage(), Ok(usage)); // no per-run/window allocation or pin leak
    assert_eq!(ROOT.lock().unwrap().windows.len(), 20);

    // Fill the real fixed 32-slot window owner. These root-boundary fixtures
    // explicitly distinguish a destroyed generation from unavailable ownership
    // and unresolved execution; no registration is retired merely due to age.
    let replay_boundary = boundary(service_windows::PENALIZED_P99_NS, 0, 10 * SECOND, 10);
    for id in 6000..6030 {
        service_windows::register_replay(SERVICE, key(id), replay_boundary).unwrap();
    }
    let mut turnover = ObjectKey { id: 7000, generation: 1 };
    assert_eq!(service_windows::register_replay(SERVICE, turnover, replay_boundary), Err(Error::Capacity));
    owner_state(SERVICE, next_target, Err(Error::Stale), ExecutionState::Unknown);
    assert_eq!(service_windows::register_replay(SERVICE, turnover, replay_boundary), Err(Error::Busy));
    owner_state(SERVICE, next_target, Err(Error::Busy), ExecutionState::Applied);
    assert_eq!(service_windows::register_replay(SERVICE, turnover, replay_boundary), Err(Error::Busy));
    owner_state(SERVICE, next_target, Err(Error::Stale), ExecutionState::Applied);

    // The previous scope is fully consumed and its exact target is dead, but
    // an active (and later sealed) capture still forbids recycling the slot.
    let held_requests = requests(56 * SECOND, [10; 10]);
    start(5, SERVICE, 54 * SECOND, 56 * SECOND, [8; 32], &held_requests);
    assert_eq!(service_windows::register_replay(SERVICE, turnover, replay_boundary), Err(Error::Busy));
    for request in held_requests.iter().copied() {
        issue(request, Some(RequestResult::Completed { finished_ns: request.arrived_ns + 100 }));
    }
    let held_seal = finish_capture(66 * SECOND, false);
    assert_eq!(service_windows::register_replay(SERVICE, turnover, replay_boundary), Err(Error::Busy));
    learning_evidence::retire_exported(held_seal).unwrap();
    learning_evidence::test_support::with_gate(|| {
        assert_eq!(service_windows::register_replay(SERVICE, turnover, replay_boundary), Err(Error::Busy));
    });
    let registrations = ROOT.lock().unwrap().registrations;
    REGISTER_BUSY.store(true, Ordering::Release);
    assert_eq!(service_windows::register_replay(SERVICE, turnover, replay_boundary), Err(Error::Busy));
    // A failed replacement did not remove or overwrite the old registration.
    service_windows::register(next_registration).unwrap();
    assert_eq!(ROOT.lock().unwrap().registrations, registrations);
    service_windows::register_replay(SERVICE, turnover, replay_boundary).unwrap();
    assert_eq!(service_windows::poll(), Ok(false));

    // More than the entire table's capacity in exact-generation turnovers.
    // The production helper reuses one retired slot while every live object's
    // immutable origin and sticky service-boundary freeze remain intact.
    for generation in 2..=45 {
        owner_state(SERVICE, turnover,
            Err(if generation % 2 == 0 { Error::Stale } else { Error::NotFound }),
            ExecutionState::Applied);
        turnover.generation = generation;
        service_windows::register_replay(SERVICE, turnover, replay_boundary).unwrap();
    }
    service_windows::register(registration).unwrap();
    assert_eq!(ROOT.lock().unwrap().registrations, registrations + 45);
    let root = ROOT.lock().unwrap();
    let live = root.guards.iter().find(|guard| guard.target() == target && guard.family() == (IO.domain, IO.kind)).unwrap();
    assert_eq!(live.boundary(), Some(registration.boundary));
    assert_eq!(live.window_origin_ns(), Some(registration.origin_ns));
    assert_eq!(live.freeze_reason(), Some(FreezeReason::ServiceBoundary));
    drop(root);
    assert_eq!(control_pool::usage(), Ok(usage));
    owner_state(SERVICE, turnover, Err(Error::Stale), ExecutionState::Applied);

    // First/observation/family can all match while the frozen workload hash
    // differs. Such a run must neither supply a window nor inherit the bound
    // scope's retirement obligation. This also covers an explicit third
    // metric registration without making an invented successful observation.
    let hash_target = key(301);
    let hash_first = domain_platform::now_ns() + 2 * SECOND;
    let hash_observation = hash_first + 2 * SECOND;
    let hash_end = hash_observation + OBSERVATION_NS;
    service_windows::register(service_windows::Registration {
        family: SERVICE,
        target: hash_target,
        boundary: boundary(service_windows::COMPLETED_P99_NS, 0, 500, 1),
        origin_ns: hash_observation,
    })
    .unwrap();
    service_windows::prepare(SERVICE, hash_target, [6; 32], hash_first, hash_observation).unwrap();
    let mismatched = requests(hash_observation, [10; 10]);
    start(6, SERVICE, hash_first, hash_observation, [7; 32], &mismatched);
    for request in mismatched.iter().copied() {
        issue(
            request,
            Some(RequestResult::Completed {
                finished_ns: request.arrived_ns + 100,
            }),
        );
    }
    let mismatched_seal = finish_capture(hash_end, false);
    assert_eq!(service_windows::poll(), Err(Error::Stale));
    assert_eq!(ROOT.lock().unwrap().windows.len(), 20);
    learning_evidence::retire_exported(mismatched_seal).unwrap();
    assert_eq!(control_pool::usage(), Ok(usage));

    // The native producer registers long after boot. A zero origin is stale;
    // its replay helper must choose a real future origin once and retain it.
    let replay_target = key(401);
    // Even a proven-dead generation cannot be recycled while its bound scope
    // has unconsumed windows. An unrelated capture's retirement is no proof.
    owner_state(SERVICE, hash_target, Err(Error::NotFound), ExecutionState::Applied);
    assert_eq!(learning_evidence::current_config().unwrap(), None);
    assert_eq!(service_windows::register_replay(SERVICE, replay_target, replay_boundary), Err(Error::Busy));
    owner_state(SERVICE, key(6000), Err(Error::Stale), ExecutionState::Applied);
    service_windows::register_replay(SERVICE, replay_target, replay_boundary).unwrap();
    service_windows::register(service_windows::Registration { family: SERVICE,
        target: replay_target, boundary: replay_boundary, origin_ns: hash_end + SECOND }).unwrap();
    domain_platform::set(hash_end + 2 * SECOND);
    service_windows::register_replay(SERVICE, replay_target, replay_boundary).unwrap();
    let changed = Boundary { maximum: 9 * SECOND, ..replay_boundary };
    assert_eq!(service_windows::register_replay(SERVICE, replay_target, changed), Err(Error::Conflict));
    owner_state(SERVICE, key(6001), Err(Error::Stale), ExecutionState::Applied);
    assert_eq!(service_windows::register(service_windows::Registration { family: SERVICE,
        target: key(402), boundary: replay_boundary, origin_ns: 0 }), Err(Error::Stale));
}
