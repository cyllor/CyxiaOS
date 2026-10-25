//! Execute the production D15 workload adapter, collector, and ConsolePump.
//! CPU, clock, root publications, and UART are explicit host fixtures; these
//! tests do not manufacture accepted replay labels or claim a native run.
extern crate self as cyxia_arch_aarch64;
pub mod sha256 {
    pub fn digest_page(_: &[u8; 4096]) -> Option<[u8; 32]> {
        None
    }
}
pub mod cpu {
    pub fn slot() -> usize {
        0
    }
}
pub mod domain_platform {
    use core::sync::atomic::{AtomicU64, Ordering};
    static CLOCK: AtomicU64 = AtomicU64::new(1_000_000_000);
    pub fn now_ns() -> u64 {
        CLOCK.load(Ordering::Acquire)
    }
    pub fn at(ns: u64) {
        CLOCK.store(ns, Ordering::Release);
    }
}
pub mod domain_tasks {
    pub fn authorize_service_turn() -> Result<(), cyxia_prototype::domains::Error> {
        Ok(())
    }
}
pub mod learning_canary {
    pub fn owns_output() -> bool {
        false
    }
}
pub mod service_windows {
    pub const PENALIZED_P99_NS: u16 = 1;
}
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_evidence.rs"]
mod learning_evidence;
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_history.rs"]
mod learning_history;
#[path = "support/learning.rs"]
mod support;

use core::sync::atomic::{AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey, PolicyStamp},
    learning::{
        self, Family, ReplayGroup,
        capture::{CaptureInit, FrozenRequest, InitValue, Source},
        reward::{Adoption, BaselineAdoption, CpuClass, RequestResult},
    },
    policy::ExecutionState,
};
use std::sync::Mutex;
const TARGET: ObjectKey = ObjectKey {
    id: 0x5345_5249,
    generation: 1,
};
const OWNER: ObjectKey = ObjectKey {
    id: 0x5245_504c,
    generation: 1,
};
const FAMILY: Family = Family {
    domain: 15,
    kind: 1,
};
const OBS: u64 = 2_000_000_000;
const END: u64 = OBS + 10_000_000_000;
pub mod learning_workload {
    use super::*;
    pub const REQUESTS: usize = 100;
    pub const SOURCES: usize = 16;
    pub const EMPTY_SOURCE: Source = Source {
        owner: ObjectKey {
            id: 0,
            generation: 0,
        },
        class: CpuClass::Policy,
        allowed_cores: 0,
    };
    #[derive(Clone, Copy)]
    pub struct RelativeRequest {
        pub id: u64,
        pub owner: ObjectKey,
        pub offset_ns: u64,
    }
    pub const EMPTY_REQUEST: RelativeRequest = RelativeRequest {
        id: 0,
        owner: ObjectKey {
            id: 0,
            generation: 0,
        },
        offset_ns: 0,
    };
    #[derive(Clone, Copy)]
    pub struct Prepared {
        pub family: Family,
        pub target: ObjectKey,
        pub baseline: Action,
        pub boundary: cyxia_prototype::domains::stability::Boundary,
        pub group: ReplayGroup,
        pub sources: [Source; SOURCES],
        pub source_count: usize,
        pub requests: [RelativeRequest; REQUESTS],
        pub checks: learning_history::ReplayChecks,
    }
    #[derive(Clone, Copy)]
    pub struct PreparedFailure {
        pub target: Option<ObjectKey>,
        pub group: Option<ReplayGroup>,
        pub queued_at: u64,
        pub fault: Option<Error>,
        pub drained_at: u64,
    }
}
pub mod domain_control {
    pub mod replay {
        use super::super::*;
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct Token {
            pub id: u64,
            pub boot_epoch: u64,
            pub owner: ObjectKey,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct Preparation {
            pub id: u64,
            pub boot_epoch: u64,
            pub owner: ObjectKey,
            pub trial_id: u64,
            pub family: Family,
            pub seed: u64,
            pub kind: learning_history::TrialKind,
            pub started_ns: u64,
        }
        static PREPARATION: Mutex<Option<Preparation>> = Mutex::new(None);
        static ARCHIVED: Mutex<bool> = Mutex::new(false);
        pub fn install_preparation(p: Preparation) {
            *PREPARATION.lock().unwrap() = Some(p);
            *ARCHIVED.lock().unwrap() = false;
        }
        pub fn preparation_archived(p: Preparation) -> bool {
            *PREPARATION.lock().unwrap() == Some(p) && *ARCHIVED.lock().unwrap()
        }
        pub fn archive_preparation(p: Preparation) {
            verify_preparation(p).unwrap();
            *ARCHIVED.lock().unwrap() = true;
        }
        pub fn verify_preparation(p: Preparation) -> Result<(), Error> {
            if *PREPARATION.lock().unwrap() == Some(p) {
                Ok(())
            } else {
                Err(Error::Stale)
            }
        }
        #[derive(Clone, Copy)]
        pub struct Receipt {
            pub state: ExecutionState,
            pub stamp: PolicyStamp,
        }
        pub struct Status {
            pub closing: Option<Receipt>,
        }
        pub const TOKEN: Token = Token {
            id: 1,
            boot_epoch: 7,
            owner: OWNER,
        };
        static CLOSING: Mutex<Option<Receipt>> = Mutex::new(None);
        pub fn activation(t: Token) -> bool {
            t == TOKEN
        }
        pub fn poll(t: Token) -> Result<Status, Error> {
            if t != TOKEN {
                return Err(Error::Stale);
            }
            Ok(Status {
                closing: *CLOSING.lock().unwrap(),
            })
        }
        pub fn close(stamp: PolicyStamp) {
            *CLOSING.lock().unwrap() = Some(Receipt {
                stamp,
                state: ExecutionState::Pending,
            });
        }
        pub fn applied(version: u64) {
            let mut v = CLOSING.lock().unwrap();
            if let Some(r) = v.as_mut() {
                if r.stamp.version == version {
                    r.state = ExecutionState::Applied;
                }
            }
        }
        pub fn verify_scope(
            t: Token,
            _: &learning_history::FrozenScope,
        ) -> Result<(), learning::Error> {
            if t == TOKEN {
                Ok(())
            } else {
                Err(learning::Error::Evidence)
            }
        }
        pub fn verify_adoption(_: Token, _: &Adoption<'_>) -> Result<(), learning::Error> {
            Err(learning::Error::Evidence)
        }
        pub fn verify_baseline(_: Token, _: &BaselineAdoption) -> Result<(), learning::Error> {
            Err(learning::Error::Evidence)
        }
        pub fn verify_scope_bounded(
            t: Token,
            scope: &learning_history::FrozenScope,
        ) -> Result<bool, learning::Error> {
            verify_scope(t, scope).map(|()| true)
        }
        pub fn verify_adoption_bounded(
            t: Token,
            adoption: &Adoption<'_>,
        ) -> Result<bool, learning::Error> {
            verify_adoption(t, adoption).map(|()| true)
        }
        pub fn verify_baseline_bounded(
            t: Token,
            baseline: &BaselineAdoption,
        ) -> Result<bool, learning::Error> {
            verify_baseline(t, baseline).map(|()| true)
        }
    }
}

pub mod domain_services {
    use super::*;
    use cyxia_prototype::domains::maintenance::{ConsoleHardware, ConsolePump};
    struct Fixture {
        pump: ConsolePump,
        installed: Option<(PolicyStamp, ExecutionState)>,
        bytes: Vec<u8>,
    }
    static FIXTURE: Mutex<Fixture> = Mutex::new(Fixture {
        pump: ConsolePump::new(),
        installed: None,
        bytes: Vec::new(),
    });
    pub(crate) fn replay_console_enqueue(bytes: &[u8]) -> Result<u64, Error> {
        let mut f = FIXTURE.lock().unwrap();
        f.pump.enqueue(bytes, domain_platform::now_ns())?;
        Ok(f.pump.written + f.pump.queued() as u64)
    }
    pub(crate) fn replay_console_state() -> Result<(ObjectKey, u64, usize, bool), Error> {
        let f = FIXTURE.lock().unwrap();
        Ok((TARGET, f.pump.written, f.pump.queued(), f.pump.poisoned()))
    }
    pub(crate) fn replay_console_installation()
    -> Result<Option<(PolicyStamp, ExecutionState)>, Error> {
        Ok(FIXTURE.lock().unwrap().installed)
    }
    pub fn install(stamp: PolicyStamp) {
        let mut f = FIXTURE.lock().unwrap();
        f.pump.install(stamp, 8, domain_platform::now_ns()).unwrap();
        f.installed = Some((stamp, ExecutionState::Pending));
    }
    struct Uart<'a> {
        bytes: &'a mut Vec<u8>,
        now: u64,
        blocked: bool,
    }
    impl ConsoleHardware for Uart<'_> {
        fn now_ns(&mut self) -> u64 {
            self.now
        }
        fn try_write(&mut self, b: u8) -> Result<bool, Error> {
            if self.blocked {
                return Ok(false);
            }
            self.bytes.push(b);
            self.now += 1;
            Ok(true)
        }
    }
    pub fn pump(blocked: bool) {
        let mut f = FIXTURE.lock().unwrap();
        let Fixture {
            pump,
            installed,
            bytes,
        } = &mut *f;
        let mut uart = Uart {
            bytes,
            now: domain_platform::now_ns(),
            blocked,
        };
        let receipt = pump.pump(uart.now, &mut uart).unwrap();
        domain_platform::at(uart.now);
        if receipt.chars != 0 {
            if let Some((stamp, state)) = installed {
                if stamp.version == receipt.policy_version {
                    *state = ExecutionState::Applied;
                    domain_control::replay::applied(stamp.version);
                }
            }
        }
    }
    pub fn bytes() -> usize {
        FIXTURE.lock().unwrap().bytes.len()
    }
    pub use crate::adapter as replay_serial;
}
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_services/replay_serial.rs"]
pub mod adapter;
// Production adapter uses its domain_services parent's typed queue functions.
use domain_services::{replay_console_enqueue, replay_console_installation, replay_console_state};

static CAPTURE: AtomicUsize = AtomicUsize::new(0);
fn pool_check(
    key: ObjectKey,
    address: usize,
    bytes: usize,
) -> Result<(), learning_evidence::Error> {
    if key == OWNER
        && address == CAPTURE.load(Ordering::Acquire)
        && bytes == learning_evidence::STORAGE_BYTES
    {
        Ok(())
    } else {
        Err(learning_evidence::Error::Owner)
    }
}
fn storage() -> &'static mut learning_evidence::Storage {
    let mut value = Box::<learning_evidence::Storage>::new_uninit();
    let base = value.as_mut_ptr().cast::<u8>();
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
    Box::leak(unsafe { value.assume_init() })
}
#[test]
fn actual_serial_workload_retains_arrivals_and_waits_for_real_restoration_bytes() {
    let mem = storage();
    CAPTURE.store(mem as *mut _ as usize, Ordering::Release);
    learning_evidence::install(mem, [1; 32], 7, OWNER, pool_check)
        .map_err(|(e, _)| e)
        .unwrap();
    adapter::init().unwrap();
    let preparation = domain_control::replay::Preparation {
        id: 1,
        boot_epoch: 7,
        owner: OWNER,
        trial_id: 1,
        family: FAMILY,
        seed: 17,
        kind: learning_history::TrialKind::Baseline,
        started_ns: domain_platform::now_ns(),
    };
    domain_control::replay::install_preparation(preparation);
    adapter::bind_preparation(preparation).unwrap();
    let p = adapter::prepare(FAMILY, 17, learning_history::TrialKind::Baseline)
        .unwrap()
        .unwrap();
    assert!(adapter::reserved());
    assert_eq!(p.baseline, Action::ConsoleBatch(8));
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: p.requests[i].id,
        owner: p.requests[i].owner,
        arrived_ns: OBS + p.requests[i].offset_ns,
    });
    let run = learning_evidence::start(
        1,
        FAMILY,
        domain_platform::now_ns(),
        OBS,
        [7; 32],
        &p.sources[..p.source_count],
        &requests,
    )
    .unwrap();
    adapter::bind_root(domain_control::replay::TOKEN).unwrap();
    let scope = learning_history::FrozenScope {
        key: run,
        kind: learning_history::TrialKind::Baseline,
        family: FAMILY,
        target: TARGET,
        group: p.group,
        schemas: support::schemas(),
        frozen_other_domains: [8; 32],
        frozen_scope_hash: [7; 32],
        first_ns: domain_platform::now_ns(),
        warmed_from_ns: OBS - 1_000_000_000,
        observation_ns: OBS,
    };
    let mut wrong = scope;
    wrong.group.seed += 1;
    assert_eq!(adapter::bind_scope(&wrong), Err(Error::Auth));
    adapter::bind_scope(&scope).unwrap();
    adapter::activate(run, OBS).unwrap();
    adapter::activate(run, OBS).unwrap();
    // Entering the real activation path is irreversible for this narrow
    // cancellation API, even before the first fixed request is released.
    assert_eq!(
        adapter::abort_unactivated(preparation, &scope),
        Err(Error::Conflict)
    );
    // Arm all actual retained schedule tokens before their release.
    for _ in 0..100 {
        assert!(adapter::service_io().unwrap());
    }
    let mut at = domain_platform::now_ns();
    while at < END {
        domain_platform::at(at);
        adapter::poll(run).unwrap();
        domain_services::pump(false);
        adapter::service_io().unwrap();
        at += 1_000_000;
    }
    domain_platform::at(END);
    adapter::poll(run).unwrap();
    adapter::service_io().unwrap();
    assert_eq!(domain_services::bytes(), 101 * 16);
    assert_eq!(adapter::settled(run), Err(Error::Busy));
    let stamp = PolicyStamp {
        version: 3,
        snapshot_ns: END,
        installed_until_ns: END + 10_000_000_000,
    };
    domain_control::replay::close(stamp);
    assert!(!adapter::drain(run).unwrap());
    assert_eq!(domain_services::replay_console_state().unwrap().2, 0);
    // Merely publishing a baseline does not enqueue its proof before the
    // executor actually installs that exact version.
    domain_services::install(stamp);
    assert!(!adapter::drain(run).unwrap());
    assert_eq!(domain_services::replay_console_state().unwrap().2, 16);
    domain_services::pump(true);
    assert!(!adapter::drain(run).unwrap());
    assert_eq!(adapter::settled(run), Err(Error::Busy));
    domain_platform::at(END + 1_000_000);
    domain_services::pump(false);
    assert!(!adapter::drain(run).unwrap());
    domain_platform::at(END + 2_000_000);
    domain_services::pump(false);
    assert!(adapter::drain(run).unwrap());
    adapter::settled(run).unwrap();
    assert_eq!(domain_services::bytes(), 102 * 16);
    for source in &p.sources[..p.source_count] {
        learning_evidence::close_source(
            learning_evidence::source(source.owner, source.class).unwrap(),
        )
        .unwrap();
    }
    let seal = learning_evidence::seal(false).unwrap();
    let empty = cyxia_prototype::learning::reward::WorkRequest {
        id: 0,
        arrived_ns: 0,
        result: RequestResult::Pending,
    };
    let mut rows = [(empty, None); 100];
    for at in (0..100).step_by(16) {
        let end = (at + 16).min(100);
        assert_eq!(
            learning_evidence::copy_requests(seal, at, &mut rows[at..end]).unwrap(),
            end - at
        );
    }
    for (i, (row, issued)) in rows.iter().enumerate() {
        assert_eq!(row.arrived_ns, requests[i].arrived_ns);
        assert!(issued.is_some());
        assert!(
            matches!(row.result,RequestResult::Completed{finished_ns}if finished_ns>=row.arrived_ns)
        );
    }
    adapter::release(run).unwrap();
    assert!(!adapter::reserved());
    assert_eq!(adapter::settled(run), Err(Error::Stale));

    // A preparation failure has no RunKey and cannot invent an execution
    // receipt. Already accepted UART bytes still own their real queue space.
    let next = domain_control::replay::Preparation {
        id: 2,
        trial_id: 2,
        seed: 18,
        started_ns: domain_platform::now_ns(),
        ..preparation
    };
    domain_control::replay::install_preparation(next);
    assert_eq!(adapter::bind_preparation(preparation), Err(Error::Stale));
    adapter::bind_preparation(next).unwrap();
    let staged = adapter::prepare(FAMILY, 18, learning_history::TrialKind::Baseline)
        .unwrap()
        .unwrap();
    domain_services::replay_console_enqueue(b"pending.uart.00\n").unwrap();
    assert!(!adapter::abort_prepared(next).unwrap());
    assert_eq!(adapter::settled_prepared(next), Err(Error::Busy));
    assert_eq!(adapter::release_prepared(next), Err(Error::Busy));
    domain_services::pump(true);
    assert!(!adapter::abort_prepared(next).unwrap());
    domain_platform::at(domain_platform::now_ns() + 1_000_000);
    domain_services::pump(false);
    assert!(!adapter::abort_prepared(next).unwrap());
    domain_services::pump(false);
    assert!(adapter::abort_prepared(next).unwrap());
    adapter::settled_prepared(next).unwrap();
    let failure = adapter::prepared_failure(next).unwrap();
    assert_eq!(failure.target, Some(TARGET));
    assert_eq!(failure.group, Some(staged.group));
    assert!(failure.drained_at >= failure.queued_at);
    assert_eq!(failure.fault, None);
    assert_eq!(adapter::release_prepared(next), Err(Error::Busy));
    domain_control::replay::archive_preparation(next);
    adapter::release_prepared(next).unwrap();
    adapter::release_prepared(next).unwrap();
    assert!(!adapter::reserved());

    learning_evidence::retire_exported(seal).unwrap();
    let partial = domain_control::replay::Preparation {
        id: 3,
        trial_id: 3,
        seed: 19,
        started_ns: domain_platform::now_ns(),
        ..preparation
    };
    domain_control::replay::install_preparation(partial);
    adapter::bind_preparation(partial).unwrap();
    let p = adapter::prepare(FAMILY, partial.seed, partial.kind)
        .unwrap()
        .unwrap();
    let first = domain_platform::now_ns();
    let observation = first + 1_000_000_000;
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: p.requests[i].id,
        owner: p.requests[i].owner,
        arrived_ns: observation + p.requests[i].offset_ns,
    });
    let run = learning_evidence::start(
        partial.trial_id,
        FAMILY,
        first,
        observation,
        [9; 32],
        &p.sources[..p.source_count],
        &requests,
    )
    .unwrap();
    adapter::bind_root(domain_control::replay::TOKEN).unwrap();
    let scope = learning_history::FrozenScope {
        key: run,
        kind: partial.kind,
        family: FAMILY,
        target: TARGET,
        group: p.group,
        schemas: support::schemas(),
        frozen_other_domains: [8; 32],
        frozen_scope_hash: [9; 32],
        first_ns: first,
        warmed_from_ns: first,
        observation_ns: observation,
    };
    adapter::bind_scope(&scope).unwrap();
    let bytes = domain_services::bytes();
    domain_services::replay_console_enqueue(b"pending.uart.00\n").unwrap();
    let mut wrong = scope;
    wrong.group.seed += 1;
    assert_eq!(
        adapter::abort_unactivated(partial, &wrong),
        Err(Error::Stale)
    );
    assert!(!adapter::abort_unactivated(partial, &scope).unwrap());
    assert_eq!(
        adapter::settled_unactivated(partial, &scope),
        Err(Error::Busy)
    );
    assert_eq!(
        adapter::release_unactivated(partial, &scope),
        Err(Error::Busy)
    );
    assert!(!adapter::poll(run).unwrap());
    assert!(!adapter::service_io().unwrap());
    domain_services::pump(true);
    assert!(!adapter::abort_unactivated(partial, &scope).unwrap());
    domain_platform::at(domain_platform::now_ns() + 1_000_000);
    domain_services::pump(false);
    assert!(!adapter::abort_unactivated(partial, &scope).unwrap());
    domain_services::pump(false);
    assert!(adapter::abort_unactivated(partial, &scope).unwrap());
    adapter::settled_unactivated(partial, &scope).unwrap();
    assert_eq!(
        learning_evidence::current_config().unwrap().unwrap().key,
        run
    );
    assert_eq!(learning_evidence::status().unwrap().0.issued, 0);
    assert_eq!(domain_services::bytes(), bytes + 16);
    assert_eq!(adapter::activate(run, observation), Err(Error::Conflict));
    assert_eq!(
        adapter::release_unactivated(partial, &scope),
        Err(Error::Busy)
    );
    domain_control::replay::archive_preparation(partial);
    adapter::release_unactivated(partial, &scope).unwrap();
    adapter::release_unactivated(partial, &scope).unwrap();
    assert!(adapter::release_unactivated(partial, &wrong).is_err());
    assert!(!adapter::reserved());
}
