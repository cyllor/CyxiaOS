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

#[test]
fn actual_completed_sources_are_attributed_without_changing_capture() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let storage = Box::leak(Box::new(bridge::Storage::empty()));
            ALLOCATION.store(storage as *mut bridge::Storage as usize, Ordering::Release);
            bridge::install(storage, [1; 32], 7, key(44), pool_check)
                .map_err(|(error, _)| error)
                .unwrap();
            bridge::register_source_classifier(classify).unwrap();
            let run = begin(1);
            domain_platform::at(OBS + 200_000_100);
            let mut attempt = bridge::attempt_work(key(99), false).unwrap().unwrap();
            bridge::finish_attempt(&mut attempt, OBS + 200_000_000, OBS + 200_000_037).unwrap();
            drop(attempt);
            let words = bridge::test_support::source_snapshot();
            assert_eq!(
                &words[3..6],
                &[7, 1, 1],
                "source provenance lost the original full RunKey"
            );
            assert_eq!(&words[6..10], &[1, 1, 0, 0]);
            assert_eq!(
                &words[16..24],
                &[99, 1, 13, 1, 2, 0, 1, 37],
                "original child and resolved source must stay distinct"
            );
            assert_eq!(
                &words[24..28],
                &[
                    OBS + 200_000_000,
                    OBS + 200_000_037,
                    OBS + 200_000_000,
                    OBS + 200_000_037
                ]
            );
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 37, 0]);
            let seal = close_and_export(false);
            assert_eq!(seal.key, run);
            assert_eq!(seal.exclusion, None);
            let mut rows = [CpuInterval {
                node: [0; 32],
                core: 0,
                start_ns: 0,
                end_ns: 0,
                class: CpuClass::Policy,
            }; 2];
            assert_eq!(bridge::copy_intervals(seal, 0, &mut rows).unwrap(), 1);
            assert_eq!(
                (rows[0].start_ns, rows[0].end_ns),
                (OBS + 200_000_000, OBS + 200_000_037)
            );
            bridge::retire_exported(seal).unwrap();
            // Full caller generation and request identity are copied, even when
            // two callers reuse request9. Source aggregation grants no identity.
            begin(2);
            domain_platform::at(OBS + 200_000_000);
            let reads = domain_platform::reads();
            bridge::measure_task(
                key(13),
                CpuClass::ExecutorWork,
                bridge::TaskIdentity {
                    site: 2,
                    caller: ObjectKey {
                        id: 70,
                        generation: 8,
                    },
                    request: 9,
                    child: ObjectKey {
                        id: 4097,
                        generation: 6,
                    },
                    recipe: 2,
                },
                || domain_platform::at(OBS + 200_000_037),
            );
            assert_eq!(
                domain_platform::reads() - reads,
                4,
                "diagnostics added a clock read"
            );
            let words = bridge::test_support::source_snapshot();
            assert_eq!(&words[3..6], &[7, 2, 2]);
            assert_eq!(words[12], 1);
            assert_eq!(
                &words[29..37],
                &[1, 2, 70, 8, 9, 4097, 6, 2],
                "TaskGuard caller/request/child identity was not copied"
            );
            let before = bridge::status().unwrap();
            let reads = domain_platform::reads();
            assert_eq!(bridge::test_support::source_snapshot(), words);
            assert_eq!(domain_platform::reads(), reads);
            assert_eq!(
                bridge::status().unwrap(),
                before,
                "diagnostic read changed capture counters"
            );
            let seal = close_and_export(false);
            bridge::retire_exported(seal).unwrap();
            assert_eq!(
                bridge::test_support::source_snapshot(),
                words,
                "seal/retire erased provenance"
            );

            // Four source/site buckets are a diagnostic bound only. The fifth
            // distinct source stays in the original interval collection, with an
            // explicit omitted-attribution counter and no overwritten bucket.
            begin(3);
            domain_platform::at(OBS + 200_000_100);
            for site in 1..=5 {
                domain_platform::at(OBS + 200_000_000 + site * 100);
                bridge::measure_task(
                    key(13),
                    CpuClass::ExecutorWork,
                    bridge::TaskIdentity {
                        site,
                        caller: key(70 + site),
                        request: 9,
                        child: key(4096 + site),
                        recipe: 0,
                    },
                    || domain_platform::at(OBS + 200_000_037 + site * 100),
                );
            }
            let words = bridge::test_support::source_snapshot();
            assert_eq!(&words[6..12], &[5, 5, 0, 0, 1, 4]);
            assert_eq!(
                words[14], 1,
                "overflow attribution lost the producing source"
            );
            assert_eq!(
                &words[112..128],
                &[
                    13,
                    1,
                    13,
                    1,
                    2,
                    OBS + 200_000_500,
                    OBS + 200_000_537,
                    1,
                    1,
                    5,
                    75,
                    1,
                    9,
                    4101,
                    1,
                    0
                ]
            );
            assert_eq!(words[31], 71);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 185, 0]);
            let seal = close_and_export(false);
            assert_eq!(seal.intervals, 5);
            bridge::retire_exported(seal).unwrap();

            // The hard interval limit remains8192. Every37ns interval has a63ns
            // physical gap. The8193rd real cost is retained raw and excluded as
            // Capacity, never merged into a neighboring accepted interval.
            begin(4);
            for i in 0..8193 {
                let first = OBS + 200_000_000 + i * 100;
                domain_platform::at(first + 37);
                let mut attempt = bridge::attempt_work(key(13), false).unwrap().unwrap();
                let result = bridge::finish_attempt(&mut attempt, first, first + 37);
                assert_eq!(
                    result,
                    if i < 8192 {
                        Ok(())
                    } else {
                        Err(bridge::Error::Capture(learning::Error::Capacity))
                    }
                );
            }
            let words = bridge::test_support::source_snapshot();
            assert_eq!(&words[6..10], &[8193, 8192, 1, 0]);
            assert_eq!(&words[37..40], &[OBS + 200_819_200, OBS + 200_819_237, 1]);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 303141, 0]);
            let seal = close_and_export(true);
            assert_eq!(seal.intervals, 8192);
            assert_eq!(seal.exclusion, Some(learning::Error::Capacity));
            assert_eq!(bridge::copy_intervals(seal, 8191, &mut rows).unwrap(), 1);
            assert_eq!(
                (rows[0].start_ns, rows[0].end_ns),
                (OBS + 200_819_100, OBS + 200_819_137)
            );
            bridge::retire_exported(seal).unwrap();

            // Original cleanup bound remains five seconds after observation end.
            begin(5);
            domain_platform::at(END + 5_000_000_001);
            for source in sources() {
                bridge::close_source(bridge::source(source.owner, source.class).unwrap()).unwrap();
            }
            assert_eq!(
                bridge::seal(false),
                Err(bridge::Error::Capture(learning::Error::Deadline))
            );
            let seal = bridge::seal(true).unwrap();
            assert_eq!(seal.exclusion, Some(learning::Error::Deadline));
            assert_eq!(seal.intervals, 0);
            assert_eq!(
                bridge::test_support::source_snapshot(),
                words,
                "a run without records must not claim attribution"
            );
            bridge::retire_exported(seal).unwrap();

            // A retained original completion can import on another CPU. Its
            // source/core/times remain exact, while unavailable task identity
            // stays absent rather than being joined to a later caller.
            begin(6);
            domain_platform::at(OBS + 200_000_000);
            bridge::test_support::with_gate(|| {
                bridge::measure_task(
                    key(99),
                    CpuClass::ExecutorWork,
                    bridge::TaskIdentity {
                        site: 2,
                        caller: key(77),
                        request: 9,
                        child: key(99),
                        recipe: 0,
                    },
                    || domain_platform::at(OBS + 200_000_037),
                );
            });
            assert_eq!(bridge::test_support::handoff_status()[28], 1);
            cpu::at(1);
            let seal = close_and_export(false);
            let words = bridge::test_support::source_snapshot();
            assert_eq!(&words[3..6], &[7, 6, 6]);
            assert_eq!(&words[16..24], &[99, 1, 13, 1, 2, 0, 1, 37]);
            assert_eq!(words[13], 1);
            assert_eq!(words[29], 0, "delayed completion invented task identity");
            assert_eq!(bridge::test_support::handoff_status()[28], 0);
            assert_eq!(seal.intervals, 1);
            assert_eq!(seal.exclusion, None);
            bridge::retire_exported(seal).unwrap();

            // Even an unbucketed producer retains its first Capacity sample,
            // with the original complete identity. A later error cannot move
            // that physical interval or substitute another caller.
            begin(7);
            for i in 0..8194 {
                let first = OBS + 200_000_000 + i * 100;
                domain_platform::at(first);
                bridge::measure_task(
                    key(13),
                    CpuClass::ExecutorWork,
                    bridge::TaskIdentity {
                        site: if i < 4 { i + 1 } else { 5 },
                        caller: key(70 + i),
                        request: 9,
                        child: key(4096 + i),
                        recipe: 2,
                    },
                    || domain_platform::at(first + 37),
                );
            }
            let words = bridge::test_support::source_snapshot();
            assert_eq!(&words[6..12], &[8194, 8192, 2, 0, 8190, 4]);
            assert_eq!(words[14], 2);
            assert_eq!(
                &words[112..128],
                &[
                    13,
                    1,
                    13,
                    1,
                    2,
                    OBS + 200_819_200,
                    OBS + 200_819_237,
                    0x10a,
                    1,
                    5,
                    8262,
                    1,
                    9,
                    12288,
                    1,
                    2
                ]
            );
            let seal = close_and_export(true);
            assert_eq!(seal.intervals, 8192);
            assert_eq!(seal.exclusion, Some(learning::Error::Capacity));
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 303178, 0]);
            bridge::retire_exported(seal).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
