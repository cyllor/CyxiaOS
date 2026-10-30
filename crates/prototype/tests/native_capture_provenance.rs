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
        allowed_cores: if class == CpuClass::ExecutorWork {
            9
        } else {
            1
        },
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
fn paid_entries_do_not_claim_completion_or_rewrite_capture() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let storage = Box::leak(Box::new(bridge::Storage::empty()));
            ALLOCATION.store(storage as *mut bridge::Storage as usize, Ordering::Release);
            bridge::install(storage, [1; 32], 7, key(44), pool_check)
                .map_err(|(e, _)| e)
                .unwrap();
            bridge::register_source_classifier(classify).unwrap();
            let mut rows = [CpuInterval {
                node: [0; 32],
                core: 0,
                start_ns: 0,
                end_ns: 0,
                class: CpuClass::Policy,
            }; 2];
            // Generic measurement/completion has no proved enclosing ledger sample.
            // Its original capture works, but it adds no diagnostic observation.
            begin(1);
            domain_platform::at(OBS + 200_000_000);
            bridge::measure_task(key(99), CpuClass::ExecutorWork, identity(2, 70), || {
                domain_platform::at(OBS + 200_000_037)
            });
            assert_eq!(bridge::test_support::source_snapshot(), [0; 128]);
            let seal = close_and_export(false);
            assert_eq!(seal.intervals, 1);
            assert_eq!(seal.exclusion, None);
            bridge::retire_exported(seal).unwrap();

            let mut copied_without_attempt = false;
            bridge::measure_paid_task(key(13), CpuClass::ExecutorWork, |entry| {
                if let Some(entry) = entry {
                    entry.observe(|| {
                        copied_without_attempt = true;
                        identity(2, 70)
                    });
                }
            });
            assert!(
                !copied_without_attempt,
                "no-attempt path copied TaskIdentity"
            );
            assert_eq!(bridge::test_support::source_snapshot(), [0; 128]);

            // Unit fixture supplies the paid boundary; the dedicated source-cost
            // harness checks real TaskGuard cleanup/service-I/O and Scheduler debit.
            let run = begin(2);
            domain_platform::at(OBS + 200_000_000);
            let reads = domain_platform::reads();
            bridge::measure_paid_task(key(13), CpuClass::ExecutorWork, |entry| {
                entry.unwrap().observe(|| identity(2, 70));
                domain_platform::at(OBS + 200_000_037)
            });
            assert_eq!(
                domain_platform::reads() - reads,
                4,
                "diagnostic probe added a clock read"
            );
            let words = bridge::test_support::source_snapshot();
            assert_eq!(
                &words[0..2],
                &[0x4359535243450001, 2],
                "source provenance missing paid observation header"
            );
            assert_eq!(
                &words[3..6],
                &[7, 2, 2],
                "source provenance lost full RunKey"
            );
            assert_eq!(&words[6..12], &[1, 1, 0, 0, 0, 1]);
            assert_eq!(&words[16..24], &[13, 1, 13, 1, 2, 0, 2, 1]);
            assert_eq!(
                &words[24..34],
                &[
                    OBS + 200_000_000,
                    OBS + 200_000_000,
                    1,
                    1,
                    70,
                    8,
                    9,
                    4097,
                    6,
                    2
                ],
                "TaskGuard caller/request/child identity was not copied"
            );
            let counters = bridge::status().unwrap();
            let reads = domain_platform::reads();
            assert_eq!(bridge::test_support::source_snapshot(), words);
            assert_eq!(domain_platform::reads(), reads);
            assert_eq!(
                bridge::status().unwrap(),
                counters,
                "diagnostic snapshot mutated capture counters"
            );
            let seal = close_and_export(false);
            assert_eq!(seal.key, run);
            assert_eq!(seal.exclusion, None);
            assert_eq!(bridge::copy_intervals(seal, 0, &mut rows).unwrap(), 1);
            assert_eq!(
                (rows[0].start_ns, rows[0].end_ns),
                (OBS + 200_000_000, OBS + 200_000_037)
            );
            bridge::retire_exported(seal).unwrap();
            assert_eq!(bridge::test_support::source_snapshot(), words);

            // Busy probe skips only diagnostics and does not invoke the lazy
            // identity copier, mutate capture, or publish when handoff imports.
            begin(3);
            domain_platform::at(OBS + 200_000_000);
            let mut copied = false;
            bridge::test_support::with_gate(|| {
                bridge::measure_paid_task(key(99), CpuClass::ExecutorWork, |entry| {
                    entry.unwrap().observe(|| {
                        copied = true;
                        identity(2, 70)
                    });
                    domain_platform::at(OBS + 200_000_037)
                });
            });
            assert!(!copied);
            assert_eq!(bridge::test_support::handoff_status()[28], 1);
            let seal = close_and_export(false);
            assert_eq!(seal.intervals, 1);
            assert_eq!(seal.exclusion, None);
            assert_eq!(bridge::test_support::handoff_status()[28], 0);
            assert_eq!(
                bridge::test_support::source_snapshot(),
                words,
                "completion/import published a diagnostic"
            );
            bridge::retire_exported(seal).unwrap();

            // A child alias is offered, not resolved by the diagnostic probe. The
            // actual later classifier may be Busy and retain original custody.
            begin(4);
            CLASSIFIER_BUSY.store(true, Ordering::Release);
            domain_platform::at(OBS + 200_000_000);
            bridge::measure_paid_task(key(99), CpuClass::ExecutorWork, |entry| {
                entry.unwrap().observe(|| identity(2, 70));
                domain_platform::at(OBS + 200_000_037)
            });
            let words = bridge::test_support::source_snapshot();
            assert_eq!(&words[6..12], &[1, 0, 1, 0, 0, 1]);
            assert_eq!(
                &words[16..24],
                &[99, 1, 0, 0, 2, 0, 2, 1],
                "offered alias was fabricated as resolved source"
            );
            assert_eq!(words[26], 0);
            CLASSIFIER_BUSY.store(false, Ordering::Release);
            cpu::at(1);
            let seal = close_and_export(false);
            assert_eq!(seal.exclusion, None);
            assert_eq!(bridge::copy_intervals(seal, 0, &mut rows).unwrap(), 1);
            assert_eq!(rows[0].core, 0);
            assert_eq!(bridge::test_support::source_snapshot(), words);
            bridge::retire_exported(seal).unwrap();

            // Four bounded buckets plus a first overflow sample remain explicitly
            // incomplete. All five original physical intervals remain collected.
            begin(5);
            for i in 0..5 {
                domain_platform::at(OBS + 200_000_000 + i * 100);
                bridge::measure_paid_task(
                    if i < 3 { key(13) } else { key(99) },
                    CpuClass::ExecutorWork,
                    |entry| {
                        entry
                            .unwrap()
                            .observe(|| identity(if i < 3 { i + 2 } else { i - 1 }, 71 + i));
                        domain_platform::at(OBS + 200_000_037 + i * 100)
                    },
                );
            }
            let words = bridge::test_support::source_snapshot();
            assert_eq!(&words[6..12], &[5, 3, 2, 0, 1, 4]);
            assert_eq!(words[14], 1);
            assert_eq!(
                &words[112..128],
                &[
                    99,
                    1,
                    0,
                    0,
                    2,
                    0,
                    3,
                    OBS + 200_000_400,
                    0,
                    1,
                    75,
                    8,
                    9,
                    4097,
                    6,
                    2
                ]
            );
            let seal = close_and_export(false);
            assert_eq!(seal.intervals, 5);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 185, 0]);
            bridge::retire_exported(seal).unwrap();

            // Capacity and Deadline stay actual exclusions. No completion path
            // publishes a capacity/admission/result claim in the entry bank.
            begin(6);
            for i in 0..8193 {
                let first = OBS + 200_000_000 + i * 100;
                domain_platform::at(first + 37);
                let mut a = bridge::attempt_work(key(13), false).unwrap().unwrap();
                assert_eq!(
                    bridge::finish_attempt(&mut a, first, first + 37),
                    if i < 8192 {
                        Ok(())
                    } else {
                        Err(bridge::Error::Capture(learning::Error::Capacity))
                    }
                );
            }
            assert_eq!(bridge::test_support::source_snapshot(), words);
            let seal = close_and_export(true);
            assert_eq!(seal.intervals, 8192);
            assert_eq!(seal.exclusion, Some(learning::Error::Capacity));
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 303141, 0]);
            assert_eq!(bridge::copy_intervals(seal, 8191, &mut rows).unwrap(), 1);
            assert_eq!(
                (rows[0].start_ns, rows[0].end_ns),
                (OBS + 200_819_100, OBS + 200_819_137)
            );
            bridge::retire_exported(seal).unwrap();
            begin(7);
            domain_platform::at(END + 5_000_000_001);
            for source in sources() {
                bridge::close_source(bridge::source(source.owner, source.class).unwrap()).unwrap();
            }
            assert_eq!(
                bridge::seal(false),
                Err(bridge::Error::Capture(learning::Error::Deadline))
            );
            assert_eq!(
                bridge::seal(true).unwrap().exclusion,
                Some(learning::Error::Deadline)
            );
            assert_eq!(bridge::test_support::source_snapshot(), words);
            bridge::retire_exported(bridge::seal(true).unwrap()).unwrap();
            begin(8);
            cpu::at(3);
            domain_platform::at(OBS + 200_000_000);
            let mut copied_on_cpu3 = false;
            bridge::measure_paid_task(key(13), CpuClass::ExecutorWork, |entry| {
                if let Some(entry) = entry {
                    entry.observe(|| {
                        copied_on_cpu3 = true;
                        identity(2, 70)
                    });
                }
                domain_platform::at(OBS + 200_000_037);
            });
            assert!(!copied_on_cpu3, "non-CPU0 path copied TaskIdentity");
            assert_eq!(bridge::test_support::source_snapshot(), words);
            let seal = close_and_export(false);
            assert_eq!(seal.exclusion, None);
            assert_eq!(bridge::copy_intervals(seal, 0, &mut rows).unwrap(), 1);
            assert_eq!(rows[0].core, 3);
            bridge::retire_exported(seal).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
fn identity(site: u64, caller: u64) -> bridge::TaskIdentity {
    bridge::TaskIdentity {
        site,
        caller: ObjectKey {
            id: caller,
            generation: 8,
        },
        request: 9,
        child: ObjectKey {
            id: 4097,
            generation: 6,
        },
        recipe: 2,
    }
}
