//! Actual native collector ingress with host clocks. These are contention
//! counterexamples, not native samples or accepted learning evidence.
extern crate self as cyxia_arch_aarch64;

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
    use core::sync::atomic::{AtomicU64, Ordering};
    static CLOCK: AtomicU64 = AtomicU64::new(0);
    pub fn now_ns() -> u64 {
        CLOCK.load(Ordering::Acquire)
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
fn finished_native_segments_keep_original_custody_across_collector_contention() {
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
            assert_eq!(bridge::test_support::handoff_scans(), 0);

            // This is the actual fire-and-forget path used by synchronous native
            // owners: completion happens while another collector operation owns
            // its gate. The elapsed work cannot be reconstructed from a retry.
            domain_platform::at(OBS + 200_000_000);
            bridge::test_support::with_gate(|| {
                bridge::measure(key(13), CpuClass::ExecutorWork, || {
                    domain_platform::at(OBS + 200_000_037);
                });
            });
            // An unrelated owner has the same contention but is omitted only
            // after its exact identity is positively classified, never on Busy.
            domain_platform::at(OBS + 300_000_000);
            bridge::test_support::with_gate(|| {
                bridge::measure(key(100), CpuClass::ExecutorWork, || {
                    domain_platform::at(OBS + 300_000_071);
                });
            });
            // Import on another CPU preserves the completed token's original
            // core. No caller can submit a substitute core or a new interval.
            cpu::at(1);
            let seal = close_and_export(false);
            assert_eq!(seal.key, run);
            assert_eq!(seal.exclusion, None);
            let status = bridge::status().unwrap().0;
            assert_eq!(status.missing_events, 0);
            assert_eq!(status.raw_tagged_ns, [0, 0, 37, 0]);
            let mut rows = [CpuInterval {
                node: [0; 32],
                core: 0,
                start_ns: 0,
                end_ns: 0,
                class: CpuClass::Policy,
            }; 4];
            assert_eq!(bridge::copy_intervals(seal, 0, &mut rows).unwrap(), 1);
            assert_eq!(rows[0].core, 0);
            assert_eq!(
                (rows[0].start_ns, rows[0].end_ns),
                (OBS + 200_000_000, OBS + 200_000_037)
            );
            bridge::retire_exported(seal).unwrap();

            // Unknown classification is a retry, never an Outside verdict. The
            // original producer lease blocks both close and capture replacement.
            let run = begin(2);
            CLASSIFIER_BUSY.store(true, Ordering::Release);
            domain_platform::at(OBS + 200_000_000);
            bridge::measure(key(99), CpuClass::ExecutorWork, || {
                domain_platform::at(OBS + 200_000_037)
            });
            assert_eq!(bridge::test_support::handoff_status()[28], 1);
            assert_eq!(bridge::status().unwrap().0.missing_events, 0);
            domain_platform::at(END + 1000);
            let source = bridge::source(key(13), CpuClass::ExecutorWork).unwrap();
            assert_eq!(bridge::close_source(source), Err(bridge::Error::Busy));
            assert_eq!(bridge::seal(true), Err(bridge::Error::Busy));
            assert_eq!(
                bridge::start(
                    99,
                    Family { domain: 1, kind: 1 },
                    FIRST,
                    OBS,
                    [7; 32],
                    &sources(),
                    &[]
                ),
                Err(bridge::Error::Busy)
            );
            assert_eq!(bridge::current_config().unwrap().unwrap().key, run);
            CLASSIFIER_BUSY.store(false, Ordering::Release);
            cpu::at(1);
            let seal = close_and_export(false);
            assert_eq!(seal.exclusion, None);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 37, 0]);
            assert_eq!(bridge::test_support::handoff_status()[28], 0);
            bridge::retire_exported(seal).unwrap();

            // Retiring/reusing the child after its actual exit cannot erase a
            // precise source proof already obtained at that original exit.
            begin(3);
            domain_platform::at(OBS + 200_000_000);
            bridge::test_support::with_gate(|| {
                bridge::measure(key(99), CpuClass::ExecutorWork, || {
                    domain_platform::at(OBS + 200_000_037)
                });
            });
            CHILD_LIVE.store(false, Ordering::Release);
            cpu::at(1);
            let seal = close_and_export(false);
            assert_eq!(bridge::copy_intervals(seal, 0, &mut rows).unwrap(), 1);
            assert_eq!(rows[0].core, 0);
            assert_eq!(bridge::status().unwrap().0.missing_events, 0);
            bridge::retire_exported(seal).unwrap();

            // A caller retaining its own continuation also uses the exact tuple.
            // A changed time is rejected; it never becomes a second local row.
            begin(4);
            domain_platform::at(OBS + 200_000_000);
            let mut original = bridge::attempt(key(13), CpuClass::ExecutorWork)
                .unwrap()
                .unwrap();
            domain_platform::at(OBS + 200_000_037);
            bridge::test_support::with_gate(|| {
                assert_eq!(
                    bridge::finish_attempt(&mut original, OBS + 200_000_000, OBS + 200_000_037),
                    Err(bridge::Error::Busy)
                );
            });
            cpu::at(1);
            assert_eq!(
                bridge::finish_attempt(&mut original, OBS + 200_000_001, OBS + 200_000_037),
                Err(bridge::Error::Stale)
            );
            bridge::finish_attempt(&mut original, OBS + 200_000_000, OBS + 200_000_037).unwrap();
            assert_eq!(
                bridge::finish_attempt(&mut original, OBS + 200_000_000, OBS + 200_000_037),
                Err(bridge::Error::Stale)
            );
            drop(original);
            let seal = close_and_export(false);
            assert_eq!(bridge::copy_intervals(seal, 0, &mut rows).unwrap(), 1);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 37, 0]);
            bridge::retire_exported(seal).unwrap();

            // Wrong-core or future-time FIRST completion cannot acquire trusted
            // handoff custody by moving CPUs or waiting until the clock catches up.
            begin(5);
            domain_platform::at(OBS + 200_000_000);
            let mut invalid = bridge::attempt(key(13), CpuClass::ExecutorWork)
                .unwrap()
                .unwrap();
            domain_platform::at(OBS + 200_000_037);
            cpu::at(1);
            assert_eq!(
                bridge::finish_attempt(&mut invalid, OBS + 200_000_000, OBS + 200_000_037),
                Err(bridge::Error::Owner)
            );
            cpu::at(0);
            assert_eq!(
                bridge::finish_attempt(&mut invalid, OBS + 200_000_000, OBS + 200_000_037),
                Err(bridge::Error::Owner)
            );
            drop(invalid);
            let mut future = bridge::attempt(key(13), CpuClass::ExecutorWork)
                .unwrap()
                .unwrap();
            assert_eq!(
                bridge::finish_attempt(&mut future, OBS + 300_000_000, OBS + 300_000_037),
                Err(bridge::Error::Owner)
            );
            domain_platform::at(OBS + 300_000_037);
            assert_eq!(
                bridge::finish_attempt(&mut future, OBS + 300_000_000, OBS + 300_000_037),
                Err(bridge::Error::Owner)
            );
            drop(future);
            assert_eq!(bridge::test_support::handoff_status()[28], 0);
            let seal = close_and_export(true);
            assert_eq!(seal.exclusion, Some(learning::Error::DataIncomplete));
            assert_eq!(bridge::status().unwrap().0.missing_events, 2);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 74, 0]);
            let first_loss = bridge::test_support::handoff_status();
            assert_eq!(first_loss[0], 2);
            assert_eq!(first_loss[8], 5); // InvalidCompletion, not known Outside.
            assert_eq!((first_loss[4], first_loss[5], first_loss[7]), (13, 1, 0));
            assert_eq!(first_loss[13], 0); // Original completion never validated.
            bridge::retire_exported(seal).unwrap();

            // The bank is bounded. Sixteen original exits remain live; the next
            // is a real, exactly-once loss with raw duration, never an overwrite.
            begin(6);
            let full_before = bridge::test_support::handoff_status()[24];
            bridge::test_support::with_gate(|| {
                for index in 0..17 {
                    let first = OBS + 200_000_000 + index * 100;
                    domain_platform::at(first);
                    bridge::measure(key(13), CpuClass::ExecutorWork, || {
                        domain_platform::at(first + 37)
                    });
                }
            });
            assert_eq!(bridge::test_support::handoff_status()[28], 16);
            assert_eq!(bridge::test_support::handoff_status()[24], full_before + 1);
            assert_eq!(bridge::status().unwrap().0.missing_events, 1);
            cpu::at(1);
            let seal = close_and_export(true);
            assert_eq!(seal.intervals, 16);
            assert_eq!(
                bridge::status().unwrap().0.raw_tagged_ns,
                [0, 0, 17 * 37, 0]
            );
            assert_eq!(bridge::test_support::handoff_status()[28], 0);
            assert_eq!(bridge::status().unwrap().0.missing_events, 1);
            bridge::retire_exported(seal).unwrap();

            // A permanently unknown identity remains missing, including after a
            // temporary collector refusal. No id-only fallback was introduced.
            begin(7);
            domain_platform::at(OBS + 200_000_000);
            bridge::test_support::with_gate(|| {
                bridge::measure(key(777), CpuClass::ExecutorWork, || {
                    domain_platform::at(OBS + 200_000_037)
                });
            });
            let seal = close_and_export(true);
            assert_eq!(seal.exclusion, Some(learning::Error::DataIncomplete));
            assert_eq!(bridge::status().unwrap().0.missing_events, 1);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 37, 0]);
            assert_eq!(bridge::test_support::handoff_status()[28], 0);
            bridge::retire_exported(seal).unwrap();

            // Peer refusal occurs BEFORE the local collector lookup. The
            // original child identity must be retained at that same exit as
            // well; an eventual collector retry cannot resurrect a retired
            // generation. The peer ledger itself has separate real-gate tests.
            begin(8);
            CHILD_LIVE.store(true, Ordering::Release);
            bridge::test_support::set_peer_busy(true);
            domain_platform::at(OBS + 200_000_000);
            bridge::measure(key(99), CpuClass::ExecutorWork, || {
                domain_platform::at(OBS + 200_000_037);
            });
            assert_eq!(bridge::test_support::handoff_status()[28], 1);
            CHILD_LIVE.store(false, Ordering::Release);
            bridge::test_support::set_peer_busy(false);
            cpu::at(1);
            let seal = close_and_export(false);
            assert_eq!(seal.exclusion, None);
            assert_eq!(bridge::copy_intervals(seal, 0, &mut rows).unwrap(), 1);
            assert_eq!(rows[0].core, 0);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [0, 0, 37, 0]);
            assert_eq!(bridge::test_support::handoff_status()[28], 0);
            bridge::retire_exported(seal).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
