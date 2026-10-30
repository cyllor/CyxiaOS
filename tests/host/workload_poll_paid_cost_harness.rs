//! Actual ordinary poll/helper/collector and Scheduler, with controlled clocks.
//! The reused collector fixture owns installation, roster and frozen requests.
//! Hardware, unused workload dependencies and credit admission are facades;
//! sample finishers, real queue scan, observer and Scheduler debit stay actual.
// COLLECTOR_FIXTURE

const WORK_OWNER: ObjectKey = ObjectKey {
    id: 0x5245_504c_4159,
    generation: 1,
};
fn advance(ns: u64) {
    domain_platform::at(domain_platform::now_ns() + ns);
}
fn dependency_cost(ns: u64) {
    if std::env::var("CYXIA_POLL_CASE").as_deref() == Ok("dependencies") {
        advance(ns);
    }
}
mod learning_prewarm {
    pub fn poll(_: crate::RunKey) -> Result<bool, cyxia_prototype::domains::Error> {
        panic!("one-shot dependency must not run for ordinary family1")
    }
}
mod workload {
    use super::*;
    use crate::bridge as evidence;
    use cyxia_prototype::domains::Error;
    use std::sync::Mutex;
    const OWNER: ObjectKey = WORK_OWNER;
    const REQUESTS: usize = 100;
    const REQUEST_DEADLINE_NS: u64 = 50_000_000;
    // ACTUAL_QUEUE_TYPES
    #[derive(Clone, Copy)]
    struct Scope {
        family: Family,
        observation_ns: u64,
    }
    struct Background;
    struct OptionalEcho;
    impl Background {
        fn settled(&self) -> bool {
            true
        }
        fn poll(&mut self, _: u64, _: u64, _: u64, _: &mut OptionalEcho) -> Result<(), Error> {
            panic!("optional dependency must not run for ordinary family1")
        }
    }
    struct State {
        family: Option<Family>,
        run: Option<RunKey>,
        activated: bool,
        scope: Option<Scope>,
        requests: [Request; REQUESTS],
        cursor: usize,
        seed: u64,
        fault: Option<Error>,
        warm: Option<()>,
        background: Background,
    }
    static STATE: Mutex<State> = Mutex::new(State {
        family: None,
        run: None,
        activated: false,
        scope: None,
        requests: [EMPTY; REQUESTS],
        cursor: 0,
        seed: 19,
        fault: None,
        warm: None,
        background: Background,
    });
    fn with<R>(f: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
        dependency_cost(2);
        f(&mut *STATE.try_lock().map_err(|_| Error::Busy)?)
    }
    // ACTUAL_OWNER_CHECK
    fn now() -> u64 {
        domain_platform::now_ns()
    }
    fn one_shot(_: Family) -> bool {
        false
    }
    fn uses_file(_: Family) -> bool {
        false
    }
    fn poll_native(_: RunKey, _: u64, _: bridge::Error) -> Error {
        Error::NotReady
    }
    fn transient(e: Error) -> bool {
        matches!(
            e,
            Error::Busy | Error::Again | Error::NotReady | Error::Budget | Error::Capacity
        )
    }
    // Controlled body37 is charged inside the actual queue scan. No fake
    // sample or fake observer records that cost on behalf of production.
    fn warm(_: &mut State, _: Family, _: u64, _: u64) -> Result<(), Error> {
        advance(37);
        Ok(())
    }
    fn submit(_: Family, _: u64, _: u64, _: u64, _: u64) -> Result<(), Error> {
        panic!("future arrival must remain queued")
    }
    fn outcome(_: Family, _: u64) -> Result<Option<Result<u64, Error>>, Error> {
        panic!("future queued requests have no active outcome")
    }
    // ACTUAL_POLL
    pub fn configure(run: RunKey) {
        let mut s = STATE.lock().unwrap();
        s.family = Some(Family { domain: 1, kind: 1 });
        s.run = Some(run);
        s.activated = true;
        // The first ten requests already settled; the remaining ninety are
        // armed future arrivals under the actual capture observation time.
        // This ordinary poll has no new work, completion or result.
        s.scope = Some(Scope {
            family: s.family.unwrap(),
            observation_ns: OBS,
        });
        s.requests = [Request {
            armed: true,
            ..EMPTY
        }; REQUESTS];
        for row in &mut s.requests[..10] {
            *row = Request {
                phase: Phase::Settled,
                outcome: RequestResult::Completed {
                    finished_ns: OBS + 100,
                },
                reported: true,
                armed: true,
            };
        }
    }
    pub fn run(run: RunKey) {
        assert_eq!(
            billing::service_segment(|| poll(run)),
            Some(Ok(false)),
            "ordinary poll result changed"
        );
        let s = STATE.lock().unwrap();
        assert!(
            s.requests[10..].iter().all(|r| r.phase == Phase::Queued
                && r.armed
                && !r.reported
                && r.outcome == RequestResult::Pending),
            "ordinary poll changed future request custody"
        );
        assert!(
            s.requests[..10].iter().all(|r| r.phase == Phase::Settled
                && r.armed
                && r.reported
                && r.outcome
                    == RequestResult::Completed {
                        finished_ns: OBS + 100
                    }),
            "ordinary poll changed settled request custody"
        );
        assert_eq!(s.cursor, 0);
    }
}
mod billing {
    use crate::timer;
    use cyxia_prototype::domains::{
        Error,
        tasks::{CpuLayout, Dispatch, RunState, Scheduler, ThreadSpec},
    };
    static DEBIT: std::sync::Mutex<Option<(Scheduler, Dispatch)>> = std::sync::Mutex::new(None);
    static ACTUAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn now_ns() -> u64 {
        crate::domain_platform::now_ns()
    }
    fn begin_service_segment() -> Option<Dispatch> {
        let mut held = DEBIT.lock().unwrap();
        assert!(held.is_none());
        let mut s = Scheduler::new();
        let group = crate::key(999);
        s.register_group(group).unwrap();
        let layout = CpuLayout {
            business_mask: 1,
            healthy_mask: 15,
            generation: 1,
        };
        s.admit(
            ThreadSpec {
                key: crate::WORK_OWNER,
                group,
                cpu: 0,
                allowed_mask: 1,
                minimum_ns: 0,
                budget_ns: 10_000_000,
            },
            layout,
            now_ns(),
        )
        .unwrap();
        let d = s
            .dispatch_with_window_headroom(0, layout, now_ns(), 2_500_000, 20_000_000)
            .unwrap()
            .unwrap();
        *held = Some((s, d));
        Some(d)
    }
    fn revalidate_service_segment() -> bool {
        DEBIT.lock().unwrap().is_some()
    }
    fn complete_service(actual: u64, finished: u64) -> Result<(), Error> {
        let (mut s, d) = DEBIT.lock().unwrap().take().unwrap();
        let result = s.complete(d, actual, RunState::Runnable, finished);
        ACTUAL.fetch_add(s.stats().actual_ns, std::sync::atomic::Ordering::AcqRel);
        result
    }
    // ACTUAL_SERVICE_SAMPLES
    pub fn actual() -> u64 {
        ACTUAL.load(std::sync::atomic::Ordering::Acquire)
    }
}
#[test]
fn ordinary_poll_observation_is_inside_original_capture_and_actual_debit() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let storage = Box::leak(Box::new(bridge::Storage::empty()));
            ALLOCATION.store(storage as *mut bridge::Storage as usize, Ordering::Release);
            bridge::install(storage, [1; 32], 7, key(44), pool_check)
                .map_err(|(e, _)| e)
                .unwrap();
            bridge::register_source_classifier(classify).unwrap();
            let case = std::env::var("CYXIA_POLL_CASE").unwrap();
            if case == "noattempt" {
                let run = RunKey {
                    boot_epoch: 7,
                    trial_id: 1,
                    generation: 1,
                };
                workload::configure(run);
                domain_platform::at(OBS + 200_000_000);
                workload::run(run);
                assert_eq!(
                    bridge::test_support::source_snapshot(),
                    [0; 128],
                    "no-attempt poll published observation"
                );
                assert_eq!(billing::actual(), 37);
                return;
            }
            let run = begin(1);
            workload::configure(run);
            domain_platform::at(OBS + 200_000_000);
            if case == "invalidsite" {
                for site in [1, 6, 7] {
                    bridge::measure_paid_task(WORK_OWNER, CpuClass::ExecutorWork, |entry| {
                        entry.unwrap().observe(|| bridge::TaskIdentity {
                            site,
                            caller: key(70),
                            request: 9,
                            child: key(4097),
                            recipe: 0,
                        });
                    });
                    assert_eq!(
                        bridge::test_support::source_snapshot(),
                        [0; 128],
                        "invalid paid site or fabricated poll identity reached bank"
                    );
                }
                return;
            }
            if case == "noncpu0" {
                cpu::at(3);
                assert_eq!(
                    workload::poll(run),
                    Err(cyxia_prototype::domains::Error::Auth)
                );
                // Exercise absent paid context independently: real poll rejects CPU3.
                bridge::measure_paid_task(WORK_OWNER, CpuClass::ExecutorWork, |entry| {
                    assert!(entry.is_none(), "CPU3 received paid CPU0 context");
                    advance(37);
                });
                assert_eq!(bridge::test_support::source_snapshot(), [0; 128]);
                return;
            }
            if case == "contended" {
                bridge::test_support::with_gate(|| workload::run(run));
                assert_eq!(
                    bridge::test_support::source_snapshot(),
                    [0; 128],
                    "contended poll published observation"
                );
                assert_eq!(billing::actual(), 37);
                return;
            }
            workload::run(run);
            let words = bridge::test_support::source_snapshot();
            assert_eq!(
                &words[..2],
                &[0x4359535243450001, 2],
                "ordinary poll missing paid observation"
            );
            assert_eq!(&words[3..6], &[7, 1, 1], "ordinary poll lost full RunKey");
            assert_eq!(&words[6..12], &[1, 1, 0, 1, 0, 1]);
            assert_eq!(
                &words[16..24],
                &[0x5245504c4159, 1, 0x5245504c4159, 1, 2, 0, 6, 1]
            );
            assert_eq!(
                &words[26..34],
                &[1, 0, 0, 0, 0, 0, 0, 0],
                "ordinary poll fabricated task identity"
            );
            if case == "gap" {
                advance(63);
                workload::run(run);
                assert_eq!(
                    &bridge::test_support::source_snapshot()[6..12],
                    &[2, 2, 0, 2, 0, 1]
                );
            }
            let debit = match case.as_str() {
                "gap" => 108,
                "dependencies" => 79,
                _ => 54,
            };
            // Dependency case: owner3 + five queue-gate costs2 + within_work5+7
            // + body37 + recorder17 =79 ledger; inner is2+5+7+37+17 =68.
            assert_eq!(
                billing::actual(),
                debit,
                "recorder17ns escaped actual submitted Scheduler debit"
            );
            assert_eq!(
                domain_platform::now_ns(),
                OBS + 200_000_000 + debit + if case == "gap" { 63 } else { 0 }
            );
            let seal = close_and_export(false);
            assert_eq!(seal.exclusion, None);
            let mut rows = [CpuInterval {
                node: [0; 32],
                core: 0,
                start_ns: 0,
                end_ns: 0,
                class: CpuClass::Policy,
            }; 2];
            assert_eq!(
                bridge::copy_intervals(seal, 0, &mut rows).unwrap(),
                if case == "gap" { 2 } else { 1 }
            );
            let (offset, duration) = if case == "dependencies" {
                (7, 68)
            } else {
                (0, 54)
            };
            assert_eq!(
                (rows[0].start_ns, rows[0].end_ns),
                (
                    OBS + 200_000_000 + offset,
                    OBS + 200_000_000 + offset + duration
                ),
                "recorder17ns escaped original physical poll interval"
            );
            if case == "gap" {
                assert_eq!(
                    (rows[1].start_ns, rows[1].end_ns),
                    (OBS + 200_000_117, OBS + 200_000_171),
                    "original63ns poll gap was filled"
                );
            }
            let words = bridge::test_support::source_snapshot();
            assert_eq!(
                words[24],
                OBS + 200_000_000 + offset,
                "poll observation lost original first PMCC start"
            );
            assert_eq!(
                words[25],
                OBS + 200_000_000 + if case == "gap" { 117 } else { offset },
                "poll observation lost original latest PMCC start"
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
