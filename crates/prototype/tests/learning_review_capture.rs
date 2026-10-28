//! Independent collector counterexamples using synthetic owner events only.
extern crate self as cyxia_arch_aarch64;
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_tasks/cancellation.rs"]
mod cancellation;
mod domain_tasks {
    pub(crate) use super::cancellation::Cancellation;
}

// The bridge itself is compiled unchanged. Only platform CPU/time providers
// are replaced for host contract tests; this does not claim native execution.
pub mod cpu {
    pub fn slot() -> usize {
        0
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
mod native_bridge;
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        Error, Family,
        capture::{Capture, Config, FrozenRequest, RunKey, Source},
        reward::{CpuClass, OBSERVATION_NS},
    },
};

const FIRST: u64 = 1_000_000_000;
const OBS: u64 = 3_000_000_000;
const END: u64 = OBS + OBSERVATION_NS;
fn owner(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn sources() -> [Source; 3] {
    [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
    ]
    .map(|class| Source {
        owner: owner(class as u64 + 1),
        class,
        allowed_cores: 1,
    })
}
fn requests() -> [FrozenRequest; 100] {
    core::array::from_fn(|i| FrozenRequest {
        id: i as u64 + 1,
        owner: owner(10),
        arrived_ns: OBS + i as u64 * 1_000_000,
    })
}
fn started() -> Capture<16, 100> {
    let mut capture = Capture::empty();
    capture
        .start(
            Config {
                key: RunKey {
                    boot_epoch: 1,
                    trial_id: 1,
                    generation: 1,
                },
                family: Family {
                    domain: 15,
                    kind: 1,
                },
                node: [1; 32],
                first_ns: FIRST,
                observation_ns: OBS,
                frozen_scope_hash: [7; 32],
            },
            &sources(),
            &requests(),
        )
        .unwrap();
    capture
}
fn issue_and_close(capture: &mut Capture<16, 100>) {
    for request in requests() {
        capture
            .issued(request.owner, request.id, request.arrived_ns)
            .unwrap();
    }
    for source in sources() {
        let token = capture.source(source.owner, source.class).unwrap();
        capture.close_source(token, END + 1_000).unwrap();
    }
}

#[test]
fn a_real_record_after_source_close_cannot_be_silently_lost_then_claim_complete() {
    let mut capture = started();
    let policy = capture.source(owner(1), CpuClass::Policy).unwrap();
    capture.close_source(policy, FIRST + 10).unwrap();
    assert!(capture.record(policy, 0, FIRST + 20, FIRST + 30).is_err());
    assert!(capture.status().fault.is_some());
    assert_eq!(capture.status().raw_tagged_ns[0], 10);
    issue_and_close(&mut capture);
    assert!(capture.seal(END + 2_000).is_err());
    let excluded = capture.seal_incomplete(END + 2_000).unwrap();
    assert!(excluded.exclusion.is_some());
    assert!(capture.coverage(excluded).is_err());
}

#[test]
fn a_real_slice_on_an_unapproved_cpu_is_retained_as_excluded_raw_cost() {
    let mut capture = started();
    let policy = capture.source(owner(1), CpuClass::Policy).unwrap();
    assert!(capture.record(policy, 1, FIRST + 20, FIRST + 45).is_err());
    assert!(capture.status().fault.is_some());
    assert_eq!(capture.status().raw_tagged_ns[0], 25);
    issue_and_close(&mut capture);
    assert!(capture.seal(END + 2_000).is_err());
    let excluded = capture.seal_incomplete(END + 2_000).unwrap();
    assert!(capture.coverage(excluded).is_err());
}

#[test]
fn foreign_instance_tokens_do_not_poison_the_current_run() {
    let first = started();
    let mut second = started();
    let foreign = first.source(owner(1), CpuClass::Policy).unwrap();
    assert_eq!(
        second.record(foreign, 0, FIRST, FIRST + 100),
        Err(Error::Stale)
    );
    assert_eq!(second.status().raw_tagged_ns, [0; 4]);
    assert_eq!(second.status().fault, None);
    issue_and_close(&mut second);
    let complete = second.seal(END + 2_000).unwrap();
    assert_eq!(complete.exclusion, None);
    assert!(second.coverage(complete).is_ok());
}

#[test]
fn a_late_taint_invalidates_the_old_seal_before_an_excluded_export() {
    let mut capture = started();
    issue_and_close(&mut capture);
    let original = capture.seal(END + 2_000).unwrap();
    capture.taint(Error::DataIncomplete);
    assert!(capture.coverage(original).is_err());
    let excluded = capture.seal_incomplete(END + 3_000).unwrap();
    assert_eq!(excluded.exclusion, Some(Error::DataIncomplete));
    assert_ne!(excluded.event_hash, original.event_hash);
    assert!(capture.retire_exported(original).is_err());
    assert_eq!(capture.sealed(), Some(excluded));
    capture.retire_exported(excluded).unwrap();
}

#[test]
fn native_bridge_drains_real_producer_leases_binds_request_runs_and_hashes_known_losses_once() {
    // Storage is large; this is a host test thread, not a native stack change.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use core::sync::atomic::{AtomicUsize, Ordering};
            use cyxia_prototype::learning::reward::{RequestResult, WorkRequest};
            use native_bridge as bridge;
            static ALLOCATION: AtomicUsize = AtomicUsize::new(0);
            fn pool_check(
                key: ObjectKey,
                address: usize,
                bytes: usize,
            ) -> Result<(), bridge::Error> {
                if key == owner(44)
                    && address == ALLOCATION.load(Ordering::Acquire)
                    && bytes == bridge::STORAGE_BYTES
                    && bytes <= 1024 * 1024
                {
                    Ok(())
                } else {
                    Err(bridge::Error::Owner)
                }
            }
            let loan = Box::leak(Box::new(bridge::Storage::empty()));
            ALLOCATION.store(loan as *mut bridge::Storage as usize, Ordering::Release);
            let loan = match bridge::install(loan, [1; 32], 7, owner(45), pool_check) {
                Err((error, returned)) => {
                    assert_eq!(error, bridge::Error::Owner);
                    returned
                }
                Ok(()) => panic!("unregistered allocation was accepted"),
            };
            bridge::install(loan, [1; 32], 7, owner(44), pool_check)
                .map_err(|(error, _)| error)
                .unwrap();
            domain_platform::at(FIRST);
            bridge::start(
                1,
                Family {
                    domain: 15,
                    kind: 1,
                },
                FIRST,
                OBS,
                [7; 32],
                &sources(),
                &requests(),
            )
            .unwrap();
            let tokens = sources().map(|s| bridge::source(s.owner, s.class).unwrap());
            let old_request = bridge::request(owner(10), 1).unwrap();
            assert_eq!(bridge::request(owner(11), 1), Err(bridge::Error::Owner));
            for request in requests() {
                domain_platform::at(request.arrived_ns);
                bridge::issued(bridge::request(request.owner, request.id).unwrap()).unwrap();
            }
            domain_platform::at(END + 1_000);
            bridge::test_support::with_producer(tokens[0], || {
                bridge::test_support::with_gate(|| {
                    assert_eq!(
                        bridge::record(tokens[0], FIRST, FIRST + 37),
                        Err(bridge::Error::Busy)
                    );
                });
                assert_eq!(bridge::seal(false), Err(bridge::Error::Busy));
            });
            assert!(bridge::begin(tokens[0]).unwrap().is_none());
            for token in tokens {
                bridge::close_source(token).unwrap();
            }
            assert_eq!(
                bridge::seal(false),
                Err(bridge::Error::Capture(Error::DataIncomplete))
            );
            let excluded = bridge::seal(true).unwrap();
            assert_eq!(excluded.exclusion, Some(Error::DataIncomplete));
            let (status, dropped, durations) = bridge::status().unwrap();
            assert_eq!(status.raw_tagged_ns, [37, 0, 0, 0]);
            assert_eq!(status.missing_events, 1);
            assert_eq!((dropped, durations), (1, [37, 0, 0, 0]));
            assert_eq!(status.sealed, Some(excluded));
            assert!(bridge::coverage(excluded).is_err());
            let empty = WorkRequest {
                id: 0,
                arrived_ns: 0,
                result: RequestResult::Pending,
            };
            let mut output = [(empty, None); 16];
            assert_eq!(bridge::copy_requests(excluded, 0, &mut output).unwrap(), 16);
            assert_eq!(output[0].1, Some(RequestResult::Pending));
            // A second read must not merge the same loss again or invalidate seal.
            assert_eq!(bridge::status().unwrap().0.sealed, Some(excluded));
            bridge::retire_exported(excluded).unwrap();

            let shift = 20_000_000_000;
            let second_requests = requests().map(|r| FrozenRequest {
                arrived_ns: r.arrived_ns + shift,
                ..r
            });
            domain_platform::at(FIRST + shift);
            bridge::start(
                2,
                Family {
                    domain: 15,
                    kind: 1,
                },
                FIRST + shift,
                OBS + shift,
                [7; 32],
                &sources(),
                &second_requests,
            )
            .unwrap();
            assert_eq!(
                bridge::result(old_request, RequestResult::Rejected),
                Err(bridge::Error::Stale)
            );
            assert_eq!(bridge::status().unwrap().0.fault, None);
            let current = bridge::request(owner(10), 1).unwrap();
            domain_platform::at(OBS + shift);
            bridge::issued(current).unwrap();
            assert_eq!(
                bridge::result(
                    current,
                    RequestResult::Completed {
                        finished_ns: OBS + shift + 1
                    }
                ),
                Err(bridge::Error::Capture(Error::Evidence))
            );
            for request in &second_requests[1..] {
                domain_platform::at(request.arrived_ns);
                bridge::issued(bridge::request(request.owner, request.id).unwrap()).unwrap();
            }
            domain_platform::at(END + shift + 1);
            let actual = RequestResult::Completed {
                finished_ns: END + shift + 1,
            };
            bridge::result(current, actual).unwrap();
            domain_platform::at(END + shift + 1_000);
            for source in sources() {
                bridge::close_source(bridge::source(source.owner, source.class).unwrap()).unwrap();
            }
            let second_seal = bridge::seal(true).unwrap();
            bridge::copy_requests(second_seal, 0, &mut output).unwrap();
            assert_eq!(output[0].0.result, RequestResult::Pending);
            assert_eq!(output[0].1, Some(actual));
            assert_eq!(bridge::status().unwrap().0.missing_events, 1);
            bridge::retire_exported(second_seal).unwrap();

            // Closing admission must still permit an already-open span to
            // deliver its real exit after seal initially reports UNKNOWN.
            let shift = 40_000_000_000;
            let third_requests = requests().map(|r| FrozenRequest {
                arrived_ns: r.arrived_ns + shift,
                ..r
            });
            domain_platform::at(FIRST + shift);
            bridge::start(
                3,
                Family {
                    domain: 15,
                    kind: 1,
                },
                FIRST + shift,
                OBS + shift,
                [7; 32],
                &sources(),
                &third_requests,
            )
            .unwrap();
            for request in third_requests {
                domain_platform::at(request.arrived_ns);
                bridge::issued(bridge::request(request.owner, request.id).unwrap()).unwrap();
            }
            let policy = bridge::source(owner(1), CpuClass::Policy).unwrap();
            domain_platform::at(END + shift - 100);
            let mut span = bridge::begin(policy).unwrap().unwrap();
            domain_platform::at(END + shift);
            assert_eq!(
                bridge::seal(false),
                Err(bridge::Error::Capture(Error::Unknown))
            );
            assert!(span.pending());
            domain_platform::at(END + shift + 100);
            bridge::end(&mut span).unwrap();
            assert!(!span.pending());
            domain_platform::at(END + shift + 1_000);
            for source in sources() {
                bridge::close_source(bridge::source(source.owner, source.class).unwrap()).unwrap();
            }
            let complete = bridge::seal(false).unwrap();
            assert_eq!(complete.exclusion, None);
            assert_eq!(bridge::status().unwrap().0.raw_tagged_ns, [200, 0, 0, 0]);
            assert!(bridge::coverage(complete).is_ok());
            bridge::retire_exported(complete).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
