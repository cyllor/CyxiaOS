//! Production platform classification through the actual native collector.
//! Host clocks and the IRQ registry are fixtures, not native replay evidence.
extern crate self as cyxia_arch_aarch64;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        self, Family,
        capture::{FrozenRequest, RunKey, Source},
        reward::{CpuClass, CpuInterval, OBSERVATION_NS},
    },
};

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
const IRQ_SLOTS: usize = 2;
const IRQ: ObjectKey = ObjectKey {
    id: 48,
    generation: 1,
};
const TIMER_SERVICE: ObjectKey = ObjectKey {
    id: 0x5449_4d45,
    generation: 1,
};
static READY: AtomicBool = AtomicBool::new(false);
fn registered_irq(index: usize) -> Option<(ObjectKey, u32, u64)> {
    (index == 0).then_some((IRQ, 2, 0x0a00_0000))
}
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_evidence.rs"]
mod bridge;
#[path = "../../../kernel/src/domain_platform/replay_sources.rs"]
mod platform_sources;

static ALLOCATION: AtomicUsize = AtomicUsize::new(0);
static CLASSIFICATIONS: AtomicUsize = AtomicUsize::new(0);
fn key(id: u64) -> ObjectKey {
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
    class: CpuClass,
) -> Result<bridge::SourceDisposition, learning::Error> {
    CLASSIFICATIONS.fetch_add(1, Ordering::Relaxed);
    if platform_sources::outside_source(owner, class) {
        Ok(bridge::SourceDisposition::Outside)
    } else {
        Err(learning::Error::DataIncomplete)
    }
}
fn segment(owner: ObjectKey, class: CpuClass, first: u64) -> Result<(), bridge::Error> {
    domain_platform::at(first + 37);
    let mut attempt = bridge::attempt(owner, class).unwrap().unwrap();
    bridge::finish_attempt(&mut attempt, first, first + 37)
}

#[test]
fn registered_irq_is_outside_only_when_absent_from_the_frozen_roster() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            assert!(!platform_sources::outside_source(
                IRQ,
                CpuClass::ExecutorWork
            ));
            READY.store(true, Ordering::Release);
            assert!(platform_sources::outside_source(
                IRQ,
                CpuClass::ExecutorWork
            ));
            assert!(!platform_sources::outside_source(
                key(49),
                CpuClass::ExecutorWork
            ));
            assert!(!platform_sources::outside_source(
                ObjectKey {
                    generation: 2,
                    ..IRQ
                },
                CpuClass::ExecutorWork
            ));

            let storage = Box::leak(Box::new(bridge::Storage::empty()));
            ALLOCATION.store(storage as *mut bridge::Storage as usize, Ordering::Release);
            bridge::install(storage, [1; 32], 7, key(44), pool_check)
                .map_err(|(error, _)| error)
                .unwrap();
            bridge::register_source_classifier(classify).unwrap();

            // D01 has unrelated platform IRQs; D04/D06 explicitly own the
            // same IRQ. The last case checks unknown identity and class.
            for (index, (domain, owns_irq, unknown)) in [
                (1, false, false),
                (4, true, false),
                (6, true, false),
                (1, false, true),
            ]
            .into_iter()
            .enumerate()
            {
                let first = 1_000_000_000 + index as u64 * 20_000_000_000;
                let observation = first + 1_000_000_000;
                let sources = [
                    Source {
                        owner: key(10),
                        class: CpuClass::Policy,
                        allowed_cores: 1,
                    },
                    Source {
                        owner: key(11),
                        class: CpuClass::ExecutorAction,
                        allowed_cores: 1,
                    },
                    Source {
                        owner: if owns_irq { IRQ } else { key(12) },
                        class: CpuClass::ExecutorWork,
                        allowed_cores: 1,
                    },
                ];
                let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
                    id: i as u64 + 1,
                    owner: key(13),
                    arrived_ns: observation + i as u64 * 1_000_000,
                });
                domain_platform::at(first);
                bridge::start(
                    index as u64 + 1,
                    Family { domain, kind: 1 },
                    first,
                    observation,
                    [2; 32],
                    &sources,
                    &requests,
                )
                .unwrap();
                let before = CLASSIFICATIONS.load(Ordering::Relaxed);
                segment(IRQ, CpuClass::ExecutorWork, observation + 100).unwrap();
                assert_eq!(
                    CLASSIFICATIONS.load(Ordering::Relaxed) - before,
                    usize::from(!owns_irq)
                );

                // The existing owner-action and soft-timer exceptions remain
                // limited to those exact identities and CPU classes.
                segment(IRQ, CpuClass::ExecutorAction, observation + 200).unwrap();
                segment(TIMER_SERVICE, CpuClass::ExecutorWork, observation + 300).unwrap();
                if unknown {
                    for (owner, class, offset) in [
                        (key(49), CpuClass::ExecutorWork, 400),
                        (
                            ObjectKey {
                                generation: 2,
                                ..IRQ
                            },
                            CpuClass::ExecutorWork,
                            500,
                        ),
                        (IRQ, CpuClass::Policy, 600),
                    ] {
                        assert!(matches!(
                            segment(owner, class, observation + offset),
                            Err(bridge::Error::Capture(_))
                        ));
                    }
                }
                let status = bridge::status().unwrap().0;
                assert_eq!(status.missing_events, if unknown { 3 } else { 0 });
                assert_eq!(status.intervals, usize::from(owns_irq));
                assert_eq!(
                    status.raw_tagged_ns,
                    if unknown {
                        [37, 0, 74, 0]
                    } else if owns_irq {
                        [0, 0, 37, 0]
                    } else {
                        [0; 4]
                    }
                );
                assert_eq!(status.fault.is_some(), unknown);

                for request in requests {
                    domain_platform::at(request.arrived_ns);
                    bridge::issued(bridge::request(request.owner, request.id).unwrap()).unwrap();
                }
                domain_platform::at(observation + OBSERVATION_NS + 1);
                for source in sources {
                    bridge::close_source(bridge::source(source.owner, source.class).unwrap())
                        .unwrap();
                }
                let seal = bridge::seal(unknown).unwrap();
                assert_eq!(seal.exclusion.is_some(), unknown);
                let mut rows = [CpuInterval {
                    node: [0; 32],
                    core: 0,
                    start_ns: 0,
                    end_ns: 0,
                    class: CpuClass::ExecutorWork,
                }; 1];
                assert_eq!(
                    bridge::copy_intervals(seal, 0, &mut rows).unwrap(),
                    usize::from(owns_irq)
                );
                if owns_irq {
                    assert_eq!(rows[0].class, CpuClass::ExecutorWork);
                    assert_eq!(
                        (rows[0].core, rows[0].start_ns, rows[0].end_ns),
                        (0, observation + 100, observation + 137)
                    );
                }
                assert_eq!(bridge::coverage(seal).is_ok(), !unknown);
                bridge::retire_exported(seal).unwrap();
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
