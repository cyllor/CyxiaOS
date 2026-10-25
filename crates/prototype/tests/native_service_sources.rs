//! Real source-classification and collector code under the production
//! ReadSnapshot gate. CPU/time and actual service registration are host fixtures.
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    learning::{
        self, Family,
        capture::{FrozenRequest, RunKey, Source},
        reward::{CpuClass, OBSERVATION_NS},
    },
};

pub mod cpu {
    pub fn slot() -> usize {
        0
    }
}
pub mod domain_platform {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(0);
    pub fn now_ns() -> u64 {
        NOW.load(Ordering::Acquire)
    }
    pub fn at(now: u64) {
        NOW.store(now, Ordering::Release);
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_evidence.rs"]
mod bridge;
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_platform/read_snapshot.rs"]
mod read_snapshot;
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_services/replay_sources.rs"]
mod service_sources;

static READY: AtomicBool = AtomicBool::new(false);
mod replay {
    use super::*;
    pub static OWNED: AtomicBool = AtomicBool::new(false);
    pub fn owns(recipe: u16) -> bool {
        recipe == 2 && OWNED.load(Ordering::Acquire)
    }
}
#[derive(Clone, Copy)]
struct Service {
    key: ObjectKey,
    recipe: u16,
}
#[derive(Clone, Copy)]
struct ReadView {
    at: u64,
    console_key: ObjectKey,
    services: [Option<Service>; 2],
}
static READ_VIEW: read_snapshot::ReadSnapshot<ReadView> = read_snapshot::ReadSnapshot::new();
// This is the service's existing feature contract: real short publication
// gate plus the unchanged 50 ms freshness requirement. Source classification
// must no longer use it as evidence of an identity's existence.
fn read<R>(f: impl FnOnce(&ReadView) -> Result<R, Error>) -> Result<R, Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let view = READ_VIEW
        .read()
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?;
    let now = domain_platform::now_ns();
    if now < view.at || now - view.at >= 50_000_000 {
        return Err(Error::Busy);
    }
    f(&view)
}
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 7 }
}
const CONSOLE: ObjectKey = ObjectKey {
    id: 0x0900_0000,
    generation: 7,
};
static ALLOCATION: AtomicUsize = AtomicUsize::new(0);
static CLASSIFICATIONS: AtomicUsize = AtomicUsize::new(0);
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
    key: ObjectKey,
    class: CpuClass,
) -> Result<bridge::SourceDisposition, learning::Error> {
    CLASSIFICATIONS.fetch_add(1, Ordering::Relaxed);
    match service_sources::outside_source(key, class) {
        Ok(true) => Ok(bridge::SourceDisposition::Outside),
        Ok(false) => Err(learning::Error::DataIncomplete),
        Err(Error::Busy | Error::NotReady | Error::Again) => Err(learning::Error::Unknown),
        Err(_) => Err(learning::Error::Evidence),
    }
}
fn segment(key: ObjectKey, class: CpuClass, first: u64) -> Result<(), bridge::Error> {
    domain_platform::at(first + 37);
    let mut attempt = bridge::attempt(key, class).unwrap().unwrap();
    bridge::finish_attempt(&mut attempt, first, first + 37)
}

#[test]
fn actual_service_identity_survives_feature_gate_and_age_without_hiding_owned_or_unknown_work() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let registered = [Some((key(0x1002), 1)), Some((key(0x1003), 2))];
            let view = ReadView {
                at: 1_000_000_000,
                console_key: CONSOLE,
                services: registered.map(|s| s.map(|(key, recipe)| Service { key, recipe })),
            };
            READ_VIEW.publish(view).unwrap();
            service_sources::publish(CONSOLE, registered);
            READY.store(true, Ordering::Release);
            domain_platform::at(view.at);
            assert_eq!(read(|v| Ok(v.console_key)), Ok(CONSOLE));
            assert_eq!(
                read(|v| Ok(v.services.map(|s| s.map(|s| (s.key, s.recipe))))),
                Ok(registered)
            );
            assert_eq!(
                service_sources::outside_source(CONSOLE, CpuClass::ExecutorWork),
                Ok(true)
            );
            assert_eq!(service_sources::IDENTITY_BYTES, 72);

            let storage = Box::leak(Box::new(bridge::Storage::empty()));
            ALLOCATION.store(storage as *mut bridge::Storage as usize, Ordering::Release);
            bridge::install(storage, [1; 32], 7, key(44), pool_check)
                .map_err(|(e, _)| e)
                .unwrap();
            bridge::register_source_classifier(classify).unwrap();
            for (index, (domain, owns_console, unknown)) in
                [(1, false, false), (15, true, false), (1, false, true)]
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
                        owner: if owns_console { CONSOLE } else { key(12) },
                        class: CpuClass::ExecutorWork,
                        allowed_cores: 1,
                    },
                ];
                let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
                    id: i as u64 + 1,
                    owner: key(13),
                    arrived_ns: observation + (i as u64 + 1) * 1_000_000,
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
                let before = CLASSIFICATIONS.load(Ordering::Acquire);
                // The exact production gate is actually held. An identity lookup
                // cannot borrow this feature view; the real owner record is separate.
                let recorded = READ_VIEW
                    .inspect(|_| {
                        assert_eq!(read(|v| Ok(v.console_key)), Err(Error::Busy));
                        segment(CONSOLE, CpuClass::ExecutorWork, observation + 100)
                    })
                    .unwrap()
                    .unwrap();
                assert_eq!(recorded, Ok(()));
                assert_eq!(
                    CLASSIFICATIONS.load(Ordering::Acquire) - before,
                    usize::from(!owns_console)
                );
                // Removing contention does not make the old feature snapshot fresh.
                assert_eq!(read(|v| Ok(v.console_key)), Err(Error::Busy));
                segment(CONSOLE, CpuClass::ExecutorWork, observation + 200).unwrap();
                segment(key(0x1002), CpuClass::ExecutorAction, observation + 300).unwrap();
                if unknown {
                    for (key, class, offset) in [
                        (
                            ObjectKey {
                                generation: 8,
                                ..CONSOLE
                            },
                            CpuClass::ExecutorWork,
                            400,
                        ),
                        (
                            ObjectKey {
                                generation: 8,
                                ..key(0x1002)
                            },
                            CpuClass::ExecutorAction,
                            500,
                        ),
                        (CONSOLE, CpuClass::Policy, 600),
                    ] {
                        assert!(matches!(
                            segment(key, class, observation + offset),
                            Err(bridge::Error::Capture(_))
                        ));
                    }
                }
                let status = bridge::status().unwrap().0;
                assert_eq!(status.missing_events, if unknown { 3 } else { 0 });
                assert_eq!(status.intervals, if owns_console { 2 } else { 0 });
                assert_eq!(status.fault.is_some(), unknown);
                for request in requests {
                    domain_platform::at(domain_platform::now_ns().max(request.arrived_ns));
                    bridge::issued(bridge::request(request.owner, request.id).unwrap()).unwrap();
                }
                domain_platform::at(observation + OBSERVATION_NS + 1);
                for source in sources {
                    bridge::close_source(bridge::source(source.owner, source.class).unwrap())
                        .unwrap();
                }
                let seal = bridge::seal(unknown).unwrap();
                assert_eq!(seal.exclusion.is_some(), unknown);
                bridge::retire_exported(seal).unwrap();
            }

            // Generation changes and retirement come from the real owner publisher,
            // even if a concurrent feature reader prevents its separate view update.
            let next = ObjectKey {
                generation: 8,
                ..key(0x1002)
            };
            READ_VIEW
                .inspect(|_| {
                    service_sources::publish(CONSOLE, [Some((next, 1)), registered[1]]);
                    assert_eq!(
                        service_sources::outside_source(key(0x1002), CpuClass::ExecutorAction),
                        Ok(false)
                    );
                    assert_eq!(
                        service_sources::outside_source(next, CpuClass::ExecutorAction),
                        Ok(true)
                    );
                    service_sources::publish(CONSOLE, [None, registered[1]]);
                    assert_eq!(
                        service_sources::outside_source(next, CpuClass::ExecutorAction),
                        Ok(false)
                    );
                })
                .unwrap();
            replay::OWNED.store(true, Ordering::Release);
            assert_eq!(
                service_sources::outside_source(key(0x1003), CpuClass::ExecutorAction),
                Ok(false)
            );
            replay::OWNED.store(false, Ordering::Release);
            assert_eq!(
                service_sources::outside_source(key(0x1003), CpuClass::ExecutorAction),
                Ok(true)
            );
            assert_eq!(
                service_sources::outside_source(ObjectKey::default(), CpuClass::ExecutorWork),
                Ok(false)
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
