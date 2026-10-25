//! Exercise the production pre-snapshot CPU custody bridge with real Capture.
//! CPU, clock, pool and task completion are explicit host fixtures, never
//! accepted learning labels or evidence of a native workload run.
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    learning::{
        self, Family,
        capture::{Capture, Config, FrozenRequest, RunKey, Source},
        reward::CpuClass,
    },
};
use std::sync::Mutex;

pub mod cpu {
    use super::*;
    static CPU: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize {
        CPU.load(Ordering::Acquire)
    }
    pub fn set(value: usize) {
        CPU.store(value, Ordering::Release);
    }
}
pub mod domain_platform {
    use super::*;
    static CLOCK: AtomicU64 = AtomicU64::new(10_000_000_000);
    pub fn now_ns() -> u64 {
        CLOCK.load(Ordering::Acquire)
    }
    pub fn at(value: u64) {
        CLOCK.store(value, Ordering::Release);
    }
}
pub mod domain_tasks {
    use super::*;
    use cyxia_prototype::domains::tasks::ControlCredit;
    static CONTROL: Mutex<Option<ControlCredit>> = Mutex::new(None);
    pub struct PaidServiceWitness {
        _private: (),
    }
    pub fn authorize_service_turn() -> Result<(), Error> {
        if cpu::slot() == 0 {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
    pub fn paid() -> PaidServiceWitness {
        authorize_service_turn().unwrap();
        PaidServiceWitness { _private: () }
    }
    pub fn verify_control_credit(credit: &ControlCredit) -> Result<(), Error> {
        if !matches!(cpu::slot(), 1 | 2) || usize::from(credit.cpu) != cpu::slot() {
            return Err(Error::Auth);
        }
        if *CONTROL.lock().unwrap() == Some(*credit) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    pub fn control(sequence: u64) -> ControlCredit {
        assert!(matches!(cpu::slot(), 1 | 2));
        let credit = ControlCredit {
            sequence,
            cpu: cpu::slot() as u16,
            core_generation: 1,
            window: 1,
            started_ns: domain_platform::now_ns(),
            reserved_ns: 1_000_000,
            control_total_ns: 1_000_000,
            physical_total_ns: 1_000_000,
        };
        let mut current = CONTROL.lock().unwrap();
        assert!(current.is_none());
        *current = Some(credit);
        credit
    }
    pub fn complete(credit: ControlCredit) {
        let mut current = CONTROL.lock().unwrap();
        assert_eq!(*current, Some(credit));
        *current = None;
    }
}
pub mod domain_control {
    pub mod replay {
        use super::super::*;
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct Preparation {
            pub id: u64,
            pub family: Family,
        }
        static CURRENT: Mutex<Option<Preparation>> = Mutex::new(None);
        static ARCHIVED: AtomicBool = AtomicBool::new(false);
        pub fn prepared(id: u64, family: Family) -> Preparation {
            let preparation = Preparation { id, family };
            *CURRENT.lock().unwrap() = Some(preparation);
            ARCHIVED.store(false, Ordering::Release);
            preparation
        }
        pub fn verify_preparation(p: Preparation) -> Result<(), Error> {
            if *CURRENT.lock().unwrap() == Some(p) {
                Ok(())
            } else {
                Err(Error::Stale)
            }
        }
        pub fn preparation_archived(p: Preparation) -> bool {
            verify_preparation(p).is_ok() && ARCHIVED.load(Ordering::Acquire)
        }
        pub fn archived(p: Preparation) {
            verify_preparation(p).unwrap();
            ARCHIVED.store(true, Ordering::Release);
        }
    }
    pub mod core_replay {
        use super::super::*;
        use cyxia_prototype::domains::tasks::ControlCredit;
        pub const CORE_OWNER: ObjectKey = ObjectKey {
            id: 3,
            generation: 7,
        };
        pub struct PaidWorkWitness {
            credit: ControlCredit,
        }
        impl PaidWorkWitness {
            pub fn new(credit: ControlCredit) -> Self {
                domain_tasks::verify_control_credit(&credit).unwrap();
                Self { credit }
            }
            pub fn core(&self) -> u16 {
                self.credit.cpu
            }
            pub fn credit(&self) -> &ControlCredit {
                &self.credit
            }
        }
    }
}
pub mod learning_workload {
    use super::*;
    pub const OWNER: ObjectKey = ObjectKey {
        id: 1,
        generation: 7,
    };
    pub const TASK_OWNER: ObjectKey = ObjectKey {
        id: 2,
        generation: 7,
    };
}
pub mod control_pool {
    use super::*;
    #[derive(Clone, Copy)]
    pub struct Allocation {
        base: usize,
        bytes: usize,
    }
    pub struct Lease;
    pub fn allocate(owner: ObjectKey, pages: usize) -> Result<Allocation, Error> {
        if cpu::slot() != 0 || owner.id == 0 || pages != 6 {
            return Err(Error::Auth);
        }
        let layout = std::alloc::Layout::from_size_align(pages * 4096, 4096).unwrap();
        let base = unsafe { std::alloc::alloc(layout) } as usize;
        if base == 0 {
            return Err(Error::Capacity);
        }
        Ok(Allocation {
            base,
            bytes: pages * 4096,
        })
    }
    pub fn pin(_: Allocation) -> Result<Lease, Error> {
        Ok(Lease)
    }
    pub fn span(a: Allocation) -> Result<(usize, u64, usize), Error> {
        Ok((a.base, a.base as u64, a.bytes))
    }
}
pub mod learning_evidence {
    use super::*;
    type Attest = fn(RunKey, ObjectKey, u64, u16, u64, u64) -> Result<(), learning::Error>;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        Busy,
        NotReady,
        Stale,
        Capacity,
        Owner,
    }
    static CHECKS: Mutex<Vec<(ObjectKey, Attest)>> = Mutex::new(Vec::new());
    pub static BUSY: AtomicBool = AtomicBool::new(false);
    pub static CAPTURE: Mutex<Capture<512, 100>> = Mutex::new(Capture::empty());
    pub static IMPORTED: Mutex<Vec<prewarm::RawRow>> = Mutex::new(Vec::new());
    pub fn register_recorded_core_owner(owner: ObjectKey, check: Attest) -> Result<(), Error> {
        let mut checks = CHECKS.lock().unwrap();
        if let Some((_, old)) = checks.iter().find(|(o, _)| *o == owner) {
            if !core::ptr::fn_addr_eq(*old, check) {
                return Err(Error::Owner);
            }
        } else {
            checks.push((owner, check));
        }
        Ok(())
    }
    pub fn attest(key: RunKey, row: prewarm::RawRow) -> Result<(), learning::Error> {
        let checks = CHECKS.lock().unwrap();
        let check = checks
            .iter()
            .find(|(o, _)| *o == row.owner)
            .ok_or(learning::Error::Evidence)?
            .1;
        check(
            key,
            row.owner,
            row.event,
            row.core,
            row.first_ns,
            row.last_ns,
        )
    }
    pub fn record_on_core(
        key: RunKey,
        owner: ObjectKey,
        class: CpuClass,
        event: u64,
        core: u16,
        first_ns: u64,
        last_ns: u64,
    ) -> Result<(), Error> {
        if BUSY.load(Ordering::Acquire) {
            return Err(Error::Busy);
        }
        attest(
            key,
            prewarm::RawRow {
                owner,
                core,
                event,
                first_ns,
                last_ns,
            },
        )
        .map_err(|_| Error::Owner)?;
        let mut capture = CAPTURE.lock().unwrap();
        if capture.config().is_none_or(|c| c.key != key) {
            return Err(Error::Stale);
        }
        let source = capture.source(owner, class).map_err(|_| Error::Owner)?;
        capture
            .record(source, core, first_ns, last_ns)
            .map_err(|_| Error::Owner)?;
        IMPORTED.lock().unwrap().push(prewarm::RawRow {
            owner,
            core,
            event,
            first_ns,
            last_ns,
        });
        Ok(())
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_prewarm.rs"]
mod prewarm;

#[test]
fn original_credits_survive_freeze_and_busy_import_and_lost_credit_cannot_close() {
    let family = Family {
        domain: 14,
        kind: 1,
    };
    let member = ObjectKey {
        id: 99,
        generation: 4,
    };
    let key = RunKey {
        boot_epoch: 7,
        trial_id: 1,
        generation: 1,
    };
    assert_eq!(prewarm::OWNED_BYTES, 24576);
    assert_eq!(prewarm::MAX_ROWS, 768);
    let preparation = domain_control::replay::prepared(1, family);
    prewarm::bind_preparation(preparation).unwrap();
    for _ in 0..5 {
        assert_eq!(prewarm::begin(family, member), Err(Error::Again));
    }
    prewarm::begin(family, member).unwrap();
    assert_eq!(
        prewarm::freeze(domain_platform::now_ns()),
        Err(Error::Again)
    );
    cpu::set(3);
    assert!(prewarm::attempt_service().is_none());
    assert!(
        prewarm::attempt_task(ObjectKey {
            generation: 5,
            ..member
        })
        .is_none()
    );
    assert_eq!(prewarm::completed(), Err(Error::Auth));
    cpu::set(0);
    for i in 0..13 {
        let at = 10_040_000_000 + i * 80_000_000;
        domain_platform::at(at);
        let mut service = if i % 2 == 0 {
            prewarm::attempt_service()
        } else {
            prewarm::attempt_paid_service(&domain_tasks::paid())
        }
        .unwrap();
        prewarm::finish(&mut service, at - 20_000, at - 10_000).unwrap();
        cpu::set(3);
        let mut task = prewarm::attempt_task(member).unwrap();
        prewarm::finish(&mut task, at - 9_000, at - 1_000).unwrap();
        cpu::set(0);
        prewarm::completed().unwrap();
    }
    domain_platform::at(11_010_000_000);
    cpu::set(3);
    let mut inflight = prewarm::attempt_task(member).unwrap();
    cpu::set(0);
    domain_platform::at(11_020_000_000);
    assert_eq!(prewarm::freeze(domain_platform::now_ns()), Err(Error::Busy));
    assert!(!prewarm::active());
    assert!(prewarm::attempt_service().is_none());
    assert_eq!(
        prewarm::finish(&mut inflight, 11_010_000_000, 11_020_000_000),
        Err(Error::Auth)
    );
    cpu::set(3);
    domain_platform::at(11_023_000_000);
    prewarm::finish(&mut inflight, 11_010_000_000, 11_023_000_000).unwrap();
    assert!(prewarm::attempt_task(member).is_none());
    cpu::set(0);
    domain_platform::at(11_024_000_000);
    let first = domain_platform::now_ns();
    prewarm::freeze(first).unwrap();
    prewarm::freeze(first).unwrap();
    assert_eq!(prewarm::freeze(first - 1), Err(Error::Stale));
    prewarm::activate(key, first).unwrap();
    prewarm::activate(key, first).unwrap();
    let sources = [
        Source {
            owner: learning_workload::OWNER,
            class: CpuClass::Policy,
            allowed_cores: 7,
        },
        Source {
            owner: learning_workload::OWNER,
            class: CpuClass::ExecutorAction,
            allowed_cores: 1,
        },
        Source {
            owner: learning_workload::OWNER,
            class: CpuClass::ExecutorWork,
            allowed_cores: 1,
        },
        Source {
            owner: learning_workload::TASK_OWNER,
            class: CpuClass::ExecutorWork,
            allowed_cores: 8,
        },
    ];
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: i as u64 + 1,
        owner: learning_workload::OWNER,
        arrived_ns: first + i as u64 * 1_000_000,
    });
    learning_evidence::CAPTURE
        .lock()
        .unwrap()
        .start(
            Config {
                key,
                family,
                node: [1; 32],
                first_ns: first,
                observation_ns: first,
                frozen_scope_hash: [2; 32],
            },
            &sources,
            &requests,
        )
        .unwrap();
    assert_eq!(prewarm::row_count(key).unwrap(), 27);
    let empty = prewarm::RawRow {
        owner: learning_workload::OWNER,
        core: 0,
        event: 0,
        first_ns: 0,
        last_ns: 0,
    };
    let mut original = [empty; 27];
    assert_eq!(prewarm::copy_rows(key, 0, &mut original[..16]).unwrap(), 16);
    assert_eq!(
        prewarm::copy_rows(key, 16, &mut original[16..]).unwrap(),
        11
    );
    assert_eq!(
        learning_evidence::attest(
            key,
            prewarm::RawRow {
                core: 3,
                ..original[0]
            }
        ),
        Err(learning::Error::Evidence)
    );
    assert_eq!(
        learning_evidence::attest(
            key,
            prewarm::RawRow {
                last_ns: original[0].last_ns + 1,
                ..original[0]
            }
        ),
        Err(learning::Error::Evidence)
    );
    learning_evidence::BUSY.store(true, Ordering::Release);
    assert_eq!(prewarm::poll(key), Err(Error::Busy));
    learning_evidence::attest(key, original[0]).unwrap();
    assert_eq!(prewarm::release(key), Err(Error::Busy));
    learning_evidence::BUSY.store(false, Ordering::Release);
    assert!(!prewarm::poll(key).unwrap());
    assert_eq!(learning_evidence::IMPORTED.lock().unwrap().len(), 8);
    while !prewarm::poll(key).unwrap() {}
    assert!(prewarm::drain(key).unwrap());
    {
        let capture = learning_evidence::CAPTURE.lock().unwrap();
        let mut ordered = original.to_vec();
        ordered.sort_by_key(|row| row.event);
        assert_eq!(*learning_evidence::IMPORTED.lock().unwrap(), ordered);
        let actual_ns = original.iter().map(|r| r.last_ns - r.first_ns).sum::<u64>();
        assert_eq!(capture.status().ordinary_warmup_ns, actual_ns);
        assert_eq!(
            capture.status().raw_tagged_ns[CpuClass::ExecutorWork as usize],
            actual_ns
        );
        assert_eq!(capture.status().fault, None);
        // Warm CPU is retained separately and cannot inflate observation CPU.
        assert!(capture.intervals().is_empty());
    }
    // Export is independent of the acknowledged import cursor.
    let mut after = [empty; 16];
    prewarm::copy_rows(key, 0, &mut after).unwrap();
    assert_eq!(after, original[..16]);
    prewarm::release(key).unwrap();
    assert_eq!(prewarm::poll(key), Err(Error::Stale));

    // CoreSet's original-state work comes from real control reservations,
    // with C1/C2 preserved; the CPU3 business path cannot substitute for it.
    domain_platform::at(12_000_000_000);
    let core_family = Family { domain: 1, kind: 2 };
    let core_owner = domain_control::core_replay::CORE_OWNER;
    let preparation = domain_control::replay::prepared(2, core_family);
    prewarm::bind_preparation(preparation).unwrap();
    assert_eq!(prewarm::begin(core_family, member), Err(Error::Auth));
    prewarm::begin(core_family, core_owner).unwrap();
    cpu::set(3);
    assert!(prewarm::attempt_task(core_owner).is_none());
    cpu::set(0);
    assert_eq!(prewarm::completed(), Err(Error::Auth));
    for i in 0..13 {
        let at = 12_040_000_000 + i * 80_000_000;
        domain_platform::at(at - 20_000);
        cpu::set(0);
        let mut queue = prewarm::attempt_service().unwrap();
        domain_platform::at(at - 10_000);
        prewarm::finish(&mut queue, at - 20_000, at - 10_000).unwrap();
        cpu::set(1 + i as usize % 2);
        domain_platform::at(at - 9_000);
        let credit = domain_tasks::control(i + 1);
        let witness = domain_control::core_replay::PaidWorkWitness::new(credit);
        let mut work = prewarm::attempt_control(&witness).unwrap();
        domain_platform::at(at);
        assert_eq!(
            prewarm::finish(&mut work, at - 10_000, at - 1_000),
            Err(Error::Auth)
        );
        prewarm::finish(&mut work, at - 9_000, at - 1_000).unwrap();
        prewarm::completed_control(&witness).unwrap();
        domain_tasks::complete(credit);
        assert_eq!(prewarm::completed_control(&witness), Err(Error::Stale));
    }
    // Preserve over 128 distinct paid slices on each control CPU without
    // charging the gaps between them or collapsing work across real waits.
    for core in [1, 2] {
        cpu::set(core);
        let base = 13_001_000_000 + core as u64 * 1_000_000;
        domain_platform::at(base);
        let credit = domain_tasks::control(100 + core as u64);
        let witness = domain_control::core_replay::PaidWorkWitness::new(credit);
        for piece in 0..200 {
            let first = base + piece * 2000;
            domain_platform::at(first);
            let mut work = prewarm::attempt_control(&witness).unwrap();
            domain_platform::at(first + 1000);
            prewarm::finish(&mut work, first, first + 1000).unwrap();
        }
        domain_tasks::complete(credit);
    }
    cpu::set(0);
    domain_platform::at(13_024_000_000);
    let first = domain_platform::now_ns();
    prewarm::freeze(first).unwrap();
    let key = RunKey { trial_id: 2, ..key };
    prewarm::activate(key, first).unwrap();
    let mut sources = sources.to_vec();
    sources.push(Source {
        owner: core_owner,
        class: CpuClass::ExecutorWork,
        allowed_cores: 6,
    });
    let requests = requests.map(|r| FrozenRequest {
        arrived_ns: first + r.id * 1_000_000,
        ..r
    });
    *learning_evidence::CAPTURE.lock().unwrap() = Capture::empty();
    learning_evidence::CAPTURE
        .lock()
        .unwrap()
        .start(
            Config {
                key,
                family: core_family,
                node: [1; 32],
                first_ns: first,
                observation_ns: first,
                frozen_scope_hash: [3; 32],
            },
            &sources,
            &requests,
        )
        .unwrap();
    learning_evidence::IMPORTED.lock().unwrap().clear();
    while !prewarm::poll(key).unwrap() {}
    let imported = learning_evidence::IMPORTED.lock().unwrap();
    assert_eq!(imported.len(), 426);
    assert!(imported.windows(2).all(|r| r[0].event < r[1].event));
    assert!(
        imported
            .iter()
            .any(|r| r.owner == core_owner && r.core == 1)
    );
    assert!(
        imported
            .iter()
            .any(|r| r.owner == core_owner && r.core == 2)
    );
    assert!(imported.iter().all(|r| r.core != 3));
    assert!(imported.iter().filter(|r| r.core == 1).count() > 128);
    assert!(imported.iter().filter(|r| r.core == 2).count() > 128);
    assert_eq!(
        learning_evidence::CAPTURE.lock().unwrap().status().fault,
        None
    );
    drop(imported);
    prewarm::release(key).unwrap();

    domain_platform::at(14_000_000_000);
    let preparation = domain_control::replay::prepared(
        3,
        Family {
            domain: 16,
            kind: 2,
        },
    );
    prewarm::bind_preparation(preparation).unwrap();
    prewarm::begin(
        Family {
            domain: 16,
            kind: 2,
        },
        member,
    )
    .unwrap();
    let unknown = prewarm::attempt_service().unwrap();
    drop(unknown);
    domain_platform::at(15_000_000_000);
    assert_eq!(
        prewarm::freeze(domain_platform::now_ns()),
        Err(Error::Capacity)
    );
    assert!(prewarm::active());
    // Losing a real credit cannot become zero CPU or a closable warmup.
    assert!(prewarm::freeze_abort(preparation).unwrap());
    let failure = prewarm::summary_prepared(preparation).unwrap().unwrap();
    assert!(failure.lost);
    assert_eq!(failure.completed, 0);
    assert_eq!(failure.rows, 0);
    assert_eq!(prewarm::copy_prepared(preparation, 0), Err(Error::Range));
    assert_eq!(prewarm::release_prepared(preparation), Err(Error::Busy));
    domain_control::replay::archived(preparation);
    prewarm::release_prepared(preparation).unwrap();

    // A pre-capture failure has no RunKey. It retains exact original rows and
    // cannot release a still-open real credit or omit durable failure export.
    domain_platform::at(16_000_000_000);
    let preparation = domain_control::replay::prepared(4, family);
    prewarm::bind_preparation(preparation).unwrap();
    prewarm::begin(family, member).unwrap();
    let mut inflight = prewarm::attempt_service().unwrap();
    assert!(!prewarm::freeze_abort(preparation).unwrap());
    assert_eq!(prewarm::summary_prepared(preparation), Err(Error::Busy));
    domain_platform::at(16_000_012_345);
    prewarm::finish(&mut inflight, 16_000_000_000, 16_000_012_345).unwrap();
    assert!(prewarm::freeze_abort(preparation).unwrap());
    let failure = prewarm::summary_prepared(preparation).unwrap().unwrap();
    assert_eq!(failure.rows, 1);
    assert!(!failure.lost);
    assert_eq!(failure.completed, 0);
    let raw = prewarm::copy_prepared(preparation, 0).unwrap();
    assert_eq!(
        (raw.core, raw.owner, raw.first_ns, raw.last_ns),
        (0, learning_workload::OWNER, 16_000_000_000, 16_000_012_345)
    );
    assert_eq!(prewarm::release_prepared(preparation), Err(Error::Busy));
    domain_control::replay::archived(preparation);
    prewarm::release_prepared(preparation).unwrap();
}
