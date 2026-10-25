//! Execute the production hard-IRQ custody ring against the real Capture.
//! Explicit host IRQ/clock fixtures are not exported as native replay data.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    learning::{
        self, Family,
        capture::{Capture, Config, FrozenRequest, RunKey, Source},
        reward::CpuClass,
    },
};
use std::sync::Mutex;
const IRQ_SLOTS: usize = 1;
const IRQ: ObjectKey = ObjectKey {
    id: 48,
    generation: 1,
};
const RUN: RunKey = RunKey {
    boot_epoch: 7,
    trial_id: 1,
    generation: 1,
};
static INFLIGHT: [AtomicU64; 1] = [AtomicU64::new(0)];
fn owner() {}
fn slot(irq: u32) -> Result<usize, Error> {
    if irq == 48 { Ok(0) } else { Err(Error::Stale) }
}
fn registered_irq(index: usize) -> Option<(ObjectKey, u16, u16)> {
    (index == 0).then_some((IRQ, 2, 0))
}
mod timer {
    pub fn frequency() -> u64 {
        1_000
    }
}

mod learning_evidence {
    use super::*;
    type Attest = fn(RunKey, ObjectKey, u64, u16, u64, u64) -> Result<(), learning::Error>;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        Busy,
        Evidence,
    }
    static CHECK: Mutex<Option<Attest>> = Mutex::new(None);
    pub static BUSY: AtomicBool = AtomicBool::new(false);
    pub static CAPTURE: Mutex<Capture<512, 100>> = Mutex::new(Capture::empty());
    pub fn register_recorded_core_owner(owner: ObjectKey, check: Attest) -> Result<(), Error> {
        if owner != IRQ {
            return Err(Error::Evidence);
        }
        *CHECK.lock().unwrap() = Some(check);
        Ok(())
    }
    pub fn attest(
        run: RunKey,
        owner: ObjectKey,
        id: u64,
        core: u16,
        first: u64,
        last: u64,
    ) -> Result<(), learning::Error> {
        CHECK.lock().unwrap().ok_or(learning::Error::State)?(run, owner, id, core, first, last)
    }
    pub fn record_on_core(
        run: RunKey,
        owner: ObjectKey,
        class: CpuClass,
        id: u64,
        core: u16,
        first: u64,
        last: u64,
    ) -> Result<(), Error> {
        if BUSY.load(Ordering::Acquire) {
            return Err(Error::Busy);
        }
        attest(run, owner, id, core, first, last).map_err(|_| Error::Evidence)?;
        let mut capture = CAPTURE.lock().unwrap();
        if capture.config().is_none_or(|c| c.key != run) {
            return Err(Error::Evidence);
        }
        let source = capture.source(owner, class).map_err(|_| Error::Evidence)?;
        capture
            .record(source, core, first, last)
            .map_err(|_| Error::Evidence)
    }
}
#[path = "../../../kernel/src/domain_platform/irq_replay.rs"]
mod irq_replay;

#[test]
fn actual_irq_core_and_ticks_survive_busy_import_and_inflight_drain() {
    let sources = [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
    ]
    .map(|class| Source {
        owner: IRQ,
        class,
        allowed_cores: 9,
    });
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: i as u64 + 1,
        owner: IRQ,
        arrived_ns: 2_000_000_000 + i as u64 * 1_000_000,
    });
    learning_evidence::CAPTURE
        .lock()
        .unwrap()
        .start(
            Config {
                key: RUN,
                family: Family { domain: 6, kind: 1 },
                node: [1; 32],
                first_ns: 1_000_000_000,
                observation_ns: 2_000_000_000,
                frozen_scope_hash: [2; 32],
            },
            &sources,
            &requests,
        )
        .unwrap();
    irq_replay::activate(RUN).unwrap();
    irq_replay::activate(RUN).unwrap();
    INFLIGHT[0].store(1, Ordering::Release);
    irq_replay::entered(48, 3, 2001);
    irq_replay::completed(48, 2003);
    INFLIGHT[0].store(0, Ordering::Release);
    assert_eq!(
        learning_evidence::attest(RUN, IRQ, 1, 0, 2_001_000_000, 2_003_000_000),
        Err(learning::Error::Evidence)
    );
    assert_eq!(
        learning_evidence::attest(RUN, IRQ, 1, 3, 2_001_000_000, 2_004_000_000),
        Err(learning::Error::Evidence)
    );
    learning_evidence::BUSY.store(true, Ordering::Release);
    assert_eq!(irq_replay::poll(RUN), Err(Error::Busy));
    assert!(
        learning_evidence::CAPTURE
            .lock()
            .unwrap()
            .intervals()
            .is_empty()
    );
    // The exact unacknowledged raw event remains in custody across Busy.
    learning_evidence::attest(RUN, IRQ, 1, 3, 2_001_000_000, 2_003_000_000).unwrap();
    learning_evidence::BUSY.store(false, Ordering::Release);
    assert!(irq_replay::poll(RUN).unwrap());
    assert!(irq_replay::poll(RUN).unwrap());
    {
        let capture = learning_evidence::CAPTURE.lock().unwrap();
        let rows = capture.intervals();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].core, 3);
        assert_eq!(
            (rows[0].start_ns, rows[0].end_ns),
            (2_001_000_000, 2_003_000_000)
        );
        assert_eq!(rows[0].class, CpuClass::ExecutorWork);
    }
    INFLIGHT[0].store(1, Ordering::Release);
    irq_replay::entered(48, 0, 2100);
    assert!(!irq_replay::drain(RUN).unwrap());
    // Disarming stops new entry but cannot erase the actual running IRQ.
    irq_replay::completed(48, 2105);
    INFLIGHT[0].store(0, Ordering::Release);
    assert!(irq_replay::drain(RUN).unwrap());
    irq_replay::release(RUN).unwrap();
    {
        let capture = learning_evidence::CAPTURE.lock().unwrap();
        let rows = capture.intervals();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].core, 0);
        assert_eq!(
            (rows[1].start_ns, rows[1].end_ns),
            (2_100_000_000, 2_105_000_000)
        );
    }
    assert_eq!(
        irq_replay::poll(RunKey {
            generation: 2,
            ..RUN
        }),
        Err(Error::Stale)
    );
    let next = RunKey {
        trial_id: 2,
        generation: 2,
        ..RUN
    };
    irq_replay::activate(next).unwrap();
    for i in 0..129 {
        irq_replay::entered(48, 3, 2200 + i * 2);
        irq_replay::completed(48, 2201 + i * 2);
    }
    assert_eq!(irq_replay::poll(next), Err(Error::Capacity));
    assert_eq!(irq_replay::drain(next), Err(Error::Capacity));
    assert_eq!(irq_replay::release(next), Err(Error::Capacity));
    // Missing CPU makes closure fail; it never becomes a zero-cost sample.
}
