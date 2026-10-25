//! Production peer Attempt and Ledger with a real contended host mutex as the
//! platform ledger gate. CPU/clock providers do not claim native execution.
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use cyxia_peer_billing::{Binding, Endpoint};
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        self, Family, ReplayGroup,
        capture::RunKey,
        reward::{CpuClass, CpuInterval, OBSERVATION_NS},
    },
};
use std::sync::Mutex;
#[allow(dead_code)]
#[path = "../../../kernel/src/peer_replay/ledger.rs"]
mod ledger;
#[path = "../../../kernel/src/peer_replay/attempt.rs"]
mod owner_attempt;

static SERIAL: Mutex<()> = Mutex::new(());
static LEDGER: Mutex<Option<ledger::Ledger>> = Mutex::new(None);
static BANK: AtomicUsize = AtomicUsize::new(0);
static CLOCK: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static DROPPED_OPEN: AtomicU64 = AtomicU64::new(0);
pub mod cpu {
    use super::*;
    static CORE: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize {
        CORE.load(Ordering::Acquire)
    }
    pub fn set(core: usize) {
        CORE.store(core, Ordering::Release);
    }
}
fn now() -> u64 {
    CLOCK.load(Ordering::Acquire)
}
fn family() -> Option<u16> {
    Some(16)
}
fn stored(index: usize) -> *mut CpuInterval {
    (BANK.load(Ordering::Acquire) as *mut CpuInterval).wrapping_add(index)
}
// Platform fixture: the callback receives the actual production Ledger only
// after a real exclusive gate acquisition; holding that gate yields Unknown.
fn ledger_with<T>(
    f: impl FnOnce(&mut ledger::Ledger) -> Result<T, learning::Error>,
) -> Result<T, learning::Error> {
    let mut guard = LEDGER.try_lock().map_err(|_| learning::Error::Unknown)?;
    let ledger = guard.as_mut().ok_or(learning::Error::Stale)?;
    ledger.missing = ledger
        .missing
        .saturating_add(DROPPED.swap(0, Ordering::AcqRel));
    ledger.open = ledger
        .open
        .saturating_sub(DROPPED_OPEN.swap(0, Ordering::AcqRel) as usize);
    f(ledger)
}
const OBS: u64 = 2_000_000_000;
fn binding() -> Binding {
    Binding {
        origin: Endpoint {
            node: [1; 32],
            boot: 3,
        },
        participant: Endpoint {
            node: [2; 32],
            boot: 4,
        },
        session: [5; 32],
        run: RunKey {
            boot_epoch: 3,
            trial_id: 41,
            generation: 9,
        },
        family: Family {
            domain: 16,
            kind: 2,
        },
        baseline: false,
        owner: ObjectKey {
            id: 19,
            generation: 1,
        },
        target: ObjectKey {
            id: 4098,
            generation: 3,
        },
        group: ReplayGroup {
            seed: 1,
            workload: [6; 32],
            initial_image: [7; 32],
        },
        frozen_scope_hash: [8; 32],
    }
}
fn remote() -> ObjectKey {
    ObjectKey {
        id: 0x100,
        generation: 42,
    }
}
fn reset() {
    let mut ledger = ledger::Ledger::new(binding(), 100, OBS, [9; 32]).unwrap();
    ledger.register_remote(remote().generation).unwrap();
    *LEDGER.lock().unwrap() = Some(ledger);
    DROPPED.store(0, Ordering::Release);
    DROPPED_OPEN.store(0, Ordering::Release);
    CLOCK.store(OBS + 1_000, Ordering::Release);
    let rows = Box::leak(
        vec![
            CpuInterval {
                node: [0; 32],
                core: 0,
                start_ns: 0,
                end_ns: 0,
                class: CpuClass::Policy,
            };
            4
        ]
        .into_boxed_slice(),
    );
    BANK.store(rows.as_mut_ptr() as usize, Ordering::Release);
}

#[test]
fn completed_original_core_tuple_survives_busy_and_only_that_tuple_can_flush_elsewhere() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    cpu::set(3);
    let mut pending = owner_attempt::attempt(remote(), CpuClass::ExecutorWork, 3).unwrap();
    let first = OBS + 37;
    let last = OBS + 74;
    {
        let gate = LEDGER.lock().unwrap();
        assert_eq!(
            owner_attempt::finish(&mut pending, first, last),
            Err(learning::Error::Unknown)
        );
        let ledger = gate.as_ref().unwrap();
        assert_eq!((ledger.open, ledger.count, ledger.missing), (1, 0, 0));
    }
    // Neither an origin-core retry nor a remote-core retry may replace the
    // recorded execution interval with a shorter or newly dated interval.
    assert_eq!(
        owner_attempt::finish(&mut pending, first + 1, last),
        Err(learning::Error::Evidence)
    );
    cpu::set(0);
    assert_eq!(
        owner_attempt::finish(&mut pending, first, last + 1),
        Err(learning::Error::Evidence)
    );
    CLOCK.store(OBS + OBSERVATION_NS + 1, Ordering::Release);
    assert_eq!(
        ledger_with(|l| l.close(now(), true)),
        Err(learning::Error::Unknown)
    );
    assert_eq!(owner_attempt::finish(&mut pending, first, last), Ok(()));
    let actual = unsafe { stored(0).read() };
    assert_eq!(
        (
            actual.node,
            actual.core,
            actual.start_ns,
            actual.end_ns,
            actual.class
        ),
        ([2; 32], 3, first, last, CpuClass::ExecutorWork)
    );
    ledger_with(|l| {
        assert_eq!(l.binding, binding());
        assert_eq!((l.open, l.count, l.missing), (0, 1, 0));
        l.close(now(), true)?;
        assert!(l.hash_piece(0, &[actual])?);
        assert!(l.sealed.is_some());
        assert!(l.excluded.is_none());
        Ok(())
    })
    .unwrap();
    assert_eq!(
        owner_attempt::finish(&mut pending, first, last),
        Err(learning::Error::Stale)
    );
    drop(pending);
    ledger_with(|l| {
        assert_eq!((l.open, l.count, l.missing), (0, 1, 0));
        Ok(())
    })
    .unwrap();
}

#[test]
fn foreign_first_finish_cannot_create_a_completion_proof_and_dropping_unknown_stays_missing() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    cpu::set(3);
    let mut pending = owner_attempt::attempt(remote(), CpuClass::ExecutorWork, 3).unwrap();
    let first = OBS + 37;
    let last = OBS + 74;
    cpu::set(0);
    assert_eq!(
        owner_attempt::finish(&mut pending, first, last),
        Err(learning::Error::Evidence)
    );
    cpu::set(2);
    assert_eq!(
        owner_attempt::finish(&mut pending, first, last),
        Err(learning::Error::Evidence)
    );
    cpu::set(3);
    assert_eq!(
        owner_attempt::finish(&mut pending, last, first),
        Err(learning::Error::Evidence)
    );
    assert_eq!(
        owner_attempt::finish(&mut pending, first, now() + 1),
        Err(learning::Error::Evidence)
    );
    {
        let gate = LEDGER.lock().unwrap();
        assert_eq!(
            owner_attempt::finish(&mut pending, first, last),
            Err(learning::Error::Unknown)
        );
        assert_eq!(gate.as_ref().unwrap().open, 1);
    }
    drop(pending);
    CLOCK.store(OBS + OBSERVATION_NS + 1, Ordering::Release);
    ledger_with(|l| {
        assert_eq!((l.open, l.count, l.missing), (0, 0, 1));
        l.close(now(), true)?;
        assert!(l.hash_piece(0, &[])?);
        assert!(l.sealed.is_none());
        assert_eq!(l.excluded.unwrap().trace.missing_events, 1);
        Ok(())
    })
    .unwrap();
}
