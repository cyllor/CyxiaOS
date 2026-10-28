#[path = "../../../kernel/src/domain_tasks/owner_gate.rs"]
mod owner_gate;
use owner_gate::Gate;

#[test]
fn real_waiters_receive_round_robin_opportunities() {
    let gate = Gate::new();
    let held = gate.try_acquire(0, 100, 10).unwrap();
    for cpu in 1..4 {
        assert!(gate.try_acquire(cpu, 100, 10).is_none());
    }
    held.release(100);
    // Admission and use may borrow again, without extending the same turn.
    gate.try_acquire(0, 101, 10).unwrap().release(101);
    for cpu in 1..4 {
        let at = 100 + cpu as u64 * 10;
        assert!(gate.try_acquire(0, at, 10).is_none());
        gate.try_acquire(cpu, at, 10).unwrap().release(at);
    }
    gate.try_acquire(0, 140, 10).unwrap().release(140);
}

#[test]
fn expired_waiter_is_removed_while_other_real_waiter_is_retained() {
    let gate = Gate::new();
    let held = gate.try_acquire(0, 100, 10).unwrap();
    assert!(gate.try_acquire(1, 100, 10).is_none());
    assert!(gate.try_acquire(2, 100, 10).is_none());
    held.release(100);
    assert!(gate.try_acquire(0, 110, 10).is_none());
    assert!(gate.try_acquire(2, 119, 10).is_none());
    gate.try_acquire(2, 120, 10).unwrap().release(120);
    assert!(gate.try_acquire(2, 130, 10).is_none());
    gate.try_acquire(0, 130, 10).unwrap().release(130);
    gate.try_acquire(2, 140, 10).unwrap().release(140);
    // CPU1 no longer has a stale queue bit.
    gate.try_acquire(3, 140, 10).unwrap().release(140);
}

#[test]
fn saturating_clock_edge_does_not_make_handoff_permanent() {
    let gate = Gate::new();
    let held = gate.try_acquire(0, u64::MAX - 5, 10).unwrap();
    assert!(gate.try_acquire(1, u64::MAX - 5, 10).is_none());
    held.release(u64::MAX - 5);
    assert!(gate.try_acquire(2, u64::MAX - 1, 10).is_none());
    assert!(gate.try_acquire(2, u64::MAX, 10).is_none());
    gate.try_acquire(1, u64::MAX, 10).unwrap().release(u64::MAX);
    gate.try_acquire(2, u64::MAX, 10).unwrap().release(u64::MAX);
    gate.try_acquire(0, u64::MAX, 10).unwrap().release(u64::MAX);
}

#[test]
fn uncontended_release_does_not_delay_another_cpu() {
    let gate = Gate::new();
    for cpu in 0..4 {
        gate.try_acquire(cpu, 100, 10).unwrap().release(100);
    }
}

#[test]
fn concurrent_callers_exclude_each_other_and_all_make_progress() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    let gate = Arc::new(Gate::new());
    let active = Arc::new(AtomicU64::new(0));
    let effects = Arc::new(AtomicU64::new(0));
    let clock = Arc::new(AtomicU64::new(0));
    let threads: Vec<_> = (0..4)
        .map(|cpu| {
            let (gate, active, effects, clock) =
                (gate.clone(), active.clone(), effects.clone(), clock.clone());
            std::thread::spawn(move || {
                for _ in 0..200 {
                    let mut entered = false;
                    for _ in 0..1_000_000 {
                        let now = clock.fetch_add(1, Ordering::AcqRel);
                        if let Some(permit) = gate.try_acquire(cpu, now, 10) {
                            assert_eq!(active.fetch_add(1, Ordering::AcqRel), 0);
                            effects.fetch_add(1, Ordering::AcqRel);
                            assert_eq!(active.fetch_sub(1, Ordering::AcqRel), 1);
                            permit.release(clock.fetch_add(1, Ordering::AcqRel));
                            entered = true;
                            break;
                        }
                        std::thread::yield_now();
                    }
                    assert!(entered, "CPU {cpu} lost all owner opportunities");
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(effects.load(Ordering::Acquire), 800);
}
