//! Production measurement collector and ConsolePump; the UART is a controlled
//! test fixture. No replay labels or native execution claims are constructed.
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_canary/collector.rs"]
mod collector;
use collector::*;
use cyxia_prototype::{
    domains::{
        Error as DomainError, ObjectKey, PolicyStamp,
        maintenance::{ConsoleHardware, ConsolePump},
    },
    learning::{
        Error,
        governance::CanaryPermit,
        reward::{RequestResult, WorkRequest, inspect_one_second_with_latencies},
    },
};
struct Uart {
    now: u64,
    full: bool,
    failed: bool,
    bytes: Vec<u8>,
}
impl ConsoleHardware for Uart {
    fn now_ns(&mut self) -> u64 {
        self.now
    }
    fn try_write(&mut self, b: u8) -> Result<bool, DomainError> {
        if self.failed {
            return Err(DomainError::Io);
        }
        if self.full {
            return Ok(false);
        }
        self.bytes.push(b);
        self.now += 10;
        Ok(true)
    }
}
fn target() -> ObjectKey {
    ObjectKey {
        id: 7,
        generation: 2,
    }
}
fn view(p: &ConsolePump, now: u64, unresolved: bool) -> Observation {
    Observation {
        written: p.written,
        queued: p.queued(),
        batch: p.current(now),
        unresolved,
        poisoned: p.poisoned(),
    }
}
fn piece(c: &mut Collector, p: &mut ConsolePump, u: &mut Uart, now: u64) -> Result<(), Error> {
    u.now = now;
    if let Some(d) = c.before(now, view(p, now, false))? {
        let result = p
            .enqueue(PAYLOAD, now)
            .map(|()| p.written + p.queued() as u64);
        c.admitted(d, now, result)?;
    }
    let _ = p.pump(now, u);
    c.after(u.now, view(p, u.now, false))
}
fn ready() -> (Box<Collector>, ConsolePump, Uart, u64) {
    let mut c = Box::new(Collector::new());
    let mut p = ConsolePump::new();
    let mut u = Uart {
        now: 0,
        full: false,
        failed: false,
        bytes: Vec::new(),
    };
    assert!(!c.reserve(target()).unwrap());
    let mut now = 0;
    while c.state.phase != Phase::Ready {
        piece(&mut c, &mut p, &mut u, now).unwrap();
        now += PERIOD;
        assert!(now < 40 * SECOND);
    }
    assert_eq!(u.bytes.len(), ROWS * PAYLOAD.len());
    (c, p, u, now)
}
fn permit(now: u64) -> CanaryPermit {
    CanaryPermit {
        id: 1,
        active_generation: 3,
        candidate_hash: [5; 32],
        target: target(),
        start_ns: now + PERIOD,
        expires_ns: now + PERIOD + 10 * SECOND,
        windows: 100,
        quota: 100,
    }
}
const EMPTY: WorkRequest = WorkRequest {
    id: 0,
    arrived_ns: 0,
    result: RequestResult::Pending,
};
#[test]
fn hardware_completions_and_frozen_baseline_authenticate_exact_window() {
    let (mut c, mut p, mut u, mut now) = ready();
    let permit = permit(now);
    c.bind(permit, now).unwrap();
    p.install(
        PolicyStamp {
            version: 1,
            snapshot_ns: now,
            installed_until_ns: now + 10 * SECOND,
        },
        32,
        now,
    )
    .unwrap();
    while now < permit.start_ns + SECOND {
        piece(&mut c, &mut p, &mut u, now).unwrap();
        now += PERIOD;
    }
    piece(&mut c, &mut p, &mut u, now).unwrap();
    let (mut b, mut a) = ([EMPTY; PER_SECOND], [EMPTY; PER_SECOND]);
    c.second(permit, 0, now, &mut b, &mut a).unwrap();
    assert!(
        a.iter()
            .all(|r| matches!(r.result, RequestResult::Completed { .. }))
    );
    let hash = measurement_digest(permit, 0, &b, &a);
    c.verify(permit, 0, now, &b, &a, hash).unwrap();
    let metrics = inspect_one_second_with_latencies(&a, permit.start_ns, &mut [0; PER_SECOND])
        .unwrap()
        .unwrap();
    assert_eq!((metrics.emitted, metrics.completed), (100, 100));
    a[1].result = RequestResult::Completed {
        finished_ns: a[1].arrived_ns,
    };
    assert_eq!(
        c.verify(
            permit,
            0,
            now,
            &b,
            &a,
            measurement_digest(permit, 0, &b, &a)
        ),
        Err(Error::Evidence)
    );
    c.acknowledge(permit, 0).unwrap();
    assert_eq!(c.acknowledge(permit, 0), Err(Error::Stale));
}
#[test]
fn blocked_uart_keeps_pending_penalty_and_late_write_cannot_change_closed_window() {
    let (mut c, mut p, mut u, mut now) = ready();
    let permit = permit(now);
    c.bind(permit, now).unwrap();
    u.full = true;
    while now < permit.start_ns + SECOND {
        piece(&mut c, &mut p, &mut u, now).unwrap();
        now += PERIOD;
    }
    let (mut b, mut a) = ([EMPTY; PER_SECOND], [EMPTY; PER_SECOND]);
    c.second(permit, 0, now, &mut b, &mut a).unwrap();
    assert!(a.iter().all(|r| r.result == RequestResult::Pending));
    let before = measurement_digest(permit, 0, &b, &a);
    let m = inspect_one_second_with_latencies(&a, permit.start_ns, &mut [0; PER_SECOND])
        .unwrap()
        .unwrap();
    assert_eq!((m.pending, m.penalty_p99_ns), (100, 10 * SECOND));
    u.full = false;
    for _ in 0..150 {
        piece(&mut c, &mut p, &mut u, now).unwrap();
        now += PERIOD;
    }
    c.second(permit, 0, now, &mut b, &mut a).unwrap();
    assert_eq!(measurement_digest(permit, 0, &b, &a), before);
    assert_eq!(c.release(view(&p, now, true)), Err(Error::Unknown));
}
#[test]
fn baseline_waits_for_existing_lease_and_unknown_custody_and_rejects_wrong_target() {
    let mut c = Collector::new();
    let mut p = ConsolePump::new();
    let mut now = 0;
    p.install(
        PolicyStamp {
            version: 1,
            snapshot_ns: 0,
            installed_until_ns: 10 * SECOND,
        },
        64,
        0,
    )
    .unwrap();
    c.reserve(target()).unwrap();
    for _ in 0..100 {
        c.before(now, view(&p, now, false)).unwrap();
        now += PERIOD;
    }
    assert_eq!(c.state.phase, Phase::Drain);
    assert!(c.blocks_active());
    c.before(11 * SECOND, view(&p, 11 * SECOND, true)).unwrap();
    assert_eq!(c.state.phase, Phase::Drain);
    c.before(11 * SECOND, view(&p, 11 * SECOND, false)).unwrap();
    assert_eq!(c.state.phase, Phase::Warm);
    let mut wrong = permit(11 * SECOND);
    wrong.target.generation += 1;
    assert_eq!(c.bind(wrong, 11 * SECOND), Err(Error::Evidence));
}
#[test]
fn unknown_uart_effect_cannot_become_success_or_release_a_live_queue() {
    let (mut c, mut p, mut u, now) = ready();
    let permit = permit(now);
    c.bind(permit, now).unwrap();
    u.failed = true;
    assert!(piece(&mut c, &mut p, &mut u, permit.start_ns).is_err());
    assert!(c.state.fault.is_some());
    assert_eq!(
        c.release(view(&p, permit.start_ns, false)),
        Err(Error::Unknown)
    );
    let (mut b, mut a) = ([EMPTY; PER_SECOND], [EMPTY; PER_SECOND]);
    assert!(
        c.second(permit, 0, permit.start_ns + SECOND, &mut b, &mut a)
            .is_err()
    );
}
#[test]
fn delayed_permit_binding_keeps_the_predeclared_arrivals_and_counts_waiting() {
    let (mut c, mut p, mut u, now) = ready();
    let permit = permit(now);
    // A root permit issued exactly at a window boundary is inevitably seen
    // a little later. The workload was retained before that boundary; binding
    // must neither move its releases nor synthesize past completions.
    let bound = permit.start_ns + PERIOD / 2;
    c.bind(permit, bound).unwrap();
    piece(&mut c, &mut p, &mut u, bound).unwrap();
    let (mut b, mut a) = ([EMPTY; PER_SECOND], [EMPTY; PER_SECOND]);
    c.second(permit, 0, permit.start_ns + SECOND, &mut b, &mut a)
        .unwrap();
    assert_eq!(a[0].arrived_ns, permit.start_ns);
    assert!(matches!(a[0].result,RequestResult::Completed{finished_ns}if finished_ns>=bound));
    assert!(a[1..].iter().all(|r| r.result == RequestResult::Pending));
}
