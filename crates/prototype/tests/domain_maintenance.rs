use cyxia_prototype::{
    domains::{maintenance::*, *},
    policy::ExecutionState,
};
fn key() -> ObjectKey {
    ObjectKey {
        id: 1,
        generation: 1,
    }
}
fn apply(seq: u64) -> ApplyId {
    ApplyId {
        boot_epoch: 1,
        controller_epoch: 1,
        plan_seq: seq,
        action_index: 0,
        target: key(),
    }
}
#[test]
fn optional_budget_is_shared_across_cpu_reservations() {
    let mut b = BackgroundBudgets::new();
    b.register(key(), 100, 50, 0).unwrap();
    let a = b.reserve(key(), 7_000_000, 0).unwrap();
    assert_eq!(b.reserve(key(), 4_000_000, 0), Err(Error::Budget));
    b.complete(a, 6_000_000, 7_000_000).unwrap();
    assert_eq!(b.status(key()).unwrap().spent_ns, 6_000_000);
    assert!(b.reserve(key(), 4_000_000, 7_000_000).is_ok());
    assert_eq!(b.complete(a, 0, 7_000_000), Err(Error::Stale));
}
#[test]
fn unresolved_old_window_cannot_gain_new_budget() {
    let mut b = BackgroundBudgets::new();
    b.register(key(), 100, 0, 0).unwrap();
    let a = b.reserve(key(), 9_000_000, 0).unwrap();
    assert_eq!(b.reserve(key(), 1, 100_000_000), Err(Error::Busy));
    b.complete(a, 9_000_000, 101_000_000).unwrap();
    assert_eq!(
        b.current_status(key(), 101_000_000).unwrap().spent_ns,
        9_000_000
    );
    assert_eq!(b.reserve(key(), 1_000_001, 101_000_000), Err(Error::Budget));
}
#[test]
fn actual_overrun_stays_isolated_until_explicit_stopped_recovery() {
    let mut b = BackgroundBudgets::new();
    b.register(key(), 100, 0, 0).unwrap();
    let a = b.reserve(key(), 10_000_000, 0).unwrap();
    assert_eq!(b.complete(a, 12_000_000, 12_000_000), Err(Error::Budget));
    assert!(b.current_status(key(), 100_000_000).unwrap().overrun);
    assert_eq!(b.reserve(key(), 1, 100_000_000), Err(Error::Budget));
    b.recover_stopped(key(), 100_000_000).unwrap();
    assert!(b.reserve(key(), 1, 100_000_000).is_ok());
}
#[test]
fn expiration_never_reduces_existing_promises() {
    let mut b = BackgroundBudgets::new();
    b.register(key(), 400, 200, 0).unwrap();
    b.install(key(), 400, PolicyStamp::new(1, 0, 0).unwrap(), 0)
        .unwrap();
    let s = b.current_status(key(), POLICY_NS).unwrap();
    assert_eq!(s.budget_milli, 400);
    assert!(s.freeze_admission);
    assert_eq!(b.set_commitment(key(), 250, POLICY_NS), Err(Error::Busy));
    assert!(b.reserve(key(), 1_000_000, POLICY_NS).is_ok());
}
#[derive(Default)]
struct Service {
    starts: usize,
    stops: usize,
    start_unknown: bool,
    fail: bool,
}
impl RecoveryBackend for Service {
    fn close_admission(&mut self, _: ObjectKey) -> Result<(), Error> {
        if self.fail {
            Err(Error::Unsupported)
        } else {
            Ok(())
        }
    }
    fn readonly_drained(&mut self, _: ObjectKey) -> Result<bool, Error> {
        Ok(true)
    }
    fn request_stop(&mut self, _: ObjectKey) -> Result<(), Error> {
        self.stops += 1;
        Ok(())
    }
    fn stopped(&mut self, _: ObjectKey) -> Result<bool, Error> {
        Ok(true)
    }
    fn start_generation(&mut self, _: ObjectKey, _: u64) -> Result<(), Error> {
        self.starts += 1;
        if self.start_unknown {
            Err(Error::Io)
        } else {
            Ok(())
        }
    }
    fn running(&mut self, _: ObjectKey, _: u64) -> Result<bool, Error> {
        Ok(true)
    }
}
#[test]
fn recovery_unknown_start_is_queried_not_repeated() {
    let mut supervisor = RecoverySupervisor::new();
    supervisor.register(key(), 1).unwrap();
    let mut backend = Service {
        start_unknown: true,
        ..Service::default()
    };
    supervisor.begin(apply(1), 1, 0).unwrap();
    for now in 1..=6 {
        supervisor.poll(apply(1), now, &mut backend).unwrap();
    }
    assert_eq!(
        supervisor.query(apply(1)).unwrap().state,
        ExecutionState::Applied
    );
    assert_eq!(backend.starts, 1);
    assert_eq!(backend.stops, 1);
    let again = supervisor.begin(apply(1), 1, 2_000_000_000).unwrap();
    assert_eq!(again.generation, 2);
    assert_eq!(backend.starts, 1);
}
#[test]
fn recovery_whitelist_failures_and_evicted_identity_fail_closed() {
    let mut s = RecoverySupervisor::new();
    s.register(key(), 1).unwrap();
    let mut b = Service {
        fail: true,
        ..Service::default()
    };
    assert_eq!(s.begin(apply(1), 2, 0), Err(Error::Auth));
    s.begin(apply(1), 1, 0).unwrap();
    s.poll(apply(1), 1, &mut b).unwrap();
    s.begin(apply(2), 1, 1_000_000_001).unwrap();
    s.poll(apply(2), 1_000_000_002, &mut b).unwrap();
    assert!(s.isolated(key()).unwrap());
    assert_eq!(s.begin(apply(3), 1, 2_000_000_002), Err(Error::Busy));
    for seq in 3..=280 {
        s.begin(apply(seq), 0, 2_000_000_003).unwrap();
    }
    assert_eq!(s.begin(apply(1), 1, 3_000_000_000), Err(Error::Stale));
}
struct Serial {
    bytes: Vec<u8>,
    capacity: usize,
    now: u64,
    fail: bool,
}
impl ConsoleHardware for Serial {
    fn try_write(&mut self, byte: u8) -> Result<bool, Error> {
        if self.fail {
            return Err(Error::Io);
        }
        if self.bytes.len() >= self.capacity {
            Ok(false)
        } else {
            self.bytes.push(byte);
            Ok(true)
        }
    }
    fn now_ns(&mut self) -> u64 {
        let now = self.now;
        self.now += 10;
        now
    }
}
#[test]
fn serial_partial_fifo_preserves_order_and_actual_version() {
    let mut p = ConsolePump::new();
    p.install(PolicyStamp::new(1, 0, 0).unwrap(), 32, 0)
        .unwrap();
    p.enqueue(b"abcdef", 0).unwrap();
    let mut hw = Serial {
        bytes: vec![],
        capacity: 2,
        now: 0,
        fail: false,
    };
    let first = p.pump(0, &mut hw).unwrap();
    assert_eq!((first.chars, first.policy_version), (2, 1));
    assert!(first.tx_full);
    assert_eq!(p.pump(99_999, &mut hw).unwrap().chars, 0);
    hw.capacity = 10;
    hw.now = 100_000;
    p.pump(100_000, &mut hw).unwrap();
    assert_eq!(hw.bytes, b"abcdef");
    assert_eq!(p.queued(), 0);
}
#[test]
fn audit_storage_is_independent_and_uncertain_serial_is_not_retried() {
    let mut p = ConsolePump::new();
    p.enqueue(&[1; 4096], 0).unwrap();
    assert_eq!(p.enqueue(&[2], 0), Err(Error::Again));
    p.audit_enqueue(b"critical").unwrap();
    let mut hw = Serial {
        bytes: vec![],
        capacity: 10,
        now: 0,
        fail: true,
    };
    assert_eq!(p.pump(0, &mut hw), Err(Error::Io));
    assert!(p.cpu_ns > 0);
    hw.fail = false;
    hw.now = 1_000_000;
    assert_eq!(p.pump(1_000_000, &mut hw), Err(Error::Io));
    assert!(hw.bytes.is_empty());
    let mut bytes = [0; 8];
    assert_eq!(p.audit_read(&mut bytes), 8);
    assert_eq!(&bytes, b"critical");
    p.audit_ack(8).unwrap();
    assert_eq!(p.audit_read(&mut bytes), 0);
}
