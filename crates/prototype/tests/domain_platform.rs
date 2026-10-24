use cyxia_prototype::domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp, platform::*};
fn key(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
fn stamp(version: u64, now: u64) -> PolicyStamp { PolicyStamp::new(version, now, now).unwrap() }
fn apply(id: u64, seq: u64) -> ApplyId { ApplyId { boot_epoch: 1, controller_epoch: 2, plan_seq: seq, action_index: 0, target: key(id) } }

struct Irq { view: IrqTopology, masked: bool, quiescent: bool, target: u16, commits: usize }
impl IrqHardware for Irq {
    fn topology(&self, _: u32) -> Result<IrqTopology, Error> { Ok(self.view) }
    fn mask(&mut self, _: u32) -> Result<(), Error> { self.masked = true; Ok(()) }
    fn synchronized(&mut self, _: u32) -> Result<bool, Error> { Ok(self.quiescent) }
    fn commit_route(&mut self, _: u32, guard: IrqCommitGuard) -> Result<u64, Error> {
        assert!(self.masked && self.quiescent); assert_eq!(guard.topology, self.view);
        assert_ne!(guard.allowed & self.view.healthy_business & !self.view.draining & (1 << guard.target_cpu), 0);
        self.target = guard.target_cpu; self.view.route_generation += 1; self.commits += 1;
        self.masked = false; Ok(self.view.route_generation)
    }
}
fn irq() -> Irq { Irq { view: IrqTopology { core_generation: 1, ledger_generation: 1, route_generation: 1, healthy_business: 9, draining: 0 },
    masked: false, quiescent: false, target: 0, commits: 0 } }
#[test]
fn irq_masks_before_waiting_and_rejects_a_generation_race_without_fake_commit() {
    let mut router = IrqRouter::new(key(40), 40, 9).unwrap(); let mut hw = irq();
    assert_eq!(router.request(apply(40, 1), stamp(1, 0), 3, 0, &mut hw), Ok(IrqProgress::Pending));
    assert!(hw.masked); assert_eq!(router.poll(1, &mut hw), Ok(IrqProgress::Pending));
    hw.quiescent = true; hw.view.core_generation += 1; hw.view.draining = 8;
    assert_eq!(router.poll(2, &mut hw), Ok(IrqProgress::Degraded(Error::Stale)));
    assert!(hw.masked); assert_eq!(hw.commits, 0);
    router.force_baseline(3, &mut hw).unwrap(); router.poll(4, &mut hw).unwrap();
    assert_eq!((hw.target, hw.commits, hw.masked), (0, 1, false));
    assert_eq!(router.request(apply(40, 1), stamp(1, 0), 3, 5, &mut hw), Ok(IrqProgress::Degraded(Error::Stale)),
        "baseline reconciliation must preserve the original operation's result");
}
#[test]
fn irq_timeout_and_illegal_interrupt_leave_obligations_intact() {
    assert!(IrqRouter::new(key(30), 30, 9).is_err());
    let mut router = IrqRouter::new(key(40), 40, 9).unwrap(); let mut hw = irq();
    router.request(apply(40, 1), stamp(1, 0), 3, 0, &mut hw).unwrap();
    assert_eq!(router.poll(IRQ_ROUTE_TIMEOUT_NS, &mut hw), Ok(IrqProgress::Degraded(Error::Expired)));
    assert!(hw.masked); assert_eq!(hw.commits, 0);
}
#[derive(Default)]
struct Clock { arms: Vec<TimerArm>, fired: Vec<ObjectKey>, block: bool }
impl TimerBackend for Clock {
    fn arm(&mut self, arm: TimerArm) -> Result<(), Error> { if self.block { Err(Error::Again) } else { self.arms.push(arm); Ok(()) } }
    fn cancel(&mut self, _: ObjectKey) -> Result<(), Error> { Ok(()) }
    fn fire(&mut self, key: ObjectKey) -> Result<(), Error> { if self.block { Err(Error::Again) } else { self.fired.push(key); Ok(()) } }
}
#[test]
fn timers_round_only_new_soft_arms_preserve_hard_and_expired_deadlines() {
    let mut timers = Timers::new(); let mut clock = Clock::default();
    timers.register(key(9000), TimerClass::Soft, 30_000).unwrap();
    timers.register(key(9001), TimerClass::HardDeadline, 0).unwrap();
    assert_eq!(timers.register(key(9002), TimerClass::Lease, 1), Err(Error::Auth));
    timers.install(stamp(1, 0), 50, 0).unwrap();
    let soft = timers.arm(key(9000), 101_000, 0, &mut clock).unwrap();
    assert_eq!(soft.programmed_ns, 131_000);
    let hard = timers.arm(key(9001), 101_000, 0, &mut clock).unwrap();
    assert_eq!((hard.programmed_ns, hard.policy_version), (101_000, 0));
    timers.install(stamp(2, 1000), 1000, 1000).unwrap();
    assert_eq!(clock.arms.len(), 2, "a new policy does not rewrite old hardware arms");
    clock.block = true; assert_eq!(timers.poll(200_000, 2, &mut clock), Ok(0));
    clock.block = false; assert_eq!(timers.poll(200_000, 2, &mut clock), Ok(2));
    assert_eq!(timers.poll(200_000, 2, &mut clock), Ok(0));
    assert_eq!(timers.arm(key(9000), 100_000, 200_000, &mut clock).unwrap().programmed_ns, 100_000);
    assert_eq!(timers.arm(key(9000), 10_001_001_000, 10_000_001_000, &mut clock).unwrap().programmed_ns, 10_001_001_000);
    assert_eq!(timers.soft_observation(), (1, 30_000, 1, 1));
}
#[test]
fn timer_registration_is_bounded_and_keys_are_opaque() {
    let mut timers = Timers::new();
    for id in 1000..1256 { timers.register(key(id), TimerClass::Soft, 0).unwrap(); }
    assert_eq!(timers.register(key(1256), TimerClass::Soft, 0), Err(Error::Capacity));
    assert_eq!(timers.register(key(1000), TimerClass::Soft, 0), Err(Error::Exists));
}
struct Send { reserved: usize, ordinary: Vec<ObjectKey>, ready: usize }
impl NetworkTx for Send {
    fn reserved(&mut self) -> Result<TxStep, Error> { self.reserved += 1; Ok(TxStep { sent: true, still_ready: true }) }
    fn send_ready(&mut self, key: ObjectKey) -> Result<TxStep, Error> {
        if self.ready == 0 { return Ok(TxStep { sent: false, still_ready: false }); }
        self.ready -= 1; self.ordinary.push(key); Ok(TxStep { sent: true, still_ready: self.ready != 0 })
    }
}
#[test]
fn send_batches_preserve_reserved_progress_fairness_and_no_fill_wait() {
    let mut scheduler = NetworkScheduler::new(); scheduler.register(key(1)).unwrap(); scheduler.register(key(2)).unwrap();
    scheduler.mark_ready(key(1)).unwrap(); scheduler.mark_ready(key(2)).unwrap();
    scheduler.install(stamp(1, 0), 8, 0).unwrap(); let mut send = Send { reserved: 0, ordinary: vec![], ready: 12 };
    let round = scheduler.service(1, &mut send).unwrap(); assert_eq!((round.ordinary, round.reserved), (8, 4));
    assert!(send.ordinary.windows(2).all(|w| w[0] != w[1]));
    assert_eq!(scheduler.install(stamp(1, 0), 16, 1), Err(Error::Conflict));
    let expired = scheduler.service(10_000_000_000, &mut send).unwrap(); assert_eq!(expired.ordinary, 4);
    scheduler.mark_ready(key(1)).unwrap(); send.ready = 1;
    assert_eq!(scheduler.service(10_000_000_001, &mut send).unwrap().ordinary, 1);
}
#[test]
fn ingress_enforces_both_buckets_and_failed_handshakes_do_not_refund() {
    let mut ingress = SecurityIngress::new(0); ingress.install(stamp(1, 0), 32, 0).unwrap();
    for _ in 0..4 { let t = ingress.begin([1,2,3,4], 0).unwrap(); ingress.finish(t, false, 0).unwrap(); }
    assert_eq!(ingress.begin([1,2,3,4], 0), Err(Error::Again));
    assert_eq!(ingress.begin([1,2,3,4], 31_250_000), Err(Error::Again));
    let t = ingress.begin([4,3,2,1], 31_250_000).unwrap(); ingress.finish(t, true, 31_250_000).unwrap();
    let t = ingress.begin([1,2,3,4], 125_000_000).unwrap(); ingress.finish(t, true, 125_000_000).unwrap();
    assert_eq!(ingress.counters.failures, 4);
    assert_eq!(ingress.install(stamp(2, 125_000_000), 16, 125_000_000), Err(Error::Busy));
    assert_eq!(ingress.install(stamp(1, 0), 16, 125_000_000), Err(Error::Conflict));
    ingress.install(stamp(1, 0), 32, 10_000_000_000).unwrap();
    assert_eq!(ingress.effective_rate(10_000_000_000), Ok(16));
}
#[test]
fn source_capacity_cannot_evict_recent_sources_or_steal_authenticated_recovery_slots() {
    let mut ingress = SecurityIngress::new(0); ingress.install(stamp(1, 0), 32, 0).unwrap();
    ingress.authorize_recovery_session(key(90)).unwrap(); let recovery = ingress.begin_recovery(key(90), 0).unwrap();
    for i in 0..32 {
        let now = if i < 4 { 0 } else { (i - 3) * 31_250_000 };
        let t = ingress.begin([10,0,0,i as u8], now).unwrap(); ingress.finish(t, true, now).unwrap();
    }
    assert_eq!(ingress.begin([11,0,0,1], 906_250_000), Err(Error::Capacity));
    assert_eq!(ingress.active(), (0, 1));
    let t = ingress.begin([11,0,0,1], 1_000_000_000).unwrap(); ingress.finish(t, true, 1_000_000_000).unwrap();
    ingress.revoke_recovery_session(key(90)).unwrap(); ingress.finish(recovery, true, 1_000_000_000).unwrap();
    assert_eq!(ingress.begin_recovery(key(90), 1_000_000_000), Err(Error::Auth));
}
fn request(id: u64) -> PlacementRequest { PlacementRequest { key: key(id), payload_hash: [1;32], package_hash: [2;32],
    cpu_milli: 100, memory_pages: 16, isa: 1, abi: 1, peer: Some(key(90)) } }
struct Place { intents: Vec<PlacementIntent>, receipts: Vec<PlacementOutcome>, calls: usize, unknown: bool, result: Option<PlacementOutcome>, receipt_unknown: bool }
impl Place { fn new() -> Self { Self { intents: vec![], receipts: vec![], calls: 0, unknown: false, result: None, receipt_unknown: false } } }
impl PlacementBackend for Place {
    fn persist_intent(&mut self, i: PlacementIntent) -> PlacementDurability { self.intents.push(i); PlacementDurability::Committed }
    fn intent_status(&mut self, _: PlacementIntent) -> PlacementDurability { PlacementDurability::Unknown }
    fn local_admit(&mut self, i: PlacementIntent) -> PlacementAdmission { assert!(self.intents.contains(&i)); self.calls += 1;
        if self.unknown { PlacementAdmission::Unknown } else { PlacementAdmission::Admitted(key(100)) } }
    fn peer_ready(&self, _: PlacementRequest) -> bool { true }
    fn peer_prepare(&mut self, i: PlacementIntent) -> PlacementAdmission { self.local_admit(i) }
    fn reconcile(&mut self, _: PlacementIntent) -> Option<PlacementOutcome> { self.result }
    fn persist_receipt(&mut self, _: PlacementIntent, o: PlacementOutcome) -> PlacementDurability { self.receipts.push(o);
        if self.receipt_unknown { PlacementDurability::Unknown } else { PlacementDurability::Committed } }
}
#[test]
fn placement_unknown_and_durable_result_retry_never_repeat_start() {
    let mut queue = PlacementQueue::<64>::new(); let mut backend = Place::new(); backend.unknown = true;
    queue.submit(request(1), 0).unwrap(); queue.choose(apply(1, 1), PlacementChoice::Local, 1).unwrap();
    queue.poll(2, 32, &mut backend).unwrap(); for now in 3..10 { queue.poll(now, 32, &mut backend).unwrap(); }
    assert_eq!(backend.calls, 1); assert_eq!(queue.status(key(1)), Ok(PlacementStatus::Unknown));
    assert_eq!(queue.choose(apply(1, 2), PlacementChoice::Peer, 11), Err(Error::Busy));
    backend.result = Some(PlacementOutcome::Local(key(100))); backend.receipt_unknown = true;
    queue.poll(12, 32, &mut backend).unwrap(); queue.poll(13, 32, &mut backend).unwrap();
    assert_eq!(backend.calls, 1); assert_eq!(queue.pending_count(), 1);
    backend.receipt_unknown = false; queue.poll(14, 32, &mut backend).unwrap();
    assert_eq!(queue.pending_count(), 0); assert_eq!(queue.submit(request(1), 15), Ok(PlacementStatus::Complete(PlacementOutcome::Local(key(100)))));
    let mut changed = request(1); changed.payload_hash[0] += 1; assert_eq!(queue.submit(changed, 16), Err(Error::Conflict));
}
#[test]
fn defer_has_four_second_local_fallback_and_restored_intents_only_query() {
    let mut queue = PlacementQueue::<64>::new(); let mut backend = Place::new();
    for i in 1..=32 { queue.submit(request(i), 0).unwrap(); }
    assert_eq!(queue.submit(request(33), 0), Err(Error::Capacity));
    queue.choose(apply(1, 1), PlacementChoice::Defer, 1).unwrap();
    queue.poll(3_999_999_999, 32, &mut backend).unwrap(); assert_eq!(backend.calls, 0);
    queue.poll(4_000_000_000, 4, &mut backend).unwrap(); assert_eq!(backend.calls, 4); assert_eq!(queue.fallbacks, 4);
    let intent = backend.intents[0]; let mut restored = PlacementQueue::<2>::new();
    restored.restore_intent(intent, 5_000_000_000).unwrap();
    restored.poll(10_000_000_000, 32, &mut backend).unwrap(); assert_eq!(backend.calls, 4);
    restored.restore_receipt(intent, PlacementOutcome::Local(key(100)), 10_000_000_001).unwrap();
    assert_eq!(restored.pending_count(), 0);
}
struct Quotes { cap: QuoteCapacity, sent: Vec<CpuQuote> }
impl QuoteBackend for Quotes { fn capacity(&self) -> QuoteCapacity { self.cap } fn publish(&mut self, q: CpuQuote) -> Result<(), Error> { self.sent.push(q); Ok(()) } }
#[test]
fn quotes_are_actual_remaining_capacity_and_have_no_positive_expired_baseline() {
    let mut policy = QuotePolicy::new(); let mut backend = Quotes { cap: QuoteCapacity { cpu_milli: 300, memory_pages: 16, core_generation: 2, ledger_generation: 3, ready: true }, sent: vec![] };
    assert_eq!(policy.publish(0, &mut backend), Err(Error::Expired)); policy.install(stamp(1, 0), 500, 0).unwrap();
    assert_eq!(policy.publish(1, &mut backend).unwrap().cpu_milli, 300);
    backend.cap.cpu_milli = 50; assert_eq!(policy.publish(2, &mut backend).unwrap().cpu_milli, 50);
    assert_eq!(policy.install(stamp(1, 0), 1000, 2), Err(Error::Conflict));
    backend.cap.cpu_milli = 0; assert_eq!(policy.publish(3, &mut backend), Err(Error::Capacity));
    assert_eq!(policy.publish(10_000_000_000, &mut backend), Err(Error::Expired));
    assert_eq!(backend.sent.len(), 2);
}
