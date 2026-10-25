//! CPU0 bridge for the isolated TLS/cluster service. A published policy is not
//! an execution receipt; only matching feedback from the real adapter settles it.
use crate::unified::abi::{self, DomainFeedback, PolicyReceiptWire, PolicyWire, Shared};
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_prototype::{
    domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp},
    features::{DomainObservation, TargetFeatures},
    policy::ExecutionState,
};
mod dependencies;
mod placement_legal;
mod quote_stop;
pub mod replay;
mod requests;
pub use quote_stop::{baseline_stop_custody, baseline_stop_quotes};
pub use requests::{status as placement_request_status, submit as submit_placement_request};

pub fn application_request(phase: u64, payload: &mut [u8; 4096], len: usize) -> (u64, usize, u64) {
    owner();
    match requests::broker(phase, payload, len) {
        Ok(bytes) => (abi::OK, bytes, 0),
        Err(Error::Busy | Error::Again | Error::NotReady) => (abi::AGAIN, 0, 0),
        Err(Error::Stale | Error::NotFound) => (abi::NOT_FOUND, 0, 0),
        Err(_) => (abi::FAILED, 0, 0),
    }
}

#[derive(Clone, Copy)]
struct Desired {
    action: Action,
    apply: ApplyId,
    stamp: PolicyStamp,
}
static READY: AtomicBool = AtomicBool::new(false);
#[derive(Clone, Copy)]
struct ReadView {
    published_ns: u64,
    ready: bool,
    network: Option<(u64, ObjectKey)>,
    effective: [Option<Desired>; 3],
    feedback: DomainFeedback,
}
static READ_VIEW: crate::domain_platform::read_snapshot::ReadSnapshot<ReadView> =
    crate::domain_platform::read_snapshot::ReadSnapshot::new();
fn owner_view() -> ReadView {
    owner();
    let mut feedback = unsafe { *core::ptr::addr_of!(FEEDBACK) };
    if let Some(key) = replay::advertised() {
        if !feedback
            .waiting
            .iter()
            .any(|v| v.request_id == key.id && v.request_generation == key.generation)
        {
            if let Some(row) = feedback
                .waiting
                .iter_mut()
                .find(|v| v.request_generation == 0)
            {
                *row = abi::PendingPlacementWire {
                    request_id: key.id,
                    request_generation: key.generation,
                    queued_us: 0,
                    cpu_milli: 100,
                    memory_pages: 16,
                    peer_ready: u64::from(
                        feedback.measurement_valid & 4 != 0
                            && feedback.peer_cpu_milli >= 100
                            && feedback.peer_memory_pages >= 16,
                    ),
                };
            }
        }
    }
    ReadView {
        published_ns: crate::domain_platform::now_ns(),
        ready: READY.load(Ordering::Acquire),
        network: unsafe { *core::ptr::addr_of!(NETWORK) },
        effective: unsafe { *core::ptr::addr_of!(EFFECTIVE) },
        feedback,
    }
}
fn publish_view() {
    let _ = READ_VIEW.publish(owner_view());
}
// Keep the fresh CPU0 owner copy out of the control reader's stack frame. C
// projects only the fields it needs from the immutable published observation.
#[inline(never)]
fn inspect_owner<R>(inspect: impl FnOnce(&ReadView) -> Result<R, Error>) -> Result<R, Error> {
    inspect(&owner_view())
}
fn inspect_view<R>(inspect: impl FnOnce(&ReadView) -> Result<R, Error>) -> Result<R, Error> {
    if cyxia_arch_aarch64::cpu::slot() == 0 {
        return inspect_owner(inspect);
    }
    READ_VIEW
        .inspect(|view| {
            let now = crate::domain_platform::now_ns();
            if now < view.published_ns || now - view.published_ns > 50_000_000 {
                return Err(Error::NotReady);
            }
            inspect(view)
        })
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?
}
// This is the endpoint which actually owns the current ciphertext prefix.
// It changes only after the previous TCP generation has been retired.
static mut NETWORK: Option<(u64, ObjectKey)> = None;
static mut DESIRED: [Option<Desired>; 4] = [None; 4];
// Keep an independently confirmed installed policy. A rejected proposal is
// retained for exact reconciliation, but must not become the next action's
// claimed current parameter or permit a two-tier jump from the real baseline.
static mut EFFECTIVE: [Option<Desired>; 3] = [None; 3];
static mut FEEDBACK: DomainFeedback = DomainFeedback {
    tx: EMPTY,
    unauth: EMPTY,
    offer: EMPTY,
    placement: EMPTY,
    tx_ordinary: 0,
    tx_reserved: 0,
    auth_attempts: 0,
    auth_rejected: 0,
    auth_failures: 0,
    auth_slots: 0,
    recovery_slots: 0,
    pending_placements: 0,
    waiting_request_id: 0,
    waiting_request_generation: 0,
    peer_cpu_milli: 0,
    peer_memory_pages: 0,
    placement_fallbacks: 0,
    measurement_ms: 0,
    measurement_valid: 0,
    network: [0; 4],
    security: [0; 4],
    cluster: [0; 4],
    tx_last_ordinary: 0,
    tx_last_reserved: 0,
    waiting: [abi::PendingPlacementWire::EMPTY; 32],
    quote_stop: abi::QuoteStopReceiptWire::EMPTY,
    quotes_stopped: 0,
};
const EMPTY: PolicyReceiptWire = PolicyReceiptWire {
    version: 0,
    actual: 0,
    outcome: 0,
    plan_seq: 0,
    controller_epoch: 0,
    action_index: 0,
    request_id: 0,
    request_generation: 0,
};
fn owner() {
    assert_eq!(cyxia_arch_aarch64::cpu::slot(), 0);
}
pub fn bind_network(epoch: u64, endpoint: Option<ObjectKey>) -> Result<(), Error> {
    owner();
    if let Some(endpoint) = endpoint {
        if crate::domain_tasks::network_key(epoch)? != endpoint {
            return Err(Error::Stale);
        }
        unsafe {
            *core::ptr::addr_of_mut!(NETWORK) = Some((epoch, endpoint));
        }
    } else {
        let prior = unsafe { *core::ptr::addr_of!(NETWORK) };
        if prior.is_some_and(|(current, _)| current != epoch) {
            return Err(Error::Stale);
        }
        unsafe {
            *core::ptr::addr_of_mut!(NETWORK) = None;
        }
    }
    crate::peer_replay::transport(endpoint.map(|_| epoch));
    publish_view();
    Ok(())
}
fn network_dependencies(
    key: ObjectKey,
) -> Result<[Option<crate::domain_control::Prerequisite>; 2], Error> {
    if key
        != (ObjectKey {
            id: abi::TX_SERVICE_ID,
            generation: 1,
        })
    {
        return Err(Error::Stale);
    }
    let published = inspect_view(|view| view.network.ok_or(Error::NotReady))?;
    // The read gate is released first. C consumes CPU0's bounded-freshness
    // identity without entering a CPU0-only owner; CPU0 still checks directly.
    let target = dependencies::endpoint(
        published,
        cyxia_arch_aarch64::cpu::slot() == 0,
        crate::domain_tasks::network_key,
    )?;
    Ok([
        Some(crate::domain_control::Prerequisite { domain: 5, target }),
        None,
    ])
}
fn index(action: Action) -> Result<usize, Error> {
    match action {
        Action::TxBatch(_) => Ok(0),
        Action::UnauthRate(_) => Ok(1),
        Action::OfferCpu(_) => Ok(2),
        Action::Placement(_) => Ok(3),
        _ => Err(Error::Unsupported),
    }
}
fn value(action: Action) -> u64 {
    match action {
        Action::TxBatch(v) => v as u64,
        Action::UnauthRate(v) | Action::OfferCpu(v) | Action::Placement(v) => v as u64,
        _ => 0,
    }
}
fn wire(desired: Option<Desired>) -> PolicyWire {
    desired.map_or_else(PolicyWire::default, |d| PolicyWire {
        version: d.stamp.version,
        snapshot_ns: d.stamp.snapshot_ns,
        installed_until_ns: d.stamp.installed_until_ns,
        value: value(d.action),
        plan_seq: d.apply.plan_seq,
        controller_epoch: d.apply.controller_epoch,
        action_index: u64::from(d.apply.action_index),
    })
}
/// Call only while EL0 is stopped, immediately before the next entry. The
/// network owner supplies peer_ipv4 from its live socket; it is not RPC input.
pub fn prepare(shared: &mut Shared) {
    owner();
    let _ = requests::initialize(shared.boot_epoch);
    shared.monotonic_ns = crate::domain_platform::now_ns();
    let desired = unsafe { *core::ptr::addr_of!(DESIRED) };
    shared.domains.tx = wire(desired[0]);
    shared.domains.unauth = wire(desired[1]);
    shared.domains.offer = wire(desired[2]);
    shared.domains.placement = wire(desired[3]);
    shared.domains.placement_request_id = desired[3].map_or(0, |d| d.apply.target.id);
    shared.domains.placement_request_generation =
        desired[3].map_or(0, |d| d.apply.target.generation);
    let [cpu, pages, core, ledger] = crate::unified_task::capacity();
    shared.domains.available_cpu_milli = cpu;
    shared.domains.memory_pages = pages;
    shared.domains.core_generation = core;
    shared.domains.ledger_generation = ledger;
    shared.domains.quote_stop = quote_stop::input(shared.boot_epoch);
    READY.store(true, Ordering::Release);
    publish_view();
}
pub fn observe(shared: &Shared) {
    owner();
    if shared.version == abi::VERSION && shared.magic == abi::MAGIC {
        let before = unsafe { core::ptr::addr_of!(shared.feedback_sequence).read_volatile() };
        if before == 0 || before & 1 != 0 {
            return;
        }
        let feedback = unsafe { core::ptr::addr_of!(shared.domain_feedback).read_volatile() };
        core::sync::atomic::compiler_fence(Ordering::Acquire);
        let after = unsafe { core::ptr::addr_of!(shared.feedback_sequence).read_volatile() };
        if before != after {
            return;
        }
        unsafe {
            *core::ptr::addr_of_mut!(FEEDBACK) = feedback;
        }
        quote_stop::observe(feedback.quote_stop);
        let receipts = [feedback.tx, feedback.unauth, feedback.offer];
        for (slot, receipt) in receipts.into_iter().enumerate() {
            let desired = unsafe { (*core::ptr::addr_of!(DESIRED))[slot] };
            if let Some(desired) = desired
                && matching_receipt(desired, receipt)
                && applied_value(slot, desired.action, receipt)
            {
                unsafe {
                    (*core::ptr::addr_of_mut!(EFFECTIVE))[slot] = Some(desired);
                }
            }
        }
        publish_view();
    }
}
fn matching_receipt(desired: Desired, receipt: PolicyReceiptWire) -> bool {
    receipt.version == desired.stamp.version
        && receipt.plan_seq == desired.apply.plan_seq
        && receipt.controller_epoch == desired.apply.controller_epoch
        && receipt.action_index == u64::from(desired.apply.action_index)
        && receipt.request_id == desired.apply.target.id
        && receipt.request_generation == desired.apply.target.generation
}
fn applied_value(slot: usize, action: Action, receipt: PolicyReceiptWire) -> bool {
    receipt.outcome == abi::DOMAIN_APPLIED
        && (receipt.actual == value(action) || (slot == 2 && receipt.actual <= value(action)))
}
fn target(domain: u16, kind: u16, ordinal: usize) -> Option<ObjectKey> {
    inspect_view(|view| Ok(target_in(view, domain, kind, ordinal))).ok()?
}
fn target_in(view: &ReadView, domain: u16, kind: u16, ordinal: usize) -> Option<ObjectKey> {
    if !view.ready {
        return None;
    }
    if domain == 16 && kind == 2 {
        let feedback = &view.feedback;
        let waiting = feedback.waiting.get(ordinal)?;
        return (waiting.request_generation != 0).then_some(ObjectKey {
            id: waiting.request_id,
            generation: waiting.request_generation,
        });
    }
    if ordinal != 0 {
        return None;
    }
    let id = match (domain, kind) {
        (10, 1) => abi::TX_SERVICE_ID,
        (12, 1) => abi::UNAUTH_SERVICE_ID,
        (16, 1) => abi::OFFER_SERVICE_ID,
        _ => return None,
    };
    Some(ObjectKey { id, generation: 1 })
}
fn measurements(domain: u16, key: ObjectKey) -> Result<DomainObservation, Error> {
    inspect_view(|view| {
        let f = &view.feedback;
        let now = crate::domain_platform::now_ns() / 1_000_000;
        if domain == 16
            && key
                != (ObjectKey {
                    id: abi::OFFER_SERVICE_ID,
                    generation: 1,
                })
        {
            return placement_legal::observation(key, f, now);
        }
        let (bit, values) = match domain {
            10 => (1, f.network),
            12 => (2, f.security),
            16 => (4, f.cluster),
            _ => return Err(Error::Unsupported),
        };
        if f.measurement_valid & bit == 0 || now < f.measurement_ms || now - f.measurement_ms > 100
        {
            return Err(Error::NotReady);
        }
        Ok(DomainObservation::complete(values))
    })
}
fn current(domain: u16, kind: u16, key: ObjectKey) -> Result<Action, Error> {
    inspect_view(|view| {
        let baseline = match (domain, kind) {
            (10, 1) => Action::TxBatch(4),
            (12, 1) => Action::UnauthRate(16),
            (16, 1) => Action::OfferCpu(0),
            (16, 2) => Action::Placement(2),
            _ => return Err(Error::Unsupported),
        };
        if !(0..32).any(|ordinal| target_in(view, domain, kind, ordinal) == Some(key)) {
            return Err(Error::Stale);
        }
        if domain == 16 && kind == 1 && view.feedback.quotes_stopped == 1 {
            return Ok(baseline);
        }
        let effective = view.effective.get(index(baseline)?).copied().flatten();
        Ok(effective
            .filter(|d| d.apply.target == key && d.stamp.live(crate::domain_platform::now_ns()))
            .map_or(baseline, |d| d.action))
    })
}
fn legal(action: Action, key: ObjectKey, _: u64) -> Result<(), Error> {
    inspect_view(|view| legal_in(view, action, key))
}
fn legal_in(view: &ReadView, action: Action, key: ObjectKey) -> Result<(), Error> {
    action.validate()?;
    if !(0..32).any(|ordinal| target_in(view, action.domain(), action.kind(), ordinal) == Some(key))
    {
        return Err(Error::Stale);
    }
    if let Action::Placement(choice) = action {
        placement_legal::legal(
            choice,
            key,
            &view.feedback,
            crate::domain_platform::now_ns() / 1_000_000,
        )?;
    }
    Ok(())
}
fn target_features(action: Action, key: ObjectKey) -> Result<TargetFeatures, Error> {
    inspect_view(|view| {
        legal_in(view, action, key)?;
        if action == Action::Placement(1) {
            let f = &view.feedback;
            Ok(TargetFeatures {
                values: [Some(f.peer_cpu_milli), None, None, Some(1)],
            })
        } else {
            Ok(TargetFeatures::default())
        }
    })
}
fn apply(
    action: Action,
    apply: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<ExecutionState, Error> {
    owner();
    let slot = index(action)?;
    let old = unsafe { (*core::ptr::addr_of!(DESIRED))[slot] };
    // A completed placement leaves the live waiting queue. An exact old
    // invocation must still query its retained receipt, never re-admit it.
    if let Some(old) = old {
        if old.apply == apply {
            if old.action != action || old.stamp != stamp {
                return Err(Error::Conflict);
            }
            return reconcile(action, apply, stamp, now);
        }
    }
    legal(action, apply.target, now)?;
    if let Some(old) = old {
        old.stamp.accepts_action(action, stamp, now)?;
        // An unresolved one-shot may not be replaced just because the remote
        // adapter is taking longer than the control service's 50ms budget.
        if slot == 3
            && matches!(
                reconcile(old.action, old.apply, old.stamp, now)?,
                ExecutionState::Pending | ExecutionState::Unknown
            )
        {
            return Err(Error::Busy);
        }
    } else {
        PolicyStamp::default().accepts_action(action, stamp, now)?;
    }
    if matches!(action, Action::Placement(_)) {
        replay::release_target(apply.target)?;
    }
    unsafe {
        (*core::ptr::addr_of_mut!(DESIRED))[slot] = Some(Desired {
            action,
            apply,
            stamp,
        });
    }
    Ok(ExecutionState::Pending)
}
fn reconcile(
    action: Action,
    apply: ApplyId,
    stamp: PolicyStamp,
    _: u64,
) -> Result<ExecutionState, Error> {
    owner();
    let slot = index(action)?;
    let old = unsafe { (*core::ptr::addr_of!(DESIRED))[slot] }.ok_or(Error::Stale)?;
    if old.action != action || old.apply != apply || old.stamp != stamp {
        return Err(Error::Stale);
    }
    let f = unsafe { *core::ptr::addr_of!(FEEDBACK) };
    let r = [f.tx, f.unauth, f.offer, f.placement][slot];
    if !matching_receipt(old, r) {
        return Ok(ExecutionState::Unknown);
    }
    match r.outcome {
        abi::DOMAIN_APPLIED if applied_value(slot, action, r) => Ok(ExecutionState::Applied),
        abi::DOMAIN_REJECTED => Ok(ExecutionState::Failed(Error::Again)),
        abi::DOMAIN_EXPIRED => Ok(ExecutionState::Failed(Error::Expired)),
        abi::DOMAIN_PENDING => Ok(ExecutionState::Pending),
        _ => Ok(ExecutionState::Unknown),
    }
}
pub fn register_control() -> Result<(), Error> {
    crate::domain_control::register_dependencies(10, network_dependencies)?;
    for (domain, kind) in [(10, 1), (12, 1), (16, 1), (16, 2)] {
        crate::domain_control::register(crate::domain_control::Family {
            domain,
            kind,
            target,
            observe: measurements,
            current,
            legal,
            target_features,
            apply,
            reconcile,
        })?;
    }
    Ok(())
}
