#[allow(dead_code)]
#[path = "../../../user/prototype-runtime/abi.rs"]
mod abi;
use cyxia_prototype::model::Model;

// Removing the control-load feature or swapping candidate meanings breaks this.
#[test]
fn model_selects_both_core_targets_from_observed_control_backlog() {
    let bytes = abi::model_bytes();
    let model = Model::parse(&bytes).unwrap();
    let high = abi::core_candidates(12);
    let low = abi::core_candidates(0);
    assert_eq!(model.select(&high).unwrap(), 1);
    assert_eq!(model.select(&low).unwrap(), 0);
    assert_eq!(model.score(&high[1]), 12);
    assert_eq!(model.score(&low[0]), 4);
}

#[path = "../../../user/prototype-runtime/dynamic.rs"]
mod dynamic;
use cyxia_prototype::cores::{CoreSet, Cores, Error, Plane, StopDomain};
use dynamic::{Handoff, NativeStop};

#[test]
fn delayed_task_or_irq_and_missing_tlb_cannot_change_owner() {
    let mut owner = Cores::new(CoreSet::from_bits(15), CoreSet::from_bits(2)).unwrap();
    let before = owner.snapshot();
    let mut handoff = Handoff::new(&before, 6, 1000).unwrap();
    let mut stop = NativeStop::default();
    assert_eq!(handoff.poll(&mut owner, stop, 1001), Ok(false));
    assert_eq!(owner.snapshot().control, before.control);
    assert_eq!(owner.snapshot().business, before.business);
    assert_eq!(owner.snapshot().draining.bits(), 4);
    stop.dispatch = true;
    stop.tasks = true;
    stop.dma = true;
    stop.references = true;
    assert_eq!(handoff.poll(&mut owner, stop, 1002), Ok(false));
    assert_eq!(owner.snapshot().control, before.control);
    assert_eq!(owner.snapshot().business, before.business);
    assert_eq!(owner.snapshot().draining.bits(), 4);
    stop.irq = true;
    assert_eq!(handoff.poll(&mut owner, stop, 1003), Ok(false));
    assert_eq!(owner.snapshot().control, before.control);
    assert_eq!(owner.snapshot().business, before.business);
    assert_eq!(owner.snapshot().draining.bits(), 4);
    stop.tlb = true;
    assert_eq!(handoff.poll(&mut owner, stop, 1004), Ok(true));
    assert_eq!(owner.snapshot().control.bits(), 6);
    assert!(owner.permits(2, Plane::Control));
    assert!(owner.permits(0, Plane::Business));
    assert!(owner.permits(3, Plane::Business));
}

#[test]
fn missing_ack_keeps_old_owner_suspect_and_never_quarantines() {
    let mut owner = Cores::new(CoreSet::from_bits(15), CoreSet::from_bits(2)).unwrap();
    let mut handoff = Handoff::new(&owner.snapshot(), 6, 0).unwrap();
    assert_eq!(
        handoff.poll(&mut owner, NativeStop::default(), 200),
        Err(Error::Expired)
    );
    let state = owner.snapshot();
    assert_eq!(state.control.bits(), 2);
    assert_eq!(state.business.bits(), 13);
    assert_eq!(state.quarantined.bits(), 0);
    assert_eq!(state.suspect.bits(), 4);
    assert!(!state.permits(2, Plane::Business));
    assert_eq!(
        handoff.poll(&mut owner, NativeStop::default(), 201),
        Err(Error::Stale)
    );
}

#[test]
fn real_owner_rejects_stale_requests_and_rate_limits_second_transition() {
    let mut owner = Cores::new(CoreSet::from_bits(15), CoreSet::from_bits(2)).unwrap();
    let old = owner.snapshot();
    let complete = NativeStop {
        dispatch: true,
        tasks: true,
        irq: true,
        dma: true,
        tlb: true,
        references: true,
    };
    let mut first = Handoff::new(&old, 6, 1000).unwrap();
    assert_eq!(first.poll(&mut owner, complete, 1001), Ok(true));
    let mut stale = Handoff::new(&old, 6, 2000).unwrap();
    assert_eq!(stale.poll(&mut owner, complete, 2000), Err(Error::Stale));
    let mut early = Handoff::new(&owner.snapshot(), 2, 1999).unwrap();
    assert_eq!(
        early.poll(&mut owner, complete, 1999),
        Err(Error::RateLimited)
    );
    let mut second = Handoff::new(&owner.snapshot(), 2, 2001).unwrap();
    assert_eq!(second.poll(&mut owner, complete, 2002), Ok(true));
    assert_eq!(owner.snapshot().control.bits(), 2);
    // Old CPU-generation domain receipts cannot apply to a later operation.
    let before = owner.snapshot();
    let t = owner
        .begin(
            CoreSet::from_bits(6),
            before.core_generation,
            before.ledger_generation,
            3002,
        )
        .unwrap();
    let r = owner.stop_request(t, 2).unwrap();
    owner.record_stop_completion(r, StopDomain::Tasks).unwrap();
    assert_eq!(owner.ack_quiescent(t, 2), Err(Error::MissingProof));
}

// If DRAIN drops the source reservation or leaves it dispatchable this fails.
#[test]
fn draining_a_retiring_workload_keeps_its_reservation_until_native_stop() {
    use cyxia_prototype::cores::ThreadSpec;
    let mut owner = Cores::new(CoreSet::from_bits(15), CoreSet::from_bits(2)).unwrap();
    let handle = owner
        .admit(ThreadSpec {
            thread_id: 2,
            budget_milli: 900,
            allowed_mask: CoreSet::from_bits(4),
            assigned_cpu: 2,
        })
        .unwrap();
    owner.charge(handle, 300).unwrap();
    let state = owner.snapshot();
    let ticket = owner
        .begin_retiring(
            CoreSet::from_bits(6),
            state.core_generation,
            state.ledger_generation,
            1000,
            handle,
        )
        .unwrap();
    assert_eq!(owner.snapshot().control.bits(), 2);
    assert_eq!(owner.snapshot().business.bits(), 13);
    assert_eq!(owner.snapshot().draining.bits(), 4);
    assert_eq!(owner.reservation(handle).unwrap().consumed_milli, 300);
    assert_eq!(owner.charge(handle, 1), Err(Error::Unhealthy));
    assert_eq!(owner.publish(ticket, 1001), Err(Error::MissingProof));
    owner.expire(1200).unwrap();
    assert_eq!(owner.reservation(handle).unwrap().budget_milli, 900);
    assert_eq!(owner.snapshot().suspect.bits(), 4);
}

#[path = "../../../user/prototype-runtime/idle.rs"]
mod idle;

// Catch a missing heartbeat, a heartbeat flood after a delay, or a strict- >
// boundary that leaves a budget-waiting control context parked another turn.
#[test]
fn idle_wake_heartbeat_is_immediate_bounded_and_resumes_after_delay() {
    let mut pulse = idle::WakePulse::new(10);
    assert!(pulse.due(100));
    assert!(!pulse.due(100));
    assert!(!pulse.due(109));
    assert!(pulse.due(110));
    assert!(pulse.due(1000));
    assert!(!pulse.due(1000));
    assert!(!pulse.due(1009));
    assert!(pulse.due(1010));
}
