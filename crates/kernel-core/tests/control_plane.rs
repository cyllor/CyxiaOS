use cyxia_kernel_core::control_plane::{
    Epochs, Error, Identity, Plane,
    budget::{Budget, Lease},
    cores::{Limits, Ownership, Phase, Proof, ScaleProposal, State, Ticket},
    policy,
    queue::{Channel, QueueError},
};

fn limits() -> Limits {
    Limits {
        resource_epoch: 1,
        min_control_cores: 1,
        min_control_capacity: 100,
        min_business_capacity: 100,
        committed_business_capacity: 100,
        protected_control: 0,
        protected_business: 0,
        cooldown_ticks: 3,
    }
}
fn topology(control: u64) -> Ownership<4> {
    Ownership::new(15, control, [100; 4], [1, 2, 4, 8], limits()).unwrap()
}
fn proposal(o: &Ownership<4>, control: u64, sequence: u64) -> ScaleProposal {
    ScaleProposal {
        generation: o.snapshot().generation,
        resource_epoch: 1,
        sequence,
        desired_control: control,
        deadline: 100,
    }
}
fn invariant(o: &Ownership<4>) {
    let s = o.snapshot();
    let masks = [s.control, s.business, s.transition, s.quarantined];
    assert_eq!(masks.iter().fold(0, |a, b| a | b), s.online);
    for i in 0..4 {
        for j in 0..i {
            assert_eq!(masks[i] & masks[j], 0);
        }
    }
    for cpu in 0..4 {
        assert!(!(s.permits(cpu, Plane::Control) && s.permits(cpu, Plane::Business)));
    }
}
fn handoff(o: &mut Ownership<4>, t: Ticket, changed: u64) {
    for cpu in 0..4 {
        if changed & (1 << cpu) != 0 {
            o.acknowledge_drain(t, cpu, Proof::DRAIN, 11).unwrap();
            o.acknowledge_handoff(t, cpu, Proof::HANDOFF, 11).unwrap();
            invariant(o);
        }
    }
}
#[test]
fn dynamic_expand_shrink_does_not_fix_cpu_number_or_count() {
    let mut o = topology(1);
    for (index, target) in [3, 7, 5, 4].into_iter().enumerate() {
        let now = 10 + index as u64 * 10;
        let changed = o.snapshot().control ^ target;
        let t = o
            .begin(proposal(&o, target, index as u64 + 1), now, limits())
            .unwrap();
        assert_eq!(o.snapshot().transition, changed);
        invariant(&o);
        for cpu in 0..4 {
            if changed & (1 << cpu) != 0 {
                assert!(!o.snapshot().permits(cpu, Plane::Business));
                assert!(!o.snapshot().permits(cpu, Plane::Control));
                o.acknowledge_drain(t, cpu, Proof::DRAIN, now + 1).unwrap();
                o.acknowledge_handoff(t, cpu, Proof::HANDOFF, now + 1)
                    .unwrap();
            }
        }
        let s = o.publish(t, now + 2, limits()).unwrap();
        assert_eq!(s.control, target);
        invariant(&o);
    }
    assert_eq!(o.core(0).unwrap().owner, Some(Plane::Business));
    assert_eq!(o.core(2).unwrap().owner, Some(Plane::Control));
}
#[test]
fn rejected_scale_is_atomic() {
    let mut o = topology(1);
    let before = o.snapshot();
    for target in [0, 1, 15, 16, 2] {
        assert!(o.begin(proposal(&o, target, 1), 10, limits()).is_err());
        assert_eq!(o.snapshot(), before);
    }
    let mut p = proposal(&o, 3, 1);
    p.generation += 1;
    assert_eq!(o.begin(p, 10, limits()), Err(Error::Stale));
    p = proposal(&o, 3, 1);
    p.resource_epoch = 2;
    assert_eq!(o.begin(p, 10, limits()), Err(Error::Stale));
    p = proposal(&o, 3, 1);
    p.deadline = 10;
    assert_eq!(o.begin(p, 10, limits()), Err(Error::Expired));
    assert_eq!(o.snapshot(), before);
}
#[test]
fn current_contracts_and_protected_irqs_block_unsafe_scale() {
    let mut o = topology(1);
    let mut l = limits();
    l.committed_business_capacity = 300;
    assert_eq!(o.begin(proposal(&o, 3, 1), 10, l), Err(Error::Denied));
    l = limits();
    l.protected_business = 2;
    assert_eq!(o.begin(proposal(&o, 3, 1), 10, l), Err(Error::Denied));
    l = limits();
    l.protected_control = 8;
    assert_eq!(o.begin(proposal(&o, 3, 1), 10, l), Err(Error::Denied));
    invariant(&o);
}
#[test]
fn smt_siblings_cannot_be_split_between_planes() {
    let mut o = Ownership::new(15, 3, [100; 4], [3, 3, 12, 12], limits()).unwrap();
    let p = ScaleProposal {
        generation: 1,
        resource_epoch: 1,
        sequence: 1,
        desired_control: 7,
        deadline: 100,
    };
    assert_eq!(o.begin(p, 1, limits()), Err(Error::Denied));
    assert!(Ownership::new(15, 1, [100; 4], [3, 3, 12, 12], limits()).is_err());
    assert!(Ownership::new(15, 3, [100; 4], [3, 2, 12, 12], limits()).is_err());
    let t = o.fault(0, 2).unwrap();
    assert_eq!(o.snapshot().quarantined, 3);
    o.acknowledge_recovery(t, 0, Proof::RECOVERY, 3).unwrap();
    assert_eq!(o.restore(t, 4, limits()), Err(Error::NotReady));
}
#[test]
fn cannot_publish_before_every_drain_and_handoff_proof() {
    let mut o = topology(1);
    let t = o.begin(proposal(&o, 7, 1), 10, limits()).unwrap();
    assert_eq!(o.publish(t, 11, limits()), Err(Error::NotReady));
    assert_eq!(
        o.acknowledge_handoff(t, 1, Proof::HANDOFF, 11),
        Err(Error::NotReady)
    );
    assert_eq!(
        o.acknowledge_drain(t, 1, Proof(Proof::DRAIN.0 & !Proof::IRQ), 11),
        Err(Error::NotReady)
    );
    handoff(&mut o, t, 2);
    assert_eq!(o.publish(t, 12, limits()), Err(Error::NotReady));
    o.acknowledge_drain(t, 2, Proof::DRAIN, 12).unwrap();
    assert_eq!(
        o.acknowledge_handoff(t, 2, Proof(Proof::STOPPED), 12),
        Err(Error::NotReady)
    );
    o.acknowledge_handoff(t, 2, Proof::HANDOFF, 12).unwrap();
    assert_eq!(o.publish(t, 13, limits()).unwrap().control, 7);
    assert_eq!(o.publish(t, 13, limits()), Err(Error::Stale));
}
#[test]
fn timeout_does_not_release_unconfirmed_cores() {
    let mut o = topology(3);
    let mut p = proposal(&o, 1, 1);
    p.deadline = 12;
    let t = o.begin(p, 10, limits()).unwrap();
    let recovery = o.expire(12).unwrap().unwrap();
    assert_eq!(o.core(1).unwrap().owner, Some(Plane::Control));
    assert_eq!(o.core(1).unwrap().state, State::Quarantined);
    assert!(!o.snapshot().permits(1, Plane::Business));
    assert_eq!(
        o.acknowledge_drain(t, 1, Proof::DRAIN, 13),
        Err(Error::Stale)
    );
    assert_eq!(o.restore(recovery, 13, limits()), Err(Error::NotReady));
    o.acknowledge_recovery(recovery, 1, Proof::RECOVERY, 14)
        .unwrap();
    assert_eq!(o.restore(recovery, 15, limits()).unwrap().control, 3);
    invariant(&o);
}
#[test]
fn faults_invalidate_all_old_acknowledgements_and_retain_owner() {
    let mut o = topology(1);
    let t = o.begin(proposal(&o, 3, 1), 10, limits()).unwrap();
    handoff(&mut o, t, 2);
    let r = o.fault(0, 12).unwrap();
    assert_eq!(o.snapshot().quarantined, 3);
    assert_eq!(o.core(0).unwrap().owner, Some(Plane::Control));
    assert_eq!(o.core(1).unwrap().owner, Some(Plane::Business));
    assert_eq!(o.publish(t, 13, limits()), Err(Error::Stale));
    o.acknowledge_recovery(r, 0, Proof::RECOVERY, 13).unwrap();
    let r2 = o.fault(2, 14).unwrap();
    assert_eq!(
        o.acknowledge_recovery(r, 1, Proof::RECOVERY, 15),
        Err(Error::Stale)
    );
    assert_eq!(o.restore(r2, 15, limits()), Err(Error::NotReady));
    assert!(o.snapshot().permits(3, Plane::Business));
    invariant(&o);
}
#[test]
fn recovery_revalidates_current_commitments_not_an_old_default() {
    let mut o = topology(3);
    let r = o.fault(1, 10).unwrap();
    o.acknowledge_recovery(r, 1, Proof::RECOVERY, 11).unwrap();
    let mut l = limits();
    l.resource_epoch = 2;
    l.committed_business_capacity = 300;
    assert_eq!(o.restore(r, 12, l), Err(Error::Denied));
    assert_eq!(o.core(1).unwrap().state, State::Quarantined);
    l.committed_business_capacity = 200;
    assert_eq!(o.restore(r, 12, l).unwrap().control, 3);
}
#[test]
fn changed_resource_epoch_stops_publication_and_clock_cannot_go_backwards() {
    let mut o = topology(1);
    let t = o.begin(proposal(&o, 3, 1), 10, limits()).unwrap();
    handoff(&mut o, t, 2);
    let mut l = limits();
    l.resource_epoch = 2;
    assert_eq!(o.publish(t, 12, l), Err(Error::Stale));
    assert_eq!(o.publish(t, 9, limits()), Err(Error::Clock));
    assert_eq!(o.snapshot().control, 1);
    invariant(&o);
}
#[test]
fn cooldown_and_consumed_decision_id_survive_an_abort() {
    let mut o = topology(1);
    let t = o.begin(proposal(&o, 3, 1), 10, limits()).unwrap();
    let r = o.abort(t, 11).unwrap();
    o.acknowledge_recovery(r, 1, Proof::RECOVERY, 12).unwrap();
    o.restore(r, 13, limits()).unwrap();
    assert_eq!(o.begin(proposal(&o, 3, 1), 16, limits()), Err(Error::Stale));
    assert_eq!(o.begin(proposal(&o, 3, 2), 14, limits()), Err(Error::Busy));
    o.begin(proposal(&o, 3, 2), 16, limits()).unwrap();
}
#[test]
fn invalid_cpu_and_single_core_fail_closed_without_panics() {
    let mut o = topology(1);
    assert_eq!(o.fault(64, 1), Err(Error::Invalid));
    assert!(!o.snapshot().permits(64, Plane::Business));
    assert!(Ownership::new(1, 1, [100], [1], limits()).is_err());
    assert!(Ownership::<0>::new(0, 0, [], [], limits()).is_err());
    assert!(Ownership::new(15, 1, [0, 100, 100, 100], [1, 2, 4, 8], limits()).is_err());
}
#[test]
fn exhaustive_four_core_transitions_preserve_exclusive_ownership() {
    for old in 1..15 {
        for target in 1..15 {
            let mut o = topology(old);
            let before = o.snapshot();
            match o.begin(proposal(&o, target, 1), 10, limits()) {
                Ok(t) => {
                    invariant(&o);
                    handoff(&mut o, t, old ^ target);
                    o.publish(t, 12, limits()).unwrap();
                    assert_eq!(o.snapshot().control, target);
                    invariant(&o);
                }
                Err(_) => assert_eq!(o.snapshot(), before),
            }
        }
    }
}
fn id(n: u64) -> Identity {
    Identity {
        id: n,
        generation: 1,
    }
}
fn epochs() -> Epochs {
    Epochs {
        boot: 1,
        controller: 1,
        model: 1,
        resources: 1,
        cores: 1,
    }
}
fn env() -> policy::Environment {
    policy::Environment {
        epochs: epochs(),
        cores: topology(1).snapshot(),
        now: 10,
        limits: policy::Limits {
            max_units: 8,
            max_budget_ticks: 4,
            max_lifetime: 100,
            allowed_cpus: 15,
        },
    }
}
fn plan() -> policy::Proposal {
    policy::Proposal {
        epochs: epochs(),
        subject: id(20),
        domain: 0,
        sequence: 1,
        valid_from: 0,
        expires_at: 100,
        plane: Plane::Business,
        cpus: 2,
        units: 4,
        budget_ticks: 4,
    }
}
fn bank() -> policy::Bank<16> {
    policy::Bank::new(id(10), epochs()).unwrap()
}
#[test]
fn only_authenticated_controller_on_a_control_cpu_can_publish() {
    let mut b = bank();
    let p = plan();
    assert_eq!(b.accept(id(11), 0, p, env()), Err(Error::Denied));
    assert_eq!(b.accept(id(10), 1, p, env()), Err(Error::Denied));
    b.accept(id(10), 0, p, env()).unwrap();
    assert_eq!(
        b.select(0, id(20), 1, Plane::Business, env()),
        policy::Selection::Policy(p)
    );
}
#[test]
fn replay_revoke_and_failed_replacements_never_restore_old_policy() {
    let mut b = bank();
    let p = plan();
    b.accept(id(10), 0, p, env()).unwrap();
    assert_eq!(b.accept(id(10), 0, p, env()), Err(Error::Stale));
    let mut bad = p;
    bad.sequence = 2;
    bad.cpus = 1;
    assert_eq!(b.accept(id(10), 0, bad, env()), Err(Error::Denied));
    assert_eq!(
        b.select(0, id(20), 1, Plane::Business, env()),
        policy::Selection::Policy(p)
    );
    b.revoke(0).unwrap();
    assert_eq!(b.accept(id(10), 0, p, env()), Err(Error::Stale));
}
#[test]
fn late_arrival_does_not_extend_original_expiry() {
    let mut b = bank();
    let mut e = env();
    e.now = 99;
    b.accept(id(10), 0, plan(), e).unwrap();
    e.now = 100;
    assert_eq!(
        b.select(0, id(20), 1, Plane::Business, e),
        policy::Selection::SafeExec(Error::Expired)
    );
    let mut p = plan();
    p.sequence = 2;
    assert_eq!(b.accept(id(10), 0, p, e), Err(Error::Expired));
}
#[test]
fn every_epoch_and_object_generation_is_checked_on_execution() {
    let mut b = bank();
    b.accept(id(10), 0, plan(), env()).unwrap();
    for field in 0..5 {
        let mut e = env();
        match field {
            0 => e.epochs.boot += 1,
            1 => e.epochs.controller += 1,
            2 => e.epochs.model += 1,
            3 => e.epochs.resources += 1,
            _ => e.epochs.cores += 1,
        }
        assert_eq!(
            b.select(0, id(20), 1, Plane::Business, e),
            policy::Selection::SafeExec(Error::Stale)
        );
    }
    let subject = Identity {
        id: 20,
        generation: 2,
    };
    assert_eq!(
        b.select(0, subject, 1, Plane::Business, env()),
        policy::Selection::SafeExec(Error::Stale)
    );
}
#[test]
fn execution_rechecks_limits_and_falls_back_without_waiting() {
    let mut b = bank();
    b.accept(id(10), 0, plan(), env()).unwrap();
    let mut e = env();
    e.limits.max_units = 3;
    assert_eq!(
        b.select(0, id(20), 1, Plane::Business, e),
        policy::Selection::SafeExec(Error::Denied)
    );
    e = env();
    e.cores.phase = Phase::Recovery;
    assert_eq!(
        b.select(0, id(20), 1, Plane::Business, e),
        policy::Selection::SafeExec(Error::NotReady)
    );
    assert_eq!(
        b.select(15, id(20), 1, Plane::Business, env()),
        policy::Selection::SafeExec(Error::NotReady)
    );
}
#[test]
fn model_change_cannot_reset_sequence_and_controller_restart_rejects_old_epoch() {
    let mut b = bank();
    b.accept(id(10), 0, plan(), env()).unwrap();
    let mut e = env();
    e.epochs.model = 2;
    b.reconfigure(id(10), e.epochs, 11).unwrap();
    e.now = 11;
    let mut p = plan();
    p.epochs = e.epochs;
    assert_eq!(b.accept(id(10), 0, p, e), Err(Error::Stale));
    p.sequence = 2;
    b.accept(id(10), 0, p, e).unwrap();
    assert_eq!(b.reconfigure(id(11), e.epochs, 11), Err(Error::Stale));
    e.epochs.controller = 2;
    b.reconfigure(id(11), e.epochs, 12).unwrap();
    e.now = 12;
    assert_eq!(b.accept(id(11), 0, p, e), Err(Error::Stale));
    p.epochs = e.epochs;
    p.sequence = 1;
    b.accept(id(11), 0, p, e).unwrap();
    assert_eq!(b.reconfigure(id(10), epochs(), 13), Err(Error::Stale));
}
#[test]
fn malformed_domains_windows_and_resources_are_rejected() {
    let mut b = bank();
    for i in 0..7 {
        let mut p = plan();
        match i {
            0 => p.domain = 16,
            1 => p.subject.generation = 0,
            2 => p.sequence = 0,
            3 => p.valid_from = 11,
            4 => p.cpus = 0,
            5 => p.units = 0,
            _ => p.budget_ticks = 0,
        };
        assert_eq!(b.accept(id(10), 0, p, env()), Err(Error::Invalid));
    }
    let mut p = plan();
    p.expires_at = 101;
    assert_eq!(b.accept(id(10), 0, p, env()), Err(Error::Denied));
    assert!(policy::Bank::<0>::new(id(1), epochs()).is_err());
}
#[test]
fn all_domains_have_identical_policy_access_semantics() {
    let mut b = bank();
    for domain in 0..16 {
        let p = policy::Proposal { domain, ..plan() };
        b.accept(id(10), 0, p, env()).unwrap();
        assert_eq!(
            b.select(domain, id(20), 1, Plane::Business, env()),
            policy::Selection::Policy(p)
        );
    }
}
fn lease() -> Lease {
    Lease {
        thread: id(20),
        sequence: 1,
        window: 1,
        starts_at: 0,
        ends_at: 100,
        quota: 10,
    }
}
#[test]
fn thread_budget_stops_at_quota_and_absolute_deadline() {
    let mut b = Budget::new(lease(), 0).unwrap();
    assert_eq!(b.allowance(0, 20), Ok(10));
    assert_eq!(b.charge(7, 7), Ok(false));
    assert_eq!(b.allowance(8, 20), Ok(3));
    assert_eq!(b.allowance(99, 20), Ok(1));
    assert_eq!(b.charge(5, 100), Ok(true));
    assert_eq!(b.allowance(100, 10), Ok(0));
    assert_eq!(b.spent(), 12);
}
#[test]
fn same_window_policy_replacement_never_refills_thread_budget() {
    let mut b = Budget::new(lease(), 0).unwrap();
    b.charge(7, 10).unwrap();
    let l = Lease {
        sequence: 2,
        quota: 9,
        ..lease()
    };
    b.replace(l, 11).unwrap();
    assert_eq!(b.allowance(11, 9), Ok(2));
    assert_eq!(
        b.replace(
            Lease {
                sequence: 3,
                starts_at: 1,
                ..l
            },
            12
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        b.replace(
            Lease {
                sequence: 3,
                window: 2,
                ..l
            },
            12
        ),
        Err(Error::Denied)
    );
    assert_eq!(b.spent(), 7);
}
#[test]
fn only_nonoverlapping_new_window_can_reset_consumption() {
    let mut b = Budget::new(lease(), 0).unwrap();
    b.charge(10, 10).unwrap();
    let l = Lease {
        sequence: 2,
        window: 2,
        starts_at: 100,
        ends_at: 200,
        ..lease()
    };
    b.replace(l, 100).unwrap();
    assert_eq!(b.spent(), 0);
    assert_eq!(
        b.replace(
            Lease {
                sequence: 3,
                thread: Identity {
                    id: 20,
                    generation: 2
                },
                ..l
            },
            101
        ),
        Err(Error::Stale)
    );
    assert_eq!(b.charge(1, 99), Err(Error::Clock));
}
#[test]
fn overflowing_charge_saturates_and_cannot_create_allowance() {
    let mut b = Budget::new(lease(), 0).unwrap();
    b.charge(u64::MAX, 1).unwrap();
    b.charge(u64::MAX, 2).unwrap();
    assert_eq!(b.spent(), u64::MAX);
    assert_eq!(b.allowance(3, 10), Ok(0));
}
#[test]
fn bounded_queue_is_fifo_full_and_wrap_safe() {
    let mut q = Channel::<3, 2>::new();
    assert_eq!(q.capacity(), 2);
    let (mut s, mut r) = q.split().unwrap();
    assert_eq!(r.try_receive(), Err(QueueError::Empty));
    for n in 0..1000 {
        assert_eq!(s.try_send([n, !n]), Ok(()));
        assert_eq!(s.try_send([n + 1, !(n + 1)]), Ok(()));
        assert_eq!(s.try_send([0, 0]), Err(QueueError::Full));
        assert_eq!(r.try_receive(), Ok([n, !n]));
        assert_eq!(r.try_receive(), Ok([n + 1, !(n + 1)]));
    }
}
#[test]
fn queue_reset_requires_exclusive_ownership_and_drops_stale_messages() {
    let mut q = Channel::<2, 1>::new();
    {
        let (mut s, _r) = q.split().unwrap();
        s.try_send([99]).unwrap();
    }
    q.reset();
    let (_s, mut r) = q.split().unwrap();
    assert_eq!(r.try_receive(), Err(QueueError::Empty));
    assert!(Channel::<1, 1>::new().split().is_err());
    assert!(Channel::<2, 0>::new().split().is_err());
}
#[test]
fn concurrent_queue_does_not_publish_torn_payloads() {
    let mut q = Channel::<17, 8>::new();
    let (mut s, mut r) = q.split().unwrap();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            for n in 1u64..=50000 {
                let value = [n, !n, n + 1, n * 3, n ^ 123, n.rotate_left(7), n - 1, 42];
                while s.try_send(value) == Err(QueueError::Full) {
                    std::thread::yield_now();
                }
            }
        });
        scope.spawn(move || {
            for n in 1u64..=50000 {
                let value = loop {
                    match r.try_receive() {
                        Ok(v) => break v,
                        Err(QueueError::Empty) => std::thread::yield_now(),
                        other => panic!("{other:?}"),
                    }
                };
                assert_eq!(
                    value,
                    [n, !n, n + 1, n * 3, n ^ 123, n.rotate_left(7), n - 1, 42]
                );
            }
        });
    });
}
use cyxia_kernel_core::control_plane::{
    manager::{Manager, Receipt},
    wire::{Request, WORDS},
};
fn manager() -> Manager<4, 16> {
    Manager::new(topology(1), id(10), epochs(), limits(), [env().limits; 16]).unwrap()
}
#[test]
fn wire_roundtrip_and_reserved_fields_are_checked() {
    let p = Request::Policy(plan());
    assert_eq!(Request::decode(p.encode()), Ok(p));
    let c = Request::Scale {
        epochs: epochs(),
        proposal: proposal(&topology(1), 3, 1),
    };
    assert_eq!(Request::decode(c.encode()), Ok(c));
    for at in [0, 1, 18, 19] {
        let mut w = p.encode();
        w[at] ^= 8;
        assert_eq!(Request::decode(w), Err(Error::Invalid));
    }
    let mut w = c.encode();
    w[8] = 1;
    assert_eq!(Request::decode(w), Err(Error::Invalid));
    let mut w = p.encode();
    w[14] = 2;
    assert_eq!(Request::decode(w), Err(Error::Invalid));
}
#[test]
fn manager_migration_automatically_invalidates_cached_and_queued_plans() {
    let mut m = manager();
    m.submit(id(10), 0, Request::Policy(plan()).encode(), 10)
        .unwrap();
    let c = Request::Scale {
        epochs: m.epochs(),
        proposal: proposal(&topology(1), 3, 1),
    };
    let t = match m.submit(id(10), 0, c.encode(), 11).unwrap() {
        Receipt::Draining(t) => t,
        _ => panic!(),
    };
    assert!(matches!(
        m.select(0, id(20), 1, Plane::Business, 11),
        policy::Selection::SafeExec(_)
    ));
    assert_eq!(
        m.submit(id(10), 0, Request::Policy(plan()).encode(), 11),
        Err(Error::Stale)
    );
    m.acknowledge_drain(t, 1, Proof::DRAIN, 12).unwrap();
    m.acknowledge_handoff(t, 1, Proof::HANDOFF, 12).unwrap();
    m.publish(t, 13).unwrap();
    assert_eq!(m.snapshot().control, 3);
    assert!(matches!(
        m.select(0, id(20), 2, Plane::Business, 13),
        policy::Selection::SafeExec(_)
    ));
}
#[test]
fn model_publication_aborts_pending_old_model_handoff() {
    let mut m = manager();
    let c = Request::Scale {
        epochs: m.epochs(),
        proposal: proposal(&topology(1), 3, 1),
    };
    let t = match m.submit(id(10), 0, c.encode(), 10).unwrap() {
        Receipt::Draining(t) => t,
        _ => panic!(),
    };
    let recovery = m.replace_controller(id(10), 1, 2, 11).unwrap().unwrap();
    assert_eq!(m.snapshot().phase, Phase::Recovery);
    assert_eq!(m.publish(t, 12), Err(Error::Stale));
    assert_eq!(m.restore(recovery, 12), Err(Error::NotReady));
    m.acknowledge_recovery(recovery, 1, Proof::RECOVERY, 13)
        .unwrap();
    m.restore(recovery, 14).unwrap();
    assert_eq!(m.epochs().model, 2);
    assert_eq!(m.snapshot().control, 1);
}
#[test]
fn manager_resource_epoch_change_prevents_pending_publication() {
    let mut m = manager();
    let c = Request::Scale {
        epochs: m.epochs(),
        proposal: proposal(&topology(1), 3, 1),
    };
    let t = match m.submit(id(10), 0, c.encode(), 10).unwrap() {
        Receipt::Draining(t) => t,
        _ => panic!(),
    };
    m.acknowledge_drain(t, 1, Proof::DRAIN, 11).unwrap();
    m.acknowledge_handoff(t, 1, Proof::HANDOFF, 11).unwrap();
    let mut l = limits();
    l.resource_epoch = 2;
    m.update_limits(l, [env().limits; 16], 12).unwrap();
    assert_eq!(m.publish(t, 13), Err(Error::Stale));
    assert_eq!(m.snapshot().transition, 2);
}
#[test]
fn controller_queue_drain_is_bounded_and_bad_messages_do_not_block_good_ones() {
    let mut m = manager();
    let mut channel = Channel::<5, WORDS>::new();
    let (mut tx, mut rx) = channel.split().unwrap();
    tx.try_send([0; WORDS]).unwrap();
    tx.try_send(Request::Policy(plan()).encode()).unwrap();
    let mut p = plan();
    p.sequence = 2;
    tx.try_send(Request::Policy(p).encode()).unwrap();
    let r = m.drain(id(10), 0, &mut rx, 2, 10).unwrap();
    assert_eq!((r.received, r.accepted, r.rejected), (2, 1, 1));
    assert_eq!(
        m.select(0, id(20), 1, Plane::Business, 10),
        policy::Selection::Policy(plan())
    );
    assert_eq!(m.drain(id(10), 1, &mut rx, 1, 10), Err(Error::Denied));
    assert_eq!(m.drain(id(10), 0, &mut rx, 1, 10).unwrap().accepted, 1);
}
#[test]
fn restarted_controller_can_start_new_scale_sequence_but_old_epoch_cannot() {
    let mut m = manager();
    let mut c = Request::Scale {
        epochs: m.epochs(),
        proposal: proposal(&topology(1), 3, 99),
    };
    let t = match m.submit(id(10), 0, c.encode(), 10).unwrap() {
        Receipt::Draining(t) => t,
        _ => panic!(),
    };
    m.acknowledge_drain(t, 1, Proof::DRAIN, 11).unwrap();
    m.acknowledge_handoff(t, 1, Proof::HANDOFF, 11).unwrap();
    m.publish(t, 12).unwrap();
    m.replace_controller(id(11), 2, 1, 13).unwrap();
    assert_eq!(m.submit(id(11), 0, c.encode(), 15), Err(Error::Stale));
    c = Request::Scale {
        epochs: m.epochs(),
        proposal: ScaleProposal {
            generation: m.epochs().cores,
            resource_epoch: 1,
            sequence: 1,
            desired_control: 1,
            deadline: 100,
        },
    };
    assert!(matches!(
        m.submit(id(11), 0, c.encode(), 15),
        Ok(Receipt::Draining(_))
    ));
}
