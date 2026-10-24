use cyxia_prototype::cores::{CoreSet, Cores, Error, Plane, StopDomain, ThreadSpec};

fn set(bits: u64) -> CoreSet {
    CoreSet::from_bits(bits)
}
fn system() -> Cores {
    Cores::new(set(0b1111), set(1)).unwrap()
}
fn begin(c: &mut Cores, target: u64, now: u64) -> cyxia_prototype::cores::Ticket {
    let s = c.snapshot();
    c.begin(set(target), s.core_generation, s.ledger_generation, now)
        .unwrap()
}
fn prove(c: &mut Cores, request: cyxia_prototype::cores::StopRequest) {
    for domain in StopDomain::ALL {
        c.record_stop_completion(request, domain).unwrap();
    }
}
fn spec(id: u64, budget: u16, allowed: u64, cpu: usize) -> ThreadSpec {
    ThreadSpec {
        thread_id: id,
        budget_milli: budget,
        allowed_mask: set(allowed),
        assigned_cpu: cpu,
    }
}

#[test]
fn scale_one_two_one_preserves_source_until_ack() {
    let mut c = system();
    let t = begin(&mut c, 3, 0);
    let s = c.snapshot();
    assert_eq!(
        (s.control.bits(), s.business.bits(), s.transition.bits()),
        (1, 14, 0)
    );
    assert_eq!(s.draining.bits(), 2);
    assert!(!s.permits(1, Plane::Business));
    assert_eq!(c.ack_quiescent(t, 1), Err(Error::MissingProof));
    assert_eq!(c.publish(t, 1), Err(Error::MissingProof));
    let r = c.stop_request(t, 1).unwrap();
    prove(&mut c, r);
    c.ack_quiescent(t, 1).unwrap();
    assert_eq!(c.snapshot().transition.bits(), 2);
    assert_eq!(c.snapshot().business.bits(), 12);
    c.publish(t, 2).unwrap();
    assert_eq!(c.snapshot().control.bits(), 3);
    let t = begin(&mut c, 1, 1000);
    assert_eq!(c.snapshot().control.bits(), 3);
    let r = c.stop_request(t, 1).unwrap();
    prove(&mut c, r);
    c.ack_quiescent(t, 1).unwrap();
    c.publish(t, 1001).unwrap();
    assert_eq!(c.snapshot().control.bits(), 1);
    assert!(c.snapshot().permits(1, Plane::Business));
}

#[test]
fn timeout_and_late_receipts_do_not_invent_stop_proof() {
    let mut c = system();
    let t = begin(&mut c, 3, 10);
    let r = c.stop_request(t, 1).unwrap();
    assert!(!c.expire(209).unwrap());
    assert!(c.expire(210).unwrap());
    let s = c.snapshot();
    assert_eq!(
        (s.control.bits(), s.business.bits(), s.quarantined.bits()),
        (1, 14, 0)
    );
    assert_eq!(s.suspect.bits(), 2);
    assert!(!s.permits(1, Plane::Business));
    assert_eq!(
        c.record_stop_completion(r, StopDomain::Tasks),
        Err(Error::Stale)
    );
    assert_eq!(c.ack_quiescent(t, 1), Err(Error::Stale));
    assert_eq!(c.publish(t, 211), Err(Error::Stale));
    let stop = c.suspect(1).unwrap();
    prove(&mut c, stop);
    c.confirm_stopped(stop).unwrap();
    assert_eq!(c.snapshot().quarantined.bits(), 2);
    assert_eq!(c.snapshot().business.bits(), 12);
}

#[test]
fn cancel_quarantines_only_fully_proven_cores() {
    for acknowledged in [false, true] {
        let mut c = system();
        let t = begin(&mut c, 3, 0);
        let r = c.stop_request(t, 1).unwrap();
        for d in StopDomain::ALL.into_iter().take(5) {
            c.record_stop_completion(r, d).unwrap();
        }
        assert_eq!(c.ack_quiescent(t, 1), Err(Error::MissingProof));
        if acknowledged {
            c.record_stop_completion(r, StopDomain::References).unwrap();
            c.ack_quiescent(t, 1).unwrap();
        }
        c.expire(200).unwrap();
        let s = c.snapshot();
        assert_eq!(s.quarantined.bits(), if acknowledged { 2 } else { 0 });
        assert_eq!(s.business.bits(), if acknowledged { 12 } else { 14 });
        assert_eq!(s.suspect.bits(), if acknowledged { 0 } else { 2 });
        assert_eq!(s.transition.bits(), 0);
        assert_eq!(
            c.record_stop_completion(r, StopDomain::References),
            Err(Error::Stale)
        );
    }
}

#[test]
fn healthy_minima_overlap_and_stale_generations_are_checked() {
    let mut c = system();
    let s = c.snapshot();
    for target in [0, 15, 2, 16] {
        assert!(
            c.begin(set(target), s.core_generation, s.ledger_generation, 0)
                .is_err()
        );
        assert_eq!(c.snapshot(), s);
    }
    c.suspect(2).unwrap();
    assert_eq!(
        c.begin(set(3), s.core_generation, s.ledger_generation, 0),
        Err(Error::Stale)
    );
    let s = c.snapshot();
    assert_eq!(
        c.begin(set(7), s.core_generation, s.ledger_generation, 0),
        Err(Error::Unhealthy)
    );
    c.suspect(0).unwrap();
    let s = c.snapshot();
    assert_eq!(
        c.begin(set(3), s.core_generation, s.ledger_generation, 0),
        Err(Error::Unhealthy)
    );
}

#[test]
fn proof_requires_every_domain_and_rejects_replay() {
    let mut c = system();
    let t = begin(&mut c, 3, 0);
    let r = c.stop_request(t, 1).unwrap();
    assert_eq!(c.stop_request(t, 9), Err(Error::UnknownCpu));
    assert_eq!(c.stop_request(t, 0), Err(Error::Invalid));
    for d in StopDomain::ALL.into_iter().take(5) {
        c.record_stop_completion(r, d).unwrap();
    }
    assert_eq!(c.ack_quiescent(t, 1), Err(Error::MissingProof));
    assert_eq!(
        c.record_stop_completion(r, StopDomain::Tasks),
        Err(Error::Duplicate)
    );
    c.record_stop_completion(r, StopDomain::References).unwrap();
    c.ack_quiescent(t, 1).unwrap();
    assert_eq!(c.ack_quiescent(t, 1), Err(Error::Duplicate));
    c.publish(t, 1).unwrap();
    let next = begin(&mut c, 1, 1000);
    let before = c.snapshot();
    assert_eq!(
        c.record_stop_completion(r, StopDomain::Dma),
        Err(Error::Stale)
    );
    assert_eq!(c.ack_quiescent(t, 1), Err(Error::Stale));
    assert_eq!(c.snapshot(), before);
    assert_eq!(c.ack_quiescent(next, 1), Err(Error::MissingProof));
}

#[test]
fn deadline_checked_at_publish_without_explicit_timer_poll() {
    let mut c = system();
    let t = begin(&mut c, 3, 0);
    let r = c.stop_request(t, 1).unwrap();
    prove(&mut c, r);
    c.ack_quiescent(t, 1).unwrap();
    assert_eq!(c.publish(t, 200), Err(Error::Expired));
    assert_eq!(c.snapshot().quarantined.bits(), 2);
    assert_eq!(c.publish(t, 201), Err(Error::Stale));
}

#[test]
fn aggregate_spare_capacity_does_not_allow_per_core_overcommit() {
    let mut c = system();
    c.admit(spec(1, 600, 2, 1)).unwrap();
    let before = c.snapshot();
    assert_eq!(c.admit(spec(2, 600, 2, 1)), Err(Error::Capacity));
    assert_eq!(c.snapshot(), before);
    c.admit(spec(2, 300, 2, 1)).unwrap();
    assert_eq!(c.committed_milli(1), Ok(900));
}

#[test]
fn migration_reserves_both_sides_and_preserves_consumption() {
    let mut c = system();
    let thread = c.admit(spec(1, 600, 6, 1)).unwrap();
    c.charge(thread, 400).unwrap();
    c.begin_migration(thread, 2).unwrap();
    assert_eq!(c.committed_milli(1), Ok(600));
    assert_eq!(c.committed_milli(2), Ok(600));
    assert_eq!(c.admit(spec(2, 400, 4, 2)), Err(Error::Capacity));
    assert_eq!(c.reservation(thread).unwrap().assigned_cpu, 1);
    c.commit_migration(thread).unwrap();
    assert_eq!(c.committed_milli(1), Ok(400));
    assert_eq!(c.reservation(thread).unwrap().consumed_milli, 400);
    assert_eq!(c.charge(thread, 201), Err(Error::Budget));
    c.charge(thread, 200).unwrap();
    assert_eq!(c.charge(thread, 1), Err(Error::Budget));
    c.advance_window(1).unwrap();
    c.charge(thread, 600).unwrap();
    assert_eq!(c.advance_window(1), Err(Error::Stale));
}

#[test]
fn core_transfer_cannot_discard_thread_reservations() {
    let mut c = system();
    let h = c.admit(spec(1, 500, 6, 1)).unwrap();
    let s = c.snapshot();
    assert_eq!(
        c.begin(set(3), s.core_generation, s.ledger_generation, 0),
        Err(Error::Capacity)
    );
    c.begin_migration(h, 2).unwrap();
    let s = c.snapshot();
    assert_eq!(
        c.begin(set(3), s.core_generation, s.ledger_generation, 0),
        Err(Error::Capacity)
    );
    c.commit_migration(h).unwrap();
    begin(&mut c, 3, 0);
    assert_eq!(c.admit(spec(2, 100, 2, 1)), Err(Error::Unhealthy));
}

#[test]
fn invalid_thread_affinity_and_stale_handle_rejected() {
    let mut c = system();
    assert_eq!(c.admit(spec(1, 600, 4, 1)), Err(Error::Affinity));
    assert_eq!(c.admit(spec(1, 901, 2, 1)), Err(Error::Invalid));
    assert_eq!(c.admit(spec(1, 0, 2, 1)), Err(Error::Invalid));
    let old = c.admit(spec(1, 100, 2, 1)).unwrap();
    c.release(old).unwrap();
    let new = c.admit(spec(1, 100, 2, 1)).unwrap();
    assert_ne!(old, new);
    assert_eq!(c.charge(old, 1), Err(Error::Stale));
    assert_eq!(c.begin_migration(new, 2), Err(Error::Affinity));
    c.suspect(1).unwrap();
    assert_eq!(c.charge(new, 1), Err(Error::Unhealthy));
}

#[test]
fn fixed_capacity_is_sixty_four_threads() {
    let mut c = system();
    for id in 0..64 {
        c.admit(spec(id, 1, 2, 1)).unwrap();
    }
    assert_eq!(c.admit(spec(64, 1, 2, 1)), Err(Error::Full));
}

#[test]
fn invalid_masks_and_time_overflow_do_not_mutate() {
    assert_eq!(Cores::new(set(0), set(0)).err(), Some(Error::Invalid));
    assert_eq!(Cores::new(set(3), set(4)).err(), Some(Error::Invalid));
    let mut c = system();
    let s = c.snapshot();
    assert_eq!(
        c.begin(set(3), s.core_generation, s.ledger_generation, u64::MAX),
        Err(Error::Exhausted)
    );
    assert_eq!(c.snapshot(), s);
    assert!(!s.permits(64, Plane::Control));
    assert_eq!(c.suspect(64), Err(Error::UnknownCpu));
}

#[test]
fn suspicion_of_already_proven_transition_is_non_mutating() {
    let mut c = system();
    let t = begin(&mut c, 3, 0);
    let r = c.stop_request(t, 1).unwrap();
    prove(&mut c, r);
    c.ack_quiescent(t, 1).unwrap();
    let before = c.snapshot();
    assert_eq!(c.suspect(1), Err(Error::Invalid));
    assert_eq!(c.snapshot(), before);
    c.publish(t, 1).unwrap();
}

#[test]
fn fault_cancels_transfer_and_invalidates_all_old_collectors() {
    let mut c = system();
    let t = begin(&mut c, 3, 0);
    let r1 = c.stop_request(t, 1).unwrap();
    c.record_stop_completion(r1, StopDomain::Dispatch).unwrap();
    let r2 = c.suspect(1).unwrap();
    let fresh = c.suspect(1).unwrap();
    let before = c.snapshot();
    assert_eq!(before.business.bits(), 14);
    assert_eq!(before.suspect.bits(), 2);
    assert_eq!(
        c.record_stop_completion(r1, StopDomain::Tasks),
        Err(Error::Stale)
    );
    assert_eq!(
        c.record_stop_completion(r2, StopDomain::Tasks),
        Err(Error::Stale)
    );
    assert_eq!(c.confirm_stopped(fresh), Err(Error::MissingProof));
    assert_eq!(c.snapshot(), before);
    prove(&mut c, fresh);
    c.confirm_stopped(fresh).unwrap();
    assert_eq!(c.confirm_stopped(fresh), Err(Error::Stale));
}

#[test]
fn ledger_generation_and_faulted_migration_are_rechecked() {
    let mut c = system();
    let old = c.snapshot();
    let h = c.admit(spec(1, 500, 12, 2)).unwrap();
    assert_eq!(
        c.begin(set(3), old.core_generation, old.ledger_generation, 0),
        Err(Error::Stale)
    );
    c.charge(h, 200).unwrap();
    c.begin_migration(h, 3).unwrap();
    c.suspect(3).unwrap();
    assert_eq!(c.commit_migration(h), Err(Error::Unhealthy));
    assert_eq!(c.committed_milli(3), Ok(500));
    c.cancel_migration(h).unwrap();
    assert_eq!(c.committed_milli(3), Ok(0));
    assert_eq!(c.reservation(h).unwrap().consumed_milli, 200);
}

#[test]
fn quarantine_does_not_release_thread_budget_or_reservations() {
    let mut c = system();
    let h = c.admit(spec(1, 600, 6, 1)).unwrap();
    c.charge(h, 250).unwrap();
    let r = c.suspect(1).unwrap();
    prove(&mut c, r);
    c.confirm_stopped(r).unwrap();
    assert_eq!(c.committed_milli(1), Ok(600));
    assert_eq!(c.reservation(h).unwrap().consumed_milli, 250);
    assert_eq!(c.begin_migration(h, 2), Err(Error::Unhealthy));
}

#[test]
fn every_four_cpu_partition_and_intermediate_stage_preserves_cover() {
    fn partition(c: &Cores) {
        let s = c.snapshot();
        let masks = [
            s.control.bits(),
            s.business.bits(),
            s.transition.bits(),
            s.quarantined.bits(),
        ];
        assert_eq!(masks.iter().fold(0, |a, b| a | b), s.online.bits());
        for i in 0..4 {
            for j in i + 1..4 {
                assert_eq!(masks[i] & masks[j], 0);
            }
        }
        for cpu in 0..4 {
            assert!(!(s.permits(cpu, Plane::Control) && s.permits(cpu, Plane::Business)));
        }
    }
    for initial in 1u64..15 {
        for target in 1u64..15 {
            let mut c = Cores::new(set(15), set(initial)).unwrap();
            let s = c.snapshot();
            let result = c.begin(set(target), s.core_generation, s.ledger_generation, 0);
            if (initial ^ target).count_ones() != 1 {
                assert!(result.is_err());
                assert_eq!(c.snapshot(), s);
                continue;
            }
            if let Ok(t) = result {
                partition(&c);
                for cpu in 0..4 {
                    if (initial ^ target) & (1 << cpu) != 0 {
                        let r = c.stop_request(t, cpu).unwrap();
                        prove(&mut c, r);
                        c.ack_quiescent(t, cpu).unwrap();
                        partition(&c);
                    }
                }
                c.publish(t, 1).unwrap();
                partition(&c);
                assert_eq!(c.snapshot().control.bits(), target);
            } else {
                assert_eq!(c.snapshot(), s);
            }
        }
    }
}

#[test]
fn review_migration_cannot_recycle_spent_source_capacity() {
    let mut c = system();
    let a = c.admit(spec(1, 900, 6, 1)).unwrap();
    c.charge(a, 900).unwrap();
    c.begin_migration(a, 2).unwrap();
    c.commit_migration(a).unwrap();
    let before = c.snapshot();
    assert_eq!(c.admit(spec(2, 1, 2, 1)), Err(Error::Capacity));
    assert_eq!(c.snapshot(), before);
    assert_eq!(c.committed_milli(1), Ok(900));
    c.advance_window(1).unwrap();
    let b = c.admit(spec(2, 900, 2, 1)).unwrap();
    c.charge(b, 900).unwrap();
}

#[test]
fn review_release_and_repeated_readmission_keep_source_debt() {
    let mut c = system();
    for id in 0..3 {
        let a = c.admit(spec(id, 300, 2, 1)).unwrap();
        c.charge(a, 300).unwrap();
        c.release(a).unwrap();
        assert_eq!(c.release(a), Err(Error::Stale));
    }
    let before = c.snapshot();
    assert_eq!(c.admit(spec(3, 1, 2, 1)), Err(Error::Capacity));
    assert_eq!(c.snapshot(), before);
    assert_eq!(c.advance_window(0), Err(Error::Stale));
    assert_eq!(c.admit(spec(3, 1, 2, 1)), Err(Error::Capacity));
    c.advance_window(1).unwrap();
    let b = c.admit(spec(3, 900, 2, 1)).unwrap();
    c.charge(b, 900).unwrap();
    c.release(b).unwrap();
    assert_eq!(c.advance_window(1), Err(Error::Stale));
    assert_eq!(c.admit(spec(4, 1, 2, 1)), Err(Error::Capacity));
}

#[test]
fn review_multi_hop_and_return_preserve_each_cpus_spending() {
    let mut c = system();
    let a = c.admit(spec(1, 900, 14, 1)).unwrap();
    c.charge(a, 300).unwrap();
    c.begin_migration(a, 2).unwrap();
    c.commit_migration(a).unwrap();
    c.charge(a, 300).unwrap();
    c.begin_migration(a, 3).unwrap();
    c.commit_migration(a).unwrap();
    c.charge(a, 300).unwrap();
    // Returning with no remaining thread quota must not erase source debt.
    c.begin_migration(a, 1).unwrap();
    c.commit_migration(a).unwrap();
    assert_eq!(c.charge(a, 1), Err(Error::Budget));
    c.release(a).unwrap();
    for cpu in 1..4 {
        assert_eq!(c.committed_milli(cpu), Ok(300));
        let b = c.admit(spec(cpu as u64 + 10, 600, 1 << cpu, cpu)).unwrap();
        c.charge(b, 600).unwrap();
        c.release(b).unwrap();
        assert_eq!(
            c.admit(spec(cpu as u64 + 20, 1, 1 << cpu, cpu)),
            Err(Error::Capacity)
        );
    }
}

#[test]
fn review_normal_begin_rejects_multiple_changes_and_same_size_swaps() {
    for (initial, target) in [(1, 7), (7, 1), (3, 5)] {
        let mut c = Cores::new(set(15), set(initial)).unwrap();
        let before = c.snapshot();
        assert_eq!(
            c.begin(
                set(target),
                before.core_generation,
                before.ledger_generation,
                0
            ),
            Err(Error::Invalid)
        );
        assert_eq!(c.snapshot(), before);
    }
}

fn complete_change(c: &mut Cores, ticket: cyxia_prototype::cores::Ticket, cpu: usize, now: u64) {
    let r = c.stop_request(ticket, cpu).unwrap();
    prove(c, r);
    c.ack_quiescent(ticket, cpu).unwrap();
    c.publish(ticket, now).unwrap();
}

#[test]
fn review_normal_proposal_spacing_and_clock_regression() {
    let mut c = system();
    let t = begin(&mut c, 3, 1000);
    complete_change(&mut c, t, 1, 1001);
    let before = c.snapshot();
    for (now, error) in [
        (999, Error::ClockRegression),
        (1000, Error::RateLimited),
        (1999, Error::RateLimited),
    ] {
        assert_eq!(
            c.begin(
                set(1),
                before.core_generation,
                before.ledger_generation,
                now
            ),
            Err(error)
        );
        assert_eq!(c.snapshot(), before);
    }
    let t = begin(&mut c, 1, 2000);
    complete_change(&mut c, t, 1, 2001);
}

#[test]
fn review_cancellation_still_consumes_normal_proposal_interval() {
    let mut c = Cores::new(set(31), set(1)).unwrap();
    let t = begin(&mut c, 3, 0);
    assert!(c.expire(200).unwrap());
    let before = c.snapshot();
    assert_eq!(
        c.begin(
            set(5),
            before.core_generation,
            before.ledger_generation,
            999
        ),
        Err(Error::RateLimited)
    );
    assert_eq!(c.snapshot(), before);
    // Urgent stop proof collection remains available during the normal cooldown.
    let r = c.suspect(1).unwrap();
    prove(&mut c, r);
    c.confirm_stopped(r).unwrap();
    assert_eq!(c.publish(t, 999), Err(Error::Stale));
    let next = begin(&mut c, 5, 1000);
    c.suspect(2).unwrap();
    let before = c.snapshot();
    // Repeated cancellation cannot reset the last successful begin timestamp.
    assert_eq!(
        c.begin(
            set(9),
            before.core_generation,
            before.ledger_generation,
            1999
        ),
        Err(Error::RateLimited)
    );
    assert_eq!(c.snapshot(), before);
    assert_eq!(c.publish(next, 2000), Err(Error::Stale));
    let next = begin(&mut c, 9, 2000);
    complete_change(&mut c, next, 3, 2001);
}

#[test]
fn review_failed_validation_does_not_consume_rate_slot() {
    let mut c = system();
    let h = c.admit(spec(1, 100, 2, 1)).unwrap();
    let s = c.snapshot();
    assert_eq!(
        c.begin(set(3), s.core_generation, s.ledger_generation, 500),
        Err(Error::Capacity)
    );
    c.release(h).unwrap();
    let t = begin(&mut c, 3, 500);
    complete_change(&mut c, t, 1, 501);
    let s = c.snapshot();
    assert_eq!(
        c.begin(set(7), s.core_generation, s.ledger_generation, 1499),
        Err(Error::RateLimited)
    );
    let t = begin(&mut c, 1, 1500);
    complete_change(&mut c, t, 1, 1501);
}
