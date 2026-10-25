use cyxia_peer_billing::*;
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        Family, ReplayGroup,
        capture::RunKey,
        reward::{CpuClass, CpuCoverage, CpuInterval, OBSERVATION_NS},
    },
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
fn pair() -> (Keys, Keys) {
    let a = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
    let b = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    (
        Keys::new(&[1; 32], &a, &b).unwrap(),
        Keys::new(&[2; 32], &b, &a).unwrap(),
    )
}
fn binding() -> Binding {
    Binding {
        origin: Endpoint {
            node: [3; 32],
            boot: 4,
        },
        participant: Endpoint {
            node: [5; 32],
            boot: 6,
        },
        session: [7; 32],
        run: RunKey {
            boot_epoch: 4,
            trial_id: 8,
            generation: 9,
        },
        family: Family {
            domain: 10,
            kind: 1,
        },
        baseline: false,
        owner: ObjectKey {
            id: 11,
            generation: 1,
        },
        target: ObjectKey {
            id: 10,
            generation: 1,
        },
        group: ReplayGroup {
            seed: 81,
            workload: [12; 32],
            initial_image: [13; 32],
        },
        frozen_scope_hash: [14; 32],
    }
}

#[test]
fn only_separate_billing_key_authenticates_exact_node_boot_session_and_bytes() {
    let (a, b) = pair();
    let binding = binding();
    let mut payload = [0; BINDING_BYTES];
    assert_eq!(binding.encode(&mut payload), Ok(BINDING_BYTES));
    assert_eq!(Binding::decode(&payload), Ok(binding));
    let h = Header {
        kind: FREEZE,
        sequence: 1,
        source: binding.origin,
        destination: binding.participant,
        session: binding.session,
    };
    let mut bytes = [0; PACKET_BYTES];
    let n = a.encode(h, &payload, &mut bytes).unwrap();
    let decoded = b
        .decode(
            &bytes[..n],
            binding.origin.node,
            binding.participant,
            Some(binding.session),
        )
        .unwrap();
    assert_eq!(decoded.header, h);
    assert_eq!(decoded.body, payload);
    assert!(
        b.decode(
            &bytes[..n],
            binding.origin.node,
            Endpoint {
                boot: 7,
                ..binding.participant
            },
            Some(binding.session)
        )
        .is_err()
    );
    assert!(
        b.decode(
            &bytes[..n],
            binding.origin.node,
            binding.participant,
            Some([8; 32])
        )
        .is_err()
    );
    assert!(
        a.decode(
            &bytes[..n],
            binding.origin.node,
            binding.participant,
            Some(binding.session)
        )
        .is_err()
    );
    bytes[HEADER_BYTES + 17] ^= 1;
    assert!(matches!(
        b.decode(
            &bytes[..n],
            binding.origin.node,
            binding.participant,
            Some(binding.session)
        ),
        Err(Error::Signature)
    ));
}

#[test]
fn signed_summary_without_all_exact_raw_intervals_is_incomplete() {
    let binding = binding();
    let values = [CpuInterval {
        node: binding.participant.node,
        core: 0,
        start_ns: 1_000_000_000,
        end_ns: 1_000_000_100,
        class: CpuClass::ExecutorWork,
    }];
    let mut bytes = [0; INTERVAL_BYTES];
    encode_interval(values[0], &mut bytes).unwrap();
    assert_eq!(decode_interval(&bytes), Ok(values[0]));
    let mut hash = Sha256::new();
    hash.update(b"CYXIA_KERNEL_CPU_TRACE_1.3\0");
    hash.update(bytes);
    let seal = TraceSeal {
        binding_hash: binding.hash().unwrap(),
        owner: binding.owner,
        coverage: CpuCoverage {
            node: binding.participant.node,
            first_ns: 100,
            observation_ns: 1_000_000_000,
            observation_end_ns: 1_000_000_000 + OBSERVATION_NS,
            closing_ns: 1_000_000_001 + OBSERVATION_NS,
            required: 3,
            reported: 3,
        },
        count: 1,
        intervals_hash: hash.finalize().into(),
        frozen_other_domains: [21; 32],
        missing_events: 0,
        ordinary_warmup_ns: 0,
        later_workload_ns: 0,
    };
    let mut encoded = [0; SEAL_BYTES];
    assert_eq!(seal.encode(&mut encoded), Ok(SEAL_BYTES));
    assert_eq!(TraceSeal::decode(&encoded), Ok(seal));
    let mut assembler = Assembler::new(binding).unwrap();
    assert_eq!(assembler.finish(seal), Err(Error::Incomplete));
    assert_eq!(assembler.append(1, &values), Err(Error::Stale));
    assembler.append(0, &values).unwrap();
    assert_eq!(assembler.append(0, &values), Err(Error::Stale));
    assert_eq!(
        assembler.finish(TraceSeal {
            missing_events: 1,
            ..seal
        }),
        Err(Error::Incomplete)
    );
    assert_eq!(
        assembler.finish(TraceSeal {
            binding_hash: [11; 32],
            ..seal
        }),
        Err(Error::Incomplete)
    );
    assembler.finish(seal).unwrap();
    assert_eq!(assembler.sealed(), Some(seal));
    assert_eq!(assembler.append(1, &values), Err(Error::Stale));
}

#[test]
fn simultaneous_reservation_yields_exactly_one_unstarted_owner_and_never_cancels_frozen_work() {
    let low = [1; 32];
    let high = [2; 32];
    assert_eq!(
        arbitrate(low, high, true, false, false),
        Arbitration::Decline
    );
    assert_eq!(
        arbitrate(high, low, true, false, false),
        Arbitration::YieldUnstarted
    );
    assert_eq!(
        arbitrate(high, low, true, true, false),
        Arbitration::Decline
    );
    assert_eq!(
        arbitrate(high, low, false, false, true),
        Arbitration::Decline
    );
    assert_eq!(
        arbitrate(high, low, false, false, false),
        Arbitration::Accept
    );
    let (a, b) = pair();
    let binding = binding();
    let mut payload = [0; BINDING_BYTES];
    binding.encode(&mut payload).unwrap();
    let mut bytes = [0; PACKET_BYTES];
    let n = b
        .encode(
            Header {
                kind: DECLINED,
                sequence: 7,
                source: binding.participant,
                destination: binding.origin,
                session: binding.session,
            },
            &payload,
            &mut bytes,
        )
        .unwrap();
    let signed = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    assert_eq!(Binding::decode(signed.body).unwrap(), binding);
    assert!(
        a.decode(
            &bytes[..n],
            binding.participant.node,
            Endpoint {
                boot: 5,
                ..binding.origin
            },
            Some(binding.session)
        )
        .is_err()
    );
}

#[test]
fn lost_raw_chunk_ack_and_real_resigning_for_new_session_cannot_double_import_or_change_body() {
    let (a, b) = pair();
    let binding = binding();
    let interval = CpuInterval {
        node: binding.participant.node,
        core: 0,
        start_ns: 1_000_000_000,
        end_ns: 1_000_000_100,
        class: CpuClass::ExecutorWork,
    };
    let mut body = [0; INTERVAL_BYTES];
    encode_interval(interval, &mut body).unwrap();
    let h = Header {
        kind: TRACE,
        sequence: 19,
        source: binding.participant,
        destination: binding.origin,
        session: binding.session,
    };
    let mut bytes = [0; PACKET_BYTES];
    let n = b.encode(h, &body, &mut bytes).unwrap();
    let first = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    let mut cursor = ReceiveCursor::new();
    cursor.rebind(binding.participant.boot, false).unwrap();
    let mut actual = Assembler::new(binding).unwrap();
    assert!(cursor.fresh(&first).unwrap());
    actual
        .append(0, &[decode_interval(first.body).unwrap()])
        .unwrap();
    cursor.accepted(&first).unwrap();
    // No ACK reached the sender. The operation is re-signed only after a new
    // authenticated session; the retained logical sequence and body remain.
    let session = [22; 32];
    let n = b
        .encode(Header { session, ..h }, &body, &mut bytes)
        .unwrap();
    cursor.rebind(binding.participant.boot, true).unwrap();
    let retry = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(session),
        )
        .unwrap();
    assert!(!cursor.fresh(&retry).unwrap());
    assert_eq!(actual.count(), 1);
    assert!(
        a.decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(binding.session)
        )
        .is_err()
    );
    body[40] ^= 1;
    let n = b
        .encode(Header { session, ..h }, &body, &mut bytes)
        .unwrap();
    let changed = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(session),
        )
        .unwrap();
    assert_eq!(cursor.fresh(&changed), Err(Error::Conflict));
    assert_eq!(
        cursor.rebind(binding.participant.boot + 1, true),
        Err(Error::Stale)
    );
    assert!(cursor.rebind(binding.participant.boot + 1, false).is_ok());
}

#[test]
fn excluded_partial_trace_requires_exact_signed_raw_hash_and_cannot_become_a_complete_seal() {
    let (a, b) = pair();
    let binding = binding();
    let interval = CpuInterval {
        node: binding.participant.node,
        core: 0,
        start_ns: 1_000_000_000,
        end_ns: 1_000_000_100,
        class: CpuClass::ExecutorWork,
    };
    let mut raw = [0; INTERVAL_BYTES];
    encode_interval(interval, &mut raw).unwrap();
    let mut h = Sha256::new();
    h.update(b"CYXIA_KERNEL_CPU_TRACE_1.3\0");
    h.update(raw);
    let trace = TraceSeal {
        binding_hash: binding.hash().unwrap(),
        owner: binding.owner,
        coverage: CpuCoverage {
            node: binding.participant.node,
            first_ns: 100,
            observation_ns: 1_000_000_000,
            observation_end_ns: 1_000_000_000 + OBSERVATION_NS,
            closing_ns: 1_000_000_001 + OBSERVATION_NS,
            required: 3,
            reported: 0,
        },
        count: 1,
        intervals_hash: h.finalize().into(),
        frozen_other_domains: [21; 32],
        missing_events: 2,
        ordinary_warmup_ns: 100,
        later_workload_ns: 30,
    };
    let excluded = ExcludedSeal {
        trace,
        exclusion: Exclusion {
            reasons: MISSING_EVENTS,
            drained_ns: trace.coverage.closing_ns,
            failure: None,
        },
    };
    assert_eq!(trace.encode(&mut [0; SEAL_BYTES]), Err(Error::Incomplete));
    let mut body = [0; EXCLUDED_BYTES];
    excluded.encode(&mut body).unwrap();
    assert_eq!(
        ExcludedSeal::decode(&body[..body.len() - FAILURE_BYTES]),
        Ok(excluded),
        "previously signed 240-byte excluded bodies remain readable without reconstructing their signatures"
    );
    let mut bytes = [0; PACKET_BYTES];
    let n = b
        .encode(
            Header {
                kind: EXCLUDED,
                sequence: 20,
                source: binding.participant,
                destination: binding.origin,
                session: binding.session,
            },
            &body,
            &mut bytes,
        )
        .unwrap();
    assert_eq!(n, EXCLUDED_PACKET_BYTES);
    let authenticated = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    let received = ExcludedSeal::decode(authenticated.body).unwrap();
    let mut assembler = Assembler::new(binding).unwrap();
    assert_eq!(assembler.finish_excluded(received), Err(Error::Incomplete));
    assembler.append(0, &[interval]).unwrap();
    assert_eq!(
        assembler.finish_excluded(ExcludedSeal {
            trace: TraceSeal {
                intervals_hash: [31; 32],
                ..trace
            },
            ..received
        }),
        Err(Error::Incomplete)
    );
    assert!(
        ExcludedSeal {
            exclusion: Exclusion {
                reasons: 0,
                ..received.exclusion
            },
            ..received
        }
        .validate()
        .is_err()
    );
    assembler.finish_excluded(received).unwrap();
    assert!(assembler.sealed().is_none());
    assert_eq!(
        assembler.finish(TraceSeal {
            missing_events: 0,
            coverage: CpuCoverage {
                reported: 3,
                ..trace.coverage
            },
            ..trace
        }),
        Err(Error::Conflict)
    );
}

#[test]
fn preparation_cancel_uses_original_reservation_and_never_discards_an_issued_start() {
    let reservation = binding();
    let real_run = RunKey {
        trial_id: 241,
        generation: 55,
        ..reservation.run
    };
    let captured = Binding {
        run: real_run,
        frozen_scope_hash: [29; 32],
        ..reservation
    };
    assert_eq!(
        preparation_abort_binding(reservation, reservation, None, None, false, false),
        Ok(reservation)
    );
    // bind_scope changed the local capture identity, but START was never
    // issued. The remote owner still knows only the signed FREEZE identity.
    assert_eq!(
        preparation_abort_binding(
            reservation,
            captured,
            Some(real_run),
            Some(real_run),
            false,
            false
        ),
        Ok(reservation)
    );
    assert_eq!(
        preparation_abort_binding(reservation, captured, Some(real_run), None, false, false),
        Err(Error::Conflict)
    );
    assert_eq!(
        preparation_abort_binding(
            reservation,
            captured,
            Some(real_run),
            Some(reservation.run),
            false,
            false
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        preparation_abort_binding(
            reservation,
            Binding {
                group: ReplayGroup {
                    seed: 82,
                    ..captured.group
                },
                ..captured
            },
            Some(real_run),
            Some(real_run),
            false,
            false
        ),
        Err(Error::Conflict)
    );
    // A START ACK can empty the outbox before STARTED arrives. The immutable
    // issued flag still blocks cancellation of that genuine unknown operation.
    assert_eq!(
        preparation_abort_binding(
            reservation,
            captured,
            Some(real_run),
            Some(real_run),
            true,
            false
        ),
        Err(Error::Incomplete)
    );
    assert_eq!(
        preparation_abort_binding(
            reservation,
            captured,
            Some(real_run),
            Some(real_run),
            true,
            true
        ),
        Err(Error::Incomplete)
    );
    assert!(!preparation_cancellable(true, false, 0, false));
    assert!(!preparation_cancellable(false, false, 1, false));
    assert!(!preparation_cancellable(false, false, 0, true));
    assert!(!preparation_cancellable(true, true, 1, false));
    assert!(!preparation_cancellable(true, true, 0, true));
    assert!(preparation_cancellable(false, false, 0, false));
    assert!(
        preparation_cancellable(true, true, 0, false),
        "a genuinely sealed baseline hold can release its configuration gate"
    );
}

#[test]
fn cancelled_preparation_preserves_signed_binding_drain_time_and_prior_hold_across_retry() {
    let (a, b) = pair();
    let binding = binding();
    let prior = Binding {
        baseline: true,
        run: RunKey {
            trial_id: 7,
            ..binding.run
        },
        ..binding
    }
    .hash()
    .unwrap();
    let seal = PreparationSeal {
        binding,
        drained_ns: 98_765,
        frozen_other_domains: [21; 32],
        prior_sealed_binding: prior,
        failure: None,
    };
    let mut body = [0; PREPARATION_SEAL_BYTES];
    assert_eq!(seal.encode(&mut body), Ok(PREPARATION_SEAL_BYTES));
    assert_eq!(PreparationSeal::decode(&body), Ok(seal));
    let header = Header {
        kind: PREPARED_ABORTED,
        sequence: 37,
        source: binding.participant,
        destination: binding.origin,
        session: binding.session,
    };
    let mut bytes = [0; PACKET_BYTES];
    let n = b.encode(header, &body, &mut bytes).unwrap();
    assert_eq!(n, PREPARATION_PACKET_BYTES);
    assert_eq!(n, 712);
    let received = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    let mut cursor = ReceiveCursor::new();
    cursor.rebind(binding.participant.boot, false).unwrap();
    assert!(cursor.fresh(&received).unwrap());
    cursor.accepted(&received).unwrap();
    assert_eq!(PreparationSeal::decode(received.body), Ok(seal));
    let session = [45; 32];
    let n = b
        .encode(Header { session, ..header }, &body, &mut bytes)
        .unwrap();
    cursor.rebind(binding.participant.boot, true).unwrap();
    let retry = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(session),
        )
        .unwrap();
    assert!(!cursor.fresh(&retry).unwrap());
    assert_eq!(
        PreparationSeal::decode(retry.body).unwrap().drained_ns,
        98_765
    );
    assert!(
        a.decode(
            &bytes[..n],
            binding.participant.node,
            Endpoint {
                boot: 99,
                ..binding.origin
            },
            Some(session)
        )
        .is_err()
    );
    let changed = PreparationSeal {
        drained_ns: 99_000,
        ..seal
    };
    changed.encode(&mut body).unwrap();
    let n = b
        .encode(Header { session, ..header }, &body, &mut bytes)
        .unwrap();
    let forged_retry = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(session),
        )
        .unwrap();
    assert_eq!(cursor.fresh(&forged_retry), Err(Error::Conflict));
    assert!(
        PreparationSeal {
            drained_ns: 0,
            ..seal
        }
        .encode(&mut body)
        .is_err()
    );
}

fn actual_terminal_busy() -> (Failure, cyxia_prototype::policy::PlanReceipt) {
    use cyxia_prototype::{
        domains::{Action, Error as DomainError, POLICY_NS, WINDOW_NS},
        policy::{
            Clock, Executor, ModelBinding, PlanId, Publisher, RegisteredSet, Registry, Snapshot,
        },
        policy_wire::*,
    };
    struct ClockAt;
    impl Clock for ClockAt {
        fn now_ns(&mut self) -> u64 {
            101
        }
    }
    struct ActualOwner;
    impl Executor for ActualOwner {
        fn authorize_baseline(
            &mut self,
            _: ModelBinding,
            _: &RegisteredSet,
            _: u64,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        fn check(&mut self, _: Decision, _: &RegisteredSet, _: u64) -> Result<(), DomainError> {
            Err(DomainError::Busy)
        }
        fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), DomainError> {
            panic!("rejected before resources")
        }
        fn revalidate(&mut self, _: &Plan, _: u64) -> Result<(), DomainError> {
            panic!("rejected before resources")
        }
        fn publish(&mut self, _: &Plan, _: u64, _: u64) -> Result<(), DomainError> {
            panic!("a rejected fixture cannot publish")
        }
        fn cancel_prepared(&mut self, _: &Plan) {
            panic!("no PREPARE was entered")
        }
    }
    let b = binding();
    let publisher = Publisher {
        object: ObjectKey {
            id: 91,
            generation: 1,
        },
        controller_epoch: 8,
    };
    let model = ModelBinding {
        generation: 1,
        model_hash: [22; 32],
        schema_hash: [23; 32],
    };
    let snapshot = Snapshot {
        sequence: 2,
        taken_ns: 100,
        ledger_generation: 3,
        core_generation: 1,
    };
    let target = ObjectKey {
        id: 16,
        generation: 1,
    };
    let mut registry = Registry::new(b.participant.boot, publisher, model).unwrap();
    let action = Action::OfferCpu(100);
    let hash = registry
        .register_baseline(publisher, snapshot, target, model, action)
        .unwrap();
    let decision = Decision {
        action,
        candidate_index: 0,
        envelope: Envelope {
            controller_epoch: publisher.controller_epoch,
            decision_seq: 2,
            snapshot_seq: 2,
            target,
            ledger_generation: 3,
            core_generation: 1,
            expires_local_ns: 100 + WINDOW_NS,
            model_hash: model.model_hash,
            candidate_set_hash: hash,
        },
    };
    let header = PlanHeader {
        plan_seq: 2,
        base_plan_version: 0,
        active_model_generation: 1,
        controller_epoch: publisher.controller_epoch,
        snapshot_seq: 2,
        active_until_local_ns: 100 + POLICY_NS,
    };
    let mut bytes = [0; 384];
    let count = encode_plan(header, &[decision], &mut bytes).unwrap();
    let receipt = registry
        .submit_job(
            publisher,
            &bytes[..count],
            101,
            50_000_100,
            &mut ClockAt,
            &mut ActualOwner,
        )
        .unwrap();
    assert_eq!(
        receipt.id,
        PlanId {
            boot_epoch: b.participant.boot,
            controller_epoch: 8,
            plan_seq: 2
        }
    );
    assert_eq!(
        receipt.state(),
        cyxia_prototype::policy::ExecutionState::Failed(DomainError::Busy)
    );
    let failure = Failure::rejected(
        17,
        receipt,
        snapshot,
        target,
        Sha256::digest(&bytes[..count]).into(),
        101,
        102,
        50_000_100,
    )
    .unwrap();
    (failure, receipt)
}

#[test]
fn actual_registry_terminal_busy_is_signed_retained_and_cancelled_only_after_real_drain() {
    let (a, b) = pair();
    let binding = binding();
    let (failure, receipt) = actual_terminal_busy();
    let notice = RootFailure { binding, failure };
    let mut body = [0; ROOT_FAILURE_BYTES];
    notice.encode(&mut body).unwrap();
    let header = Header {
        kind: ROOT_FAILED,
        sequence: 40,
        source: binding.participant,
        destination: binding.origin,
        session: binding.session,
    };
    let mut packet = [0; PACKET_BYTES];
    let len = b.encode(header, &body, &mut packet).unwrap();
    assert_eq!(len, ROOT_FAILURE_PACKET_BYTES);
    let signed = a
        .decode(
            &packet[..len],
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    let received = RootFailure::decode(signed.body).unwrap();
    let mut retained = None;
    received.retain(&mut retained, binding, binding).unwrap();
    assert_eq!(retained.unwrap().publication.unwrap().id, receipt.id);
    assert_eq!(
        retained.unwrap().error,
        cyxia_prototype::domains::Error::Busy as u64 + 1
    );
    assert!(preparation_cancellable(false, false, 0, false));
    assert!(!preparation_cancellable(false, false, 1, false));
    assert!(!preparation_cancellable(false, false, 0, true));
    assert_eq!(
        preparation_abort_binding(binding, binding, None, None, true, false),
        Err(Error::Incomplete),
        "even a genuine root failure cannot discard an issued but unacknowledged START"
    );
    let cancel = preparation_abort_binding(binding, binding, None, None, false, false).unwrap();
    let seal = PreparationSeal {
        binding: cancel,
        drained_ns: 300,
        frozen_other_domains: [0; 32],
        prior_sealed_binding: [0; 32],
        failure: retained,
    };
    let mut body = [0; PREPARATION_SEAL_BYTES];
    seal.encode(&mut body).unwrap();
    let len = b
        .encode(
            Header {
                kind: PREPARED_ABORTED,
                sequence: 41,
                ..header
            },
            &body,
            &mut packet,
        )
        .unwrap();
    let signed = a
        .decode(
            &packet[..len],
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    assert_eq!(PreparationSeal::decode(signed.body).unwrap(), seal);
    assert_eq!(
        seal.failure.unwrap().publication.unwrap().snapshot,
        failure.publication.unwrap().snapshot
    );
    assert!(
        PreparationSeal {
            drained_ns: 101,
            ..seal
        }
        .encode(&mut body)
        .is_err()
    );
}

#[test]
fn failure_cannot_rebind_boot_trial_plan_or_be_forged_from_pending_and_unknown() {
    use cyxia_prototype::policy::ExecutionState;
    let (failure, receipt) = actual_terminal_busy();
    let b = binding();
    let p = failure.publication.unwrap();
    for state in [
        ExecutionState::Pending,
        ExecutionState::Unknown,
        ExecutionState::Applied,
    ] {
        let mut unresolved = receipt;
        unresolved.actions[0] = state;
        assert_eq!(
            Failure::rejected(
                17,
                unresolved,
                p.snapshot,
                p.target,
                p.plan_hash,
                p.received_ns,
                p.observed_ns,
                p.wall_deadline_ns
            ),
            Err(Error::Incomplete)
        );
    }
    for published in [
        cyxia_prototype::policy::PlanReceipt {
            version: 1,
            ..receipt
        },
        cyxia_prototype::policy::PlanReceipt {
            published_ns: 101,
            ..receipt
        },
    ] {
        assert_eq!(
            Failure::rejected(
                17,
                published,
                p.snapshot,
                p.target,
                p.plan_hash,
                p.received_ns,
                p.observed_ns,
                p.wall_deadline_ns
            ),
            Err(Error::Incomplete)
        );
    }
    let notice = RootFailure {
        binding: b,
        failure,
    };
    let mut retained = None;
    notice.retain(&mut retained, b, b).unwrap();
    notice.retain(&mut retained, b, b).unwrap();
    let changed = RootFailure {
        failure: Failure {
            observed_ns: 103,
            ..failure
        },
        ..notice
    };
    assert_eq!(changed.retain(&mut retained, b, b), Err(Error::Conflict));
    assert_eq!(retained, Some(failure));
    let wrong_trial = Binding {
        run: cyxia_prototype::learning::capture::RunKey {
            trial_id: 10,
            ..b.run
        },
        ..b
    };
    assert_eq!(
        RootFailure {
            binding: wrong_trial,
            ..notice
        }
        .retain(&mut retained, b, b),
        Err(Error::Stale)
    );
    let wrong_boot = FailedPublication {
        id: cyxia_prototype::policy::PlanId {
            boot_epoch: 99,
            ..p.id
        },
        ..p
    };
    assert_eq!(
        RootFailure {
            failure: Failure {
                publication: Some(wrong_boot),
                ..failure
            },
            ..notice
        }
        .validate(),
        Err(Error::Identity)
    );
}

#[test]
fn root_failure_reauthentication_keeps_original_failure_and_legacy_cancel_remains_readable() {
    let (a, b) = pair();
    let binding = binding();
    let (failure, _) = actual_terminal_busy();
    let notice = RootFailure { binding, failure };
    let mut body = [0; ROOT_FAILURE_BYTES];
    notice.encode(&mut body).unwrap();
    let header = Header {
        kind: ROOT_FAILED,
        sequence: 50,
        source: binding.participant,
        destination: binding.origin,
        session: binding.session,
    };
    let mut bytes = [0; PACKET_BYTES];
    let n = b.encode(header, &body, &mut bytes).unwrap();
    let first = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    let mut cursor = ReceiveCursor::new();
    cursor.rebind(binding.participant.boot, false).unwrap();
    cursor.accepted(&first).unwrap();
    let session = [90; 32];
    let n = b
        .encode(Header { session, ..header }, &body, &mut bytes)
        .unwrap();
    let again = a
        .decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(session),
        )
        .unwrap();
    assert!(!cursor.fresh(&again).unwrap());
    assert_eq!(RootFailure::decode(again.body).unwrap(), notice);
    bytes[HEADER_BYTES + BINDING_BYTES + 8] ^= 1;
    assert!(matches!(
        a.decode(
            &bytes[..n],
            binding.participant.node,
            binding.origin,
            Some(session)
        ),
        Err(Error::Signature)
    ));
    let legacy = PreparationSeal {
        binding,
        drained_ns: 400,
        frozen_other_domains: [21; 32],
        prior_sealed_binding: [0; 32],
        failure: None,
    };
    let mut raw = [0; PREPARATION_SEAL_BYTES];
    legacy.encode(&mut raw).unwrap();
    assert_eq!(
        PreparationSeal::decode(&raw[..raw.len() - FAILURE_BYTES]),
        Ok(legacy)
    );
    // The optional extension is canonical: nonzero bytes cannot hide under an absent tag.
    raw[PREPARATION_SEAL_BYTES - 1] = 1;
    assert!(PreparationSeal::decode(&raw).is_err());
}
