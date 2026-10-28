use cyxia_prototype::{
    domains::{ApplyId, ObjectKey},
    learning::{
        Error, Family,
        coordinator_wire::{
            COMMAND_BYTES, Command, CommandAction, CoordinatorSnapshot, CreditEvidence,
            LastCommandStatus, ObservedExecutionState, PendingObservation, PermitObservation,
            RECEIPT_BYTES, Receipt, ReceiptResult, RejectReason, SNAPSHOT_BYTES, ScoreMode,
            VerifiedScore,
        },
        governance::{EXTRA_NS, Stage},
        worker_wire::JobBinding,
    },
    policy::ModelBinding,
};

fn key(id: u64, generation: u64) -> ObjectKey {
    ObjectKey { id, generation }
}

fn binding() -> JobBinding {
    JobBinding {
        boot_epoch: 7,
        job_id: 11,
        controller_epoch: 13,
        core_generation: 17,
        model_generation: 19,
        data_generation: 23,
        role_context: key(29, 31),
        image_hash: [37; 32],
        ledger_generation: 41,
    }
}

fn score() -> VerifiedScore {
    VerifiedScore {
        handle: 43,
        digest: [47; 32],
    }
}

fn snapshot() -> CoordinatorSnapshot {
    CoordinatorSnapshot {
        binding: binding(),
        session: key(53, 59),
        revision: 61,
        now_ns: 1_000,
        deadline_ns: 51_000,
        stage: Stage::Canary,
        original_hash: [67; 32],
        candidate_hash: [71; 32],
        registration_hash: [73; 32],
        shadow_coverage: (1 << 18) - 1,
        closed_windows: 10,
        permit: Some(PermitObservation {
            id: 79,
            target: key(83, 89),
            start_ns: 500,
            expires_ns: 30_000_000_500,
            quota: 100,
            used: 3,
        }),
        pending: Some(PendingObservation {
            apply: ApplyId {
                boot_epoch: 7,
                controller_epoch: 13,
                plan_seq: 97,
                action_index: 2,
                target: key(83, 89),
            },
            plan_version: 101,
            state: ObservedExecutionState::Failed,
        }),
        baseline_ready: true,
        last_command_sequence: 103,
        last_command_status: LastCommandStatus::Applied,
        verified_score: Some(score()),
    }
}

fn command(action: CommandAction) -> Command {
    let observation = snapshot();
    Command {
        binding: observation.binding,
        session: observation.session,
        revision: observation.revision,
        sequence: observation.last_command_sequence + 1,
        snapshot_digest: observation.digest().unwrap(),
        action,
    }
}

#[test]
fn snapshot_is_fixed_canonical_and_digest_bound() {
    let observation = snapshot();
    let mut bytes = [0; SNAPSHOT_BYTES];
    assert_eq!(observation.encode(&mut bytes), Ok(SNAPSHOT_BYTES));
    assert_eq!(CoordinatorSnapshot::decode(&bytes), Ok(observation));
    assert_ne!(observation.digest().unwrap(), [0; 32]);

    bytes[511] = 1;
    assert_eq!(CoordinatorSnapshot::decode(&bytes), Err(Error::Evidence));

    let mut malformed = snapshot();
    malformed.shadow_coverage |= 1 << 20;
    assert_eq!(malformed.shape(), Err(Error::Evidence));
    malformed = snapshot();
    malformed.permit.as_mut().unwrap().used = 101;
    assert_eq!(malformed.shape(), Err(Error::Evidence));
}

#[test]
fn every_command_variant_has_one_canonical_encoding() {
    let observation = snapshot();
    let actions = [
        CommandAction::Wait,
        CommandAction::Score {
            mode: ScoreMode::Shadow,
            family: Family { domain: 1, kind: 1 },
        },
        CommandAction::Score {
            mode: ScoreMode::Canary,
            family: Family {
                domain: 15,
                kind: 1,
            },
        },
        CommandAction::CloseShadowWindow { window: 11 },
        CommandAction::PrepareBaseline {
            target: key(83, 89),
        },
        CommandAction::BeginCanary {
            target: key(83, 89),
        },
        CommandAction::PublishCanary { score: score() },
        CommandAction::Freeze { permit_id: 79 },
        CommandAction::Promote {
            registration_hash: observation.registration_hash,
        },
        CommandAction::Rollback {
            expected_active_generation: observation.binding.model_generation,
        },
        CommandAction::Reject {
            reason: RejectReason::Safety,
        },
        CommandAction::Release,
    ];
    for action in actions {
        let request = command(action);
        let mut bytes = [0; COMMAND_BYTES];
        assert_eq!(request.encode(&mut bytes), Ok(COMMAND_BYTES));
        assert_eq!(Command::decode(&bytes), Ok(request));
        assert_eq!(request.validate_for_snapshot(observation, 2_000), Ok(()));
        assert_ne!(request.digest().unwrap(), [0; 32]);
        assert_eq!(request.key().boot_epoch, observation.binding.boot_epoch);
    }

    let mut bytes = [0; COMMAND_BYTES];
    command(CommandAction::Wait).encode(&mut bytes).unwrap();
    bytes[184] = 1;
    assert_eq!(Command::decode(&bytes), Err(Error::Evidence));
}

#[test]
fn command_echoes_fresh_snapshot_and_monotonic_sequence() {
    let observation = snapshot();
    let request = command(CommandAction::Wait);
    assert_eq!(
        request.validate_for_snapshot(observation, observation.deadline_ns),
        Err(Error::Deadline)
    );

    let mut stale = request;
    stale.sequence = observation.last_command_sequence;
    assert_eq!(
        stale.validate_for_snapshot(observation, 2_000),
        Err(Error::Stale)
    );
    let mut skipped = request;
    skipped.sequence += 1;
    assert_eq!(
        skipped.validate_for_snapshot(observation, 2_000),
        Err(Error::Order)
    );
    let mut wrong_generation = request;
    wrong_generation.binding.model_generation += 1;
    assert_eq!(
        wrong_generation.validate_for_snapshot(observation, 2_000),
        Err(Error::Stale)
    );
    let mut wrong_digest = request;
    wrong_digest.snapshot_digest[0] ^= 1;
    assert_eq!(
        wrong_digest.validate_for_snapshot(observation, 2_000),
        Err(Error::Evidence)
    );

    let mut wrapped = observation;
    wrapped.last_command_sequence = u64::MAX;
    let mut after_wrap = request;
    after_wrap.snapshot_digest = wrapped.digest().unwrap();
    assert_eq!(
        after_wrap.validate_for_snapshot(wrapped, 2_000),
        Err(Error::Numeric)
    );
}

#[test]
fn protected_handles_must_match_the_observation() {
    let observation = snapshot();
    let mut publish = command(CommandAction::PublishCanary { score: score() });
    if let CommandAction::PublishCanary { score } = &mut publish.action {
        score.handle += 1;
    }
    assert_eq!(
        publish.validate_for_snapshot(observation, 2_000),
        Err(Error::Stale)
    );

    let freeze = command(CommandAction::Freeze { permit_id: 80 });
    assert_eq!(
        freeze.validate_for_snapshot(observation, 2_000),
        Err(Error::Stale)
    );
    let promote = command(CommandAction::Promote {
        registration_hash: [1; 32],
    });
    assert_eq!(
        promote.validate_for_snapshot(observation, 2_000),
        Err(Error::Stale)
    );
}

fn receipt(request: Command) -> Receipt {
    Receipt {
        result: ReceiptResult::Applied,
        boot_epoch: request.binding.boot_epoch,
        role_context: request.binding.role_context,
        session: request.session,
        revision: request.revision,
        command_sequence: request.sequence,
        state_revision: request.revision + 1,
        command_digest: request.digest().unwrap(),
        model: ModelBinding {
            generation: request.binding.model_generation + 1,
            model_hash: [107; 32],
            schema_hash: [109; 32],
        },
        effect_handle: 113,
        credit: CreditEvidence {
            ledger_id: 127,
            serial: 131,
            window: 0,
            actual_ns: 1_000_000,
            core_generation: request.binding.core_generation,
            cpu: 1,
        },
    }
}

#[test]
fn receipt_binds_command_model_effect_and_paid_credit() {
    let request = command(CommandAction::Wait);
    let response = receipt(request);
    let mut bytes = [0; RECEIPT_BYTES];
    assert_eq!(response.encode(&mut bytes), Ok(RECEIPT_BYTES));
    assert_eq!(Receipt::decode(&bytes), Ok(response));
    assert_eq!(response.validate_for_command(request), Ok(()));

    bytes[255] = 1;
    assert_eq!(Receipt::decode(&bytes), Err(Error::Evidence));

    let mut wrong = response;
    wrong.command_digest[0] ^= 1;
    assert_eq!(wrong.validate_for_command(request), Err(Error::Evidence));
    wrong = response;
    wrong.credit.core_generation += 1;
    assert_eq!(wrong.validate_for_command(request), Err(Error::Stale));
    wrong = response;
    wrong.credit.actual_ns = EXTRA_NS + 1;
    assert_eq!(wrong.shape(), Err(Error::Evidence));
}
