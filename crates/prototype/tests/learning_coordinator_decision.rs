//! Host execution of the exact pure EL0 decision module. These tests prove the
//! bounded command producer, not native scheduling, authority or A16 evidence.
#[path = "../../../user/prototype-governance/src/decision.rs"]
mod decision;
use cyxia_prototype::{
    domains::{ApplyId, ObjectKey},
    learning::{
        Error, Family,
        coordinator_wire::{
            COMMAND_BYTES, Command, CommandAction, CoordinatorSnapshot, LastCommandStatus,
            ObservedExecutionState, PendingObservation, PermitObservation, ScoreMode,
            VerifiedScore,
        },
        governance::Stage,
        worker_wire::JobBinding,
    },
};

fn key(id: u64, generation: u64) -> ObjectKey {
    ObjectKey { id, generation }
}

fn binding() -> JobBinding {
    JobBinding {
        boot_epoch: 2,
        job_id: 3,
        controller_epoch: 5,
        core_generation: 7,
        model_generation: 11,
        data_generation: 13,
        role_context: key(17, 19),
        image_hash: [23; 32],
        ledger_generation: 29,
    }
}

fn permit() -> PermitObservation {
    PermitObservation {
        id: 31,
        target: key(15, 37),
        start_ns: 500,
        expires_ns: 30_000,
        quota: 100,
        used: 1,
    }
}

fn snapshot(stage: Stage) -> CoordinatorSnapshot {
    CoordinatorSnapshot {
        binding: binding(),
        session: key(41, 43),
        revision: 47,
        now_ns: 1_000,
        deadline_ns: 50_000,
        stage,
        original_hash: [53; 32],
        candidate_hash: [59; 32],
        registration_hash: [61; 32],
        shadow_coverage: 0,
        closed_windows: 0,
        permit: Some(permit()),
        pending: None,
        baseline_ready: false,
        last_command_sequence: 0,
        last_command_status: LastCommandStatus::None,
        verified_score: None,
    }
}

fn action(stage: Stage) -> CommandAction {
    decision::decide(snapshot(stage)).unwrap().action
}

#[test]
fn shadow_cycles_all_eighteen_families_then_closes_one_window() {
    let expected = [
        Family { domain: 1, kind: 1 },
        Family { domain: 1, kind: 2 },
        Family { domain: 2, kind: 1 },
        Family { domain: 3, kind: 1 },
        Family { domain: 4, kind: 1 },
        Family { domain: 5, kind: 1 },
        Family { domain: 6, kind: 1 },
        Family { domain: 7, kind: 1 },
        Family { domain: 8, kind: 1 },
        Family { domain: 9, kind: 1 },
        Family {
            domain: 10,
            kind: 1,
        },
        Family {
            domain: 11,
            kind: 1,
        },
        Family {
            domain: 12,
            kind: 1,
        },
        Family {
            domain: 13,
            kind: 1,
        },
        Family {
            domain: 14,
            kind: 1,
        },
        Family {
            domain: 15,
            kind: 1,
        },
        Family {
            domain: 16,
            kind: 1,
        },
        Family {
            domain: 16,
            kind: 2,
        },
    ];
    for (sequence, family) in expected.into_iter().enumerate() {
        let mut observation = snapshot(Stage::Shadow);
        observation.last_command_sequence = sequence as u64;
        observation.last_command_status = if sequence == 0 {
            LastCommandStatus::None
        } else {
            LastCommandStatus::Applied
        };
        assert_eq!(
            decision::decide(observation).unwrap().action,
            CommandAction::Score {
                mode: ScoreMode::Shadow,
                family,
            }
        );
    }
    let mut observation = snapshot(Stage::Shadow);
    observation.last_command_sequence = 18;
    observation.last_command_status = LastCommandStatus::Applied;
    assert_eq!(
        decision::decide(observation).unwrap().action,
        CommandAction::CloseShadowWindow { window: 1 }
    );
}

#[test]
fn qualified_shadow_requests_window_close_without_claiming_promotion() {
    let mut observation = snapshot(Stage::Shadow);
    observation.shadow_coverage = (1 << 18) - 1;
    observation.closed_windows = 10;
    assert_eq!(
        decision::decide(observation).unwrap().action,
        CommandAction::CloseShadowWindow { window: 11 }
    );
}

#[test]
fn ready_stage_requests_baseline_then_canary_for_registered_target() {
    assert_eq!(
        action(Stage::Ready),
        CommandAction::PrepareBaseline {
            target: permit().target,
        }
    );
    let mut observation = snapshot(Stage::Ready);
    observation.baseline_ready = true;
    assert_eq!(
        decision::decide(observation).unwrap().action,
        CommandAction::BeginCanary {
            target: permit().target,
        }
    );
    observation.permit = None;
    assert_eq!(
        decision::decide(observation).unwrap().action,
        CommandAction::Wait
    );
}

#[test]
fn canary_never_publishes_unknown_or_inflight_execution() {
    for state in [
        ObservedExecutionState::Pending,
        ObservedExecutionState::Unknown,
    ] {
        let mut observation = snapshot(Stage::Canary);
        observation.pending = Some(PendingObservation {
            apply: ApplyId {
                boot_epoch: 2,
                controller_epoch: 5,
                plan_seq: 67,
                action_index: 0,
                target: permit().target,
            },
            plan_version: 71,
            state,
        });
        observation.verified_score = Some(VerifiedScore {
            handle: 73,
            digest: [79; 32],
        });
        assert_eq!(
            decision::decide(observation).unwrap().action,
            CommandAction::Wait
        );
    }
}

#[test]
fn canary_failure_or_exhaustion_freezes_exact_permit() {
    let mut failed = snapshot(Stage::Canary);
    failed.pending = Some(PendingObservation {
        apply: ApplyId {
            boot_epoch: 2,
            controller_epoch: 5,
            plan_seq: 67,
            action_index: 0,
            target: permit().target,
        },
        plan_version: 71,
        state: ObservedExecutionState::Failed,
    });
    assert_eq!(
        decision::decide(failed).unwrap().action,
        CommandAction::Freeze { permit_id: 31 }
    );

    let mut expired = snapshot(Stage::Canary);
    expired.now_ns = permit().expires_ns;
    expired.deadline_ns = expired.now_ns + 1_000;
    assert_eq!(
        decision::decide(expired).unwrap().action,
        CommandAction::Freeze { permit_id: 31 }
    );

    let mut quota = snapshot(Stage::Canary);
    let quota_limit = quota.permit.unwrap().quota;
    quota.permit.as_mut().unwrap().used = quota_limit;
    assert_eq!(
        decision::decide(quota).unwrap().action,
        CommandAction::Freeze { permit_id: 31 }
    );
}

#[test]
fn canary_publishes_only_the_protected_verified_score() {
    let mut observation = snapshot(Stage::Canary);
    let score = VerifiedScore {
        handle: 73,
        digest: [79; 32],
    };
    observation.verified_score = Some(score);
    assert_eq!(
        decision::decide(observation).unwrap().action,
        CommandAction::PublishCanary { score }
    );

    observation.verified_score = None;
    assert_eq!(
        decision::decide(observation).unwrap().action,
        CommandAction::Score {
            mode: ScoreMode::Canary,
            family: Family {
                domain: 15,
                kind: 1,
            },
        }
    );
}

#[test]
fn terminal_and_safety_stages_do_not_invent_an_optimization() {
    for stage in [Stage::Frozen, Stage::Restoring, Stage::Active] {
        assert_eq!(action(stage), CommandAction::Wait);
    }
    assert_eq!(action(Stage::Rejected), CommandAction::Release);
}

#[test]
fn exact_guest_module_emits_canonical_digest_bound_command() {
    let observation = snapshot(Stage::Canary);
    let mut input = [0; 512];
    observation.encode(&mut input).unwrap();
    let mut output = [0xa5; COMMAND_BYTES + 16];
    let written = decision::run(&input, &mut output[..COMMAND_BYTES]).unwrap();
    assert_eq!(written, COMMAND_BYTES);
    assert!(output[COMMAND_BYTES..].iter().all(|byte| *byte == 0xa5));
    let command = Command::decode(&output[..COMMAND_BYTES]).unwrap();
    assert_eq!(
        command.validate_for_snapshot(observation, observation.now_ns),
        Ok(())
    );

    input[511] = 1;
    assert_eq!(
        decision::run(&input, &mut output[..COMMAND_BYTES]),
        Err(Error::Evidence)
    );
    assert_eq!(
        decision::run(&input[..511], &mut output[..COMMAND_BYTES]),
        Err(Error::Capacity)
    );
}

#[test]
fn sequence_wrap_fails_closed() {
    let mut observation = snapshot(Stage::Active);
    observation.last_command_sequence = u64::MAX;
    observation.last_command_status = LastCommandStatus::Applied;
    assert_eq!(decision::decide(observation), Err(Error::Numeric));
}
