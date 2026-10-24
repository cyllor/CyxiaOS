#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::learning::{
    Error, Family,
    governance::*,
    reward::{RequestResult, RewardWorkspace, WorkRequest},
};
use cyxia_prototype::{
    domains::{Action, ApplyId, ObjectKey, PolicyStamp},
    features::RawFeatures,
    policy::{Candidate, CandidateSet, ExecutionState, ModelBinding, Snapshot},
};

struct Owners {
    extend: bool,
}
impl ControlAuthority for Owners {
    fn authorize(&self, _: Role, cpu: u16, generation: u64, workspace: u32) -> Result<(), Error> {
        if cpu != 1 || generation != 1 || workspace > 1024 * 1024 {
            Err(Error::State)
        } else {
            Ok(())
        }
    }
}
impl GovernanceAuthority for Owners {
    fn registered_noncritical_console(&self, target: TargetRegistration) -> Result<(), Error> {
        if target.key == console() && target.baseline == Action::ConsoleBatch(1) {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn legal_console(&self, target: ObjectKey, action: Action, _: u64) -> Result<(), Error> {
        if target == console() && matches!(action, Action::ConsoleBatch(1 | 8 | 32 | 64)) {
            Ok(())
        } else {
            Err(Error::Safety)
        }
    }
    fn verify_receipt(&self, r: &CanaryReceipt) -> Result<(), Error> {
        if r.evidence_hash == [3; 32] {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn verify_measurement(
        &self,
        _: CanaryPermit,
        _: u16,
        _: &[WorkRequest],
        _: &[WorkRequest],
        hash: [u8; 32],
    ) -> Result<(), Error> {
        if hash != [0; 32] {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn authorize_extension(
        &self,
        _: [u8; 32],
        _: CanaryPermit,
        _: u64,
        _: u16,
    ) -> Result<(), Error> {
        if self.extend {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn verify_restoration(
        &self,
        request: RestorationRequest,
        r: &RestorationReceipt,
    ) -> Result<(), Error> {
        if r.evidence_hash == [4; 32]
            && r.boot_epoch == request.boot_epoch
            && r.restoration_id == request.id
            && r.actual_version == 0
        {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
}
fn console() -> ObjectKey {
    ObjectKey {
        id: 15,
        generation: 1,
    }
}
fn candidates(family: Family, binding: ModelBinding, now: u64, target: ObjectKey) -> CandidateSet {
    let actions = if family
        == (Family {
            domain: 15,
            kind: 1,
        }) {
        vec![Action::ConsoleBatch(1), Action::ConsoleBatch(8)]
    } else {
        support::choices(family)
    };
    let choices: Vec<_> = actions
        .iter()
        .map(|action| Candidate {
            action: *action,
            features: RawFeatures {
                control_capacity: Some(1000),
                ..RawFeatures::default()
            },
        })
        .collect();
    CandidateSet::new(
        Snapshot {
            sequence: 1,
            taken_ns: now,
            ledger_generation: 1,
            core_generation: 1,
        },
        target,
        binding,
        &choices,
        Some(actions[0]),
    )
    .unwrap()
}
fn shadow(g: &mut Governance<'_, '_>, gate: &CommitGate, budget: &mut ExtraBudget) {
    let owners = Owners { extend: true };
    for window in 0..10 {
        let families: &[Family] = if window == 0 {
            &support::FAMILIES
        } else {
            &support::FAMILIES[..1]
        };
        for (index, family) in families.iter().enumerate() {
            let now = window * WINDOW_NS + index as u64 * 2000;
            let credit = budget
                .reserve(Role::Shadow, 1, 1, 1024 * 1024, now, 2000, &owners)
                .unwrap();
            let proof = g
                .score_shadow(&candidates(*family, gate.active(), now, console()), &credit)
                .unwrap();
            let cost = budget.settle(credit, 1000, now + 1000).unwrap();
            g.record_shadow(proof, cost).unwrap();
        }
        g.close_shadow_window((window + 1) * WINDOW_NS).unwrap();
    }
    assert_eq!(g.stage(), Stage::Ready);
}
fn publish(
    g: &mut Governance<'_, '_>,
    gate: &mut CommitGate,
    budget: &mut ExtraBudget,
    now: u64,
    seq: u64,
) -> Result<Publication, Error> {
    let owners = Owners { extend: true };
    let permit = gate.permit().unwrap();
    let binding = ModelBinding {
        generation: gate.active().generation,
        model_hash: permit.candidate_hash,
        schema_hash: gate.active().schema_hash,
    };
    let set = candidates(
        Family {
            domain: 15,
            kind: 1,
        },
        binding,
        now,
        console(),
    );
    let credit = budget.reserve(Role::Canary, 1, 1, 1024 * 1024, now, 2000, &owners)?;
    let proof = g.score_canary(&set, &credit)?;
    let cost = budget.settle(credit, 1000, now + 1000)?;
    g.publish(
        gate,
        now + 1000,
        proof,
        cost,
        ApplyId {
            boot_epoch: 1,
            controller_epoch: 3,
            plan_seq: seq,
            action_index: 0,
            target: console(),
        },
        PolicyStamp::new(seq, now, now + 1000).unwrap(),
        &owners,
    )
}
fn receipt(s: Submission, state: ExecutionState) -> CanaryReceipt {
    CanaryReceipt {
        apply: s.apply,
        plan_version: s.stamp.version,
        executor_generation: 1,
        model: s.model,
        state,
        actual: (state == ExecutionState::Applied).then_some(s.action),
        started_ns: s.stamp.snapshot_ns + 1500,
        finished_ns: s.stamp.snapshot_ns + 2000,
        installed_until_ns: s.stamp.installed_until_ns,
        evidence_hash: [3; 32],
    }
}
fn observations(start: u64, count: u64, latency: u64, pending: u64) -> Vec<WorkRequest> {
    (0..count)
        .map(|i| WorkRequest {
            id: i + 1,
            arrived_ns: start + i * 1_000_000,
            result: if i < pending {
                RequestResult::Pending
            } else {
                RequestResult::Completed {
                    finished_ns: start + i * 1_000_000 + latency,
                }
            },
        })
        .collect()
}

#[test]
fn all_extra_roles_share_prepaid_budget_and_unknown_credit_cannot_reset_it() {
    let owners = Owners { extend: true };
    let mut b = ExtraBudget::new();
    b.record_mandatory(0, 61_000_000).unwrap();
    let credit = b
        .reserve(Role::Training, 1, 1, 1024 * 1024, 0, 4_000_000, &owners)
        .unwrap();
    assert_eq!(
        b.reserve(
            Role::Validation,
            1,
            1,
            1024 * 1024,
            WINDOW_NS,
            1000,
            &owners
        )
        .err(),
        Some(Error::Unknown)
    );
    b.settle(credit, 4_000_000, 4_000_000).unwrap();
    let credit = b
        .reserve(
            Role::Shadow,
            1,
            1,
            1024 * 1024,
            4_000_000,
            5_000_000,
            &owners,
        )
        .unwrap();
    b.settle(credit, 5_000_000, 9_000_000).unwrap();
    assert_eq!(
        b.reserve(Role::Canary, 1, 1, 1024 * 1024, 9_000_000, 1, &owners)
            .err(),
        Some(Error::Budget)
    );
    assert_eq!(
        b.reserve(Role::Training, 3, 1, 1024 * 1024, WINDOW_NS, 1, &owners)
            .err(),
        Some(Error::State)
    );
    let credit = b
        .reserve(Role::Training, 1, 1, 1024 * 1024, WINDOW_NS, 1000, &owners)
        .unwrap();
    assert_eq!(
        b.settle(credit, 1001, WINDOW_NS + 1001).err(),
        Some(Error::Budget)
    );
    assert!(b.faulted());
    assert_eq!(b.spent_ns(), 1001);
    assert_eq!(
        b.reserve(Role::Training, 1, 1, 1024 * 1024, 2 * WINDOW_NS, 1, &owners)
            .err(),
        Some(Error::Budget)
    );
}

#[test]
fn shadow_has_no_execution_permit_and_canary_lease_excludes_old_target_writes() {
    support::with_candidate(|candidate, old| {
        let binding = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let mut gate = CommitGate::new(1, binding).unwrap();
        let mut g = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        assert_eq!(
            g.begin_canary(
                &mut gate,
                TargetRegistration {
                    key: console(),
                    baseline: Action::ConsoleBatch(1)
                },
                0,
                &Owners { extend: true }
            )
            .err(),
            Some(Error::State)
        );
        assert_eq!(gate.permit(), None);
        shadow(&mut g, &gate, &mut budget);
        assert_eq!(
            g.begin_canary(
                &mut gate,
                TargetRegistration {
                    key: ObjectKey {
                        id: 14,
                        generation: 1
                    },
                    baseline: Action::ConsoleBatch(1)
                },
                10 * WINDOW_NS,
                &Owners { extend: true }
            )
            .err(),
            Some(Error::Evidence)
        );
        let permit = g
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: console(),
                    baseline: Action::ConsoleBatch(1),
                },
                10 * WINDOW_NS,
                &Owners { extend: true },
            )
            .unwrap();
        assert_eq!((permit.windows, permit.quota), (100, 100));
        assert_eq!(
            gate.check_active_publication(binding, console()),
            Err(Error::State)
        );
        assert!(
            gate.check_active_publication(
                binding,
                ObjectKey {
                    id: 99,
                    generation: 1
                }
            )
            .is_ok()
        );
        publish(&mut g, &mut gate, &mut budget, permit.start_ns + 1, 1).unwrap();
        let submission = g.submissions().next().unwrap();
        g.reconcile(
            &mut gate,
            receipt(submission, ExecutionState::Applied),
            &Owners { extend: true },
        )
        .unwrap();
        assert_eq!(
            publish(&mut g, &mut gate, &mut budget, permit.start_ns + 3000, 2),
            Err(Error::Budget)
        );
        assert_eq!(g.stage(), Stage::Restoring);
        assert!(gate.permit().is_none());
    });
}

#[test]
fn unknown_cannot_promote_or_release_restore_gate_but_exact_reconciliation_can_close() {
    support::with_candidate(|candidate, old| {
        let binding = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let mut gate = CommitGate::new(1, binding).unwrap();
        let mut g = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        shadow(&mut g, &gate, &mut budget);
        let permit = g
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: console(),
                    baseline: Action::ConsoleBatch(1),
                },
                10 * WINDOW_NS,
                &Owners { extend: true },
            )
            .unwrap();
        publish(&mut g, &mut gate, &mut budget, permit.start_ns + 1, 1).unwrap();
        let submission = g.submissions().next().unwrap();
        g.reconcile(
            &mut gate,
            receipt(submission, ExecutionState::Unknown),
            &Owners { extend: true },
        )
        .unwrap();
        g.freeze().unwrap();
        assert_eq!(g.promote(&mut gate, permit.expires_ns), Err(Error::Unknown));
        assert_eq!(gate.active(), binding);
        g.abort(&mut gate, Error::Deadline);
        let request = gate.restoration_request().unwrap();
        let restore = RestorationReceipt {
            boot_epoch: request.boot_epoch,
            restoration_id: request.id,
            target: console(),
            actual: Action::ConsoleBatch(1),
            actual_version: 0,
            executor_generation: 1,
            state: ExecutionState::Applied,
            evidence_hash: [4; 32],
        };
        assert_eq!(
            g.restored(&mut gate, restore, &Owners { extend: true }),
            Err(Error::Unknown)
        );
        assert_eq!(gate.restoration_pending(), Some(console()));
        let mut wrong = receipt(submission, ExecutionState::Applied);
        wrong.model.generation += 1;
        assert_eq!(
            g.reconcile(&mut gate, wrong, &Owners { extend: true }),
            Err(Error::Evidence)
        );
        g.reconcile(
            &mut gate,
            receipt(submission, ExecutionState::Applied),
            &Owners { extend: true },
        )
        .unwrap();
        g.restored(&mut gate, restore, &Owners { extend: true })
            .unwrap();
        assert_eq!(gate.restoration_pending(), None);
        assert_eq!(g.stage(), Stage::Rejected);
    });
}

#[test]
fn real_applied_complete_feedback_and_unchanged_ttl_precede_generation_switch_and_aba_safe_rollback()
 {
    support::with_candidate(|candidate, old| {
        let original = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let mut gate = CommitGate::new(1, original).unwrap();
        let mut g = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        shadow(&mut g, &gate, &mut budget);
        let permit = g
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: console(),
                    baseline: Action::ConsoleBatch(1),
                },
                10 * WINDOW_NS,
                &Owners { extend: true },
            )
            .unwrap();
        publish(&mut g, &mut gate, &mut budget, permit.start_ns + 1, 1).unwrap();
        let submission = g.submissions().next().unwrap();
        let applied = receipt(submission, ExecutionState::Applied);
        g.reconcile(&mut gate, applied, &Owners { extend: true })
            .unwrap();
        g.reconcile(&mut gate, applied, &Owners { extend: true })
            .unwrap();
        let mut workspace = RewardWorkspace::new();
        for second in 0..10 {
            let start = permit.start_ns + second * 1_000_000_000;
            let baseline = observations(start, 100, 1000, 0);
            let better = observations(start, 100, 900, 0);
            g.observe_second(
                &mut gate,
                second as u16,
                &baseline,
                &better,
                &mut workspace,
                &Owners { extend: true },
            )
            .unwrap();
        }
        assert_eq!(
            g.promote(&mut gate, permit.expires_ns).err(),
            Some(Error::State)
        );
        g.freeze().unwrap();
        let active = g.promote(&mut gate, permit.expires_ns).unwrap();
        assert_eq!(active.generation, 8);
        assert_ne!(active.model_hash, original.model_hash);
        assert_eq!(
            g.submissions().next().unwrap().stamp.installed_until_ns,
            applied.installed_until_ns
        );
        assert_eq!(gate.permit(), None);
        let rollback = g.rollback(&mut gate).unwrap();
        assert_eq!(rollback.model_hash, original.model_hash);
        assert_eq!(rollback.generation, 9);
        assert_eq!(
            gate.check_active_publication(
                original,
                ObjectKey {
                    id: 99,
                    generation: 1
                }
            ),
            Err(Error::Stale)
        );
        assert_eq!(g.submissions().next().unwrap().receipt, Some(applied));
    });
}

#[test]
fn insufficient_windows_need_independent_preexpiry_extension_and_three_bad_seconds_abort() {
    support::with_candidate(|candidate, old| {
        let original = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let mut gate = CommitGate::new(1, original).unwrap();
        let mut g = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        shadow(&mut g, &gate, &mut budget);
        let permit = g
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: console(),
                    baseline: Action::ConsoleBatch(1),
                },
                10 * WINDOW_NS,
                &Owners { extend: true },
            )
            .unwrap();
        let mut workspace = RewardWorkspace::new();
        let requests = observations(permit.start_ns, 99, 1000, 0);
        assert_eq!(
            g.observe_second(
                &mut gate,
                0,
                &requests,
                &requests,
                &mut workspace,
                &Owners { extend: true }
            ),
            Err(Error::DataIncomplete)
        );
        let raw = g.incomplete_second(0).unwrap();
        assert_eq!(raw.baseline.unwrap().emitted, 99);
        assert_eq!(raw.candidate.unwrap().completed, 99);
        assert_eq!(raw.candidate.unwrap().penalty_p99_ns, 1000);
        assert!(g.second(0).is_none());
        assert_eq!(
            g.extend(
                &mut gate,
                permit.expires_ns - 1,
                200,
                &Owners { extend: false }
            ),
            Err(Error::Evidence)
        );
        assert_eq!(
            g.extend(&mut gate, permit.expires_ns, 200, &Owners { extend: true }),
            Err(Error::Deadline)
        );
        g.extend(
            &mut gate,
            permit.expires_ns - 1,
            200,
            &Owners { extend: true },
        )
        .unwrap();
        assert_eq!(gate.permit().unwrap().quota, 200);
        assert_eq!(
            g.extend(
                &mut gate,
                permit.expires_ns - 1,
                301,
                &Owners { extend: true }
            ),
            Err(Error::Deadline)
        );
        for second in 1..4 {
            let start = permit.start_ns + second * 1_000_000_000;
            let baseline = observations(start, 100, 1000, 0);
            let degraded = observations(start, 100, 1000, 11);
            let result = g.observe_second(
                &mut gate,
                second as u16,
                &baseline,
                &degraded,
                &mut workspace,
                &Owners { extend: true },
            );
            if second < 3 {
                result.unwrap()
            } else {
                assert_eq!(result, Err(Error::Validation));
            }
        }
        assert_eq!(g.stage(), Stage::Restoring);
        assert!(gate.permit().is_none());
        assert_eq!(gate.restoration_pending(), Some(console()));
    });
}
