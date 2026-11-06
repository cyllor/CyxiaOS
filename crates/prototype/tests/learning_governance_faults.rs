//! A16/E14: accounting faults and unresolved side effects cannot be forgotten.
#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::{
    domains::{Action, ApplyId, ObjectKey, PolicyStamp},
    features::RawFeatures,
    learning::{Error, Family, governance::*, reward::WorkRequest},
    policy::{Candidate, CandidateSet, ExecutionState, ModelBinding, Snapshot},
};

struct Owners;
impl ControlAuthority for Owners {
    fn authorize(&self, _: Role, cpu: u16, generation: u64, bytes: u32) -> Result<(), Error> {
        assert_eq!((cpu, generation, bytes), (1, 1, 1024 * 1024));
        Ok(())
    }
}
impl GovernanceAuthority for Owners {
    fn registered_noncritical_console(&self, _: TargetRegistration) -> Result<(), Error> {
        Ok(())
    }
    fn legal_console(&self, _: ObjectKey, _: Action, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn verify_receipt(&self, receipt: &CanaryReceipt) -> Result<(), Error> {
        assert_eq!(receipt.evidence_hash, [3; 32]);
        Ok(())
    }
    fn verify_measurement(
        &self,
        _: CanaryPermit,
        _: u16,
        _: &[WorkRequest],
        _: &[WorkRequest],
        _: [u8; 32],
    ) -> Result<(), Error> {
        Err(Error::Evidence)
    }
    fn authorize_extension(
        &self,
        _: [u8; 32],
        _: CanaryPermit,
        _: u64,
        _: u16,
    ) -> Result<(), Error> {
        Err(Error::Evidence)
    }
    fn verify_restoration(
        &self,
        _: RestorationRequest,
        _: &RestorationReceipt,
    ) -> Result<(), Error> {
        Err(Error::Evidence)
    }
}

#[test]
fn mandatory_accounting_overflow_is_sticky_across_windows() {
    let mut budget = ExtraBudget::new();
    budget.record_mandatory(0, 1).unwrap();
    assert_eq!(budget.record_mandatory(0, u64::MAX), Err(Error::Numeric));
    assert!(budget.faulted());
    for now in [0, WINDOW_NS, 2 * WINDOW_NS] {
        assert_eq!(
            budget
                .reserve(Role::Training, 1, 1, 1024 * 1024, now, 1, &Owners)
                .err(),
            Some(Error::Budget)
        );
    }
}

#[test]
fn settlement_overflow_keeps_debt_and_stops_future_credits() {
    let mut budget = ExtraBudget::new();
    let first = budget
        .reserve(Role::Shadow, 1, 1, 1024 * 1024, 0, 1, &Owners)
        .unwrap();
    budget.settle(first, 1, 1).unwrap();
    let second = budget
        .reserve(Role::Validation, 1, 1, 1024 * 1024, 1, 1, &Owners)
        .unwrap();
    assert_eq!(
        budget.settle(second, u64::MAX, 2).err(),
        Some(Error::Numeric)
    );
    assert!(budget.faulted());
    assert_eq!(budget.spent_ns(), 1); // last representable charge is not reset
    assert_eq!(
        budget
            .reserve(Role::Training, 1, 1, 1024 * 1024, WINDOW_NS, 1, &Owners)
            .err(),
        Some(Error::Budget)
    );
}

fn target() -> ObjectKey {
    ObjectKey {
        id: 15,
        generation: 1,
    }
}
fn choices(family: Family, model: ModelBinding, now: u64) -> CandidateSet {
    let actions = if family
        == (Family {
            domain: 15,
            kind: 1,
        }) {
        vec![Action::ConsoleBatch(1), Action::ConsoleBatch(8)]
    } else {
        support::choices(family)
    };
    let candidates: Vec<_> = actions
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
        target(),
        model,
        &candidates,
        Some(actions[0]),
    )
    .unwrap()
}

#[test]
fn delayed_pending_receipt_cannot_erase_canary_uncertainty() {
    support::with_candidate(|candidate, old| {
        let binding = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let mut gate = CommitGate::new(1, binding).unwrap();
        let mut governance = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        for window in 0..10 {
            let families: &[Family] = if window == 0 {
                &support::FAMILIES
            } else {
                &support::FAMILIES[..1]
            };
            for (index, family) in families.iter().enumerate() {
                let now = window * WINDOW_NS + index as u64 * 2000;
                let credit = budget
                    .reserve(Role::Shadow, 1, 1, 1024 * 1024, now, 2000, &Owners)
                    .unwrap();
                let score = governance
                    .score_shadow(&choices(*family, binding, now), &credit)
                    .unwrap();
                let cost = budget.settle(credit, 1000, now + 1000).unwrap();
                governance.record_shadow(score, cost).unwrap();
            }
            governance
                .close_shadow_window((window + 1) * WINDOW_NS)
                .unwrap();
        }
        let permit = governance
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: target(),
                    baseline: Action::ConsoleBatch(1),
                },
                10 * WINDOW_NS,
                &Owners,
            )
            .unwrap();
        let now = permit.start_ns + 1;
        let model = ModelBinding {
            model_hash: permit.candidate_hash,
            ..binding
        };
        let credit = budget
            .reserve(Role::Canary, 1, 1, 1024 * 1024, now, 2000, &Owners)
            .unwrap();
        let score = governance
            .score_canary(
                &choices(
                    Family {
                        domain: 15,
                        kind: 1,
                    },
                    model,
                    now,
                ),
                &credit,
            )
            .unwrap();
        let cost = budget.settle(credit, 1000, now + 1000).unwrap();
        governance
            .publish(
                &mut gate,
                now + 1000,
                score,
                cost,
                ApplyId {
                    boot_epoch: 1,
                    controller_epoch: 3,
                    plan_seq: 1,
                    action_index: 0,
                    target: target(),
                },
                PolicyStamp::new(1, now, now + 1000).unwrap(),
                &Owners,
            )
            .unwrap();
        let submission = governance.submissions().next().unwrap();
        let unknown = CanaryReceipt {
            apply: submission.apply,
            plan_version: submission.stamp.version,
            executor_generation: 1,
            model: submission.model,
            state: ExecutionState::Unknown,
            actual: None,
            started_ns: now + 1500,
            finished_ns: now + 2000,
            installed_until_ns: submission.stamp.installed_until_ns,
            evidence_hash: [3; 32],
        };
        governance.reconcile(&mut gate, unknown, &Owners).unwrap();
        assert_eq!(
            governance.reconcile(
                &mut gate,
                CanaryReceipt {
                    state: ExecutionState::Pending,
                    ..unknown
                },
                &Owners,
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            governance.submissions().next().unwrap().receipt,
            Some(unknown)
        );
        assert_eq!(
            governance.submissions().next().unwrap().state,
            ExecutionState::Unknown
        );
        governance.reconcile(&mut gate, unknown, &Owners).unwrap();
        governance.freeze().unwrap();
        assert_eq!(
            governance.promote(&mut gate, permit.expires_ns),
            Err(Error::Unknown)
        );
        assert_eq!(gate.active(), binding);
        let applied = CanaryReceipt {
            state: ExecutionState::Applied,
            actual: Some(submission.action),
            ..unknown
        };
        governance.reconcile(&mut gate, applied, &Owners).unwrap();
        governance.reconcile(&mut gate, applied, &Owners).unwrap();
        assert_eq!(
            governance.reconcile(&mut gate, unknown, &Owners),
            Err(Error::Conflict)
        );
        assert_eq!(gate.active(), binding); // terminal reconciliation alone is not promotion
    });
}
