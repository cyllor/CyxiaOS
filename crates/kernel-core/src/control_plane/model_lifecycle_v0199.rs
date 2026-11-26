//! Protected Operations model promotion and rollback, V0.19.9 §6.3.
//!
//! The serialized EL1 publication owner authenticates the signed permit,
//! native measurement and terminal archives, immutable parameters, and
//! durable switch/audit record. Model output supplies none of these proofs.
use super::{
    Error, Identity,
    action_schema_v2::ActionV2,
    apply_report_v1::{ActionStatus, ApplyReportV1},
    decision_record_v3::{DecisionRecordV3, DecisionSource},
    feedback_v0199::{CausalLabel, FeedbackRecord},
    learning_data_v0199::{SchemaBinding, ShadowReady},
    plan_wire_v2::PlanV2,
    role_manifest_v0199::{Role, ValidatedRoleManifest},
    trial_permit_v1::Permit,
};
use crate::security::{
    durable_role_epoch_v0199::DurableEpochGate, offline_config_v1::VerifiedOfflineConfig,
};
use cyxia_control_model::reward_v2::{self, Request};
use sha2::{Digest, Sha256};

const WINDOW_NS: u64 = 100_000_000;
const SECOND_NS: u64 = 1_000_000_000;
const INITIAL_SECONDS: u16 = 10;
const INITIAL_SUBMISSIONS: u32 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelRevision {
    pub candidate: Identity,
    pub parameter_hash: [u8; 32],
    pub schemas: SchemaBinding,
    /// Exact independent validation record, verified against the archive.
    pub validation_digest: [u8; 32],
}

impl ModelRevision {
    fn valid(self) -> bool {
        self.candidate.valid()
            && self.parameter_hash != [0; 32]
            && self.validation_digest != [0; 32]
            && self.schemas.valid()
    }
}

pub struct CanarySecond<'a> {
    pub baseline_start_ns: u64,
    pub baseline: &'a [Request],
    pub trial: &'a [Request],
    pub evidence_digest: [u8; 32],
}

pub struct CanaryReceipt<'a> {
    pub accepted_ns: u64,
    pub feedback: &'a FeedbackRecord,
}

pub struct FrozenTrial<'a> {
    pub accepted: u32,
    pub unresolved: u32,
    pub receipts: &'a [CanaryReceipt<'a>],
    pub evidence_digest: [u8; 32],
}

#[derive(Default)]
struct PreviousAction {
    window: Option<u64>,
    completed_ns: u64,
    controller_epoch: Option<u64>,
    plan_seq: u64,
    decision_seq: u64,
}

pub struct CanaryGate {
    manager: Identity,
    active_generation: u64,
    parent_hash: [u8; 32],
    revision: ModelRevision,
    permit: Permit,
    seconds: u16,
    degraded_run: u8,
    failed: bool,
    evidence: [u8; 32],
}

impl CanaryGate {
    /// Observe the first 100 windows with a current retained signed D15
    /// permit. Issuance, budget reservation and action publication remain
    /// with the actual permit and publication owners.
    pub fn start(
        proof: ShadowReady,
        manager: Identity,
        revision: ModelRevision,
        permit: Permit,
        now_ns: u64,
        verify_open: impl FnOnce(&Permit, &ModelRevision, &ShadowReady) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let (boot, active_generation, binding, claim_head, shadow_digest, target) = proof.scope();
        let permit_wire = permit.encode()?;
        if proof.manager() != manager
            || !revision.valid()
            || proof.schemas() != revision.schemas
            || binding.candidate != revision.parameter_hash
            || binding.candidate == binding.parent
            || permit.flags != 1
            || permit.boot_epoch != boot
            || permit.domain != 15
            || permit.target_id != target.id
            || permit.target_generation != target.generation
            || permit.model_hash != revision.parameter_hash
            || permit.model_generation != revision.candidate.generation
            || permit.start_ns < now_ns
            || !permit.start_ns.is_multiple_of(WINDOW_NS)
            || permit.expires_ns - permit.start_ns != SECOND_NS * u64::from(INITIAL_SECONDS)
            || permit.max_submissions > INITIAL_SUBMISSIONS
        {
            return Err(Error::Denied);
        }
        // Verify current Active, the signed grant retained for this target,
        // the exact candidate identity and independent validation history.
        verify_open(&permit, &revision, &proof)?;
        let mut hash = Sha256::new();
        hash.update(b"CYX/CANARY/v0199");
        hash.update(permit_wire);
        hash.update(revision.candidate.id.to_le_bytes());
        hash.update(revision.validation_digest);
        hash.update(claim_head);
        hash.update(shadow_digest);
        Ok(Self {
            manager,
            active_generation,
            parent_hash: binding.parent,
            revision,
            permit,
            seconds: 0,
            degraded_run: 0,
            failed: false,
            evidence: hash.finalize().into(),
        })
    }

    /// Called by the independent owner after an illegal request, budget or
    /// deadline violation, or failed safety assertion. The owner also
    /// blocks new submissions and preserves any accepted obligations.
    pub fn abort(&mut self) {
        self.failed = true;
    }

    pub fn record_second(
        &mut self,
        now_ns: u64,
        measurement: CanarySecond<'_>,
        latencies: &mut [u64],
        verify_measurement: impl FnOnce(&Permit, u16, &CanarySecond<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.failed || self.seconds >= INITIAL_SECONDS {
            return Err(Error::NotReady);
        }
        let start = self.permit.start_ns + u64::from(self.seconds) * SECOND_NS;
        if now_ns < start + SECOND_NS || measurement.evidence_digest == [0; 32] {
            return Err(Error::Denied);
        }
        if measurement.baseline.len() != measurement.trial.len() {
            return Err(Error::Denied);
        }
        if measurement.trial.len() > reward_v2::MAX_REQUESTS
            || measurement.trial.len() > latencies.len()
        {
            return Err(Error::Exhausted);
        }
        // These must describe the same pre-frozen workload and verified
        // CPU and safety evidence through the scoring interval.
        verify_measurement(&self.permit, self.seconds, &measurement)?;
        if measurement
            .baseline
            .iter()
            .zip(measurement.trial)
            .any(|(b, c)| {
                b.id != c.id
                    || b.arrived_ns.checked_sub(measurement.baseline_start_ns)
                        != c.arrived_ns.checked_sub(start)
            })
        {
            return Err(Error::Denied);
        }
        let read = |rows, start, scratch: &mut [u64]| {
            reward_v2::inspect_canary_second(rows, start, scratch).map_err(|error| match error {
                reward_v2::Error::Incomplete => Error::NotReady,
                reward_v2::Error::Capacity => Error::Exhausted,
                _ => Error::Invalid,
            })
        };
        let baseline = read(
            measurement.baseline,
            measurement.baseline_start_ns,
            latencies,
        )?;
        let trial = read(measurement.trial, start, latencies)?;
        let degraded = u128::from(trial.completed) * 10 < u128::from(baseline.completed) * 9
            || u128::from(trial.penalty_p99_ns) * 10 > u128::from(baseline.penalty_p99_ns) * 11;
        let mut hash = Sha256::new();
        hash.update(self.evidence);
        hash.update(start.to_le_bytes());
        hash.update(measurement.evidence_digest);
        hash.update([u8::from(degraded)]);
        self.evidence = hash.finalize().into();
        self.seconds += 1;
        self.degraded_run = if degraded { self.degraded_run + 1 } else { 0 };
        if self.degraded_run == 3 {
            self.abort();
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// The adapter first closes new submissions and proves the complete
    /// permit-owned terminal set. This includes actual acceptance times,
    /// fixed order, report provenance and settled costs.
    pub fn seal(
        &self,
        manager: Identity,
        now_ns: u64,
        trial: FrozenTrial<'_>,
        verify_closed: impl FnOnce(&Permit, &FrozenTrial<'_>) -> Result<(), Error>,
    ) -> Result<PromotionProof, Error> {
        if self.manager != manager {
            return Err(Error::Denied);
        }
        if self.failed || self.seconds != INITIAL_SECONDS || now_ns < self.permit.expires_ns {
            return Err(Error::NotReady);
        }
        if trial.unresolved != 0 || trial.accepted == 0 {
            return Err(Error::NotReady);
        }
        if usize::try_from(trial.accepted) != Ok(trial.receipts.len())
            || trial.accepted > self.permit.max_submissions
            || trial.evidence_digest == [0; 32]
        {
            return Err(Error::Denied);
        }
        verify_closed(&self.permit, &trial)?;
        let mut applied = false;
        let mut previous = PreviousAction::default();
        let mut hash = Sha256::new();
        hash.update(self.evidence);
        hash.update(trial.evidence_digest);
        for receipt in trial.receipts {
            applied |= self.check_receipt(receipt, &mut previous, now_ns)?;
            hash.update(receipt.accepted_ns.to_le_bytes());
            hash.update(receipt.feedback.evidence_digest());
        }
        if !applied {
            return Err(Error::NotReady);
        }
        Ok(PromotionProof {
            manager,
            boot: self.permit.boot_epoch,
            expected_generation: self.active_generation,
            parent_hash: self.parent_hash,
            revision: self.revision,
            permit_id: self.permit.permit_id,
            evidence_digest: hash.finalize().into(),
        })
    }

    fn check_receipt(
        &self,
        receipt: &CanaryReceipt<'_>,
        previous: &mut PreviousAction,
        now_ns: u64,
    ) -> Result<bool, Error> {
        let f = receipt.feedback;
        let d = DecisionRecordV3::decode(&f.decision)?;
        let r = ApplyReportV1::decode(
            f.report
                .get(..usize::from(f.report_len))
                .ok_or(Error::Invalid)?,
        )?;
        let window = receipt.accepted_ns / WINDOW_NS;
        if d.source != DecisionSource::AuthorizedTrial
            || d.trial_permit_id != self.permit.permit_id
            || d.boot_epoch != self.permit.boot_epoch
            || d.domain_id != 15
            || d.action_index != 0
            || d.rule_id != self.permit.rule_id
            || d.rules_generation != self.permit.rules_generation
            || d.rules_hash != self.permit.rule_hash
            || d.target_id != self.permit.target_id
            || d.target_generation != self.permit.target_generation
            || f.causal_label != CausalLabel::NoAdoption
            || f.advice.is_some()
            || r.key.boot_epoch != d.boot_epoch
            || r.key.controller_epoch != d.controller_epoch
            || r.key.plan_seq != d.plan_seq
            || r.action_index != 0
            || r.domain_id != 15
            || r.target.id != d.target_id
            || r.target.generation != d.target_generation
            || !(self.permit.start_ns..self.permit.expires_ns).contains(&receipt.accepted_ns)
            || receipt.accepted_ns >= d.decision_expires_ns
            || !(receipt.accepted_ns..=now_ns).contains(&r.completed_ns)
            || r.state == ActionStatus::Unknown
            || previous.window.is_some_and(|prev| prev >= window)
            || receipt.accepted_ns < previous.completed_ns
            || previous
                .controller_epoch
                .is_some_and(|prev| prev != d.controller_epoch)
            || d.plan_seq <= previous.plan_seq
            || d.decision_seq <= previous.decision_seq
        {
            return Err(Error::Denied);
        }
        ActionV2::decode(15, 1, r.action)?;
        *previous = PreviousAction {
            window: Some(window),
            completed_ns: r.completed_ns,
            controller_epoch: Some(d.controller_epoch),
            plan_seq: d.plan_seq,
            decision_seq: d.decision_seq,
        };
        Ok(r.state == ActionStatus::Applied)
    }
}

pub struct PromotionProof {
    manager: Identity,
    boot: u64,
    expected_generation: u64,
    parent_hash: [u8; 32],
    revision: ModelRevision,
    permit_id: u64,
    evidence_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveModel {
    pub generation: u64,
    pub active: ModelRevision,
    pub previous: Option<ModelRevision>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    Promote {
        permit_id: u64,
        evidence_digest: [u8; 32],
    },
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelTransition {
    pub boot: u64,
    pub before: ActiveModel,
    pub after: ActiveModel,
    pub change: Change,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    Durable,
    NoEffect,
    Unknown,
}

pub struct ModelLifecycle {
    boot: u64,
    manager: Identity,
    state: ActiveModel,
    pending: Option<ModelTransition>,
}

impl ModelLifecycle {
    pub fn recover(
        epochs: &DurableEpochGate,
        config: &VerifiedOfflineConfig<'_>,
        roles: &ValidatedRoleManifest<'_>,
        persisted: ActiveModel,
        verify_native: impl FnOnce(&VerifiedOfflineConfig<'_>, &ActiveModel) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let boot = epochs
            .confirmed_config_boot(config)
            .map_err(|_| Error::NotReady)?;
        let manager = roles
            .manifest()
            .members
            .iter()
            .find(|m| m.role == Role::ModelManager)
            .ok_or(Error::Denied)?
            .actor;
        if epochs
            .service_generation(Role::ModelManager)
            .map_err(|_| Error::Stale)?
            != manager.generation
        {
            return Err(Error::Stale);
        }
        let state = Self::restore(boot, manager, persisted)?;
        // Verify both immutable packages and their current schemas and
        // prove that no pending generation transition is unresolved.
        verify_native(config, &persisted)?;
        Ok(state)
    }

    fn restore(boot: u64, manager: Identity, state: ActiveModel) -> Result<Self, Error> {
        if boot == 0
            || !manager.valid()
            || state.generation == 0
            || !state.active.valid()
            || state.previous.is_some_and(|p| {
                !p.valid()
                    || state.generation < 2
                    || p.schemas != state.active.schemas
                    || p.parameter_hash == state.active.parameter_hash
                    || p.candidate == state.active.candidate
            })
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            boot,
            manager,
            state,
            pending: None,
        })
    }

    pub fn active(&self) -> Result<ActiveModel, Error> {
        if self.pending.is_some() {
            return Err(Error::NotReady);
        }
        Ok(self.state)
    }

    /// Invoke under the same EL1 serialization as model switch and final
    /// publish. Previously accepted plans keep their original obligations.
    pub fn check_publication_model(&self, boot: u64, plan_wire: &[u8]) -> Result<(), Error> {
        if boot != self.boot {
            return Err(Error::Stale);
        }
        let plan = PlanV2::decode(plan_wire)?;
        if plan.header.flags == 0 {
            return Ok(());
        }
        let state = self.active()?;
        if plan.header.active_model_generation != state.generation
            || plan.action(0)?.model_hash != state.active.parameter_hash
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    pub fn promote(
        &mut self,
        actor: Identity,
        proof: &PromotionProof,
        seal: impl FnOnce(&ModelTransition) -> CommitOutcome,
    ) -> Result<ActiveModel, Error> {
        if actor != self.manager || actor != proof.manager {
            return Err(Error::Denied);
        }
        let current = self.active()?;
        if proof.boot != self.boot
            || proof.expected_generation != current.generation
            || proof.parent_hash != current.active.parameter_hash
            || proof.revision.schemas != current.active.schemas
            || proof.revision.candidate == current.active.candidate
        {
            return Err(Error::Stale);
        }
        self.commit(
            proof.revision,
            Change::Promote {
                permit_id: proof.permit_id,
                evidence_digest: proof.evidence_digest,
            },
            seal,
        )
    }

    pub fn rollback(
        &mut self,
        actor: Identity,
        expected_generation: u64,
        revision: ModelRevision,
        seal: impl FnOnce(&ModelTransition) -> CommitOutcome,
    ) -> Result<ActiveModel, Error> {
        if actor != self.manager {
            return Err(Error::Denied);
        }
        let current = self.active()?;
        if current.generation != expected_generation {
            return Err(Error::Stale);
        }
        if current.previous != Some(revision) {
            return Err(Error::Denied);
        }
        self.commit(revision, Change::Rollback, seal)
    }

    fn commit(
        &mut self,
        revision: ModelRevision,
        change: Change,
        seal: impl FnOnce(&ModelTransition) -> CommitOutcome,
    ) -> Result<ActiveModel, Error> {
        let generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let transition = ModelTransition {
            boot: self.boot,
            before: self.state,
            after: ActiveModel {
                generation,
                active: revision,
                previous: Some(self.state.active),
            },
            change,
        };
        self.pending = Some(transition);
        // The committer independently verifies the current mode and both
        // immutable packages, rechecks live trial or rollback evidence,
        // and durably seals the active selector and audit record.
        let outcome = seal(&transition);
        self.finish(transition, outcome)
    }

    pub fn reconcile(
        &mut self,
        transition: ModelTransition,
        verify_native: impl FnOnce(&ModelTransition) -> CommitOutcome,
    ) -> Result<ActiveModel, Error> {
        if self.pending != Some(transition) {
            return Err(Error::Stale);
        }
        let outcome = verify_native(&transition);
        self.finish(transition, outcome)
    }

    fn finish(
        &mut self,
        transition: ModelTransition,
        outcome: CommitOutcome,
    ) -> Result<ActiveModel, Error> {
        match outcome {
            CommitOutcome::Unknown => Err(Error::NotReady),
            CommitOutcome::NoEffect => {
                self.pending = None;
                Err(Error::Denied)
            }
            CommitOutcome::Durable => {
                self.state = transition.after;
                self.pending = None;
                Ok(self.state)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::{
        apply_report_v1::{MAX_APPLY_REPORT_BYTES, PlanKey},
        decision_record_v3::{DECISION_BYTES, DECISION_MAGIC, DECISION_VERSION},
        learning_data_v0199::ValidationEvidence,
        plan_wire_v2::{PLAN_MAGIC, POLICY_MAGIC},
    };
    use cyxia_control_model::reward_v2::RequestResult;

    const MANAGER: Identity = Identity {
        id: 3,
        generation: 7,
    };
    const TARGET: Identity = Identity {
        id: 15,
        generation: 1,
    };
    const SCHEMAS: SchemaBinding = SchemaBinding {
        feature: [1; 32],
        action: [2; 32],
        reward: [3; 32],
        learning: [4; 32],
    };
    const FIRST: ModelRevision = ModelRevision {
        candidate: Identity {
            id: 1,
            generation: 1,
        },
        parameter_hash: [1; 32],
        schemas: SCHEMAS,
        validation_digest: [5; 32],
    };
    const CANDIDATE: ModelRevision = ModelRevision {
        candidate: Identity {
            id: 2,
            generation: 3,
        },
        parameter_hash: [2; 32],
        schemas: SCHEMAS,
        validation_digest: [6; 32],
    };

    fn put<const N: usize>(bytes: &mut [u8], at: usize, value: [u8; N]) {
        bytes[at..at + N].copy_from_slice(&value);
    }

    fn shadow() -> ShadowReady {
        ShadowReady::lifecycle_fixture(
            MANAGER,
            5,
            1,
            ValidationEvidence {
                candidate: CANDIDATE.parameter_hash,
                parent: FIRST.parameter_hash,
                training: [7; 32],
                holdout: [8; 32],
            },
            SCHEMAS,
            TARGET,
        )
    }

    fn permit() -> Permit {
        let mut order = [u16::MAX; 32];
        order[0] = 2;
        Permit {
            permit_id: 44,
            boot_epoch: 5,
            rules_generation: 4,
            target_id: TARGET.id,
            target_generation: TARGET.generation,
            start_ns: SECOND_NS,
            expires_ns: 11 * SECOND_NS,
            rule_id: 3,
            domain: 15,
            order_count: 1,
            flags: 1,
            max_submissions: 100,
            cpu_budget_ns: 1,
            memory_budget_bytes: 0,
            rule_hash: [7; 32],
            model_hash: CANDIDATE.parameter_hash,
            template_id: 9,
            model_generation: CANDIDATE.candidate.generation,
            order,
        }
    }

    fn open() -> CanaryGate {
        CanaryGate::start(shadow(), MANAGER, CANDIDATE, permit(), 2, |p, c, s| {
            assert_eq!(*p, permit());
            assert_eq!(*c, CANDIDATE);
            assert_eq!(s.scope().3, [5; 32]);
            Ok(())
        })
        .unwrap()
    }

    fn rows(start: u64, latency: u64) -> [Request; 100] {
        core::array::from_fn(|i| Request {
            id: i as u64 + 1,
            arrived_ns: start + i as u64,
            result: RequestResult::Completed {
                finished_ns: start + i as u64 + latency,
            },
        })
    }

    fn measure(gate: &mut CanaryGate, i: u64, latency: u64) -> Result<(), Error> {
        let start = SECOND_NS * (i + 1);
        let reference = rows(start + 1, 100);
        let candidate = rows(start, latency);
        gate.record_second(
            start + SECOND_NS,
            CanarySecond {
                baseline_start_ns: start + 1,
                baseline: &reference,
                trial: &candidate,
                evidence_digest: [1 + i as u8; 32],
            },
            &mut [0; 100],
            |p, sec, _| {
                assert_eq!(*p, permit());
                assert_eq!(u64::from(sec), i);
                Ok(())
            },
        )
    }

    fn feedback(
        plan_seq: u64,
        accepted_ns: u64,
        completed_ns: u64,
        state: ActionStatus,
    ) -> FeedbackRecord {
        let p = permit();
        let mut decision = [0; DECISION_BYTES];
        put(&mut decision, 0, DECISION_MAGIC.to_le_bytes());
        put(&mut decision, 4, DECISION_VERSION.to_le_bytes());
        put(&mut decision, 6, (DECISION_BYTES as u16).to_le_bytes());
        for (at, value) in [
            (8, p.boot_epoch),
            (16, 1),
            (24, plan_seq),
            (32, plan_seq),
            (40, 8),
            (48, TARGET.id),
            (56, TARGET.generation),
            (64, 1),
            (72, 2),
            (80, p.rules_generation),
            (136, p.permit_id),
            (144, accepted_ns + 1),
        ] {
            put(&mut decision, at, value.to_le_bytes());
        }
        put(&mut decision, 88, p.rule_id.to_le_bytes());
        put(&mut decision, 94, p.domain.to_le_bytes());
        put(&mut decision, 96, 1u16.to_le_bytes());
        decision[99] = 2;
        decision[100] = 3;
        put(&mut decision, 104, u16::MAX.to_le_bytes());
        put(&mut decision, 108, 5u32.to_le_bytes());
        put(&mut decision, 152, 1u32.to_le_bytes());
        put(&mut decision, 158, 2u16.to_le_bytes());
        put(&mut decision, 160, p.rule_hash);
        decision[192..224].fill(7);
        decision[224..].fill(8);
        let mut report = [0; MAX_APPLY_REPORT_BYTES];
        let n = ApplyReportV1 {
            key: PlanKey {
                boot_epoch: p.boot_epoch,
                controller_epoch: 1,
                plan_seq,
            },
            action_index: 0,
            domain_id: 15,
            state,
            target: TARGET,
            executor_generation: 1,
            plan_version: 2,
            result: 0,
            completed_ns,
            action: &[8, 0],
        }
        .encode(&mut report)
        .unwrap();
        FeedbackRecord {
            decision,
            report,
            report_len: n as u16,
            causal_label: CausalLabel::NoAdoption,
            advice: None,
        }
    }

    fn trial<'a>(receipts: &'a [CanaryReceipt<'a>], unresolved: u32) -> FrozenTrial<'a> {
        FrozenTrial {
            accepted: receipts.len() as u32,
            unresolved,
            receipts,
            evidence_digest: [10; 32],
        }
    }

    fn plan(generation: u64, hash: [u8; 32]) -> [u8; 212] {
        let mut bytes = [0; 212];
        put(&mut bytes, 0, PLAN_MAGIC.to_le_bytes());
        put(&mut bytes, 4, 2u16.to_le_bytes());
        put(&mut bytes, 6, 64u16.to_le_bytes());
        put(&mut bytes, 8, 212u32.to_le_bytes());
        put(&mut bytes, 12, 1u16.to_le_bytes());
        put(&mut bytes, 14, u16::from(generation != 0).to_le_bytes());
        for (at, v) in [
            (16, 1u64),
            (32, generation),
            (40, 2),
            (48, 3),
            (56, 10000),
            (80, 2),
            (88, 4),
            (96, 3),
            (104, 17),
            (112, 1),
            (120, 5),
            (128, 6),
            (136, 200),
        ] {
            put(&mut bytes, at, v.to_le_bytes());
        }
        put(&mut bytes, 64, POLICY_MAGIC.to_le_bytes());
        put(&mut bytes, 68, 2u16.to_le_bytes());
        put(&mut bytes, 70, 144u16.to_le_bytes());
        put(&mut bytes, 72, 1u16.to_le_bytes());
        put(&mut bytes, 74, 1u16.to_le_bytes());
        put(&mut bytes, 76, 4u32.to_le_bytes());
        put(&mut bytes, 144, hash);
        bytes[176] = 1;
        put(&mut bytes, 208, 1u16.to_le_bytes());
        put(&mut bytes, 210, 2u16.to_le_bytes());
        bytes
    }

    #[test]
    fn canary_rejects_unbound_measurements_and_three_degraded_seconds() {
        let mut bad = permit();
        bad.model_generation += 1;
        assert!(matches!(
            CanaryGate::start(shadow(), MANAGER, CANDIDATE, bad, 0, |_, _, _| panic!()),
            Err(Error::Denied)
        ));
        assert!(matches!(
            CanaryGate::start(shadow(), MANAGER, CANDIDATE, permit(), 0, |_, _, _| Err(
                Error::Stale
            )),
            Err(Error::Stale)
        ));
        let mut gate = open();
        let baseline = rows(1, 100);
        let mut trial_rows = rows(SECOND_NS, 100);
        let capture = |trial| CanarySecond {
            baseline_start_ns: 1,
            baseline: &baseline[..trial],
            trial: &trial_rows[..trial],
            evidence_digest: [5; 32],
        };
        assert_eq!(
            gate.record_second(
                2 * SECOND_NS - 1,
                capture(100),
                &mut [0; 100],
                |_, _, _| panic!()
            ),
            Err(Error::Denied)
        );
        assert_eq!(
            gate.record_second(2 * SECOND_NS, capture(99), &mut [0; 100], |_, _, _| Ok(())),
            Err(Error::NotReady)
        );
        trial_rows.swap(0, 1);
        assert_eq!(
            gate.record_second(
                2 * SECOND_NS,
                CanarySecond {
                    baseline_start_ns: 1,
                    baseline: &baseline,
                    trial: &trial_rows,
                    evidence_digest: [5; 32],
                },
                &mut [0; 100],
                |_, _, _| Ok(())
            ),
            Err(Error::Denied)
        );
        assert_eq!(measure(&mut gate, 0, 111), Ok(()));
        assert_eq!(measure(&mut gate, 1, 110), Ok(()));
        assert_eq!(measure(&mut gate, 2, 111), Ok(()));
        assert_eq!(measure(&mut gate, 3, 111), Ok(()));
        assert_eq!(measure(&mut gate, 4, 111), Err(Error::Denied));
        assert_eq!(measure(&mut gate, 5, 100), Err(Error::NotReady));
    }

    #[test]
    fn promotion_requires_closed_permit_and_verified_applied_feedback() {
        let mut gate = open();
        let p = permit();
        let accepted = p.start_ns;
        let rejected = feedback(1, accepted, accepted + 1, ActionStatus::Rejected);
        let unknown = feedback(1, accepted, accepted + 1, ActionStatus::Unknown);
        let applied = feedback(1, accepted, accepted + 1, ActionStatus::Applied);
        let receipt = |f| CanaryReceipt {
            accepted_ns: accepted,
            feedback: f,
        };
        assert!(matches!(
            gate.seal(
                MANAGER,
                p.expires_ns,
                trial(&[receipt(&applied)], 0),
                |_, _| panic!()
            ),
            Err(Error::NotReady)
        ));
        for i in 0..10 {
            measure(&mut gate, i, 100).unwrap();
        }
        for (f, unresolved, error) in [
            (&rejected, 0, Error::NotReady),
            (&applied, 1, Error::NotReady),
            (&unknown, 0, Error::Denied),
        ] {
            assert!(matches!(
                gate.seal(MANAGER, p.expires_ns, trial(&[receipt(f)], unresolved), |_, _| Ok(())),
                Err(got) if got == error
            ));
        }
        let same_window = feedback(2, accepted + 2, accepted + 3, ActionStatus::Applied);
        assert!(matches!(
            gate.seal(
                MANAGER,
                p.expires_ns,
                trial(
                    &[
                        receipt(&applied),
                        CanaryReceipt {
                            accepted_ns: accepted + 2,
                            feedback: &same_window
                        },
                    ],
                    0
                ),
                |_, _| Ok(())
            ),
            Err(Error::Denied)
        ));
        let unresolved_previous =
            feedback(1, accepted, accepted + WINDOW_NS + 1, ActionStatus::Applied);
        let next = feedback(
            2,
            accepted + WINDOW_NS,
            accepted + WINDOW_NS + 1,
            ActionStatus::Applied,
        );
        assert!(matches!(
            gate.seal(
                MANAGER,
                p.expires_ns,
                trial(
                    &[
                        receipt(&unresolved_previous),
                        CanaryReceipt {
                            accepted_ns: accepted + WINDOW_NS,
                            feedback: &next
                        },
                    ],
                    0
                ),
                |_, _| Ok(())
            ),
            Err(Error::Denied)
        ));
        assert!(matches!(
            gate.seal(
                MANAGER,
                p.expires_ns,
                trial(&[receipt(&applied)], 0),
                |_, _| Err(Error::Denied)
            ),
            Err(Error::Denied)
        ));
        let proof = gate
            .seal(
                MANAGER,
                p.expires_ns,
                trial(&[receipt(&applied)], 0),
                |actual, evidence| {
                    assert_eq!(*actual, p);
                    assert_eq!(
                        evidence.receipts[0].feedback.evidence_digest(),
                        applied.evidence_digest()
                    );
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(proof.permit_id, p.permit_id);
        assert_ne!(proof.evidence_digest, [0; 32]);
    }

    #[test]
    fn unknown_switch_retains_custody_and_rollback_never_revives_old_plan() {
        let mut gate = open();
        for i in 0..10 {
            measure(&mut gate, i, 100).unwrap();
        }
        let p = permit();
        let effect = feedback(1, p.start_ns, p.start_ns + 1, ActionStatus::Applied);
        let proof = gate
            .seal(
                MANAGER,
                p.expires_ns,
                trial(
                    &[CanaryReceipt {
                        accepted_ns: p.start_ns,
                        feedback: &effect,
                    }],
                    0,
                ),
                |_, _| Ok(()),
            )
            .unwrap();
        let initial = ActiveModel {
            generation: 1,
            active: FIRST,
            previous: None,
        };
        let mut active = ModelLifecycle::restore(p.boot_epoch, MANAGER, initial).unwrap();
        let old_plan = plan(1, FIRST.parameter_hash);
        let rule_plan = plan(0, [0; 32]);
        assert_eq!(
            active.check_publication_model(p.boot_epoch, &old_plan),
            Ok(())
        );
        assert_eq!(
            active.promote(
                Identity {
                    generation: 6,
                    ..MANAGER
                },
                &proof,
                |_| panic!()
            ),
            Err(Error::Denied)
        );
        let mut pending = None;
        assert_eq!(
            active.promote(MANAGER, &proof, |change| {
                pending = Some(*change);
                CommitOutcome::Unknown
            }),
            Err(Error::NotReady)
        );
        assert_eq!(
            active.check_publication_model(p.boot_epoch, &old_plan),
            Err(Error::NotReady)
        );
        assert_eq!(
            active.check_publication_model(p.boot_epoch, &rule_plan),
            Ok(())
        );
        let pending = pending.unwrap();
        let wrong = ModelTransition { boot: 6, ..pending };
        assert_eq!(active.reconcile(wrong, |_| panic!()), Err(Error::Stale));
        let current = active
            .reconcile(pending, |_| CommitOutcome::Durable)
            .unwrap();
        assert_eq!(current.generation, 2);
        assert_eq!(current.active, CANDIDATE);
        assert_eq!(
            active.promote(MANAGER, &proof, |_| panic!()),
            Err(Error::Stale)
        );
        assert_eq!(
            active.rollback(MANAGER, 2, CANDIDATE, |_| panic!()),
            Err(Error::Denied)
        );
        let rolled_back = active
            .rollback(MANAGER, 2, FIRST, |_| CommitOutcome::Durable)
            .unwrap();
        assert_eq!(rolled_back.generation, 3);
        assert_eq!(rolled_back.active, FIRST);
        assert_eq!(
            active.check_publication_model(p.boot_epoch, &old_plan),
            Err(Error::Stale)
        );
        assert_eq!(
            active.check_publication_model(p.boot_epoch, &plan(3, FIRST.parameter_hash)),
            Ok(())
        );
    }
}
