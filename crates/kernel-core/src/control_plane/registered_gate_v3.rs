//! Bounded, no-alloc EL1 DecisionRecord v3 registration/publication guard.
//!
//! Narrow V0.19.9 G1 vertical slice: RULE_ONLY plans without an AI disposition
//! or TrialPermit. Other sources FAIL CLOSED as NotReady. This is not an SVC
//! handler, credential loader or proof of a native driver APPLY. The only way
//! to call the publication adapter is via an exact previously frozen plan.
//! The adapter must be an EL1 native owner, and must report actual acceptance
//! separately from any eventual per-action APPLIED/UNKNOWN receipt.
use sha2::{Digest, Sha256};
use super::{
    Error, Identity,
    decision_record_v3::{DecisionRecordV3, DecisionSource, DECISION_BYTES},
    plan_wire_v2::{PlanV2, MAX_ACTIONS},
    rule_profile_v2::Profile,
};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest=Sha256::new();
    digest.update(bytes);
    digest.finalize().into()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registration {
    Frozen,
    ExactRetry,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    AdapterAccepted,
    ReplayNoEffect,
}

/// The EL1 caller must derive every field from protected local state, never
/// from model-advertised identities, hashes or clock values.
#[derive(Clone, Copy, Debug)]
pub struct TrustedRegistrationScope {
    pub boot_epoch: u64,
    pub controller_epoch: u64,
    pub rules_generation: u64,
    pub rules_hash: [u8;32],
    pub base_plan_version: u64,
    pub ledger_generation: u64,
    pub core_generation: u64,
    pub snapshot_seq: u64,
    pub sampled_ns: u64,
    pub now_ns: u64,
}

/// One frozen local candidate set registered by the deterministic controller.
/// ActionSchema decoding, memory/CPU quotas and permission checks must already
/// have been performed independently by EL1 and be rechecked at PUBLISH.
pub struct FrozenAction<'a> {
    pub domain_id: u16,
    pub target: Identity,
    pub candidate_set_hash: [u8;32],
    pub static_ordinals: &'a [u16],
    pub raw_fields: [Option<u64>;7],
    pub action_payload: &'a [u8],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingStatus { Frozen, AdapterAccepted, AdapterUnknown }
struct Pending {
    plan_seq: u64,
    plan_digest: [u8;32],
    count: usize,
    decision_bytes: [[u8;DECISION_BYTES];MAX_ACTIONS],
    status: PendingStatus,
    expires_ns: u64,
}

/// Fixed-memory guard. This can be owned by a protected, serialized EL1
/// executor; no public entry point grants a new CPU, memory page or capability.
/// The caller-supplied Identity must be authenticated by the architecture
/// adapter before reaching this object.
pub struct RegisteredDecisionGate {
    controller: Identity,
    publisher: Identity,
    boot_epoch: u64,
    controller_epoch: u64,
    last_plan_seq: u64,
    last_decision_seq: u64,
    pending: Option<Pending>,
}
impl RegisteredDecisionGate {
    pub fn new(controller: Identity, publisher: Identity, boot: u64, epoch: u64)
        -> Result<Self, Error>
    {
        if !controller.valid() || !publisher.valid()
            || controller == publisher || boot == 0 || epoch == 0
        {return Err(Error::Invalid);}
        Ok(Self {
            controller, publisher, boot_epoch:boot, controller_epoch:epoch,
            last_plan_seq:0,last_decision_seq:0,pending:None,
        })
    }

    fn check_identity_and_context(&self, context: TrustedRegistrationScope)
        -> Result<(),Error>
    {
        if context.boot_epoch != self.boot_epoch
            || context.controller_epoch != self.controller_epoch
            || context.boot_epoch == 0 || context.controller_epoch == 0
            || context.rules_generation == 0 || context.rules_hash == [0;32]
            || context.ledger_generation == 0 || context.core_generation == 0
            || context.snapshot_seq == 0
            || context.sampled_ns > context.now_ns
            || !context.sampled_ns.checked_add(100_000_000)
                .is_some_and(|end| context.now_ns < end)
        {return Err(Error::Stale);}
        Ok(())
    }

    /// No user/model-provided SHA, no unregistered sidecar, and no AI/trial
    /// source is accepted. Idempotent retries preserve the *first* frozen
    /// bytes and do not reset expiry or high-water sequence numbers.
    pub fn register_rule_only(
        &mut self,
        actor: Identity,
        plan_wire: &[u8],
        records: &[[u8; DECISION_BYTES]],
        rule_profile: &Profile<'_>,
        actions: &[FrozenAction<'_>],
        context: TrustedRegistrationScope,
    ) -> Result<Registration,Error> {
        if actor != self.controller {return Err(Error::Denied);}
        let plan=PlanV2::decode(plan_wire)?;
        if let Some(pending)=&self.pending {
            let same_key=plan.header.plan_seq==pending.plan_seq;
            let same_bytes=same_key
                && sha256(plan_wire)==pending.plan_digest
                && records.len()==pending.count
                && records.iter().zip(pending.decision_bytes[..pending.count].iter())
                    .all(|(a,b)| a==b);
            return if same_bytes {
                Ok(Registration::ExactRetry)
            } else if same_key {
                Err(Error::Denied)
            } else {
                Err(Error::Busy)
            };
        }
        self.validate_rule_only(plan_wire, &plan, records, rule_profile, actions,context)?;
        if plan.header.plan_seq<=self.last_plan_seq {return Err(Error::Stale);}
        let mut last=self.last_decision_seq;
        for raw in records {
            let record=DecisionRecordV3::decode(raw)?;
            if record.decision_seq<=last {return Err(Error::Stale);}
            last=record.decision_seq;
        }
        let mut copied=[[0u8;DECISION_BYTES];MAX_ACTIONS];
        for (dest,src) in copied.iter_mut().zip(records) {*dest=*src;}
        let mut expires=u64::MAX;
        for index in 0..usize::from(plan.header.action_count) {
            expires=expires.min(plan.action(index)?.expires_local_ns);
        }
        self.pending=Some(Pending {
            plan_seq:plan.header.plan_seq,
            plan_digest:sha256(plan_wire),
            count:records.len(),
            decision_bytes:copied,
            status:PendingStatus::Frozen,
            expires_ns:expires,
        });
        self.last_plan_seq=plan.header.plan_seq;
        self.last_decision_seq=last;
        Ok(Registration::Frozen)
    }

    fn validate_rule_only(
        &self,
        plan_wire:&[u8],
        plan:&PlanV2<'_>,
        records:&[[u8;DECISION_BYTES]],
        profile:&Profile<'_>,
        actions:&[FrozenAction<'_>],
        context: TrustedRegistrationScope,
    ) -> Result<(),Error> {
        self.check_identity_and_context(context)?;
        if plan.header.flags != 0 {return Err(Error::NotReady);}
        if rule_profile_mismatch(profile,context) {return Err(Error::Stale);}
        if records.len()!=usize::from(plan.header.action_count)
            || actions.len()!=records.len()
            || plan.header.base_plan_version!=context.base_plan_version
            || plan.header.controller_epoch!=context.controller_epoch
            || plan.header.snapshot_seq!=context.snapshot_seq
        {return Err(Error::Stale);}
        plan.matches_untrusted_sidecars(records)?;
        let digest=sha256(plan_wire);
        let admission_end=context.sampled_ns.checked_add(100_000_000)
            .ok_or(Error::Clock)?;
        let installed_end=context.sampled_ns.checked_add(10_000_000_000)
            .ok_or(Error::Clock)?;
        if plan.header.active_until_local_ns!=0
            && plan.header.active_until_local_ns!=installed_end
        {return Err(Error::Invalid);}
        let mut last_seq=0u64;
        for (index,(raw,local)) in records.iter().zip(actions).enumerate() {
            let rec=DecisionRecordV3::decode(raw)?;
            let act=plan.action(index)?;
            if rec.source!=DecisionSource::RuleOnly
                || rec.reason_code==7 // requires frozen AdviceDisposition v1
            {return Err(Error::NotReady);}
            if rec.boot_epoch!=context.boot_epoch
                || rec.rules_generation!=context.rules_generation
                || rec.rules_hash!=context.rules_hash
                || rec.plan_digest!=digest
                || rec.decision_seq<=last_seq
                || rec.target_id!=local.target.id
                || rec.target_generation!=local.target.generation
                || rec.domain_id!=local.domain_id
                || act.candidate_set_hash!=local.candidate_set_hash
                || rec.candidate_set_hash!=local.candidate_set_hash
                || act.action_payload!=local.action_payload
                || act.expires_local_ns<=context.now_ns
                || act.expires_local_ns>admission_end
                || !local.target.valid()
            {return Err(Error::Denied);}
            let rule=profile.match_candidates(
                local.domain_id,local.target.id,local.raw_fields,
                super::rule_profile_v2::Candidates {
                    static_ordinals:local.static_ordinals,
                },
            )?.ok_or(Error::Denied)?;
            if !rec.matches_rule(rule)
                || !rec.matches_candidate_count(local.static_ordinals.len())
                || rec.selected_index!=rule.fallback_index
            {return Err(Error::Denied);}
            last_seq=rec.decision_seq;
        }
        Ok(())
    }

    /// Invokes the caller's **EL1 native publication adapter at most once**,
    /// only for the exact frozen bytes and a still-current trusted snapshot.
    /// A callback failure is UNKNOWN: never replay it as not-executed. A
    /// successful adapter return only means accepted, NOT per-action APPLIED.
    pub fn publish_once(
        &mut self,
        actor: Identity,
        plan_wire:&[u8],
        records:&[[u8;DECISION_BYTES]],
        profile:&Profile<'_>,
        actions:&[FrozenAction<'_>],
        context: TrustedRegistrationScope,
        native_accept:impl FnOnce()->Result<(),Error>,
    ) -> Result<Publication,Error> {
        if actor!=self.publisher {return Err(Error::Denied);}
        let pending=self.pending.as_ref().ok_or(Error::Stale)?;
        let plan=PlanV2::decode(plan_wire)?;
        if plan.header.plan_seq!=pending.plan_seq
            || sha256(plan_wire)!=pending.plan_digest
            || records.len()!=pending.count
            || !records.iter().zip(pending.decision_bytes[..pending.count].iter())
                .all(|(a,b)| a==b)
        {return Err(Error::Denied);}
        if pending.status!=PendingStatus::Frozen {
            return Ok(Publication::ReplayNoEffect);
        }
        self.validate_rule_only(plan_wire,&plan,records,profile,actions,context)?;
        // Mark before the potentially side-effecting callback; failures
        // cannot safely be interpreted as "nothing happened".
        self.pending.as_mut().ok_or(Error::Stale)?.status=PendingStatus::AdapterUnknown;
        let result=native_accept();
        if result.is_ok() {
            self.pending.as_mut().ok_or(Error::Stale)?.status=PendingStatus::AdapterAccepted;
            Ok(Publication::AdapterAccepted)
        } else {
            result.map(|_|Publication::AdapterAccepted)
        }
    }

    /// Expired *unpublished* registration may be discarded by the controller;
    /// all high-water keys remain burned. In-flight/unknown work is never
    /// freed without an independent native terminal/recovery proof.
    pub fn expire_unpublished(
        &mut self, actor:Identity, now_ns:u64
    ) -> Result<bool,Error> {
        if actor!=self.controller {return Err(Error::Denied);}
        if let Some(p)=&self.pending {
            if p.status!=PendingStatus::Frozen {return Err(Error::NotReady);}
            if now_ns>=p.expires_ns {
                self.pending=None;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
fn rule_profile_mismatch(profile:&Profile<'_>, ctx:TrustedRegistrationScope) ->bool {
    profile.generation!=ctx.rules_generation
        || sha256(profile.canonical_bytes())!=ctx.rules_hash
}
