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

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROLLER:Identity=Identity{id:2,generation:1};
    const PUBLISHER:Identity=Identity{id:8,generation:1};

    fn profile_bytes() -> [u8;80] {
        let mut b=[0u8;80];
        b[0..4].copy_from_slice(&0x4359_5255u32.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[6..8].copy_from_slice(&32u16.to_le_bytes());
        b[8..16].copy_from_slice(&7u64.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b[20..24].copy_from_slice(&80u32.to_le_bytes());
        b[32..36].copy_from_slice(&1u32.to_le_bytes());
        b[36..38].copy_from_slice(&1u16.to_le_bytes()); // D01
        b[38..40].copy_from_slice(&1u16.to_le_bytes()); // kind=1
        b[40..48].copy_from_slice(&17u64.to_le_bytes());
        b[52..54].copy_from_slice(&2u16.to_le_bytes()); // two legal values
        b[56..60].copy_from_slice(&48u32.to_le_bytes());
        b[64..66].copy_from_slice(&2u16.to_le_bytes()); // ordinal 2, rank 0
        b[72..74].copy_from_slice(&4u16.to_le_bytes()); // ordinal 4
        b[74..76].copy_from_slice(&1u16.to_le_bytes()); // rank 1
        b
    }
    fn plan_bytes() -> [u8;212] {
        let mut b=[0u8;212];
        b[0..4].copy_from_slice(&0x4359_4c31u32.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[6..8].copy_from_slice(&64u16.to_le_bytes());
        b[8..12].copy_from_slice(&212u32.to_le_bytes());
        b[12..14].copy_from_slice(&1u16.to_le_bytes()); // action count
        b[16..24].copy_from_slice(&1u64.to_le_bytes()); // plan sequence
        b[40..48].copy_from_slice(&2u64.to_le_bytes()); // controller epoch
        b[48..56].copy_from_slice(&3u64.to_le_bytes()); // snapshot sequence
        b[56..64].copy_from_slice(&10_000_000_100u64.to_le_bytes());
        let h=64;
        b[h..h+4].copy_from_slice(&0x4359_5031u32.to_le_bytes());
        b[h+4..h+6].copy_from_slice(&2u16.to_le_bytes());
        b[h+6..h+8].copy_from_slice(&144u16.to_le_bytes());
        b[h+8..h+10].copy_from_slice(&1u16.to_le_bytes()); // D01
        b[h+10..h+12].copy_from_slice(&1u16.to_le_bytes()); // action kind
        b[h+12..h+16].copy_from_slice(&4u32.to_le_bytes()); // payload len
        for (at,value) in [
            (16,2u64), (24,4), (32,3), (40,17),
            (48,1), (56,5), (64,6), (72,200),
        ] { b[h+at..h+at+8].copy_from_slice(&value.to_le_bytes()); }
        b[h+112..h+144].copy_from_slice(&[1u8;32]); // candidate set digest
        b[h+144..h+146].copy_from_slice(&0u16.to_le_bytes()); // candidate index
        b[h+146..h+148].copy_from_slice(&[2u8,0]); // native D01 action payload
        b
    }
    fn decision(plan:&[u8],rules:&[u8]) -> [u8;DECISION_BYTES] {
        let mut b=[0u8;DECISION_BYTES];
        b[0..4].copy_from_slice(&0x4359_4431u32.to_le_bytes());
        b[4..6].copy_from_slice(&3u16.to_le_bytes());
        b[6..8].copy_from_slice(&256u16.to_le_bytes());
        for (at,value) in [
            (8,1u64), (16,2), (24,4), (32,1), (40,3),
            (48,17), (56,1), (64,5), (72,6), (80,7), (144,200),
        ] { b[at..at+8].copy_from_slice(&value.to_le_bytes()); }
        b[88..92].copy_from_slice(&1u32.to_le_bytes());
        b[94..96].copy_from_slice(&1u16.to_le_bytes());
        b[96..98].copy_from_slice(&1u16.to_le_bytes());
        b[104..106].copy_from_slice(&u16::MAX.to_le_bytes());
        b[108..112].copy_from_slice(&2u32.to_le_bytes()); // RULE_ONLY baseline
        b[152..156].copy_from_slice(&3u32.to_le_bytes());
        b[160..192].copy_from_slice(&sha256(rules));
        b[192..224].copy_from_slice(&sha256(plan));
        b[224..256].copy_from_slice(&[1u8;32]);
        b
    }
    fn trusted(rules:&[u8]) -> TrustedRegistrationScope {
        TrustedRegistrationScope {
            boot_epoch:1, controller_epoch:2, rules_generation:7,
            rules_hash:sha256(rules), base_plan_version:0,
            ledger_generation:5, core_generation:6, snapshot_seq:3,
            sampled_ns:100, now_ns:150,
        }
    }
    fn frozen<'a>(ordinals:&'a[u16],payload:&'a[u8]) -> [FrozenAction<'a>;1] {
        [FrozenAction {
            domain_id:1, target:Identity{id:17,generation:1},
            candidate_set_hash:[1;32],static_ordinals:ordinals,
            raw_fields:[None;7], action_payload:payload,
        }]
    }
    #[test]
    fn authenticated_exact_registration_and_single_shot_native_callback() {
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        assert_eq!(gate.register_rule_only(
            PUBLISHER,&plan,&records,&catalog,&frozen,ctx
        ),Err(Error::Denied));
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&records,&catalog,&frozen,ctx
        ),Ok(Registration::Frozen));
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&records,&catalog,&frozen,ctx
        ),Ok(Registration::ExactRetry));
        let mut invoked=0u32;
        assert_eq!(gate.publish_once(
            CONTROLLER,&plan,&records,&catalog,&frozen,ctx,
            ||{invoked+=1;Ok(())}
        ),Err(Error::Denied));
        assert_eq!(gate.publish_once(
            PUBLISHER,&plan,&records,&catalog,&frozen,ctx,
            ||{invoked+=1;Ok(())}
        ),Ok(Publication::AdapterAccepted));
        assert_eq!(invoked,1);
        assert_eq!(gate.publish_once(
            PUBLISHER,&plan,&records,&catalog,&frozen,ctx,
            ||{invoked+=1;Ok(())}
        ),Ok(Publication::ReplayNoEffect));
        assert_eq!(invoked,1);
        assert_eq!(gate.expire_unpublished(CONTROLLER,201),Err(Error::NotReady));
    }
    #[test]
    fn tampered_digest_rule_epoch_target_or_decision_will_not_reach_native_adapter() {
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let mut rec=decision(&plan,&bytes);
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        let mut wrong=rec;wrong[192]=wrong[192].wrapping_add(1);
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&[wrong],&catalog,&frozen,ctx
        ),Err(Error::Denied));
        let mut stale=ctx;stale.rules_generation=8;
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&[rec],&catalog,&frozen,stale
        ),Err(Error::Stale));
        rec[48..56].copy_from_slice(&18u64.to_le_bytes());
        assert!(gate.register_rule_only(
            CONTROLLER,&plan,&[rec],&catalog,&frozen,ctx
        ).is_err());
        rec=decision(&plan,&bytes);
        gate.register_rule_only(CONTROLLER,&plan,&[rec],&catalog,&frozen,ctx).unwrap();
        let mut bad_plan=plan;bad_plan[209]=1;
        let mut invoked=false;
        assert!(gate.publish_once(
            PUBLISHER,&bad_plan,&[rec],&catalog,&frozen,ctx,
            ||{invoked=true;Ok(())}
        ).is_err());
        assert!(!invoked);
        let mut bad_record=rec;bad_record[224]=2;
        assert!(gate.publish_once(
            PUBLISHER,&plan,&[bad_record],&catalog,&frozen,ctx,
            ||{invoked=true;Ok(())}
        ).is_err());
        assert!(!invoked);
        assert_eq!(gate.expire_unpublished(CONTROLLER,200),Ok(true));
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&[rec],&catalog,&frozen,ctx
        ),Err(Error::Stale));
    }
    #[test]
    fn unknown_adapter_result_keeps_key_consumed_and_blocks_reexecution() {
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx).unwrap();
        let mut attempts=0u32;
        assert_eq!(gate.publish_once(
            PUBLISHER,&plan,&records,&catalog,&frozen,ctx,
            ||{attempts+=1;Err(Error::Busy)}
        ),Err(Error::Busy));
        assert_eq!(gate.publish_once(
            PUBLISHER,&plan,&records,&catalog,&frozen,ctx,
            ||{attempts+=1;Ok(())}
        ),Ok(Publication::ReplayNoEffect));
        assert_eq!(attempts,1);
        assert_eq!(gate.expire_unpublished(CONTROLLER,200),Err(Error::NotReady));
    }
    #[test]
    fn trial_and_advice_without_disposition_or_permit_are_not_authorized() {
        let rules=profile_bytes();
        let catalog=Profile::parse(&rules).unwrap();
        let mut plan=plan_bytes();
        let mut rec=decision(&plan,&rules);
        rec[108..112].copy_from_slice(&7u32.to_le_bytes());
        let ctx=trusted(&rules);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&[rec],&catalog,&frozen,ctx
        ),Err(Error::NotReady)); // source0 reason7 needs frozen AdviceDisposition
        rec=decision(&plan,&rules);
        plan[14]=1; // AI assisted header, no trusted Active model
        assert!(gate.register_rule_only(
            CONTROLLER,&plan,&[rec],&catalog,&frozen,ctx
        ).is_err());
    }
}
