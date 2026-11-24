//! Bounded, no-alloc EL1 DecisionRecord v3 registration/publication guard.
//!
//! V0.19.9 G1 vertical slices: RULE_ONLY, single-action causal fallback
//! and AI_ASSISTED with atomic admitted-advice disposition.
//! Ordinary single-action authorized trials use a retained signed permit.
//! Canary remains fail-closed. This is not an SVC
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
    advice_envelope_v1::{AdviceEnvelopeV1,TrustedAdviceScope,ADVICE_BYTES},
    advice_disposition_v1::{AdviceDispositionV1,DISPOSITION_BYTES},
    advice_ledger_v0199::{AdviceKey,EvidenceLedger},
    apply_report_v1::{self,ApplyReportV1,BoundReport,ExecutorBindingV1,TrustedApplyScope},
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

/// Recent terminal summaries are read-only audit/query evidence, not new
/// authorization and never an APPLIED result synthesized by an AI role.
pub const TERMINAL_HISTORY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedTerminal {
    pub boot_epoch: u64,
    pub controller_epoch: u64,
    pub plan_seq: u64,
    pub plan_digest: [u8; 32],
    /// Every action must have a separately verified durable or device terminal.
    pub action_count: u16,
    pub terminal_mask: u16,
    pub unknown_mask: u16,
    pub evidence_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSummary {
    pub plan_seq: u64,
    pub plan_digest: [u8; 32],
    pub action_count: u16,
    pub evidence_digest: [u8; 32],
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
#[derive(Clone,Copy)]
struct AssistedProof {
    advice:[u8;ADVICE_BYTES],
    disposition_digest:[u8;32],
}
/// Supplied from the actual protected Active model, offline configuration
/// and current rule mode. Neither boolean is read from a user/model frame.
pub struct AssistedScope<'a>{
    pub advice:&'a TrustedAdviceScope<'a>,
    pub assisted_mode:bool,
    pub offline_model_authorized:bool,
}
#[derive(Clone,Copy)]
struct ClaimedWork { frame:super::apply_work_v1::WorkFrame, origin:apply_report_v1::ReportOrigin, accepted_ns:u64 }
#[derive(Clone,Copy)]
struct TrialProof{permit_id:u64,permit_hash:[u8;32],hold:Option<super::trial_permit_v1::Hold>,cost_settled:bool}
struct Pending {
    plan_seq: u64,
    plan_digest: [u8;32],
    count: usize,
    decision_bytes: [[u8;DECISION_BYTES];MAX_ACTIONS],
    status: PendingStatus,
    expires_ns: u64,
    assisted:Option<AssistedProof>,
    claimed:[Option<ClaimedWork>;MAX_ACTIONS],
    trial:Option<TrialProof>,
}

/// 64 published nonterminal obligations plus one unpublished candidate.
/// Native owner places this storage in its already accounted control pool;
/// do not construct it on the kernel stack. No slot eviction is permitted.
pub const MAX_PUBLISHED_PLANS:usize=64;
pub struct PublishedPlanPool{
    bound:bool,
    slots:[Option<Pending>;MAX_PUBLISHED_PLANS+1],
}
impl PublishedPlanPool{
    pub const fn new()->Self{Self{bound:false,slots:[const{None};MAX_PUBLISHED_PLANS+1]}}
    pub const fn bytes()->usize{core::mem::size_of::<Self>()}
    fn count_published(&self)->usize{
        self.slots.iter().flatten().filter(|p|p.status!=PendingStatus::Frozen).count()
    }
}
const _:()=assert!(PublishedPlanPool::bytes()<1024*1024);

/// Fixed-memory guard. This can be owned by a protected, serialized EL1
/// executor; no public entry point grants a new CPU, memory page or capability.
/// The caller-supplied Identity must be authenticated by the architecture
/// adapter before reaching this object.
pub struct RegisteredDecisionGate<'pool> {
    controller: Identity,
    publisher: Identity,
    boot_epoch: u64,
    controller_epoch: u64,
    last_plan_seq: u64,
    last_decision_seq: u64,
    pending: Option<Pending>, // legacy single-plan component profile
    pool: Option<&'pool mut PublishedPlanPool>,
    /// Only an EL1-authenticated independent terminal/recovery owner can
    /// close an accepted/UNKNOWN plan. Unconfigured gates stay fail-closed.
    terminal_owner: Option<Identity>,
    history: [Option<TerminalSummary>; TERMINAL_HISTORY],
    history_next: usize,
}
impl<'pool> RegisteredDecisionGate<'pool> {
    pub fn new(controller: Identity, publisher: Identity, boot: u64, epoch: u64)
        -> Result<Self, Error>
    {
        if !controller.valid() || !publisher.valid()
            || controller.id == publisher.id || boot == 0 || epoch == 0
        {return Err(Error::Invalid);}
        Ok(Self {
            controller, publisher, boot_epoch:boot, controller_epoch:epoch,
            last_plan_seq:0,last_decision_seq:0,pending:None,pool:None,
            terminal_owner:None,history:[None;TERMINAL_HISTORY],history_next:0,
        })
    }

    /// Native EL1 must assign an independently authenticated terminal owner
    /// (e.g. role11 supervisor) from its capability table, never EL0 input.
    pub fn new_with_terminal_owner(
        controller:Identity,publisher:Identity,terminal_owner:Identity,
        boot:u64,epoch:u64
    ) -> Result<Self,Error> {
        if !terminal_owner.valid()
            || terminal_owner.id==controller.id || terminal_owner.id==publisher.id
        {return Err(Error::Invalid);}
        let mut gate=Self::new(controller,publisher,boot,epoch)?;
        gate.terminal_owner=Some(terminal_owner);
        Ok(gate)
    }

    /// Full-capacity profile, borrowing an exclusive, preallocated pool.
    /// Its boot-scoped authority remains unique; an occupied pool cannot
    /// be rebound to a new gate or cleared to recover capacity.
    pub fn with_pool(controller:Identity,publisher:Identity,terminal_owner:Identity,
        boot:u64,epoch:u64,pool:&'pool mut PublishedPlanPool)->Result<Self,Error>{
        if pool.bound||pool.slots.iter().any(Option::is_some){return Err(Error::Busy);}
        let mut gate=Self::new_with_terminal_owner(controller,publisher,terminal_owner,boot,epoch)?;
        pool.bound=true;gate.pool=Some(pool);Ok(gate)
    }
    fn lookup(&self,seq:u64)->Option<&Pending>{
        if let Some(pool)=self.pool.as_deref(){
            pool.slots.iter().flatten().find(|p|p.plan_seq==seq)
        }else{self.pending.as_ref().filter(|p|p.plan_seq==seq)}
    }
    fn lookup_mut(&mut self,seq:u64)->Option<&mut Pending>{
        if let Some(pool)=self.pool.as_deref_mut(){
            pool.slots.iter_mut().flatten().find(|p|p.plan_seq==seq)
        }else{self.pending.as_mut().filter(|p|p.plan_seq==seq)}
    }
    fn frozen_or_legacy_busy(&self)->Option<&Pending>{
        if let Some(pool)=self.pool.as_deref(){
            pool.slots.iter().flatten().find(|p|p.status==PendingStatus::Frozen)
        }else{self.pending.as_ref()}
    }
    fn check_registration_slot(&self)->Result<(),Error>{
        if self.frozen_or_legacy_busy().is_some(){return Err(Error::Busy);}
        if self.pool.as_deref().is_some_and(|p|p.slots.iter().all(Option::is_some)){
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn insert_frozen(&mut self,pending:Pending){
        // Checked before any advice ledger mutation. Serialized EL1 owner
        // ensures no competing insertion between preflight and this store.
        if let Some(pool)=self.pool.as_deref_mut(){
            *pool.slots.iter_mut().find(|p|p.is_none()).expect("preflighted pool slot")=Some(pending);
        }else{assert!(self.pending.is_none());self.pending=Some(pending);}
    }
    fn begin_publish(&mut self,seq:u64)->Result<(),Error>{
        if self.published_count()>=MAX_PUBLISHED_PLANS{return Err(Error::Busy);}
        let p=self.lookup_mut(seq).ok_or(Error::Stale)?;
        if p.status!=PendingStatus::Frozen{return Err(Error::Busy);}
        p.status=PendingStatus::AdapterUnknown;
        Ok(())
    }
    fn release(&mut self,seq:u64){
        if let Some(pool)=self.pool.as_deref_mut(){
            let slot=pool.slots.iter_mut().find(|v|v.as_ref().is_some_and(|p|p.plan_seq==seq))
                .expect("retained plan");*slot=None;
        }else{assert_eq!(self.pending.as_ref().map(|p|p.plan_seq),Some(seq));self.pending=None;}
    }
    pub fn published_count(&self)->usize{
        self.pool.as_deref().map_or_else(
            ||usize::from(self.pending.as_ref().is_some_and(|p|p.status!=PendingStatus::Frozen)),
            PublishedPlanPool::count_published)
    }
    pub fn has_unpublished(&self)->bool{
        self.frozen_or_legacy_busy().is_some_and(|p|p.status==PendingStatus::Frozen)
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
        if let Some(pending)=self.lookup(plan.header.plan_seq).or_else(||self.frozen_or_legacy_busy()) {
            if pending.assisted.is_some()||pending.trial.is_some(){return Err(Error::Busy);}
            let same_key=plan.header.plan_seq==pending.plan_seq;
            let same_bytes=same_key
                && sha256(plan_wire)==pending.plan_digest
                && records.len()==pending.count
                && records.iter().zip(pending.decision_bytes[..pending.count].iter())
                    .all(|(a,b)| a==b);
            return if same_bytes {
                match pending.status {
                    // No effects occurred yet: even an exact retry must not
                    // bypass a revoked rule, changed ledger or expired scope.
                    PendingStatus::Frozen => {
                        self.validate_rule_only(
                            plan_wire, &plan, records, rule_profile, actions, context,false
                        )?;
                        Ok(Registration::ExactRetry)
                    }
                    // A previously accepted plan is only queryable by its
                    // immutable identity. It is never re-authorized or applied.
                    PendingStatus::AdapterAccepted => Ok(Registration::ExactRetry),
                    // Unknown real-device outcomes cannot be re-registered
                    // as if they were safely awaiting a new submission.
                    PendingStatus::AdapterUnknown => Err(Error::NotReady),
                }
            } else if same_key {
                Err(Error::Denied)
            } else {
                Err(Error::Busy)
            };
        }
        self.check_registration_slot()?;
        self.validate_rule_only(plan_wire, &plan, records, rule_profile, actions,context,false)?;
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
        self.insert_frozen(Pending {
            plan_seq:plan.header.plan_seq,
            plan_digest:sha256(plan_wire),
            count:records.len(),
            decision_bytes:copied,
            status:PendingStatus::Frozen,
            expires_ns:expires,
            assisted:None,claimed:[None;MAX_ACTIONS],trial:None,
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
        causal_fallback:bool,
    ) -> Result<(),Error> {
        self.check_identity_and_context(context)?;
        if plan.header.flags != 0 {return Err(Error::NotReady);}
        if rule_profile_mismatch(profile,context) {return Err(Error::Stale);}
        if records.len()!=usize::from(plan.header.action_count)
            || actions.len()!=records.len()
            || plan.header.base_plan_version!=context.base_plan_version
            || plan.ledger_generation!=context.ledger_generation
            || plan.core_generation!=context.core_generation
            || plan.header.controller_epoch!=context.controller_epoch
            || plan.header.snapshot_seq!=context.snapshot_seq
        {return Err(Error::Stale);}
        plan.matches_untrusted_sidecars(records)?;
        let digest=sha256(plan_wire);
        let admission_end=context.sampled_ns.checked_add(100_000_000)
            .ok_or(Error::Clock)?;
        let installed_end=context.sampled_ns.checked_add(10_000_000_000)
            .ok_or(Error::Clock)?;
        // D14 is the single one-shot family. A continuous parameter
        // cannot be accepted with a zero lease (or be extended at APPLY).
        let required_lease=if plan.action(0)?.domain_id==14 {0}else{installed_end};
        if plan.header.active_until_local_ns!=required_lease {
            return Err(Error::Invalid);
        }
        let mut last_seq=0u64;
        for (index,(raw,local)) in records.iter().zip(actions).enumerate() {
            let rec=DecisionRecordV3::decode(raw)?;
            let act=plan.action(index)?;
            if super::action_schema_v2::ActionV2::decode(act.domain_id,act.action_kind,act.action_payload)?.requires_trial(){
                return Err(Error::Denied);
            }
            if rec.source!=DecisionSource::RuleOnly
                || (rec.reason_code==7)!=causal_fallback // only atomic causal path
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
        let plan=PlanV2::decode(plan_wire)?;
        let pending=self.lookup(plan.header.plan_seq).or_else(||self.frozen_or_legacy_busy()).ok_or(Error::Stale)?;
        if pending.assisted.is_some()||pending.trial.is_some(){return Err(Error::Denied);}
        if plan.header.plan_seq!=pending.plan_seq
            || sha256(plan_wire)!=pending.plan_digest
            || records.len()!=pending.count
            || !records.iter().zip(pending.decision_bytes[..pending.count].iter())
                .all(|(a,b)| a==b)
        {return Err(Error::Denied);}
        match pending.status {
            PendingStatus::AdapterAccepted => return Ok(Publication::ReplayNoEffect),
            // A failed adapter call may have committed a partial side
            // effect. Never return success or invoke it again without an
            // independent native reconciliation/terminal proof.
            PendingStatus::AdapterUnknown => return Err(Error::NotReady),
            PendingStatus::Frozen => {}
        }
        self.validate_rule_only(plan_wire,&plan,records,profile,actions,context,false)?;
        // Mark before the potentially side-effecting callback; failures
        // cannot safely be interpreted as "nothing happened".
        self.begin_publish(plan.header.plan_seq)?;
        let result=native_accept();
        if result.is_ok() {
            self.lookup_mut(plan.header.plan_seq).ok_or(Error::Stale)?.status=PendingStatus::AdapterAccepted;
            Ok(Publication::AdapterAccepted)
        } else {
            result.map(|_|Publication::AdapterAccepted)
        }
    }

    fn validate_trial_one(&self,plan_wire:&[u8],plan:&PlanV2<'_>,
        record:&[u8;DECISION_BYTES],profile:&Profile<'_>,local:&FrozenAction<'_>,
        context:TrustedRegistrationScope,table:&super::trial_permit_v1::TrialTable,
    )->Result<(super::trial_permit_v1::Permit,u16),Error>{
        self.check_identity_and_context(context)?;
        if plan.header.flags!=0||plan.header.action_count!=1||rule_profile_mismatch(profile,context)
            ||plan.header.base_plan_version!=context.base_plan_version||plan.ledger_generation!=context.ledger_generation
            ||plan.core_generation!=context.core_generation||plan.header.controller_epoch!=context.controller_epoch
            ||plan.header.snapshot_seq!=context.snapshot_seq{return Err(Error::Stale);}
        plan.matches_untrusted_sidecars(core::slice::from_ref(record))?;
        let rec=DecisionRecordV3::decode(record)?;let act=plan.action(0)?;
        let end=context.sampled_ns.checked_add(100_000_000).ok_or(Error::Clock)?;
        let installed=context.sampled_ns.checked_add(10_000_000_000).ok_or(Error::Clock)?;
        if rec.source!=DecisionSource::AuthorizedTrial||rec.boot_epoch!=context.boot_epoch
            ||rec.rules_generation!=context.rules_generation||rec.rules_hash!=context.rules_hash
            ||rec.plan_digest!=sha256(plan_wire)||rec.target_id!=local.target.id||rec.target_generation!=local.target.generation
            ||rec.domain_id!=local.domain_id||act.candidate_set_hash!=local.candidate_set_hash
            ||rec.candidate_set_hash!=local.candidate_set_hash||act.action_payload!=local.action_payload
            ||act.expires_local_ns<=context.now_ns||act.expires_local_ns>end
            ||plan.header.active_until_local_ns!=if act.domain_id==14{0}else{installed}{
            return Err(Error::Denied);
        }
        let (permit,ordinal)=table.next(rec.trial_permit_id,context.boot_epoch,local.target,local.domain_id,
            context.now_ns,context.rules_generation,context.rules_hash)?;
        let rule=profile.match_trial(permit.rule_id,local.domain_id,local.target.id,ordinal,local.raw_fields,
            super::rule_profile_v2::Candidates{static_ordinals:local.static_ordinals})?;
        if permit.flags!=0||rec.rule_id!=rule.rule_id||rec.choice_policy!=rule.choice_policy
            ||rec.allowed_mask!=rule.allowed_mask||rec.fallback_index!=rule.fallback_index
            ||rec.selected_index!=rule.fallback_index||!rec.matches_candidate_count(local.static_ordinals.len())
            ||act.expires_local_ns>permit.expires_ns
            ||plan.header.active_until_local_ns>permit.expires_ns{return Err(Error::Denied);}
        Ok((permit,ordinal))
    }
    /// Restricted ordinary one-action trial. Unlike ordinary rule matching
    /// it requires a real protected signed permit, not an AI-provided value.
    pub fn register_trial_one(&mut self,actor:Identity,plan_wire:&[u8],record:&[u8;DECISION_BYTES],
        profile:&Profile<'_>,local:&FrozenAction<'_>,context:TrustedRegistrationScope,
        table:&super::trial_permit_v1::TrialTable)->Result<Registration,Error>{
        if actor!=self.controller{return Err(Error::Denied);}
        let plan=PlanV2::decode(plan_wire)?;
        if let Some(p)=self.lookup(plan.header.plan_seq).or_else(||self.frozen_or_legacy_busy()){
            if p.plan_seq!=plan.header.plan_seq{return Err(Error::Busy);}
            let trial=p.trial.ok_or(Error::Denied)?;
            if p.count!=1||p.plan_digest!=sha256(plan_wire)||p.decision_bytes[0]!=*record{return Err(Error::Denied);}
            return match p.status{
                PendingStatus::AdapterAccepted=>Ok(Registration::ExactRetry),
                PendingStatus::AdapterUnknown=>Err(Error::NotReady),
                PendingStatus::Frozen=>{
                    let (permit,_)=self.validate_trial_one(plan_wire,&plan,record,profile,local,context,table)?;
                    if permit.permit_id!=trial.permit_id||sha256(&permit.encode()?)!=trial.permit_hash{return Err(Error::Stale);}
                    Ok(Registration::ExactRetry)
                }
            };
        }
        self.check_registration_slot()?;
        let (permit,_)=self.validate_trial_one(plan_wire,&plan,record,profile,local,context,table)?;
        let rec=DecisionRecordV3::decode(record)?;
        if plan.header.plan_seq<=self.last_plan_seq||rec.decision_seq<=self.last_decision_seq{return Err(Error::Stale);}
        let mut copied=[[0;DECISION_BYTES];MAX_ACTIONS];copied[0]=*record;
        self.insert_frozen(Pending{plan_seq:plan.header.plan_seq,plan_digest:sha256(plan_wire),count:1,
            decision_bytes:copied,status:PendingStatus::Frozen,expires_ns:plan.action(0)?.expires_local_ns,
            assisted:None,claimed:[None;MAX_ACTIONS],
            trial:Some(TrialProof{permit_id:permit.permit_id,permit_hash:sha256(&permit.encode()?),
                hold:None,cost_settled:false})});
        self.last_plan_seq=plan.header.plan_seq;self.last_decision_seq=rec.decision_seq;
        Ok(Registration::Frozen)
    }
    pub fn publish_trial_one(&mut self,actor:Identity,plan_wire:&[u8],record:&[u8;DECISION_BYTES],
        profile:&Profile<'_>,local:&FrozenAction<'_>,context:TrustedRegistrationScope,
        table:&mut super::trial_permit_v1::TrialTable,cpu:u64,memory:u64,
        verify_native_reservation:impl FnOnce(&super::trial_permit_v1::Permit)->Result<(),Error>,
        native_accept:impl FnOnce()->Result<(),Error>,
    )->Result<Publication,Error>{
        use super::trial_permit_v1::UseKey;
        if actor!=self.publisher{return Err(Error::Denied);}
        let plan=PlanV2::decode(plan_wire)?;
        let p=self.lookup(plan.header.plan_seq).ok_or(Error::Stale)?;
        let trial=p.trial.ok_or(Error::Denied)?;
        if p.count!=1||p.plan_digest!=sha256(plan_wire)||p.decision_bytes[0]!=*record{return Err(Error::Denied);}
        match p.status{
            PendingStatus::AdapterAccepted=>return Ok(Publication::ReplayNoEffect),
            PendingStatus::AdapterUnknown=>return Err(Error::NotReady),
            PendingStatus::Frozen=>{},
        }
        if self.published_count()>=MAX_PUBLISHED_PLANS{return Err(Error::Busy);}
        let (permit,ordinal)=self.validate_trial_one(plan_wire,&plan,record,profile,local,context,table)?;
        if permit.permit_id!=trial.permit_id||sha256(&permit.encode()?)!=trial.permit_hash{return Err(Error::Stale);}
        let rec=DecisionRecordV3::decode(record)?;
        let hold=table.reserve(permit.permit_id,UseKey{controller_epoch:self.controller_epoch,
            plan_seq:plan.header.plan_seq,decision_seq:rec.decision_seq},ordinal,cpu,memory,
            context.now_ns,verify_native_reservation)?;
        // Preflighted while serialized: no fallible work between
        // reservation and recording the potentially unknown publication.
        self.begin_publish(plan.header.plan_seq).expect("preflighted trial publication");
        self.lookup_mut(plan.header.plan_seq).unwrap().trial.as_mut().unwrap().hold=Some(hold);
        native_accept()?;
        table.confirm_accept(hold,|_|Ok(()))?;
        self.lookup_mut(plan.header.plan_seq).unwrap().status=PendingStatus::AdapterAccepted;
        Ok(Publication::AdapterAccepted)
    }
    /// Exact terminal cost/acceptance recovery must close the permit
    /// obligation before releasing the corresponding registered plan.
    /// Actual overrun closes the permit but preserves its charged costs.
    pub fn settle_trial_costs(&mut self,actor:Identity,plan_seq:u64,
        table:&mut super::trial_permit_v1::TrialTable,accepted:bool,cpu:u64,memory:u64,
        verify_native:impl FnOnce(super::trial_permit_v1::Hold,bool)->Result<(),Error>,
    )->Result<(),Error>{
        if self.terminal_owner!=Some(actor){return Err(Error::Denied);}
        let p=self.lookup_mut(plan_seq).ok_or(Error::Stale)?;
        let trial=p.trial.as_mut().ok_or(Error::Denied)?;
        if trial.cost_settled{return Err(Error::Stale);}
        let hold=trial.hold.ok_or(Error::NotReady)?;
        if p.status==PendingStatus::AdapterAccepted&&!accepted{return Err(Error::Denied);}
        let result=table.settle(hold,accepted,cpu,memory,verify_native);
        // Only an actually completed settlement clears this exact hold.
        if table.hold_is_settled(hold)?{trial.cost_settled=true;}
        result
    }

    /// Narrow one-action assisted vertical slice. Unlike RULE_ONLY the
    /// exact admitted advice and independently authorized model are required.
    /// Sensitive domains, mixed plans, trials and rejected fallback with
    /// causal evidence stay closed until their respective gates are wired.
    fn validate_assisted_one(&self,plan_wire:&[u8],plan:&PlanV2<'_>,
        record:&[u8;DECISION_BYTES],profile:&Profile<'_>,local:&FrozenAction<'_>,
        context:TrustedRegistrationScope,scope:&AssistedScope<'_>,
        advice_wire:&[u8;ADVICE_BYTES])->Result<(),Error>
    {
        self.check_identity_and_context(context)?;
        let trusted=scope.advice;
        if !scope.assisted_mode||!scope.offline_model_authorized
            || plan.header.flags!=1||plan.header.action_count!=1
            || rule_profile_mismatch(profile,context)
            || plan.header.base_plan_version!=context.base_plan_version
            || plan.ledger_generation!=context.ledger_generation
            || plan.core_generation!=context.core_generation
            || plan.header.controller_epoch!=context.controller_epoch
            || plan.header.snapshot_seq!=context.snapshot_seq
            || plan.header.active_model_generation!=trusted.epochs.model
            || trusted.epochs.boot!=context.boot_epoch
            || trusted.epochs.controller!=context.controller_epoch
            || trusted.epochs.resources!=context.ledger_generation
            || trusted.epochs.cores!=context.core_generation
            || trusted.snapshot_seq!=context.snapshot_seq
            || trusted.sampled_ns!=context.sampled_ns || trusted.now_ns!=context.now_ns
            || trusted.domain!=local.domain_id || trusted.target!=local.target
            || trusted.candidates!=local.static_ordinals
            || trusted.candidate_set_hash!=local.candidate_set_hash
        {return Err(Error::Denied);}
        let advice=AdviceEnvelopeV1::decode(advice_wire)?;
        advice.into_advice(trusted)?;
        plan.matches_untrusted_sidecars(core::slice::from_ref(record))?;
        let rec=DecisionRecordV3::decode(record)?;
        let act=plan.action(0)?;
        let end=context.sampled_ns.checked_add(100_000_000).ok_or(Error::Clock)?;
        let installed=context.sampled_ns.checked_add(10_000_000_000).ok_or(Error::Clock)?;
        if matches!(local.domain_id,6|11|12|14)||rec.source!=DecisionSource::AiAssisted
            || rec.boot_epoch!=context.boot_epoch
            || rec.rules_generation!=context.rules_generation || rec.rules_hash!=context.rules_hash
            || rec.plan_digest!=sha256(plan_wire)
            || rec.target_id!=local.target.id || rec.target_generation!=local.target.generation
            || rec.domain_id!=local.domain_id||rec.candidate_set_hash!=local.candidate_set_hash
            || act.candidate_set_hash!=local.candidate_set_hash||act.action_payload!=local.action_payload
            || act.model_hash!=trusted.model_hash
            || rec.advisor_epoch!=advice.advisor_epoch || rec.advice_seq!=advice.advice_seq
            || rec.advice_model_generation!=advice.active_model_generation
            || rec.recommended_index!=advice.recommended_index
            || rec.selected_index!=advice.recommended_index
            || act.expires_local_ns<=context.now_ns||act.expires_local_ns>end
            || plan.header.active_until_local_ns!=installed
        {return Err(Error::Denied);}
        let rule=profile.match_candidates(local.domain_id,local.target.id,local.raw_fields,
            super::rule_profile_v2::Candidates{static_ordinals:local.static_ordinals})?
            .ok_or(Error::Denied)?;
        if rule.choice_policy!=1||!rec.matches_rule(rule)
            ||!rec.matches_candidate_count(local.static_ordinals.len())
            ||rule.allowed_mask&(1u32<<rec.selected_index)==0
        {return Err(Error::Denied);}
        Ok(())
    }

    /// Atomically freeze one actual controller decision AND its admitted
    /// advice disposition under the serialized EL1 owner. All registration
    /// checks precede ledger.finalize; subsequent writes are infallible
    /// local custody changes. Advice by itself never grants execution.
    pub fn register_assisted_one(&mut self,actor:Identity,plan_wire:&[u8],
        record:&[u8;DECISION_BYTES],disposition:&[u8;DISPOSITION_BYTES],
        profile:&Profile<'_>,local:&FrozenAction<'_>,context:TrustedRegistrationScope,
        scope:&AssistedScope<'_>,ledger:&mut EvidenceLedger)->Result<Registration,Error>
    {
        if actor!=self.controller{return Err(Error::Denied);}
        let plan=PlanV2::decode(plan_wire)?;
        if let Some(p)=self.lookup(plan.header.plan_seq).or_else(||self.frozen_or_legacy_busy()){
            if plan.header.plan_seq!=p.plan_seq{return Err(Error::Busy);}
            let proof=p.assisted.ok_or(Error::Denied)?;
            if p.count!=1||sha256(plan_wire)!=p.plan_digest||p.decision_bytes[0]!=*record
                ||sha256(disposition)!=proof.disposition_digest{return Err(Error::Denied);}
            return match p.status{
                PendingStatus::Frozen=>{
                    self.validate_assisted_one(plan_wire,&plan,record,profile,local,context,scope,&proof.advice)?;
                    Ok(Registration::ExactRetry)
                }
                PendingStatus::AdapterAccepted=>Ok(Registration::ExactRetry),
                PendingStatus::AdapterUnknown=>Err(Error::NotReady),
            };
        }
        self.check_registration_slot()?;
        let disp=AdviceDispositionV1::decode(disposition)?;
        if disp.state!=1||disp.processed_ns!=context.now_ns{return Err(Error::Denied);}
        let key=AdviceKey{boot_epoch:disp.boot_epoch,advisor_epoch:disp.advisor_epoch,advice_seq:disp.advice_seq};
        let advice_wire=ledger.admitted_wire(actor,key)?;
        self.validate_assisted_one(plan_wire,&plan,record,profile,local,context,scope,&advice_wire)?;
        disp.matches_decision_pair(self.boot_epoch,&advice_wire,record)?;
        let rec=DecisionRecordV3::decode(record)?;
        if plan.header.plan_seq<=self.last_plan_seq||rec.decision_seq<=self.last_decision_seq{
            return Err(Error::Stale);
        }
        let expiry=plan.action(0)?.expires_local_ns.min(AdviceEnvelopeV1::decode(&advice_wire)?.expires_ns);
        let mut copied=[[0;DECISION_BYTES];MAX_ACTIONS];copied[0]=*record;
        ledger.finalize_registered_adoption(actor,disposition,record,context.now_ns)?;
        self.insert_frozen(Pending{plan_seq:plan.header.plan_seq,plan_digest:sha256(plan_wire),
            count:1,decision_bytes:copied,status:PendingStatus::Frozen,expires_ns:expiry,
            assisted:Some(AssistedProof{advice:advice_wire,disposition_digest:sha256(disposition)}),claimed:[None;MAX_ACTIONS],trial:None});
        self.last_plan_seq=plan.header.plan_seq;self.last_decision_seq=rec.decision_seq;
        Ok(Registration::Frozen)
    }

    /// Atomically freeze RULE_ONLY reason7 and REJECTED_FALLBACK state2.
    /// The current legal fallback is independently recomputed. The old
    /// recommendation never becomes an action authority or training label.
    /// This restricted path accepts one action, same snapshot and target;
    /// mismatched old advice must instead be handled as observation only.
    pub fn register_rejected_fallback_one(&mut self,actor:Identity,plan_wire:&[u8],
        record:&[u8;DECISION_BYTES],disposition:&[u8;DISPOSITION_BYTES],
        profile:&Profile<'_>,local:&FrozenAction<'_>,context:TrustedRegistrationScope,
        scope:&AssistedScope<'_>,ledger:&mut EvidenceLedger,
        verify_hard_rejection:impl FnOnce(&AdviceEnvelopeV1,&FrozenAction<'_>)->Result<(),Error>,
    )->Result<Registration,Error>{
        if actor!=self.controller{return Err(Error::Denied);}
        let plan=PlanV2::decode(plan_wire)?;
        let disp=AdviceDispositionV1::decode(disposition)?;
        let rec=DecisionRecordV3::decode(record)?;
        if disp.state!=2||rec.source!=DecisionSource::RuleOnly||rec.reason_code!=7
            ||plan.header.action_count!=1{return Err(Error::Denied);}
        if let Some(p)=self.lookup(plan.header.plan_seq).or_else(||self.frozen_or_legacy_busy()){
            if p.plan_seq!=plan.header.plan_seq{return Err(Error::Busy);}
            let proof=p.assisted.ok_or(Error::Denied)?;
            if p.count!=1||p.plan_digest!=sha256(plan_wire)||p.decision_bytes[0]!=*record
                ||proof.disposition_digest!=sha256(disposition){return Err(Error::Denied);}
            return match p.status{
                PendingStatus::Frozen=>{
                    self.validate_rule_only(plan_wire,&plan,core::slice::from_ref(record),profile,
                        core::slice::from_ref(local),context,true)?;
                    Ok(Registration::ExactRetry)
                }
                PendingStatus::AdapterAccepted=>Ok(Registration::ExactRetry),
                PendingStatus::AdapterUnknown=>Err(Error::NotReady),
            };
        }
        self.check_registration_slot()?;
        self.validate_rule_only(plan_wire,&plan,core::slice::from_ref(record),profile,
            core::slice::from_ref(local),context,true)?;
        if !scope.assisted_mode||!scope.offline_model_authorized||rec.mode!=2
            ||matches!(local.domain_id,6|11|12|14)||disp.processed_ns!=context.now_ns{
            return Err(Error::Denied);
        }
        let trusted=scope.advice;
        if !trusted.epochs.valid()||trusted.epochs.boot!=context.boot_epoch
            ||trusted.epochs.controller!=context.controller_epoch
            ||trusted.epochs.resources!=context.ledger_generation||trusted.epochs.cores!=context.core_generation
            ||trusted.snapshot_seq!=context.snapshot_seq||trusted.sampled_ns!=context.sampled_ns
            ||trusted.now_ns!=context.now_ns||trusted.domain!=local.domain_id||trusted.target!=local.target
            ||trusted.candidates!=local.static_ordinals||trusted.candidate_set_hash!=local.candidate_set_hash{
            return Err(Error::Denied);
        }
        let key=AdviceKey{boot_epoch:disp.boot_epoch,advisor_epoch:disp.advisor_epoch,advice_seq:disp.advice_seq};
        let advice_wire=ledger.admitted_wire(actor,key)?;
        let advice=AdviceEnvelopeV1::decode(&advice_wire)?;
        disp.matches_decision_pair(self.boot_epoch,&advice_wire,record)?;
        // Rejection reason is independently determined; expiry/model
        // change takes precedence. A stale source epoch is never adopted,
        // and requires observation/recovery rather than a new causal pair.
        if advice.advisor_epoch!=trusted.advisor_epoch{return Err(Error::Stale);}
        let reason=if context.now_ns>=advice.expires_ns||advice.active_model_generation!=trusted.epochs.model
            ||advice.model_hash!=trusted.model_hash{4}
        else if rec.choice_policy!=1{2}
        else if rec.allowed_mask&(1u32<<advice.recommended_index)==0{1}
        else{verify_hard_rejection(&advice,local)?;3};
        if disp.reason_code!=reason{return Err(Error::Denied);}
        if plan.header.plan_seq<=self.last_plan_seq||rec.decision_seq<=self.last_decision_seq{return Err(Error::Stale);}
        let expiry=plan.action(0)?.expires_local_ns;
        let mut copied=[[0;DECISION_BYTES];MAX_ACTIONS];copied[0]=*record;
        // No fallible mutation after the causal ledger is finalized.
        ledger.finalize_registered_fallback(actor,disposition,record,context.now_ns)?;
        self.insert_frozen(Pending{plan_seq:plan.header.plan_seq,plan_digest:sha256(plan_wire),
            count:1,decision_bytes:copied,status:PendingStatus::Frozen,expires_ns:expiry,
            assisted:Some(AssistedProof{advice:advice_wire,disposition_digest:sha256(disposition)}),
            claimed:[None;MAX_ACTIONS],trial:None});
        self.last_plan_seq=plan.header.plan_seq;self.last_decision_seq=rec.decision_seq;
        Ok(Registration::Frozen)
    }
    /// Separate exact publisher gate for a causal rule fallback. Even if
    /// the rejected advice expired, the independent *current* fallback
    /// still needs current rule, candidate, resource and lease validation.
    pub fn publish_rejected_fallback_one(&mut self,actor:Identity,plan_wire:&[u8],
        record:&[u8;DECISION_BYTES],profile:&Profile<'_>,local:&FrozenAction<'_>,
        context:TrustedRegistrationScope,native_accept:impl FnOnce()->Result<(),Error>,
    )->Result<Publication,Error>{
        if actor!=self.publisher{return Err(Error::Denied);}
        let plan=PlanV2::decode(plan_wire)?;
        let rec=DecisionRecordV3::decode(record)?;
        let p=self.lookup(plan.header.plan_seq).ok_or(Error::Stale)?;
        if rec.source!=DecisionSource::RuleOnly||rec.reason_code!=7||p.assisted.is_none()
            ||p.count!=1||p.plan_digest!=sha256(plan_wire)||p.decision_bytes[0]!=*record{return Err(Error::Denied);}
        match p.status{
            PendingStatus::AdapterAccepted=>return Ok(Publication::ReplayNoEffect),
            PendingStatus::AdapterUnknown=>return Err(Error::NotReady),
            PendingStatus::Frozen=>{},
        }
        self.validate_rule_only(plan_wire,&plan,core::slice::from_ref(record),profile,
            core::slice::from_ref(local),context,true)?;
        self.begin_publish(plan.header.plan_seq)?;
        native_accept()?;
        self.lookup_mut(plan.header.plan_seq).unwrap().status=PendingStatus::AdapterAccepted;
        Ok(Publication::AdapterAccepted)
    }

    /// The distinct publisher presents the same frozen registered decision.
    /// Current model/rule/resource/candidate authority is revalidated before
    /// the actual native accept callback. UNKNOWN keeps the original slot.
    pub fn publish_assisted_once(&mut self,actor:Identity,plan_wire:&[u8],
        record:&[u8;DECISION_BYTES],profile:&Profile<'_>,local:&FrozenAction<'_>,
        context:TrustedRegistrationScope,scope:&AssistedScope<'_>,
        native_accept:impl FnOnce()->Result<(),Error>)->Result<Publication,Error>
    {
        if actor!=self.publisher{return Err(Error::Denied);}
        let plan=PlanV2::decode(plan_wire)?;
        let p=self.lookup(plan.header.plan_seq).or_else(||self.frozen_or_legacy_busy()).ok_or(Error::Stale)?;
        let proof=p.assisted.ok_or(Error::Denied)?;
        if plan.header.plan_seq!=p.plan_seq||p.count!=1||sha256(plan_wire)!=p.plan_digest
            ||p.decision_bytes[0]!=*record{return Err(Error::Denied);}
        match p.status{
            PendingStatus::AdapterAccepted=>return Ok(Publication::ReplayNoEffect),
            PendingStatus::AdapterUnknown=>return Err(Error::NotReady),
            PendingStatus::Frozen=>{},
        }
        self.validate_assisted_one(plan_wire,&plan,record,profile,local,context,scope,&proof.advice)?;
        self.begin_publish(plan.header.plan_seq)?;
        native_accept()?;
        self.lookup_mut(plan.header.plan_seq).unwrap().status=PendingStatus::AdapterAccepted;
        Ok(Publication::AdapterAccepted)
    }

    /// Release the single pending plan only after a distinct EL1 terminal
    /// owner has independently established a final state for EVERY action.
    /// A digest or boolean supplied by the model, publisher or the plan
    /// itself is never sufficient: `verify_native` must validate authoritative
    /// executor/device/persistent evidence and exact action identities.
    ///
    /// An UNKNOWN publication may be settled ONLY with such independent proof,
    /// never by elapsed time. The plan/decision key high-water remains burned
    /// after release; the most recent 256 terminal digests remain queryable.
    pub fn settle_with_native_proof(
        &mut self,
        actor:Identity,
        terminal:TrustedTerminal,
        verify_native:impl FnOnce(&TrustedTerminal)->Result<(),Error>,
    ) -> Result<TerminalSummary,Error> {
        if self.terminal_owner!=Some(actor) || !actor.valid() {
            return Err(Error::Denied);
        }
        let pending=self.lookup(terminal.plan_seq).or_else(||self.frozen_or_legacy_busy()).ok_or(Error::Stale)?;
        if pending.status==PendingStatus::Frozen||pending.trial.is_some_and(|t|!t.cost_settled) {
            return Err(Error::NotReady);
        }
        let required=(1u32.checked_shl(pending.count as u32).ok_or(Error::Invalid)?-1) as u16;
        if terminal.boot_epoch!=self.boot_epoch
            || terminal.controller_epoch!=self.controller_epoch
            || terminal.plan_seq!=pending.plan_seq
            || terminal.plan_digest!=pending.plan_digest
            || usize::from(terminal.action_count)!=pending.count
            || terminal.terminal_mask!=required
            || terminal.unknown_mask!=0
            || terminal.evidence_digest==[0;32]
        {
            return Err(Error::Denied);
        }
        // Independent authority check executes before modifying any state.
        verify_native(&terminal)?;
        let summary=TerminalSummary {
            plan_seq:pending.plan_seq,
            plan_digest:pending.plan_digest,
            action_count:terminal.action_count,
            evidence_digest:terminal.evidence_digest,
        };
        self.history[self.history_next]=Some(summary);
        self.history_next=(self.history_next+1)%TERMINAL_HISTORY;
        self.release(summary.plan_seq);
        Ok(summary)
    }

    /// Native EXECUTOR_FETCH/EL1 acceptance linearization boundary.
    /// Before a returned WorkFrame can execute, the real resource owner
    /// must atomically check desired/current version, object generation,
    /// reservation, dependencies and executor cap. The callback is a
    /// protected native gate, not user-provided authorization.
    /// Repeated fetch with a *new* RPC key is not a second execution.
    pub fn claim_apply_work(&mut self,plan_wire:&[u8],index:usize,
        scope:TrustedApplyScope,binding:ExecutorBindingV1,
        origin:apply_report_v1::ReportOrigin,
        verify_and_accept:impl FnOnce(&super::apply_work_v1::ApplyWorkV1<'_>)->Result<(),Error>,
    )->Result<super::apply_work_v1::WorkFrame,Error>{
        let plan=PlanV2::decode(plan_wire)?;
        if plan.header.controller_epoch!=self.controller_epoch||scope.boot_epoch!=self.boot_epoch
            ||scope.now_ns==0{return Err(Error::Denied);}
        let boot=self.boot_epoch;
        let p=self.lookup_mut(plan.header.plan_seq).ok_or(Error::Stale)?;
        if p.status!=PendingStatus::AdapterAccepted{return Err(Error::NotReady);}
        if sha256(plan_wire)!=p.plan_digest||index>=p.count{return Err(Error::Denied);}
        if p.claimed[index].is_some(){return Err(Error::Busy);}
        if plan.header.active_until_local_ns!=0&&scope.now_ns>=plan.header.active_until_local_ns{
            return Err(Error::Expired);
        }
        let frame=super::apply_work_v1::WorkFrame::from_plan(&plan,index,boot,
            scope.plan_version,binding,origin)?;
        let work=super::apply_work_v1::ApplyWorkV1::decode(frame.bytes())?;
        // Contract: this callback commits atomically or makes NO effect.
        // Unknown external operations are not allowed in this admission
        // callback; actual execution occurs only after the retained claim.
        verify_and_accept(&work)?;
        p.claimed[index]=Some(ClaimedWork{frame,origin,accepted_ns:scope.now_ns});
        Ok(frame)
    }

    pub fn publisher_scope(&self,actor:Identity)->Result<(u64,u64),Error>{
        if actor!=self.publisher||!actor.valid(){return Err(Error::Denied);}
        Ok((self.boot_epoch,self.controller_epoch))
    }

    /// Read the exact retained registered DecisionRecord (ControlRPC op9).
    /// The only authorized EL0 reader is the independently registered
    /// publisher. No record reconstruction and no implicit publication.
    pub fn read_decision(&self,actor:Identity,boot:u64,epoch:u64,seq:u64)
        ->Result<[u8;DECISION_BYTES],Error>{
        if actor!=self.publisher||!actor.valid(){return Err(Error::Denied);}
        if boot!=self.boot_epoch||epoch!=self.controller_epoch||seq==0{return Err(Error::Stale);}
        let find=|p:&Pending|->Result<Option<[u8;DECISION_BYTES]>,Error>{
            for raw in &p.decision_bytes[..p.count]{
                let d=DecisionRecordV3::decode(raw)?;
                if d.decision_seq==seq{return Ok(Some(*raw));}
            }
            Ok(None)
        };
        if let Some(pool)=self.pool.as_deref(){
            for p in pool.slots.iter().flatten(){if let Some(raw)=find(p)?{return Ok(raw);}}
        }else if let Some(p)=self.pending.as_ref(){if let Some(raw)=find(p)?{return Ok(raw);}}
        Err(Error::Stale)
    }

    /// Query is limited to authenticated local roles; old terminal keys
    /// outside the 256-record retention window are stale, never re-executed.
    pub fn terminal_summary(
        &self,actor:Identity,plan_seq:u64
    ) -> Result<Option<TerminalSummary>,Error> {
        if actor!=self.controller && actor!=self.publisher
            && self.terminal_owner!=Some(actor)
        {return Err(Error::Denied);}
        if !actor.valid() {return Err(Error::Denied);}
        Ok(self.history.iter().flatten().copied()
            .find(|item|item.plan_seq==plan_seq))
    }

    /// Terminal integration from exact copied 0x43 ApplyReport v1 bytes.
    ///
    /// This method still requires a TRUE native EL1 evidence verifier:
    /// signed/authenticated executor identity, device/redo completion,
    /// accepted apply_id and pin/resource accounting. The report body itself
    /// is only a claim and must not authorize APPLIED or reference release.
    pub fn settle_verified_apply_reports_with_feedback(
        &mut self,
        supervisor:Identity,
        plan_wire:&[u8],
        report_frames:&[BoundReport<'_>],
        bindings:&[ExecutorBindingV1],
        scope:TrustedApplyScope,
        causal:Option<super::feedback_v0199::CausalPair<'_>>,
        mut verify_native:impl FnMut(usize,&ApplyReportV1<'_>)->Result<(),Error>,
        retain:impl FnOnce(&super::feedback_v0199::VerifiedFeedbackBatch<'_>)->Result<(),Error>,
    )->Result<TerminalSummary,Error>{
        // Validate the terminal owner before invoking any verifier callback.
        if !supervisor.valid() || self.terminal_owner!=Some(supervisor){
            return Err(Error::Denied);
        }
        let plan=PlanV2::decode(plan_wire)?;
        let pending=self.lookup(plan.header.plan_seq).or_else(||self.frozen_or_legacy_busy()).ok_or(Error::Stale)?;
        if pending.status==PendingStatus::Frozen {
            return Err(Error::NotReady);
        }
        if plan.header.plan_seq!=pending.plan_seq
            || sha256(plan_wire)!=pending.plan_digest
            || plan.header.controller_epoch!=self.controller_epoch
            || scope.boot_epoch!=self.boot_epoch
        {return Err(Error::Denied);}
        if pending.trial.is_some_and(|t|!t.cost_settled){return Err(Error::NotReady);}
        // A valid current executor binding alone is insufficient. Every
        // report must refer to an already accepted exact ApplyWork key;
        // a stale or never-accepted report cannot reach the effect verifier.
        for copied in report_frames{
            let r=ApplyReportV1::decode(copied.bytes)?;
            let i=usize::from(r.action_index);
            let claim=pending.claimed.get(i).and_then(|v|v.as_ref()).ok_or(Error::NotReady)?;
            let work=super::apply_work_v1::ApplyWorkV1::decode(claim.frame.bytes())?;
            if claim.origin!=copied.origin||!work.matches_report(r)
                ||r.completed_ns<claim.accepted_ns{return Err(Error::Denied);}
        }
        // Retain the exact causal sidecar from registration, not a new
        // model-supplied explanation. A missing pair never becomes a label.
        match (pending.assisted,causal){
            (Some(frozen),Some(pair)) if pending.count==1
                && frozen.advice==*pair.advice
                && frozen.disposition_digest==sha256(pair.disposition)=>{
                AdviceDispositionV1::decode(pair.disposition)?.matches_decision_pair(
                    self.boot_epoch,pair.advice,&pending.decision_bytes[0])?;
            }
            (None,None)=>(),
            _=>return Err(Error::Denied),
        }
        let terminal_mask=apply_report_v1::verified_bound_terminal_mask(
            &plan,report_frames,bindings,scope,|index,report|{
                verify_native(index,report)
            }
        )?;
        // The native effect verifier above must be observational. Only
        // release the pending plan after the protected feedback owner has
        // accepted the whole batch. Failure/backpressure keeps it owned.
        let batch=super::feedback_v0199::VerifiedFeedbackBatch{
            plan_wire,decisions:&pending.decision_bytes[..pending.count],reports:report_frames,causal,
        };
        retain(&batch)?;
        // Full copied-byte digest is a searchable audit link, not proof by
        // itself; only the preceding independent native callback is proof.
        let mut h=Sha256::new();
        for frame in report_frames {
            h.update((frame.bytes.len() as u32).to_le_bytes());
            h.update(frame.bytes);
        }
        let evidence_digest:[u8;32]=h.finalize().into();
        let proof=TrustedTerminal {
            boot_epoch:self.boot_epoch,
            controller_epoch:self.controller_epoch,
            plan_seq:pending.plan_seq,
            plan_digest:pending.plan_digest,
            action_count:plan.header.action_count,
            terminal_mask,
            unknown_mask:0,
            evidence_digest,
        };
        self.settle_with_native_proof(supervisor,proof,|_|Ok(()))
    }

    // Historical unit-test helper; production report closure must retain
    // exact feedback through the new interface.
    #[cfg(test)]
    fn settle_verified_apply_reports(
        &mut self,supervisor:Identity,plan_wire:&[u8],report_frames:&[BoundReport<'_>],
        bindings:&[ExecutorBindingV1],scope:TrustedApplyScope,
        verify_native:impl FnMut(usize,&ApplyReportV1<'_>)->Result<(),Error>,
    )->Result<TerminalSummary,Error>{
        self.settle_verified_apply_reports_with_feedback(supervisor,plan_wire,report_frames,
            bindings,scope,None,verify_native,|_|Ok(()))
    }

    /// Expired *unpublished* registration may be discarded by the controller;
    /// all high-water keys remain burned. In-flight/unknown work is never
    /// freed without an independent native terminal/recovery proof.
    pub fn expire_unpublished(
        &mut self, actor:Identity, now_ns:u64
    ) -> Result<bool,Error> {
        if actor!=self.controller {return Err(Error::Denied);}
        if let Some(p)=self.frozen_or_legacy_busy(){
            if p.status!=PendingStatus::Frozen{return Err(Error::NotReady);}
            if now_ns>=p.expires_ns{let seq=p.plan_seq;self.release(seq);return Ok(true);}
        }else if self.published_count()!=0{return Err(Error::NotReady);}
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
    fn trial_registration_publication_and_cost_custody_are_independent(){
        use super::super::trial_permit_v1::{Permit,TrialTable};
        let mut rules=profile_bytes();rules[48..50].copy_from_slice(&2u16.to_le_bytes());
        let profile=Profile::parse(&rules).unwrap();let ctx=trusted(&rules);
        let plan=plan_bytes();let mut rec=decision(&plan,&rules);
        rec[99]=2;rec[100]=3;rec[108..112].copy_from_slice(&5u32.to_le_bytes());
        rec[136..144].copy_from_slice(&1u64.to_le_bytes());
        rec[152..156].copy_from_slice(&1u32.to_le_bytes());
        rec[158..160].copy_from_slice(&2u16.to_le_bytes());
        let actions=frozen(&[2,4],&[2,0]);let local=&actions[0];
        let mut order=[u16::MAX;32];order[..2].copy_from_slice(&[2,4]);
        let p=Permit{permit_id:1,boot_epoch:1,rules_generation:7,target_id:17,target_generation:1,
            start_ns:100,expires_ns:20_000_000_000,rule_id:1,domain:1,order_count:2,flags:0,
            max_submissions:2,cpu_budget_ns:100,memory_budget_bytes:20,rule_hash:ctx.rules_hash,
            model_hash:[0;32],template_id:1,model_generation:0,order};
        let mut table=TrialTable::new(1,CONTROLLER,2).unwrap();
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(CONTROLLER,PUBLISHER,SUPERVISOR,1,2).unwrap();
        assert_eq!(gate.register_trial_one(CONTROLLER,&plan,&rec,&profile,local,ctx,&table),Err(Error::Stale));
        table.insert_fixture(p).unwrap();
        assert_eq!(gate.register_trial_one(CONTROLLER,&plan,&rec,&profile,local,ctx,&table),Ok(Registration::Frozen));
        assert_eq!(gate.publish_once(PUBLISHER,&plan,&[rec],&profile,&actions,ctx,||panic!()),Err(Error::Denied));
        assert_eq!(gate.publish_trial_one(PUBLISHER,&plan,&rec,&profile,local,ctx,&mut table,
            20,1,|_|Err(Error::Denied),||panic!()),Err(Error::Denied));
        assert_eq!(gate.publish_trial_one(PUBLISHER,&plan,&rec,&profile,local,ctx,&mut table,
            20,1,|_|Ok(()),||Ok(())),Ok(Publication::AdapterAccepted));
        assert_eq!(gate.publish_trial_one(PUBLISHER,&plan,&rec,&profile,local,ctx,&mut table,
            20,1,|_|panic!(),||panic!()),Ok(Publication::ReplayNoEffect));
        assert_eq!(gate.settle_with_native_proof(SUPERVISOR,terminal_proof(&plan),|_|panic!()),Err(Error::NotReady));
        assert_eq!(gate.settle_trial_costs(SUPERVISOR,1,&mut table,true,10,1,|_,_|Err(Error::NotReady)),Err(Error::NotReady));
        gate.settle_trial_costs(SUPERVISOR,1,&mut table,true,10,1,|_,_|Ok(())).unwrap();
        gate.settle_with_native_proof(SUPERVISOR,terminal_proof(&plan),|_|Ok(())).unwrap();
        assert_eq!(table.next(1,1,local.target,1,151,7,ctx.rules_hash).unwrap().1,4);
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
        ),Err(Error::NotReady));
        assert_eq!(attempts,1);
        assert_eq!(gate.expire_unpublished(CONTROLLER,200),Err(Error::NotReady));
    }
    const SUPERVISOR: Identity=Identity{id:11,generation:1};

    fn terminal_proof(plan:&[u8]) -> TrustedTerminal {
        TrustedTerminal {
            boot_epoch:1,controller_epoch:2,plan_seq:1,
            plan_digest:sha256(plan),
            action_count:1,terminal_mask:1,unknown_mask:0,
            evidence_digest:[9;32],
        }
    }

    #[test]
    fn independent_terminal_proof_releases_capacity_without_replaying_old_keys() {
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(
            CONTROLLER,PUBLISHER,SUPERVISOR,1,2
        ).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx).unwrap();
        let proof=terminal_proof(&plan);
        assert_eq!(gate.settle_with_native_proof(
            SUPERVISOR,proof, |_|Ok(())
        ),Err(Error::NotReady)); // no native publication was accepted
        gate.publish_once(PUBLISHER,&plan,&records,&catalog,&frozen,ctx,||Ok(())).unwrap();
        assert_eq!(gate.settle_with_native_proof(
            PUBLISHER,proof, |_|Ok(())
        ),Err(Error::Denied)); // publisher cannot forge its own completion
        let mut bad=proof;bad.terminal_mask=0;
        assert_eq!(gate.settle_with_native_proof(
            SUPERVISOR,bad, |_|Ok(())
        ),Err(Error::Denied));
        bad=proof;bad.unknown_mask=1;
        assert_eq!(gate.settle_with_native_proof(
            SUPERVISOR,bad, |_|Ok(())
        ),Err(Error::Denied));
        bad=proof;bad.evidence_digest=[0;32];
        assert_eq!(gate.settle_with_native_proof(
            SUPERVISOR,bad, |_|Ok(())
        ),Err(Error::Denied));
        let mut verifier_called=0;
        assert_eq!(gate.settle_with_native_proof(SUPERVISOR,proof, |_|{
            verifier_called+=1; Err(Error::NotReady)
        }),Err(Error::NotReady));
        assert_eq!(verifier_called,1);
        assert_eq!(gate.terminal_summary(SUPERVISOR,1),Ok(None));
        let result=gate.settle_with_native_proof(SUPERVISOR,proof, |_|{
            verifier_called+=1; Ok(())
        }).unwrap();
        assert_eq!(verifier_called,2);
        assert_eq!(result.plan_seq,1);
        assert_eq!(gate.terminal_summary(PUBLISHER,1),Ok(Some(result)));
        assert_eq!(gate.terminal_summary(Identity{id:6,generation:1},1),Err(Error::Denied));
        assert_eq!(gate.terminal_summary(SUPERVISOR,0),Ok(None));
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&records,&catalog,&frozen,ctx
        ),Err(Error::Stale)); // old idempotent key cannot restart on eviction

        let mut plan2=plan;
        plan2[16..24].copy_from_slice(&2u64.to_le_bytes());
        plan2[64+24..64+32].copy_from_slice(&5u64.to_le_bytes());
        let mut record2=decision(&plan2,&bytes);
        record2[24..32].copy_from_slice(&5u64.to_le_bytes());
        record2[32..40].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan2,&[record2],&catalog,&frozen,ctx
        ),Ok(Registration::Frozen)); // new, genuine work can progress
    }

    #[test]
    fn unknown_adapter_result_requires_independent_terminal_reconciliation() {
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(
            CONTROLLER,PUBLISHER,SUPERVISOR,1,2
        ).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx).unwrap();
        let mut invocations=0;
        assert_eq!(gate.publish_once(
            PUBLISHER,&plan,&records,&catalog,&frozen,ctx,
            ||{invocations+=1;Err(Error::Busy)}
        ),Err(Error::Busy));
        assert_eq!(gate.publish_once(
            PUBLISHER,&plan,&records,&catalog,&frozen,ctx,
            ||{invocations+=1;Ok(())}
        ),Err(Error::NotReady));
        assert_eq!(invocations,1);
        assert_eq!(gate.expire_unpublished(CONTROLLER,u64::MAX),Err(Error::NotReady));
        let mut corrupted=terminal_proof(&plan);
        corrupted.plan_digest[0]^=1;
        assert_eq!(gate.settle_with_native_proof(
            SUPERVISOR,corrupted, |_|Ok(())
        ),Err(Error::Denied));
        assert_eq!(gate.settle_with_native_proof(
            SUPERVISOR,terminal_proof(&plan), |_|Ok(())
        ).unwrap().action_count,1);
        assert_eq!(invocations,1);
    }

    fn executor_report(state:u16)->[u8;98]{
        let mut b=[0u8;98];
        for (at,value) in [
            (0,1u64),(8,2),(16,1),(32,17),(40,1),
            (48,9),(56,7),(72,180),
        ]{b[at..at+8].copy_from_slice(&value.to_le_bytes());}
        b[26..28].copy_from_slice(&1u16.to_le_bytes());
        b[28..30].copy_from_slice(&state.to_le_bytes());
        b[68..72].copy_from_slice(&2u32.to_le_bytes());
        b[96..98].copy_from_slice(&[2u8,0]);
        b
    }
    fn verified_binding()->ExecutorBindingV1{
        ExecutorBindingV1{
            domain:1,role:1,active:true,target:Identity{id:17,generation:1},
            executor_generation:9,holder:Identity{id:0,generation:0},endpoint_cap_id:0,
        }
    }
    fn verified_scope()->TrustedApplyScope{
        TrustedApplyScope{boot_epoch:1,plan_version:7,now_ns:200}
    }
    fn claim_test_work(gate:&mut RegisteredDecisionGate,plan:&[u8]){
        let scope=TrustedApplyScope{now_ns:150,..verified_scope()};
        gate.claim_apply_work(plan,0,scope,verified_binding(),
            apply_report_v1::ReportOrigin::Kernel,|_|Ok(())).unwrap();
    }
    #[test]
    fn native_apply_reports_require_supervisor_and_real_completion_proof(){
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(
            CONTROLLER,PUBLISHER,SUPERVISOR,1,2
        ).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx).unwrap();
        gate.publish_once(PUBLISHER,&plan,&records,&catalog,&frozen,ctx,||Ok(())).unwrap();
        let report=executor_report(1);
        let mut verifications=0;
        assert_eq!(gate.settle_verified_apply_reports(
            PUBLISHER,&plan,&[BoundReport{bytes:&report,origin:apply_report_v1::ReportOrigin::Kernel}],&[verified_binding()],verified_scope(),
            |_,_|{verifications+=1;Ok(())}
        ),Err(Error::Denied));
        assert_eq!(verifications,0);
        assert_eq!(gate.settle_verified_apply_reports(
            SUPERVISOR,&plan,&[BoundReport{bytes:&report,origin:apply_report_v1::ReportOrigin::Kernel}],&[verified_binding()],verified_scope(),
            |_,_|panic!("unaccepted work")
        ),Err(Error::NotReady));
        claim_test_work(&mut gate,&plan);
        assert_eq!(gate.claim_apply_work(&plan,0,verified_scope(),verified_binding(),
            apply_report_v1::ReportOrigin::Kernel,|_|panic!("duplicate accept")),Err(Error::Busy));
        assert_eq!(gate.settle_verified_apply_reports(
            SUPERVISOR,&plan,&[BoundReport{bytes:&report,origin:apply_report_v1::ReportOrigin::Kernel}],&[verified_binding()],verified_scope(),
            |_,_|{verifications+=1;Err(Error::NotReady)}
        ),Err(Error::NotReady));
        assert_eq!(verifications,1);
        assert_eq!(gate.settle_verified_apply_reports(
            SUPERVISOR,&plan,&[BoundReport{bytes:&report,origin:apply_report_v1::ReportOrigin::Kernel}],&[verified_binding()],verified_scope(),
            |_,_|{verifications+=1;Ok(())}
        ).unwrap().action_count,1);
        assert_eq!(verifications,2);
        assert!(gate.terminal_summary(SUPERVISOR,1).unwrap().is_some());
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&records,&catalog,&frozen,ctx
        ),Err(Error::Stale));
    }
    #[test]
    fn feedback_must_retain_real_terminal_bytes_before_plan_release(){
        use super::super::feedback_v0199::{FeedbackInbox,CausalLabel};
        let bytes=profile_bytes();let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(
            CONTROLLER,PUBLISHER,SUPERVISOR,1,2).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx).unwrap();
        gate.publish_once(PUBLISHER,&plan,&records,&catalog,&frozen,ctx,||Ok(())).unwrap();
        claim_test_work(&mut gate,&plan);
        let learner=Identity{id:10,generation:1};
        let mut inbox=FeedbackInbox::new(SUPERVISOR,learner).unwrap();
        let report=executor_report(1);
        let frames=[BoundReport{bytes:&report,origin:apply_report_v1::ReportOrigin::Kernel}];
        let bindings=[verified_binding()];
        assert_eq!(gate.settle_verified_apply_reports_with_feedback(SUPERVISOR,&plan,&frames,&bindings,
            verified_scope(),None,|_,_|Err(Error::NotReady),|_|panic!("not a real effect")),Err(Error::NotReady));
        assert_eq!(gate.settle_verified_apply_reports_with_feedback(SUPERVISOR,&plan,&frames,&bindings,
            verified_scope(),None,|_,_|Ok(()),|_|Err(Error::Exhausted)),Err(Error::Exhausted));
        assert_eq!(gate.terminal_summary(SUPERVISOR,1),Ok(None));
        gate.settle_verified_apply_reports_with_feedback(SUPERVISOR,&plan,&frames,&bindings,
            verified_scope(),None,|_,_|Ok(()),|batch|inbox.retain(SUPERVISOR,batch)).unwrap();
        assert_eq!(inbox.len(),1);
        let row=inbox.read(learner,0).unwrap().unwrap();
        assert_eq!(row.decision,records[0]);assert_eq!(row.report_bytes(),&report);
        assert_eq!(row.causal_label,CausalLabel::NoAdoption);
        let digest=row.evidence_digest();
        assert!(matches!(inbox.read(CONTROLLER,0),Err(Error::Denied)));
        assert_eq!(inbox.retire(learner,0,digest,|_|Ok(())),Err(Error::Denied));
        assert_eq!(inbox.retire(SUPERVISOR,0,digest,|_|Err(Error::NotReady)),Err(Error::NotReady));
        assert_eq!(inbox.len(),1);
        inbox.retire(SUPERVISOR,0,digest,|_|Ok(())).unwrap();
        assert_eq!(inbox.len(),0);
    }
    #[test]
    fn unknown_apply_report_remains_owned_even_with_time_and_matching_bytes(){
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(
            CONTROLLER,PUBLISHER,SUPERVISOR,1,2
        ).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx).unwrap();
        gate.publish_once(PUBLISHER,&plan,&records,&catalog,&frozen,ctx,||Ok(())).unwrap();
        claim_test_work(&mut gate,&plan);
        let report=executor_report(3);
        let mut checked=0;
        assert_eq!(gate.settle_verified_apply_reports(
            SUPERVISOR,&plan,&[BoundReport{bytes:&report,origin:apply_report_v1::ReportOrigin::Kernel}],&[verified_binding()],verified_scope(),
            |_,_|{checked+=1;Ok(())}
        ),Err(Error::NotReady));
        assert_eq!(checked,0);
        assert_eq!(gate.expire_unpublished(CONTROLLER,u64::MAX),Err(Error::NotReady));
        assert_eq!(gate.terminal_summary(SUPERVISOR,1),Ok(None));
    }

    #[test]
    fn unconfigured_terminal_authority_never_releases_inflight_plan() {
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx).unwrap();
        gate.publish_once(PUBLISHER,&plan,&records,&catalog,&frozen,ctx,||Ok(())).unwrap();
        assert_eq!(gate.settle_with_native_proof(
            CONTROLLER,terminal_proof(&plan), |_|Ok(())
        ),Err(Error::Denied));
        assert_eq!(gate.register_rule_only(
            CONTROLLER,&plan,&records,&catalog,&frozen,ctx
        ),Ok(Registration::ExactRetry));
        assert_eq!(gate.expire_unpublished(CONTROLLER,10000),Err(Error::NotReady));
        assert!(RegisteredDecisionGate::new_with_terminal_owner(
            CONTROLLER,PUBLISHER,CONTROLLER,1,2
        ).is_err());
    }

    #[test]
    fn sixty_four_inflight_plus_one_frozen_preserve_unknown_and_release_by_exact_key(){
        // The production adapter must allocate this pool in the protected
        // 8MiB control pool. Give the host test an independent larger stack
        // for initialization, never a kernel-sized stack.
        extern crate std;
        std::thread::Builder::new().stack_size(8*1024*1024).spawn(||{
            let bytes=profile_bytes();let profile=Profile::parse(&bytes).unwrap();
            let ctx=trusted(&bytes);let actions=frozen(&[2,4],&[2,0]);
            let mut pool=PublishedPlanPool::new();
            let mut gate=RegisteredDecisionGate::with_pool(CONTROLLER,PUBLISHER,SUPERVISOR,1,2,&mut pool).unwrap();
            let plan_and_record=|seq:u64|{
                let mut plan=plan_bytes();
                plan[16..24].copy_from_slice(&seq.to_le_bytes());
                plan[88..96].copy_from_slice(&(seq+3).to_le_bytes());
                let mut record=decision(&plan,&bytes);
                record[24..32].copy_from_slice(&(seq+3).to_le_bytes());
                record[32..40].copy_from_slice(&seq.to_le_bytes());
                (plan,record)
            };
            for seq in 1..=64{
                let (plan,rec)=plan_and_record(seq);
                gate.register_rule_only(CONTROLLER,&plan,&[rec],&profile,&actions,ctx).unwrap();
                let result=gate.publish_once(PUBLISHER,&plan,&[rec],&profile,&actions,ctx,
                    ||if seq==1{Err(Error::NotReady)}else{Ok(())});
                if seq==1{assert_eq!(result,Err(Error::NotReady));}else{assert_eq!(result,Ok(Publication::AdapterAccepted));}
                assert_eq!(gate.published_count(),seq as usize);assert!(!gate.has_unpublished());
            }
            let (frozen_plan,frozen_record)=plan_and_record(65);
            gate.register_rule_only(CONTROLLER,&frozen_plan,&[frozen_record],&profile,&actions,ctx).unwrap();
            assert!(gate.has_unpublished());
            let (extra,extra_record)=plan_and_record(66);
            assert_eq!(gate.register_rule_only(CONTROLLER,&extra,&[extra_record],&profile,&actions,ctx),Err(Error::Busy));
            assert_eq!(gate.publish_once(PUBLISHER,&frozen_plan,&[frozen_record],&profile,&actions,ctx,||panic!("full pool")),Err(Error::Busy));
            let (old,old_record)=plan_and_record(1);
            assert_eq!(gate.publish_once(PUBLISHER,&old,&[old_record],&profile,&actions,ctx,||panic!("unknown replay")),Err(Error::NotReady));
            let (other,other_record)=plan_and_record(32);
            assert_eq!(gate.read_decision(PUBLISHER,1,2,35),Ok(other_record));
            assert_eq!(gate.publish_once(PUBLISHER,&other,&[other_record],&profile,&actions,ctx,||panic!("accepted replay")),Ok(Publication::ReplayNoEffect));
            let mut proof=terminal_proof(&other);proof.plan_seq=32;
            assert_eq!(gate.settle_with_native_proof(SUPERVISOR,proof,|_|Err(Error::NotReady)),Err(Error::NotReady));
            assert_eq!(gate.published_count(),64);
            gate.settle_with_native_proof(SUPERVISOR,proof,|_|Ok(())).unwrap();
            assert_eq!(gate.published_count(),63);assert!(gate.has_unpublished());
            gate.publish_once(PUBLISHER,&frozen_plan,&[frozen_record],&profile,&actions,ctx,||Ok(())).unwrap();
            assert_eq!(gate.published_count(),64);assert!(!gate.has_unpublished());
            assert!(gate.terminal_summary(SUPERVISOR,32).unwrap().is_some());
            assert_eq!(gate.publish_once(PUBLISHER,&old,&[old_record],&profile,&actions,ctx,||panic!("old unknown")),Err(Error::NotReady));
        }).unwrap().join().unwrap();
    }

    #[test]
    fn bounded_terminal_summary_history_retains_only_latest_256_distinct_plan_keys() {
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(
            CONTROLLER,PUBLISHER,SUPERVISOR,1,2
        ).unwrap();
        for seq in 1u64..=257 {
            let mut plan=plan_bytes();
            plan[16..24].copy_from_slice(&seq.to_le_bytes());
            let decision_seq=seq+3;
            plan[64+24..64+32].copy_from_slice(&decision_seq.to_le_bytes());
            let mut record=decision(&plan,&bytes);
            record[24..32].copy_from_slice(&decision_seq.to_le_bytes());
            record[32..40].copy_from_slice(&seq.to_le_bytes());
            gate.register_rule_only(
                CONTROLLER,&plan,&[record],&catalog,&frozen,ctx
            ).unwrap();
            gate.publish_once(
                PUBLISHER,&plan,&[record],&catalog,&frozen,ctx,||Ok(())
            ).unwrap();
            let mut proof=terminal_proof(&plan);
            proof.plan_seq=seq;
            gate.settle_with_native_proof(
                SUPERVISOR,proof, |_|Ok(())
            ).unwrap();
        }
        assert_eq!(gate.terminal_summary(SUPERVISOR,1),Ok(None));
        assert!(gate.terminal_summary(SUPERVISOR,2).unwrap().is_some());
        assert!(gate.terminal_summary(SUPERVISOR,257).unwrap().is_some());
        assert_eq!(gate.terminal_summary(PUBLISHER,258),Ok(None));
        assert_eq!(gate.last_plan_seq,257);
        assert_eq!(gate.last_decision_seq,260);
    }
    #[test]
    fn exact_unpublished_retry_cannot_bypass_current_rule_or_expired_scope() {
        let rule_bytes=profile_bytes();
        let profile=Profile::parse(&rule_bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&rule_bytes)];
        let frozen=frozen(&[2,4],&[2,0]);
        let ctx=trusted(&rule_bytes);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&profile,&frozen,ctx).unwrap();
        assert_eq!(
            gate.register_rule_only(CONTROLLER,&plan,&records,&profile,&frozen,ctx),
            Ok(Registration::ExactRetry)
        );
        // Caller-supplied idempotence cannot revive a stale EL1 snapshot.
        let mut stale=ctx;
        stale.now_ns=ctx.sampled_ns+100_000_000;
        assert_eq!(
            gate.register_rule_only(CONTROLLER,&plan,&records,&profile,&frozen,stale),
            Err(Error::Stale)
        );
        // A newly frozen rule generation invalidates *unpublished* retries.
        stale=ctx;
        stale.rules_generation+=1;
        assert_eq!(
            gate.register_rule_only(CONTROLLER,&plan,&records,&profile,&frozen,stale),
            Err(Error::Stale)
        );
        // Cross-role exact wire replay is not registration authority.
        assert_eq!(
            gate.register_rule_only(PUBLISHER,&plan,&records,&profile,&frozen,ctx),
            Err(Error::Denied)
        );
    }

    #[test]
    fn once_native_adapter_unknown_retry_is_never_advertised_as_frozen() {
        let rule_bytes=profile_bytes();
        let profile=Profile::parse(&rule_bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&rule_bytes)];
        let frozen=frozen(&[2,4],&[2,0]);
        let ctx=trusted(&rule_bytes);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        gate.register_rule_only(CONTROLLER,&plan,&records,&profile,&frozen,ctx).unwrap();
        assert_eq!(gate.publish_once(
            PUBLISHER,&plan,&records,&profile,&frozen,ctx,
            ||Err(Error::Busy)
        ),Err(Error::Busy));
        assert_eq!(
            gate.register_rule_only(CONTROLLER,&plan,&records,&profile,&frozen,ctx),
            Err(Error::NotReady)
        );
        // Neither EL1 timeout nor repeated SVC input releases the slot.
        assert_eq!(gate.expire_unpublished(CONTROLLER,u64::MAX),Err(Error::NotReady));
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
    #[test]
    fn actual_resource_or_core_generation_change_blocks_frozen_publication(){
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let plan=plan_bytes();
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        for stale in [
            TrustedRegistrationScope{ledger_generation:ctx.ledger_generation+1,..ctx},
            TrustedRegistrationScope{core_generation:ctx.core_generation+1,..ctx}
        ]{
            assert_eq!(gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,stale),Err(Error::Stale));
        }
        gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx).unwrap();
        for stale in [
            TrustedRegistrationScope{ledger_generation:ctx.ledger_generation+1,..ctx},
            TrustedRegistrationScope{core_generation:ctx.core_generation+1,..ctx}
        ]{
            assert_eq!(gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,stale),Err(Error::Stale));
            assert_eq!(gate.publish_once(PUBLISHER,&plan,&records,&catalog,&frozen,stale,
                ||panic!("stale authority reached native publication")),Err(Error::Stale));
        }
        assert_eq!(gate.publish_once(PUBLISHER,&plan,&records,&catalog,&frozen,ctx,||Ok(())),
            Ok(Publication::AdapterAccepted));
    }

    #[test]
    fn continuous_plan_requires_exact_lease_and_distinct_live_role_ids(){
        let bytes=profile_bytes();
        let catalog=Profile::parse(&bytes).unwrap();
        let mut plan=plan_bytes();
        plan[56..64].fill(0);
        let records=[decision(&plan,&bytes)];
        let ctx=trusted(&bytes);
        let frozen=frozen(&[2,4],&[2,0]);
        let mut gate=RegisteredDecisionGate::new(CONTROLLER,PUBLISHER,1,2).unwrap();
        assert_eq!(gate.register_rule_only(CONTROLLER,&plan,&records,&catalog,&frozen,ctx),Err(Error::Invalid));
        let alias=Identity{id:CONTROLLER.id,generation:2};
        assert!(RegisteredDecisionGate::new(CONTROLLER,alias,1,2).is_err());
        assert!(RegisteredDecisionGate::new_with_terminal_owner(CONTROLLER,PUBLISHER,alias,1,2).is_err());
    }

    #[test]
    fn reason7_fallback_requires_exact_admitted_advice_and_actual_rejection_reason(){
        use super::super::{Epochs,advice_ledger_v0199::{AdviceKey,AdviceResult}};
        let rules=profile_bytes(); // ordinary choice_policy 0
        let profile=Profile::parse(&rules).unwrap();
        let plan=plan_bytes();let mut rec=decision(&plan,&rules);
        rec[98]=2;rec[108..112].copy_from_slice(&7u32.to_le_bytes());
        let ctx=trusted(&rules);let actions=frozen(&[2,4],&[2,0]);let local=&actions[0];
        let mut advice=[0;ADVICE_BYTES];
        advice[..4].copy_from_slice(&0x43594131u32.to_le_bytes());
        advice[4..6].copy_from_slice(&1u16.to_le_bytes());
        advice[6..8].copy_from_slice(&152u16.to_le_bytes());
        for (at,v) in [(8,1u64),(16,1),(24,3),(32,17),(40,1),(48,5),(56,6),(64,200),(72,9)]{
            advice[at..at+8].copy_from_slice(&v.to_le_bytes());
        }
        for (at,v) in [(80,1u16),(82,1),(84,1),(86,2)]{advice[at..at+2].copy_from_slice(&v.to_le_bytes());}
        advice[88..120].fill(3);advice[120..152].fill(1);
        let mut disp=[0;DISPOSITION_BYTES];
        disp[..4].copy_from_slice(&0x43594144u32.to_le_bytes());
        disp[4..6].copy_from_slice(&1u16.to_le_bytes());disp[6..8].copy_from_slice(&240u16.to_le_bytes());
        for (at,v) in [(8,1u64),(16,1),(24,1),(32,3),(40,2),(48,4),(56,17),(64,1),(72,9),(80,150)]{
            disp[at..at+8].copy_from_slice(&v.to_le_bytes());
        }
        for (at,v) in [(88,1u16),(90,1),(92,2),(94,2),(100,0),(102,1),(104,0),(106,0)]{
            disp[at..at+2].copy_from_slice(&v.to_le_bytes());
        }
        disp[96..100].copy_from_slice(&3u32.to_le_bytes());
        disp[112..144].fill(1);disp[144..176].copy_from_slice(&sha256(&advice));
        disp[176..208].copy_from_slice(&sha256(&rec));disp[208..240].copy_from_slice(&sha256(&rules));
        let trusted=TrustedAdviceScope{epochs:Epochs{boot:1,controller:2,model:9,resources:5,cores:6},
            advisor_epoch:1,snapshot_seq:3,domain:1,target:local.target,sampled_ns:100,now_ns:150,
            action_kind:1,candidates:&[2,4],model_hash:[3;32],candidate_set_hash:[1;32]};
        let scope=AssistedScope{advice:&trusted,assisted_mode:true,offline_model_authorized:true};
        let ops=Identity{id:6,generation:1};
        let mut ledger=EvidenceLedger::new(ops,CONTROLLER,SUPERVISOR,1,1).unwrap();
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(CONTROLLER,PUBLISHER,SUPERVISOR,1,2).unwrap();
        assert_eq!(ledger.record(ops,&advice,&trusted),Ok(AdviceResult::Recorded));
        assert_eq!(gate.register_rule_only(CONTROLLER,&plan,&[rec],&profile,&actions,ctx),Err(Error::NotReady));
        let mut bad=disp;bad[94..96].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(gate.register_rejected_fallback_one(CONTROLLER,&plan,&rec,&bad,&profile,local,ctx,&scope,
            &mut ledger,|_,_|panic!("policy rejection needs no fabricated hard proof")),Err(Error::Denied));
        let key=AdviceKey{boot_epoch:1,advisor_epoch:1,advice_seq:1};
        assert_eq!(ledger.admitted_wire(CONTROLLER,key),Ok(advice));
        assert_eq!(gate.register_rejected_fallback_one(CONTROLLER,&plan,&rec,&disp,&profile,local,ctx,&scope,
            &mut ledger,|_,_|panic!("policy rejection is independently derived")),Ok(Registration::Frozen));
        assert_eq!(ledger.admitted_wire(CONTROLLER,key),Err(Error::Stale));
        assert_eq!(gate.publish_once(PUBLISHER,&plan,&[rec],&profile,&actions,ctx,||panic!("ordinary bypass")),Err(Error::Denied));
        assert_eq!(gate.publish_rejected_fallback_one(PUBLISHER,&plan,&rec,&profile,local,ctx,||Ok(())),Ok(Publication::AdapterAccepted));
        assert_eq!(gate.publish_rejected_fallback_one(PUBLISHER,&plan,&rec,&profile,local,ctx,||panic!("no replay")),Ok(Publication::ReplayNoEffect));
        claim_test_work(&mut gate,&plan);
        let report=executor_report(1);let bound=[BoundReport{bytes:&report,origin:apply_report_v1::ReportOrigin::Kernel}];
        let learner=Identity{id:10,generation:1};
        let mut feedback=super::super::feedback_v0199::FeedbackInbox::new(SUPERVISOR,learner).unwrap();
        let pair=super::super::feedback_v0199::CausalPair{advice:&advice,disposition:&disp};
        gate.settle_verified_apply_reports_with_feedback(SUPERVISOR,&plan,&bound,&[verified_binding()],
            verified_scope(),Some(pair),|_,_|Ok(()),|batch|feedback.retain(SUPERVISOR,batch)).unwrap();
        let row=feedback.read(learner,0).unwrap().unwrap();
        assert_eq!(row.causal_label,super::super::feedback_v0199::CausalLabel::NoAdoption);
        assert_eq!(row.report_bytes(),&report);
        assert_eq!(row.decision,rec);
    }

    #[test]
    fn assisted_advice_is_not_authority_and_exact_disposition_and_model_are_rechecked(){
        use super::super::advice_ledger_v0199::{AdviceResult,AdviceKey};
        use super::super::Epochs;
        let mut rules=profile_bytes();
        rules[48..50].copy_from_slice(&1u16.to_le_bytes()); // choice_policy=1, real RuleProfile
        let profile=Profile::parse(&rules).unwrap();
        let mut plan=plan_bytes();
        plan[14..16].copy_from_slice(&1u16.to_le_bytes());
        plan[32..40].copy_from_slice(&9u64.to_le_bytes());
        plan[64+80..64+112].copy_from_slice(&[3;32]);
        plan[208..210].copy_from_slice(&1u16.to_le_bytes());
        plan[210..212].copy_from_slice(&[4,0]);
        let mut rec=decision(&plan,&rules);
        rec[98]=2;rec[99]=1;rec[100]=1;rec[101]=1;
        rec[102..104].copy_from_slice(&1u16.to_le_bytes());
        rec[104..106].copy_from_slice(&1u16.to_le_bytes());
        rec[108..112].copy_from_slice(&8u32.to_le_bytes());
        for (at,value) in [(112,1u64),(120,1),(128,9)]{rec[at..at+8].copy_from_slice(&value.to_le_bytes());}
        rec[158..160].copy_from_slice(&1u16.to_le_bytes());
        let ctx=trusted(&rules);
        let actions=frozen(&[2,4],&[4,0]);
        let local=&actions[0];
        let mut advice=[0u8;ADVICE_BYTES];
        advice[0..4].copy_from_slice(&0x4359_4131u32.to_le_bytes());
        advice[4..6].copy_from_slice(&1u16.to_le_bytes());
        advice[6..8].copy_from_slice(&152u16.to_le_bytes());
        for (at,value) in [(8,1u64),(16,1),(24,3),(32,17),(40,1),(48,5),(56,6),(64,200),(72,9)]{
            advice[at..at+8].copy_from_slice(&value.to_le_bytes());
        }
        for (at,value) in [(80,1u16),(82,1),(84,1),(86,2)]{advice[at..at+2].copy_from_slice(&value.to_le_bytes());}
        advice[88..120].copy_from_slice(&[3;32]);advice[120..152].copy_from_slice(&[1;32]);
        let mut disp=[0u8;DISPOSITION_BYTES];
        disp[0..4].copy_from_slice(&0x4359_4144u32.to_le_bytes());
        disp[4..6].copy_from_slice(&1u16.to_le_bytes());disp[6..8].copy_from_slice(&240u16.to_le_bytes());
        for (at,value) in [(8,1u64),(16,1),(24,1),(32,3),(40,2),(48,4),
            (56,17),(64,1),(72,9),(80,150)]{disp[at..at+8].copy_from_slice(&value.to_le_bytes());}
        for (at,value) in [(88,1u16),(90,1),(92,1),(94,0),(100,0),(102,1),(104,1),(106,1)]{
            disp[at..at+2].copy_from_slice(&value.to_le_bytes());
        }
        disp[96..100].copy_from_slice(&3u32.to_le_bytes());
        disp[112..144].copy_from_slice(&[1;32]);
        disp[144..176].copy_from_slice(&sha256(&advice));disp[176..208].copy_from_slice(&sha256(&rec));
        disp[208..240].copy_from_slice(&sha256(&rules));
        let trusted=TrustedAdviceScope{epochs:Epochs{boot:1,controller:2,model:9,resources:5,cores:6},
            advisor_epoch:1,snapshot_seq:3,domain:1,target:local.target,sampled_ns:100,now_ns:150,
            action_kind:1,candidates:&[2,4],model_hash:[3;32],candidate_set_hash:[1;32]};
        let allowed=AssistedScope{advice:&trusted,assisted_mode:true,offline_model_authorized:true};
        let shadow=AssistedScope{advice:&trusted,assisted_mode:false,offline_model_authorized:true};
        let ops=Identity{id:6,generation:1};
        let mut ledger=EvidenceLedger::new(ops,CONTROLLER,SUPERVISOR,1,1).unwrap();
        let mut gate=RegisteredDecisionGate::new_with_terminal_owner(CONTROLLER,PUBLISHER,SUPERVISOR,1,2).unwrap();
        assert_eq!(gate.register_assisted_one(CONTROLLER,&plan,&rec,&disp,&profile,local,ctx,&allowed,&mut ledger),Err(Error::Stale));
        assert_eq!(ledger.record(ops,&advice,&trusted),Ok(AdviceResult::Recorded));
        assert_eq!(gate.register_assisted_one(ops,&plan,&rec,&disp,&profile,local,ctx,&allowed,&mut ledger),Err(Error::Denied));
        assert_eq!(gate.register_assisted_one(CONTROLLER,&plan,&rec,&disp,&profile,local,ctx,&shadow,&mut ledger),Err(Error::Denied));
        let key=AdviceKey{boot_epoch:1,advisor_epoch:1,advice_seq:1};
        // CONTROL_AUX must not create the audit fact ADOPTED merely from
        // canonical paired bytes, even when the caller is the controller.
        assert_eq!(ledger.finalize(CONTROLLER,&disp,Some(&rec),150),Err(Error::Denied));
        assert_eq!(ledger.consume_verified(SUPERVISOR,key,|_,_,_|panic!("unregistered decision")),Err(Error::NotReady));
        assert_eq!(gate.register_assisted_one(CONTROLLER,&plan,&rec,&disp,&profile,local,ctx,&allowed,&mut ledger),Ok(Registration::Frozen));
        assert_eq!(ledger.admitted_wire(CONTROLLER,key),Err(Error::Stale));
        assert_eq!(ledger.consume_verified(SUPERVISOR,key,|_,_,_|Err(Error::NotReady)),Err(Error::NotReady));
        assert_eq!(ledger.pending(),1);
        assert_eq!(ledger.consume_verified(SUPERVISOR,key,|e,a,d|{
            assert_eq!(a,&advice);assert_eq!(d,&disp);
            assert_eq!(e.disposition_hash,sha256(d));
            assert_eq!(AdviceDispositionV1::decode(d).unwrap().decision_digest,sha256(&rec));
            Ok(())
        }).unwrap().state,1);
        assert_eq!(gate.register_assisted_one(CONTROLLER,&plan,&rec,&disp,&profile,local,ctx,&allowed,&mut ledger),Ok(Registration::ExactRetry));
        assert_eq!(gate.publish_assisted_once(ops,&plan,&rec,&profile,local,ctx,&allowed,||panic!("AI cannot publish")),Err(Error::Denied));
        assert_eq!(gate.publish_assisted_once(PUBLISHER,&plan,&rec,&profile,local,ctx,&shadow,||panic!("SHADOW cannot publish")),Err(Error::Denied));
        let mut count=0;
        assert_eq!(gate.publish_assisted_once(PUBLISHER,&plan,&rec,&profile,local,ctx,&allowed,||{count+=1;Ok(())}),Ok(Publication::AdapterAccepted));
        assert_eq!(gate.publish_assisted_once(PUBLISHER,&plan,&rec,&profile,local,ctx,&allowed,||panic!("duplicate")),Ok(Publication::ReplayNoEffect));
        assert_eq!(count,1);
        assert_eq!(gate.terminal_summary(SUPERVISOR,1),Ok(None));
        assert_eq!(gate.expire_unpublished(CONTROLLER,10000),Err(Error::NotReady));
    }

}
