//! V0.19 fixed one-core control role (CPU1 on native four-core profile).
//!
//! CPU0 is the EL1 mechanism/device broker, not an additional AI control CPU.
//! A fault never reallocates the control role to a business core.
//! The two advisory brains have separate bounded mailboxes; neither may
//! publish policy, allocate a resource, revoke a capability, or execute work.
use super::{
    Epochs, Error, Identity,
    advisory::{Advice, Controller, Source, TrustedScope},
    advice_envelope_v1::{AdviceEnvelopeV1, TrustedAdviceScope},
    rule_profile_v2::{Candidates, Profile},
    security_finding::{FrozenObservation, SecurityFinding},
};

pub const CONTROL_CPU: usize = 1;
pub const CONTROL_MASK: u64 = 1 << CONTROL_CPU;
pub const CONTROL_CORES: u32 = 1;
/// CPU0 is the deterministic EL1 broker and must never count as a business CPU.
pub const BROKER_CPU: usize = 0;
pub const BROKER_MASK: u64 = 1 << BROKER_CPU;

/// A trusted native topology snapshot must retain precisely one dedicated
/// control CPU and at least one distinct business CPU. Offline/faulted CPU1 is
/// NOT silently replaced by another CPU.
pub const fn valid_layout(online: u64, control: u64) -> bool {
    online & CONTROL_MASK != 0
        && online & BROKER_MASK != 0
        && control == CONTROL_MASK
        && online & !(CONTROL_MASK | BROKER_MASK) != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Brain {
    Operations,
    Security,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChoiceSource {
    Baseline,
    OperationsAdvice,
}
/// Suggestions alone never grant execution. Consumers must still consult the
/// authoritative deterministic native ledger, policy and capability guards.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Review {
    pub candidate: u16,
    pub source: ChoiceSource,
    pub epochs: Epochs,
    pub target: Identity,
    pub domain: usize,
}
#[derive(Clone, Copy, Debug)]
struct Slot {
    identity: Identity,
    sequence: u64,
    advice: Option<Advice>,
}
impl Slot {
    fn new(identity: Identity) -> Self {
        Self { identity, sequence: 0, advice: None }
    }
    fn submit(&mut self, actor: Identity, sequence: u64, advice: Advice) -> Result<(), Error> {
        if actor != self.identity || !actor.valid() {
            return Err(Error::Denied);
        }
        if sequence == 0 || sequence <= self.sequence {
            return Err(Error::Stale);
        }
        // Reserve the sequence even if the suggestion is stale/illegal. A
        // replayed model output cannot reclaim a former mailbox generation.
        self.sequence = sequence;
        self.advice = Some(advice);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
struct FindingSlot {
    identity: Identity,
    sequence: u64,
    finding: Option<SecurityFinding>,
}
impl FindingSlot {
    fn new(identity: Identity) -> Self {
        Self { identity, sequence: 0, finding: None }
    }
    fn submit(&mut self, actor: Identity, finding: SecurityFinding) -> Result<(), Error> {
        if actor != self.identity || !actor.valid() { return Err(Error::Denied); }
        if finding.finding_seq == 0 || finding.finding_seq <= self.sequence {
            return Err(Error::Stale);
        }
        self.sequence = finding.finding_seq;
        self.finding = Some(finding);
        Ok(())
    }
}
/// Separate bounded values/identities, not a claim that native EL0 page-table
/// isolation has been proven. EL1 must authenticate sender and construct the
/// frozen scope independently. Security findings cannot propose resource actions.
pub struct Pair {
    operations: Slot,
    security: FindingSlot,
}
impl Pair {
    pub fn new(operations: Identity, security: Identity) -> Result<Self, Error> {
        if !operations.valid() || !security.valid() || operations == security {
            return Err(Error::Invalid);
        }
        Ok(Self { operations: Slot::new(operations), security: FindingSlot::new(security) })
    }

    /// Legacy security-role Action advice is denied even if authenticated.
    pub fn submit(
        &mut self,
        brain: Brain,
        authenticated_actor: Identity,
        sequence: u64,
        advice: Advice,
    ) -> Result<(), Error> {
        match brain {
            Brain::Operations => self.operations.submit(authenticated_actor, sequence, advice),
            Brain::Security => Err(Error::Denied),
        }
    }

    /// Authenticated operations IPC intake, with the target, candidate table,
    /// model identity and epochs supplied by protected kernel snapshots.
    /// The model's recommended_index is never treated as a raw parameter.
    pub fn submit_operations_wire(
        &mut self,
        authenticated_actor: Identity,
        frame: &[u8],
        scope: &TrustedAdviceScope<'_>,
    ) -> Result<(), Error> {
        if authenticated_actor != self.operations.identity || !authenticated_actor.valid() {
            return Err(Error::Denied);
        }
        let packet = AdviceEnvelopeV1::decode(frame)?;
        let checked = packet.into_advice(scope)?;
        self.operations.submit(authenticated_actor, packet.advice_seq, checked)
    }

    /// Authenticated role7 IPC intake. Reject legacy Safety+Action advice
    /// and malformed v2 frames before touching the bounded security slot.
    /// The supervisor still independently freezes scope and deduplicates.
    pub fn submit_security_wire(
        &mut self,
        authenticated_actor: Identity,
        frame: &[u8],
    ) -> Result<(), Error> {
        if authenticated_actor != self.security.identity || !authenticated_actor.valid() {
            return Err(Error::Denied);
        }
        let finding = SecurityFinding::decode(frame)?;
        self.security.submit(authenticated_actor, finding)
    }

    /// Records an independently decoded v2 risk report; no policy/ledger effect.
    pub fn submit_finding(
        &mut self,
        authenticated_actor: Identity,
        finding: SecurityFinding,
    ) -> Result<(), Error> {
        self.security.submit(authenticated_actor, finding)
    }

    /// A valid hint requests an independent RuleProfile review, not authorization.
    pub fn security_review_requested(&self, trusted: FrozenObservation) -> bool {
        self.security.finding.is_some_and(|finding| finding.requests_review(trusted))
    }

    /// Use a parsed, immutable RuleProfile v2 to bound the operations
    /// nomination to the current authenticated candidate set. This returns a
    /// read-only review; even an adopted choice is NOT DecisionRecord v3,
    /// authority, a new capacity grant, or an APPLIED receipt.
    ///
    /// `assisted` must be derived from the protected offline authorization
    /// (AI_DISABLED/SHADOW must pass false), never from the model message.
    pub fn review_with_rule_profile(
        &self,
        profile: &Profile<'_>,
        rules_generation: u64,
        trusted: TrustedScope,
        raw_fields: [Option<u64>; 7],
        frozen_candidates: &[u16],
        assisted: bool,
    ) -> Result<Review, Error> {
        // RULE_ONLY/AI_DISABLED must work with no Active model epoch.
        // Model generation is required only to adopt model advice.
        if trusted.epochs.boot == 0 || trusted.epochs.controller == 0
            || trusted.epochs.resources == 0 || trusted.epochs.cores == 0
            || !trusted.target.valid()
            || trusted.domain == 0 || trusted.domain > 15
        {
            return Err(Error::Denied);
        }
        if profile.generation != rules_generation {
            return Err(Error::Stale);
        }
        let frozen = profile.match_candidates(
            trusted.domain as u16, trusted.target.id,
            raw_fields,
            Candidates { static_ordinals: frozen_candidates },
        )?.ok_or(Error::Denied)?;
        let mut chosen = usize::from(frozen.fallback_index);
        let mut source = ChoiceSource::Baseline;
        if assisted && trusted.epochs.model != 0
            && frozen.choice_policy == 1
            && !matches!(trusted.domain, 6 | 11 | 12 | 14)
        {
            if let Some(advice) = self.operations.advice {
                let current = advice.domain == trusted.domain
                    && advice.target == trusted.target
                    && advice.epochs == trusted.epochs
                    && advice.model_generation == trusted.epochs.model
                    && advice.snapshot_ns <= trusted.now_ns
                    && advice.expires_ns > trusted.now_ns
                    && advice.expires_ns > advice.snapshot_ns
                    && advice.snapshot_ns.checked_add(100_000_000)
                        .is_some_and(|end| advice.expires_ns <= end);
                if current {
                    if let Some(index) = frozen_candidates.iter()
                        .position(|&value| value == advice.candidate)
                    {
                        if frozen.allowed_mask & (1u32 << index) != 0 {
                            chosen = index;
                            source = ChoiceSource::OperationsAdvice;
                        }
                    }
                }
            }
        }
        Ok(Review {
            candidate: *frozen_candidates.get(chosen).ok_or(Error::Denied)?,
            source,
            epochs: trusted.epochs,
            target: trusted.target,
            domain: trusted.domain,
        })
    }

    /// The operations brain may nominate an allowed candidate; the independent
    /// deterministic controller and native execution guards retain final authority.
    pub fn review<const D: usize>(
        &self,
        rules: &Controller<D>,
        trusted: TrustedScope,
    ) -> Result<Review, Error> {
        let chosen = rules.review(trusted, self.operations.advice)?;
        Ok(Review {
            candidate: chosen.choice(),
            source: if chosen.source() == Source::AdoptedAdvice {
                ChoiceSource::OperationsAdvice
            } else {
                ChoiceSource::Baseline
            },
            epochs: trusted.epochs,
            target: trusted.target,
            domain: trusted.domain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::advisory::Rule;
    const RULE: Rule = Rule { baseline: 2, options: &[1,2,4] };
    fn scope() -> TrustedScope {
        TrustedScope {
            epochs: Epochs { boot:1, controller:1, model:1, resources:1, cores:1 },
            domain: 1, target: Identity {id:99,generation:1}, now_ns:100,
        }
    }
    fn suggestion(candidate:u16) -> Advice {
        Advice {
            epochs: scope().epochs, model_generation: 1, domain:1,
            target:scope().target, candidate, snapshot_ns:80, expires_ns:150,
        }
    }
    fn pair() -> Pair {
        Pair::new(Identity {id:10,generation:1}, Identity {id:20,generation:1}).unwrap()
    }
    fn review(p:&Pair) -> Review {
        p.review(&Controller::new([RULE;15]).unwrap(),scope()).unwrap()
    }
    #[test] fn v019_fixed_cpu_is_one_and_cannot_be_replaced() {
        assert_eq!(CONTROL_CPU,1);
        assert_eq!(CONTROL_MASK.count_ones(),CONTROL_CORES);
        assert!(valid_layout(0b1111,0b0010));
        assert!(!valid_layout(0b1111,0b0110));
        assert!(!valid_layout(0b1111,0b0100));
        assert!(!valid_layout(0b1101,0b0010));
        assert!(!valid_layout(0b0010,0b0010));
        // CPU0 is not a business CPU, even when it is online beside CPU1.
        assert!(!valid_layout(0b0011,0b0010));
        assert!(valid_layout(0b0111,0b0010));
        // Without CPU0, no deterministic broker can authorize control actions.
        assert!(!valid_layout(0b0110,0b0010));
    }
    fn finding() -> SecurityFinding {
        SecurityFinding {
            boot_epoch: 1, security_epoch: 1, finding_seq: 1, snapshot_seq: 1,
            target: scope().target, expires_ns: 150, kind: 1, severity: 2,
            hint: 1, evidence_count: 1,
            evidence_digest: [1; 32], model_hash: [2; 32], config_hash: [3; 32],
            score_q8_8: 256,
        }
    }
    fn observation() -> FrozenObservation {
        FrozenObservation {
            boot_epoch: 1, security_epoch: 1, snapshot_seq: 1,
            domain_id: 12, target: scope().target,
            sampled_ns: 80, now_ns: 100,
            model_hash: [2; 32], config_hash: [3; 32],
        }
    }
    #[test]
    fn canonical_operations_frame_cannot_be_replayed_by_security_actor() {
        let mut packet = [0u8; 152];
        packet[0..4].copy_from_slice(&0x43594131u32.to_le_bytes());
        packet[4..6].copy_from_slice(&1u16.to_le_bytes());
        packet[6..8].copy_from_slice(&152u16.to_le_bytes());
        for (at, value) in [
            (8, 1u64), (16, 1), (24, 9), (32, 99),
            (40, 1), (48, 1), (56, 1), (64, 150), (72, 1),
        ] {
            packet[at..at+8].copy_from_slice(&value.to_le_bytes());
        }
        packet[80..82].copy_from_slice(&1u16.to_le_bytes());
        packet[82..84].copy_from_slice(&1u16.to_le_bytes());
        packet[84..86].copy_from_slice(&2u16.to_le_bytes());
        packet[86..88].copy_from_slice(&3u16.to_le_bytes());
        packet[88] = 1;
        packet[120] = 2;
        let scope = TrustedAdviceScope {
            epochs: scope().epochs,
            advisor_epoch: 1, snapshot_seq: 9,
            domain: 1, target: scope().target,
            sampled_ns: 80, now_ns: 100, action_kind: 1,
            candidates: &[1, 2, 4],
            model_hash: { let mut b=[0;32]; b[0]=1; b },
            candidate_set_hash: { let mut b=[0;32]; b[0]=2; b },
        };
        let mut p=pair();
        assert_eq!(
            p.submit_operations_wire(Identity{id:20,generation:1}, &packet, &scope),
            Err(Error::Denied)
        );
        assert_eq!(review(&p).candidate, 2);
        p.submit_operations_wire(Identity{id:10,generation:1}, &packet, &scope).unwrap();
        assert_eq!(review(&p).candidate, 4);
        assert_eq!(
            p.submit_operations_wire(Identity{id:10,generation:1}, &packet, &scope),
            Err(Error::Stale)
        );
        let mut bad=packet;
        bad[56..64].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(
            p.submit_operations_wire(Identity{id:10,generation:1}, &bad, &scope),
            Err(Error::Denied)
        );
        assert_eq!(review(&p).candidate, 4);
    }
    #[test]
    fn role7_security_wire_is_canonical_and_never_chooses_actions() {
        let mut raw=[0u8;192];
        raw[0..4].copy_from_slice(&0x4359_4644u32.to_le_bytes());
        raw[4..6].copy_from_slice(&2u16.to_le_bytes());
        raw[6..8].copy_from_slice(&192u16.to_le_bytes());
        for (at,value) in [
            (8,1u64), (16,1), (24,1), (32,1), (40,99),
            (48,1), (56,150),
        ] {raw[at..at+8].copy_from_slice(&value.to_le_bytes());}
        raw[64..66].copy_from_slice(&1u16.to_le_bytes());
        raw[66]=2;raw[67]=1;
        raw[68..70].copy_from_slice(&1u16.to_le_bytes());
        raw[72]=1;raw[104]=2;raw[136]=3;
        raw[168..170].copy_from_slice(&256i16.to_le_bytes());
        let mut p=pair();
        assert_eq!(p.submit_security_wire(
            Identity{id:10,generation:1},&raw),Err(Error::Denied));
        let mut bad=raw;bad[171]=1;
        assert_eq!(p.submit_security_wire(
            Identity{id:20,generation:1},&bad),Err(Error::Invalid));
        assert_eq!(review(&p).source,ChoiceSource::Baseline);
        p.submit_security_wire(Identity{id:20,generation:1},&raw).unwrap();
        assert!(p.security_review_requested(observation()));
        assert_eq!(review(&p).candidate,2);
        assert_eq!(p.submit_security_wire(
            Identity{id:20,generation:1},&raw),Err(Error::Stale));
    }
    #[test] fn distinct_brains_have_no_cross_channel_write() {
        assert!(Pair::new(Identity {id:1,generation:1},Identity {id:1,generation:1}).is_err());
        let mut p=pair();
        assert_eq!(p.submit(Brain::Operations,Identity {id:20,generation:1},1,suggestion(4)),Err(Error::Denied));
        assert_eq!(p.submit(Brain::Security,Identity {id:20,generation:1},1,suggestion(4)),Err(Error::Denied));
        assert_eq!(p.submit_finding(Identity {id:10,generation:1},finding()),Err(Error::Denied));
        assert_eq!(review(&p).source,ChoiceSource::Baseline);
        assert!(!p.security_review_requested(observation()));
    }
    #[test] fn security_finding_may_request_review_but_never_choose_a_parameter() {
        let mut p=pair();
        p.submit_finding(Identity {id:20,generation:1},finding()).unwrap();
        assert!(p.security_review_requested(observation()));
        assert_eq!(review(&p).source,ChoiceSource::Baseline);
        assert_eq!(review(&p).candidate,2);
        p.submit(Brain::Operations,Identity{id:10,generation:1},1,suggestion(4)).unwrap();
        assert_eq!(review(&p).source,ChoiceSource::OperationsAdvice);
        assert_eq!(review(&p).candidate,4);
        assert_eq!(p.submit_finding(Identity {id:20,generation:1},finding()),Err(Error::Stale));
        let mut stale=observation(); stale.security_epoch=2;
        assert!(!p.security_review_requested(stale));
        assert_eq!(review(&p).candidate,4);
    }
    #[test] fn risk_hint_and_score_cannot_override_operations_advice_or_rule_baseline() {
        let mut p=pair();
        p.submit_finding(Identity{id:20,generation:1},finding()).unwrap();
        let mut no_hint=observation(); no_hint.domain_id=1;
        assert!(!p.security_review_requested(no_hint));
        assert_eq!(review(&p).candidate,2);
        p.submit(Brain::Operations,Identity{id:10,generation:1},1,suggestion(1)).unwrap();
        assert_eq!(review(&p).candidate,1);
        assert!(p.security_review_requested(observation()));
    }
    #[test]
    fn v2_rule_profile_nomination_respects_mode_and_current_fallback() {
        let mut catalog = [0u8; 80];
        catalog[0..4].copy_from_slice(&0x4359_5255u32.to_le_bytes());
        catalog[4..6].copy_from_slice(&2u16.to_le_bytes());
        catalog[6..8].copy_from_slice(&32u16.to_le_bytes());
        catalog[8..16].copy_from_slice(&1u64.to_le_bytes());
        catalog[16..20].copy_from_slice(&1u32.to_le_bytes());
        catalog[20..24].copy_from_slice(&80u32.to_le_bytes());
        catalog[32..36].copy_from_slice(&1u32.to_le_bytes());
        catalog[36..38].copy_from_slice(&1u16.to_le_bytes());
        catalog[38..40].copy_from_slice(&1u16.to_le_bytes());
        catalog[40..48].copy_from_slice(&99u64.to_le_bytes());
        catalog[48..50].copy_from_slice(&1u16.to_le_bytes());
        catalog[52..54].copy_from_slice(&2u16.to_le_bytes());
        catalog[56..60].copy_from_slice(&48u32.to_le_bytes());
        catalog[64..66].copy_from_slice(&2u16.to_le_bytes());
        catalog[66..68].copy_from_slice(&1u16.to_le_bytes());
        catalog[72..74].copy_from_slice(&4u16.to_le_bytes());
        let rules = Profile::parse(&catalog).unwrap();
        let mut brain=pair();
        let trusted=scope();
        let candidates=[2u16,4u16];
        let initial=brain.review_with_rule_profile(
            &rules,1,trusted,[None;7],&candidates,true
        ).unwrap();
        assert_eq!(initial.candidate,4);
        assert_eq!(initial.source,ChoiceSource::Baseline);
        brain.submit(Brain::Operations,Identity{id:10,generation:1},1,suggestion(2)).unwrap();
        assert_eq!(brain.review_with_rule_profile(
            &rules,1,trusted,[None;7],&candidates,false
        ).unwrap().candidate,4);
        let adopted=brain.review_with_rule_profile(
            &rules,1,trusted,[None;7],&candidates,true
        ).unwrap();
        assert_eq!(adopted.candidate,2);
        assert_eq!(adopted.source,ChoiceSource::OperationsAdvice);
        assert_eq!(brain.review_with_rule_profile(
            &rules,2,trusted,[None;7],&candidates,true
        ),Err(Error::Stale));
        let mut no_model=trusted;
        no_model.epochs.model=0;
        let rule_only=brain.review_with_rule_profile(
            &rules,1,no_model,[None;7],&candidates,false
        ).unwrap();
        assert_eq!(rule_only.candidate,4);
        assert_eq!(rule_only.source,ChoiceSource::Baseline);
        assert_eq!(brain.review_with_rule_profile(
            &rules,1,no_model,[None;7],&candidates,true
        ).unwrap().source,ChoiceSource::Baseline);
    }
    #[test] fn stale_epoch_illegal_choice_and_expired_advice_revert_to_baseline() {
        let mut p=pair();
        let mut stale=suggestion(4);
        stale.epochs.model=2;
        p.submit(Brain::Operations,Identity{id:10,generation:1},1,stale).unwrap();
        assert_eq!(review(&p).candidate,2);
        p.submit(Brain::Operations,Identity{id:10,generation:1},2,suggestion(999)).unwrap();
        assert_eq!(review(&p).candidate,2);
        let mut expired=suggestion(4);
        expired.expires_ns=100;
        p.submit(Brain::Operations,Identity{id:10,generation:1},3,expired).unwrap();
        assert_eq!(review(&p).candidate,2);
    }
    #[test] fn replayed_sequence_and_old_actor_generation_do_not_replace_new_advice() {
        let mut p=pair();
        p.submit(Brain::Operations,Identity{id:10,generation:1},2,suggestion(4)).unwrap();
        assert_eq!(p.submit(Brain::Operations,Identity{id:10,generation:1},2,suggestion(1)),Err(Error::Stale));
        assert_eq!(p.submit(Brain::Operations,Identity{id:10,generation:2},3,suggestion(1)),Err(Error::Denied));
        assert_eq!(review(&p).candidate,4);
    }
}
