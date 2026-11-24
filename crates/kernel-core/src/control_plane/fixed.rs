//! V0.19 fixed one-core control role (CPU1 on native four-core profile).
//!
//! CPU0 is the EL1 mechanism/device broker, not an additional AI control CPU.
//! A fault never reallocates the control role to a business core.
//! The two advisory brains have separate bounded mailboxes; neither may
//! publish policy, allocate a resource, revoke a capability, or execute work.
use super::{
    Epochs, Error, Identity,
    advisory::{Advice, Controller, Source, TrustedScope},
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
