//! V0.19 fixed one-core control role (CPU1 on native four-core profile).
//!
//! CPU0 is the EL1 mechanism/device broker, not an additional AI control CPU.
//! A fault never reallocates the control role to a business core.
//! The two advisory brains have separate bounded mailboxes; neither may
//! publish policy, allocate a resource, revoke a capability, or execute work.
use super::{Epochs, Error, Identity, advisory::{Advice, Controller, Source, TrustedScope}};

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
    SecurityAdvice,
    Agreement,
    ConflictFallback,
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
/// Memory-isolated by *separate bounded values*, not by a claim that EL0
/// address-space separation has already been verified. The native caller
/// must supply an authenticated actor (not a field copied from model output).
pub struct Pair {
    operations: Slot,
    security: Slot,
}
impl Pair {
    pub fn new(operations: Identity, security: Identity) -> Result<Self, Error> {
        if !operations.valid() || !security.valid() || operations == security {
            return Err(Error::Invalid);
        }
        Ok(Self { operations: Slot::new(operations), security: Slot::new(security) })
    }

    pub fn submit(
        &mut self,
        brain: Brain,
        authenticated_actor: Identity,
        sequence: u64,
        advice: Advice,
    ) -> Result<(), Error> {
        match brain {
            Brain::Operations => self.operations.submit(authenticated_actor, sequence, advice),
            Brain::Security => self.security.submit(authenticated_actor, sequence, advice),
        }
    }

    /// Deterministic arbitration: one well-scoped legal suggestion is usable,
    /// agreement is usable, conflicting suggestions revert to the protected
    /// baseline. No model is required; the business path does not wait.
    pub fn review<const D: usize>(
        &self,
        rules: &Controller<D>,
        trusted: TrustedScope,
    ) -> Result<Review, Error> {
        let baseline = rules.review(trusted, None)?;
        let left = rules.review(trusted, self.operations.advice)?;
        let right = rules.review(trusted, self.security.advice)?;
        let ops = (left.source() == Source::AdoptedAdvice).then_some(left.choice());
        let sec = (right.source() == Source::AdoptedAdvice).then_some(right.choice());
        let (candidate, source) = match (ops, sec) {
            (None, None) => (baseline.choice(), ChoiceSource::Baseline),
            (Some(a), None) => (a, ChoiceSource::OperationsAdvice),
            (None, Some(b)) => (b, ChoiceSource::SecurityAdvice),
            (Some(a), Some(b)) if a == b => (a, ChoiceSource::Agreement),
            (Some(_), Some(_)) => (baseline.choice(), ChoiceSource::ConflictFallback),
        };
        Ok(Review {
            candidate,
            source,
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
    }
    #[test] fn two_brains_require_distinct_authenticated_roles() {
        assert!(Pair::new(Identity {id:1,generation:1},Identity {id:1,generation:1}).is_err());
        let mut p=pair();
        assert_eq!(p.submit(Brain::Operations,Identity {id:20,generation:1},1,suggestion(4)),Err(Error::Denied));
        assert_eq!(p.submit(Brain::Security,Identity {id:10,generation:1},1,suggestion(4)),Err(Error::Denied));
        assert_eq!(review(&p).source,ChoiceSource::Baseline);
    }
    #[test] fn distinct_mailboxes_do_not_overwrite_each_other() {
        let mut p=pair();
        p.submit(Brain::Operations,Identity {id:10,generation:1},1,suggestion(4)).unwrap();
        p.submit(Brain::Security,Identity {id:20,generation:1},1,suggestion(4)).unwrap();
        assert_eq!(review(&p).source,ChoiceSource::Agreement);
        assert_eq!(review(&p).candidate,4);
    }
    #[test] fn absent_ai_uses_complete_deterministic_baseline() {
        let p=pair();
        assert_eq!(review(&p).source,ChoiceSource::Baseline);
        assert_eq!(review(&p).candidate,2);
    }
    #[test] fn lone_operational_and_security_advice_are_only_recommendations() {
        let mut p=pair();
        p.submit(Brain::Operations,Identity{id:10,generation:1},1,suggestion(4)).unwrap();
        assert_eq!(review(&p).source,ChoiceSource::OperationsAdvice);
        let mut q=pair();
        q.submit(Brain::Security,Identity{id:20,generation:1},1,suggestion(1)).unwrap();
        assert_eq!(review(&q).source,ChoiceSource::SecurityAdvice);
        assert_eq!(review(&q).candidate,1);
    }
    #[test] fn contradictory_ai_recommendations_fall_back_without_grant() {
        let mut p=pair();
        p.submit(Brain::Operations,Identity{id:10,generation:1},1,suggestion(4)).unwrap();
        p.submit(Brain::Security,Identity{id:20,generation:1},1,suggestion(1)).unwrap();
        assert_eq!(review(&p).source,ChoiceSource::ConflictFallback);
        assert_eq!(review(&p).candidate,2);
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
