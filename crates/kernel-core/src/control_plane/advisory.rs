//! V0.19 local-only deterministic review of bounded, untrusted AI advice.
//!
//! This module has no device/ledger publication access. A caller must build
//! TrustedScope from authenticated local kernel state; a returned choice is
//! NOT a capability, resource grant, or evidence of actual execution.
//! Native manager/driver integration is a separate release gate.
use super::{Epochs, Error, Identity};

/// AI output is data. All its fields are untrusted until checked against
/// the independently owned local scope and protected rule table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Advice {
    pub epochs: Epochs,
    pub model_generation: u64,
    pub domain: usize,
    pub target: Identity,
    pub candidate: u16,
    pub snapshot_ns: u64,
    pub expires_ns: u64,
}

/// Construct only from a current, independently observed local kernel state.
/// The identity and epochs must not be accepted from the AI message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedScope {
    pub epochs: Epochs,
    pub domain: usize,
    pub target: Identity,
    pub now_ns: u64,
}

/// Preauthorized, immutable candidate space. The baseline must be included.
/// Resource quotas, permissions, ownership and execution dependencies must
/// still be checked by the authoritative ledger and executor.
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub baseline: u16,
    pub options: &'static [u16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    DeterministicBaseline,
    AdoptedAdvice,
}

/// A reviewed *choice*, not a grant or an executable policy envelope.
/// Its private fields prevent external code from constructing a fake review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reviewed {
    domain: usize,
    target: Identity,
    epochs: Epochs,
    choice: u16,
    source: Source,
}
impl Reviewed {
    pub const fn domain(self) -> usize { self.domain }
    pub const fn target(self) -> Identity { self.target }
    pub const fn epochs(self) -> Epochs { self.epochs }
    pub const fn choice(self) -> u16 { self.choice }
    pub const fn source(self) -> Source { self.source }
}

/// Domains 1..=15 are local. The old D16 cluster/remote placement domain has
/// no review path and must not be migrated as a local resource authority.
pub struct Controller<const D: usize> {
    rules: [Rule; D],
}
impl<const D: usize> Controller<D> {
    pub fn new(rules: [Rule; D]) -> Result<Self, Error> {
        if D == 0 || D > 15 || rules.iter().any(|rule| {
            rule.options.is_empty()
                || rule.options.len() > 32
                || !rule.options.contains(&rule.baseline)
        }) {
            return Err(Error::Invalid);
        }
        Ok(Self { rules })
    }

    /// Always produces a deterministic legal baseline without AI.
    /// Only an exact, fresh, locally allowed suggestion may replace it.
    /// Unknown, malformed, late, cross-target or cross-generation advice
    /// causes a baseline selection, not a new grant or model wait.
    pub fn review(
        &self,
        trusted: TrustedScope,
        advice: Option<Advice>,
    ) -> Result<Reviewed, Error> {
        if !trusted.epochs.valid()
            || !trusted.target.valid()
            || trusted.domain == 0
            || trusted.domain > D
        {
            return Err(Error::Denied);
        }
        let rule = &self.rules[trusted.domain - 1];
        let adopted = advice.is_some_and(|value| {
            value.domain == trusted.domain
                && value.target == trusted.target
                && value.epochs == trusted.epochs
                && value.model_generation == trusted.epochs.model
                && value.snapshot_ns <= trusted.now_ns
                && value.expires_ns > trusted.now_ns
                && value.expires_ns > value.snapshot_ns
                && rule.options.contains(&value.candidate)
        });
        Ok(Reviewed {
            domain: trusted.domain,
            target: trusted.target,
            epochs: trusted.epochs,
            choice: if adopted { advice.unwrap().candidate } else { rule.baseline },
            source: if adopted { Source::AdoptedAdvice } else { Source::DeterministicBaseline },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const RULE: Rule = Rule { baseline: 2, options: &[1, 2, 4] };
    fn scope() -> TrustedScope {
        TrustedScope {
            epochs: Epochs { boot: 1, controller: 1, model: 2, resources: 1, cores: 1 },
            domain: 3,
            target: Identity { id: 17, generation: 5 },
            now_ns: 100,
        }
    }
    fn advice() -> Advice {
        let scope = scope();
        Advice {
            epochs: scope.epochs,
            model_generation: scope.epochs.model,
            domain: scope.domain,
            target: scope.target,
            candidate: 4,
            snapshot_ns: 90,
            expires_ns: 150,
        }
    }
    #[test]
    fn no_model_is_a_complete_deterministic_path() {
        let controller = Controller::new([RULE; 15]).unwrap();
        let result = controller.review(scope(), None).unwrap();
        assert_eq!(result.choice(), 2);
        assert_eq!(result.source(), Source::DeterministicBaseline);
    }
    #[test]
    fn fresh_legal_suggestion_can_be_considered_but_does_not_authorize() {
        let controller = Controller::new([RULE; 15]).unwrap();
        let result = controller.review(scope(), Some(advice())).unwrap();
        assert_eq!(result.choice(), 4);
        assert_eq!(result.source(), Source::AdoptedAdvice);
    }
    #[test]
    fn stale_cross_target_and_out_of_set_suggestions_use_baseline() {
        let controller = Controller::new([RULE; 15]).unwrap();
        let mut value = advice();
        value.expires_ns = 100;
        assert_eq!(controller.review(scope(), Some(value)).unwrap().choice(), 2);
        value = advice();
        value.target.generation = 6;
        assert_eq!(controller.review(scope(), Some(value)).unwrap().choice(), 2);
        value = advice();
        value.candidate = 99;
        assert_eq!(controller.review(scope(), Some(value)).unwrap().choice(), 2);
        value = advice();
        value.model_generation = 1;
        assert_eq!(controller.review(scope(), Some(value)).unwrap().choice(), 2);
    }
    #[test]
    fn remote_domain_and_invalid_rule_tables_cannot_be_approved() {
        assert!(matches!(Controller::<16>::new([RULE; 16]), Err(Error::Invalid)));
        assert!(matches!(Controller::new([Rule { baseline: 9, options: &[1] }; 15]), Err(Error::Invalid)));
        let controller = Controller::new([RULE; 15]).unwrap();
        let mut request = scope();
        request.domain = 16;
        assert_eq!(controller.review(request, None), Err(Error::Denied));
    }
}
