use crate::{ContractError, GrantId, PlanId};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    AiDirect,
    AiPlan,
    Bootstrap,
    SafetyGuard,
    Recovery,
    Operator,
    Mechanism,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionOrigin {
    source: DecisionSource,
    model: Option<u64>,
    plan: Option<PlanId>,
    parent: Option<GrantId>,
}
impl DecisionOrigin {
    pub fn new(
        source: DecisionSource,
        model: Option<u64>,
        plan: Option<PlanId>,
        parent: Option<GrantId>,
    ) -> Result<Self, ContractError> {
        let valid = match source {
            DecisionSource::AiDirect => model.is_some_and(|x| x > 0) && plan.is_none(),
            DecisionSource::AiPlan => model.is_some_and(|x| x > 0) && plan.is_some(),
            _ => model.is_none() && plan.is_none(),
        };
        if !valid {
            return Err(ContractError::Invalid);
        }
        Ok(Self {
            source,
            model,
            plan,
            parent,
        })
    }
    pub const fn bootstrap() -> Self {
        Self {
            source: DecisionSource::Bootstrap,
            model: None,
            plan: None,
            parent: None,
        }
    }
    pub const fn source(self) -> DecisionSource {
        self.source
    }
    pub const fn parent(self) -> Option<GrantId> {
        self.parent
    }
}
