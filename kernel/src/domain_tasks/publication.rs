//! One live task-owner gate for an unsubmitted, fixed CPU0 baseline.
//! A failed acquisition has no Registry identity or resource custody. Once
//! acquired, all task constraints and the final paid-service check use this
//! same borrow; a normal C worker or task return cannot turn a later try-lock
//! into a version-zero terminal policy failure.
use super::*;

pub(crate) struct BaselinePublication {
    state: &'static State,
    _guard: Guard,
    _local: core::marker::PhantomData<*mut ()>,
}

fn owns(action: Action) -> bool {
    matches!(
        action,
        Action::CpuWeight(_)
            | Action::SpawnTokens(_)
            | Action::Cache { .. }
            | Action::Ipc { .. }
            | Action::ServiceBatch(_)
            | Action::BackgroundBudget(_)
    )
}

pub(crate) fn reserve_baseline_publication(
    action: Action,
    _target: ObjectKey,
) -> Result<Option<BaselinePublication>, Error> {
    // Control-core recovery keeps its existing CACP authority. Only the
    // protected CPU0 BaselineScope consumes this service-owner reservation.
    if cpu::slot() != 0 || !owns(action) {
        return Ok(None);
    }
    let guard = acquire_guard()?;
    let state = unsafe { &*core::ptr::addr_of!(STATE) };
    service_witness_locked(state)?;
    Ok(Some(BaselinePublication {
        state,
        _guard: guard,
        _local: core::marker::PhantomData,
    }))
}

impl BaselinePublication {
    pub(crate) fn validate(
        &self,
        action: Action,
        target: ObjectKey,
        _at: u64,
    ) -> Result<(), Error> {
        if cpu::slot() != 0 || !owns(action) {
            return Err(Error::Auth);
        }
        validate_locked(self.state, action, target, now_ns())
    }

    pub(crate) fn current(&self, domain: u16, target: ObjectKey) -> Result<Action, Error> {
        if cpu::slot() != 0 {
            return Err(Error::Auth);
        }
        current_locked(self.state, domain, target, now_ns())
    }

    pub(crate) fn prerequisites(
        &self,
        action: Action,
        target: ObjectKey,
    ) -> Result<[Option<crate::domain_control::Prerequisite>; 2], Error> {
        if cpu::slot() != 0 || !owns(action) {
            return Err(Error::Auth);
        }
        match action {
            Action::CpuWeight(_) => scheduling_dependencies_locked(self.state, target),
            Action::ServiceBatch(_) => Ok(service_endpoints_locked(self.state, target)?
                .map(|target| Some(crate::domain_control::Prerequisite { domain: 5, target }))),
            _ => Ok([None; 2]),
        }
    }

    pub(crate) fn authorize_service_turn(&self) -> Result<(), Error> {
        // Recheck the actual still-live dispatch and its original time bound
        // at PUBLISH. Holding a gate does not extend or settle CPU credit.
        service_witness_locked(self.state).map(|_| ())
    }
}
