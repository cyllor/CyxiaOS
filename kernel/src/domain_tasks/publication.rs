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

/// Ordinary C publication pins one immutable task-owner view. This supplies
/// no baseline, recovery or model authority; the Active executor keeps those
/// original checks and its complete ordinary selection algorithm.
pub(crate) struct SchedulerPublication {
    state: &'static State,
    cpu: usize,
    _guard: Guard,
    _local: core::marker::PhantomData<*mut ()>,
}

pub(crate) fn reserve_scheduler_publication(
    action: Action,
) -> Result<Option<SchedulerPublication>, Error> {
    if !matches!(action, Action::CpuWeight(_)) {
        return Ok(None);
    }
    let cpu = cpu::slot();
    if cpu >= 64 {
        return Err(Error::Auth);
    }
    let guard = acquire_guard()?;
    let state = unsafe { &*core::ptr::addr_of!(STATE) };
    let allowed = state.layout.healthy_mask
        & !state.layout.business_mask
        & !state.draining
        & !state.scheduler.stats().quarantine_mask;
    if allowed & (1u64 << cpu) == 0 {
        return Err(Error::Auth);
    }
    Ok(Some(SchedulerPublication {
        state,
        cpu,
        _guard: guard,
        _local: core::marker::PhantomData,
    }))
}

impl SchedulerPublication {
    fn check_cpu(&self) -> Result<(), Error> {
        if cpu::slot() != self.cpu {
            Err(Error::Auth)
        } else {
            Ok(())
        }
    }
    pub(crate) fn validate(
        &self,
        action: Action,
        target: ObjectKey,
        _at: u64,
    ) -> Result<(), Error> {
        self.check_cpu()?;
        if !matches!(action, Action::CpuWeight(_) | Action::BackgroundBudget(_)) {
            return Err(Error::Unsupported);
        }
        validate_locked(self.state, action, target, now_ns())
    }
    pub(crate) fn current(&self, domain: u16, target: ObjectKey) -> Result<Action, Error> {
        self.check_cpu()?;
        if !matches!(domain, 1 | 13) {
            return Err(Error::Unsupported);
        }
        current_locked(self.state, domain, target, now_ns())
    }
    pub(crate) fn legal_options(
        &self,
        options: &[Option<Action>],
        target: ObjectKey,
        _at: u64,
        output: &mut [Option<Action>],
    ) -> Result<usize, Error> {
        self.check_cpu()?;
        if options
            .iter()
            .flatten()
            .any(|action| !matches!(action, Action::CpuWeight(_)))
        {
            return Err(Error::Unsupported);
        }
        let at = now_ns();
        cyxia_prototype::policy::collect_legal_actions(options, output, |action| {
            validate_locked(self.state, action, target, at)
        })
    }
    pub(crate) fn prerequisites(
        &self,
        action: Action,
        target: ObjectKey,
    ) -> Result<[Option<crate::domain_control::Prerequisite>; 2], Error> {
        self.check_cpu()?;
        if !matches!(action, Action::CpuWeight(_)) {
            return Err(Error::Unsupported);
        }
        scheduling_dependencies_locked(self.state, target)
    }
}
