//! Readiness for the paid caller of the unchanged collector close operation.
//! Waiting grants no close authority and emits no source or release event.
use cyxia_prototype::learning::{
    Error,
    capture::{Config, RunKey},
    reward::{CpuClass, OBSERVATION_NS},
};

/// `config` is the current capture metadata; `class` was resolved through its
/// actual registered source lookup. The real close callback retains its own
/// fresh clock, source token, open-span and chronology checks.
pub fn close_if_due(
    config: &Config,
    run: RunKey,
    class: CpuClass,
    observed_ns: u64,
    close: impl FnOnce() -> Result<(), Error>,
) -> Result<bool, Error> {
    if config.key != run {
        return Err(Error::Stale);
    }
    let earliest = match class {
        CpuClass::Policy | CpuClass::ExecutorAction => config.first_ns,
        CpuClass::ExecutorWork | CpuClass::Optional => config
            .observation_ns
            .checked_add(OBSERVATION_NS)
            .ok_or(Error::Numeric)?,
    };
    if observed_ns < earliest {
        return Ok(false);
    }
    close()?;
    Ok(true)
}
