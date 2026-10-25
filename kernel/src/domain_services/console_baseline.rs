//! D15's deterministic recovery target, independent of any live AI policy.
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey},
    learning::governance::TargetRegistration,
};

pub(super) fn registration(key: ObjectKey, poisoned: bool) -> Result<TargetRegistration, Error> {
    if poisoned {
        return Err(Error::Io);
    }
    // A live Active action is still an AI lease. Capturing it here would grant
    // it a fresh lease when a failed/expired Canary restores its baseline.
    // Recovery still passes the ordinary owner legality and execution gates.
    Ok(TargetRegistration {
        key,
        baseline: Action::ConsoleBatch(8),
    })
}
