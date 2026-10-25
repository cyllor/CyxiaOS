//! A completed execution is historical evidence. TTL only closes unused new
//! admission; it cannot erase a completed credit or an outstanding obligation.
use cyxia_prototype::{
    domains::{Error, PolicyStamp},
    policy::ExecutionState,
};
pub(super) fn reconcile(
    version: u64,
    stamp: PolicyStamp,
    now: u64,
    in_flight: bool,
) -> ExecutionState {
    if version == stamp.version {
        ExecutionState::Applied
    } else if stamp.live(now) {
        ExecutionState::Pending
    } else if in_flight {
        ExecutionState::Unknown
    } else {
        ExecutionState::Failed(Error::Expired)
    }
}
