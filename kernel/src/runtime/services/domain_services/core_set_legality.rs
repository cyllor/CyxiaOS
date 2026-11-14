//! The original CoreSet service-view predicate; the caller supplies the
//! task-owner query, preserving the view's existing freshness/identity checks.
use crate::domain_control::{Family, TargetSource};
use cyxia_prototype::domains::{Error, ObjectKey};
use cyxia_prototype::{
    domains::{Action, ApplyId, PolicyStamp},
    features::TargetFeatures,
    policy::ExecutionState,
};

/// Named native registrations, not inferred callback behavior. Only legality
/// is substituted; current/observation and all executor callbacks stay native.
pub(super) struct NativeCallbacks {
    pub target: fn(u16, u16, usize) -> Option<ObjectKey>,
    pub current: fn(u16, u16, ObjectKey) -> Result<Action, Error>,
    pub legal: fn(Action, ObjectKey, u64) -> Result<(), Error>,
    pub legal_options:
        fn(&[Option<Action>], ObjectKey, u64, &mut [Option<Action>]) -> Result<usize, Error>,
    pub target_features: fn(Action, ObjectKey) -> Result<TargetFeatures, Error>,
    pub apply: fn(Action, ApplyId, PolicyStamp, u64) -> Result<ExecutionState, Error>,
    pub reconcile: fn(Action, ApplyId, PolicyStamp, u64) -> Result<ExecutionState, Error>,
}
pub(super) fn native_family_matches(f: &Family, native: NativeCallbacks) -> bool {
    f.domain == 1
        && f.kind == 2
        && f.target_source == TargetSource::Services
        && core::ptr::fn_addr_eq(f.target, native.target)
        && core::ptr::fn_addr_eq(f.current, native.current)
        && core::ptr::fn_addr_eq(f.legal, native.legal)
        && core::ptr::fn_addr_eq(f.legal_options, native.legal_options)
        && core::ptr::fn_addr_eq(f.target_features, native.target_features)
        && core::ptr::fn_addr_eq(f.apply, native.apply)
        && core::ptr::fn_addr_eq(f.reconcile, native.reconcile)
}

#[derive(Clone, Copy)]
pub(super) struct View {
    pub key: ObjectKey,
    pub generation: u64,
    pub control: u64,
    pub healthy: u64,
    pub draining: u64,
    pub business: u64,
    pub pending: bool,
}

pub(super) fn check(
    s: View,
    mask: u64,
    target: ObjectKey,
    can_move: impl FnOnce(usize) -> Result<(), Error>,
    mut failure: impl FnMut(u64),
) -> Result<(), Error> {
    if target != s.key || s.generation == 0 {
        return Err(Error::Stale);
    }
    if ![2, 6].contains(&mask)
        || mask & s.healthy != mask
        || mask & s.draining != 0
        || s.business & s.healthy & !s.draining & !mask == 0
    {
        return Err(Error::Budget);
    }
    if mask != s.control {
        if (mask ^ s.control) != 4 {
            return Err(Error::Range);
        }
        if s.pending {
            failure(5);
            return Err(Error::Busy);
        }
        if let Err(error) = can_move(2) {
            if error == Error::Busy {
                failure(6);
            }
            return Err(error);
        }
    }
    Ok(())
}
