//! Protected ordinary-workload owner for paired native replay. Requests are
//! retained before their logical release and completed only by real owners.
use crate::learning_history::{FrozenScope, ReplayChecks, TrialKind};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU16, Ordering},
};
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey},
    learning::{
        self, Family, ReplayGroup,
        capture::{RunKey, Source},
        reward::{Adoption, BaselineAdoption, CpuClass, RequestResult, Trial},
    },
};
use sha2::{Digest, Sha256};

pub const REQUESTS: usize = 100;
pub const SOURCES: usize = 16;
pub const REQUEST_DEADLINE_NS: u64 = 5_000_000_000;
pub const OWNER: ObjectKey = ObjectKey {
    id: 0x5245_504c_4159,
    generation: 1,
};
pub const TASK_OWNER: ObjectKey = ObjectKey {
    id: 0x5245_504c_5453,
    generation: 1,
};
pub const IO_OWNER: ObjectKey = ObjectKey {
    id: 0x5245_504c_494f,
    generation: 1,
};
const ZERO: ObjectKey = ObjectKey {
    id: 0,
    generation: 0,
};
pub const EMPTY_SOURCE: Source = Source {
    owner: ZERO,
    class: CpuClass::Policy,
    allowed_cores: 0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelativeRequest {
    pub id: u64,
    pub owner: ObjectKey,
    pub offset_ns: u64,
}
pub const EMPTY_REQUEST: RelativeRequest = RelativeRequest {
    id: 0,
    owner: ZERO,
    offset_ns: 0,
};

/// The image digest is produced after the actual owner's reset/readback.
/// Source and arrival tables are values, so later trials cannot mutate a
/// previously returned manifest through an aliased static reference.
#[derive(Clone, Copy)]
pub struct Prepared {
    pub family: Family,
    pub target: ObjectKey,
    pub baseline: Action,
    pub boundary: cyxia_prototype::domains::stability::Boundary,
    pub group: ReplayGroup,
    pub sources: [Source; SOURCES],
    pub source_count: usize,
    pub requests: [RelativeRequest; REQUESTS],
    pub checks: ReplayChecks,
}
#[derive(Clone, Copy)]
pub struct PreparedFailure {
    pub target: Option<ObjectKey>,
    pub group: Option<ReplayGroup>,
    pub queued_at: u64,
    pub fault: Option<Error>,
    pub drained_at: u64,
}

#[path = "learning_workload/background.rs"]
pub(crate) mod background;
#[path = "learning_workload/owner.rs"]
mod owner;
use crate::domain_control::replay::Token;
use cyxia_prototype::policy::Snapshot;
static DOMAIN: AtomicU16 = AtomicU16::new(0);
fn network(domain: u16) -> bool {
    matches!(domain, 10 | 12 | 16)
}
pub fn init() -> Result<(), Error> {
    owner::init()?;
    crate::domain_services::replay_serial::init()?;
    crate::domain_network::replay::init()?;
    crate::learning_evidence::register_schedule_owner_at(OWNER, schedule_check)
        .map_err(|_| Error::NotReady)
}
fn schedule_check(
    run: RunKey,
    owner: ObjectKey,
    id: u64,
    release_ns: u64,
) -> Result<u64, learning::Error> {
    if network(DOMAIN.load(Ordering::Acquire)) {
        crate::domain_network::replay::schedule_check(run, owner, id, release_ns)
    } else {
        self::owner::schedule_check(run, owner, id, release_ns)
    }
}
pub fn prepare(family: Family, seed: u64, kind: TrialKind) -> Result<Option<Prepared>, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    match DOMAIN.compare_exchange(0, family.domain, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => (),
        Err(old) if old == family.domain => (),
        Err(_) => return Err(Error::Busy),
    }
    if network(family.domain) {
        crate::domain_network::replay::prepare(family, seed, kind)
    } else if family.domain == 15 {
        crate::domain_services::replay_serial::prepare(family, seed, kind)
    } else {
        owner::prepare(family, seed, kind)
    }
}
pub fn bind_preparation(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    crate::domain_control::replay::verify_preparation(preparation)?;
    match DOMAIN.compare_exchange(
        0,
        preparation.family.domain,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => (),
        Err(old) if old == preparation.family.domain => (),
        Err(_) => return Err(Error::Busy),
    }
    if network(preparation.family.domain) {
        crate::domain_network::replay::bind_preparation(preparation)
    } else if preparation.family.domain == 15 {
        crate::domain_services::replay_serial::bind_preparation(preparation)
    } else {
        owner::bind_preparation(preparation)
    }
}
pub fn abort_prepared(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<bool, Error> {
    crate::domain_control::replay::verify_preparation(preparation)?;
    if DOMAIN.load(Ordering::Acquire) != preparation.family.domain {
        return Err(Error::Stale);
    }
    if network(preparation.family.domain) {
        crate::domain_network::replay::abort_prepared(preparation)
    } else if preparation.family.domain == 15 {
        crate::domain_services::replay_serial::abort_prepared(preparation)
    } else {
        owner::abort_prepared(preparation)
    }
}
/// This callback also runs under the root gate; it must not reenter root.
pub fn settled_prepared(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<(), Error> {
    if DOMAIN.load(Ordering::Acquire) != preparation.family.domain {
        return Err(Error::Stale);
    }
    if network(preparation.family.domain) {
        crate::domain_network::replay::settled_prepared(preparation)
    } else if preparation.family.domain == 15 {
        crate::domain_services::replay_serial::settled_prepared(preparation)
    } else {
        owner::settled_prepared(preparation)
    }
}
pub fn prepared_failure(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<PreparedFailure, Error> {
    if DOMAIN.load(Ordering::Acquire) != preparation.family.domain {
        return Err(Error::Stale);
    }
    if network(preparation.family.domain) {
        crate::domain_network::replay::prepared_failure(preparation)
    } else if preparation.family.domain == 15 {
        crate::domain_services::replay_serial::prepared_failure(preparation)
    } else {
        owner::prepared_failure(preparation)
    }
}
pub fn release_prepared(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<(), Error> {
    if !crate::domain_control::replay::preparation_archived(preparation) {
        return Err(Error::Busy);
    }
    if DOMAIN.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    if DOMAIN.load(Ordering::Acquire) != preparation.family.domain {
        return Err(Error::Stale);
    }
    if network(preparation.family.domain) {
        crate::domain_network::replay::release_prepared(preparation)?;
    } else if preparation.family.domain == 15 {
        crate::domain_services::replay_serial::release_prepared(preparation)?;
    } else {
        owner::release_prepared(preparation)?;
    }
    DOMAIN.store(0, Ordering::Release);
    Ok(())
}
pub fn abort_unactivated(
    preparation: crate::domain_control::replay::Preparation,
    scope: &FrozenScope,
) -> Result<bool, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    crate::domain_control::replay::verify_preparation(preparation)?;
    let actual = crate::learning_evidence::current_config()
        .map_err(|error| match error {
            crate::learning_evidence::Error::Busy => Error::Busy,
            crate::learning_evidence::Error::NotReady => Error::NotReady,
            crate::learning_evidence::Error::Stale => Error::Stale,
            _ => Error::Conflict,
        })?
        .ok_or(Error::Stale)?;
    if actual.key != scope.key
        || actual.family != scope.family
        || actual.first_ns != scope.first_ns
        || actual.observation_ns != scope.observation_ns
        || actual.frozen_scope_hash != scope.frozen_scope_hash
    {
        return Err(Error::Conflict);
    }
    if DOMAIN.load(Ordering::Acquire) != preparation.family.domain {
        return Err(Error::Stale);
    }
    if network(preparation.family.domain) {
        crate::domain_network::replay::abort_unactivated(preparation, scope)
    } else if preparation.family.domain == 15 {
        crate::domain_services::replay_serial::abort_unactivated(preparation, scope)
    } else {
        owner::abort_unactivated(preparation, scope)
    }
}
pub fn settled_unactivated(
    preparation: crate::domain_control::replay::Preparation,
    scope: &FrozenScope,
) -> Result<(), Error> {
    if DOMAIN.load(Ordering::Acquire) != preparation.family.domain {
        return Err(Error::Stale);
    }
    if network(preparation.family.domain) {
        crate::domain_network::replay::settled_unactivated(preparation, scope)
    } else if preparation.family.domain == 15 {
        crate::domain_services::replay_serial::settled_unactivated(preparation, scope)
    } else {
        owner::settled_unactivated(preparation, scope)
    }
}
pub fn release_unactivated(
    preparation: crate::domain_control::replay::Preparation,
    scope: &FrozenScope,
) -> Result<(), Error> {
    if !crate::domain_control::replay::preparation_archived(preparation) {
        return Err(Error::Busy);
    }
    if DOMAIN.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    if DOMAIN.load(Ordering::Acquire) != preparation.family.domain {
        return Err(Error::Stale);
    }
    if network(preparation.family.domain) {
        crate::domain_network::replay::release_unactivated(preparation, scope)?;
    } else if preparation.family.domain == 15 {
        crate::domain_services::replay_serial::release_unactivated(preparation, scope)?;
    } else {
        owner::release_unactivated(preparation, scope)?;
    }
    DOMAIN.store(0, Ordering::Release);
    Ok(())
}
macro_rules! route {
    ($method:ident $(, $arg:expr)*) => {{
        let domain = DOMAIN.load(Ordering::Acquire);
        if network(domain) { crate::domain_network::replay::$method($($arg),*) }
        else if domain == 15 { crate::domain_services::replay_serial::$method($($arg),*) }
        else if domain != 0 { owner::$method($($arg),*) }
        else { Err(Error::NotReady) }
    }};
}
pub fn bind_root(token: Token) -> Result<(), Error> {
    route!(bind_root, token)
}
pub fn bind_scope(scope: &FrozenScope) -> Result<(), Error> {
    route!(bind_scope, scope)
}
pub fn activate(run: RunKey, observation_ns: u64) -> Result<(), Error> {
    route!(activate, run, observation_ns)
}
pub fn poll(run: RunKey) -> Result<bool, Error> {
    if DOMAIN.load(Ordering::Acquire) == 15 {
        let _ = crate::domain_services::replay_serial::poll(run)?;
        let _ = crate::domain_services::replay_serial::service_io()?;
        Ok(false)
    } else {
        route!(poll, run)
    }
}
pub fn drain(run: RunKey) -> Result<bool, Error> {
    route!(drain, run)
}
pub fn settled(run: RunKey) -> Result<(), Error> {
    route!(settled, run)
}
pub fn release(run: RunKey) -> Result<(), Error> {
    route!(release, run)?;
    DOMAIN.store(0, Ordering::Release);
    Ok(())
}
pub fn before_first(token: Token, snapshot: Snapshot) -> Result<(), Error> {
    let domain = DOMAIN.load(Ordering::Acquire);
    if network(domain) {
        crate::domain_network::replay::before_first(token, snapshot)
    } else if domain == 15 {
        Ok(())
    } else if domain != 0 {
        owner::before_first(token, snapshot)
    } else {
        Err(Error::NotReady)
    }
}
pub fn prewarm_step() -> Result<(), Error> {
    let domain = DOMAIN.load(Ordering::Acquire);
    if network(domain) {
        crate::domain_network::replay::prewarm_step()
    } else if domain == 0 || domain == 15 {
        Ok(())
    } else {
        owner::prewarm_step()
    }
}
pub fn quiescent() -> bool {
    let domain = DOMAIN.load(Ordering::Acquire);
    if network(domain) {
        crate::domain_network::replay::quiescent()
    } else if domain == 15 {
        !crate::domain_services::replay_serial::reserved()
    } else {
        domain == 0 && owner::quiescent()
    }
}
pub fn service_io(progress: &mut dyn FnMut()) {
    owner::service_io(progress);
}

// Incremental verification preserves actual lock contention separately from
// an unresolved execution. Routing is authenticated by the still-retained
// prepared owner; a caller's family cannot select another owner's witness.
macro_rules! bounded_check {
    ($scope:expr, $method:ident $(, $arg:expr)*) => {{
        let scope = $scope;
        let domain = DOMAIN.load(Ordering::Acquire);
        if domain == 0 || domain != scope.family.domain {
            Err(learning::Error::Stale)
        } else if network(domain) {
            crate::domain_network::replay::$method($($arg),*)
        } else if domain == 15 {
            crate::domain_services::replay_serial::$method($($arg),*)
        } else {
            owner::$method($($arg),*)
        }
    }};
}
pub(crate) fn check_frozen_bounded(scope: &FrozenScope) -> Result<bool, learning::Error> {
    bounded_check!(scope, check_frozen_bounded, scope)
}
pub(crate) fn check_issued_bounded(
    scope: &FrozenScope,
    adoption: &Adoption<'_>,
) -> Result<bool, learning::Error> {
    bounded_check!(scope, check_issued_bounded, scope.key, adoption)
}
pub(crate) fn check_baseline_bounded(
    scope: &FrozenScope,
    baseline: &BaselineAdoption,
) -> Result<bool, learning::Error> {
    bounded_check!(scope, check_baseline_bounded, scope.key, baseline)
}
pub(crate) fn check_closing_bounded(
    scope: &FrozenScope,
    trial: &Trial<'_>,
) -> Result<bool, learning::Error> {
    bounded_check!(scope, check_closing_bounded, scope, trial)
}
/// Unknown sources remain incomplete. Only a still-live, explicitly known
/// owner outside this frozen roster may be omitted from the trial cost.
pub fn outside_source(
    run: RunKey,
    key: ObjectKey,
    class: CpuClass,
) -> Result<bool, learning::Error> {
    let known = |error| match error {
        Error::Busy | Error::Again | Error::NotReady => learning::Error::Unknown,
        _ => learning::Error::Evidence,
    };
    if crate::domain_tasks::replay::outside_source(key, class).map_err(known)? {
        return Ok(true);
    }
    if crate::domain_platform::replay::outside_source(key, class) {
        return Ok(true);
    }
    if crate::domain_services::replay::outside_source(key, class).map_err(known)? {
        return Ok(true);
    }
    if network(DOMAIN.load(Ordering::Acquire)) {
        return crate::domain_network::replay::outside_source(run, key, class);
    }
    Ok(false)
}
