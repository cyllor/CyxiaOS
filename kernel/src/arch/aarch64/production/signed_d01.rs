//! Snapshot and execution owner for the boot-admitted business group.

use super::{role_loader::now_ns, signed_business};
use core::sync::atomic::Ordering;
use cyxia_kernel_core::control_plane::{
    Error, Identity,
    action_schema_v2::ActionV2,
    apply_work_v1::ApplyWorkV1,
    cpu0_v0199::{BUSINESS_MASK, BUSINESS_THREAD_ID_BASE, ONLINE},
    snapshot_store_v3::{DomainObservation, Target},
};
use cyxia_prototype::domains::{Error as SchedulerError, ObjectKey, PolicyStamp, tasks::Scheduler};

#[derive(Clone, Copy)]
pub(super) struct D01Observation {
    pub domain: DomainObservation,
    pub current_weight: u16,
    pub sampled_ns: u64,
    pub ledger_generation: u64,
    pub core_generation: u64,
}

pub(super) const fn target(epoch: u64) -> Target {
    Target {
        domain: 1,
        object: Identity {
            id: BUSINESS_THREAD_ID_BASE,
            generation: epoch,
        },
        owner: Identity {
            id: 1,
            generation: epoch,
        },
    }
}

fn group(epoch: u64) -> ObjectKey {
    let object = target(epoch).object;
    ObjectKey {
        id: object.id,
        generation: object.generation,
    }
}

fn inspect_live<T>(
    epoch: u64,
    access: impl FnOnce(&mut Scheduler, ObjectKey) -> Result<T, Error>,
) -> Result<T, Error> {
    signed_business::try_scheduler(|scheduler| {
        if !signed_business::is_live_epoch(epoch)
            || super::super::ONLINE.load(Ordering::Acquire) != ONLINE
            || scheduler.stats().quarantine_mask & BUSINESS_MASK != 0
        {
            return Err(Error::Stale);
        }
        access(scheduler, group(epoch))
    })
    .ok_or(Error::Busy)?
}

fn scheduler_error(error: SchedulerError) -> Error {
    match error {
        SchedulerError::Auth => Error::Denied,
        SchedulerError::Busy | SchedulerError::Again => Error::Busy,
        SchedulerError::NotReady => Error::NotReady,
        SchedulerError::Stale | SchedulerError::NotFound | SchedulerError::Conflict => Error::Stale,
        SchedulerError::Expired => Error::Expired,
        SchedulerError::Capacity | SchedulerError::Budget | SchedulerError::Overflow => {
            Error::Exhausted
        }
        _ => Error::Invalid,
    }
}

pub(super) fn check_scope(epoch: u64) -> Result<(), Error> {
    inspect_live(epoch, |scheduler, object| {
        scheduler
            .weight_version(object)
            .map(|_| ())
            .map_err(scheduler_error)
    })
}

pub(super) fn observe(epoch: u64, _now_ns: u64) -> Result<D01Observation, Error> {
    inspect_live(epoch, |scheduler, object| {
        let (threads, runnable) = scheduler.group_threads(object).map_err(scheduler_error)?;
        if threads == 0 {
            return Err(Error::Stale);
        }
        let sampled_ns = now_ns();
        Ok(D01Observation {
            domain: DomainObservation {
                target: target(epoch),
                fields: [Some(runnable as u64), None, None, None],
            },
            current_weight: scheduler
                .weight(object, sampled_ns)
                .map_err(scheduler_error)?,
            sampled_ns,
            // These two admissions are installed once for this BootEpoch.
            // Any loss of the fixed scheduler layout closes access above.
            ledger_generation: epoch,
            core_generation: epoch,
        })
    })
}

fn weight(work: ApplyWorkV1<'_>) -> Result<u16, Error> {
    let owner = target(work.key.boot_epoch);
    if !work.key.valid() || work.plan_version == 0 || work.domain != owner.domain {
        return Err(Error::Invalid);
    }
    if work.target != owner.object || work.executor_generation != owner.owner.generation {
        return Err(Error::Stale);
    }
    match ActionV2::decode(work.domain, 1, work.payload)? {
        ActionV2::GroupWeight(weight) => Ok(weight),
        _ => Err(Error::Invalid),
    }
}

pub(super) fn apply(
    work: ApplyWorkV1<'_>,
    prior_target_version: u64,
    sampled_ns: u64,
    valid_until_ns: u64,
    published_ns: u64,
    apply_deadline_ns: u64,
) -> Result<(), Error> {
    let weight = weight(work)?;
    inspect_live(work.key.boot_epoch, |scheduler, target| {
        if scheduler.weight_version(target).map_err(scheduler_error)? != prior_target_version {
            return Err(Error::Stale);
        }
        // Take the mutation timestamp under the same lock as the writers on
        // CPU1–3 to preserve the scheduler's monotonic time ordering.
        let now = now_ns();
        if now > apply_deadline_ns {
            return Err(Error::Expired);
        }
        let stamp = PolicyStamp::new(work.plan_version, sampled_ns, published_ns)
            .map_err(scheduler_error)?;
        if stamp.installed_until_ns != valid_until_ns {
            return Err(Error::Denied);
        }
        scheduler
            .install_published_weight(target, weight, stamp, published_ns, now)
            .map_err(scheduler_error)
    })
}

pub(super) fn verify_applied(work: ApplyWorkV1<'_>, _now_ns: u64) -> Result<u64, Error> {
    let weight = weight(work)?;
    inspect_live(work.key.boot_epoch, |scheduler, target| {
        scheduler
            .verify_weight_effect(target, work.plan_version, weight, now_ns())
            .map_err(scheduler_error)
    })
}
