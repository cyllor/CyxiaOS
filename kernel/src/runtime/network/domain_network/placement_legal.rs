//! Candidate-local placement feasibility. A missing peer excludes REMOTE;
//! it does not invalidate the fresh request observation for LOCAL or DEFER.
use crate::unified::abi::DomainFeedback;
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey},
    features::DomainObservation,
};

fn fresh(feedback: &DomainFeedback, now_ms: u64) -> Result<(), Error> {
    if now_ms < feedback.measurement_ms || now_ms - feedback.measurement_ms > 100 {
        return Err(Error::NotReady);
    }
    Ok(())
}

fn request(
    key: ObjectKey,
    feedback: &DomainFeedback,
) -> Result<&crate::unified::abi::PendingPlacementWire, Error> {
    feedback
        .waiting
        .iter()
        .find(|request| {
            request.request_generation != 0
                && request.request_id == key.id
                && request.request_generation == key.generation
        })
        .ok_or(Error::Stale)
}

pub(super) fn observation(
    key: ObjectKey,
    feedback: &DomainFeedback,
    now_ms: u64,
) -> Result<DomainObservation, Error> {
    fresh(feedback, now_ms)?;
    let request = request(key, feedback)?;
    if feedback.measurement_valid & 4 == 0 {
        return Ok(DomainObservation {
            values: [0, 0, 0, request.queued_us],
            present: 0b1000,
        });
    }
    let mut values = feedback.cluster;
    values[3] = request.queued_us;
    Ok(DomainObservation::complete(values))
}

pub(super) fn legal(
    choice: u16,
    key: ObjectKey,
    feedback: &DomainFeedback,
    now_ms: u64,
) -> Result<(), Error> {
    Action::Placement(choice).validate()?;
    fresh(feedback, now_ms)?;
    let request = request(key, feedback)?;
    if choice == 1
        && (feedback.measurement_valid & 4 == 0
            || request.peer_ready != 1
            || feedback.peer_cpu_milli < request.cpu_milli
            || feedback.peer_memory_pages < request.memory_pages)
    {
        return Err(Error::Capacity);
    }
    Ok(())
}
