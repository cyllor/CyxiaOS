//! Exact one-second request metrics. An unissued frozen row makes the window
//! incomplete. Actual rejected, timed-out and pending requests remain in the
//! sample and receive the prescribed penalty; they cannot be deleted to
//! improve throughput or latency.
use cyxia_prototype::{
    domains::Error,
    learning::reward::{OBSERVATION_NS, RequestResult, WorkRequest},
};
pub const SECOND_NS: u64 = 1_000_000_000;
pub const COMPLETED_REQUESTS: u16 = 1;
pub const COMPLETED_P99_NS: u16 = 2;
pub const PENALIZED_P99_NS: u16 = 3;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metrics {
    pub samples: u64,
    pub complete: bool,
    pub value: Option<u64>,
}
pub fn valid_metric(metric: u16) -> bool {
    matches!(
        metric,
        COMPLETED_REQUESTS | COMPLETED_P99_NS | PENALIZED_P99_NS
    )
}
pub fn summarize(
    rows: &[(WorkRequest, Option<RequestResult>)],
    metric: u16,
    start: u64,
    latencies: &mut [u64],
) -> Result<Metrics, Error> {
    if !valid_metric(metric) {
        return Err(Error::Unsupported);
    }
    let end = start.checked_add(SECOND_NS).ok_or(Error::Overflow)?;
    let mut samples = 0usize;
    let mut completed = 0usize;
    let mut complete = true;
    for (i, (request, actual)) in rows.iter().enumerate() {
        if request.id == 0 || rows[..i].iter().any(|(r, _)| r.id == request.id) {
            return Err(Error::Conflict);
        }
        if request.arrived_ns < start || request.arrived_ns >= end {
            continue;
        }
        if samples == latencies.len() {
            return Err(Error::Capacity);
        }
        samples += 1;
        let Some(actual) = actual else {
            complete = false;
            continue;
        };
        if let RequestResult::Completed { finished_ns } = actual {
            if *finished_ns < request.arrived_ns {
                return Err(Error::Range);
            }
            // A late completion was still pending at this window's end.
            if *finished_ns <= end {
                latencies[completed] = *finished_ns - request.arrived_ns;
                completed += 1;
            }
        }
    }
    latencies[..completed].sort_unstable();
    let value = if !complete || samples == 0 {
        None
    } else {
        match metric {
            COMPLETED_REQUESTS => Some(completed as u64),
            COMPLETED_P99_NS => {
                (completed != 0).then(|| latencies[(99 * completed).div_ceil(100) - 1])
            }
            PENALIZED_P99_NS => {
                latencies[completed..samples].fill(OBSERVATION_NS);
                Some(latencies[(99 * samples).div_ceil(100) - 1])
            }
            _ => return Err(Error::Unsupported),
        }
    };
    Ok(Metrics {
        samples: samples as u64,
        complete,
        value,
    })
}
