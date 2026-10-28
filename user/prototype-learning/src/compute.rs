//! Pure computation shared with host tests; the EL0 entry owns no replay or
//! model-registration authority. Timer preemption can occur within every step.
use cyxia_prototype::learning::{Error, train, validate, worker::Worker, worker_wire as wire};

pub fn run(input: &[u8], output: &mut [u8], yield_fn: fn(u64)) -> Result<usize, Error> {
    if input.len() > wire::INPUT_LIMIT || output.len() > wire::OUTPUT_LIMIT {
        return Err(Error::Capacity);
    }
    if cyxia_prototype::learning::score_wire::is_input(input) {
        let mut worker = cyxia_prototype::learning::score::Worker::start(input)?;
        loop {
            let progress = worker.step()?;
            yield_fn(progress.completed);
            if progress.done {
                return worker.finish(output);
            }
        }
    }
    let mut worker = Worker::start(input)?;
    loop {
        let progress = worker.step()?;
        yield_fn(progress.completed);
        if progress.done {
            return worker.finish(output);
        }
    }
}

/// A separate operator receipt. Its magic and fixed size cannot be decoded as
/// a training/validation report, and it contains no candidate or replay data.
pub fn selftest(output: &mut [u8], yield_fn: fn(u64)) -> Result<usize, Error> {
    if output.len() < wire::SELFTEST_BYTES {
        return Err(Error::Capacity);
    }
    let mut completed = 0u64;
    for index in 0..train::OPERATOR_SELFTEST_CASES {
        train::operator_selftest_case(index)?;
        completed += 1;
        yield_fn(completed);
    }
    for index in 0..validate::OPERATOR_SELFTEST_CASES {
        validate::operator_selftest_case(index)?;
        completed += 1;
        yield_fn(completed);
    }
    if completed != wire::SELFTEST_CASES {
        return Err(Error::Validation);
    }
    for (i, value) in [
        wire::SELFTEST_MAGIC,
        u64::from(wire::ABI),
        wire::SELFTEST_CASES,
        wire::SELFTEST_SUCCESS,
    ]
    .into_iter()
    .enumerate()
    {
        output[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(wire::SELFTEST_BYTES)
}
