//! Execute the native scheduler's latency ring, without a synthetic clock.
#[path = "../../../kernel/src/domain_tasks/samples.rs"]
mod samples;
use cyxia_prototype::domains::Error;
use samples::Samples;

#[test]
fn nearest_rank_p99_has_no_sample_until_an_actual_observation() {
    let mut samples = Samples::EMPTY;
    assert_eq!(samples.p99(), Err(Error::NotReady));
    samples.add(0);
    assert_eq!(samples.p99(), Ok(0));
    samples.add(u64::MAX);
    assert_eq!(samples.p99(), Ok(u64::MAX));
}

#[test]
fn nearest_rank_p99_is_exact_at_every_supported_population() {
    let mut samples = Samples::EMPTY;
    // For populations 1..=64, ceil(0.99*n) = n. An early high observation
    // must survive every shorter/duplicate sample until its actual eviction.
    samples.add(900);
    for value in 0..63 {
        assert_eq!(samples.p99(), Ok(900));
        samples.add(value);
    }
    assert_eq!(samples.p99(), Ok(900));
    samples.add(8);
    assert_eq!(samples.p99(), Ok(62));
    for _ in 0..64 {
        samples.add(7);
    }
    assert_eq!(samples.p99(), Ok(7));
    samples.add(1000);
    assert_eq!(samples.p99(), Ok(1000));
}
