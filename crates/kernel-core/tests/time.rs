use cyxia_contracts::*;
use cyxia_kernel_core::time::*;
#[test]
fn zero_frequency_rejected() {
    assert_eq!(ticks_to_ns(1, 0), Err(ClockError::Invalid));
}
#[test]
fn conversion_overflow_rejected() {
    assert_eq!(ticks_to_ns(u64::MAX, 1), Err(ClockError::Overflow));
}
#[test]
fn exact_conversion() {
    assert_eq!(ticks_to_ns(62500, 62500000), Ok(TimeNs(1000000)));
}
#[test]
fn deadline_monotonic() {
    assert_eq!(next_deadline(100, 10, 200), Ok(210));
    assert_eq!(next_deadline(100, 10, 105), Ok(110));
    assert_eq!(
        next_deadline(u64::MAX, 1, u64::MAX),
        Err(ClockError::Overflow)
    );
}
