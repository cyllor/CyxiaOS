//! Portable arithmetic used by the native per-vCPU PMU accounting adapter.
#![cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]

/// A 64-bit execution counter must not wrap or regress within one lease.
/// The caller prevents CPU migration and handles a failure by containment,
/// never by interpreting the observation as zero charged execution.
pub(crate) const fn execution_delta(start: u64, end: u64) -> Option<u64> {
    end.checked_sub(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_delta_is_exact_and_never_wraps_or_saturates_to_zero() {
        assert_eq!(execution_delta(100, 101), Some(1));
        assert_eq!(execution_delta(100, 100), Some(0));
        assert_eq!(execution_delta(0, u64::MAX), Some(u64::MAX));
        assert_eq!(execution_delta(101, 100), None);
        assert_eq!(execution_delta(u64::MAX, 0), None);
    }
}
