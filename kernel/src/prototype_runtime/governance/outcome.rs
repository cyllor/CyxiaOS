//! Classify a physically charged coordinator turn without changing its bill.
use cyxia_prototype::domains::Error;

pub(super) fn entry_slice_ns(mode: u64) -> Result<u64, Error> {
    match mode {
        // The command uses the existing 2 ms work envelope. A 100 us timer
        // intended for the deliberate preemption probe can expire during
        // ordinary entry/copy work and repeatedly postpone its real SVC.
        // Physical 2.5 ms settlement and the 50 ms snapshot deadline are
        // independent and remain enforced by the caller.
        0 => Ok(2_000_000),
        4 => Ok(100_000),
        1..=3 => Ok(20_000_000),
        _ => Err(Error::Conflict),
    }
}

pub(super) fn failure_code(result: Result<(), Error>) -> Option<u64> {
    match result {
        // Owner/pool locks and temporary readiness are retry boundaries. The
        // caller still settles this turn's original physical bill before any
        // retry; its context, pins and phase remain owned by the same runtime.
        Ok(()) | Err(Error::Busy | Error::NotReady) => None,
        Err(error) => Some(0x700 + error as u64),
    }
}
