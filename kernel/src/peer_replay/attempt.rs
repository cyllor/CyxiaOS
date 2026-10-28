//! Native partner CPU segment custody. The ledger and its backing remain owned
//! by the parent; a token may be consumed only once after actual completion.
use super::{DROPPED, DROPPED_OPEN, captures, ledger, ledger_with, now, stored};
use core::sync::atomic::Ordering;
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{self, reward::CpuClass},
};

pub struct Attempt {
    lease: Option<ledger::Lease>,
    // Set only by a valid first finish on the lease's actual execution CPU.
    // This private completion proof may then travel with the retained lease.
    measured: Option<(u64, u64)>,
    finish_attempted: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.lease.take().is_some() {
            DROPPED.fetch_add(1, Ordering::AcqRel);
            DROPPED_OPEN.fetch_add(1, Ordering::AcqRel);
        }
    }
}
pub fn attempt(owner: ObjectKey, class: CpuClass, core: u16) -> Option<Attempt> {
    if !captures(owner, class) {
        return None;
    }
    match ledger_with(|l| Ok(l.begin(owner, class, core))) {
        Ok(Some(lease)) => Some(Attempt {
            lease: Some(lease),
            measured: None,
            finish_attempted: false,
        }),
        Ok(None) => None,
        Err(_) => {
            DROPPED.fetch_add(1, Ordering::AcqRel);
            None
        }
    }
}
pub(crate) fn cancel_unstarted(
    attempt: &mut Attempt,
    proof: &crate::domain_tasks::Cancellation,
) -> Result<(), learning::Error> {
    let lease = attempt.lease.ok_or(learning::Error::Stale)?;
    if attempt.finish_attempted
        || attempt.measured.is_some()
        || !proof.matches(lease.owner, lease.core)
    {
        return Err(learning::Error::Evidence);
    }
    ledger_with(|ledger| ledger.cancel_unstarted(lease))?;
    attempt.lease = None;
    Ok(())
}
pub fn finish(attempt: &mut Attempt, first: u64, last: u64) -> Result<(), learning::Error> {
    attempt.finish_attempted = true;
    let lease = attempt.lease.ok_or(learning::Error::Stale)?;
    if let Some(original) = attempt.measured {
        if original != (first, last) {
            return Err(learning::Error::Evidence);
        }
    } else {
        if lease.core != cyxia_arch_aarch64::cpu::slot() as u16 || first > last || last > now() {
            return Err(learning::Error::Evidence);
        }
        attempt.measured = Some((first, last));
    }
    if last > now() {
        return Err(learning::Error::Evidence);
    }
    let result = ledger_with(|l| {
        let index = l.count;
        if let Some(value) = l.finish(lease, first, last, now())? {
            unsafe {
                stored(index).write(value);
            }
        }
        Ok(())
    });
    if result != Err(learning::Error::Unknown) {
        attempt.lease = None;
    }
    result
}
