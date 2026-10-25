//! Only CPU0 may query the live transport owner. Control CPUs use its fresh
//! published identity; admission still binds and rechecks the D05 endpoint.
use cyxia_prototype::domains::{Error, ObjectKey};

pub(super) fn endpoint(
    published: (u64, ObjectKey),
    owner_cpu: bool,
    current: impl FnOnce(u64) -> Result<ObjectKey, Error>,
) -> Result<ObjectKey, Error> {
    let (epoch, target) = published;
    if owner_cpu && current(epoch)? != target {
        return Err(Error::Stale);
    }
    Ok(target)
}
