//! Checked from the actual task gate. These copied facts alone are not a
//! capability: only authorize_service_turn obtains them from the live owner.
use cyxia_prototype::domains::{
    Error, ObjectKey, WINDOW_NS,
    tasks::{CpuLayout, Dispatch},
};

pub(super) struct View {
    pub cpu: usize,
    pub held: Dispatch,
    pub actual: Option<Dispatch>,
    pub layout: CpuLayout,
    pub draining: u64,
    pub quarantine: u64,
    pub kind: u64,
    pub published_credit_ns: u64,
    pub settlement_pending: bool,
}
pub(super) fn authorize(view: View, now: u64) -> Result<(), Error> {
    let d = view.held;
    if view.cpu != 0
        || view.kind != 5
        || view.settlement_pending
        || d.cpu != 0
        || d.thread
            != (ObjectKey {
                id: 0x101,
                generation: 1,
            })
        || d.reserved_ns != 2_500_000
        || view.published_credit_ns != d.reserved_ns
        || view.actual != Some(d)
    {
        return Err(Error::Auth);
    }
    if d.core_generation != view.layout.generation
        || view.layout.business_mask & view.layout.healthy_mask & 1 == 0
        || (view.draining | view.quarantine) & 1 != 0
    {
        return Err(Error::Stale);
    }
    if now < d.started_ns
        || now / WINDOW_NS != d.window
        || now
            >= d.started_ns
                .checked_add(d.reserved_ns)
                .ok_or(Error::Overflow)?
    {
        return Err(Error::Expired);
    }
    Ok(())
}
