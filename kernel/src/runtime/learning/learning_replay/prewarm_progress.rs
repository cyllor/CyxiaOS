//! Scheduling only: observed owned CoreSet preparation never grants a replay
//! permit, budget, policy publication, task admission or lifecycle authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub phase: u64,
    pub trial_kind: u64,
    pub domain: u16,
    pub kind: u16,
    pub preparation: u64,
    pub boot: u64,
    pub trial: u64,
    pub token: u64,
    pub target: u64,
    pub seed: u64,
    pub claimed: bool,
    pub prepared: bool,
    pub scope: bool,
    pub first: bool,
    pub activated: bool,
    pub paused: bool,
    pub error: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Queue {
    pub serial: u64,
    pub seed: u64,
    pub target: u64,
    pub has_scope: bool,
    pub first: bool,
    pub stopped: bool,
    pub fault: bool,
    pub warm_queued: bool,
    pub warm_phase: u64,
    pub warm_at: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Reason {
    EnqueueDue = 1,
    RetiredReady = 2,
    FreezeRetry = 3,
}
pub fn owned(o: Owner, q: Queue, root_matches: bool, work_matches: bool) -> bool {
    (o.phase == 3 || o.phase == 5 && o.trial_kind == 1)
        && matches!(o.trial_kind, 1 | 2)
        && (o.domain, o.kind) == (1, 2)
        && o.preparation != 0
        && o.boot != 0
        && o.trial != 0
        && o.token != 0
        && o.target != 0
        && o.claimed
        && o.prepared
        && !o.scope
        && !o.first
        && !o.activated
        && !o.paused
        && !o.error
        && q.serial != 0
        && q.seed == o.seed
        && q.target == o.target
        && !q.has_scope
        && !q.first
        && !q.stopped
        && !q.fault
        && root_matches
        && work_matches
}
pub fn reason(
    o: Owner,
    q: Queue,
    root_matches: bool,
    work_matches: bool,
    now: u64,
    active: bool,
    open: u64,
) -> Option<Reason> {
    if !owned(o, q, root_matches, work_matches) {
        return None;
    }
    if q.warm_queued {
        return (q.warm_phase == 3).then_some(Reason::RetiredReady);
    }
    if !active {
        return (open == 0).then_some(Reason::FreezeRetry);
    }
    (now >= q.warm_at).then_some(Reason::EnqueueDue)
}
/// The general piece remains first and executes exactly once. The caller's
/// optional closure requests a separate fresh service_segment, never reuses it.
pub fn after_general<G, R>(general: impl FnOnce() -> G, optional: impl FnOnce() -> Option<R>) -> G {
    let result = general();
    let _ = optional();
    result
}
