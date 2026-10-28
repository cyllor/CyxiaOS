// Host proof fixture: construction follows a successful exact production
// scheduler cancellation; callers never use missing timestamps as a proof.
fn unused_proof(owner: cyxia_prototype::domains::ObjectKey, core: u16) -> cancellation::Cancellation {
    use cyxia_prototype::domains::tasks::{CpuLayout, Scheduler, ThreadSpec};
    let mut scheduler = Scheduler::new();
    let group = cyxia_prototype::domains::ObjectKey { id: 999, generation: 1 };
    let layout = CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 };
    scheduler.register_group(group).unwrap();
    scheduler.admit(ThreadSpec { key: owner, group, cpu: core, allowed_mask: 1 << core,
        minimum_ns: 0, budget_ns: 10_000_000 }, layout, 100_000_000).unwrap();
    let dispatch = scheduler.dispatch_with_window_headroom(core as usize, layout,
        100_000_000, 2_000_000, 20_000_000).unwrap().unwrap();
    scheduler.cancel_unstarted(dispatch, 180_000_001).unwrap();
    cancellation::Cancellation::new(dispatch)
}
