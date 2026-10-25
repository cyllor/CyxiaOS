#[path = "../../../kernel/src/domain_tasks/service_authority.rs"]
mod authority;
use cyxia_prototype::domains::{
    Error, ObjectKey,
    tasks::{CpuLayout, Dispatch, RunState, Scheduler, ThreadSpec},
};
const LAYOUT: CpuLayout = CpuLayout {
    business_mask: 13,
    healthy_mask: 15,
    generation: 1,
};
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn scheduler() -> Scheduler {
    let mut s = Scheduler::new();
    s.register_group(key(14)).unwrap();
    s.admit(
        ThreadSpec {
            key: key(0x101),
            group: key(14),
            cpu: 0,
            allowed_mask: 1,
            minimum_ns: 20_000_000,
            budget_ns: 60_000_000,
        },
        LAYOUT,
        0,
    )
    .unwrap();
    s
}
fn view(s: &Scheduler, d: Dispatch, kind: u64) -> authority::View {
    authority::View {
        cpu: 0,
        held: d,
        actual: s.active(0),
        layout: LAYOUT,
        draining: 0,
        quarantine: s.stats().quarantine_mask,
        kind,
        published_credit_ns: d.reserved_ns,
        settlement_pending: false,
    }
}
#[test]
fn baseline_safety_requires_the_live_paid_service_not_a_completed_dispatch() {
    let mut s = scheduler();
    let d = s
        .dispatch(0, LAYOUT, 1_000_000, 2_500_000)
        .unwrap()
        .unwrap();
    assert_eq!(authority::authorize(view(&s, d, 5), 1_000_100), Ok(()));
    let mut pending = view(&s, d, 5);
    pending.settlement_pending = true;
    assert_eq!(authority::authorize(pending, 1_100_000), Err(Error::Auth));
    s.complete(d, 100_000, RunState::Runnable, 1_100_000)
        .unwrap();
    assert_eq!(
        authority::authorize(view(&s, d, 5), 1_100_000),
        Err(Error::Auth)
    );
    assert_eq!(s.cpu_window_usage(0, 1_100_000), Ok((100_000, 0)));
}
#[test]
fn safety_rejects_tls_slice_expired_credit_and_changed_owner() {
    let mut s = scheduler();
    let tls = s
        .dispatch(0, LAYOUT, 1_000_000, 1_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        authority::authorize(view(&s, tls, 1), 1_000_100),
        Err(Error::Auth)
    );
    assert_eq!(
        authority::authorize(view(&s, tls, 5), 1_000_100),
        Err(Error::Auth)
    );
    s.complete(tls, 100_000, RunState::Runnable, 1_100_000)
        .unwrap();
    let service = s
        .dispatch(0, LAYOUT, 1_200_000, 2_500_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        authority::authorize(view(&s, service, 5), 3_700_000),
        Err(Error::Expired)
    );
    let mut changed = view(&s, service, 5);
    changed.layout.generation += 1;
    assert_eq!(authority::authorize(changed, 1_200_100), Err(Error::Stale));
    let mut stopped = view(&s, service, 5);
    stopped.draining = 1;
    assert_eq!(authority::authorize(stopped, 1_200_100), Err(Error::Stale));
}
