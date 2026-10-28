#![allow(dead_code)]
use cyxia_prototype::domains::{Error, ObjectKey, WINDOW_NS};
use cyxia_prototype::domains::tasks::{Scheduler, ThreadSpec, CpuLayout};
// AUTHORITY_MODULE
fn key(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
fn view(execution_ns: Option<u64>) -> service_authority::View {
    let layout = CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 };
    let mut scheduler = Scheduler::new(); scheduler.register_group(key(14)).unwrap();
    scheduler.admit(ThreadSpec { key: key(0x101), group: key(14), cpu: 0, allowed_mask: 1,
        minimum_ns: 20_000_000, budget_ns: 60_000_000 }, layout, 100_000_000).unwrap();
    let mut held = scheduler.dispatch_with_window_headroom(0, layout, 100_000_000,
        2_500_000, 20_000_000).unwrap().unwrap();
    if held.reserved_ns < 2_500_000 { held = scheduler.resize_dispatch(held, 2_500_000).unwrap(); }
    service_authority::View { cpu: 0, held, actual: scheduler.active(0), layout,
        draining: 0, quarantine: 0, kind: 5, published_credit_ns: 2_500_000,
        settlement_pending: false, execution_ns }
}
#[test]
fn host_pause_within_original_window_does_not_spend_cpu_credit() {
    assert_eq!(service_authority::authorize(view(Some(434_132)), 108_300_000), Ok(()),
        "service CPU reservation was converted into a 2.5 ms wall lease");
}
#[test]
fn consumed_execution_cannot_authorize_another_effect() {
    assert_eq!(service_authority::authorize(view(Some(2_499_999)), 100_001_000), Ok(()));
    for used in [2_500_000, 2_500_001] {
        assert_eq!(service_authority::authorize(view(Some(used)), 100_001_000), Err(Error::Budget),
            "exhausted service execution credit authorized an effect");
    }
}
#[test]
fn original_wall_order_and_accounting_window_remain_authoritative() {
    assert_eq!(service_authority::authorize(view(Some(1)), 99_999_999), Err(Error::Expired));
    assert_eq!(service_authority::authorize(view(Some(1)), 2 * WINDOW_NS), Err(Error::Expired));
}
#[test]
fn live_dispatch_ownership_and_counter_origin_cannot_be_substituted() {
    for wrong in 0..7 {
        let mut v = view(Some(100));
        match wrong {
            0 => v.execution_ns = None,
            1 => v.cpu = 2,
            2 => v.kind = 1,
            3 => v.settlement_pending = true,
            4 => v.actual = None,
            5 => v.published_credit_ns = 5_000_000,
            _ => v.actual.as_mut().unwrap().sequence += 1,
        }
        assert_eq!(service_authority::authorize(v, 100_001_000), Err(Error::Auth));
    }
    for wrong in 0..3 {
        let mut v = view(Some(100));
        match wrong { 0 => v.layout.generation += 1, 1 => v.draining = 1, _ => v.quarantine = 1 }
        assert_eq!(service_authority::authorize(v, 100_001_000), Err(Error::Stale));
    }
}
