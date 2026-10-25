#[path = "../../../kernel/src/domain_platform/read_snapshot.rs"]
pub mod read_snapshot;
mod domain_platform {
    pub use crate::read_snapshot;
}
#[path = "../../../kernel/src/domain_services/target_projection.rs"]
mod target_projection;
use cyxia_prototype::domains::ObjectKey;
use read_snapshot::ReadSnapshot;
use target_projection::{Query, Targets};
fn key(id: u64, generation: u64) -> ObjectKey {
    ObjectKey { id, generation }
}
fn roster(at: u64) -> Targets {
    Targets {
        published_ns: at,
        core: Some(key(10, 1)),
        services: [Some(key(20, 1)), Some(key(21, 1))],
        console: key(30, 1),
    }
}
fn query(
    view: &ReadSnapshot<Targets>,
    domain: u16,
    kind: u16,
    ordinal: usize,
    now: u64,
) -> Option<ObjectKey> {
    target_projection::target(
        view,
        Query {
            domain,
            kind,
            ordinal,
        },
        || now,
        |v| *v,
    )
}
#[test]
fn projection_preserves_roster_order_fallback_and_live_generation_changes() {
    let view = ReadSnapshot::new();
    assert_eq!(query(&view, 14, 1, 0, 100), None);
    view.publish(roster(100)).unwrap();
    assert_eq!(query(&view, 14, 1, 1, 100), Some(key(21, 1)));
    assert_eq!(
        query(&view, 14, 1, 2, 100).or_else(|| query(&view, 14, 1, 0, 100)),
        Some(key(20, 1))
    );
    let mut next = roster(200);
    next.services = [None, Some(key(21, 2))];
    view.publish(next).unwrap();
    assert_eq!(query(&view, 14, 1, 0, 200), None);
    assert_eq!(query(&view, 14, 1, 1, 200), Some(key(21, 2)));
    assert_eq!(
        query(&view, 14, 1, 2, 200).or_else(|| query(&view, 14, 1, 0, 200)),
        None
    );
}
#[test]
fn projection_preserves_exact_freshness_boundary_and_clock_regression() {
    let view = ReadSnapshot::new();
    view.publish(roster(100)).unwrap();
    assert_eq!(query(&view, 1, 2, 0, 99), None);
    assert_eq!(query(&view, 1, 2, 0, 50_000_099), Some(key(10, 1)));
    assert_eq!(query(&view, 1, 2, 0, 50_000_100), None);
    view.publish(roster(50_000_100)).unwrap();
    assert_eq!(query(&view, 1, 2, 0, 50_000_100), Some(key(10, 1)));
}
#[test]
fn projection_rejects_busy_snapshot_and_does_not_hold_the_publication_gate() {
    let view = ReadSnapshot::new();
    view.publish(roster(100)).unwrap();
    view.inspect(|_| assert_eq!(query(&view, 15, 1, 0, 100), None))
        .unwrap();
    assert_eq!(query(&view, 15, 1, 0, 100), Some(key(30, 1)));
    view.publish(roster(101)).unwrap();
}
#[test]
fn projection_exposes_only_registered_service_families_and_available_cores() {
    let view = ReadSnapshot::new();
    let mut targets = roster(100);
    targets.core = None;
    view.publish(targets).unwrap();
    for (domain, kind, ordinal) in [(1, 1, 0), (14, 2, 0), (15, 1, 1), (16, 1, 0), (1, 2, 0)] {
        assert_eq!(query(&view, domain, kind, ordinal, 100), None);
    }
    assert_eq!(query(&view, 15, 1, 0, 100), Some(key(30, 1)));
}

#[test]
fn one_live_publication_projection_serves_all_service_families() {
    use cyxia_prototype::domains::Error;
    let view = ReadSnapshot::new();
    view.publish(roster(100)).unwrap();
    let (mut clocks, mut reads) = (0, 0);
    let targets = target_projection::targets(
        &view,
        || {
            clocks += 1;
            100
        },
        |v| {
            reads += 1;
            *v
        },
    )
    .unwrap();
    assert_eq!((clocks, reads), (1, 1));
    assert_eq!(
        targets.get(Query {
            domain: 1,
            kind: 2,
            ordinal: 0
        }),
        Some(key(10, 1))
    );
    assert_eq!(
        targets.get(Query {
            domain: 14,
            kind: 1,
            ordinal: 1
        }),
        Some(key(21, 1))
    );
    assert_eq!(
        targets.get(Query {
            domain: 15,
            kind: 1,
            ordinal: 0
        }),
        Some(key(30, 1))
    );
    view.inspect(|_| {
        assert!(matches!(
            target_projection::targets(&view, || 100, |v| *v),
            Err(Error::Busy)
        ))
    })
    .unwrap();
    assert!(matches!(
        target_projection::targets(&view, || 50_000_100, |v| *v),
        Err(Error::Busy)
    ));
    let mut updated = roster(200);
    updated.services[1] = Some(key(21, 8));
    view.publish(updated).unwrap();
    let fresh = target_projection::targets(&view, || 200, |v| *v).unwrap();
    assert_eq!(
        fresh.get(Query {
            domain: 14,
            kind: 1,
            ordinal: 1
        }),
        Some(key(21, 8))
    );
    assert_eq!(
        targets.get(Query {
            domain: 14,
            kind: 1,
            ordinal: 1
        }),
        Some(key(21, 1))
    );
}
