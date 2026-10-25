#[path = "../../../kernel/src/domain_control/target_batch.rs"]
mod target_batch;
use cyxia_prototype::domains::{Error, ObjectKey};
use target_batch::{FAMILIES, Query, Source, queued_wcet_us, resolve};

fn key(id: u64, generation: u64) -> ObjectKey {
    ObjectKey { id, generation }
}

#[test]
fn every_released_mandatory_slot_counts_without_owner_projection() {
    let mut reads = [0u32; FAMILIES];
    let wcet = queued_wcet_us(7, 100, |index| {
        reads[index] += 1;
        Some(100)
    });
    assert_eq!(wcet, Ok(45_000));
    assert_eq!(reads, core::array::from_fn(|index| u32::from(index != 7)));
}

#[test]
fn active_future_and_unregistered_slots_are_excluded_deterministically() {
    let active = 3;
    let wcet = queued_wcet_us(active, 100, |index| match index {
        5 => None,
        8 | 12 => Some(101),
        _ => Some(100),
    });
    // Current evaluation + fourteen other registered and released slots.
    assert_eq!(wcet, Ok(37_500));
    assert_eq!(
        queued_wcet_us(FAMILIES, 100, |_| Some(0)),
        Err(Error::Range)
    );
}

#[test]
fn empty_object_walk_remains_a_required_released_evaluation() {
    // Object absence is discovered only when the family's own turn runs. Its
    // released slot still belongs to the mandatory 18-family control schedule.
    assert_eq!(
        queued_wcet_us(0, 100, |index| (index == 1).then_some(100)),
        Ok(5_000)
    );
}

#[test]
fn projection_preserves_holes_and_fallback() {
    let queries = [
        Query {
            domain: 14,
            kind: 1,
            ordinal: 2,
        },
        Query {
            domain: 14,
            kind: 1,
            ordinal: 1,
        },
    ];
    let mut out = [None; 2];
    resolve(&queries, &mut out, |q| {
        [None, Some(key(8, 2))].get(q.ordinal).copied().flatten()
    })
    .unwrap();
    assert_eq!(out, [None, Some(key(8, 2))]);
}

#[test]
fn batch_rejects_unbounded_or_mismatched_outputs_before_projection() {
    let queries = [Query::default(); FAMILIES + 1];
    let mut output = [None; FAMILIES + 1];
    assert_eq!(
        resolve(&queries, &mut output, |_| panic!("must validate bound")),
        Err(Error::Range)
    );
    assert_eq!(
        resolve(&queries[..1], &mut [], |_| panic!("must validate shape")),
        Err(Error::Range)
    );
}

#[test]
fn every_registered_family_has_one_explicit_owner_source() {
    let actual = [
        (1, 1),
        (1, 2),
        (2, 1),
        (3, 1),
        (4, 1),
        (5, 1),
        (6, 1),
        (7, 1),
        (8, 1),
        (9, 1),
        (10, 1),
        (11, 1),
        (12, 1),
        (13, 1),
        (14, 1),
        (15, 1),
        (16, 1),
        (16, 2),
    ];
    let mut owners = [0; 5];
    for (domain, kind) in actual {
        let source = Source::for_family(domain, kind).unwrap();
        owners[Source::ALL.iter().position(|v| *v == source).unwrap()] += 1;
    }
    assert_eq!(owners, [6, 3, 4, 3, 2]);
    for pair in [(0, 1), (1, 3), (14, 2), (17, 1)] {
        assert_eq!(Source::for_family(pair.0, pair.1), None);
    }
}
