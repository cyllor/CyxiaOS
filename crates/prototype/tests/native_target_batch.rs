#[path = "../../../kernel/src/domain_control/target_batch.rs"]
mod target_batch;
use cyxia_prototype::domains::{Error, ObjectKey};
use target_batch::{FAMILIES, Query, Released, Source, queued_wcet_us, resolve};

fn key(id: u64, generation: u64) -> ObjectKey {
    ObjectKey { id, generation }
}
fn released(index: usize, due_ns: u64) -> Released {
    Released {
        source: Source::ALL[index % 5],
        query: Query {
            domain: index as u16 + 1,
            kind: 1,
            ordinal: index % 3,
        },
        due_ns,
    }
}

#[test]
fn eighteen_released_families_count_once_and_read_each_owner_once() {
    let mut reads = [0; 5];
    let mut exposed = [0; FAMILIES];
    let wcet = queued_wcet_us(
        7,
        100,
        |index| Some(released(index, 100)),
        |source, queries, output| {
            reads[Source::ALL.iter().position(|v| *v == source).unwrap()] += 1;
            assert!(queries.len() <= FAMILIES);
            resolve(queries, output, |q| Some(key(q.domain as u64, 9)))
        },
        |index, target| {
            exposed[index] += 1;
            assert_eq!(target.generation, 9);
            true
        },
    );
    assert_eq!(wcet, Ok(45_000));
    assert_eq!(reads, [1; 5]);
    assert_eq!(exposed, core::array::from_fn(|i| u32::from(i != 7)));
}

#[test]
fn unavailable_owner_discards_partial_count_and_retry_reads_all_fresh() {
    for unavailable in [Error::Busy, Error::Again, Error::NotReady] {
        let first = queued_wcet_us(
            0,
            100,
            |i| Some(released(i, 100)),
            |source, queries, output| {
                if source == Source::Network {
                    return Err(unavailable);
                }
                resolve(queries, output, |q| Some(key(q.domain as u64, 1)))
            },
            |_, _| panic!("an incomplete owner batch must expose no queue estimate"),
        );
        assert_eq!(first, Err(unavailable));
        let mut generations = Vec::new();
        assert_eq!(
            queued_wcet_us(
                0,
                100,
                |i| Some(released(i, 100)),
                |_, queries, output| resolve(queries, output, |q| Some(key(q.domain as u64, 2))),
                |_, target| {
                    generations.push(target.generation);
                    true
                }
            ),
            Ok(45_000)
        );
        assert_eq!(generations, vec![2; 17]);
    }
}

#[test]
fn grouping_matches_scalar_due_cursor_absence_and_eligibility_rules() {
    let families = core::array::from_fn::<_, FAMILIES, _>(|i| {
        (i != 12).then(|| released(i, if i % 4 == 0 { 101 } else { 100 }))
    });
    let target = |q: Query| {
        if q.domain == 6 || q.ordinal > 1 {
            None
        } else {
            Some(key(
                q.domain as u64 * 10 + q.ordinal as u64,
                q.domain as u64 + 3,
            ))
        }
    };
    // Represent existing independent replay/model/blocked-desired exclusions.
    let eligible = |index: usize, key: ObjectKey| index % 7 != 0 && key.generation != 12;
    let active = 3;
    let expected = 2_500
        * (1 + families
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != active)
            .filter_map(|(i, family)| family.filter(|f| f.due_ns <= 100).map(|f| (i, f)))
            .filter_map(|(i, f)| {
                target(f.query)
                    .or_else(|| {
                        target(Query {
                            ordinal: 0,
                            ..f.query
                        })
                    })
                    .map(|key| (i, key))
            })
            .filter(|(i, key)| eligible(*i, *key))
            .count() as u64);
    assert_eq!(
        queued_wcet_us(
            active,
            100,
            |i| families[i],
            |_, queries, output| resolve(queries, output, target),
            eligible
        ),
        Ok(expected)
    );
}

#[test]
fn unused_owners_are_not_read_and_projection_preserves_holes_and_fallback() {
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
    let mut reads = 0;
    assert_eq!(
        queued_wcet_us(
            0,
            100,
            |i| (i == 1).then(|| released(i, 100)),
            |source, queries, output| {
                reads += 1;
                assert_eq!(source, Source::Services);
                resolve(queries, output, |_| None)
            },
            |_, _| panic!("no object is eligible")
        ),
        Ok(2_500)
    );
    assert_eq!(reads, 1);
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
