#[path = "../../../kernel/src/domain_control/preparation.rs"]
mod preparation;
#[path = "../../../kernel/src/domain_control/target_batch.rs"]
#[allow(dead_code)]
mod target_batch;
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    policy::{ModelBinding, Snapshot},
};
use preparation::{Identity, Pending, Rejections, next_sequence};

fn identity() -> Identity {
    Identity {
        boot: 1,
        controller: 2,
        sequence: 3,
        domain: 14,
        kind: 1,
        target: ObjectKey {
            id: 4,
            generation: 5,
        },
        model: ModelBinding {
            generation: 6,
            model_hash: [7; 32],
            schema_hash: [8; 32],
        },
        core_generation: 9,
        ledger_generation: 10,
        work: None,
    }
}
fn pending() -> Pending {
    Pending::new(
        identity(),
        Snapshot {
            sequence: 3,
            taken_ns: 100,
            core_generation: 9,
            ledger_generation: 10,
        },
        14,
        2,
    )
}
#[test]
fn retry_spans_cannot_refresh_the_two_millisecond_decision_bound() {
    let mut debit = pending();
    debit.charge(1_200_000).unwrap();
    assert_eq!(
        debit.total(identity(), 5_000_100, 900_000),
        Err(Error::Budget)
    );
    assert_eq!(debit.charge(900_000), Err(Error::Budget));
    assert_eq!(debit.check(identity(), 5_000_100), Err(Error::Budget));
    assert_eq!(debit.total(identity(), 5_000_100, 0), Err(Error::Budget));
}
#[test]
fn debit_keeps_original_deadline_and_only_adds_cpu_spans() {
    let mut debit = pending();
    debit.charge(200_000).unwrap();
    debit.charge(300_000).unwrap();
    assert_eq!(debit.total(identity(), 49_000_100, 400_000), Ok(900_000));
    assert_eq!(debit.snapshot.taken_ns, 100);
    assert_eq!((debit.family, debit.ordinal), (14, 2));
    assert_eq!(debit.check(identity(), 50_000_100), Ok(()));
    assert_eq!(debit.check(identity(), 50_000_101), Err(Error::Expired));
    assert_eq!(debit.check(identity(), 99), Err(Error::Expired));
}
#[test]
fn every_decision_identity_field_rejects_cross_identity_debit_reuse() {
    let debit = pending();
    let changes: [fn(&mut Identity); 12] = [
        |i| i.boot += 1,
        |i| i.controller += 1,
        |i| i.sequence += 1,
        |i| i.domain += 1,
        |i| i.kind += 1,
        |i| i.target.id += 1,
        |i| i.target.generation += 1,
        |i| i.model.generation += 1,
        |i| i.model.model_hash[0] += 1,
        |i| i.model.schema_hash[0] += 1,
        |i| i.core_generation += 1,
        |i| i.ledger_generation += 1,
    ];
    for change in changes {
        let mut changed = identity();
        change(&mut changed);
        assert_eq!(debit.total(changed, 100, 100), Err(Error::Stale));
    }
    let mut changed = identity();
    changed.work = Some([1, 2, 0, 0]);
    assert_eq!(debit.total(changed, 100, 100), Err(Error::Stale));
}
#[test]
fn overflow_is_checked_and_cannot_later_become_a_fresh_small_debit() {
    let mut debit = pending();
    debit.charge(1).unwrap();
    assert_eq!(debit.charge(u64::MAX), Err(Error::Overflow));
    assert_eq!(debit.total(identity(), 100, 1), Err(Error::Overflow));
    assert_eq!(debit.charge(0), Err(Error::Overflow));
}

#[test]
fn terminal_preparation_retires_once_and_releases_other_families() {
    for reason in [Error::Budget, Error::Expired, Error::Overflow, Error::Stale] {
        let mut debit = pending();
        debit.charge(1_200_000).unwrap();
        let _ = debit.charge(900_000);
        let mut journal = Rejections::new();
        let retired = journal.retire(debit, reason, 60_000_100, 2).unwrap();
        assert_eq!(retired.sequence, 3);
        assert_eq!(
            (retired.family, retired.ordinal, retired.next_family),
            (14, 2, 15)
        );
        assert_eq!(retired.due_ns, 100_000_100);
        let record = journal.rows[0].unwrap();
        assert_eq!(record.pending.identity, identity());
        assert_eq!(record.pending.snapshot.taken_ns, 100);
        assert_eq!(record.pending.carried(identity(), 0), Ok(2_100_000));
        assert_eq!((record.reason, record.retired_ns), (reason, 60_000_100));
        assert_eq!(
            next_sequence(retired.sequence, identity()),
            Err(Error::Stale)
        );
        assert_eq!(
            journal.retire(debit, reason, 60_000_101, retired.sequence),
            Err(Error::Stale)
        );
        let mut fresh = identity();
        fresh.sequence = 4;
        fresh.domain = 15;
        assert_eq!(next_sequence(retired.sequence, fresh), Ok(()));
        assert_eq!(journal.total, 1);
        let queued = target_batch::queued_wcet_us(retired.next_family, 60_000_100, |family| {
            Some(if family == retired.family {
                retired.due_ns
            } else {
                0
            })
        });
        assert_eq!(
            queued,
            Ok(42_500),
            "other released families remain schedulable"
        );
    }
}

#[test]
fn newer_reserved_sequence_is_not_rewound_by_old_preparation_retirement() {
    let mut journal = Rejections::new();
    let retired = journal.retire(pending(), Error::Stale, 200, 8).unwrap();
    assert_eq!(retired.sequence, 8);
    assert_eq!(
        next_sequence(retired.sequence, identity()),
        Err(Error::Stale)
    );
    let record = journal.rows[0].unwrap().words(1);
    assert_eq!(&record[..11], &[3, 1, 2, 14, 1, 4, 5, 6, 9, 10, 100]);
    assert_eq!(&record[30..34], &[3, 9, 10, 1]);
    assert_eq!(record[13], Error::Stale as u64 + 1);
    assert_eq!(&record[22..26], &[u64::from_le_bytes([7; 8]); 4]);
    assert_eq!(&record[26..30], &[u64::from_le_bytes([8; 8]); 4]);
    assert_eq!(&record[34..], &[0; 6]);
}

#[test]
fn rejection_journal_is_bounded_and_records_overwritten_history() {
    let mut journal = Rejections::new();
    for sequence in 1..=18 {
        let mut debit = pending();
        debit.identity.sequence = sequence;
        debit.snapshot.sequence = sequence;
        journal
            .retire(debit, Error::Expired, 50_000_101, sequence - 1)
            .unwrap();
    }
    assert_eq!((journal.total, journal.overwritten), (18, 2));
    assert_eq!(journal.rows.iter().flatten().count(), 16);
    assert_eq!(journal.rows[0].unwrap().pending.identity.sequence, 17);
}
