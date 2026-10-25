#[path = "../../../kernel/src/peer_replay/ledger.rs"]
mod ledger;
use cyxia_peer_billing::{Assembler, Binding, Endpoint, MAX_INTERVALS};
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        Error, Family, ReplayGroup,
        capture::RunKey,
        reward::{CpuClass, OBSERVATION_NS},
    },
};
fn binding() -> Binding {
    Binding {
        origin: Endpoint {
            node: [1; 32],
            boot: 3,
        },
        participant: Endpoint {
            node: [2; 32],
            boot: 4,
        },
        session: [5; 32],
        run: RunKey {
            boot_epoch: 3,
            trial_id: 41,
            generation: 9,
        },
        family: Family {
            domain: 16,
            kind: 2,
        },
        baseline: false,
        owner: ObjectKey {
            id: 19,
            generation: 1,
        },
        target: ObjectKey {
            id: 4098,
            generation: 3,
        },
        group: ReplayGroup {
            seed: 1,
            workload: [6; 32],
            initial_image: [7; 32],
        },
        frozen_scope_hash: [8; 32],
    }
}
fn service() -> ObjectKey {
    ObjectKey {
        id: 0x101,
        generation: 1,
    }
}
#[test]
fn actual_open_credits_and_custody_block_closing_and_original_core_times_survive() {
    let b = binding();
    let observation = 2_000_000_000;
    let mut l = ledger::Ledger::new(b, 100, observation, [9; 32]).unwrap();
    assert!(
        l.begin(
            ObjectKey {
                id: 0x100,
                generation: 12
            },
            CpuClass::ExecutorWork,
            3
        )
        .is_none(),
        "unbound executor token cannot enter"
    );
    l.register_remote(12).unwrap();
    let remote = l
        .begin(
            ObjectKey {
                id: 0x100,
                generation: 12,
            },
            CpuClass::ExecutorWork,
            3,
        )
        .unwrap();
    assert_eq!(
        l.close(observation + OBSERVATION_NS, true),
        Err(Error::Unknown)
    );
    let actual = l
        .finish(remote, observation - 10, observation + 30, observation + 30)
        .unwrap()
        .unwrap();
    assert_eq!(
        (actual.core, actual.start_ns, actual.end_ns),
        (3, observation, observation + 30)
    );
    assert_eq!(l.warmup, 10);
    let ordinary = l.begin(service(), CpuClass::ExecutorWork, 0).unwrap();
    assert!(
        l.finish(
            ordinary,
            observation + OBSERVATION_NS,
            observation + OBSERVATION_NS + 70,
            observation + OBSERVATION_NS + 70
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(l.later, 70);
    assert_eq!(
        l.close(observation + OBSERVATION_NS + 80, false),
        Err(Error::Unknown)
    );
    l.close(observation + OBSERVATION_NS + 80, true).unwrap();
    assert!(l.hash_piece(0, &[actual]).unwrap());
    let seal = l.sealed.unwrap();
    assert_eq!(seal.coverage.required, 3);
    assert_eq!((seal.ordinary_warmup_ns, seal.later_workload_ns), (10, 70));
    let mut imported = Assembler::new(b).unwrap();
    imported.append(0, &[actual]).unwrap();
    imported.finish(seal).unwrap();
}
#[test]
fn missing_credit_and_full_bank_never_masquerade_as_zero_cpu_or_complete_coverage() {
    let b = binding();
    let observation = 2_000_000_000;
    let mut l = ledger::Ledger::new(b, 100, observation, [9; 32]).unwrap();
    let lease = l.begin(service(), CpuClass::ExecutorWork, 0).unwrap();
    l.dropped(lease);
    assert_eq!(
        l.close(observation + OBSERVATION_NS, false),
        Err(Error::Unknown)
    );
    assert!(
        l.excluded.is_none(),
        "missing evidence cannot cancel real custody"
    );
    l.close(observation + OBSERVATION_NS, true).unwrap();
    assert_eq!(l.hash_piece(0, &[]), Ok(true));
    assert!(l.sealed.is_none());
    let excluded = l.excluded.unwrap();
    assert!(excluded.trace.validate().is_err());
    assert_eq!(
        excluded.exclusion.reasons,
        cyxia_peer_billing::MISSING_EVENTS
    );
    let mut raw = [0; cyxia_peer_billing::EXCLUDED_BYTES];
    excluded.encode(&mut raw).unwrap();
    assert_eq!(
        cyxia_peer_billing::ExcludedSeal::decode(&raw).unwrap(),
        excluded
    );
    let mut imported = Assembler::new(b).unwrap();
    imported.finish_excluded(excluded).unwrap();
    assert!(imported.sealed().is_none());
    let mut l = ledger::Ledger::new(b, 100, observation, [9; 32]).unwrap();
    let mut values = Vec::new();
    for i in 0..MAX_INTERVALS {
        let lease = l.begin(service(), CpuClass::ExecutorWork, 0).unwrap();
        values.push(
            l.finish(
                lease,
                observation + (i * 2) as u64,
                observation + (i * 2 + 1) as u64,
                observation + 20_000,
            )
            .unwrap()
            .unwrap(),
        );
    }
    let extra = l.begin(service(), CpuClass::ExecutorWork, 0).unwrap();
    assert_eq!(
        l.finish(
            extra,
            observation + 10_000,
            observation + 10_001,
            observation + 20_000
        ),
        Err(Error::Capacity)
    );
    assert_eq!(l.count, MAX_INTERVALS);
    assert_eq!(l.missing, 1);
    l.close(observation + OBSERVATION_NS, true).unwrap();
    let mut imported = Assembler::new(b).unwrap();
    for (i, piece) in values
        .chunks(cyxia_peer_billing::CHUNK_INTERVALS)
        .enumerate()
    {
        let at = i * cyxia_peer_billing::CHUNK_INTERVALS;
        l.hash_piece(at, piece).unwrap();
        imported.append(at, piece).unwrap();
    }
    let excluded = l.excluded.unwrap();
    assert_eq!(excluded.trace.count, MAX_INTERVALS as u64);
    imported.finish_excluded(excluded).unwrap();
    assert_eq!(imported.excluded(), Some(excluded));
    assert!(imported.sealed().is_none());
    assert_eq!(
        imported.finish(excluded.trace),
        Err(cyxia_peer_billing::Error::Incomplete)
    );
}
#[test]
fn only_exact_fixed_fixture_and_actual_remote_token_are_billed() {
    let mut l = ledger::Ledger::new(binding(), 100, 2_000_000_000, [9; 32]).unwrap();
    assert!(
        l.begin(
            ObjectKey {
                id: 16,
                generation: 2
            },
            CpuClass::Policy,
            0
        )
        .is_none()
    );
    let fixture = l
        .begin(
            ObjectKey {
                id: 16,
                generation: 1,
            },
            CpuClass::Policy,
            0,
        )
        .unwrap();
    let actual = l.finish(fixture, 101, 110, 110).unwrap().unwrap();
    assert_eq!(actual.class, CpuClass::Policy);
    l.register_remote(29).unwrap();
    assert!(
        l.begin(
            ObjectKey {
                id: 0x100,
                generation: 28
            },
            CpuClass::ExecutorWork,
            3
        )
        .is_none()
    );
    let bound = l
        .begin(
            ObjectKey {
                id: 0x100,
                generation: 29,
            },
            CpuClass::ExecutorWork,
            3,
        )
        .unwrap();
    assert!(
        l.finish(bound, 2_000_000_010, 2_000_000_020, 2_000_000_020)
            .unwrap()
            .is_some()
    );
}

#[test]
fn late_real_drain_is_excluded_at_original_time_without_extending_closing_window() {
    let observation = 2_000_000_000;
    let mut l = ledger::Ledger::new(binding(), 100, observation, [9; 32]).unwrap();
    let late = observation + OBSERVATION_NS + 5_000_000_001;
    assert_eq!(l.close(late, false), Err(Error::Unknown));
    let open = l.begin(service(), CpuClass::ExecutorWork, 0).unwrap();
    assert_eq!(l.close(late, true), Err(Error::Unknown));
    l.finish(open, late - 1, late, late).unwrap();
    l.close(late, true).unwrap();
    l.hash_piece(0, &[]).unwrap();
    let excluded = l.excluded.unwrap();
    assert_eq!(excluded.exclusion.reasons, cyxia_peer_billing::LATE_CLOSING);
    assert_eq!(excluded.exclusion.drained_ns, late);
    assert_eq!(
        excluded.trace.missing_events, 0,
        "late completion is not a fabricated missing CPU event"
    );
    assert_eq!(
        excluded.trace.coverage.observation_end_ns,
        observation + OBSERVATION_NS
    );
    assert_eq!(excluded.trace.coverage.closing_ns, late);
    assert!(l.sealed.is_none());
}

#[test]
fn root_failure_preserves_real_cpu_and_requires_drain_before_a_negative_seal() {
    let b = binding();
    let observation = 2_000_000_000;
    let mut l = ledger::Ledger::new(b, 100, observation, [9; 32]).unwrap();
    let failure = cyxia_peer_billing::Failure {
        root_token: 77,
        error: cyxia_prototype::domains::Error::Busy as u64 + 1,
        observed_ns: observation + 20,
        publication: None,
    };
    let open = l.begin(service(), CpuClass::ExecutorWork, 0).unwrap();
    l.fail(failure).unwrap();
    l.fail(failure).unwrap();
    assert_eq!(
        l.missing, 0,
        "a real root rejection is not fabricated missing CPU"
    );
    assert_eq!(
        l.close(observation + OBSERVATION_NS, true),
        Err(Error::Unknown)
    );
    let row = l
        .finish(open, observation + 1, observation + 30, observation + 30)
        .unwrap()
        .unwrap();
    assert_eq!(
        l.close(observation + OBSERVATION_NS, false),
        Err(Error::Unknown)
    );
    assert!(l.sealed.is_none() && l.excluded.is_none());
    l.close(observation + OBSERVATION_NS, true).unwrap();
    l.hash_piece(0, &[row]).unwrap();
    let excluded = l.excluded.unwrap();
    assert_eq!(excluded.exclusion.reasons, cyxia_peer_billing::ROOT_FAULT);
    assert_eq!(excluded.exclusion.failure, Some(failure));
    assert_eq!(excluded.trace.missing_events, 0);
    assert_eq!(excluded.trace.count, 1);
    assert_eq!(
        (row.start_ns, row.end_ns),
        (observation + 1, observation + 30)
    );
    let mut imported = Assembler::new(b).unwrap();
    assert!(
        imported.finish_excluded(excluded).is_err(),
        "all actual raw intervals remain mandatory"
    );
    imported.append(0, &[row]).unwrap();
    imported.finish_excluded(excluded).unwrap();
    assert!(imported.sealed().is_none());
    assert!(
        imported
            .finish(cyxia_peer_billing::TraceSeal {
                coverage: cyxia_prototype::learning::reward::CpuCoverage {
                    reported: 3,
                    ..excluded.trace.coverage
                },
                ..excluded.trace
            })
            .is_err(),
        "negative failure evidence cannot be promoted to complete coverage"
    );
}

#[test]
fn failure_after_close_or_seal_cannot_rewrite_the_original_cpu_window() {
    let b = binding();
    let observation = 2_000_000_000;
    let closing = observation + OBSERVATION_NS;
    let mut l = ledger::Ledger::new(b, 100, observation, [9; 32]).unwrap();
    let open = l.begin(service(), CpuClass::ExecutorWork, 0).unwrap();
    let row = l
        .finish(open, observation + 1, observation + 30, observation + 30)
        .unwrap()
        .unwrap();
    l.close(closing, true).unwrap();
    let failure = cyxia_peer_billing::Failure {
        root_token: 77,
        error: cyxia_prototype::domains::Error::Busy as u64 + 1,
        observed_ns: closing + 1,
        publication: None,
    };
    assert!(failure.after_closing(closing));
    assert!(!failure.after_closing(0));
    assert!(
        !cyxia_peer_billing::Failure {
            observed_ns: closing,
            ..failure
        }
        .after_closing(closing)
    );
    assert_eq!(
        l.fail(failure),
        Err(Error::Stale),
        "even pending hash work cannot reopen a physically closed window"
    );
    l.hash_piece(0, &[row]).unwrap();
    let original = l.sealed.unwrap();
    let mut bytes = [0; cyxia_peer_billing::SEAL_BYTES];
    original.encode(&mut bytes).unwrap();
    assert_eq!(l.fail(failure), Err(Error::Stale));
    assert_eq!(l.sealed, Some(original));
    assert!(l.excluded.is_none());
    assert_eq!((l.count, l.missing, l.open), (1, 0, 0));
    let mut after = [0; cyxia_peer_billing::SEAL_BYTES];
    l.sealed.unwrap().encode(&mut after).unwrap();
    assert_eq!(after, bytes);
    let mut imported = Assembler::new(b).unwrap();
    imported.append(0, &[row]).unwrap();
    imported.finish(original).unwrap();
    assert_eq!(imported.sealed(), Some(original));
}
