//! Actual diagnostic encoder/latch; synthetic host identities are never
//! publication authority or native replay evidence.
#[path = "../../../kernel/src/domain_control/replay/config_diagnostic.rs"]
#[allow(dead_code)]
mod diagnostic;
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey},
    learning::Family,
    policy::Snapshot,
};
use diagnostic::{Context, Evidence};

fn context() -> Context {
    Context {
        phase: 4,
        cursor: 17,
        count: 41,
        token: 2,
        boot: 3,
        trial: 4,
        kind: 2,
        first: Some(Snapshot {
            sequence: 9,
            taken_ns: 100,
            ledger_generation: 7,
            core_generation: 1,
        }),
        ledger: 11,
        core: 2,
        fault: None,
    }
}

#[test]
fn actual_changed_parameters_keep_both_values_and_original_generations() {
    let words = diagnostic::words(
        context(),
        Family { domain: 4, kind: 1 },
        ObjectKey {
            id: 55,
            generation: 8,
        },
        Action::Filesystem {
            readahead: 2,
            flush: 4,
        },
        Ok(Action::Filesystem {
            readahead: 4,
            flush: 8,
        }),
        150,
    );
    assert_eq!(&words[5..9], &[4, 1, 55, 8]);
    assert_eq!(&words[9..13], &[4, 1, 2, 4]);
    assert_eq!(&words[13..19], &[4, 1, 4, 8, 1, 0]);
    assert_eq!(&words[24..32], &[9, 100, 11, 2, 41, 0, 7, 1]);
    let bank = Evidence::new();
    assert!(bank.retain(words));
    let first = bank.snapshot();
    assert_eq!(first[0], 2);
    assert_eq!(first[19], 150);
    assert!(!bank.retain([0; 32]));
    assert_eq!(bank.snapshot(), first);
}

#[test]
fn missing_owner_is_distinct_from_an_observed_zero_offer() {
    let family = Family {
        domain: 16,
        kind: 1,
    };
    let target = ObjectKey {
        id: 16,
        generation: 1,
    };
    let missing = diagnostic::words(
        context(),
        family,
        target,
        Action::OfferCpu(0),
        Err(Error::Stale),
        200,
    );
    assert_eq!(&missing[9..13], &[16, 1, 0, 0]);
    assert_eq!(&missing[13..18], &[0; 5]);
    assert_eq!(missing[18], Error::Stale as u64 + 1);
    let observed = diagnostic::words(
        context(),
        family,
        target,
        Action::OfferCpu(100),
        Ok(Action::OfferCpu(0)),
        201,
    );
    assert_eq!(&observed[13..19], &[16, 1, 0, 0, 1, 0]);
}
