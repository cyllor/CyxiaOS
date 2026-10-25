#[path = "../../../user/prototype-cluster/src/abi.rs"]
#[allow(dead_code)]
mod abi;
#[path = "../../../kernel/src/domain_network/quote_stop.rs"]
#[allow(dead_code)]
mod quote_stop;
use cyxia_prototype::{domains::{Error, ObjectKey}, policy::Snapshot};
use quote_stop::{Identity, Journal};

#[test]
fn real_stop_receipt_keeps_first_snapshot_and_cannot_be_replaced_by_elapsed_time() {
    let mut owner = Journal::<2>::new();
    let id = Identity { boot: 7, replay: 11, owner: ObjectKey { id: 91, generation: 1 } };
    let snapshot = Snapshot { sequence: 9, taken_ns: 123, core_generation: 2, ledger_generation: 8 };
    let first = owner.request(id, snapshot, 124).unwrap();
    assert_eq!(owner.request(id, snapshot, 9_000_000_000).unwrap(), first);
    assert_eq!(owner.request(id, Snapshot { taken_ns: 125, ..snapshot }, 126), Err(Error::Conflict));
    assert_eq!(owner.request(Identity { replay: 12, ..id }, snapshot, 126), Err(Error::Busy));
    let receipt = abi::QuoteStopReceiptWire { command: first.command, offer_version: 3,
        started_ns: 400, finished_ns: 401, outcome: abi::DOMAIN_APPLIED };
    assert_eq!(owner.observe(abi::QuoteStopReceiptWire { command: abi::QuoteStopWire {
        replay_id: 12, ..first.command }, ..receipt }, 500), Err(Error::Stale));
    assert_eq!(owner.observe(receipt, 400), Err(Error::Again));
    owner.observe(receipt, 500).unwrap();
    owner.observe(receipt, 600).unwrap();
    assert_eq!(owner.observe(abi::QuoteStopReceiptWire { finished_ns: 402, ..receipt }, 600), Err(Error::Conflict));
    let retained = owner.request(id, snapshot, 10_000_000_000).unwrap();
    assert_eq!(retained.snapshot, snapshot);
    assert_eq!(retained.accepted_ns, 124);
    assert_eq!(retained.receipt, Some(receipt));
    owner.request(Identity { replay: 12, ..id }, snapshot, 10_000_000_000).unwrap();
    assert_eq!(owner.request(id, snapshot, 20_000_000_000).unwrap(), retained);
    assert_eq!(owner.pending(8), abi::QuoteStopWire::EMPTY);
}

#[test]
fn no_publication_query_cannot_erase_retained_or_unknown_stop_custody() {
    let mut owner = Journal::<2>::new();
    let id = Identity { boot: 7, replay: 11, owner: ObjectKey { id: 91, generation: 1 } };
    let snapshot = Snapshot { sequence: 9, taken_ns: 123, core_generation: 2, ledger_generation: 8 };
    assert_eq!(owner.custody(id, snapshot, 124), Ok(false));
    assert_eq!(owner.pending(id.boot), abi::QuoteStopWire::EMPTY,
        "a custody query must not create a command");
    let first = owner.request(id, snapshot, 124).unwrap();
    assert_eq!(owner.custody(id, snapshot, 124), Ok(true),
        "the protected outbox owns the command before any EL0 response");
    assert_eq!(owner.custody(id, snapshot, u64::MAX), Ok(true),
        "an unacknowledged stop cannot expire into no publication");
    let pending = abi::QuoteStopReceiptWire { command: first.command, offer_version: 3,
        started_ns: 125, finished_ns: 126, outcome: 0 };
    assert_eq!(owner.observe(pending, 127), Err(Error::Again));
    assert_eq!(owner.custody(id, snapshot, 128), Ok(true));
    assert_eq!(owner.custody(id, Snapshot { taken_ns: 124, ..snapshot }, 128), Err(Error::Conflict));
    assert_eq!(owner.custody(id, Snapshot { core_generation: 3, ..snapshot }, 128), Err(Error::Conflict));
    assert_eq!(owner.custody(id, Snapshot { ledger_generation: 9, ..snapshot }, 128), Err(Error::Conflict));
    assert_eq!(owner.custody(id, Snapshot { sequence: 10, ..snapshot }, 128), Err(Error::Busy),
        "a different snapshot cannot evade the pending command");
    for next in [Identity { replay: 12, ..id }, Identity { boot: 8, ..id },
        Identity { owner: ObjectKey { generation: 2, ..id.owner }, ..id }] {
        assert_eq!(owner.custody(next, snapshot, 128), Err(Error::Busy));
    }
    assert_eq!(owner.pending(id.boot), first.command);
    assert_eq!(owner.request(id, snapshot, 129).unwrap(), first);
}

#[test]
fn retired_prior_stop_is_distinct_from_a_new_unissued_baseline_and_closing_command() {
    for outcome in [abi::DOMAIN_APPLIED, abi::DOMAIN_REJECTED] {
        let mut owner = Journal::<2>::new();
        let id = Identity { boot: 7, replay: 11, owner: ObjectKey { id: 91, generation: 1 } };
        let snapshot = Snapshot { sequence: 9, taken_ns: 123, core_generation: 2, ledger_generation: 8 };
        let first = owner.request(id, snapshot, 124).unwrap();
        let next = Identity { replay: 12, ..id };
        assert_eq!(owner.custody(next, snapshot, 125), Err(Error::Busy));
        owner.observe(abi::QuoteStopReceiptWire { command: first.command, offer_version: 3,
            started_ns: 125, finished_ns: 126, outcome }, 127).unwrap();
        assert_eq!(owner.custody(id, snapshot, 128), Ok(true),
            "both successful and rejected real commands remain issued");
        assert_eq!(owner.custody(next, snapshot, 128), Ok(false));
        let closing = Snapshot { sequence: 10, taken_ns: 130, ..snapshot };
        assert_eq!(owner.custody(id, closing, 131), Ok(false));
        let second = owner.request(id, closing, 131).unwrap();
        assert_ne!(first.command.sequence, second.command.sequence);
        assert_eq!(owner.custody(id, closing, 132), Ok(true));
        assert_eq!(owner.custody(id, snapshot, 132), Ok(true),
            "a later command does not erase the original command's custody");
        assert_eq!(owner.custody(next, snapshot, 132), Err(Error::Busy));
        assert_eq!(owner.custody(id, Snapshot { taken_ns: 131, ..closing }, 132), Err(Error::Conflict));
    }
}

#[test]
fn absence_of_custody_requires_a_valid_original_identity() {
    let owner = Journal::<1>::new();
    let id = Identity { boot: 7, replay: 11, owner: ObjectKey { id: 91, generation: 1 } };
    let snapshot = Snapshot { sequence: 9, taken_ns: 123, core_generation: 2, ledger_generation: 8 };
    for invalid in [Identity { boot: 0, ..id }, Identity { replay: 0, ..id },
        Identity { owner: ObjectKey { id: 0, ..id.owner }, ..id },
        Identity { owner: ObjectKey { generation: 0, ..id.owner }, ..id }] {
        assert_eq!(owner.custody(invalid, snapshot, 124), Err(Error::Stale));
    }
    for invalid in [Snapshot { sequence: 0, ..snapshot }, Snapshot { core_generation: 0, ..snapshot },
        Snapshot { ledger_generation: 0, ..snapshot }, Snapshot { taken_ns: 125, ..snapshot }] {
        assert_eq!(owner.custody(id, invalid, 124), Err(Error::Stale));
    }
    assert_eq!(owner.custody(id, snapshot, 124), Ok(false));
}
