use cyxia_prototype::domains::{ApplyId, Error, ObjectKey, platform::*};
use cyxia_prototype_cluster::domain_placement::{self, QuoteWire, Record};
fn intent() -> (PlacementIntent, Vec<u8>) {
    let input = vec![0u8; 32];
    let key = ObjectKey {
        id: 1,
        generation: 2,
    };
    (
        PlacementIntent {
            request: PlacementRequest {
                key,
                payload_hash: ring::digest::digest(&ring::digest::SHA256, &input)
                    .as_ref()
                    .try_into()
                    .unwrap(),
                package_hash: [7; 32],
                cpu_milli: 100,
                memory_pages: 16,
                isa: 183,
                abi: 1,
                peer: Some(ObjectKey {
                    id: 3,
                    generation: 1,
                }),
            },
            choice: PlacementChoice::Local,
            apply: Some(ApplyId {
                boot_epoch: 2,
                controller_epoch: 4,
                plan_seq: 6,
                action_index: 0,
                target: key,
            }),
            decided_ns: 100,
        },
        input,
    )
}
#[test]
fn persistent_records_bind_complete_intent_payload_and_unique_outcome() {
    let (i, input) = intent();
    let original = Record::Intent(i, input);
    let mut encoded = domain_placement::encode(&original).unwrap();
    assert_eq!(domain_placement::decode(&encoded), Ok(original));
    *encoded.last_mut().unwrap() = 1;
    assert_eq!(domain_placement::decode(&encoded), Err(Error::Auth));
    for outcome in [
        PlacementOutcome::Local(ObjectKey {
            id: 4,
            generation: 1,
        }),
        PlacementOutcome::Rejected(Error::Capacity),
    ] {
        let record = Record::Receipt(i, outcome);
        let bytes = domain_placement::encode(&record).unwrap();
        assert_eq!(domain_placement::decode(&bytes), Ok(record));
        for n in 0..bytes.len() {
            assert!(domain_placement::decode(&bytes[..n]).is_err());
        }
        let mut suffix = bytes;
        suffix.push(0);
        assert!(domain_placement::decode(&suffix).is_err());
    }
    let peer = Record::Receipt(
        i,
        PlacementOutcome::Peer {
            node: i.request.peer.unwrap(),
            contract: ObjectKey {
                id: 5,
                generation: 1,
            },
        },
    );
    assert!(domain_placement::decode(&domain_placement::encode(&peer).unwrap()).is_err());
}
#[test]
fn quote_wire_rejects_positive_capacity_without_identity_lifetime_and_generations() {
    let quote = QuoteWire {
        status: 0,
        isa: 183,
        abi: 1,
        node: [1; 32],
        owner_boot: 2,
        offer_seq: 3,
        remaining_ms: 2000,
        cpu_milli: 100,
        memory_ratio: 1000,
        memory_pages: 16,
        package_hash: [7; 32],
        core_generation: 4,
        ledger_generation: 5,
    };
    assert_eq!(QuoteWire::decode(&quote.encode()), Ok(quote));
    for invalid in [
        QuoteWire {
            remaining_ms: 2001,
            ..quote
        },
        QuoteWire {
            owner_boot: 0,
            ..quote
        },
        QuoteWire {
            offer_seq: 0,
            ..quote
        },
        QuoteWire { status: 2, ..quote },
        QuoteWire {
            ledger_generation: 0,
            ..quote
        },
        QuoteWire {
            memory_ratio: 1001,
            ..quote
        },
    ] {
        assert!(QuoteWire::decode(&invalid.encode()).is_err());
    }
    let negative = QuoteWire {
        status: 2,
        offer_seq: 0,
        remaining_ms: 0,
        cpu_milli: 0,
        memory_pages: 0,
        memory_ratio: 0,
        ..quote
    };
    assert_eq!(QuoteWire::decode(&negative.encode()), Ok(negative));
}
