//! Exercise the exact native schema-preparation helper. These hashes bind
//! immutable code semantics; they do not manufacture native CPU evidence.
#[path = "../../../kernel/src/learning_replay/schemas.rs"]
mod schemas;

use cyxia_prototype::learning::{self, SchemaBinding, Schemas};
use sha2::{Digest, Sha256};

#[test]
fn source_hashing_is_bounded_complete_and_equal_to_original_schema() {
    let feature = include_bytes!("../src/features.rs");
    let action = include_bytes!("../src/policy_wire.rs");
    let mut preparation = schemas::Preparation::new();
    assert_eq!(preparation.ready(), None);
    let mut bytes = 0;
    for source in [feature.as_slice(), action.as_slice()] {
        let mut remaining = source.len();
        while remaining != 0 {
            let consumed = preparation.step();
            assert_eq!(consumed, remaining.min(schemas::SOURCE_CHUNK));
            assert!(consumed <= 512);
            remaining -= consumed;
            bytes += consumed;
            assert_eq!(preparation.ready(), None);
        }
    }
    assert_eq!(bytes, feature.len() + action.len());
    assert_eq!(preparation.step(), 0); // one separate reward-binding turn
    assert_eq!(preparation.ready(), None);
    assert_eq!(preparation.step(), 0); // one separate learning-binding turn
    let expected = Schemas {
        feature: SchemaBinding {
            version: 13,
            hash: Sha256::digest(feature).into(),
        },
        action: SchemaBinding {
            version: 13,
            hash: Sha256::digest(action).into(),
        },
        reward: learning::reward_schema(),
        learning: learning::learning_config(),
    };
    assert_eq!(preparation.ready(), Some(expected));
    expected.validate().unwrap();
    // All subsequent trials reuse the same completed value without hashing.
    for _ in 0..216 * 2 {
        assert_eq!(preparation.step(), 0);
        assert_eq!(preparation.ready(), Some(expected));
    }
}
