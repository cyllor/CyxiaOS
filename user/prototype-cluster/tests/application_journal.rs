use cyxia_prototype::domains::{Error, ObjectKey};
use cyxia_prototype_cluster::{application::{Submission, Status, REMOTE}, application_journal::Record};

#[test]
fn durable_record_binds_actor_sequence_epoch_package_and_copied_payload() {
    let actor = ObjectKey { id: 51, generation: 9 };
    let key = ObjectKey { id: 4097, generation: 3 };
    let record = Record::from_submission(Submission { actor, sequence: 17, key,
        submitted_ns: 123, input: &[3; 32] }, [2; 32]);
    let encoded = record.encode().unwrap();
    assert_eq!(Record::decode(&encoded), Ok(record.clone()));
    for at in [6, 40, 54, 80, encoded.len() - 33] {
        let mut altered = encoded.clone();
        altered[at] ^= 1;
        assert_eq!(Record::decode(&altered), Err(Error::Auth));
    }
    let wire = Status { key, state: REMOTE, target: ObjectKey { id: 88, generation: 2 } };
    assert_eq!(Status::decode(&wire.encode().unwrap()), Ok(wire));
}
