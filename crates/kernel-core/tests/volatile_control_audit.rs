use cyxia_kernel_core::control_plane::{
    Identity,
    control_rpc_v1::{Admission, Caller, Error, RpcTable, State},
};
use cyxia_kernel_core::security::recovery_proof_v2::RecoveryProofV2;
use cyxia_kernel_core::security::recovery_proof_v2::{
    DegradedEvent, DegradedEventKind, RECOVERY_PROOF_BYTES, RecoveryAccumulator,
};
use sha2::{Digest, Sha256};
#[path = "../../../user/v0199-control/audit.rs"]
mod client;

#[path = "../../../kernel/src/arch/aarch64/production/observations/audit_record.rs"]
mod audit_record;

#[test]
fn only_the_transferred_proof_yields_a_non_consuming_reconcile_record() {
    let owner = RecoveryAccumulator::new(7, 0, 1).unwrap();
    let mut worker = RecoveryAccumulator::new(7, 1, 1).unwrap();
    worker
        .record(&DegradedEvent {
            event_id: 1,
            event_digest: [99; 32],
            object_id: 0,
            object_generation: 1,
            kind: DegradedEventKind::OtherCritical,
            failure_code: 0x24,
        })
        .unwrap();
    assert!(audit_record::reconcile_record(7, owner.proof(), worker.proof()).is_none());
    worker.takeover_stopped_writer(7, 1, 1, 1).unwrap();
    let slot = audit_record::reconcile_record(7, owner.proof(), worker.proof()).unwrap();
    assert!(audit_record::reconcile_record(8, owner.proof(), worker.proof()).is_none());
    assert_eq!(&slot[..8], b"UAYC\x02\0\x80\0");
    assert_eq!(&slot[24..32], &[10, 0, 1, 0, 3, 0, 255, 255]);
    let words = |at: usize| u64::from_le_bytes(slot[at..at + 8].try_into().unwrap());
    assert_eq!(
        [
            words(8),
            words(16),
            words(32),
            words(40),
            words(48),
            words(56)
        ],
        [7, 1, 0, 1, 1, 2]
    );
    let mut proof = [0; RECOVERY_PROOF_BYTES];
    worker.proof().encode(&mut proof);
    assert_eq!(&slot[64..96], &Sha256::digest(proof)[..]);
    assert_eq!(
        &slot[96..],
        &Sha256::digest([b"CYX/AUDIT/v2".as_slice(), &slot[..96]].concat())[..]
    );
}

fn proofs() -> [RecoveryProofV2; 4] {
    core::array::from_fn(|i| {
        let mut acc = RecoveryAccumulator::new(7, i as u32, 1).unwrap();
        if i != 0 {
            acc.record(&DegradedEvent {
                event_id: 1,
                event_digest: [i as u8; 32],
                object_id: 0,
                object_generation: 1,
                kind: DegradedEventKind::OtherCritical,
                failure_code: 0x24,
            })
            .unwrap();
            acc.takeover_stopped_writer(7, i as u32, 1, 1).unwrap();
        }
        *acc.proof()
    })
}

fn caller() -> Caller {
    Caller {
        boot_epoch: 7,
        holder: Identity {
            id: 11,
            generation: 1,
        },
        role: 11,
        endpoint: 177,
        cap: 19,
    }
}

#[test]
fn release_requires_confirmed_full_delivery_to_the_same_real_holder() {
    let mut custody = audit_record::Custody::from_handoffs(7, &proofs()).unwrap();
    let c = caller();
    let first = custody.read(0);
    let second = custody.read(1);
    assert_eq!(&first[8..16], &1u64.to_le_bytes());
    assert_eq!(&second[8..16], &2u64.to_le_bytes());
    let r = &first[16..];
    let digest = &r[96..];
    assert_eq!(custody.release(c, 1, digest), Err(Error::Auth));
    assert_eq!(custody.delivered(c, 1, &r[..127]), Err(Error::Conflict));
    assert_eq!(custody.release(c, 1, digest), Err(Error::Auth));
    custody.delivered(c, 1, r).unwrap();
    assert_eq!(custody.release(c, 2, digest), Err(Error::Auth));
    assert_eq!(custody.release(c, 0, digest), Err(Error::Stale));
    assert_eq!(custody.release(c, 4, digest), Err(Error::Stale));
    assert_eq!(custody.release(c, 1, &second[112..]), Err(Error::Conflict));
    for other in [
        Caller {
            holder: Identity {
                id: 11,
                generation: 2,
            },
            ..c
        },
        Caller {
            holder: Identity {
                id: 2,
                generation: 1,
            },
            ..c
        },
        Caller {
            cap: c.cap + 1,
            ..c
        },
        Caller {
            endpoint: c.endpoint + 1,
            ..c
        },
        Caller {
            boot_epoch: c.boot_epoch + 1,
            ..c
        },
    ] {
        assert_eq!(custody.release(other, 1, digest), Err(Error::Auth));
        assert_eq!(custody.delivered(other, 1, r), Err(Error::Conflict));
    }
    assert_eq!(custody.read(0), first);
    assert_eq!(custody.released, 0);
    custody.release(c, 1, digest).unwrap();
    assert_eq!(custody.read(0), second);
    assert_eq!(custody.release(c, 1, digest), Err(Error::Stale));
    assert_eq!(custody.released, 1);
}

fn request(op: u16, seq: u64, audit_seq: u64, digest: &[u8]) -> Vec<u8> {
    let mut req = vec![0; if op == 1 { 64 } else { 96 }];
    req[..8].copy_from_slice(&[0x51, 0x43, 0x59, 0x43, 1, 0, 48, 0]);
    req[8..10].copy_from_slice(&op.to_le_bytes());
    let len = (req.len() - 48) as u32;
    req[12..16].copy_from_slice(&len.to_le_bytes());
    for (at, v) in [
        (16, seq),
        (24, seq - 1),
        (32, 1),
        (40, 300),
        (48, 1),
        (56, audit_seq),
    ] {
        req[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    req[64..].copy_from_slice(digest);
    req
}

#[test]
fn real_control_rpc_replay_and_el0_record_validation_cover_all_three_writers() {
    let c = caller();
    let mut store = audit_record::Custody::from_handoffs(7, &proofs()).unwrap();
    let mut table = RpcTable::new();
    table.bind(c, false).unwrap();
    for n in 1..=3 {
        let seq = n * 2 - 1;
        let read_req = request(1, seq, n - 1, &[]);
        let Admission::Execute(ticket) = table
            .admit(c, &read_req, 192, 1, 400, 1, |_| Ok(()))
            .unwrap()
        else {
            panic!("first admission must execute")
        };
        let reply = table
            .complete(ticket, State::Done, 0, 1, &store.read(n - 1), || Ok(()))
            .unwrap();
        let wire: &[u8; 192] = reply.bytes().try_into().unwrap();
        assert!(client::valid_reply(wire, 1, seq, 1));
        let (next, digest) = client::read_record(wire, 7, n - 1).unwrap();
        assert_eq!(next, n);
        for offset in 0..48 {
            let mut altered = *wire;
            altered[offset] ^= 1;
            assert!(!client::valid_reply(&altered, 1, seq, 1));
        }
        for offset in 48..192 {
            let mut altered = *wire;
            altered[offset] ^= 1;
            assert!(
                client::read_record(&altered, 7, n - 1).is_none(),
                "offset {offset}"
            );
        }
        store.delivered(c, n, &wire[64..]).unwrap();
        assert_eq!(
            table
                .admit(c, &read_req, 192, 302, 400, 1, |_| panic!())
                .unwrap(),
            Admission::Replay(reply)
        );
        let mut changed = read_req.clone();
        changed[40] ^= 1;
        assert_eq!(
            table.admit(c, &changed, 192, 2, 400, 1, |_| Ok(())),
            Err(Error::Conflict)
        );
        let ack_req = request(2, seq + 1, next, &digest);
        let Admission::Execute(ticket) = table
            .admit(c, &ack_req, 48, 2, 400, 1, |_| {
                store.check_ack(c, n, &digest).map(|_| ())
            })
            .unwrap()
        else {
            panic!("new ACK must execute")
        };
        let ack = table
            .complete(ticket, State::Done, 0, 1, &[], || {
                store.release(c, n, &digest)
            })
            .unwrap();
        assert!(client::valid_reply(ack.bytes(), 2, seq + 1, 1));
        assert_eq!(
            table
                .admit(c, &ack_req, 48, 301, 400, 1, |_| panic!())
                .unwrap(),
            Admission::Replay(ack)
        );
        assert_eq!(store.released, n);
    }
    assert_eq!(store.read(0), [0; 144]);
    let mut wrong = proofs();
    wrong.swap(1, 2);
    assert!(audit_record::Custody::from_handoffs(7, &wrong).is_none());
}
