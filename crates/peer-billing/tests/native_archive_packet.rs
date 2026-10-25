//! The production archive packet copier preserves actual authenticated bytes.
//! Keys, clock values and publication metadata below are explicit host fixtures.
use cyxia_peer_billing::*;
use cyxia_prototype::{
    domains::{Error as DomainError, ObjectKey},
    learning::{
        Family, ReplayGroup,
        capture::RunKey,
        reward::{CpuCoverage, OBSERVATION_NS},
    },
    policy::{PlanId, Snapshot},
};
use ed25519_dalek::SigningKey;

#[path = "../../../kernel/src/learning_replay/archive_packet.rs"]
mod archive_packet;

fn pair() -> (Keys, Keys) {
    let a = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
    let b = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    (
        Keys::new(&[1; 32], &a, &b).unwrap(),
        Keys::new(&[2; 32], &b, &a).unwrap(),
    )
}
fn binding() -> Binding {
    Binding {
        origin: Endpoint {
            node: [3; 32],
            boot: 4,
        },
        participant: Endpoint {
            node: [5; 32],
            boot: 6,
        },
        session: [7; 32],
        run: RunKey {
            boot_epoch: 4,
            trial_id: 8,
            generation: 9,
        },
        family: Family {
            domain: 10,
            kind: 1,
        },
        baseline: false,
        owner: ObjectKey {
            id: 11,
            generation: 1,
        },
        target: ObjectKey {
            id: 10,
            generation: 1,
        },
        group: ReplayGroup {
            seed: 81,
            workload: [12; 32],
            initial_image: [13; 32],
        },
        frozen_scope_hash: [14; 32],
    }
}
fn failure() -> Failure {
    Failure {
        root_token: 17,
        error: DomainError::Busy as u64 + 1,
        observed_ns: 450,
        publication: Some(FailedPublication {
            id: PlanId {
                boot_epoch: 6,
                controller_epoch: 3,
                plan_seq: 8,
            },
            snapshot: Snapshot {
                sequence: 10,
                taken_ns: 300,
                ledger_generation: 7,
                core_generation: 3,
            },
            target: binding().target,
            plan_hash: [88; 32],
            received_ns: 400,
            observed_ns: 450,
            wall_deadline_ns: 500,
        }),
    }
}
fn archived(packet: &[u8]) -> Vec<u8> {
    let padded = archive_packet::padded(packet.len()).unwrap();
    assert_eq!(padded, 768);
    let mut storage = vec![0xc7; padded + 64];
    for offset in (0..padded).step_by(archive_packet::CHUNK) {
        let mut chunk = [0xa5; archive_packet::CHUNK];
        let n = archive_packet::chunk(packet.len(), offset, &mut chunk, |offset, out| {
            let n = out.len().min(packet.len() - offset);
            out[..n].copy_from_slice(&packet[offset..offset + n]);
            Ok(n)
        })
        .unwrap();
        storage[offset..offset + n].copy_from_slice(&chunk[..n]);
    }
    assert_eq!(&storage[..packet.len()], packet);
    assert!(storage[packet.len()..padded].iter().all(|v| *v == 0));
    assert!(
        storage[padded..].iter().all(|v| *v == 0xc7),
        "next archive row was overwritten"
    );
    storage.truncate(packet.len());
    storage
}

#[test]
fn signed_negative_packets_over_512_bytes_survive_archiving_and_verify_again() {
    let (reader, writer) = pair();
    let binding = binding();
    let closing = 1_000_000_001 + OBSERVATION_NS;
    let excluded = ExcludedSeal {
        trace: TraceSeal {
            binding_hash: binding.hash().unwrap(),
            owner: binding.owner,
            coverage: CpuCoverage {
                node: binding.participant.node,
                first_ns: 100,
                observation_ns: 1_000_000_000,
                observation_end_ns: 1_000_000_000 + OBSERVATION_NS,
                closing_ns: closing,
                required: 3,
                reported: 0,
            },
            count: 0,
            intervals_hash: [21; 32],
            frozen_other_domains: [22; 32],
            missing_events: 0,
            ordinary_warmup_ns: 0,
            later_workload_ns: 0,
        },
        exclusion: Exclusion {
            reasons: ROOT_FAULT,
            drained_ns: closing,
            failure: Some(failure()),
        },
    };
    let header = Header {
        kind: EXCLUDED,
        sequence: 20,
        source: binding.participant,
        destination: binding.origin,
        session: binding.session,
    };
    let mut body = [0; EXCLUDED_BYTES];
    excluded.encode(&mut body).unwrap();
    let mut packet = [0; PACKET_BYTES];
    let len = writer.encode(header, &body, &mut packet).unwrap();
    assert_eq!(len, EXCLUDED_PACKET_BYTES);
    assert!(len > 512);
    let restored = archived(&packet[..len]);
    let authenticated = reader
        .decode(
            &restored,
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    assert_eq!(ExcludedSeal::decode(authenticated.body), Ok(excluded));
    assert!(
        TraceSeal::decode(&authenticated.body[..SEAL_BYTES]).is_err(),
        "negative evidence became a positive seal"
    );

    let prepared = PreparationSeal {
        binding,
        drained_ns: closing,
        frozen_other_domains: [22; 32],
        prior_sealed_binding: [0; 32],
        failure: Some(failure()),
    };
    let mut body = [0; PREPARATION_SEAL_BYTES];
    prepared.encode(&mut body).unwrap();
    let len = writer
        .encode(
            Header {
                kind: PREPARED_ABORTED,
                sequence: 21,
                ..header
            },
            &body,
            &mut packet,
        )
        .unwrap();
    assert_eq!(len, PREPARATION_PACKET_BYTES);
    assert!(len > 512);
    let mut restored = archived(&packet[..len]);
    let authenticated = reader
        .decode(
            &restored,
            binding.participant.node,
            binding.origin,
            Some(binding.session),
        )
        .unwrap();
    assert_eq!(PreparationSeal::decode(authenticated.body), Ok(prepared));
    restored[len - 1] ^= 1;
    assert!(matches!(
        reader.decode(
            &restored,
            binding.participant.node,
            binding.origin,
            Some(binding.session)
        ),
        Err(Error::Signature)
    ));
}

#[test]
fn archive_requires_exact_retained_chunk_and_preserves_transient_failure() {
    let len = EXCLUDED_PACKET_BYTES;
    let mut out = [0xa5; archive_packet::CHUNK];
    assert_eq!(
        archive_packet::chunk(len, 256, &mut out, |_, _| Err(DomainError::Busy)),
        Err(DomainError::Busy)
    );
    let last = len - 512;
    assert!(last > 0 && last < archive_packet::CHUNK);
    assert_eq!(
        archive_packet::chunk(len, 512, &mut out, |_, _| Ok(last - 1)),
        Err(DomainError::Stale)
    );
    assert_eq!(
        archive_packet::chunk(len, 512, &mut out, |_, _| Ok(last + 1)),
        Err(DomainError::Stale)
    );
    assert_eq!(
        archive_packet::chunk(len, 512, &mut out, |_, bytes| {
            bytes.fill(0x55);
            Ok(last)
        }),
        Ok(archive_packet::CHUNK)
    );
    assert!(out[..last].iter().all(|v| *v == 0x55));
    assert!(out[last..].iter().all(|v| *v == 0));
    assert_eq!(
        archive_packet::chunk(len, 768, &mut out, |_, _| panic!(
            "copied after signed data"
        )),
        Err(DomainError::Range)
    );
    assert_eq!(
        archive_packet::padded(PACKET_BYTES + 1),
        Err(DomainError::Capacity)
    );
}
