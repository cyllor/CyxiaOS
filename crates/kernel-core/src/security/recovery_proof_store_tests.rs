use super::*;
use crate::security::{
    offline_config_v1::{CatalogBindings, SIGNATURE_LABEL},
    recovery_proof_v2::{DegradedEvent, DegradedEventKind, RecoveryAccumulator},
};
use ed25519_dalek::{Signer, SigningKey};

const HOME: u32 = CANONICAL_BUSINESS_START + 1;
const READER: Identity = Identity {
    id: 11,
    generation: 4,
};

fn locator() -> RecoveryLocator {
    RecoveryLocator {
        fs_uuid: [5; 16],
        config_digest: [6; 32],
        inode: 1,
        first_block: HOME,
        inode_generation: 1,
        metadata_digest: [7; 32],
        carrier: [9; 32],
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Io {
    Read(u32),
    Write(u32),
    Flush,
}

struct Disk {
    pending: [[u8; BLOCK]; 2],
    durable: [[u8; BLOCK]; 2],
    trace: [Option<Io>; 24],
    operations: usize,
    fail: Option<Io>,
    persist_failed_flush: bool,
}

impl Disk {
    fn new() -> Self {
        Self {
            pending: [[0; BLOCK]; 2],
            durable: [[0; BLOCK]; 2],
            trace: [None; 24],
            operations: 0,
            fail: None,
            persist_failed_flush: false,
        }
    }

    fn crash(&mut self) {
        self.pending = self.durable;
        self.clear_trace();
        self.fail = None;
        self.persist_failed_flush = false;
    }

    fn clear_trace(&mut self) {
        self.trace.fill(None);
        self.operations = 0;
    }

    fn observe(&mut self, operation: Io) -> Result<(), Error> {
        self.trace[self.operations] = Some(operation);
        self.operations += 1;
        if self.fail == Some(operation) {
            Err(Error::Unknown)
        } else {
            Ok(())
        }
    }
}

impl EpochBlockIo for Disk {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
        self.observe(Io::Read(block))?;
        *out = self.pending[(block - HOME) as usize];
        Ok(())
    }

    fn write(&mut self, block: u32, bytes: &[u8; BLOCK]) -> Result<(), Error> {
        self.observe(Io::Write(block))?;
        self.pending[(block - HOME) as usize] = *bytes;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        let result = self.observe(Io::Flush);
        if result.is_ok() || self.persist_failed_flush {
            self.durable = self.pending;
        }
        result
    }
}

fn bound(disk: &mut Disk, work: &mut Workspace, boot: u64, reader: Identity) -> RecoveryProofStore {
    let mut store = RecoveryProofStore::open_pages(locator(), boot - 1, disk, work).unwrap();
    store.boot = boot;
    store.writer_generation = 1;
    store.reader = Some(reader);
    store
}

fn record(acc: &mut RecoveryAccumulator, seq: u64) -> RecoveryProofV2 {
    acc.record(&DegradedEvent {
        kind: DegradedEventKind::Recovery,
        event_id: seq,
        event_digest: hash(&[&seq.to_le_bytes()]),
        object_id: 2,
        object_generation: 4,
        failure_code: 0x24,
    })
    .unwrap();
    *acc.proof()
}

fn decode_read(payload: [u8; AUDIT_PAYLOAD]) -> (u64, Hash) {
    assert_eq!(&payload[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        &payload[112..],
        &hash(&[b"CYX/AUDIT/v2", &payload[16..112]])
    );
    (u64at(&payload, 8), payload[112..].try_into().unwrap())
}

#[test]
fn delivery_ack_and_boot_takeover_keep_exact_identity() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let mut store = bound(&mut disk, &mut work, 1, READER);
    let proof = record(&mut RecoveryAccumulator::new(1, 0, 1).unwrap(), 1);
    disk.clear_trace();
    store.append(proof, &mut disk, &mut work).unwrap();
    assert_eq!(
        disk.trace[..3],
        [Some(Io::Write(HOME)), Some(Io::Flush), Some(Io::Read(HOME))]
    );
    assert_eq!(store.inventory(), (1, 0));

    disk.crash();
    let prior_reader = READER;
    let reader = Identity {
        generation: 5,
        ..READER
    };
    let mut store = bound(&mut disk, &mut work, 2, reader);
    assert_eq!(
        disk.trace[..4],
        [
            Some(Io::Read(HOME)),
            Some(Io::Read(HOME + 1)),
            Some(Io::Flush),
            Some(Io::Read(HOME))
        ]
    );
    assert_eq!(store.read(prior_reader, 0), Err(Error::Unauthorized));
    let audit = store.read(reader, 0).unwrap();
    assert_eq!(u64at(&audit, 24), 1); // Writer's boot epoch.
    let mut canonical = [0; RECOVERY_PROOF_BYTES];
    proof.encode(&mut canonical);
    assert_eq!(&audit[80..112], &Sha256::digest(canonical)[..]);
    let (seq, digest) = decode_read(audit);
    assert_eq!(
        store.check_ack(reader, seq, digest),
        Err(Error::Unauthorized)
    );
    store.confirm_delivery(reader, seq, digest).unwrap();
    assert_eq!(store.check_ack(reader, seq, [2; 32]), Err(Error::Conflict));
    assert_eq!(store.ack(reader, seq, digest), Err(Error::Busy));
    assert_eq!(store.read(reader, 0).unwrap(), audit);
    assert_eq!(store.persist_ack(&mut disk, &mut work), Ok(Some(seq)));
    assert_eq!(store.ack(reader, seq, digest), Ok(()));
    assert_eq!(store.read(reader, 0).unwrap(), [0; AUDIT_PAYLOAD]);

    disk.crash();
    let mut store = bound(&mut disk, &mut work, 3, reader);
    assert_eq!(store.inventory(), (0, seq));
    assert_eq!(store.ack(reader, seq, digest), Err(Error::Stale));
    assert_eq!(store.append(proof, &mut disk, &mut work), Err(Error::Stale));
}

#[test]
fn same_boot_takeover_keeps_accepted_ack_and_requires_fresh_delivery() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let mut store = bound(&mut disk, &mut work, 1, READER);
    let mut acc = RecoveryAccumulator::new(1, 0, 1).unwrap();
    for seq in 1..=2 {
        store
            .append(record(&mut acc, seq), &mut disk, &mut work)
            .unwrap();
    }
    let (first, first_digest) = decode_read(store.read(READER, 0).unwrap());
    let unread_ack = store.read(READER, first).unwrap();
    let (second, second_digest) = decode_read(unread_ack);
    store.confirm_delivery(READER, first, first_digest).unwrap();
    store
        .confirm_delivery(READER, second, second_digest)
        .unwrap();
    assert_eq!(store.ack(READER, first, first_digest), Err(Error::Busy));

    let next = Identity {
        generation: 5,
        ..READER
    };
    assert_eq!(
        store.replace_reader_confirmed(READER, next.generation),
        Err(Error::Busy)
    );
    store.close_reader(READER).unwrap();
    assert_eq!(store.read(READER, 0), Err(Error::Unauthorized));
    assert_eq!(
        store.confirm_delivery(READER, second, second_digest),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        store.ack(READER, first, first_digest),
        Err(Error::Unauthorized)
    );
    assert_eq!(store.read(next, 0), Err(Error::Unauthorized));
    assert_eq!(
        store.retired_ack_confirmed(READER, first, first_digest),
        Err(Error::Busy)
    );
    assert_eq!(
        store.replace_reader_confirmed(READER, next.generation),
        Err(Error::Busy)
    );

    assert_eq!(store.persist_ack(&mut disk, &mut work), Ok(Some(first)));
    assert_eq!(
        store.retired_ack_confirmed(READER, first, first_digest),
        Ok(())
    );
    assert_eq!(
        store.retired_ack_confirmed(READER, first, second_digest),
        Err(Error::Conflict)
    );
    assert_eq!(
        store.replace_reader_confirmed(READER, next.generation + 1),
        Err(Error::Stale)
    );
    store
        .replace_reader_confirmed(READER, next.generation)
        .unwrap();
    assert_eq!(store.inventory(), (1, first));
    assert_eq!(store.read(READER, first), Err(Error::Unauthorized));
    assert_eq!(store.read(next, 0), Ok(unread_ack));
    assert_eq!(
        store.ack(next, second, second_digest),
        Err(Error::Unauthorized)
    );
    store.confirm_delivery(next, second, second_digest).unwrap();
    assert_eq!(store.ack(next, second, second_digest), Err(Error::Busy));
    assert_eq!(store.persist_ack(&mut disk, &mut work), Ok(Some(second)));
}

#[test]
fn crash_before_ack_flush_retains_last_confirmed_record_and_requires_delivery() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let mut owner = bound(&mut disk, &mut work, 1, READER);
    let proof = record(&mut RecoveryAccumulator::new(1, 0, 1).unwrap(), 1);
    owner.append(proof, &mut disk, &mut work).unwrap();
    let (seq, digest) = decode_read(owner.read(READER, 0).unwrap());
    owner.confirm_delivery(READER, seq, digest).unwrap();
    assert_eq!(owner.ack(READER, seq, digest), Err(Error::Busy));
    disk.fail = Some(Io::Flush);
    assert_eq!(owner.persist_ack(&mut disk, &mut work), Err(Error::Unknown));
    assert_eq!(owner.ack(READER, seq, digest), Err(Error::Unknown));
    assert_eq!(owner.read(READER, 0), Err(Error::Unknown));
    owner.close_reader(READER).unwrap();
    assert_eq!(owner.read(READER, 0), Err(Error::Unauthorized));
    assert_eq!(
        owner.retired_ack_confirmed(READER, seq, digest),
        Err(Error::Unknown)
    );
    assert_eq!(
        owner.replace_reader_confirmed(READER, READER.generation + 1),
        Err(Error::Unknown)
    );
    disk.crash();
    let owner = bound(&mut disk, &mut work, 2, READER);
    assert_eq!(
        owner.check_ack(READER, seq, digest),
        Err(Error::Unauthorized)
    );
    assert_eq!(decode_read(owner.read(READER, 0).unwrap()), (seq, digest));
}

#[test]
fn completed_flush_without_runtime_readback_is_confirmed_only_after_reopen() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let mut owner = bound(&mut disk, &mut work, 1, READER);
    let proof = record(&mut RecoveryAccumulator::new(1, 0, 1).unwrap(), 1);
    owner.append(proof, &mut disk, &mut work).unwrap();
    let (seq, digest) = decode_read(owner.read(READER, 0).unwrap());
    owner.confirm_delivery(READER, seq, digest).unwrap();
    assert_eq!(owner.ack(READER, seq, digest), Err(Error::Busy));
    disk.fail = Some(Io::Read(HOME + 1));
    assert_eq!(owner.persist_ack(&mut disk, &mut work), Err(Error::Unknown));
    assert_eq!(owner.ack(READER, seq, digest), Err(Error::Unknown));

    disk.crash();
    let mut owner = bound(&mut disk, &mut work, 2, READER);
    assert_eq!(owner.inventory(), (0, seq));
    assert_eq!(owner.read(READER, 0).unwrap(), [0; AUDIT_PAYLOAD]);
    assert_eq!(owner.ack(READER, seq, digest), Err(Error::Stale));
}

#[test]
fn full_custody_refuses_overwrite_and_traces_a_new_chain_after_ack() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let mut owner = bound(&mut disk, &mut work, 1, READER);
    let mut acc = RecoveryAccumulator::new(1, 0, 1).unwrap();
    for seq in 1..=RECORDS as u64 {
        disk.clear_trace();
        owner
            .append(record(&mut acc, seq), &mut disk, &mut work)
            .unwrap();
    }
    assert!(!owner.can_append());
    let next = record(&mut acc, RECORDS as u64 + 1);
    assert_eq!(
        owner.append(next, &mut disk, &mut work),
        Err(Error::Capacity)
    );
    let (seq, digest) = decode_read(owner.read(READER, 0).unwrap());
    let (seq2, digest2) = decode_read(owner.read(READER, seq).unwrap());
    owner.confirm_delivery(READER, seq2, digest2).unwrap();
    assert_eq!(owner.ack(READER, seq2, digest2), Err(Error::Stale));
    owner.confirm_delivery(READER, seq, digest).unwrap();
    assert_eq!(owner.ack(READER, seq, digest), Err(Error::Busy));
    assert_eq!(owner.persist_ack(&mut disk, &mut work), Ok(Some(seq)));
    owner.append(next, &mut disk, &mut work).unwrap();
    assert_eq!(owner.inventory(), (RECORDS as u64, seq));
    assert_eq!(owner.ack(READER, seq2, digest2), Err(Error::Busy));
    assert_eq!(owner.persist_ack(&mut disk, &mut work), Ok(Some(seq2)));
}

fn full_store(disk: &mut Disk, work: &mut Workspace) -> (RecoveryProofStore, RecoveryAccumulator) {
    let mut store = bound(disk, work, 1, READER);
    let mut acc = RecoveryAccumulator::new(1, 0, 1).unwrap();
    for count in 1..=RECORDS as u64 {
        disk.clear_trace();
        store.append(record(&mut acc, count), disk, work).unwrap();
    }
    disk.clear_trace();
    (store, acc)
}

fn record_stopped_cpu(boot: u64, cpu: u32) -> RecoveryProofV2 {
    let mut acc = RecoveryAccumulator::new(boot, cpu, 1).unwrap();
    acc.record(&DegradedEvent {
        kind: DegradedEventKind::OtherCritical,
        event_id: 1,
        event_digest: hash(&[&boot.to_le_bytes(), &cpu.to_le_bytes()]),
        object_id: BUSINESS_THREAD_ID_BASE + u64::from(cpu),
        object_generation: boot,
        failure_code: 0x24,
    })
    .unwrap();
    acc.takeover_stopped_writer(boot, cpu, 1, 1).unwrap();
    *acc.proof()
}

fn assert_fifo_saved(
    owner: &RecoveryProofStore,
    reader: Identity,
    expected: &[[u8; AUDIT_PAYLOAD]; RECORDS],
) {
    for (index, frame) in expected.iter().enumerate() {
        assert_eq!(owner.read(reader, index as u64), Ok(*frame));
    }
    assert_eq!(owner.read(reader, RECORDS as u64), Ok([0; AUDIT_PAYLOAD]));
}

fn ack_next(
    owner: &mut RecoveryProofStore,
    reader: Identity,
    disk: &mut Disk,
    work: &mut Workspace,
) -> u64 {
    let (seq, digest) = decode_read(owner.read(reader, 0).unwrap());
    owner.confirm_delivery(reader, seq, digest).unwrap();
    assert_eq!(owner.ack(reader, seq, digest), Err(Error::Busy));
    assert_eq!(owner.persist_ack(disk, work), Ok(Some(seq)));
    seq
}

#[test]
fn full_spill_survives_consumer_takeover_and_cold_reopen_in_order() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let (mut owner, mut acc) = full_store(&mut disk, &mut work);
    let original: [[u8; AUDIT_PAYLOAD]; RECORDS] =
        core::array::from_fn(|index| owner.read(READER, index as u64).unwrap());
    let (seq, digest) = decode_read(original[0]);
    owner.confirm_delivery(READER, seq, digest).unwrap();
    owner.close_reader(READER).unwrap();
    assert!(!owner.audit_status().reader_available);
    assert!(!owner.can_append());
    assert!(owner.can_persist_proof());

    let first = record(&mut acc, 9);
    assert_eq!(
        owner.persist_proof(first, &mut disk, &mut work),
        Ok(ProofPersistence::Deferred)
    );
    assert_eq!(&disk.durable[0][..8], SPILL_PAGE_MAGIC);
    assert_eq!(u64at(&disk.durable[0], WRITER_END), 1);
    assert_eq!(u64at(&disk.durable[0], SPILL_START), 9);
    let business = record_stopped_cpu(1, 2);
    assert_eq!(
        owner.persist_proof(business, &mut disk, &mut work),
        Ok(ProofPersistence::Deferred)
    );
    let newest = record(&mut acc, 10);
    let invalid = RecoveryProofV2 {
        recovery_count: 2,
        ..newest
    };
    assert_eq!(
        owner.persist_proof(invalid, &mut disk, &mut work),
        Err(Error::Conflict)
    );
    assert_eq!(
        owner.persist_proof(newest, &mut disk, &mut work),
        Ok(ProofPersistence::Deferred)
    );
    assert_eq!(owner.audit_status().deferred, 2);
    assert_eq!(owner.audit_status().saturated, 0);
    assert_eq!(owner.promote(&mut disk, &mut work), Ok(None));
    assert_eq!(owner.read(READER, 0), Err(Error::Unauthorized));
    assert_eq!(owner.ack(READER, seq, digest), Err(Error::Unauthorized));

    let next = Identity {
        generation: 5,
        ..READER
    };
    owner
        .replace_reader_confirmed(READER, next.generation)
        .unwrap();
    assert_fifo_saved(&owner, next, &original);
    assert_eq!(owner.ack(next, seq, digest), Err(Error::Unauthorized));

    disk.crash();
    let cold = Identity {
        generation: 6,
        ..READER
    };
    let mut owner = bound(&mut disk, &mut work, 2, cold);
    assert_fifo_saved(&owner, cold, &original);
    assert_eq!(owner.audit_status().deferred, 2);
    assert_eq!(owner.ack(next, seq, digest), Err(Error::Unauthorized));
    assert_eq!(owner.ack(cold, seq, digest), Err(Error::Unauthorized));
    assert_eq!(ack_next(&mut owner, cold, &mut disk, &mut work), seq);
    assert!(owner.can_promote());
    assert!(!owner.can_persist_proof());
    let current = record(&mut RecoveryAccumulator::new(2, 0, 1).unwrap(), 1);
    assert_eq!(
        owner.persist_proof(current, &mut disk, &mut work),
        Err(Error::Busy)
    );
    assert_eq!(owner.promote(&mut disk, &mut work), Ok(Some(9)));
    assert_eq!(owner.read(cold, 8), Ok(audit_payload(9, &newest)));
    assert_eq!(owner.read(cold, 9), Ok([0; AUDIT_PAYLOAD]));
    for index in 1..RECORDS {
        assert_eq!(owner.read(cold, index as u64), Ok(original[index]));
    }
    assert_eq!(ack_next(&mut owner, cold, &mut disk, &mut work), 2);
    assert_eq!(owner.promote(&mut disk, &mut work), Ok(Some(10)));
    assert_eq!(owner.read(cold, 9), Ok(audit_payload(10, &business)));
    assert_eq!(owner.audit_status().deferred, 0);
}

#[test]
fn repeated_boot_saturation_is_sticky_without_replacing_evidence() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let (mut owner, mut acc) = full_store(&mut disk, &mut work);
    let boot1 = record(&mut acc, 9);
    assert_eq!(
        owner.persist_proof(boot1, &mut disk, &mut work),
        Ok(ProofPersistence::Deferred)
    );
    disk.crash();
    let mut owner = bound(&mut disk, &mut work, 2, READER);
    let boot2 = record(&mut RecoveryAccumulator::new(2, 0, 1).unwrap(), 1);
    assert_eq!(
        owner.persist_proof(boot2, &mut disk, &mut work),
        Ok(ProofPersistence::Deferred)
    );
    disk.crash();
    let mut owner = bound(&mut disk, &mut work, 3, READER);
    let mut acc3 = RecoveryAccumulator::new(3, 0, 1).unwrap();
    let proof = record(&mut acc3, 1);
    assert_eq!(
        owner.persist_proof(proof, &mut disk, &mut work),
        Ok(ProofPersistence::Saturated)
    );
    assert_eq!(
        owner.persist_proof(proof, &mut disk, &mut work),
        Err(Error::Conflict)
    );
    assert_eq!(
        owner.persist_proof(record(&mut acc3, 2), &mut disk, &mut work),
        Ok(ProofPersistence::Saturated)
    );
    let business = record_stopped_cpu(3, 3);
    assert_eq!(
        owner.persist_proof(business, &mut disk, &mut work),
        Ok(ProofPersistence::Deferred)
    );
    assert_eq!(
        owner.audit_status(),
        AuditStatus {
            pending: 8,
            retired: 0,
            deferred: 3,
            saturated: 2,
            first_saturated_boot: 3,
            last_saturated_boot: 3,
            saturated_cpu_mask: 1,
            reader_available: true,
            uncertain: false,
        }
    );
    disk.crash();
    let mut owner = bound(&mut disk, &mut work, 4, READER);
    let mut acc4 = RecoveryAccumulator::new(4, 0, 1).unwrap();
    assert_eq!(
        owner.persist_proof(record(&mut acc4, 1), &mut disk, &mut work),
        Ok(ProofPersistence::Saturated)
    );
    assert_eq!(owner.audit_status().first_saturated_boot, 3);
    assert_eq!(owner.audit_status().last_saturated_boot, 4);
    assert_eq!(owner.audit_status().saturated, 3);
    let newest = record(&mut acc4, 2);
    for (sequence, proof) in [(9, boot1), (10, boot2), (11, business), (12, newest)] {
        disk.clear_trace();
        ack_next(&mut owner, READER, &mut disk, &mut work);
        assert_eq!(owner.promote(&mut disk, &mut work), Ok(Some(sequence)));
        assert_eq!(
            owner.read(READER, sequence - 1),
            Ok(audit_payload(sequence, &proof))
        );
        if sequence == 9 {
            assert_eq!(
                owner.persist_proof(newest, &mut disk, &mut work),
                Ok(ProofPersistence::Deferred)
            );
        }
    }
    disk.crash();
    let owner = bound(&mut disk, &mut work, 5, READER);
    assert_eq!(owner.audit_status().deferred, 0);
    assert_eq!(owner.audit_status().saturated, 3);
    assert_eq!(owner.audit_status().first_saturated_boot, 3);
    assert_eq!(owner.audit_status().last_saturated_boot, 4);
}

#[test]
fn spill_write_flush_and_readback_reopen_without_overwriting_the_fifo() {
    for (cut, persist_failed_flush, committed) in SPILL_CUTS {
        let (mut disk, mut work) = (Disk::new(), Workspace::new());
        let (mut owner, mut acc) = full_store(&mut disk, &mut work);
        let original: [[u8; AUDIT_PAYLOAD]; RECORDS] =
            core::array::from_fn(|index| owner.read(READER, index as u64).unwrap());
        disk.fail = Some(cut);
        disk.persist_failed_flush = persist_failed_flush;
        assert_eq!(
            owner.persist_proof(record(&mut acc, 9), &mut disk, &mut work),
            Err(Error::Unknown)
        );
        assert!(owner.audit_status().uncertain);
        assert!(!owner.can_persist_proof());
        assert!(!owner.can_promote());
        assert_eq!(owner.read(READER, 0), Err(Error::Unknown));
        disk.crash();
        let owner = bound(&mut disk, &mut work, 2, READER);
        assert_fifo_saved(&owner, READER, &original);
        assert_eq!(owner.audit_status().deferred, u64::from(committed));
    }
}

const SPILL_CUTS: [(Io, bool, bool); 4] = [
    (Io::Write(HOME), false, false),
    (Io::Flush, false, false),
    (Io::Flush, true, true),
    (Io::Read(HOME), false, true),
];

#[test]
fn promotion_reopen_assigns_at_most_one_sequence() {
    // Generation 9 defers the proof, 10 ACKs an original and 11 promotes.
    for (cut, persist_failed_flush, committed) in SPILL_CUTS {
        let (mut disk, mut work) = (Disk::new(), Workspace::new());
        let (mut owner, mut acc) = full_store(&mut disk, &mut work);
        let proof = record(&mut acc, 9);
        owner.persist_proof(proof, &mut disk, &mut work).unwrap();
        let original_second = owner.read(READER, 1).unwrap();
        assert_eq!(ack_next(&mut owner, READER, &mut disk, &mut work), 1);
        disk.fail = Some(cut);
        disk.persist_failed_flush = persist_failed_flush;
        assert_eq!(owner.promote(&mut disk, &mut work), Err(Error::Unknown));
        disk.crash();
        let mut owner = bound(&mut disk, &mut work, 2, READER);
        assert_eq!(owner.audit_status().retired, 1);
        assert_eq!(owner.read(READER, 0), Ok(original_second));
        if committed {
            assert_eq!(owner.audit_status().deferred, 0);
            assert_eq!(owner.promote(&mut disk, &mut work), Ok(None));
        } else {
            assert_eq!(owner.audit_status().deferred, 1);
            assert_eq!(owner.read(READER, 8), Ok([0; AUDIT_PAYLOAD]));
            assert_eq!(owner.promote(&mut disk, &mut work), Ok(Some(9)));
        }
        assert_eq!(owner.read(READER, 8), Ok(audit_payload(9, &proof)));
        assert_eq!(owner.read(READER, 9), Ok([0; AUDIT_PAYLOAD]));
    }
}

#[test]
fn a_sealed_page_cannot_mount_with_a_reordered_promotion() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let (mut owner, mut acc) = full_store(&mut disk, &mut work);
    let first = record(&mut acc, 9);
    let second = record_stopped_cpu(1, 2);
    owner.persist_proof(first, &mut disk, &mut work).unwrap();
    owner.persist_proof(second, &mut disk, &mut work).unwrap();
    ack_next(&mut owner, READER, &mut disk, &mut work);
    assert_eq!(owner.promote(&mut disk, &mut work), Ok(Some(9)));
    disk.crash();

    // Each proof and the sealed page can decode independently. The paired
    // transition must still enforce the oldest unseen receipt's custody.
    let prior = Page::decode(&disk.durable[0], locator().carrier, 0, 1).unwrap();
    let mut wrong = prior;
    wrong.generation += 1;
    wrong.prior_digest = prior.seal;
    wrong.proofs[wrong.count] = Some(second);
    wrong.count += 1;
    wrong.spill.deferred[2 * SPILL_PER_CPU] = None;
    wrong.encode(locator().carrier, &mut disk.pending[1]);
    assert!(Page::decode(&disk.pending[1], locator().carrier, 1, 1).is_ok());
    assert!(matches!(
        RecoveryProofStore::open_pages(locator(), 1, &mut disk, &mut work),
        Err(Error::Conflict)
    ));
}

#[test]
fn stopped_business_writer_can_be_replayed_without_displacing_cpu0() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let mut owner = bound(&mut disk, &mut work, 1, READER);
    let mut cpu0 = RecoveryAccumulator::new(1, 0, 1).unwrap();
    owner
        .append(record(&mut cpu0, 1), &mut disk, &mut work)
        .unwrap();
    assert!(
        disk.durable[0][WRITER_START + WRITER_BYTES..PAGE_SEAL]
            .iter()
            .all(|&byte| byte == 0)
    );
    let mut cpu2 = RecoveryAccumulator::new(1, 2, 1).unwrap();
    cpu2.record(&DegradedEvent {
        kind: DegradedEventKind::OtherCritical,
        event_id: 1,
        event_digest: [19; 32],
        object_id: 0x102,
        object_generation: 1,
        failure_code: 0x24,
    })
    .unwrap();
    assert!(owner.append(*cpu2.proof(), &mut disk, &mut work).is_err());
    cpu2.takeover_stopped_writer(1, 2, 1, 1).unwrap();
    let foreign = RecoveryProofV2 {
        last_object_id: BUSINESS_THREAD_ID_BASE + 3,
        ..*cpu2.proof()
    };
    assert_eq!(
        owner.append(foreign, &mut disk, &mut work),
        Err(Error::Conflict)
    );
    owner.append(*cpu2.proof(), &mut disk, &mut work).unwrap();
    assert_eq!(
        owner.append(*cpu2.proof(), &mut disk, &mut work),
        Err(Error::Conflict)
    );
    owner
        .append(record(&mut cpu0, 2), &mut disk, &mut work)
        .unwrap();

    disk.crash();
    let reader = Identity {
        generation: 5,
        ..READER
    };
    let mut owner = bound(&mut disk, &mut work, 2, reader);
    assert_eq!(owner.inventory(), (3, 0));
    let (first, digest) = decode_read(owner.read(reader, 0).unwrap());
    let business = owner.read(reader, first).unwrap();
    assert_eq!((u64at(&business, 64), u64at(&business, 72)), (2, 2));
    let mut canonical = [0; RECOVERY_PROOF_BYTES];
    cpu2.proof().encode(&mut canonical);
    assert_eq!(&business[80..112], &Sha256::digest(canonical)[..]);
    owner.confirm_delivery(reader, first, digest).unwrap();
    assert_eq!(owner.ack(reader, first, digest), Err(Error::Busy));
    assert_eq!(owner.persist_ack(&mut disk, &mut work), Ok(Some(first)));
    disk.crash();
    let owner = bound(&mut disk, &mut work, 3, reader);
    assert_eq!(owner.inventory(), (2, first));
    assert_eq!(owner.read(reader, 0).unwrap(), business);
}

#[test]
fn refuses_torn_mirrors_future_writer_and_impossible_pairs() {
    let (mut disk, mut work) = (Disk::new(), Workspace::new());
    let mut owner = bound(&mut disk, &mut work, 1, READER);
    let mut acc = RecoveryAccumulator::new(1, 0, 1).unwrap();
    owner
        .append(record(&mut acc, 1), &mut disk, &mut work)
        .unwrap();
    assert!(matches!(
        RecoveryProofStore::open_pages(locator(), 0, &mut disk, &mut work),
        Err(Error::Conflict)
    ));
    owner
        .append(record(&mut acc, 2), &mut disk, &mut work)
        .unwrap();
    disk.crash();
    disk.pending[1][220] ^= 1;
    assert!(matches!(
        RecoveryProofStore::open_pages(locator(), 1, &mut disk, &mut work),
        Err(Error::Conflict)
    ));
    disk.crash();
    disk.pending[0].fill(0);
    assert!(matches!(
        RecoveryProofStore::open_pages(locator(), 1, &mut disk, &mut work),
        Err(Error::Conflict)
    ));
    disk.crash();
    // Even a freshly sealed page has to link to its actual predecessor.
    let mut invalid = Page::decode(&disk.pending[1], locator().carrier, 1, 1).unwrap();
    invalid.prior_digest = [11; 32];
    invalid.encode(locator().carrier, &mut disk.pending[1]);
    assert!(matches!(
        RecoveryProofStore::open_pages(locator(), 1, &mut disk, &mut work),
        Err(Error::Conflict)
    ));
}

fn signed_config(key: &SigningKey, generation: u64) -> ([u8; 576], CatalogBindings) {
    let mut wire = [0; 576];
    let catalog = CatalogBindings {
        rule_generation: 1,
        security_generation: 1,
        key_generation: 1,
        rule_hash: [2; 32],
        security_hash: [3; 32],
        key_manifest_hash: [4; 32],
    };
    wire[..8].copy_from_slice(&[0x46, 0x4f, 0x59, 0x43, 1, 0, 0, 1]);
    wire[8..12].copy_from_slice(&576u32.to_le_bytes());
    wire[12..16].copy_from_slice(&256u32.to_le_bytes());
    wire[16..32].copy_from_slice(&locator().fs_uuid);
    for (at, value) in [(32, generation), (40, 1), (48, 1), (56, 1)] {
        put64(&mut wire, at, value);
    }
    wire[64..96].copy_from_slice(&catalog.rule_hash);
    wire[96..128].copy_from_slice(&catalog.security_hash);
    wire[128..160].copy_from_slice(&catalog.key_manifest_hash);
    for (i, raw) in wire[256..512].chunks_exact_mut(16).enumerate() {
        put64(raw, 0, i as u64 + 1);
        put64(raw, 8, 1);
    }
    let payload = hash(&[&wire[256..512]]);
    wire[160..192].copy_from_slice(&payload);
    let signature = key.sign(&[SIGNATURE_LABEL, &wire[..512]].concat());
    wire[512..].copy_from_slice(&signature.to_bytes());
    (wire, catalog)
}

#[test]
fn rotated_locator_requires_current_signature_and_preserves_carrier_binding() {
    let key = SigningKey::from_bytes(&[8; 32]);
    let public = key.verifying_key().to_bytes();
    let (previous, bindings) = signed_config(&key, 1);
    let (current, _) = signed_config(&key, 2);
    let mut scratch = [0; 1024];
    let verify_config = |wire, scratch: &mut [u8; 1024]| {
        VerifiedOfflineConfig::verify(wire, &public, bindings, scratch, |_, _, _| Ok(())).unwrap()
    };
    let previous = verify_config(&previous, &mut scratch);
    let current = verify_config(&current, &mut scratch);
    let mut raw = [0; LOCATOR_BYTES];
    raw[..8].copy_from_slice(b"CYXRPF01");
    raw[8..24].copy_from_slice(&previous.header().fs_uuid);
    raw[24..56].copy_from_slice(&previous.digest());
    raw[56..60].copy_from_slice(&locator().inode.to_le_bytes());
    raw[60..64].copy_from_slice(&HOME.to_le_bytes());
    put64(&mut raw, 64, locator().inode_generation);
    raw[72..104].copy_from_slice(&locator().metadata_digest);
    let sign = |raw: &[u8]| {
        key.sign(&[LOCATOR_DOMAIN.as_slice(), raw].concat())
            .to_bytes()
    };
    let sig = sign(&raw);
    let prior = RecoveryLocator::verify(&previous, &public, &raw, &sig)
        .unwrap()
        .unwrap();
    assert!(matches!(
        RecoveryLocator::verify(&current, &public, &raw, &sig),
        Err(Error::Conflict)
    ));
    raw[24..56].copy_from_slice(&current.digest());
    assert!(matches!(
        RecoveryLocator::verify(&current, &public, &raw, &sig),
        Err(Error::Unauthorized)
    ));
    let now = RecoveryLocator::verify(&current, &public, &raw, &sign(&raw))
        .unwrap()
        .unwrap();
    assert!(now.same_carrier(prior));
    raw[60..64].copy_from_slice(&(HOME + 1).to_le_bytes());
    let moved = RecoveryLocator::verify(&current, &public, &raw, &sign(&raw))
        .unwrap()
        .unwrap();
    assert!(!moved.same_carrier(prior));
}
