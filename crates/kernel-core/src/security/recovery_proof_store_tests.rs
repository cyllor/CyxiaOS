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
}

impl Disk {
    fn new() -> Self {
        Self {
            pending: [[0; BLOCK]; 2],
            durable: [[0; BLOCK]; 2],
            trace: [None; 24],
            operations: 0,
            fail: None,
        }
    }

    fn crash(&mut self) {
        self.pending = self.durable;
        self.clear_trace();
        self.fail = None;
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
        self.observe(Io::Flush)?;
        self.durable = self.pending;
        Ok(())
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
