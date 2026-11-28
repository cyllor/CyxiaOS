use std::collections::BTreeMap;

use cyxia_kernel_core::{
    control_plane::Identity,
    security::{
        Error,
        epoch_redo_v0199::EpochBlockIo,
        file_media_unified_v1::{
            BITMAP_START, BLOCK_COUNT, DATA_START, INODE_START, SNAP_CAP_CREATE,
            SNAP_CAP_HISTORY_READ, SNAP_CAP_PROTECTION, SNAP_OP_CREATE, SNAP_OP_OPEN_WRITES,
            SNAP_OP_RESTORE, SNAPSHOT_PROTECTION_BLOCK, SNAPSHOT_REQUEST_START, SUPER_BYTES,
            SnapshotEnrollment, SuperblockV1,
            protection_candidate::{ProtectionRecord, RestorePhase},
        },
        file_media_v0199::crc32c_zeroed,
        recovery_v1::{RecoveryWorkspace, RedoImage, RedoWriter, recover_checkpoint},
        snapshot_read_v4::history_prefix_digest,
        snapshot_request_store_v1::{
            MAINTENANCE_RECORDS, ORDINARY_RECORDS, RECORD_BYTES, RECORDS, RECOVERY_RECORDS,
            RequestRecord, RequestState, RequestStoreHeader, Watermark, inspect_request_store,
            record_location, record_partition, verify_request_store,
        },
        snapshot_service_v4::{
            CallBinding, RequestError, SnapshotGrant, SnapshotRequest, decode_reply, encode_reply,
        },
    },
};

const UUID: [u8; 16] = *b"CYX-D7-WIRE-0001";
const VECTORS: &str = include_str!("../../../tools/fixtures/v020-g1-snapshot-wire.tsv");

#[derive(Debug)]
struct Vector {
    name: &'static str,
    kind: &'static str,
    context: &'static str,
    verdict: &'static str,
    bytes: Vec<u8>,
}

fn vectors() -> Vec<Vector> {
    VECTORS
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            let [name, kind, context, verdict, digits] = fields[..] else {
                panic!("bad fixture row {line:?}");
            };
            assert_eq!(digits.len() % 2, 0);
            let bytes = (0..digits.len())
                .step_by(2)
                .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
                .collect();
            Vector {
                name,
                kind,
                context,
                verdict,
                bytes,
            }
        })
        .collect()
}

fn named<'a>(vectors: &'a [Vector], name: &str) -> &'a [u8] {
    &vectors.iter().find(|row| row.name == name).unwrap().bytes
}

#[test]
fn rust_and_independent_reference_match_all_requests_and_replies() {
    let vectors = vectors();
    let mut requests = BTreeMap::new();
    let mut operations = Vec::new();
    for vector in &vectors {
        if vector.kind == "request" {
            let selector = vector.context.parse::<u64>().unwrap();
            let result = SnapshotRequest::decode(&vector.bytes, selector);
            match vector.verdict {
                "accept" => {
                    let request =
                        result.unwrap_or_else(|error| panic!("{}: {error:?}", vector.name));
                    let mut encoded = [0; 1024];
                    let n = request.encode(selector, &mut encoded).unwrap();
                    assert_eq!(&encoded[..n], vector.bytes, "{}", vector.name);
                    requests.insert(vector.name, request);
                    operations.push(request.op);
                }
                "schema" => assert_eq!(result, Err(RequestError::Schema), "{}", vector.name),
                "selector" => assert_eq!(result, Err(RequestError::Selector), "{}", vector.name),
                "invalid" => assert_eq!(result, Err(RequestError::Format), "{}", vector.name),
                _ => unreachable!(),
            }
        } else if vector.kind == "reply" {
            let request = requests.get(vector.context).unwrap();
            let result = decode_reply(request, &vector.bytes);
            if vector.verdict == "accept" {
                let reply = result.unwrap_or_else(|error| panic!("{}: {error:?}", vector.name));
                let mut encoded = [0; 2048];
                let n = encode_reply(request, &reply, &mut encoded).unwrap();
                assert_eq!(&encoded[..n], vector.bytes, "{}", vector.name);
            } else {
                assert!(result.is_err(), "{}", vector.name);
            }
        }
    }
    operations.sort_unstable();
    operations.dedup();
    assert_eq!(operations, (0x20..=0x2b).collect::<Vec<_>>());
}

#[test]
fn independently_encoded_media_records_round_trip_and_reject_resealed_contradictions() {
    let vectors = vectors();
    let mut states = Vec::new();
    for vector in &vectors {
        match (vector.kind, vector.verdict) {
            ("record", "accept") => {
                let record = RequestRecord::decode(&vector.bytes).unwrap();
                let mut encoded = [0; RECORD_BYTES];
                record.encode(&mut encoded).unwrap();
                assert_eq!(encoded.as_slice(), vector.bytes, "{}", vector.name);
                states.push(record.state as u32);
            }
            ("record", "invalid") => {
                assert!(
                    RequestRecord::decode(&vector.bytes).is_err(),
                    "{}",
                    vector.name
                );
            }
            ("header", "accept") if vector.name != "genesis-header" => {
                let encoded = vector.bytes.as_slice().try_into().unwrap();
                let header = RequestStoreHeader::decode(encoded).unwrap().unwrap();
                assert_eq!(header.fs_uuid, UUID);
                assert_eq!(header.generation, 9);
                assert_eq!(header.watermarks[14], Watermark::EMPTY);
                let mut out = [0; SUPER_BYTES];
                header.encode(&mut out).unwrap();
                assert_eq!(out, *encoded);
            }
            ("header", "accept") => {
                assert_eq!(
                    RequestStoreHeader::decode(vector.bytes.as_slice().try_into().unwrap()),
                    Ok(None)
                );
            }
            ("header", "invalid") => {
                assert!(
                    RequestStoreHeader::decode(vector.bytes.as_slice().try_into().unwrap())
                        .is_err(),
                    "{}",
                    vector.name
                );
            }
            _ => {}
        }
    }
    states.sort_unstable();
    states.dedup();
    assert_eq!(states, vec![1, 2, 3, 4, 5]);
    let create = SnapshotRequest::decode(named(&vectors, "create"), 73).unwrap();
    let pending = RequestRecord::pending(&create).unwrap();
    let mut encoded = [0; RECORD_BYTES];
    pending.encode(&mut encoded).unwrap();
    assert_eq!(encoded, named(&vectors, "pending"));
}

struct Volume(Vec<[u8; SUPER_BYTES]>);

impl Volume {
    fn from_header(raw: &[u8]) -> Self {
        let mut pages = vec![[0; SUPER_BYTES]; 16];
        pages[0].copy_from_slice(raw);
        Self(pages)
    }

    fn put(&mut self, index: usize, record: &[u8]) {
        let (block, range) = record_location(index).unwrap();
        self.0[(block - SNAPSHOT_REQUEST_START) as usize][range].copy_from_slice(record);
    }

    fn read(&self, block: u32, out: &mut [u8; SUPER_BYTES]) -> Result<(), Error> {
        *out = self.0[(block - SNAPSHOT_REQUEST_START) as usize];
        Ok(())
    }
}

#[test]
fn all_sixteen_pages_enforce_partitions_watermarks_keys_commit_boundary_and_reserved_space() {
    let vectors = vectors();
    let mut media = Volume::from_header(named(&vectors, "header"));
    let pending = named(&vectors, "pending");
    let restore = named(&vectors, "restored");
    let open = named(&vectors, "opened");
    let unknown = named(&vectors, "unknown");
    media.put(0, pending);
    media.put(1, unknown);
    media.put(56, restore);
    media.put(57, open);
    let mut commits = Vec::new();
    let result = inspect_request_store(
        UUID,
        9,
        107,
        |block, page| media.read(block, page),
        |record| {
            if record.state.terminal() {
                commits.push(record.commit_lsn);
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(commits, [101, 107]);
    assert_eq!(
        (result.generation, result.occupied, result.nonterminal),
        (9, 4, 2)
    );
    assert_eq!(
        verify_request_store(UUID, 9, 106, |block, page| media.read(block, page)),
        Err(Error::Conflict),
    );
    assert_eq!(
        verify_request_store(UUID, 8, 107, |block, page| media.read(block, page)),
        Err(Error::Conflict),
    );
    media.put(48, pending);
    assert_eq!(
        verify_request_store(UUID, 9, 107, |block, page| media.read(block, page)),
        Err(Error::Conflict),
    );
    media.put(48, &[0; RECORD_BYTES]);
    media.put(28, pending);
    assert_eq!(
        verify_request_store(UUID, 9, 107, |block, page| media.read(block, page)),
        Err(Error::Conflict),
    );
    media.put(28, &[0; RECORD_BYTES]);
    media.0[15][4095] = 1;
    assert_eq!(
        verify_request_store(UUID, 9, 107, |block, page| media.read(block, page)),
        Err(Error::Conflict),
    );
    let mut empty = Volume::from_header(named(&vectors, "genesis-header"));
    let evidence = verify_request_store(UUID, 1, 0, |b, p| empty.read(b, p)).unwrap();
    assert_eq!((evidence.occupied, evidence.nonterminal), (0, 0));
    empty.put(0, pending);
    assert_eq!(
        verify_request_store(UUID, 1, 107, |block, page| empty.read(block, page)),
        Err(Error::Conflict),
    );
}

#[test]
fn full_request_store_retains_each_partition_and_rejects_cross_class_reuse() {
    let vectors = vectors();
    let mut raw_header: [u8; SUPER_BYTES] = named(&vectors, "header").try_into().unwrap();
    let mut header = RequestStoreHeader::decode(&raw_header).unwrap().unwrap();
    let classes = [
        (0, ORDINARY_RECORDS),
        (14, MAINTENANCE_RECORDS),
        (15, RECOVERY_RECORDS),
    ];
    for (slot, capacity) in classes {
        header.watermarks[slot as usize] = Watermark {
            client_generation: 1,
            highest_accepted_seq: capacity as u64,
        };
    }
    header.encode(&mut raw_header).unwrap();
    let mut media = Volume::from_header(&raw_header);
    let mut template = RequestRecord::decode(named(&vectors, "pending")).unwrap();
    template.state = RequestState::Failed;
    template.result_code = -5;
    template.log_epoch = 1;
    template.replace_payload(&[]).unwrap();
    let mut outcomes = Vec::new();
    for (slot, capacity) in classes {
        let partition = record_partition(slot).unwrap();
        assert_eq!(partition.len(), capacity);
        for (sequence, index) in (1u64..).zip(partition.clone()) {
            let mut terminal = template;
            terminal.key.client_slot = slot;
            terminal.key.client_generation = 1;
            terminal.key.request_seq = sequence;
            terminal.txid = index as u64 + 1;
            terminal.commit_lsn = terminal.txid;
            terminal.seal_result().unwrap();
            let mut raw = [0; RECORD_BYTES];
            terminal.encode(&mut raw).unwrap();
            media.put(index, &raw);
            outcomes.push(terminal);
        }
        let evidence =
            verify_request_store(UUID, header.generation, RECORDS as u64, |block, page| {
                media.read(block, page)
            })
            .unwrap();
        assert_eq!(evidence.occupied, partition.end);
        assert_eq!(evidence.nonterminal, 0);
    }
    assert_eq!(outcomes.len(), RECORDS);
    assert_eq!(record_location(RECORDS), Err(Error::Invalid));
    let mut found = Vec::new();
    inspect_request_store(
        UUID,
        header.generation,
        RECORDS as u64,
        |block, page| media.read(block, page),
        |record| {
            found.push(*record);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(found, outcomes);

    let mut raw = [0; RECORD_BYTES];
    outcomes[0].encode(&mut raw).unwrap();
    media.put(0, &[0; RECORD_BYTES]);
    media.put(RECORDS - RECOVERY_RECORDS, &raw);
    assert_eq!(
        verify_request_store(UUID, header.generation, RECORDS as u64, |block, page| {
            media.read(block, page)
        }),
        Err(Error::Conflict)
    );
}

#[test]
fn terminal_ack_and_retry_cannot_replace_an_unknown_effect_or_reissue_a_key() {
    let vectors = vectors();
    let restore = SnapshotRequest::decode(named(&vectors, "restore"), 73).unwrap();
    let pending = RequestRecord::pending(&restore).unwrap();
    let done = RequestRecord::decode(named(&vectors, "restored")).unwrap();
    let incomplete = RequestRecord::decode(named(&vectors, "incomplete")).unwrap();
    let mut unknown = pending;
    unknown.state = RequestState::Unknown;
    unknown.result_code = -6;
    unknown.log_epoch = done.log_epoch;
    unknown.txid = done.txid;
    assert_eq!(pending.permits_transition(&unknown), Ok(()));
    assert_eq!(unknown.permits_transition(&done), Ok(()));
    assert_eq!(done.permits_transition(&done), Ok(()));
    assert_eq!(unknown.permits_transition(&pending), Err(Error::Stale));
    assert_eq!(done.permits_transition(&incomplete), Err(Error::Stale));
    assert_eq!(unknown.permits_ack(unknown.key, [0; 32]), Err(Error::Busy));
    assert_eq!(done.permits_ack(done.key, [0; 32]), Err(Error::Conflict));
    assert_eq!(done.permits_ack(done.key, done.result_digest), Ok(()));
    let mut other = unknown;
    other.txid += 1;
    assert_eq!(other.permits_transition(&done), Err(Error::Conflict));
    let mark = Watermark {
        client_generation: done.key.client_generation,
        highest_accepted_seq: 3,
    };
    let after = mark.next(done.key).unwrap();
    assert_eq!(after.highest_accepted_seq, 4);
    assert_eq!(after.next(done.key), Err(Error::Conflict));
}

#[test]
fn protected_admission_uses_real_holder_endpoint_epoch_and_separate_capability_word() {
    let vectors = vectors();
    let create = SnapshotRequest::decode(named(&vectors, "create"), 73).unwrap();
    let reader = SnapshotRequest::decode(named(&vectors, "history"), 73).unwrap();
    let restore = SnapshotRequest::decode(named(&vectors, "restore"), 73).unwrap();
    let opens = SnapshotRequest::decode(named(&vectors, "open"), 73).unwrap();
    let query = SnapshotRequest::decode(named(&vectors, "request-query"), 0).unwrap();
    assert_eq!(
        (create.op, restore.op, opens.op),
        (SNAP_OP_CREATE, SNAP_OP_RESTORE, SNAP_OP_OPEN_WRITES)
    );
    let call = CallBinding {
        holder: Identity {
            id: 7,
            generation: 4,
        },
        boot_epoch: 8,
        service_generation: 11,
        endpoint: 53,
        selector: 73,
        fs_uuid: UUID,
    };
    let prefix = "/团队".as_bytes();
    let grant = SnapshotGrant {
        binding: call,
        enrollment: SnapshotEnrollment::Ordinary,
        capability_word: SNAP_CAP_CREATE | SNAP_CAP_HISTORY_READ,
        principal: Some((1, 4)),
        history_prefix_sha256: Some(history_prefix_digest(prefix)),
    };
    assert_eq!(create.verify_grant(call, grant, b""), Ok(()));
    assert_eq!(reader.verify_grant(call, grant, prefix), Ok(()));
    assert_eq!(
        reader.verify_grant(call, grant, b"/"),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        create.verify_grant(
            CallBinding {
                holder: Identity {
                    generation: 5,
                    ..call.holder
                },
                ..call
            },
            grant,
            b""
        ),
        Err(Error::Stale),
    );
    assert_eq!(
        create.verify_grant(
            CallBinding {
                endpoint: 54,
                ..call
            },
            grant,
            b""
        ),
        Err(Error::Unauthorized),
    );
    assert_eq!(
        opens.verify_grant(
            call,
            SnapshotGrant {
                capability_word: SNAP_CAP_PROTECTION,
                ..grant
            },
            b""
        ),
        Err(Error::Unauthorized),
    );
    assert_eq!(create.verify_new_mutation(3, 9), Err(Error::Stale));
    assert_eq!(opens.verify_new_mutation(3, 8), Err(Error::Stale));
    assert_eq!(opens.verify_new_mutation(3, 9), Ok(()));
    assert_eq!(
        query.verify_request_access(UUID, Some((15, 2)), false),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        query.verify_request_access(UUID, Some((15, 3)), false),
        Ok(())
    );
    assert_eq!(query.verify_request_access(UUID, None, true), Ok(()));
}

/// Test disk with a volatile cache. A cut loses all writes since the last
/// completed FLUSH by construction. A failed acknowledgement can also follow
/// successful persistence, exercised independently below.
#[derive(Clone, Default)]
struct CutDisk {
    stable: BTreeMap<u32, [u8; SUPER_BYTES]>,
    volatile: BTreeMap<u32, [u8; SUPER_BYTES]>,
    remaining: Option<usize>,
    lose_flush_ack: Option<usize>,
    flushes: usize,
}

impl CutDisk {
    fn tick(&mut self) -> Result<(), Error> {
        if let Some(remaining) = self.remaining.as_mut() {
            *remaining = remaining.checked_sub(1).ok_or(Error::Unknown)?;
        }
        Ok(())
    }

    fn power_cut(&mut self) {
        self.volatile.clear();
        self.remaining = None;
        self.lose_flush_ack = None;
        self.flushes = 0;
    }
}

impl EpochBlockIo for CutDisk {
    fn read(&mut self, block: u32, out: &mut [u8; SUPER_BYTES]) -> Result<(), Error> {
        *out = self
            .volatile
            .get(&block)
            .or_else(|| self.stable.get(&block))
            .copied()
            .unwrap_or([0; SUPER_BYTES]);
        Ok(())
    }

    fn write(&mut self, block: u32, bytes: &[u8; SUPER_BYTES]) -> Result<(), Error> {
        self.tick()?;
        self.volatile.insert(block, *bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.tick()?;
        self.stable.append(&mut self.volatile);
        self.flushes += 1;
        if self.lose_flush_ack == Some(self.flushes) {
            return Err(Error::Unknown);
        }
        Ok(())
    }
}

fn frozen_volume(
    vectors: &[Vector],
) -> (CutDisk, SuperblockV1, RequestStoreHeader, ProtectionRecord) {
    let mut disk = CutDisk::default();
    let mut s = [0; SUPER_BYTES];
    for (offset, value) in [
        (0, 0x4359_4653u32),
        (8, SUPER_BYTES as u32),
        (12, BLOCK_COUNT),
        (56, BITMAP_START),
        (60, INODE_START),
        (64, DATA_START),
        (68, 256),
    ] {
        s[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    s[4..6].copy_from_slice(&1u16.to_le_bytes());
    s[6..8].copy_from_slice(&80u16.to_le_bytes());
    s[16..32].copy_from_slice(&UUID);
    for (offset, value) in [(32, 1u64), (40, 101), (48, 9)] {
        s[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    let crc = crc32c_zeroed(&s, 76).unwrap();
    s[76..80].copy_from_slice(&crc.to_le_bytes());
    let sb = SuperblockV1::decode(&s).unwrap();
    disk.stable.insert(0, s);
    disk.stable.insert(1, s);
    let mut header = RequestStoreHeader::decode(named(vectors, "header").try_into().unwrap())
        .unwrap()
        .unwrap();
    header.watermarks[15].highest_accepted_seq = 4;
    header.encode(&mut s).unwrap();
    disk.stable.insert(SNAPSHOT_REQUEST_START, s);
    let raw_restore = named(vectors, "restored");
    let restore = RequestRecord::decode(raw_restore).unwrap();
    let (home, range) = record_location(56).unwrap();
    s.fill(0);
    s[range].copy_from_slice(raw_restore);
    disk.stable.insert(home, s);
    let p = ProtectionRecord {
        fs_uuid: UUID,
        object_generation: 3,
        protection_generation: 9,
        live_view_epoch: 3,
        online_age_ns: 100,
        retention_deadlines: [0; 8],
        writes_open: false,
        restore_phase: RestorePhase::RestoredFrozen,
        cleanup_frozen: false,
        reopen_proof_digest: [0; 32],
        restore_obligation_digest: restore.result_digest,
    };
    p.encode(&mut s).unwrap();
    disk.stable.insert(SNAPSHOT_PROTECTION_BLOCK, s);
    (disk, sb, header, p)
}

fn append_open_admission(
    disk: &mut CutDisk,
    sb: SuperblockV1,
    mut header: RequestStoreHeader,
    pending: RequestRecord,
) -> Result<(), Error> {
    let mut work = RecoveryWorkspace::new();
    let mut writer = RedoWriter::open(disk, &mut work, sb)?;
    header.generation += 1;
    header.watermarks[15] = header.watermarks[15].next(pending.key)?;
    let mut head = [0; SUPER_BYTES];
    header.encode(&mut head)?;
    let mut page = [0; SUPER_BYTES];
    let (home, range) = record_location(57)?;
    writer.read_committed(home, &mut page)?;
    pending.encode((&mut page[range]).try_into().unwrap())?;
    writer.append(
        writer.prepare(2)?,
        &[
            RedoImage {
                home: SNAPSHOT_REQUEST_START,
                contents: &head,
            },
            RedoImage {
                home,
                contents: &page,
            },
        ],
        |_| Ok(()),
    )?;
    Ok(())
}

fn append_open_effect(
    disk: &mut CutDisk,
    sb: SuperblockV1,
    mut protection: ProtectionRecord,
    pending: RequestRecord,
) -> Result<(), Error> {
    let mut work = RecoveryWorkspace::new();
    let mut writer = RedoWriter::open(disk, &mut work, sb)?;
    let plan = writer.prepare(2)?;
    let mut terminal = pending;
    terminal.state = RequestState::Done;
    terminal.new_live_view_epoch = protection.live_view_epoch;
    terminal.log_epoch = plan.log_epoch;
    terminal.txid = plan.txid;
    terminal.commit_lsn = plan.commit_lsn;
    protection.protection_generation += 1;
    protection.object_generation += 1;
    let mut output = [0; 16];
    output[..8].copy_from_slice(&protection.protection_generation.to_le_bytes());
    terminal.replace_payload(&output)?;
    terminal.seal_result()?;
    pending.permits_transition(&terminal)?;
    protection.writes_open = true;
    protection.restore_phase = RestorePhase::Idle;
    protection.restore_obligation_digest = [0; 32];
    protection.reopen_proof_digest = terminal.result_digest;
    let mut p = [0; SUPER_BYTES];
    protection.encode(&mut p)?;
    let mut page = [0; SUPER_BYTES];
    let (home, range) = record_location(57)?;
    writer.read_committed(home, &mut page)?;
    terminal.encode((&mut page[range]).try_into().unwrap())?;
    writer.append(
        plan,
        &[
            RedoImage {
                home,
                contents: &page,
            },
            RedoImage {
                home: SNAPSHOT_PROTECTION_BLOCK,
                contents: &p,
            },
        ],
        |_| Ok(()),
    )?;
    Ok(())
}

fn check_recovered_open(
    disk: &mut CutDisk,
    admitted: bool,
    opened: bool,
) -> Result<SuperblockV1, Error> {
    let generation = if admitted { 10 } else { 9 };
    let commit_lsn = 101 + 4 * u64::from(admitted) + 4 * u64::from(opened);
    let mut recovery = RecoveryWorkspace::new();
    let next = recover_checkpoint(disk, &mut recovery, |disk, _| {
        let mut page = [0; SUPER_BYTES];
        disk.read(SNAPSHOT_REQUEST_START, &mut page)?;
        let header = RequestStoreHeader::decode(&page)?.ok_or(Error::Conflict)?;
        assert_eq!(
            header.watermarks[15].highest_accepted_seq,
            if admitted { 5 } else { 4 }
        );
        disk.read(SNAPSHOT_PROTECTION_BLOCK, &mut page)?;
        let p = ProtectionRecord::decode(&page)?;
        assert_eq!(p.writes_open, opened);
        let mut matching_open_commit = false;
        let evidence = inspect_request_store(
            UUID,
            generation,
            commit_lsn,
            |block, page| disk.read(block, page),
            |row| {
                if row.operation == SNAP_OP_OPEN_WRITES {
                    assert_eq!(
                        row.state,
                        if opened {
                            RequestState::Done
                        } else {
                            RequestState::Pending
                        }
                    );
                    if opened {
                        matching_open_commit = row.result_digest == p.reopen_proof_digest
                            && row.commit_lsn == commit_lsn
                            && row.new_live_view_epoch == p.live_view_epoch;
                    }
                } else {
                    assert_eq!(row.operation, SNAP_OP_RESTORE);
                    assert_eq!(row.state, RequestState::Done);
                }
                Ok(())
            },
        )?;
        assert_eq!(matching_open_commit, opened);
        assert_eq!(evidence.occupied, if admitted { 2 } else { 1 });
        assert_eq!(evidence.nonterminal, usize::from(admitted && !opened));
        Ok(())
    })?;
    assert_eq!(next.checkpoint_lsn, commit_lsn);
    Ok(next)
}

#[test]
fn power_cuts_keep_watermark_admission_and_reopen_protection_in_their_redo_closures() {
    let vectors = vectors();
    let request = SnapshotRequest::decode(named(&vectors, "open"), 73).unwrap();
    let pending = RequestRecord::pending(&request).unwrap();
    let (base, sb, header, protection) = frozen_volume(&vectors);

    // Two images require BEGIN + four redo blocks + pre-commit FLUSH +
    // COMMIT + its FLUSH. Reopen after every number of completed operations.
    for completed in 0..=8 {
        let mut disk = base.clone();
        disk.remaining = Some(completed);
        assert_eq!(
            append_open_admission(&mut disk, sb, header, pending).is_ok(),
            completed == 8
        );
        disk.power_cut();
        check_recovered_open(&mut disk, completed == 8, false).unwrap();
    }
    let mut admitted = base;
    append_open_admission(&mut admitted, sb, header, pending).unwrap();
    admitted.power_cut();
    for completed in 0..=8 {
        let mut disk = admitted.clone();
        disk.remaining = Some(completed);
        assert_eq!(
            append_open_effect(&mut disk, sb, protection, pending).is_ok(),
            completed == 8
        );
        disk.power_cut();
        check_recovered_open(&mut disk, true, completed == 8).unwrap();
    }
    let mut uncertain = admitted.clone();
    uncertain.lose_flush_ack = Some(2);
    assert_eq!(
        append_open_effect(&mut uncertain, sb, protection, pending),
        Err(Error::Unknown)
    );
    uncertain.power_cut();
    check_recovered_open(&mut uncertain, true, true).unwrap();

    append_open_effect(&mut admitted, sb, protection, pending).unwrap();
    admitted.power_cut();
    // Three distinct committed homes, their FLUSH, and the alternating
    // superblock write and FLUSH. Every cut allows an exact restart.
    for completed in 0..=6 {
        let mut disk = admitted.clone();
        disk.remaining = Some(completed);
        assert_eq!(
            check_recovered_open(&mut disk, true, true).is_ok(),
            completed == 6
        );
        disk.power_cut();
        check_recovered_open(&mut disk, true, true).unwrap();
    }
}
