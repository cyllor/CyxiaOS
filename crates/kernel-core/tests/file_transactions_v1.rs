use cyxia_kernel_core::security::{
    Error,
    boot_epoch_v1::{BootEpochStoreV1, TlsBootPolicy},
    epoch_redo_v0199::EpochBlockIo,
    file_admission_flow_v1::FileAdmissionFlowV1,
    file_auth_context_v1::{AdmissionLedgerV1, AuthContextV1, AuthorityFacts},
    file_auth_v3::{AdmitRequestV3, FILE_SERVICE_ROLE, Verdict},
    file_format_v1::{self, FormatManifest, FormatWorkspace},
    file_fsync_v1::{FsyncJob, FsyncProgress, FsyncWorkspace, commit_segment_with_floor},
    file_media_unified_v1::{
        ACL_INODE, BOOT_INODE, CANONICAL_BUSINESS_START, RECEIPTS_INODE, SECURITY_INODE,
    },
    file_media_v0199::{
        BLOCK_COUNT, DATA_START, FileReceiptV4, INODE_START, RECEIPT_BYTES, SuperblockV1,
        crc32c_zeroed,
    },
    file_mount_v1::{MountEvidence, Workspace as MountWorkspace, validate_signed},
    file_receipt_query_v4::{ReceiptKey, ReceiptQueryCaller},
    file_service_v4::{
        REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION,
        transactions::{
            NamespaceJob, NamespaceProgress, NamespaceStaging, Object, Owner, Workspace,
            ack_ticket, allocate_ticket, bind_stream, commit_namespace,
        },
    },
    file_structure_v1::{BLOCK, INODE_BYTES, Inode, SystemKind, SystemObject},
    offline_config_v1::{CatalogBindings, MAX_SIGNED_BYTES, VerifiedOfflineConfig},
    recovery_v1::{RecoveryWorkspace, RedoImage, RedoWriter, recover_checkpoint, scan},
};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    path::Path,
};

const FIXTURE_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const CONFIG: &[u8] = include_bytes!("../../../tests/fixtures/v020-signed-scratch/config.bin");
const ROOT: u32 = CANONICAL_BUSINESS_START;
const BOOT: u32 = DATA_START;
const ACL: u32 = DATA_START + 8;
const SECURITY: u32 = DATA_START + 12;
const TRAVERSE: u64 = 1 << 14;
const CREATE: u64 = 1 << 10;
const REMOVE: u64 = 1 << 11;
const FILE_RIGHTS: u32 = (1 << 8) | (1 << 9) | (1 << 13);
const DIR_RIGHTS: u32 = (TRAVERSE | CREATE | REMOVE | (1 << 12)) as u32;
const CAP: u64 = 51;
const FILE_BYTES: &[u8] = b"SEC-F ordinary transactions survive the durable COMMIT boundary.\n";

const OBJECTS: [SystemObject; 4] = [
    SystemObject {
        kind: SystemKind::BootEpoch,
        inode: BOOT_INODE,
        generation: 1,
        first_block: BOOT,
    },
    SystemObject {
        kind: SystemKind::Receipts,
        inode: RECEIPTS_INODE,
        generation: 1,
        first_block: DATA_START + 1,
    },
    SystemObject {
        kind: SystemKind::Acl,
        inode: ACL_INODE,
        generation: 1,
        first_block: ACL,
    },
    SystemObject {
        kind: SystemKind::Security,
        inode: SECURITY_INODE,
        generation: 1,
        first_block: SECURITY,
    },
];

type Pages = BTreeMap<u32, Box<[u8; BLOCK]>>;

#[derive(Clone, Default)]
struct PowerDisk {
    durable: Pages,
    volatile: Pages,
    flushes_left: Option<usize>,
}

impl EpochBlockIo for PowerDisk {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
        *out = self
            .volatile
            .get(&block)
            .or_else(|| self.durable.get(&block))
            .map_or([0; BLOCK], |page| **page);
        Ok(())
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK]) -> Result<(), Error> {
        self.volatile.insert(block, Box::new(*data));
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        if let Some(left) = self.flushes_left.as_mut() {
            if *left == 0 {
                return Err(Error::Unknown);
            }
            *left -= 1;
        }
        self.durable.append(&mut self.volatile);
        Ok(())
    }
}

impl PowerDisk {
    fn cut(&mut self) {
        self.volatile.clear();
        self.flushes_left = None;
    }

    fn export(&self, path: &Path) {
        assert!(self.volatile.is_empty());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.set_len(u64::from(BLOCK_COUNT) * BLOCK as u64).unwrap();
        for (&block, page) in &self.durable {
            if page.iter().all(|&value| value == 0) {
                continue;
            }
            file.seek(SeekFrom::Start(u64::from(block) * BLOCK as u64))
                .unwrap();
            file.write_all(page.as_ref()).unwrap();
        }
        file.sync_all().unwrap();
    }
}

fn check_policy(wire: &[u8]) -> VerifiedOfflineConfig<'_> {
    let u64at = |at: usize| u64::from_le_bytes(wire[at..at + 8].try_into().unwrap());
    let digest = |at: usize| wire[at..at + 32].try_into().unwrap();
    let catalog = CatalogBindings {
        rule_generation: u64at(40),
        security_generation: u64at(48),
        key_generation: u64at(56),
        rule_hash: digest(64),
        security_hash: digest(96),
        key_manifest_hash: digest(128),
    };
    VerifiedOfflineConfig::verify(
        wire,
        &FIXTURE_KEY,
        catalog,
        &mut vec![0; MAX_SIGNED_BYTES],
        |header, _, lists| {
            if header.mode != 0 || header.clear_isolation_bitmap != 0 || lists != [0; 12] {
                return Err(Error::Unauthorized);
            }
            Ok(())
        },
    )
    .unwrap()
}

fn initialize(config: &VerifiedOfflineConfig<'_>) -> (PowerDisk, SuperblockV1, MountEvidence) {
    let policy = TlsBootPolicy::new(config, None).unwrap();
    let mut disk = PowerDisk::default();
    let manifest = FormatManifest {
        fs_uuid: config.header().fs_uuid,
        root_block: ROOT,
        system: OBJECTS,
        principals: *config.principals(),
        security: policy.resident_state(0).unwrap(),
    };
    let initial = file_format_v1::format(
        &mut disk,
        BLOCK_COUNT,
        &manifest,
        &mut FormatWorkspace::new(),
    )
    .unwrap();
    // The test's independently admitted root FileCap has ordinary namespace
    // rights. Keep the formatter's traverse-only default for other volumes.
    let root_acl = &mut disk.durable.get_mut(&ACL).unwrap()[..64];
    root_acl[32..36].copy_from_slice(&DIR_RIGHTS.to_le_bytes());
    let crc = crc32c_zeroed(root_acl, 60).unwrap();
    root_acl[60..].copy_from_slice(&crc.to_le_bytes());

    let mut journal = Box::new(RecoveryWorkspace::new());
    let sb = initial.superblock;
    let mut writer = RedoWriter::open(&mut disk, &mut journal, sb).unwrap();
    let boot = BootEpochStoreV1 {
        fs_uuid: sb.fs_uuid,
        boot_epoch: 1,
    }
    .encode()
    .unwrap();
    let state = policy.resident_state(1).unwrap().encode().unwrap();
    writer
        .append(
            writer.prepare(2).unwrap(),
            &[
                RedoImage {
                    home: SECURITY,
                    contents: &state,
                },
                RedoImage {
                    home: BOOT,
                    contents: &boot,
                },
            ],
            |_| Ok(()),
        )
        .unwrap();
    let mounted = mount(&mut writer.committed_view(), sb, config);
    assert_eq!(mounted.boot.boot_epoch, 1);
    (disk, sb, mounted)
}

fn mount(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    config: &VerifiedOfflineConfig<'_>,
) -> MountEvidence {
    validate_signed(
        io,
        sb,
        &OBJECTS,
        config,
        &mut Box::new(MountWorkspace::new()),
        |_, _, _| Ok(()),
    )
    .unwrap()
}

fn frame(op: u16, request_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0; REQUEST_HEADER];
    out[..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&(REQUEST_HEADER as u16).to_le_bytes());
    out[8..10].copy_from_slice(&op.to_le_bytes());
    out[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[16..24].copy_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn admit(
    owner: &Owner<'_>,
    key: ReceiptKey,
    object: Object,
    rights: u64,
    frame: &[u8],
    data: &[u8],
) -> (FileAdmissionFlowV1, AdmissionLedgerV1) {
    let ctx = AuthContextV1::new(
        17,
        owner.config.principals()[0].id,
        FILE_SERVICE_ROLE,
        1,
        owner.mounted.boot.boot_epoch,
    )
    .unwrap();
    let proposal = AdmitRequestV3 {
        auth_context_id: 0,
        target_id: u64::from(object.inode),
        target_generation: object.generation,
        required_rights: rights,
        request_seq: key.request_seq,
        prepared_version: 0,
        acl_generation: object.acl_generation,
        frozen_data_digest: [0; 32],
        operation_digest: [0; 32],
    };
    let mut admission = FileAdmissionFlowV1::freeze(ctx, frame, CAP, proposal, 0, data).unwrap();
    let mut ledger = AdmissionLedgerV1::new(ctx.boot_epoch).unwrap();
    admission
        .admit(
            &mut ledger,
            &AuthorityFacts {
                current_generation: 1,
                verdict: Verdict::Admitted,
                deny_generation: 0,
                accepted_local_ns: 1,
            },
        )
        .unwrap();
    admission.execute(&mut ledger, 1, true).unwrap();
    (admission, ledger)
}

fn issue(
    writer: &mut RedoWriter<'_, PowerDisk>,
    owner: &Owner<'_>,
    work: &mut Workspace,
    stream: u8,
) -> ReceiptKey {
    let caller = ReceiptQueryCaller {
        principal_id: owner.config.principals()[0].id,
        boot_epoch: owner.mounted.boot.boot_epoch,
        service_generation: 1,
    };
    assert!(
        bind_stream(writer, owner, work, caller, stream, |_| Ok(()))
            .unwrap()
            .is_some()
    );
    assert!(
        bind_stream(writer, owner, work, caller, stream, |_| unreachable!())
            .unwrap()
            .is_none()
    );
    let mut payload = [0; 16];
    payload[0] = stream;
    payload[8..].copy_from_slice(&1u64.to_le_bytes());
    let frame = frame(10, 0, &payload);
    let issued = allocate_ticket(writer, owner, work, caller, &frame, |_| Ok(())).unwrap();
    assert!(issued.issued.is_some());
    let replay = allocate_ticket(writer, owner, work, caller, &frame, |_| unreachable!()).unwrap();
    assert_eq!(replay.key, issued.key);
    assert!(replay.issued.is_none());
    issued.key
}

fn edit(
    writer: &mut RedoWriter<'_, PowerDisk>,
    owner: &Owner<'_>,
    work: &mut Workspace,
    parent: Object,
    op: u16,
    stream: u8,
    name: &[u8],
) -> Object {
    let key = issue(writer, owner, work, stream);
    let mut payload = (name.len() as u16).to_le_bytes().to_vec();
    payload.extend_from_slice(name);
    let rights = match op {
        7 => DIR_RIGHTS,
        1 => FILE_RIGHTS,
        _ => 0,
    };
    if op != 9 {
        payload.extend_from_slice(&rights.to_le_bytes());
    }
    payload.extend_from_slice(&[0; 4]);
    let frame = frame(op, key.request_id().unwrap(), &payload);
    let (admission, ledger) = admit(
        owner,
        key,
        parent,
        TRAVERSE | if op == 9 { REMOVE } else { CREATE },
        &frame,
        &[],
    );
    let job = NamespaceJob {
        admission: &admission,
        ledger: &ledger,
        cap_selector: CAP,
        frame: &frame,
        key,
        allocation_floor: ROOT,
    };
    let mut staged = NamespaceStaging::new();
    assert!(matches!(
        commit_namespace(
            writer,
            owner,
            &job,
            work,
            &mut staged,
            |_| Ok(()),
            |_| Ok(())
        )
        .unwrap(),
        NamespaceProgress::Bound(_)
    ));
    if op == 9 {
        assert!(matches!(
            commit_namespace(
                writer,
                owner,
                &job,
                work,
                &mut staged,
                |_| Err(Error::Busy),
                |_| unreachable!()
            ),
            Err(Error::Busy)
        ));
    }
    let NamespaceProgress::Committed {
        object,
        receipt,
        redo,
    } = commit_namespace(
        writer,
        owner,
        &job,
        work,
        &mut staged,
        |_| Ok(()),
        |_| Ok(()),
    )
    .unwrap()
    else {
        panic!("no namespace effect")
    };
    assert_eq!(receipt.commit_lsn, redo.transaction().commit_lsn);
    assert!(
        matches!(commit_namespace(writer, owner, &job, work, &mut staged, |_| unreachable!(), |_| unreachable!()).unwrap(), NamespaceProgress::AlreadyDone(r) if r == receipt)
    );
    object
}

fn stage_file(
    disk: &mut PowerDisk,
    sb: SuperblockV1,
    owner: &Owner<'_>,
) -> (Object, Object, ReceiptKey) {
    let mut journal = Box::new(RecoveryWorkspace::new());
    let mut writer = RedoWriter::open(disk, &mut journal, sb).unwrap();
    let work = &mut Box::new(Workspace::new());
    let dir = edit(
        &mut writer,
        owner,
        work,
        Object {
            inode: 0,
            generation: 1,
            acl_generation: 1,
        },
        7,
        0,
        b"project",
    );
    let file = edit(&mut writer, owner, work, dir, 1, 1, b"notes.txt");
    let key = issue(&mut writer, owner, work, 2);
    (dir, file, key)
}

fn fsync(
    disk: &mut PowerDisk,
    sb: SuperblockV1,
    owner: &Owner<'_>,
    file: Object,
    key: ReceiptKey,
    bind: bool,
) -> Result<(), Error> {
    let frame = frame(5, key.request_id().unwrap(), &1u64.to_le_bytes());
    let mut page = [0; BLOCK];
    page[..FILE_BYTES.len()].copy_from_slice(FILE_BYTES);
    let mut frozen = (FILE_BYTES.len() as u64).to_le_bytes().to_vec();
    frozen.extend_from_slice(&page);
    let (admission, ledger) = admit(owner, key, file, 1 << 13, &frame, &frozen);
    let job = FsyncJob {
        config: owner.config,
        mounted: owner.mounted,
        admission: &admission,
        ledger: &ledger,
        inode_id: file.inode,
        cap_selector: CAP,
        frame: &frame,
        key,
        grown_size: Some(FILE_BYTES.len()),
        pages: &[&page],
    };
    let mut journal = Box::new(RecoveryWorkspace::new());
    let mut writer = RedoWriter::open(disk, &mut journal, sb)?;
    let mut work = Box::new(FsyncWorkspace::new());
    let FsyncProgress::Committed { receipt, .. } =
        commit_segment_with_floor(&mut writer, &job, &mut work, ROOT, |_| Ok(()))?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(receipt.status, if bind { 2 } else { 3 });
    Ok(())
}

fn owner<'a>(config: &'a VerifiedOfflineConfig<'a>, mounted: &'a MountEvidence) -> Owner<'a> {
    Owner {
        config,
        mounted,
        service_generation: 1,
        protected_inode: None,
    }
}

fn verify_file(disk: &mut PowerDisk, file: Object, expected: bool) {
    let mut page = [0; BLOCK];
    let inode_offset = usize::from(file.inode) * INODE_BYTES;
    disk.read(INODE_START + (inode_offset / BLOCK) as u32, &mut page)
        .unwrap();
    let offset = inode_offset % BLOCK;
    let inode = Inode::decode(&page[offset..offset + INODE_BYTES]).unwrap();
    assert_eq!(
        inode.size,
        if expected { FILE_BYTES.len() as u64 } else { 0 }
    );
    assert_eq!(inode.durable_write_seq, u64::from(expected));
    if expected {
        disk.read(inode.runs[0].physical, &mut page).unwrap();
        assert_eq!(&page[..FILE_BYTES.len()], FILE_BYTES);
        assert!(page[FILE_BYTES.len()..].iter().all(|&byte| byte == 0));
    }
}

fn cases(config: &VerifiedOfflineConfig<'_>, export: Option<&Path>) {
    let (mut disk, sb, mounted) = initialize(config);
    let owner = owner(config, &mounted);
    let (dir, file, key) = stage_file(&mut disk, sb, &owner);
    fsync(&mut disk, sb, &owner, file, key, true).unwrap();
    for (name, n, complete) in [
        ("before-prepare-flush", 0, false),
        ("before-commit-flush", 1, false),
        ("committed", 2, true),
    ] {
        let mut case = disk.clone();
        case.flushes_left = Some(n);
        let result = fsync(&mut case, sb, &owner, file, key, false);
        if complete {
            result.unwrap();
        } else {
            assert_eq!(result, Err(Error::Unknown));
        }
        case.cut();
        if let Some(path) = export {
            case.export(&path.join(format!("{name}.raw")));
        }
        let mut journal = Box::new(RecoveryWorkspace::new());
        let scanned = scan(&mut case, &mut journal).unwrap();
        assert_eq!(scanned.incomplete_tail, n == 1);
        let checkpoint = recover_checkpoint(&mut case, &mut journal, |view, mounted_sb| {
            assert_eq!(
                mount(view, mounted_sb, config).structure.directory_entries,
                2
            );
            verify_file(view, file, complete);
            Ok(())
        })
        .unwrap();
        assert_eq!(checkpoint.checkpoint_lsn, scanned.last_commit_lsn);
        if complete {
            if let Some(path) = export {
                case.export(&path.join("checkpointed-before-retire.raw"));
            }
            let mut home_cut = disk.clone();
            fsync(&mut home_cut, sb, &owner, file, key, false).unwrap();
            // The home batch reaches durable media, the new superblock does not.
            home_cut.flushes_left = Some(1);
            let mut journal = Box::new(RecoveryWorkspace::new());
            assert_eq!(
                recover_checkpoint(&mut home_cut, &mut journal, |view, _| {
                    verify_file(view, file, true);
                    Ok(())
                }),
                Err(Error::Unknown)
            );
            home_cut.cut();
            if let Some(path) = export {
                home_cut.export(&path.join("homes-before-checkpoint.raw"));
            }
            recover_checkpoint(&mut home_cut, &mut journal, |view, _| {
                verify_file(view, file, true);
                Ok(())
            })
            .unwrap();
        }
    }
    fsync(&mut disk, sb, &owner, file, key, false).unwrap();
    let mut journal = Box::new(RecoveryWorkspace::new());
    let mut writer = RedoWriter::open(&mut disk, &mut journal, sb).unwrap();
    let mut work = Box::new(Workspace::new());
    let removed = edit(&mut writer, &owner, &mut work, dir, 9, 3, b"notes.txt");
    let recreated = edit(&mut writer, &owner, &mut work, dir, 1, 4, b"notes.txt");
    assert_eq!(removed.inode, recreated.inode);
    assert_eq!(removed.generation + 1, recreated.generation);
    let mut page = [0; BLOCK];
    writer.read_committed(BOOT + 1, &mut page).unwrap();
    let receipt = page
        .chunks_exact(RECEIPT_BYTES)
        .filter_map(|raw| FileReceiptV4::decode(raw).ok())
        .find(|row| row.stream_slot == 4 && row.request_seq == 1)
        .unwrap();
    let key = ReceiptKey {
        stream_slot: 4,
        ..key
    };
    let caller = ReceiptQueryCaller {
        principal_id: config.principals()[0].id,
        boot_epoch: 1,
        service_generation: 1,
    };
    let mut payload = key.encode().to_vec();
    payload.extend_from_slice(&receipt.output_digest);
    let frame = frame(12, key.request_id().unwrap(), &payload);
    let before = writer.evidence().unwrap();
    assert!(matches!(
        ack_ticket(
            &mut writer,
            &owner,
            &mut work,
            caller,
            &frame,
            |_, _| Err(Error::Unknown),
            |_| unreachable!()
        ),
        Err(Error::Unknown)
    ));
    assert_eq!(writer.evidence(), Some(before));
    ack_ticket(
        &mut writer,
        &owner,
        &mut work,
        caller,
        &frame,
        |writer, record| {
            assert_eq!(*record, receipt);
            let mut raw = [0; BLOCK];
            writer.read_committed_at_transaction(
                BOOT + 1,
                record.commit_lsn,
                record.txid,
                &mut raw,
            )?;
            assert_eq!(raw, page);
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert!(matches!(
        ack_ticket(
            &mut writer,
            &owner,
            &mut work,
            caller,
            &frame,
            |_, _| unreachable!(),
            |_| unreachable!()
        ),
        Err(Error::Stale)
    ));
    assert_eq!(
        mount(&mut writer.committed_view(), sb, config)
            .structure
            .directory_entries,
        2
    );
}

#[test]
fn ordinary_namespace_and_fsync_across_power_cuts() {
    cases(&check_policy(CONFIG), None);
}

#[test]
#[ignore = "writes disposable cold-start inputs to an explicitly supplied directory"]
fn export_native_power_cases() {
    let catalog = std::env::var_os("CYX_SEC_F_TEST_CATALOG").unwrap();
    let output = std::env::var_os("CYX_SEC_F_TEST_OUTPUT").unwrap();
    let wire = std::fs::read(Path::new(&catalog).join("offline-config.bin")).unwrap();
    let output = Path::new(&output);
    std::fs::create_dir(output).unwrap();
    cases(&check_policy(&wire), Some(output));
}
