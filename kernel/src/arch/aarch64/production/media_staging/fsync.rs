//! One sealed native baseline-v1 FSYNC diagnostic. CPU0 owns the device,
//! signed test policy and frozen input after the other cores have stopped.
//! Cold reopen exports a verified read-only receipt view to its qualified
//! native client. Only the staging owner accesses the device.

use super::super::file_durable::{ALLOC, Client, FSYNC};
use super::{
    Disk, StagedReceiptQuery, authority, reopen, report, signed,
    volume::{self, RECEIPTS_HOME, SnapshotLayout},
};
use cyxia_kernel_core::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_admission_flow_v1::FileAdmissionFlowV1,
    file_auth_context_v1::{AdmissionLedgerV1, AuthContextIssuerV1, AuthorityFacts},
    file_auth_v3::{AdmitRequestV3, FILE_SERVICE_ROLE, TerminalState, Verdict},
    file_format_v1::{
        SCRATCH_FILE_BLOCK, SCRATCH_FILE_FSYNC_RIGHTS, SCRATCH_FILE_GENERATION, SCRATCH_FILE_INODE,
    },
    file_fsync_v1::{FsyncJob, FsyncProgress, FsyncWorkspace, commit_segment},
    file_index_v0199::{BLOCK_BYTES as BLOCK, FileStreamIndexV4, SecurityStateStoreV2},
    file_media_v0199::{
        BITMAP_START, FileReceiptV4, INODE_START, RECEIPT_BYTES, SuperblockV1, crc32c_zeroed,
    },
    file_mount_v1::MountEvidence,
    file_read_v4::StagedFile,
    file_receipt_query_v4::{
        MountedReceiptQuery, RECEIPT_KEY_BYTES, ReceiptKey, ReceiptQueryCaller,
        encode_receipt_reply,
    },
    file_receipt_store_v0199::RECEIPT_STORE_BYTES,
    file_service_v4::{REPLY_HEADER, REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION, Request},
    file_structure_v1::{INODE_BYTES, Inode},
    offline_config_v1::VerifiedOfflineConfig,
    recovery_v1::{
        RedoImage, RedoTransaction, RedoWriter, recover_checkpoint_with_evidence,
        retire_checkpointed_log,
    },
};
use sha2::{Digest, Sha256};

const FILE_BYTES: &[u8; 29] = b"CyxiaOS V0.20 durable fsync!\n";
const WRITE_SEQ: u64 = 7;
const TEST_CAP: u64 = 1;
const SLOT: usize = 21;
const RECEIPT_AT: usize = SLOT * RECEIPT_BYTES;
const ISSUE_START: u32 = 8;
const BIND_START: u32 = 16;
const FINAL_START: u32 = 24;
const LOG_END: u32 = 36;
const LEGACY_LOG_END: u32 = 32;
pub(super) const FINAL_LSN: u64 = 21;
pub(super) const LEGACY_FINAL_LSN: u64 = 19;
const KEY: ReceiptKey = ReceiptKey {
    fs_uuid: volume::UUID,
    issued_boot_epoch: 1,
    group_id: 0,
    group_generation: 1,
    stream_slot: 0,
    stream_generation: 1,
    request_seq: 1,
};
const REQUEST_ID: u64 = 0x0100_0000_0000_0001;

#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut WORK: FsyncWorkspace = FsyncWorkspace::new();
#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut RECEIPTS: [u8; RECEIPT_STORE_BYTES] = [0; RECEIPT_STORE_BYTES];

fn request_header(raw: &mut [u8], op: u16, id: u64) {
    let length = (raw.len() - REQUEST_HEADER) as u32;
    raw[..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
    raw[4..6].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
    raw[6..8].copy_from_slice(&(REQUEST_HEADER as u16).to_le_bytes());
    raw[8..10].copy_from_slice(&op.to_le_bytes());
    raw[12..16].copy_from_slice(&length.to_le_bytes());
    raw[16..24].copy_from_slice(&id.to_le_bytes());
}

fn frozen_file() -> [u8; BLOCK] {
    let mut bytes = [0; BLOCK];
    bytes[..FILE_BYTES.len()].copy_from_slice(FILE_BYTES);
    bytes
}

fn fsync_frame() -> [u8; REQUEST_HEADER + 8] {
    let mut raw = [0; REQUEST_HEADER + 8];
    request_header(&mut raw, 5, REQUEST_ID);
    raw[REQUEST_HEADER..].copy_from_slice(&WRITE_SEQ.to_le_bytes());
    raw
}

fn freeze(
    issuer: &mut AuthContextIssuerV1,
    frame: &[u8],
    cap_selector: u64,
    data: &[u8],
) -> Result<FileAdmissionFlowV1, Error> {
    FileAdmissionFlowV1::begin(
        issuer,
        1,
        FILE_SERVICE_ROLE,
        frame,
        cap_selector,
        AdmitRequestV3 {
            auth_context_id: 0,
            target_id: u64::from(SCRATCH_FILE_INODE),
            target_generation: SCRATCH_FILE_GENERATION,
            required_rights: u64::from(SCRATCH_FILE_FSYNC_RIGHTS),
            request_seq: 1,
            prepared_version: 0,
            acl_generation: 1,
            frozen_data_digest: [0; 32],
            operation_digest: [0; 32],
        },
        0,
        data,
    )
}

fn issued_receipt() -> FileReceiptV4 {
    FileReceiptV4 {
        fs_uuid: KEY.fs_uuid,
        issued_boot_epoch: KEY.issued_boot_epoch,
        group_id: KEY.group_id,
        group_generation: KEY.group_generation,
        stream_slot: KEY.stream_slot,
        stream_generation: KEY.stream_generation,
        request_seq: KEY.request_seq,
        log_epoch: 0,
        txid: 0,
        commit_lsn: 0,
        write_seq: 0,
        status: 1,
        result: 0,
        completed_prefix: 0,
        operation_digest: [0; 32],
        output_digest: [0; 32],
        request_id: REQUEST_ID,
        owner_principal_id: 1,
    }
}

fn issued_index(raw: &mut [u8; BLOCK]) -> Result<(), Error> {
    let mut index = FileStreamIndexV4::decode(raw)?;
    if index.fs_uuid != volume::UUID
        || index.generation != 1
        || index.global_request_id_hi != 0
        || index.groups.iter().any(|g| g.flags != 0)
        || index.streams.iter().any(|s| s.flags != 0)
    {
        return Err(Error::Conflict);
    }
    index.generation = 2;
    index.groups[0].flags = 1;
    index.groups[0].generation = 1;
    index.groups[0].boot_epoch = 1;
    index.streams[0].flags = 1;
    index.streams[0].generation = 1;
    index.streams[0].issued_hi = 1;
    index.encode_into(raw)
}

fn reserve(
    plan: &RedoTransaction,
    start: u32,
    blocks: u32,
    txid: u64,
    lsn: u64,
) -> Result<(), Error> {
    if plan.fs_uuid == volume::UUID
        && plan.log_epoch == 1
        && plan.txid == txid
        && plan.first_log_block == start
        && plan.log_blocks == blocks
        && plan.commit_lsn == lsn
    {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

fn issue(
    writer: &mut RedoWriter<'_, Disk>,
    image: &mut [u8; RECEIPT_STORE_BYTES],
    frame: &[u8],
) -> Result<(), Error> {
    let request = Request::decode(frame, 0)?;
    if request.op != 10
        || u64::from(request.payload[0]) != KEY.stream_slot
        || u64::from_le_bytes(request.payload[8..].try_into().unwrap()) != KEY.request_seq
    {
        return Err(Error::Unauthorized);
    }
    let mut index = [0; BLOCK];
    writer.read_committed(RECEIPTS_HOME + 6, &mut index)?;
    issued_index(&mut index)?;
    image.fill(0);
    image[RECEIPT_AT..RECEIPT_AT + RECEIPT_BYTES].copy_from_slice(&issued_receipt().encode()?);
    let plan = writer.prepare(3)?;
    writer.append(
        plan,
        &[
            RedoImage {
                home: RECEIPTS_HOME,
                contents: image[..BLOCK].try_into().unwrap(),
            },
            RedoImage {
                home: RECEIPTS_HOME + 1,
                contents: image[BLOCK..2 * BLOCK].try_into().unwrap(),
            },
            RedoImage {
                home: RECEIPTS_HOME + 6,
                contents: &index,
            },
        ],
        |p| reserve(p, ISSUE_START, 8, 2, 9),
    )?;
    Ok(())
}

/// Execute through the same FSYNC owner as the host tests, over native
/// actual WRITE/FLUSH and journal readback. The homes remain checkpoint-old
/// until an independently started second guest replays the authenticated log.
pub(super) fn execute(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    mounted: &MountEvidence,
    config: &VerifiedOfflineConfig<'_>,
    committed: &SecurityStateStoreV2,
    mut client: Client<'_>,
) -> Result<(), Error> {
    config.check_committed(committed)?;
    if checkpoint.generation != 1
        || committed.last_boot_epoch != 1
        || config.principals()[0].id != 1
        || config.principals()[0].generation != 1
        || KEY.request_id() != Some(REQUEST_ID)
    {
        return Err(Error::Unauthorized);
    }
    // SAFETY: the one-shot CPU0 staging owner is the only borrower. Private
    // role packages already reside in their own pages before staging.
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(super::super::COPY_BUFFER.0) };
    let principal = signed::fsync_client_principal(config, scratch)?;
    let file = volume::read_scratch_file(
        disk,
        &mut [0; BLOCK],
        SnapshotLayout::BaselineFsyncFile,
        principal,
    )?;
    let caller = receipt_caller(principal.id, committed)?;
    let file = StagedFile::new_with_owner_rights(
        committed.last_boot_epoch,
        file.acl.principal,
        file.dirent,
        file.data,
        file.acl.owner_rights,
    )?;
    client.start(file, KEY, WRITE_SEQ);
    let allocation = client.request(ALLOC);
    // SAFETY: CPU0 is the sole synchronous staging owner. No other native
    // service or role can borrow these scratch workspaces.
    let workspace = unsafe { reopen::workspace() };
    let work = unsafe { &mut *core::ptr::addr_of_mut!(WORK) };
    let receipt_image = unsafe { &mut *core::ptr::addr_of_mut!(RECEIPTS) };
    let mut writer = RedoWriter::open(disk, workspace, checkpoint)?;
    issue(&mut writer, receipt_image, allocation.bytes())?;
    let issued = issued_receipt();
    let mut reply = [0; REPLY_HEADER + RECEIPT_KEY_BYTES];
    reply[..REPLY_HEADER].copy_from_slice(&encode_receipt_reply(caller, issued));
    reply[36..40].copy_from_slice(&(RECEIPT_KEY_BYTES as u32).to_le_bytes());
    reply[REPLY_HEADER..].copy_from_slice(&issued.encode()?[8..8 + RECEIPT_KEY_BYTES]);
    client.publish(ALLOC, &reply);

    let request = client.request(FSYNC);
    let mut data = [0; BLOCK];
    client.freeze(request, WRITE_SEQ, &mut data)?;
    if data != frozen_file() {
        // This scratch profile has one pinned data image and readback
        // specification. An unrelated write version cannot reach redo.
        return Err(Error::Unauthorized);
    }
    let mut issuer = AuthContextIssuerV1::new(1)?;
    let mut flow = freeze(&mut issuer, request.bytes(), request.selector, &data)?;
    let mut ledger = AdmissionLedgerV1::new(1)?;
    flow.admit(
        &mut ledger,
        &AuthorityFacts {
            current_generation: issuer.current_generation(1).ok_or(Error::Unauthorized)?,
            verdict: Verdict::Admitted,
            deny_generation: 0,
            accepted_local_ns: super::super::now_ns(),
        },
    )?;
    flow.execute(&mut ledger, flow.request().prepared_version, true)?;
    let pages = [&data];
    let job = FsyncJob {
        config,
        mounted,
        admission: &flow,
        ledger: &ledger,
        inode_id: SCRATCH_FILE_INODE as u16,
        cap_selector: request.selector,
        frame: request.bytes(),
        key: KEY,
        pages: &pages,
    };
    let FsyncProgress::Committed { receipt: bound, .. } =
        commit_segment(&mut writer, &job, work, |p| {
            reserve(p, BIND_START, 8, 3, 14)
        })?
    else {
        return Err(Error::Conflict);
    };
    if bound.status != 2 || bound.completed_prefix != 0 {
        return Err(Error::Conflict);
    }
    let FsyncProgress::Committed { receipt, redo } =
        commit_segment(&mut writer, &job, work, |p| {
            reserve(p, FINAL_START, 12, 4, FINAL_LSN)
        })?
    else {
        return Err(Error::Conflict);
    };
    if receipt.status != 3
        || receipt.completed_prefix as usize != FILE_BYTES.len()
        || receipt.commit_lsn != FINAL_LSN
        || !matches!(commit_segment(&mut writer, &job, work, |_| Err(Error::Conflict))?,
                     FsyncProgress::AlreadyDone(same) if same == receipt)
    {
        return Err(Error::Conflict);
    }
    let mut reread = [0; BLOCK];
    writer.read_committed(SCRATCH_FILE_BLOCK, &mut reread)?;
    if reread != data {
        return Err(Error::Conflict);
    }
    let admission = flow.admission_id();
    flow.complete(
        &mut ledger,
        FILE_SERVICE_ROLE,
        false,
        TerminalState::Done,
        redo.ordered_digest(),
    )?;
    if admission == 0 || ledger.inflight_count() != 0 {
        return Err(Error::Conflict);
    }
    client.publish(FSYNC, &encode_receipt_reply(caller, receipt));
    let holder = client.finish();
    report(
        "V020_FSYNC_COMMITTED",
        receipt.commit_lsn,
        receipt.write_seq,
        receipt.completed_prefix.into(),
    );
    report(
        "V020_FSYNC_WRITE_ABI",
        caller.boot_epoch,
        holder,
        caller.service_generation,
    );
    Ok(())
}

fn final_receipt(data: &[u8; BLOCK], commit_lsn: u64) -> Result<FileReceiptV4, Error> {
    let frame = fsync_frame();
    let frozen = freeze(&mut AuthContextIssuerV1::new(1)?, &frame, TEST_CAP, data)?;
    Ok(FileReceiptV4 {
        log_epoch: 1,
        txid: 4,
        commit_lsn,
        write_seq: WRITE_SEQ,
        status: 3,
        completed_prefix: FILE_BYTES.len() as u32,
        operation_digest: frozen.request().operation_digest,
        output_digest: Sha256::digest(data).into(),
        ..issued_receipt()
    })
}

fn verify_block(
    writer: &mut RedoWriter<'_, Disk>,
    home: u32,
    expected: &[u8; BLOCK],
) -> Result<(), Error> {
    let mut raw = [0; BLOCK];
    writer.read_committed(home, &mut raw)?;
    if &raw != expected {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub(super) fn recover(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    config: &VerifiedOfflineConfig<'_>,
) -> Result<(SuperblockV1, MountEvidence), Error> {
    if checkpoint.generation != 1 {
        return Err(Error::Stale);
    }
    let mode = SnapshotLayout::BaselineFsyncFile;
    volume::unified_map(disk, checkpoint, mode)?;
    volume::validate_homes(disk, checkpoint, 0, Some(config), mode)?;
    volume::require_zero_blocks(disk, LOG_END..BITMAP_START)?;
    let state = authority::verified_pair_state(disk, checkpoint, Some(config))?;

    // Build exact intended after-images from the sealed genesis view.
    let mut inode = [0; BLOCK];
    let mut index = [0; BLOCK];
    disk.read(INODE_START, &mut inode)?;
    disk.read(RECEIPTS_HOME + 6, &mut index)?;
    let at = SCRATCH_FILE_INODE as usize * INODE_BYTES;
    let file = &mut inode[at..at + INODE_BYTES];
    if Inode::decode(file)?.durable_write_seq != 0 {
        return Err(Error::Conflict);
    }
    file[24..32].copy_from_slice(&WRITE_SEQ.to_le_bytes());
    let crc = crc32c_zeroed(file, 252)?;
    file[252..].copy_from_slice(&crc.to_le_bytes());
    issued_index(&mut index)?;
    let data = frozen_file();
    // SAFETY: the second CPU0 boot borrows the same exclusive static areas.
    let workspace = unsafe { reopen::workspace() };
    let image = unsafe { &mut *core::ptr::addr_of_mut!(RECEIPTS) };
    image.fill(0);
    let final_lsn = {
        let mut writer = RedoWriter::open(disk, workspace, checkpoint)?;
        let summary = writer.evidence().ok_or(Error::Conflict)?;
        // Keep cold readback for the previous, exact signed test-media cut.
        // Newly written FSYNC segments include the unchanged stream index.
        if summary.transactions != 4
            || summary.distinct_home_blocks != 7
            || !matches!(summary.last_commit_lsn, FINAL_LSN | LEGACY_FINAL_LSN)
        {
            return Err(Error::Conflict);
        }
        let receipt = final_receipt(&data, summary.last_commit_lsn)?;
        image[RECEIPT_AT..RECEIPT_AT + RECEIPT_BYTES].copy_from_slice(&receipt.encode()?);
        // All seven expected homes actually change from the strictly checked
        // genesis view. Exact equality plus the union count excludes any
        // other target before replay is allowed to write.
        verify_block(&mut writer, volume::SECURITY_HOME, &state.encode()?)?;
        verify_block(
            &mut writer,
            volume::BOOT_HOME,
            &BootEpochStoreV1 {
                fs_uuid: volume::UUID,
                boot_epoch: 1,
            }
            .encode()?,
        )?;
        verify_block(&mut writer, INODE_START, &inode)?;
        verify_block(&mut writer, SCRATCH_FILE_BLOCK, &data)?;
        verify_block(
            &mut writer,
            RECEIPTS_HOME,
            image[..BLOCK].try_into().unwrap(),
        )?;
        verify_block(
            &mut writer,
            RECEIPTS_HOME + 1,
            image[BLOCK..2 * BLOCK].try_into().unwrap(),
        )?;
        verify_block(&mut writer, RECEIPTS_HOME + 6, &index)?;
        summary.last_commit_lsn
    };
    if final_lsn == LEGACY_FINAL_LSN {
        volume::require_zero_blocks(disk, LEGACY_LOG_END..LOG_END)?;
    }
    let mut mounted = None;
    let (chain, next) = recover_checkpoint_with_evidence(disk, workspace, |disk, selected| {
        if selected != checkpoint {
            return Err(Error::Conflict);
        }
        mounted = Some(volume::validate_fsync_homes(disk, selected, config)?);
        Ok(())
    })?;
    if chain.transactions != 4 || next.checkpoint_lsn != final_lsn {
        return Err(Error::Conflict);
    }
    retire_checkpointed_log(disk, workspace, next)?;
    Ok((next, mounted.ok_or(Error::Conflict)?))
}

pub(super) fn readback(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    config: &VerifiedOfflineConfig<'_>,
    state: &SecurityStateStoreV2,
) -> Result<StagedReceiptQuery, Error> {
    if state.last_boot_epoch != 2
        || !matches!(checkpoint.checkpoint_lsn, FINAL_LSN | LEGACY_FINAL_LSN)
    {
        return Err(Error::Stale);
    }
    let mut raw = [0; BLOCK];
    disk.read(SCRATCH_FILE_BLOCK, &mut raw)?;
    if raw != frozen_file() {
        return Err(Error::Conflict);
    }
    let expected = final_receipt(&raw, checkpoint.checkpoint_lsn)?;
    // Derive the static query qualification separately from the signed media
    // policy. Both are pinned to the identical persistent principal.
    // SAFETY: only the CPU0 staging owner borrows the role load scratch,
    // and the loaded executable images no longer depend on those bytes.
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(super::super::COPY_BUFFER.0) };
    let principal = signed::receipt_query_principal(config, scratch)?;
    let caller = receipt_caller(principal.id, state)?;

    // SAFETY: the one-shot CPU0 staging owner is the only writer. Reopen
    // has finished measuring and modifying the journal before this borrow.
    // No reachable operation mutates RECEIPTS after the view is published.
    let receipts = unsafe { &mut *core::ptr::addr_of_mut!(RECEIPTS) };
    for (block, output) in receipts.chunks_exact_mut(BLOCK).enumerate() {
        disk.read(RECEIPTS_HOME + block as u32, output.try_into().unwrap())?;
    }
    disk.read(RECEIPTS_HOME + 6, &mut raw)?;
    if FileReceiptV4::decode(&receipts[RECEIPT_AT..RECEIPT_AT + RECEIPT_BYTES])? != expected {
        return Err(Error::Conflict);
    }
    let view = MountedReceiptQuery::new(receipts, &raw, config, state)?;
    Ok(StagedReceiptQuery {
        view,
        caller,
        expected,
    })
}

fn receipt_caller(
    principal_id: u64,
    state: &SecurityStateStoreV2,
) -> Result<ReceiptQueryCaller, Error> {
    let service_slot = (FILE_SERVICE_ROLE - 1) as usize;
    let service_generation = state.service_generations[service_slot];
    if service_generation == 0 || state.isolated_service_bitmap & (1 << service_slot) != 0 {
        return Err(Error::Unauthorized);
    }
    Ok(ReceiptQueryCaller {
        principal_id,
        boot_epoch: state.last_boot_epoch,
        service_generation,
    })
}
