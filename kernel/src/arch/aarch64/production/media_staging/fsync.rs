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
        SCRATCH_FILE_BLOCK, SCRATCH_FILE_DATA, SCRATCH_FILE_FSYNC_RIGHTS, SCRATCH_FILE_GENERATION,
        SCRATCH_FILE_INODE,
    },
    file_fsync_v1::{FsyncJob, FsyncProgress, FsyncWorkspace, commit_segment},
    file_index_v0199::{BLOCK_BYTES as BLOCK, FileStreamIndexV4, SecurityStateStoreV2},
    file_media_v0199::{
        BITMAP_START, FileReceiptV4, INODE_START, RECEIPT_BYTES, SuperblockV1, crc32c_zeroed,
    },
    file_mount_v1::MountEvidence,
    file_read_v4::{FSYNC_SCRATCH_MAX_BYTES, StagedFile},
    file_receipt_query_v4::{
        MountedReceiptQuery, RECEIPT_KEY_BYTES, ReceiptKey, ReceiptQueryCaller,
        encode_receipt_reply,
    },
    file_receipt_store_v0199::RECEIPT_STORE_BYTES,
    file_service_v4::{REPLY_HEADER, REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION, Request},
    file_structure_v1::{Extent, INODE_BYTES, Inode},
    offline_config_v1::VerifiedOfflineConfig,
    recovery_v1::{RedoImage, RedoTransaction, RedoWriter, retire_checkpointed_log},
};
use sha2::{Digest, Sha256};

const FILE_LEN: usize = SCRATCH_FILE_DATA.len();
const SIZE_BYTES: usize = 8;
const FROZEN_BYTES: usize = SIZE_BYTES + FSYNC_SCRATCH_MAX_BYTES;
const INODE_AT: usize = SCRATCH_FILE_INODE as usize * INODE_BYTES;
const TEST_CAP: u64 = 1;
const SLOT: usize = 21;
const RECEIPT_AT: usize = SLOT * RECEIPT_BYTES;
const ISSUE_START: u32 = 8;
const BIND_START: u32 = 16;
const FINAL_START: u32 = 24;
const LOG_END: u32 = 40;
const SINGLE_LOG_END: u32 = 36;
const LEGACY_LOG_END: u32 = 32;
const BOOT_COMMIT_LSN: u64 = 4;
const ISSUE_COMMIT_LSN: u64 = 9;
const BOUND_LSN: u64 = 14;
const BOUND_STATUS: u16 = 2;
pub(super) const FINAL_LSN: u64 = 21;
const GROWTH_FINAL_LSN: u64 = 23;
const LEGACY_FINAL_LSN: u64 = 19;
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

/// The first post-FSYNC checkpoint is generation 2. Each subsequent
/// generation checkpoints one two-home BootEpoch transaction (four LSNs).
pub(super) fn receipt_lsn(checkpoint: SuperblockV1) -> Option<u64> {
    let boot_lsns = checkpoint.generation.checked_sub(2)?.checked_mul(4)?;
    let original = checkpoint.checkpoint_lsn.checked_sub(boot_lsns)?;
    matches!(
        original,
        GROWTH_FINAL_LSN | FINAL_LSN | LEGACY_FINAL_LSN | BOUND_LSN
    )
    .then_some(original)
}

#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut WORK: FsyncWorkspace = FsyncWorkspace::new();
#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut RECEIPTS: [u8; RECEIPT_STORE_BYTES] = [0; RECEIPT_STORE_BYTES];
#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut FROZEN: [u8; FROZEN_BYTES] = [0; FROZEN_BYTES];

fn request_header(raw: &mut [u8], op: u16, id: u64) {
    let length = (raw.len() - REQUEST_HEADER) as u32;
    raw[..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
    raw[4..6].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
    raw[6..8].copy_from_slice(&(REQUEST_HEADER as u16).to_le_bytes());
    raw[8..10].copy_from_slice(&op.to_le_bytes());
    raw[12..16].copy_from_slice(&length.to_le_bytes());
    raw[16..24].copy_from_slice(&id.to_le_bytes());
}

fn fsync_frame(write_seq: u64) -> [u8; REQUEST_HEADER + 8] {
    let mut raw = [0; REQUEST_HEADER + 8];
    request_header(&mut raw, 5, REQUEST_ID);
    raw[REQUEST_HEADER..].copy_from_slice(&write_seq.to_le_bytes());
    raw
}

fn frozen_material(snapshot: &mut [u8; FROZEN_BYTES], size: usize) -> &[u8] {
    let end = SIZE_BYTES + size.div_ceil(BLOCK) * BLOCK;
    if size == FILE_LEN {
        &snapshot[SIZE_BYTES..end]
    } else {
        snapshot[..SIZE_BYTES].copy_from_slice(&(size as u64).to_le_bytes());
        &snapshot[..end]
    }
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
        |p| reserve(p, ISSUE_START, 8, 2, ISSUE_COMMIT_LSN),
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
    client.start(file, KEY)?;
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
    let write_seq = u64::from_le_bytes(
        Request::decode(request.bytes(), request.selector)?
            .payload
            .try_into()
            .map_err(|_| Error::Invalid)?,
    );
    // SAFETY: this CPU0 staging operation is the sole borrower.
    let snapshot = unsafe { &mut *core::ptr::addr_of_mut!(FROZEN) };
    let size = client.freeze(
        request,
        write_seq,
        (&mut snapshot[SIZE_BYTES..]).try_into().unwrap(),
    )?;
    let mut issuer = AuthContextIssuerV1::new(1)?;
    let mut flow = freeze(
        &mut issuer,
        request.bytes(),
        request.selector,
        frozen_material(snapshot, size),
    )?;
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
    let (data, _) = snapshot[SIZE_BYTES..].as_chunks::<BLOCK>();
    let page_refs = [&data[0], &data[1]];
    let pages = &page_refs[..size.div_ceil(BLOCK)];
    let job = FsyncJob {
        config,
        mounted,
        admission: &flow,
        ledger: &ledger,
        inode_id: SCRATCH_FILE_INODE as u16,
        cap_selector: request.selector,
        frame: request.bytes(),
        key: KEY,
        grown_size: (size > FILE_LEN).then_some(size),
        pages,
    };
    let FsyncProgress::Committed { receipt: bound, .. } =
        commit_segment(&mut writer, &job, work, |p| {
            reserve(p, BIND_START, 8, 3, BOUND_LSN)
        })?
    else {
        return Err(Error::Conflict);
    };
    if bound.status != BOUND_STATUS || bound.completed_prefix != 0 {
        return Err(Error::Conflict);
    }
    if cfg!(cyxia_fsync_bound_fixture) {
        // The fixture ends with the fully committed binding. Its caller
        // received EAGAIN and never receives a successful FSYNC completion.
        report("V020_FSYNC_BOUND", bound.commit_lsn, bound.write_seq, 0);
        return Ok(());
    }
    let (final_blocks, final_lsn) = if pages.len() == 2 {
        (LOG_END - FINAL_START, GROWTH_FINAL_LSN)
    } else {
        (SINGLE_LOG_END - FINAL_START, FINAL_LSN)
    };
    let FsyncProgress::Committed { receipt, redo } =
        commit_segment(&mut writer, &job, work, |p| {
            reserve(p, FINAL_START, final_blocks, 4, final_lsn)
        })?
    else {
        return Err(Error::Conflict);
    };
    if receipt.status != 3
        || receipt.completed_prefix as usize != size
        || receipt.commit_lsn != final_lsn
        || !matches!(commit_segment(&mut writer, &job, work, |_| Err(Error::Conflict))?,
                     FsyncProgress::AlreadyDone(same) if same == receipt)
    {
        return Err(Error::Conflict);
    }
    for (index, page) in pages.iter().enumerate() {
        verify_block(
            &mut writer,
            SCRATCH_FILE_BLOCK + index as u32,
            final_lsn,
            page,
        )?;
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

fn recovered_version(inode_block: &[u8; BLOCK], commit_lsn: u64) -> Result<(usize, u64), Error> {
    let inode = Inode::decode(&inode_block[INODE_AT..INODE_AT + INODE_BYTES])?;
    let size = usize::try_from(inode.size).map_err(|_| Error::Conflict)?;
    let pages = size.div_ceil(BLOCK);
    if !(FILE_LEN..=FSYNC_SCRATCH_MAX_BYTES).contains(&size)
        || pages != if commit_lsn == GROWTH_FINAL_LSN { 2 } else { 1 }
        || inode.extents != 1
        || inode.runs[0]
            != (Extent {
                logical: 0,
                physical: SCRATCH_FILE_BLOCK,
                count: pages as u32,
            })
        || inode.durable_write_seq == 0
        || commit_lsn == LEGACY_FINAL_LSN && (size, inode.durable_write_seq) != (FILE_LEN, 7)
    {
        return Err(Error::Conflict);
    }
    Ok((size, inode.durable_write_seq))
}

fn final_receipt(
    snapshot: &mut [u8; FROZEN_BYTES],
    size: usize,
    write_seq: u64,
    commit_lsn: u64,
) -> Result<FileReceiptV4, Error> {
    let end = SIZE_BYTES + size.div_ceil(BLOCK) * BLOCK;
    if snapshot[SIZE_BYTES + size..end]
        .iter()
        .any(|&byte| byte != 0)
    {
        return Err(Error::Conflict);
    }
    let frame = fsync_frame(write_seq);
    let frozen = freeze(
        &mut AuthContextIssuerV1::new(1)?,
        &frame,
        TEST_CAP,
        frozen_material(snapshot, size),
    )?;
    Ok(FileReceiptV4 {
        log_epoch: 1,
        txid: 4,
        commit_lsn,
        write_seq,
        status: 3,
        completed_prefix: size as u32,
        operation_digest: frozen.request().operation_digest,
        output_digest: Sha256::digest(&snapshot[SIZE_BYTES..end]).into(),
        ..issued_receipt()
    })
}

fn verify_binding(receipt: FileReceiptV4) -> Result<FileReceiptV4, Error> {
    let expected = FileReceiptV4 {
        log_epoch: 1,
        txid: 3,
        commit_lsn: BOUND_LSN,
        write_seq: receipt.write_seq,
        status: BOUND_STATUS,
        operation_digest: receipt.operation_digest,
        ..issued_receipt()
    };
    if receipt != expected || receipt.write_seq == 0 || receipt.operation_digest == [0; 32] {
        return Err(Error::Conflict);
    }
    Ok(receipt)
}

fn file_size(receipt: FileReceiptV4) -> usize {
    if receipt.status == BOUND_STATUS {
        FILE_LEN
    } else {
        receipt.completed_prefix as usize
    }
}

fn verify_block(
    writer: &mut RedoWriter<'_, Disk>,
    home: u32,
    commit_lsn: u64,
    expected: &[u8; BLOCK],
) -> Result<(), Error> {
    let mut raw = [0; BLOCK];
    writer.read_committed_at(home, commit_lsn, &mut raw)?;
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
    let mode = SnapshotLayout::BaselineFsyncFile;
    if checkpoint.generation > 1 {
        let origin = receipt_lsn(checkpoint).ok_or(Error::Stale)?;
        // SAFETY: this private preflight ends before any view is published.
        let receipts = unsafe { &mut *core::ptr::addr_of_mut!(RECEIPTS) };
        let expected = read_retained_receipt(disk, origin, receipts)?;
        return reopen::recover_boot_pair(disk, checkpoint, Some(config), mode, |disk, epoch| {
            volume::validate_fsync_homes(
                disk,
                checkpoint,
                config,
                epoch,
                file_size(expected),
                expected.status == BOUND_STATUS,
            )
        });
    }
    volume::unified_map(disk, checkpoint, mode)?;
    volume::validate_homes(disk, checkpoint, 0, Some(config), mode)?;
    volume::require_zero_blocks(disk, LOG_END..BITMAP_START)?;
    let state = authority::verified_pair_state(disk, checkpoint, Some(config))?;

    // Build exact intended after-images from the sealed genesis view.
    let mut inode = [0; BLOCK];
    let mut index = [0; BLOCK];
    let mut bitmap = [0; BLOCK];
    disk.read(INODE_START, &mut inode)?;
    disk.read(RECEIPTS_HOME + 6, &mut index)?;
    disk.read(BITMAP_START, &mut bitmap)?;
    let mut tail = [0; BLOCK];
    // Read both possible legacy tails before taking the exclusive redo view.
    let mut single_tail_blank = true;
    let mut legacy_tail_blank = true;
    for home in LEGACY_LOG_END..LOG_END {
        disk.read(home, &mut tail)?;
        let empty = tail.iter().all(|&byte| byte == 0);
        legacy_tail_blank &= empty;
        if home >= SINGLE_LOG_END {
            single_tail_blank &= empty;
        }
    }
    let file = &mut inode[INODE_AT..INODE_AT + INODE_BYTES];
    if Inode::decode(file)?.durable_write_seq != 0 {
        return Err(Error::Conflict);
    }
    issued_index(&mut index)?;
    // SAFETY: the second CPU0 boot borrows the same exclusive static areas.
    let workspace = unsafe { reopen::workspace() };
    let image = unsafe { &mut *core::ptr::addr_of_mut!(RECEIPTS) };
    image.fill(0);
    let mut writer = RedoWriter::open(disk, workspace, checkpoint)?;
    let summary = writer.evidence().ok_or(Error::Conflict)?;
    let final_lsn = summary.last_commit_lsn;
    let (transactions, homes, index_lsn) = match final_lsn {
        GROWTH_FINAL_LSN => (4, 9, GROWTH_FINAL_LSN),
        FINAL_LSN if single_tail_blank => (4, 7, FINAL_LSN),
        // The legacy segment did not repeat the unchanged issued index.
        LEGACY_FINAL_LSN if legacy_tail_blank => (4, 7, ISSUE_COMMIT_LSN),
        BOUND_LSN if legacy_tail_blank => (3, 5, BOUND_LSN),
        _ => return Err(Error::Conflict),
    };
    if summary.incomplete_tail
        || (summary.transactions, summary.distinct_home_blocks) != (transactions, homes)
    {
        return Err(Error::Conflict);
    }
    let receipt = if final_lsn == BOUND_LSN {
        // The frozen input belongs to the prior caller. Preserve its
        // persisted digest without trying to reconstruct it from old data.
        for (offset, block) in image[..2 * BLOCK].chunks_exact_mut(BLOCK).enumerate() {
            writer.read_committed_at(
                RECEIPTS_HOME + offset as u32,
                BOUND_LSN,
                block.try_into().unwrap(),
            )?;
        }
        let bound = verify_binding(FileReceiptV4::decode(
            &image[RECEIPT_AT..RECEIPT_AT + RECEIPT_BYTES],
        )?)?;
        image.fill(0);
        bound
    } else {
        // SAFETY: CPU0 owns recovery exclusively before publishing a view.
        let snapshot = unsafe { &mut *core::ptr::addr_of_mut!(FROZEN) };
        let block: &mut [u8; BLOCK] = (&mut snapshot[SIZE_BYTES..SIZE_BYTES + BLOCK])
            .try_into()
            .unwrap();
        writer.read_committed_at(INODE_START, final_lsn, block)?;
        let (size, write_seq) = recovered_version(block, final_lsn)?;
        let pages = size.div_ceil(BLOCK);
        file[16..24].copy_from_slice(&(size as u64).to_le_bytes());
        file[24..32].copy_from_slice(&write_seq.to_le_bytes());
        file[56..60].copy_from_slice(&(pages as u32).to_le_bytes());
        let crc = crc32c_zeroed(file, 252)?;
        file[252..].copy_from_slice(&crc.to_le_bytes());
        if *block != inode {
            return Err(Error::Conflict);
        }
        if pages == 2 {
            // Both fixture data blocks are in the first canonical bitmap page.
            let bit = (SCRATCH_FILE_BLOCK + 1) as usize;
            let mask = 1 << (bit % 8);
            if bitmap[bit / 8] & mask != 0 {
                return Err(Error::Conflict);
            }
            bitmap[bit / 8] |= mask;
            verify_block(&mut writer, BITMAP_START, final_lsn, &bitmap)?;
        }
        for (index, page) in snapshot[SIZE_BYTES..].as_chunks_mut::<BLOCK>().0[..pages]
            .iter_mut()
            .enumerate()
        {
            writer.read_committed_at(SCRATCH_FILE_BLOCK + index as u32, final_lsn, page)?;
        }
        final_receipt(snapshot, size, write_seq, final_lsn)?
    };
    if writer.prepare(1)?.txid != receipt.txid + 1 {
        return Err(Error::Conflict);
    }
    image[RECEIPT_AT..RECEIPT_AT + RECEIPT_BYTES].copy_from_slice(&receipt.encode()?);
    // The required homes must be in their respective commits even
    // when an after-image matches its checkpoint bytes. Together with the
    // exact union count this excludes unapproved targets before replay.
    verify_block(
        &mut writer,
        volume::SECURITY_HOME,
        BOOT_COMMIT_LSN,
        &state.encode()?,
    )?;
    verify_block(
        &mut writer,
        volume::BOOT_HOME,
        BOOT_COMMIT_LSN,
        &BootEpochStoreV1 {
            fs_uuid: volume::UUID,
            boot_epoch: 1,
        }
        .encode()?,
    )?;
    verify_block(
        &mut writer,
        RECEIPTS_HOME,
        final_lsn,
        image[..BLOCK].try_into().unwrap(),
    )?;
    verify_block(
        &mut writer,
        RECEIPTS_HOME + 1,
        final_lsn,
        image[BLOCK..2 * BLOCK].try_into().unwrap(),
    )?;
    verify_block(&mut writer, RECEIPTS_HOME + 6, index_lsn, &index)?;

    let mut mounted = None;
    let (chain, next) = writer.checkpoint_verified(|disk, selected| {
        if selected != checkpoint {
            return Err(Error::Conflict);
        }
        mounted = Some(volume::validate_fsync_homes(
            disk,
            selected,
            config,
            1,
            file_size(receipt),
            receipt.status == BOUND_STATUS,
        )?);
        Ok(())
    })?;
    if chain.transactions != transactions || next.checkpoint_lsn != final_lsn {
        return Err(Error::Conflict);
    }
    retire_checkpointed_log(disk, workspace, next)?;
    Ok((next, mounted.ok_or(Error::Conflict)?))
}

fn read_retained_receipt(
    disk: &mut Disk,
    commit_lsn: u64,
    receipts: &mut [u8; RECEIPT_STORE_BYTES],
) -> Result<FileReceiptV4, Error> {
    for (block, output) in receipts.chunks_exact_mut(BLOCK).enumerate() {
        disk.read(RECEIPTS_HOME + block as u32, output.try_into().unwrap())?;
    }
    let retained = FileReceiptV4::decode(&receipts[RECEIPT_AT..RECEIPT_AT + RECEIPT_BYTES])?;
    let mut raw = [0; BLOCK];
    disk.read(INODE_START, &mut raw)?;
    if commit_lsn == BOUND_LSN {
        let inode = Inode::decode(&raw[INODE_AT..INODE_AT + INODE_BYTES])?;
        if inode.size != FILE_LEN as u64 || inode.durable_write_seq != 0 {
            return Err(Error::Conflict);
        }
        disk.read(SCRATCH_FILE_BLOCK, &mut raw)?;
        if raw[..FILE_LEN] != *SCRATCH_FILE_DATA || raw[FILE_LEN..].iter().any(|&byte| byte != 0) {
            return Err(Error::Conflict);
        }
        return verify_binding(retained);
    }
    let (size, write_seq) = recovered_version(&raw, commit_lsn)?;
    // SAFETY: the one-shot native owner holds no other frozen-data borrow.
    let snapshot = unsafe { &mut *core::ptr::addr_of_mut!(FROZEN) };
    for (index, page) in snapshot[SIZE_BYTES..].as_chunks_mut::<BLOCK>().0[..size.div_ceil(BLOCK)]
        .iter_mut()
        .enumerate()
    {
        disk.read(SCRATCH_FILE_BLOCK + index as u32, page)?;
    }
    let expected = final_receipt(snapshot, size, write_seq, commit_lsn)?;
    if retained != expected {
        return Err(Error::Conflict);
    }
    Ok(expected)
}

pub(super) fn readback(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    config: &VerifiedOfflineConfig<'_>,
    state: &SecurityStateStoreV2,
) -> Result<StagedReceiptQuery, Error> {
    let origin = receipt_lsn(checkpoint).ok_or(Error::Stale)?;
    if state.last_boot_epoch != checkpoint.generation {
        return Err(Error::Stale);
    }
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
    let expected = read_retained_receipt(disk, origin, receipts)?;
    let mut raw = [0; BLOCK];
    disk.read(RECEIPTS_HOME + 6, &mut raw)?;
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
