//! Single request handoff from the stopped-role CPU3 FILE owner to the
//! metered CPU0 journal owner. Both roles retain all completion credits until
//! the exact result has crossed back to CPU3.

use core::{
    mem::MaybeUninit,
    ptr::addr_of_mut,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};
use cyxia_kernel_core::security::{
    Error,
    epoch_redo_v0199::EpochBlockIo,
    file_fsync_v1::{
        AuthorizedFsyncJob, FsyncAuthorization, FsyncProgress, FsyncWorkspace,
        commit_authorized_segment,
    },
    file_media_unified_v1::CANONICAL_BUSINESS_START,
    file_media_v0199::FileReceiptV4,
    file_mount_v1::MountEvidence,
    file_receipt_query_v4::{
        MountedReceiptQuery, RECEIPT_KEY_BYTES, ReceiptKey, ReceiptQueryCaller,
    },
    file_receipt_store_v0199::RECEIPT_STORE_BYTES,
    file_service_v4::{
        REPLY_HEADER, REQUEST_HEADER,
        transactions::{self, Owner, Workspace},
    },
    file_structure_v1::BLOCK,
    offline_config_v1::VerifiedOfflineConfig,
    recovery_v1::{RedoTransaction, RedoWriter},
};
use sha2::{Digest, Sha256};

use super::super::super::media_staging::SignedResidentBoot;

pub(super) const ALLOC_BYTES: usize = REQUEST_HEADER + 16;
pub(super) const FSYNC_BYTES: usize = REQUEST_HEADER + 8;
pub(super) const QUERY_BYTES: usize = REQUEST_HEADER + RECEIPT_KEY_BYTES;
pub(super) const ACK_BYTES: usize = QUERY_BYTES + 32;

pub(super) struct Fsync {
    pub caller: ReceiptQueryCaller,
    pub key: ReceiptKey,
    pub frame: [u8; FSYNC_BYTES],
    pub cap: u64,
    pub inode: u16,
    pub home: u32,
    pub authorization: FsyncAuthorization,
    pub page: [u8; BLOCK],
    pub bound: bool,
}

pub(super) enum Command {
    Allocate {
        caller: ReceiptQueryCaller,
        frame: [u8; ALLOC_BYTES],
        stream_ready: bool,
    },
    Fsync(Fsync),
    Query {
        caller: ReceiptQueryCaller,
        frame: [u8; QUERY_BYTES],
    },
    Ack {
        caller: ReceiptQueryCaller,
        frame: [u8; ACK_BYTES],
        receipt: FileReceiptV4,
        home: u32,
    },
}

pub(super) enum ResultBody {
    Ticket(ReceiptKey),
    Synced {
        receipt: FileReceiptV4,
        evidence: [u8; 32],
    },
    Query([u8; REPLY_HEADER]),
    Ack,
}

const IDLE: u8 = 0;
const QUEUED: u8 = 1;
const DONE: u8 = 2;
static PHASE: AtomicU8 = AtomicU8::new(IDLE);
static FENCED: AtomicBool = AtomicBool::new(false);
#[unsafe(link_section = ".bss.sec_n")]
static mut COMMAND: MaybeUninit<Command> = MaybeUninit::uninit();
#[unsafe(link_section = ".bss.sec_n")]
static mut RESULT: MaybeUninit<Result<ResultBody, Error>> = MaybeUninit::uninit();

pub(super) fn available() -> bool {
    !FENCED.load(Ordering::Acquire) && PHASE.load(Ordering::Acquire) == IDLE
}

pub(super) fn fence() {
    FENCED.store(true, Ordering::Release);
}

pub(super) fn send(command: Command) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::registered_slot() != Some(super::CPU) || !available() {
        return Err(Error::Busy);
    }
    // SAFETY: CPU3 is the sole sender. IDLE transfers both slots from the
    // last consumer before QUEUED publishes the initialized command to CPU0.
    unsafe { (*addr_of_mut!(COMMAND)).write(command) };
    PHASE.store(QUEUED, Ordering::Release);
    Ok(())
}

pub(super) fn receive() -> Option<Result<ResultBody, Error>> {
    if cyxia_arch_aarch64::cpu::registered_slot() != Some(super::CPU)
        || PHASE.load(Ordering::Acquire) != DONE
    {
        return None;
    }
    // SAFETY: DONE hands CPU0's initialized result to the single CPU3
    // consumer. CPU0 never reads either slot again before a new send.
    let result = unsafe { (*addr_of_mut!(RESULT)).assume_init_read() };
    PHASE.store(IDLE, Ordering::Release);
    Some(result)
}

pub(in super::super::super) fn pending() -> bool {
    PHASE.load(Ordering::Acquire) == QUEUED
}

pub(in super::super::super) fn turn(
    boot: &mut SignedResidentBoot,
    checkpoint: &mut dyn FnMut() -> Result<(), Error>,
) {
    if cyxia_arch_aarch64::cpu::registered_slot() != Some(0) || !pending() {
        return;
    }
    // SAFETY: QUEUED gives the single CPU0 foreground owner exclusive
    // access until it publishes DONE. CPU3 can neither replace nor read it.
    let command = unsafe { (*addr_of_mut!(COMMAND)).assume_init_mut() };
    let result = boot.with_runtime_writer(checkpoint, |writer, mounted, config| {
        if FENCED.load(Ordering::Acquire) {
            return Err(Error::Unknown);
        }
        if mounted.snapshot.is_some() || !mounted.may_overwrite_in_place() {
            return Err(Error::Unauthorized);
        }
        Ok(match command {
            Command::Allocate {
                caller,
                frame,
                stream_ready,
            } => allocate(writer, mounted, config, *caller, frame, stream_ready)
                .map(|key| key.map(ResultBody::Ticket)),
            Command::Fsync(job) => sync_file(writer, mounted, config, job),
            Command::Query { caller, frame } => query(writer, mounted, config, *caller, frame)
                .map(|reply| Some(ResultBody::Query(reply))),
            Command::Ack {
                caller,
                frame,
                receipt,
                home,
            } => acknowledge(writer, mounted, config, *caller, frame, *receipt, *home)
                .map(|()| Some(ResultBody::Ack)),
        })
    });
    let result = match result {
        Ok(Ok(None)) | Err(Error::Busy) => return,
        Ok(Ok(Some(body))) => Ok(body),
        Ok(Err(error)) | Err(error) => Err(error),
    };
    // SAFETY: CPU0 is the only producer of the terminal result slot.
    unsafe { (*addr_of_mut!(RESULT)).write(result) };
    PHASE.store(DONE, Ordering::Release);
}

fn query<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    mounted: &MountEvidence,
    config: &VerifiedOfflineConfig<'_>,
    caller: ReceiptQueryCaller,
    frame: &[u8; QUERY_BYTES],
) -> Result<[u8; REPLY_HEADER], Error> {
    use cyxia_kernel_core::security::file_media_v0199::DATA_START;
    // The baseline-only custody already validated the fixed receipt home.
    let base = DATA_START + 1;
    let mut receipts = [0; RECEIPT_STORE_BYTES];
    for (index, page) in receipts.as_chunks_mut::<BLOCK>().0.iter_mut().enumerate() {
        writer.read_committed(base + index as u32, page)?;
    }
    let mut index = [0; BLOCK];
    writer.read_committed(base + (RECEIPT_STORE_BYTES / BLOCK) as u32, &mut index)?;
    let view = MountedReceiptQuery::new(&receipts, &index, config, &mounted.security)?;
    let mut reply = [0; REPLY_HEADER];
    view.serve(caller, 0, frame, &mut reply)?;
    Ok(reply)
}

fn acknowledge<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    mounted: &MountEvidence,
    config: &VerifiedOfflineConfig<'_>,
    caller: ReceiptQueryCaller,
    frame: &[u8; ACK_BYTES],
    expected: FileReceiptV4,
    home: u32,
) -> Result<(), Error> {
    let owner = Owner {
        mounted,
        config,
        service_generation: caller.service_generation,
        protected_inode: None,
    };
    transactions::ack_ticket(
        writer,
        &owner,
        &mut Workspace::new(),
        caller,
        frame,
        |writer, record| {
            if record != &expected || record.status != 3 {
                return Err(Error::Conflict);
            }
            let mut page = [0; BLOCK];
            writer.read_committed_at_transaction(
                home,
                record.commit_lsn,
                record.txid,
                &mut page,
            )?;
            let observed: [u8; 32] = Sha256::digest(page).into();
            if observed != record.output_digest {
                return Err(Error::Conflict);
            }
            Ok(())
        },
        reserve,
    )?;
    Ok(())
}

fn reserve(plan: &RedoTransaction) -> Result<(), Error> {
    if FENCED.load(Ordering::Acquire) {
        return Err(Error::Unknown);
    }
    // One file page, one inode page, up to two receipt pages and the index.
    if plan.log_blocks > 12 {
        return Err(Error::Capacity);
    }
    Ok(())
}

fn allocate<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    mounted: &MountEvidence,
    config: &VerifiedOfflineConfig<'_>,
    caller: ReceiptQueryCaller,
    frame: &[u8; ALLOC_BYTES],
    stream_ready: &mut bool,
) -> Result<Option<ReceiptKey>, Error> {
    let owner = Owner {
        mounted,
        config,
        service_generation: caller.service_generation,
        protected_inode: None,
    };
    let mut work = Workspace::new();
    if !*stream_ready {
        let bound = transactions::bind_stream(writer, &owner, &mut work, caller, 0, reserve)?;
        *stream_ready = true;
        if bound.is_some() {
            return Ok(None);
        }
    }
    let ticket = transactions::allocate_ticket(writer, &owner, &mut work, caller, frame, reserve)?;
    Ok(Some(ticket.key))
}

fn sync_file<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    mounted: &MountEvidence,
    config: &VerifiedOfflineConfig<'_>,
    job: &mut Fsync,
) -> Result<Option<ResultBody>, Error> {
    use cyxia_kernel_core::security::file_auth_v3::FILE_SERVICE_SLOT;
    if job.caller.boot_epoch != mounted.boot.boot_epoch
        || mounted.security.service_generations[FILE_SERVICE_SLOT] != job.caller.service_generation
        || mounted.security.isolated_service_bitmap & (1 << FILE_SERVICE_SLOT) != 0
    {
        return Err(Error::Stale);
    }
    let pages = [&job.page];
    let data = AuthorizedFsyncJob {
        config,
        mounted,
        authorization: job.authorization,
        inode_id: job.inode,
        cap_selector: job.cap,
        frame: &job.frame,
        key: job.key,
        grown_size: None,
        pages: &pages,
    };
    let FsyncProgress::Committed { receipt, redo } = commit_authorized_segment(
        writer,
        &data,
        &mut FsyncWorkspace::new(),
        CANONICAL_BUSINESS_START,
        reserve,
    )?
    else {
        return Err(Error::Conflict);
    };
    if !job.bound && receipt.status == 2 && receipt.completed_prefix == 0 {
        job.bound = true;
        return Ok(None);
    }
    if !job.bound || receipt.status != 3 || receipt.result != 0 {
        return Err(Error::Unknown);
    }
    let mut page = [0; BLOCK];
    writer.read_committed_at_transaction(job.home, receipt.commit_lsn, receipt.txid, &mut page)?;
    if page != job.page {
        return Err(Error::Unknown);
    }
    Ok(Some(ResultBody::Synced {
        receipt,
        evidence: redo.ordered_digest(),
    }))
}
