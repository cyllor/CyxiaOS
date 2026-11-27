//! Reconcile one retained operation on a verified baseline-v1 mount.
//! Recovery owns the exclusive writer and the original effect evidence.
//! This path writes only receipt/index homes and never resumes the request.
use super::{BLOCK_BYTES as BLOCK, RECEIPT_BYTES, RECEIPT_STORE_BYTES, ReceiptHome, home_closure};
use crate::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::SecurityStateStoreV2,
    file_media_v0199::FileReceiptV4,
    file_mount_v1::MountEvidence,
    file_receipt_query_v4::{MountedReceiptQuery, ReceiptKey},
    file_structure_v1::SystemKind,
    offline_config_v1::VerifiedOfflineConfig,
    recovery_v1::{CommittedRedo, RecoveryEvidence, RedoImage, RedoTransaction, RedoWriter},
};

const ISSUED: u16 = 1;
const BOUND: u16 = 2;
const DONE: u16 = 3;
const PARTIAL: u16 = 4;
const UNKNOWN: u16 = 5;
const CANCELLED: u16 = 6;

pub struct ReceiptRecoveryJob<'a> {
    pub mounted: &'a MountEvidence,
    pub config: &'a VerifiedOfflineConfig<'a>,
    pub key: ReceiptKey,
    /// The retained operation digest from protected admission custody.
    pub operation_digest: [u8; 32],
}

pub struct ReceiptRecoveryWorkspace {
    receipts: [u8; RECEIPT_STORE_BYTES],
    index: [u8; BLOCK],
    scratch: [u8; BLOCK],
}

impl ReceiptRecoveryWorkspace {
    pub const fn new() -> Self {
        Self {
            receipts: [0; RECEIPT_STORE_BYTES],
            index: [0; BLOCK],
            scratch: [0; BLOCK],
        }
    }
}

impl Default for ReceiptRecoveryWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Decision of the protected file recovery owner, with the original operation
/// identity authenticated and its I/O and transaction custody reconciled.
pub enum ReceiptDisposition {
    /// No authoritative conclusion. Keep the receipt and all obligations.
    Pending,
    /// The owner proved zero effect and no unresolved I/O or transactions.
    NoEffect { result: i32 },
    /// The owner proved this was FSYNC and the retained prefix is durable.
    /// The rest has no unresolved effect and the frozen input is unavailable.
    FsyncPrefix { bytes: u32, result: i32 },
}

pub enum ReceiptRecoveryOutcome {
    /// There is no retained exact key. This yields no effect conclusion.
    Unrecorded,
    /// Keep the original receipt/in-flight obligation. No writes occurred.
    Retained,
    /// Replay the exact terminal record already on the current trusted volume.
    Confirmed(FileReceiptV4),
    /// The bounded terminal projection completed both FLUSH and redo readback.
    Published {
        receipt: FileReceiptV4,
        commit: CommittedRedo,
    },
}

/// Reconcile a previously bound operation, using the actual exclusive file
/// owner and a fresh signed mount from this same boot/security view. The
/// protected `prove_effect` callback must independently verify the effect and
/// all original completion obligations. Media CRCs, an empty log, or timeout
/// by themselves provide no such proof. No client-supplied status is trusted.
/// `reserve` acquires the actual append/completion resources before writes.
/// After an uncertain append the writer closes, and the caller must retain
/// the original obligation and re-establish a verified recovery view.
pub fn reconcile_receipt<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    job: &ReceiptRecoveryJob<'_>,
    work: &mut ReceiptRecoveryWorkspace,
    prove_effect: impl FnOnce(
        &mut dyn EpochBlockIo,
        &FileReceiptV4,
    ) -> Result<ReceiptDisposition, Error>,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<ReceiptRecoveryOutcome, Error> {
    if job.operation_digest == [0; 32] {
        return Err(Error::Invalid);
    }
    job.config.check_committed(&job.mounted.security)?;
    let system = job.mounted.baseline_system().ok_or(Error::Unauthorized)?;
    let home = |kind| {
        system
            .iter()
            .find(|object| object.kind == kind)
            .map(|object| object.first_block)
            .ok_or(Error::Invalid)
    };
    let evidence = writer.evidence().ok_or(Error::Unknown)?;
    if evidence.incomplete_tail {
        return Err(Error::Unknown);
    }
    writer.read_committed(home(SystemKind::Security)?, &mut work.scratch)?;
    let security = SecurityStateStoreV2::decode(&work.scratch)?;
    writer.read_committed(home(SystemKind::BootEpoch)?, &mut work.scratch)?;
    let boot = BootEpochStoreV1::decode(&work.scratch)?;
    if security != job.mounted.security
        || boot != job.mounted.boot
        || !boot.matches(&security)
        || boot.fs_uuid != evidence.superblock.fs_uuid
    {
        return Err(Error::Stale);
    }

    let receipt_home = home(SystemKind::Receipts)?;
    let (blocks, _) = work.receipts.as_chunks_mut::<BLOCK>();
    let index_home = receipt_home + blocks.len() as u32;
    for (offset, block) in blocks.iter_mut().enumerate() {
        writer.read_committed(receipt_home + offset as u32, block)?;
    }
    writer.read_committed(index_home, &mut work.index)?;
    let view = MountedReceiptQuery::new(&work.receipts, &work.index, job.config, &security)?;
    let Some((slot, current)) = view.exact(job.key)? else {
        return Ok(ReceiptRecoveryOutcome::Unrecorded);
    };
    if current.status == ISSUED {
        return Ok(ReceiptRecoveryOutcome::Retained);
    }
    if current.operation_digest != job.operation_digest {
        return Err(Error::Conflict);
    }
    let closure = home_closure(slot).ok_or(Error::Invalid)?;
    let images = receipt_images(&work.receipts, &work.index, receipt_home, closure.receipt);
    let count = closure.receipt_block_count + 1;
    if !confirmed_record(
        writer,
        evidence,
        &current,
        &images[..count],
        &mut work.scratch,
    )? {
        return Ok(ReceiptRecoveryOutcome::Retained);
    }
    match current.status {
        DONE if current.result == 0 => return Ok(ReceiptRecoveryOutcome::Confirmed(current)),
        PARTIAL if current.completed_prefix != 0 && current.result < 0 => {
            return Ok(ReceiptRecoveryOutcome::Confirmed(current));
        }
        CANCELLED if current.completed_prefix == 0 && current.result <= 0 => {
            return Ok(ReceiptRecoveryOutcome::Confirmed(current));
        }
        BOUND | UNKNOWN => {}
        _ => return Err(Error::Conflict),
    }

    let (status, result) = match prove_effect(&mut writer.committed_view(), &current)? {
        ReceiptDisposition::Pending => return Ok(ReceiptRecoveryOutcome::Retained),
        ReceiptDisposition::NoEffect { result }
            if result < 0 && current.completed_prefix == 0 && current.output_digest == [0; 32] =>
        {
            (CANCELLED, result)
        }
        ReceiptDisposition::FsyncPrefix { bytes, result }
            if result < 0 && bytes != 0 && bytes == current.completed_prefix =>
        {
            (PARTIAL, result)
        }
        _ => return Err(Error::Conflict),
    };
    let plan = writer.prepare(count)?;
    let receipt = FileReceiptV4 {
        status,
        result,
        log_epoch: plan.log_epoch,
        txid: plan.txid,
        commit_lsn: plan.commit_lsn,
        ..current
    };
    let start = slot * RECEIPT_BYTES;
    work.receipts[start..start + RECEIPT_BYTES].copy_from_slice(&receipt.encode()?);
    let images = receipt_images(&work.receipts, &work.index, receipt_home, closure.receipt);
    let commit = writer.append(plan, &images[..count], reserve)?;
    Ok(ReceiptRecoveryOutcome::Published { receipt, commit })
}

fn receipt_images<'a>(
    receipts: &'a [u8; RECEIPT_STORE_BYTES],
    index: &'a [u8; BLOCK],
    base: u32,
    home: ReceiptHome,
) -> [RedoImage<'a>; 3] {
    let (blocks, _) = receipts.as_chunks::<BLOCK>();
    let entry = |offset: usize| RedoImage {
        home: base + offset as u32,
        contents: &blocks[offset],
    };
    let index = || RedoImage {
        home: base + blocks.len() as u32,
        contents: index,
    };
    [
        entry(home.first),
        home.second.map_or_else(index, entry),
        index(),
    ]
}

fn confirmed_record<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    evidence: RecoveryEvidence,
    receipt: &FileReceiptV4,
    homes: &[RedoImage<'_>],
    scratch: &mut [u8; BLOCK],
) -> Result<bool, Error> {
    if receipt.commit_lsn == 0 {
        return Ok(false);
    }
    if receipt.log_epoch < evidence.superblock.log_epoch {
        // This branch starts from the independently authenticated selected
        // checkpoint, including its validated post-replay mounted homes.
        return Ok(receipt.commit_lsn <= evidence.superblock.checkpoint_lsn);
    }
    if receipt.log_epoch != evidence.superblock.log_epoch
        || receipt.commit_lsn <= evidence.superblock.checkpoint_lsn
        || receipt.commit_lsn > evidence.last_commit_lsn
    {
        return Ok(false);
    }
    for image in homes {
        match writer.read_committed_at_transaction(
            image.home,
            receipt.commit_lsn,
            receipt.txid,
            scratch,
        ) {
            Ok(()) if scratch == image.contents => {}
            Ok(()) => return Err(Error::Conflict),
            Err(Error::Stale) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod tests;
