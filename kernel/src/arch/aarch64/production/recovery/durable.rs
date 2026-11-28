//! CPU0 custody of the signed resident disk and its optional audit carrier.

use super::super::signed_resident::report_recovery as report;
use super::{
    ConfirmedBootPolicy, EVENTS, Error, INITIAL_WRITER_GENERATION, SLOTS, STOPPED_WRITERS, TAKEN,
    contain_terminal_block, scratch_blk,
};
use core::{
    ptr::addr_of_mut,
    sync::atomic::{AtomicBool, Ordering},
};
use cyxia_arch_aarch64::cpu;
use cyxia_kernel_core::{
    control_plane::role_manifest_v0199::{NativeRole, Role},
    security::{
        epoch_redo_v0199::EpochBlockIo,
        file_index_v0199::BLOCK_BYTES,
        file_mount_v1::MountEvidence,
        recovery_proof_store::{ProofPersistence, RecoveryLocator, RecoveryProofStore, Workspace},
        recovery_proof_v2::{ACCUMULATOR_COUNT, RecoveryProofV2},
    },
};

struct Custody {
    device: &'static mut scratch_blk::ScratchBlock,
    audit: Option<AuditCustody>,
}

struct AuditCustody {
    store: RecoveryProofStore,
    epoch: u64,
    persisted_count: [u64; ACCUMULATOR_COUNT],
    reader_online: bool,
    reported_pressure: u64,
    reported_saturation: u64,
}

const FIFO_FULL: u64 = 1;
const READER_OFFLINE: u64 = 1 << 1;
const DEFERRED: u64 = 1 << 2;
const IO_UNCERTAIN: u64 = 1 << 3;

// CPU0 alone stages, dispatches each synchronous SVC, and runs foreground
// persistence between turns. There is no IRQ/DMA access to these statics.
// ScratchBlock's private queue memory stays with the driver.
static mut CUSTODY: Option<Custody> = None;
// Other CPUs may use the admission gate without reaching the disk owner.
static AUDIT_DEGRADED: AtomicBool = AtomicBool::new(false);
#[unsafe(link_section = ".bss.sec_n")]
static mut WORK: Workspace = Workspace::new();

pub(in super::super) fn open_durable(
    locator: RecoveryLocator,
    mounted: &MountEvidence,
    io: &mut impl EpochBlockIo,
) -> Result<RecoveryProofStore, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Unauthorized);
    }
    // SAFETY: one-shot CPU0 staging occurs before dispatch or installation.
    let work = unsafe { &mut *addr_of_mut!(WORK) };
    RecoveryProofStore::open(locator, mounted, io, work)
}

pub(in super::super) fn install_durable(
    store: Option<RecoveryProofStore>,
    device: &'static mut scratch_blk::ScratchBlock,
) {
    assert_eq!(cpu::slot(), 0);
    // SAFETY: the staging owner transfers its only device reference once,
    // before EL0 starts. No foreground or in-vector borrow exists yet.
    let slot = unsafe { &mut *addr_of_mut!(CUSTODY) };
    assert!(slot.is_none());
    *slot = Some(Custody {
        device,
        audit: store.map(|store| AuditCustody {
            store,
            epoch: 0,
            persisted_count: [0; ACCUMULATOR_COUNT],
            reader_online: false,
            reported_pressure: 0,
            reported_saturation: 0,
        }),
    });
}

// Bound the reference lifetime to this synchronous, non-reentrant use.
fn with_custody<R>(run: impl FnOnce(&mut Custody) -> R) -> Option<R> {
    if cpu::slot() != 0 {
        return None;
    }
    // SAFETY: CPU0 is the sole owner and none of the closures enters EL0.
    unsafe { &mut *addr_of_mut!(CUSTODY) }.as_mut().map(run)
}

fn with_store<R>(run: impl FnOnce(&mut AuditCustody) -> R) -> Option<R> {
    with_custody(|hold| hold.audit.as_mut().map(run)).flatten()
}

pub(super) fn bind(policy: &ConfirmedBootPolicy<'_>) -> Result<(), Error> {
    with_store(|hold| {
        hold.store.bind(policy, INITIAL_WRITER_GENERATION)?;
        hold.epoch = policy.boot_epoch();
        // Keep admissions closed until the signed transport has been bound.
        // Report the initial state once that transport is qualified.
        AUDIT_DEGRADED.store(true, Ordering::Release);
        Ok(())
    })
    .unwrap_or(Ok(()))
}

impl AuditCustody {
    fn update_pressure(&mut self) {
        let status = self.store.audit_status();
        let mut reasons = 0;
        if status.uncertain {
            reasons |= IO_UNCERTAIN;
        }
        if status.fifo_full() {
            reasons |= FIFO_FULL;
        }
        if !status.reader_available || !self.reader_online {
            reasons |= READER_OFFLINE;
        }
        if status.deferred != 0 {
            reasons |= DEFERRED;
        }
        AUDIT_DEGRADED.store(reasons != 0, Ordering::Release);
        if reasons != self.reported_pressure {
            if reasons == 0 {
                report(
                    "V020_SEC_S_AUDIT_RESUMED",
                    self.epoch,
                    status.pending,
                    status.retired,
                );
            } else {
                report(
                    "V020_SEC_S_AUDIT_DEGRADED",
                    self.epoch,
                    reasons,
                    status.pending,
                );
            }
            self.reported_pressure = reasons;
        }
        // A durable aggregate reports saturation across arbitrarily many
        // boots after all cells for one CPU are occupied. It has no audit
        // sequence and cannot be mistaken for a replayable RecoveryProof.
        if status.saturated != self.reported_saturation {
            report(
                "V020_SEC_S_AUDIT_SATURATION",
                status.first_saturated_boot,
                status.last_saturated_boot,
                status.saturated,
            );
            self.reported_saturation = status.saturated;
        }
    }
}

pub(in super::super) fn audit_degraded() -> bool {
    AUDIT_DEGRADED.load(Ordering::Acquire)
}

pub(in super::super) fn audit_transport_online(
    member: NativeRole,
    can_consume: bool,
) -> Result<(), Error> {
    supervisor(member)?;
    with_store(|hold| {
        if can_consume && !hold.store.reader_available(member.actor) {
            return Err(Error::Unauthorized);
        }
        hold.reader_online = can_consume;
        hold.update_pressure();
        Ok(())
    })
    .unwrap_or(Ok(()))
}

fn supervisor(member: NativeRole) -> Result<(), Error> {
    if cpu::slot() != 0
        || member.role != Role::Supervisor
        || member.actor.id != u64::from(Role::Supervisor.id())
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

pub(in super::super) fn durable_available(member: NativeRole) -> bool {
    supervisor(member).is_ok()
        && with_store(|hold| hold.store.reader_available(member.actor)).unwrap_or(false)
}

pub(in super::super) fn read_durable(member: NativeRole, after: u64) -> Result<[u8; 144], Error> {
    supervisor(member)?;
    with_store(|hold| hold.store.read(member.actor, after)).ok_or(Error::Unauthorized)?
}

pub(in super::super) fn confirm_delivery(
    member: NativeRole,
    seq: u64,
    digest: [u8; 32],
) -> Result<(), Error> {
    supervisor(member)?;
    with_store(|hold| hold.store.confirm_delivery(member.actor, seq, digest))
        .ok_or(Error::Unauthorized)?
}

pub(in super::super) fn check_durable_ack(
    member: NativeRole,
    seq: u64,
    digest: [u8; 32],
) -> Result<(), Error> {
    supervisor(member)?;
    with_store(|hold| hold.store.check_ack(member.actor, seq, digest)).ok_or(Error::Unauthorized)?
}

pub(in super::super) fn ack_durable(
    member: NativeRole,
    seq: u64,
    digest: [u8; 32],
) -> Result<(), Error> {
    supervisor(member)?;
    with_store(|hold| hold.store.ack(member.actor, seq, digest)).ok_or(Error::Unauthorized)?
}

pub(in super::super) fn close_audit_reader(member: NativeRole) -> Result<(), Error> {
    supervisor(member)?;
    with_store(|hold| {
        hold.store.close_reader(member.actor)?;
        hold.reader_online = false;
        hold.update_pressure();
        Ok(())
    })
    .unwrap_or(Ok(()))
}

pub(in super::super) fn replace_audit_reader(
    old: NativeRole,
    policy: &ConfirmedBootPolicy<'_>,
) -> Result<(), Error> {
    supervisor(old)?;
    with_store(|hold| hold.store.replace_reader(old.actor, policy)).unwrap_or(Ok(()))
}

pub(in super::super) fn verify_retired_ack(
    old: NativeRole,
    seq: u64,
    digest: [u8; 32],
) -> Result<(), Error> {
    supervisor(old)?;
    with_store(|hold| hold.store.retired_ack_confirmed(old.actor, seq, digest))
        .ok_or(Error::Unauthorized)?
}

pub(in super::super) fn has_pending_persistence() -> bool {
    with_store(|hold| {
        hold.store.has_pending_ack() || hold.store.can_promote() || pending_proof(hold).is_some()
    })
    .unwrap_or(false)
}

fn pending_proof(hold: &AuditCustody) -> Option<usize> {
    if !hold.store.can_persist_proof() {
        return None;
    }
    let available = 1 | STOPPED_WRITERS.load(Ordering::Acquire);
    (0..ACCUMULATOR_COUNT).find(|&i| {
        available & (1 << i) != 0 && EVENTS[i].load(Ordering::Acquire) > hold.persisted_count[i]
    })
}

fn take_proof(i: usize, epoch: u64) -> Result<RecoveryProofV2, Error> {
    let bit = 1 << i;
    if i != 0 && STOPPED_WRITERS.load(Ordering::Acquire) & bit == 0 {
        return Err(Error::Busy);
    }
    let count = EVENTS[i].load(Ordering::Acquire);
    // SAFETY: bind initialized the slots before any worker could dispatch.
    // CPU0 always owns slot 0. Business writers released their final access
    // before STOPPED_WRITERS above, and no subsequent path writes the slot.
    let acc = unsafe { (*addr_of_mut!(SLOTS[i])).0.assume_init_mut() };
    if i != 0 && TAKEN.load(Ordering::Relaxed) & bit == 0 {
        acc.takeover_stopped_writer(epoch, i as u32, INITIAL_WRITER_GENERATION, count)?;
        TAKEN.fetch_or(bit, Ordering::Release);
    }
    let proof = *acc.proof();
    if proof.boot_epoch != epoch || proof.cpu_id != i as u32 || proof.total_count != count {
        return Err(Error::Conflict);
    }
    Ok(proof)
}

pub(in super::super) struct MeteredDisk<'a> {
    device: &'a mut scratch_blk::ScratchBlock,
    checkpoint: &'a mut dyn FnMut() -> Result<(), Error>,
}

/// The same signed block owner serves generation transactions and audit
/// persistence. Each closure is synchronous and cannot retain the device.
pub(in super::super) fn with_epoch_io<T>(
    checkpoint: &mut dyn FnMut() -> Result<(), Error>,
    access: impl FnOnce(&mut MeteredDisk<'_>) -> Result<T, Error>,
) -> Result<T, Error> {
    with_custody(|hold| {
        access(&mut MeteredDisk {
            device: hold.device,
            checkpoint,
        })
    })
    .ok_or(Error::Unauthorized)?
}

impl EpochBlockIo for MeteredDisk<'_> {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK_BYTES]) -> Result<(), Error> {
        scratch_blk::sectors_metered(
            self.device,
            u64::from(block) * 8,
            None,
            out,
            self.checkpoint,
        )
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_BYTES]) -> Result<(), Error> {
        let mut unused = [0; BLOCK_BYTES];
        scratch_blk::sectors_metered(
            self.device,
            u64::from(block) * 8,
            Some(data),
            &mut unused,
            self.checkpoint,
        )
    }

    fn flush(&mut self) -> Result<(), Error> {
        scratch_blk::flush_metered(self.device, self.checkpoint)
    }
}

pub(in super::super) fn persist_pending(
    checkpoint: &mut dyn FnMut() -> Result<(), Error>,
) -> Result<bool, Error> {
    let Some((epoch, result)) = with_custody(|hold| {
        let audit = hold.audit.as_mut()?;
        let result = persist(audit, hold.device, checkpoint);
        audit.update_pressure();
        Some((audit.epoch, result))
    })
    .flatten() else {
        return Ok(false);
    };
    if result.is_err() {
        contain_terminal_block(epoch);
    }
    result
}

fn persist(
    hold: &mut AuditCustody,
    device: &mut scratch_blk::ScratchBlock,
    checkpoint: &mut dyn FnMut() -> Result<(), Error>,
) -> Result<bool, Error> {
    let proof_cpu = pending_proof(hold);
    if !hold.store.has_pending_ack() && !hold.store.can_promote() && proof_cpu.is_none() {
        return Ok(false);
    }
    checkpoint()?;
    // SAFETY: the CPU0 foreground is the sole staging and I/O worker. The
    // metering callback never borrows this workspace or touches custody.
    let work = unsafe { &mut *addr_of_mut!(WORK) };
    let mut disk = MeteredDisk { device, checkpoint };
    if let Some(seq) = hold.store.persist_ack(&mut disk, work)? {
        (disk.checkpoint)()?;
        report("V020_SEC_S_RECOVERY_ACK_DURABLE", hold.epoch, seq, 0);
        return Ok(true);
    }
    if let Some(seq) = hold.store.promote(&mut disk, work)? {
        (disk.checkpoint)()?;
        report("V020_SEC_S_RECOVERY_PROOF_PROMOTED", hold.epoch, seq, 0);
        return Ok(true);
    }
    let cpu = proof_cpu.ok_or(Error::Conflict)?;
    let proof = take_proof(cpu, hold.epoch)?;
    let outcome = hold.store.persist_proof(proof, &mut disk, work)?;
    hold.persisted_count[cpu] = proof.total_count;
    (disk.checkpoint)()?;
    match outcome {
        ProofPersistence::Queued { .. } if cpu == 0 => report(
            "V020_SEC_S_RECOVERY_PROOF_DURABLE",
            proof.boot_epoch,
            proof.total_count,
            proof.cpu_generation,
        ),
        ProofPersistence::Queued { .. } => report(
            "V020_SEC_S_RECOVERY_BUSINESS_DURABLE",
            proof.boot_epoch,
            u64::from(proof.cpu_id),
            proof.cpu_generation,
        ),
        ProofPersistence::Deferred => report(
            "V020_SEC_S_RECOVERY_PROOF_DEFERRED",
            proof.boot_epoch,
            u64::from(proof.cpu_id),
            proof.total_count,
        ),
        ProofPersistence::Saturated => report(
            "V020_SEC_S_RECOVERY_PROOF_SATURATED",
            proof.boot_epoch,
            u64::from(proof.cpu_id),
            proof.total_count,
        ),
    }
    Ok(true)
}
