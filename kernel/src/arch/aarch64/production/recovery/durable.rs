//! CPU0 custody of the signed resident recovery carrier and its disk.

use super::super::super::report;
use super::{
    ConfirmedBootPolicy, EVENTS, Error, INITIAL_WRITER_GENERATION, SLOTS, STOPPED_WRITERS, TAKEN,
    contain_terminal_block, scratch_blk,
};
use core::{ptr::addr_of_mut, sync::atomic::Ordering};
use cyxia_arch_aarch64::cpu;
use cyxia_kernel_core::{
    control_plane::role_manifest_v0199::{NativeRole, Role},
    security::{
        epoch_redo_v0199::EpochBlockIo,
        file_index_v0199::BLOCK_BYTES,
        file_mount_v1::MountEvidence,
        recovery_proof_store::{RecoveryLocator, RecoveryProofStore, Workspace},
        recovery_proof_v2::{ACCUMULATOR_COUNT, RecoveryProofV2},
    },
};

struct Custody {
    store: RecoveryProofStore,
    device: &'static mut scratch_blk::ScratchBlock,
    epoch: u64,
    published_count: [u64; ACCUMULATOR_COUNT],
}

// CPU0 alone stages, dispatches each synchronous SVC, and runs foreground
// persistence between turns. There is no IRQ/DMA access to these statics.
// ScratchBlock's private queue memory stays with the driver.
static mut CUSTODY: Option<Custody> = None;
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
    store: RecoveryProofStore,
    device: &'static mut scratch_blk::ScratchBlock,
) {
    assert_eq!(cpu::slot(), 0);
    // SAFETY: the staging owner transfers its only device reference once,
    // before EL0 starts. No foreground or in-vector borrow exists yet.
    let slot = unsafe { &mut *addr_of_mut!(CUSTODY) };
    assert!(slot.is_none());
    *slot = Some(Custody {
        store,
        device,
        epoch: 0,
        published_count: [0; ACCUMULATOR_COUNT],
    });
}

// Bound the reference lifetime to this synchronous, non-reentrant use.
fn with_store<R>(run: impl FnOnce(&mut Custody) -> R) -> Option<R> {
    if cpu::slot() != 0 {
        return None;
    }
    // SAFETY: CPU0 is the sole owner and none of the closures enters EL0.
    unsafe { &mut *addr_of_mut!(CUSTODY) }.as_mut().map(run)
}

pub(super) fn bind(policy: &ConfirmedBootPolicy<'_>) -> Result<(), Error> {
    with_store(|hold| {
        hold.store.bind(policy, INITIAL_WRITER_GENERATION)?;
        hold.epoch = policy.boot_epoch();
        Ok(())
    })
    .unwrap_or(Ok(()))
}

fn supervisor(member: NativeRole) -> Result<(), Error> {
    if member.role != Role::Supervisor || member.actor.id != u64::from(Role::Supervisor.id()) {
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

pub(in super::super) fn has_pending_persistence() -> bool {
    with_store(|hold| hold.store.has_pending_ack() || pending_proof(hold).is_some())
        .unwrap_or(false)
}

fn pending_proof(hold: &Custody) -> Option<usize> {
    if !hold.store.can_append() {
        return None;
    }
    let available = 1 | STOPPED_WRITERS.load(Ordering::Acquire);
    (0..ACCUMULATOR_COUNT).find(|&i| {
        available & (1 << i) != 0 && EVENTS[i].load(Ordering::Acquire) > hold.published_count[i]
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

struct MeteredDisk<'a> {
    device: &'a mut scratch_blk::ScratchBlock,
    checkpoint: &'a mut dyn FnMut() -> Result<(), Error>,
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
    let Some((epoch, result)) = with_store(|hold| (hold.epoch, persist(hold, checkpoint))) else {
        return Ok(false);
    };
    if result.is_err() {
        contain_terminal_block(epoch);
    }
    result
}

fn persist(
    hold: &mut Custody,
    checkpoint: &mut dyn FnMut() -> Result<(), Error>,
) -> Result<bool, Error> {
    let proof_cpu = pending_proof(hold);
    if !hold.store.has_pending_ack() && proof_cpu.is_none() {
        return Ok(false);
    }
    checkpoint()?;
    // SAFETY: the CPU0 foreground is the sole staging and I/O worker. The
    // metering callback never borrows this workspace or touches custody.
    let work = unsafe { &mut *addr_of_mut!(WORK) };
    let mut disk = MeteredDisk {
        device: hold.device,
        checkpoint,
    };
    if let Some(seq) = hold.store.persist_ack(&mut disk, work)? {
        (disk.checkpoint)()?;
        report("V020_SEC_S_RECOVERY_ACK_DURABLE", hold.epoch, seq, 0);
        return Ok(true);
    }
    let cpu = proof_cpu.ok_or(Error::Conflict)?;
    let proof = take_proof(cpu, hold.epoch)?;
    hold.store.append(proof, &mut disk, work)?;
    hold.published_count[cpu] = proof.total_count;
    (disk.checkpoint)()?;
    if cpu == 0 {
        report(
            "V020_SEC_S_RECOVERY_PROOF_DURABLE",
            proof.boot_epoch,
            proof.total_count,
            proof.cpu_generation,
        );
    } else {
        report(
            "V020_SEC_S_RECOVERY_BUSINESS_DURABLE",
            proof.boot_epoch,
            u64::from(proof.cpu_id),
            proof.cpu_generation,
        );
    }
    Ok(true)
}
