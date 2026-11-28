//! Scoped service generation appends in the authenticated resident journal.
//! CPU0 owns the retained device and advances at most one I/O per turn.

#[cfg(cyxia_startup_catalog)]
use super::{Disk, RuntimeJournal, authority, volume};
use cyxia_kernel_core::control_plane::role_manifest_v0199::ROLE_COUNT;
use cyxia_kernel_core::security::{Error, file_index_v0199::SecurityStateStoreV2};
#[cfg(cyxia_startup_catalog)]
use cyxia_kernel_core::security::{
    boot_epoch_v1::BootEpochAuthority,
    durable_role_epoch_v0199::{Outcome, RedoPlacement, StopEvidence},
    epoch_redo_v0199::{OneStateRedo, ServiceRestartAppend},
    file_index_v0199::BLOCK_BYTES,
    file_media_v0199::{BITMAP_START, SuperblockV1},
    offline_config_v1::VerifiedOfflineConfig,
};

// Only the serialized CPU0 foreground owner borrows the encoder.
#[cfg(cyxia_startup_catalog)]
#[unsafe(link_section = ".bss.sec_n")]
static mut LOG: OneStateRedo = OneStateRedo::zeroed();

fn successor(old: SecurityStateStoreV2, slot: usize) -> Result<SecurityStateStoreV2, Error> {
    let mut next = old;
    next.state_generation = next
        .state_generation
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    next.service_generations[slot] = next.service_generations[slot]
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    Ok(next)
}

pub(super) fn verify_successor(
    old: SecurityStateStoreV2,
    state: SecurityStateStoreV2,
) -> Result<(), Error> {
    (0..ROLE_COUNT)
        .any(|slot| successor(old, slot) == Ok(state))
        .then_some(())
        .ok_or(Error::Conflict)
}

#[cfg(cyxia_startup_catalog)]
fn placement(sb: SuperblockV1, index: u32) -> Result<RedoPlacement, Error> {
    const FIRST: u32 = volume::FIRST_LOG_BLOCK + authority::BOOT_LOG_BLOCKS;
    const BLOCKS: u32 = 4;
    const LSN_STRIDE: u64 = 3;
    let first = index
        .checked_mul(BLOCKS)
        .and_then(|offset| FIRST.checked_add(offset))
        .filter(|first| {
            first
                .checked_add(BLOCKS)
                .is_some_and(|end| end <= BITMAP_START)
        })
        .ok_or(Error::Exhausted)?;
    let ordinal = u64::from(index) + 1;
    Ok(RedoPlacement {
        fs_uuid: sb.fs_uuid,
        log_epoch: sb.log_epoch,
        first,
        state_home: volume::SECURITY_HOME,
        boot_home: None,
        txid: sb.generation.checked_add(ordinal).ok_or(Error::Exhausted)?,
        commit_lsn: sb
            .checkpoint_lsn
            .checked_add(4 + LSN_STRIDE * ordinal)
            .ok_or(Error::Exhausted)?,
    })
}

#[cfg(cyxia_startup_catalog)]
pub(super) struct RestartJournal {
    checkpoint: SuperblockV1,
    completed: u32,
    pending: Option<ServiceRestartAppend>,
}

#[cfg(cyxia_startup_catalog)]
#[unsafe(link_section = ".bss.sec_n")]
static mut CHECKPOINT: [u8; BLOCK_BYTES] = [0; BLOCK_BYTES];
#[cfg(cyxia_startup_catalog)]
#[unsafe(link_section = ".bss.sec_n")]
static mut SCRATCH: [u8; BLOCK_BYTES] = [0; BLOCK_BYTES];

#[cfg(cyxia_startup_catalog)]
impl RestartJournal {
    pub(super) fn open(
        disk: &mut Disk<'_>,
        checkpoint: SuperblockV1,
        config: &VerifiedOfflineConfig<'_>,
    ) -> Result<Self, Error> {
        // SAFETY: CPU0 still has the sole device and readback workspace.
        let raw = unsafe { &mut *core::ptr::addr_of_mut!(CHECKPOINT) };
        if volume::read_checkpoint_for(disk, raw, Some(config), volume::Checkpoints::Resident)?
            != checkpoint
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            checkpoint,
            completed: 0,
            pending: None,
        })
    }

    pub(super) fn pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn advance(
        &mut self,
        epochs: &mut BootEpochAuthority,
        config: &VerifiedOfflineConfig<'_>,
        runtime: Option<&mut RuntimeJournal>,
        stop: StopEvidence,
        checkpoint: &mut dyn FnMut() -> Result<(), Error>,
        verify_stop: impl FnOnce(StopEvidence) -> Result<(), Error>,
    ) -> Result<Option<u64>, Error> {
        if cyxia_arch_aarch64::cpu::slot() != 0 {
            return Err(Error::Unauthorized);
        }
        // SAFETY: Same exclusive CPU0 owner throughout each bounded step.
        let log = unsafe { &mut *core::ptr::addr_of_mut!(LOG) };
        let append = match &mut self.pending {
            Some(append) if append.matches_stop(stop) => append,
            Some(_) => return Err(Error::Busy),
            None => {
                let next = if let Some(runtime) = runtime {
                    let tx = runtime.workspace.next_transaction(1)?;
                    RedoPlacement {
                        fs_uuid: tx.fs_uuid,
                        log_epoch: tx.log_epoch,
                        first: tx.first_log_block,
                        state_home: volume::SECURITY_HOME,
                        boot_home: None,
                        txid: tx.txid,
                        commit_lsn: tx.commit_lsn,
                    }
                } else {
                    placement(self.checkpoint, self.completed)?
                };
                self.pending = Some(epochs.prepare_role_restart(
                    log,
                    self.checkpoint,
                    next,
                    config,
                    stop,
                    verify_stop,
                )?);
                return Ok(None);
            }
        };
        let raw = unsafe { &*core::ptr::addr_of!(CHECKPOINT) };
        let scratch = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
        let Some(result) = super::super::recovery::with_epoch_io(checkpoint, |device| {
            epochs.step_role_restart(device, log, append, raw, scratch)
        })?
        else {
            return Ok(None);
        };
        let Outcome::Service {
            role,
            generation,
            isolated: false,
        } = result
        else {
            return Err(Error::Conflict);
        };
        if role != stop.role || stop.generation.checked_add(1) != Some(generation) {
            return Err(Error::Conflict);
        }
        if let Some(runtime) = runtime {
            let state = SecurityStateStoreV2::decode(log.image())?;
            verify_successor(runtime.mounted.security, state)?;
            let proof = append.verified_redo().ok_or(Error::Unknown)?;
            runtime.workspace.include_service_restart(proof)?;
            runtime.mounted.security = state;
        }
        self.completed += 1;
        self.pending = None;
        Ok(Some(generation))
    }
}
