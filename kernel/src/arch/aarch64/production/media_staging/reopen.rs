//! Reopen the boot-only journal under exclusive CPU0 ownership. This handles
//! interruption during home replay, checkpointing, and retirement of the
//! six-block BootEpoch append. Every other redo block must be zero.
use super::{Disk, authority, volume};
use core::mem::MaybeUninit;
use cyxia_kernel_core::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::{BLOCK_BYTES, SecurityStateStoreV2},
    file_media_v0199::{BITMAP_START, SuperblockV1},
    file_mount_v1::MountEvidence,
    recovery_v1::{self, RecoveryWorkspace},
};

#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut RECOVERY: MaybeUninit<RecoveryWorkspace> = MaybeUninit::uninit();
// The workspace's Option field may have a nonzero representation for None.
// Copy the typed initializer from read-only image storage directly into BSS;
// constructing the roughly 120 KiB value on the CPU0 stack would overflow it.
static INITIAL_RECOVERY: RecoveryWorkspace = RecoveryWorkspace::new();

pub(super) fn identify(
    disk: &mut impl EpochBlockIo,
    config: volume::Config<'_>,
) -> Result<SuperblockV1, Error> {
    volume::read_checkpoint(disk, &mut [0; BLOCK_BYTES], config)
}

/// SAFETY: only the one-shot CPU0 staging owner may borrow this workspace.
pub(super) unsafe fn workspace() -> &'static mut RecoveryWorkspace {
    // SAFETY: the caller excludes all other workspace access until release.
    unsafe {
        let dest = core::ptr::addr_of_mut!(RECOVERY).cast::<RecoveryWorkspace>();
        core::ptr::copy_nonoverlapping(&INITIAL_RECOVERY, dest, 1);
        &mut *dest
    }
}

pub(super) fn recover(
    disk: &mut Disk,
    sb: SuperblockV1,
    config: volume::Config<'_>,
    snapshots: volume::SnapshotLayout,
) -> Result<(SuperblockV1, MountEvidence), Error> {
    recover_boot_pair(disk, sb, config, snapshots, |disk, epoch| {
        volume::validate_homes(disk, sb, epoch, config, snapshots)
    })
}

/// During preflight, present the previous committed pair to the existing
/// structural validator. Both physical homes are separately checked before
/// constructing this view. The post-replay check reads the actual disk.
pub(super) struct BootHomeView<'a, D> {
    disk: &'a mut D,
    previous: Option<SecurityStateStoreV2>,
}

impl<D: EpochBlockIo> EpochBlockIo for BootHomeView<'_, D> {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK_BYTES]) -> Result<(), Error> {
        match (block, self.previous) {
            (volume::SECURITY_HOME, Some(state)) => *out = state.encode()?,
            (volume::BOOT_HOME, Some(state)) => {
                *out = BootEpochStoreV1 {
                    fs_uuid: state.fs_uuid,
                    boot_epoch: state.last_boot_epoch,
                }
                .encode()?;
            }
            _ => return self.disk.read(block, out),
        }
        Ok(())
    }

    fn write(&mut self, _: u32, _: &[u8; BLOCK_BYTES]) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }

    fn flush(&mut self) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
}

fn verify_replay_homes(
    disk: &mut impl EpochBlockIo,
    previous: &SecurityStateStoreV2,
    committed: &SecurityStateStoreV2,
    config: volume::Config<'_>,
) -> Result<(), Error> {
    let mut raw = [0; BLOCK_BYTES];
    disk.read(volume::SECURITY_HOME, &mut raw)?;
    let actual = SecurityStateStoreV2::decode(&raw)?;
    if let Some(config) = config {
        config.check_committed(&actual)?;
    }
    if actual != *previous && actual != *committed {
        return Err(Error::Conflict);
    }
    disk.read(volume::BOOT_HOME, &mut raw)?;
    let actual = BootEpochStoreV1::decode(&raw)?;
    if !actual.matches(previous) && !actual.matches(committed) {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn retire(disk: &mut impl EpochBlockIo) -> Result<(), Error> {
    let end = volume::FIRST_LOG_BLOCK + authority::BOOT_LOG_BLOCKS;
    for block in volume::FIRST_LOG_BLOCK..end {
        disk.write(block, &[0; BLOCK_BYTES])
            .map_err(|_| Error::Unknown)?;
    }
    disk.flush().map_err(|_| Error::Unknown)?;
    volume::require_zero_blocks(disk, volume::FIRST_LOG_BLOCK..end).map_err(|_| Error::Unknown)
}

/// Recover a boot-only journal. The profile validates its own homes on
/// both sides of the same BootEpoch transition.
pub(super) fn recover_boot_pair<D: EpochBlockIo>(
    disk: &mut D,
    sb: SuperblockV1,
    config: volume::Config<'_>,
    snapshots: volume::SnapshotLayout,
    mut validate: impl FnMut(&mut BootHomeView<'_, D>, u64) -> Result<MountEvidence, Error>,
) -> Result<(SuperblockV1, MountEvidence), Error> {
    // Reject incompatible media, pending obligations and unexpected write
    // targets before the recovery engine is allowed to replay a single home.
    if identify(disk, config)? != sb {
        return Err(Error::Conflict);
    }
    volume::unified_map(disk, sb, snapshots)?;
    let log = authority::recovery_log(disk, sb, config)?;
    let previous_epoch = sb.generation - 1;
    let previous = if matches!(log, authority::BootLog::Committed) {
        let previous = volume::expected_state(previous_epoch, config)?;
        let committed = volume::expected_state(sb.generation, config)?;
        verify_replay_homes(disk, &previous, &committed, config)?;
        Some(previous)
    } else {
        None
    };
    let preflight = validate(&mut BootHomeView { disk, previous }, previous_epoch)?;
    let next_log = volume::FIRST_LOG_BLOCK + authority::BOOT_LOG_BLOCKS;
    volume::require_zero_blocks(disk, next_log..BITMAP_START)?;
    match log {
        authority::BootLog::Empty => return Ok((sb, preflight)),
        authority::BootLog::Checkpointed => {
            // Restore the ordering guarantee even if the previous boot
            // stopped immediately after writing the successor header.
            disk.flush().map_err(|_| Error::Unknown)?;
            retire(disk)?;
            return Ok((sb, preflight));
        }
        authority::BootLog::Committed => {}
    }

    // SAFETY: CPU0 borrows the workspace only inside the synchronous, one-shot
    // staging run; initialization precedes every use, including in host tests.
    let workspace = unsafe { workspace() };
    let mut mounted = None;
    let (chain, checkpoint) =
        recovery_v1::recover_checkpoint_with_evidence(disk, workspace, |disk, current| {
            if current != sb {
                return Err(Error::Conflict);
            }
            mounted = Some(validate(
                &mut BootHomeView {
                    disk,
                    previous: None,
                },
                sb.generation,
            )?);
            Ok(())
        })?;
    if chain.superblock != sb
        || chain.transactions != 1
        || chain.distinct_home_blocks != 2
        || chain.incomplete_tail
        || sb.checkpoint_lsn.checked_add(4) != Some(chain.last_commit_lsn)
        || identify(disk, config)? != checkpoint
    {
        return Err(Error::Conflict);
    }
    // The alternating checkpoint and the two home images have been flushed
    // and independently read back. Only this old extent may now be reused.
    retire(disk)?;
    Ok((checkpoint, mounted.ok_or(Error::Conflict)?))
}
