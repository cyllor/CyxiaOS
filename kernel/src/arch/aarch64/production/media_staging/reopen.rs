//! Reopen a completed scratch boot under exclusive CPU0 ownership. The six
//! blocks at the head of the journal must encode exactly the paired BootEpoch
//! append that this fixture produces. Every other redo block must be zero.
use super::{Disk, authority, volume};
use core::mem::MaybeUninit;
use cyxia_kernel_core::security::{
    Error,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::BLOCK_BYTES,
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

pub(super) fn identify(disk: &mut Disk) -> Result<SuperblockV1, Error> {
    volume::read_checkpoint(disk, &mut [0; BLOCK_BYTES])
}

pub(super) fn recover(
    disk: &mut Disk,
    sb: SuperblockV1,
    config: volume::Config<'_>,
    snapshots: volume::SnapshotLayout,
) -> Result<(SuperblockV1, MountEvidence), Error> {
    // Reject incompatible media, pending obligations and unexpected write
    // targets before the recovery engine is allowed to replay a single home.
    if identify(disk)? != sb {
        return Err(Error::Conflict);
    }
    volume::unified_map(disk, sb, snapshots)?;
    volume::validate_homes(disk, sb, sb.generation - 1, config, snapshots)?;
    let next_log = volume::FIRST_LOG_BLOCK + authority::BOOT_LOG_BLOCKS;
    volume::require_zero_blocks(disk, next_log..BITMAP_START)?;
    let epoch = authority::verify_previous_pair(disk, sb, config)?;

    // SAFETY: CPU0 borrows the workspace only inside the synchronous, one-shot
    // staging run; initialization precedes every use, including in host tests.
    let workspace = unsafe {
        let dest = core::ptr::addr_of_mut!(RECOVERY).cast::<RecoveryWorkspace>();
        core::ptr::copy_nonoverlapping(&INITIAL_RECOVERY, dest, 1);
        &mut *dest
    };
    let mut mounted = None;
    let (chain, checkpoint) =
        recovery_v1::recover_checkpoint_with_evidence(disk, workspace, |disk, current| {
            if current != sb {
                return Err(Error::Conflict);
            }
            mounted = Some(volume::validate_homes(disk, sb, epoch, config, snapshots)?);
            Ok(())
        })?;
    if chain.superblock != sb
        || chain.transactions != 1
        || chain.distinct_home_blocks != 2
        || chain.incomplete_tail
        || sb.checkpoint_lsn.checked_add(4) != Some(chain.last_commit_lsn)
        || identify(disk)? != checkpoint
    {
        return Err(Error::Conflict);
    }
    // The alternating checkpoint and the two home images have been flushed
    // and independently read back. Only this old extent may now be reused.
    for block in volume::FIRST_LOG_BLOCK..next_log {
        disk.write(block, &[0; BLOCK_BYTES])?;
    }
    disk.flush()?;
    Ok((checkpoint, mounted.ok_or(Error::Conflict)?))
}
