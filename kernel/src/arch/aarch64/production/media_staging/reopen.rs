//! Reopen the signed volume under exclusive CPU0 ownership. BootEpoch and
//! runtime appends share one ordered journal and advance one checkpoint.
use super::{Disk, authority, volume};
use core::mem::MaybeUninit;
#[cfg(any(test, cyxia_startup_catalog))]
use cyxia_kernel_core::security::boot_epoch_v1::{TlsBootPolicy, TlsBootTransition};
#[cfg(test)]
use cyxia_kernel_core::security::offline_config_v1::VerifiedOfflineConfig;
#[cfg(any(test, cyxia_startup_catalog))]
use cyxia_kernel_core::security::{
    recovery_proof_store::RecoveryLocator, startup_catalog_v0199::snapshot_authority::SnapshotAuthority,
};
use cyxia_kernel_core::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::{BLOCK_BYTES, SecurityStateStoreV2},
    file_media_v0199::{BITMAP_START, SuperblockV1},
    file_mount_v1::MountEvidence,
    recovery_v1::{self, RecoveryWorkspace},
};

#[cfg(any(test, cyxia_startup_catalog))]
#[path = "reopen_resident.rs"]
mod resident;

#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut RECOVERY: MaybeUninit<RecoveryWorkspace> = MaybeUninit::uninit();
// The workspace's Option field may have a nonzero representation for None.
// Copy the typed initializer from read-only image storage directly into BSS;
// constructing the roughly 120 KiB value on the CPU0 stack would overflow it.
static INITIAL_RECOVERY: RecoveryWorkspace = RecoveryWorkspace::new();

#[cfg(not(cyxia_startup_catalog))]
pub(super) fn identify(
    disk: &mut impl EpochBlockIo,
    config: volume::Config<'_>,
) -> Result<SuperblockV1, Error> {
    volume::read_checkpoint(disk, &mut [0; BLOCK_BYTES], config)
}

#[cfg(cyxia_startup_catalog)]
pub(super) fn identify_resident(
    disk: &mut impl EpochBlockIo,
    policy: TlsBootPolicy<'_>,
) -> Result<SuperblockV1, Error> {
    volume::read_checkpoint_for(
        disk,
        &mut [0; BLOCK_BYTES],
        Some(policy.config()),
        volume::Checkpoints::Resident,
    )
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

#[cfg(not(cyxia_startup_catalog))]
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

#[cfg(test)]
pub(super) fn recover_resident(
    disk: &mut Disk,
    sb: SuperblockV1,
    config: &VerifiedOfflineConfig<'_>,
) -> Result<(SuperblockV1, MountEvidence), Error> {
    recover_resident_with_tls(disk, sb, TlsBootPolicy::new(config, None)?, None)
}

#[cfg(test)]
pub(super) fn recover_resident_with_tls(
    disk: &mut Disk,
    sb: SuperblockV1,
    current: TlsBootPolicy<'_>,
    transition: Option<TlsBootTransition<'_>>,
) -> Result<(SuperblockV1, MountEvidence), Error> {
    recover_resident_with_reconciliation(disk, sb, current, transition)
        .map(|(checkpoint, mount, _)| (checkpoint, mount))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BootLogRecovery {
    Empty,
    Replayed,
    RetiredCheckpointed,
    #[cfg(any(test, cyxia_startup_catalog))]
    DiscardedPreparation {
        cleared_blocks: u8,
    },
}

/// Report the prior transaction's disposition only after recovery I/O and
/// readback. The authorized caller first owns the reset-complete block device.
#[cfg(test)]
pub(super) fn recover_resident_with_reconciliation(
    disk: &mut Disk,
    sb: SuperblockV1,
    current: TlsBootPolicy<'_>,
    transition: Option<TlsBootTransition<'_>>,
) -> Result<(SuperblockV1, MountEvidence, BootLogRecovery), Error> {
    recover_resident_for_layout(
        disk,
        sb,
        current,
        transition,
        volume::SnapshotLayout::LegacyZero,
        None,
        None,
    )
}

#[cfg(any(test, cyxia_startup_catalog))]
pub(super) fn recover_resident_for_layout(
    disk: &mut Disk,
    sb: SuperblockV1,
    current: TlsBootPolicy<'_>,
    transition: Option<TlsBootTransition<'_>>,
    snapshots: volume::SnapshotLayout,
    carrier: Option<RecoveryLocator>,
    snapshot_authority: Option<SnapshotAuthority>,
) -> Result<(SuperblockV1, MountEvidence, BootLogRecovery), Error> {
    if transition.is_some_and(|t| t.current().config().digest() != current.config().digest()) {
        return Err(Error::Conflict);
    }
    let policies = Policies {
        current: BootPolicy::Resident(current),
        predecessor: transition.map(|t| BootPolicy::Resident(t.previous())),
    };
    if let Some(recovered) =
        resident::reconcile(disk, sb, &policies, snapshots, carrier, snapshot_authority)?
    {
        return Ok(recovered);
    }
    recover_boot_pair_for(
        disk,
        sb,
        policies,
        snapshots,
        volume::Checkpoints::Resident,
        |disk, epoch, policy| match policy {
            BootPolicy::Resident(policy) => {
                volume::validate_resident_homes_for_layout(disk, sb, epoch, policy, snapshots)
            }
            #[cfg(not(cyxia_startup_catalog))]
            BootPolicy::Staging(_) => Err(Error::Conflict),
        },
    )
}

#[derive(Clone, Copy)]
enum BootPolicy<'a> {
    #[cfg(not(cyxia_startup_catalog))]
    Staging(volume::Config<'a>),
    #[cfg(any(test, cyxia_startup_catalog))]
    Resident(TlsBootPolicy<'a>),
}

impl<'a> BootPolicy<'a> {
    fn config(self) -> volume::Config<'a> {
        match self {
            #[cfg(not(cyxia_startup_catalog))]
            Self::Staging(config) => config,
            #[cfg(any(test, cyxia_startup_catalog))]
            Self::Resident(policy) => Some(policy.config()),
        }
    }

    fn state(
        self,
        epoch: u64,
        _roles_from: &SecurityStateStoreV2,
    ) -> Result<SecurityStateStoreV2, Error> {
        match self {
            #[cfg(not(cyxia_startup_catalog))]
            Self::Staging(config) => volume::expected_state(epoch, config),
            #[cfg(any(test, cyxia_startup_catalog))]
            Self::Resident(policy) => {
                use cyxia_kernel_core::control_plane::role_manifest_v0199::ROLE_COUNT;
                let roles = _roles_from.service_generations[..ROLE_COUNT]
                    .try_into()
                    .unwrap();
                policy.resident_state_with_roles(epoch, roles)
            }
        }
    }
}

struct Policies<'a> {
    current: BootPolicy<'a>,
    predecessor: Option<BootPolicy<'a>>,
}

impl<'a> Policies<'a> {
    fn policy_for(
        &self,
        actual: &SecurityStateStoreV2,
        epoch: u64,
    ) -> Result<BootPolicy<'a>, Error> {
        if *actual == self.current.state(epoch, actual)? {
            return Ok(self.current);
        }
        if let Some(previous) = self.predecessor
            && *actual == previous.state(epoch, actual)?
        {
            return Ok(previous);
        }
        if let Some(config) = self.current.config() {
            config.check_committed(actual)?;
        }
        Err(Error::Conflict)
    }
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
) -> Result<(), Error> {
    let mut raw = [0; BLOCK_BYTES];
    disk.read(volume::BOOT_HOME, &mut raw)?;
    let actual = BootEpochStoreV1::decode(&raw)?;
    if !actual.matches(previous) && !actual.matches(committed) {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// A rotated deployment must materialize the newly authorized public
/// policy before dropping its predecessor. This boot retains the already
/// durable paired redo as the anchor for runtime restart transactions.
#[cfg(test)]
pub(super) fn materialize_verified_boot(
    disk: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    policy: TlsBootPolicy<'_>,
    committed: &SecurityStateStoreV2,
) -> Result<MountEvidence, Error> {
    materialize_verified_boot_for_layout(
        disk,
        sb,
        policy,
        committed,
        volume::SnapshotLayout::LegacyZero,
    )
}

#[cfg(any(test, cyxia_startup_catalog))]
pub(super) fn materialize_verified_boot_for_layout(
    disk: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    policy: TlsBootPolicy<'_>,
    committed: &SecurityStateStoreV2,
    snapshots: volume::SnapshotLayout,
) -> Result<MountEvidence, Error> {
    policy.verify_resident_state(committed, sb.generation)?;
    authority::verified_pair_state_for(
        disk,
        sb,
        |_| Ok(()),
        |state| {
            if state != committed {
                return Err(Error::Conflict);
            }
            Ok(())
        },
    )?;
    // SAFETY: the single staging owner has released its earlier workspace.
    let work = unsafe { workspace() };
    let evidence = recovery_v1::scan(disk, work)?;
    if evidence.superblock != sb
        || evidence.transactions != 1
        || evidence.distinct_home_blocks != 2
        || evidence.incomplete_tail
        || sb.checkpoint_lsn.checked_add(4) != Some(evidence.last_commit_lsn)
    {
        return Err(Error::Conflict);
    }
    disk.flush().map_err(|_| Error::Unknown)?;
    recovery_v1::replay_home(disk, work)?;
    let mounted =
        volume::validate_resident_homes_for_layout(disk, sb, sb.generation, policy, snapshots)?;
    if &mounted.security != committed {
        return Err(Error::Conflict);
    }
    Ok(mounted)
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

#[cfg(any(test, cyxia_startup_catalog))]
fn retire_preparation(disk: &mut impl EpochBlockIo, present: u8) -> Result<(), Error> {
    // Retire newest first with a durability/readback boundary before
    // erasing any earlier record. A stop can leave a shorter valid prefix.
    for offset in (0..authority::BOOT_LOG_BLOCKS - 1).rev() {
        if present & (1 << offset) != 0 {
            let block = volume::FIRST_LOG_BLOCK + offset;
            disk.write(block, &[0; BLOCK_BYTES])
                .map_err(|_| Error::Unknown)?;
            disk.flush().map_err(|_| Error::Unknown)?;
            volume::require_zero_blocks(disk, block..block + 1).map_err(|_| Error::Unknown)?;
        }
    }
    Ok(())
}

/// Recover a boot-only journal. The profile validates its own homes on
/// both sides of the same BootEpoch transition.
#[cfg(not(cyxia_startup_catalog))]
pub(super) fn recover_boot_pair<D: EpochBlockIo>(
    disk: &mut D,
    sb: SuperblockV1,
    config: volume::Config<'_>,
    snapshots: volume::SnapshotLayout,
    mut validate: impl FnMut(&mut BootHomeView<'_, D>, u64) -> Result<MountEvidence, Error>,
) -> Result<(SuperblockV1, MountEvidence), Error> {
    recover_boot_pair_for(
        disk,
        sb,
        Policies {
            current: BootPolicy::Staging(config),
            predecessor: None,
        },
        snapshots,
        volume::Checkpoints::Staging,
        |disk, epoch, _| validate(disk, epoch),
    )
    .map(|(checkpoint, mount, _)| (checkpoint, mount))
}

fn recover_boot_pair_for<D: EpochBlockIo>(
    disk: &mut D,
    sb: SuperblockV1,
    policies: Policies<'_>,
    snapshots: volume::SnapshotLayout,
    checkpoints: volume::Checkpoints,
    mut validate: impl FnMut(
        &mut BootHomeView<'_, D>,
        u64,
        BootPolicy<'_>,
    ) -> Result<MountEvidence, Error>,
) -> Result<(SuperblockV1, MountEvidence, BootLogRecovery), Error> {
    // Reject incompatible media, pending obligations and unexpected write
    // targets before the recovery engine is allowed to replay a single home.
    let config = policies.current.config();
    let mut raw = [0; BLOCK_BYTES];
    if volume::read_checkpoint_for(disk, &mut raw, config, checkpoints)? != sb {
        return Err(Error::Conflict);
    }
    match checkpoints {
        volume::Checkpoints::Staging => {
            volume::unified_map(disk, sb, snapshots)?;
        }
        #[cfg(any(test, cyxia_startup_catalog))]
        volume::Checkpoints::Resident => volume::verify_resident_layout(disk, sb, snapshots)?,
    }
    let log = authority::recovery_log_for(disk, sb, |epoch, state| {
        policies.policy_for(state, epoch).map(|_| ())
    });
    let previous_epoch = sb.generation - 1;
    #[cfg(any(test, cyxia_startup_catalog))]
    let log = log.or_else(|error| {
        if !matches!(checkpoints, volume::Checkpoints::Resident)
            || !matches!(error, Error::Invalid | Error::Conflict | Error::Stale)
        {
            return Err(error);
        }
        disk.read(volume::SECURITY_HOME, &mut raw)?;
        let previous = SecurityStateStoreV2::decode(&raw)?;
        let before = policies.policy_for(&previous, previous_epoch)?;
        let next_same_policy = before.state(sb.generation, &previous)?;
        let next_current_policy = policies.current.state(sb.generation, &previous)?;
        // A prior boot could have armed the old policy's ordinary epoch
        // append before a newer signed configuration was deployed.
        match authority::uncommitted_log_for(disk, sb, next_same_policy) {
            Err(Error::Conflict) if next_same_policy != next_current_policy => {
                authority::uncommitted_log_for(disk, sb, next_current_policy)
            }
            answer => answer,
        }
    });
    let log = log?;
    let (mounted_policy, replay) = match log {
        authority::BootLog::Committed(committed) => {
            #[cfg(any(test, cyxia_startup_catalog))]
            if matches!(checkpoints, volume::Checkpoints::Resident) {
                // Active resident logs go through the strict extent owner.
                return Err(Error::Conflict);
            }
            let after = policies.policy_for(&committed, sb.generation)?;
            disk.read(volume::SECURITY_HOME, &mut raw)?;
            let home = SecurityStateStoreV2::decode(&raw)?;
            // Once the after-image is on the security home, its policy is
            // authoritative. The synthetic prior view below only checks file
            // structure and ACLs; its policy admits no service.
            let before = if home == committed {
                after
            } else {
                policies.policy_for(&home, previous_epoch)?
            };
            let old = before.state(previous_epoch, &committed)?;
            if !committed.no_rollback_from(&old) || (home != committed && home != old) {
                return Err(Error::Stale);
            }
            verify_replay_homes(disk, &old, &committed)?;
            (before, Some((old, after, committed)))
        }
        _ if policies.predecessor.is_some() => {
            disk.read(volume::SECURITY_HOME, &mut raw)?;
            (
                policies.policy_for(&SecurityStateStoreV2::decode(&raw)?, previous_epoch)?,
                None,
            )
        }
        _ => (policies.current, None),
    };
    let preflight = validate(
        &mut BootHomeView {
            disk,
            previous: replay.map(|(old, _, _)| old),
        },
        previous_epoch,
        mounted_policy,
    )?;
    let next_log = volume::FIRST_LOG_BLOCK + authority::BOOT_LOG_BLOCKS;
    volume::require_zero_blocks(disk, next_log..BITMAP_START)?;
    match log {
        authority::BootLog::Empty => return Ok((sb, preflight, BootLogRecovery::Empty)),
        authority::BootLog::Checkpointed => {
            // Restore the ordering guarantee even if the previous boot
            // stopped immediately after writing the successor header.
            disk.flush().map_err(|_| Error::Unknown)?;
            retire(disk)?;
            return Ok((sb, preflight, BootLogRecovery::RetiredCheckpointed));
        }
        #[cfg(any(test, cyxia_startup_catalog))]
        authority::BootLog::Prepared(present) => {
            retire_preparation(disk, present)?;
            return Ok((
                sb,
                preflight,
                BootLogRecovery::DiscardedPreparation {
                    cleared_blocks: present.count_ones() as u8,
                },
            ));
        }
        authority::BootLog::Committed(_) => {}
    }
    let (_, after, committed) = replay.ok_or(Error::Conflict)?;

    // SAFETY: CPU0 borrows the workspace only inside the synchronous, one-shot
    // staging run; initialization precedes every use, including in host tests.
    let workspace = unsafe { workspace() };
    let mut mounted = None;
    let (chain, checkpoint) =
        recovery_v1::recover_checkpoint_with_evidence(disk, workspace, |disk, current| {
            if current != sb {
                return Err(Error::Conflict);
            }
            let verified = validate(
                &mut BootHomeView {
                    disk,
                    previous: None,
                },
                sb.generation,
                after,
            )?;
            if verified.security != committed {
                return Err(Error::Conflict);
            }
            mounted = Some(verified);
            Ok(())
        })?;
    if chain.superblock != sb
        || chain.transactions != 1
        || chain.distinct_home_blocks != 2
        || chain.incomplete_tail
        || sb.checkpoint_lsn.checked_add(4) != Some(chain.last_commit_lsn)
        || volume::read_checkpoint_for(disk, &mut raw, config, checkpoints)? != checkpoint
    {
        return Err(Error::Conflict);
    }
    // The alternating checkpoint and the two home images have been flushed
    // and independently read back. Only this old extent may now be reused.
    retire(disk)?;
    Ok((
        checkpoint,
        mounted.ok_or(Error::Conflict)?,
        BootLogRecovery::Replayed,
    ))
}
