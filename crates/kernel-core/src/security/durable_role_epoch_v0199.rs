//! Durable identity allocation on the frozen SecurityStateStore v2 format.
//! Serialized EL1 owner only. A CRC, a matching block, a model claim or a
//! timeout cannot prove persistence. A real file owner must verify the exact
//! redo transaction and FLUSH, with current superblock and startup manifest.
//! This module supplies the prepared after-image and non-forgetting custody;
//! it never silently mounts legacy snapshot media or writes a raw disk block.
use super::{
    Error,
    boot_epoch_v1::{
        TlsBootPolicy, TlsBootTransition,
        tls_policy::{TLS_SIGNER_SLOT, TLS_SLOTS, TLS_VERIFIER_SLOT},
    },
    file_index_v0199::{BLOCK_BYTES, SecurityStateStoreV2},
};
use crate::control_plane::role_manifest_v0199::{ROLE_COUNT, ROLES, Role};
use sha2::{Digest, Sha256};
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// The boot manifest, not a role number supplied by EL0, selects the
/// persistent service_generation index and isolation bit. Never assume a
/// role_id is the disk array index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotBinding {
    pub role: Role,
    pub slot: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StopEvidence {
    pub role: Role,
    pub generation: u64,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    AllocateBoot,
    /// Only an authenticated cold TLS transition may prepare this boot pair.
    AllocateTlsBoot {
        generation: u64,
        digest: [u8; 32],
    },
    Restart(StopEvidence),
    Isolate(StopEvidence),
    /// Only prepare_offline_install may admit this signed transition.
    InstallConfig {
        generation: u64,
        digest: [u8; 32],
    },
}
impl Change {
    pub(super) fn allocates_boot(self) -> bool {
        matches!(self, Self::AllocateBoot | Self::AllocateTlsBoot { .. })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedEpoch {
    pub change: Change,
    pub fs_uuid: [u8; 16],
    pub old_state_generation: u64,
    pub new_state_generation: u64,
    pub target_boot_epoch: u64,
    pub after_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitEvidence {
    pub fs_uuid: [u8; 16],
    pub log_epoch: u64,
    pub txid: u64,
    pub commit_lsn: u64,
    pub after_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Boot {
        epoch: u64,
    },
    Service {
        role: Role,
        generation: u64,
        isolated: bool,
    },
    ConfigInstalled {
        generation: u64,
    },
}
/// Exact protected journal reservation, bound before the first write.
/// Not a new on-disk format. The native journal owner validates that this
/// is the current exclusive extent on the correct mounted device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedoPlacement {
    pub fs_uuid: [u8; 16],
    pub log_epoch: u64,
    pub first: u32,
    pub state_home: u32,
    pub boot_home: Option<u32>,
    pub txid: u64,
    pub commit_lsn: u64,
}
#[derive(Clone, Copy)]
struct Pending {
    ticket: PreparedEpoch,
    after: SecurityStateStoreV2,
    outcome: Outcome,
    placement: Option<RedoPlacement>,
}
/// No public method turns a prepared or UNKNOWN update into a boot/service
/// grant. An in-progress state survives ambiguous callback results; retries
/// use the same after-image, not a second monotonic increment.
pub struct DurableEpochGate {
    committed: SecurityStateStoreV2,
    slots: [SlotBinding; ROLE_COUNT],
    pending: Option<Pending>,
    last: Option<(PreparedEpoch, CommitEvidence, Outcome)>,
    last_placement: Option<RedoPlacement>,
    boot_confirmed: bool,
    paired_store: bool,
    startup_verified: bool,
    paired_confirmed: bool,
    tls_enabled: bool,
}

/// Current signed policy and durable boot identity. The borrow excludes a
/// concurrent epoch or isolation transition while a protected owner uses it.
#[derive(Clone, Copy)]
pub struct ConfirmedBootPolicy<'a> {
    epochs: &'a DurableEpochGate,
    boot: u64,
    config_digest: [u8; 32],
    key_manifest_hash: [u8; 32],
}

impl ConfirmedBootPolicy<'_> {
    pub fn boot_epoch(&self) -> u64 {
        self.boot
    }

    pub(super) fn config_digest(&self) -> [u8; 32] {
        self.config_digest
    }

    /// Compare an independently qualified boot package's policy binding
    /// with the same configuration after durable BootEpoch confirmation.
    pub fn matches_config_digest(&self, digest: [u8; 32]) -> bool {
        self.config_digest == digest
    }

    pub fn service_generation(&self, role: Role) -> Result<u64, Error> {
        self.epochs.running_service_generation(role)
    }

    /// The business file owner has its own reserved security-state slot,
    /// independent of the eight CPU0 lifecycle roles.
    pub fn file_service_generation(&self) -> Result<u64, Error> {
        use super::file_auth_v3::FILE_SERVICE_SLOT;
        if self.epochs.running_boot_epoch()? != self.boot
            || self
                .epochs
                .slots
                .iter()
                .any(|role| usize::from(role.slot) == FILE_SERVICE_SLOT)
        {
            return Err(Error::Conflict);
        }
        self.epochs.committed_generation_at(FILE_SERVICE_SLOT)
    }

    pub(super) fn verify_tls_installation(
        &self,
        installation: &super::network::TlsInstallation,
    ) -> Result<(), Error> {
        // Reject a revoked installation and any overlapping control slot.
        if !self.epochs.tls_enabled {
            return Err(Error::Unauthorized);
        }
        if self
            .epochs
            .slots
            .iter()
            .any(|binding| TLS_SLOTS & (1 << binding.slot) != 0)
        {
            return Err(Error::Conflict);
        }
        let state = &self.epochs.committed;
        if state.isolated_service_bitmap & TLS_SLOTS != 0
            || self.key_manifest_hash != installation.key_manifest_hash
        {
            return Err(Error::Unauthorized);
        }
        let generations = [
            installation.verifier_generation,
            installation.signer_generation,
            installation.key_generation,
        ];
        if generations.contains(&0)
            || generations
                != [
                    state.service_generations[TLS_VERIFIER_SLOT],
                    state.service_generations[TLS_SIGNER_SLOT],
                    state.key_generation,
                ]
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

impl DurableEpochGate {
    /// The native storage/manifest adapter must verify the recovered state
    /// against real volume identity, committed redo chain, offline config and
    /// monotonic security minima. This callback must not be supplied by EL0.
    pub fn recovered(
        raw: &[u8],
        slots: [SlotBinding; ROLE_COUNT],
        verify_recovered: impl FnOnce(&SecurityStateStoreV2) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let state = SecurityStateStoreV2::decode(raw)?;
        for (i, s) in slots.iter().enumerate() {
            if s.role != ROLES[i] || s.slot >= 16 || slots[..i].iter().any(|p| p.slot == s.slot) {
                return Err(Error::Invalid);
            }
        }
        verify_recovered(&state)?;
        Ok(Self {
            committed: state,
            slots,
            pending: None,
            last: None,
            last_placement: None,
            boot_confirmed: false,
            paired_store: false,
            startup_verified: false,
            paired_confirmed: false,
            tls_enabled: true,
        })
    }
    /// Reconcile both actual protected startup stores. This alone is
    /// not signed production startup; scratch media can exercise it.
    pub fn recovered_pair(
        raw: &[u8],
        boot_raw: &[u8],
        slots: [SlotBinding; ROLE_COUNT],
        verify_recovered: impl FnOnce(&SecurityStateStoreV2) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let boot = super::boot_epoch_v1::BootEpochStoreV1::decode(boot_raw)?;
        let mut gate = Self::recovered(raw, slots, |state| {
            if !boot.matches(state) {
                return Err(Error::Conflict);
            }
            verify_recovered(state)
        })?;
        gate.paired_store = true;
        Ok(gate)
    }
    /// Production startup additionally requires both committed stores,
    /// independently verified signed config and mounted-volume identity.
    pub fn recovered_for_startup(
        raw: &[u8],
        boot_raw: &[u8],
        slots: [SlotBinding; ROLE_COUNT],
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
        verify_recovered: impl FnOnce(&SecurityStateStoreV2) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let mut gate = Self::recovered_pair(raw, boot_raw, slots, |state| {
            config.check_committed(state)?;
            verify_recovered(state)
        })?;
        gate.startup_verified = true;
        Ok(gate)
    }
    pub fn boot_epoch(&self) -> Option<u64> {
        (self.boot_confirmed && self.pending.is_none()).then_some(self.committed.last_boot_epoch)
    }
    pub(super) fn bind_tls_startup(&mut self, policy: TlsBootPolicy<'_>) -> Result<(), Error> {
        if self.boot_confirmed || self.paired_confirmed || self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.verify_startup_config(policy.config())?;
        policy.verify_committed(&self.committed)?;
        self.tls_enabled = policy.listener_enabled();
        Ok(())
    }
    pub(super) fn verify_startup_config(
        &self,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<(), Error> {
        if !self.startup_verified {
            return Err(Error::Unauthorized);
        }
        config.check_committed(&self.committed)
    }
    /// Revalidate the committed signed startup configuration before
    /// constructing or issuing actual static control roots.
    pub fn confirmed_config_boot(
        &self,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<u64, Error> {
        if !self.paired_confirmed {
            return Err(Error::Unauthorized);
        }
        self.verify_startup_config(config)?;
        self.boot_epoch().ok_or(Error::Busy)
    }

    pub(super) fn confirmed_boot_policy(
        &self,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<ConfirmedBootPolicy<'_>, Error> {
        Ok(ConfirmedBootPolicy {
            epochs: self,
            boot: self.confirmed_config_boot(config)?,
            config_digest: config.digest(),
            key_manifest_hash: config.header().key_manifest_hash,
        })
    }

    /// A prepared service transition fences its own role while the exact
    /// committed generations for other roles remain usable in this boot.
    pub(super) fn confirmed_running_policy(
        &self,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<ConfirmedBootPolicy<'_>, Error> {
        if !self.paired_confirmed {
            return Err(Error::Unauthorized);
        }
        self.verify_startup_config(config)?;
        Ok(ConfirmedBootPolicy {
            epochs: self,
            boot: self.running_boot_epoch()?,
            config_digest: config.digest(),
            key_manifest_hash: config.header().key_manifest_hash,
        })
    }

    fn running_boot_epoch(&self) -> Result<u64, Error> {
        if !self.boot_confirmed
            || self.pending.is_some_and(|p| {
                !matches!(p.ticket.change, Change::Restart(_) | Change::Isolate(_))
            })
        {
            return Err(Error::Busy);
        }
        Ok(self.committed.last_boot_epoch)
    }

    fn running_service_generation(&self, role: Role) -> Result<u64, Error> {
        self.running_boot_epoch()?;
        if self.pending.is_some_and(|p| {
            matches!(p.ticket.change, Change::Restart(stop) | Change::Isolate(stop) if stop.role == role)
        }) {
            return Err(Error::Busy);
        }
        self.committed_service_generation(role)
    }
    fn slot(&self, role: Role) -> Result<usize, Error> {
        self.slots
            .iter()
            .find(|s| s.role == role)
            .map(|s| usize::from(s.slot))
            .ok_or(Error::Unauthorized)
    }
    /// A startup gate may read an already-confirmed generation. It is NOT
    /// a capability grant: a real registry still requires verified package,
    /// stop/recovery, current controller/security epochs and live mappings.
    pub fn service_generation(&self, role: Role) -> Result<u64, Error> {
        if self.boot_epoch().is_none() {
            return Err(Error::Busy);
        }
        self.committed_service_generation(role)
    }

    fn committed_service_generation(&self, role: Role) -> Result<u64, Error> {
        self.committed_generation_at(self.slot(role)?)
    }

    fn committed_generation_at(&self, at: usize) -> Result<u64, Error> {
        if self.committed.isolated_service_bitmap & (1u64 << at) != 0 {
            return Err(Error::Unauthorized);
        }
        let generation = self.committed.service_generations[at];
        if generation == 0 {
            return Err(Error::Stale);
        }
        Ok(generation)
    }
    pub fn prepare(
        &mut self,
        change: Change,
        verify_stop: impl FnOnce(StopEvidence) -> Result<(), Error>,
    ) -> Result<PreparedEpoch, Error> {
        // No generic runtime call may install offline configuration,
        // and the old mount must be revalidated after such a commit.
        if matches!(
            change,
            Change::InstallConfig { .. } | Change::AllocateTlsBoot { .. }
        ) {
            return Err(Error::Unauthorized);
        }
        if self
            .last
            .is_some_and(|(_, _, o)| matches!(o, Outcome::ConfigInstalled { .. }))
        {
            return Err(Error::Busy);
        }
        if let Some(p) = self.pending {
            return if p.ticket.change == change {
                Ok(p.ticket)
            } else {
                Err(Error::Busy)
            };
        }
        if let Some((ticket, _, _)) = self.last
            && ticket.change == change
        {
            return Ok(ticket);
        }
        let mut after = self.committed;
        let outcome = match change {
            Change::AllocateBoot => {
                if self.boot_confirmed {
                    return Err(Error::Conflict);
                }
                after.last_boot_epoch = after
                    .last_boot_epoch
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?;
                Outcome::Boot {
                    epoch: after.last_boot_epoch,
                }
            }
            Change::InstallConfig { .. } | Change::AllocateTlsBoot { .. } => {
                return Err(Error::Unauthorized);
            }
            Change::Restart(stop) | Change::Isolate(stop) => {
                if !self.boot_confirmed || stop.generation == 0 || stop.digest == [0; 32] {
                    return Err(Error::Unauthorized);
                }
                let slot = self.slot(stop.role)?;
                if after.service_generations[slot] != stop.generation {
                    return Err(Error::Stale);
                }
                if after.isolated_service_bitmap & (1u64 << slot) != 0 {
                    return Err(Error::Unauthorized);
                }
                // Actual close/stop/TLB/DMA/retained-obligation proof belongs
                // to the independent native recovery adapter.
                verify_stop(stop)?;
                let isolated = matches!(change, Change::Isolate(_));
                if isolated {
                    after.isolated_service_bitmap |= 1u64 << slot;
                } else {
                    after.service_generations[slot] =
                        stop.generation.checked_add(1).ok_or(Error::Exhausted)?;
                }
                Outcome::Service {
                    role: stop.role,
                    generation: after.service_generations[slot],
                    isolated,
                }
            }
        };
        after.state_generation = after
            .state_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        if !after.no_rollback_from(&self.committed) {
            return Err(Error::Conflict);
        }
        let raw = after.encode()?;
        let ticket = PreparedEpoch {
            change,
            fs_uuid: after.fs_uuid,
            old_state_generation: self.committed.state_generation,
            new_state_generation: after.state_generation,
            target_boot_epoch: after.last_boot_epoch,
            after_digest: hash(&raw),
        };
        self.pending = Some(Pending {
            ticket,
            after,
            outcome,
            placement: None,
        });
        Ok(ticket)
    }

    /// Cold boot owns the quiescent state before either TLS role has started.
    /// Advance the configuration and boot epoch with no observable midpoint.
    pub(super) fn prepare_tls_boot(
        &mut self,
        transition: TlsBootTransition<'_>,
    ) -> Result<PreparedEpoch, Error> {
        if !self.paired_store
            || !self.startup_verified
            || self.boot_confirmed
            || self.paired_confirmed
        {
            return Err(Error::Unauthorized);
        }
        if self.pending.is_some() || self.last.is_some() {
            return Err(Error::Busy);
        }
        let before = self.committed;
        let after = transition.successor_state(&before)?;
        let ticket = PreparedEpoch {
            change: Change::AllocateTlsBoot {
                generation: after.offline_config_generation,
                digest: after.offline_config_hash,
            },
            fs_uuid: after.fs_uuid,
            old_state_generation: before.state_generation,
            new_state_generation: after.state_generation,
            target_boot_epoch: after.last_boot_epoch,
            after_digest: hash(&after.encode()?),
        };
        self.tls_enabled = transition.current().listener_enabled();
        self.pending = Some(Pending {
            ticket,
            after,
            outcome: Outcome::Boot {
                epoch: after.last_boot_epoch,
            },
            placement: None,
        });
        Ok(ticket)
    }
    /// Offline startup only. The caller must supply the actual verified
    /// signed envelope and independently attest the full stopped/quiescent
    /// old registry, signed service whitelist, principal/ACL compatibility,
    /// current rules and each explicitly authorized clearance. No online
    /// SVC, AI or higher generation alone authorizes an isolation clear.
    /// This restricted state-block transition does not migrate ACLs,
    /// change the media format or publish any cap; a successful commit
    /// requires fresh complete signed-volume validation before boot.
    pub fn prepare_offline_install(
        &mut self,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
        clear: u64,
        service_generations: [u64; 16],
        verify_quiesced: impl FnOnce(
            &super::offline_config_v1::VerifiedOfflineConfig<'_>,
            &SecurityStateStoreV2,
            &SecurityStateStoreV2,
        ) -> Result<(), Error>,
    ) -> Result<PreparedEpoch, Error> {
        if !self.paired_store || self.boot_confirmed || self.paired_confirmed {
            return Err(Error::Unauthorized);
        }
        if self
            .last
            .is_some_and(|(_, _, o)| matches!(o, Outcome::ConfigInstalled { .. }))
        {
            return Err(Error::Busy);
        }
        let h = config.header();
        let old = self.committed;
        if h.fs_uuid != old.fs_uuid
            || h.generation <= old.offline_config_generation
            || h.rule_generation < old.rule_min_generation
            || h.security_generation < old.security_min_generation
            || h.key_generation < old.key_generation
        {
            return Err(Error::Stale);
        }
        if clear & !h.clear_isolation_bitmap != 0 || clear & !old.isolated_service_bitmap != 0 {
            return Err(Error::Unauthorized);
        }
        for (i, (&before, &after)) in old
            .service_generations
            .iter()
            .zip(&service_generations)
            .enumerate()
        {
            if after < before
                || after != before && before.checked_add(1) != Some(after)
                || clear & (1u64 << i) != 0 && (after == 0 || before.checked_add(1) != Some(after))
            {
                return Err(Error::Conflict);
            }
        }
        let mut after = old;
        after.state_generation = old
            .state_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        after.offline_config_generation = h.generation;
        after.offline_config_hash = config.digest();
        after.rule_min_generation = h.rule_generation;
        after.security_min_generation = h.security_generation;
        after.key_generation = h.key_generation;
        after.isolated_service_bitmap &= !clear;
        after.service_generations = service_generations;
        // The only monotonic exception is the explicitly signed clear.
        let mut conservative = after;
        conservative.isolated_service_bitmap |= clear;
        if !conservative.no_rollback_from(&old) {
            return Err(Error::Conflict);
        }
        let ticket = PreparedEpoch {
            change: Change::InstallConfig {
                generation: h.generation,
                digest: config.digest(),
            },
            fs_uuid: old.fs_uuid,
            old_state_generation: old.state_generation,
            new_state_generation: after.state_generation,
            target_boot_epoch: old.last_boot_epoch,
            after_digest: hash(&after.encode()?),
        };
        if let Some(p) = self.pending {
            return if p.ticket == ticket && p.after == after {
                Ok(ticket)
            } else if p.ticket.change == ticket.change {
                Err(Error::Conflict)
            } else {
                Err(Error::Busy)
            };
        }
        verify_quiesced(config, &old, &after)?;
        self.startup_verified = false;
        self.pending = Some(Pending {
            ticket,
            after,
            outcome: Outcome::ConfigInstalled {
                generation: h.generation,
            },
            placement: None,
        });
        Ok(ticket)
    }
    /// Bind the one actual transaction before any side-effecting I/O.
    /// A repeat, even with identical bytes, is query-only; callers must
    /// independently reconcile the retained extent rather than append again.
    pub fn claim_redo_once(
        &mut self,
        ticket: PreparedEpoch,
        placement: RedoPlacement,
        verify_reserved_extent: impl FnOnce(&RedoPlacement) -> Result<(), Error>,
    ) -> Result<(), Error> {
        use super::file_media_v0199::{BLOCK_COUNT, DATA_START};
        let p = self.pending.as_mut().ok_or(Error::Stale)?;
        if p.ticket != ticket {
            return Err(Error::Conflict);
        }
        if let Some(prior) = p.placement {
            return Err(if prior == placement {
                Error::Busy
            } else {
                Error::Conflict
            });
        }
        let paired = self.paired_store && ticket.change.allocates_boot();
        if placement.fs_uuid != ticket.fs_uuid
            || placement.log_epoch == 0
            || placement.txid == 0
            || placement.commit_lsn < if paired { 4 } else { 3 }
            || !(2..=if paired { 4092 } else { 4094 }).contains(&placement.first)
            || !(DATA_START..BLOCK_COUNT).contains(&placement.state_home)
            || placement.boot_home.is_some() != paired
            || placement.boot_home.is_some_and(|b| {
                b == placement.state_home || !(DATA_START..BLOCK_COUNT).contains(&b)
            })
        {
            return Err(Error::Invalid);
        }
        verify_reserved_extent(&placement)?;
        p.placement = Some(placement);
        Ok(())
    }
    fn check_redo_placement(
        &self,
        ticket: PreparedEpoch,
        placement: RedoPlacement,
    ) -> Result<(), Error> {
        if let Some(p) = self.pending {
            if p.ticket != ticket {
                return Err(Error::Busy);
            }
            return if p.placement == Some(placement) {
                Ok(())
            } else if p.placement.is_none() {
                Err(Error::Unauthorized)
            } else {
                Err(Error::Conflict)
            };
        }
        if self.last.is_some_and(|(t, _, _)| t == ticket) && self.last_placement == Some(placement)
        {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    pub fn after_image(&self, ticket: PreparedEpoch) -> Result<[u8; BLOCK_BYTES], Error> {
        let p = self.pending.ok_or(Error::Stale)?;
        if p.ticket != ticket {
            return Err(Error::Conflict);
        }
        let bytes = p.after.encode()?;
        if hash(&bytes) != ticket.after_digest {
            return Err(Error::Conflict);
        }
        Ok(bytes)
    }
    /// Production adapter entry: require a complete baseline-v1 redo chain
    /// covering the exact prepared state image. In addition, the EL1 file
    /// owner must authenticate the superblock and state inode mapping, prove
    /// both real device FLUSH completions in order, and establish that this
    /// transaction is the current committed version (not historical media).
    /// This entry never writes blocks, fabricates FLUSH or accepts v2 media.
    // Stable wide redo-confirmation API; regrouping arguments would change the public contract.
    #[allow(clippy::too_many_arguments)]
    pub fn confirm_from_redo(
        &mut self,
        ticket: PreparedEpoch,
        receipt: CommitEvidence,
        readback: &[u8],
        superblock_raw: &[u8],
        first_log_block: u32,
        state_home: u64,
        begin: &[u8],
        redos: &[&[u8]],
        commit: &[u8],
        verify_native: impl FnOnce(&PreparedEpoch, &CommitEvidence) -> Result<(), Error>,
    ) -> Result<Outcome, Error> {
        use super::file_media_v0199::{SuperblockV1, verify_state_redo_v1};
        let superblock = SuperblockV1::decode(superblock_raw)?;
        if superblock.fs_uuid != receipt.fs_uuid || superblock.log_epoch != receipt.log_epoch {
            return Err(Error::Conflict);
        }
        if redos.len() != 1 {
            return Err(Error::Conflict);
        }
        self.check_redo_placement(
            ticket,
            RedoPlacement {
                fs_uuid: receipt.fs_uuid,
                log_epoch: receipt.log_epoch,
                first: first_log_block,
                state_home: u32::try_from(state_home).map_err(|_| Error::Invalid)?,
                boot_home: None,
                txid: receipt.txid,
                commit_lsn: receipt.commit_lsn,
            },
        )?;
        verify_state_redo_v1(
            superblock,
            first_log_block,
            state_home,
            begin,
            redos,
            commit,
            readback,
            receipt.txid,
            receipt.commit_lsn,
        )?;
        self.confirm_inner(ticket, receipt, readback, false, true, verify_native)
    }
    /// Atomic startup proof: both exact state and BootEpochStore images
    /// appear in the same complete committed transaction, and actual native
    /// FLUSH/readback verification is mandatory. Single-store confirmation
    /// cannot publish a production BootEpoch.
    // Stable wide redo-confirmation API; regrouping arguments would change the public contract.
    #[allow(clippy::too_many_arguments)]
    pub fn confirm_boot_from_redo(
        &mut self,
        ticket: PreparedEpoch,
        receipt: CommitEvidence,
        readback: &[u8],
        boot_readback: &[u8],
        superblock_raw: &[u8],
        first_log_block: u32,
        state_home: u32,
        boot_home: u32,
        begin: &[u8],
        redos: &[&[u8]],
        commit: &[u8],
        verify_native: impl FnOnce(&PreparedEpoch, &CommitEvidence, &[u8]) -> Result<(), Error>,
    ) -> Result<Outcome, Error> {
        if !self.paired_store || !ticket.change.allocates_boot() {
            return Err(Error::Unauthorized);
        }
        let sb = super::file_media_v0199::SuperblockV1::decode(superblock_raw)?;
        if sb.fs_uuid != receipt.fs_uuid || sb.log_epoch != receipt.log_epoch {
            return Err(Error::Conflict);
        }
        self.check_redo_placement(
            ticket,
            RedoPlacement {
                fs_uuid: receipt.fs_uuid,
                log_epoch: receipt.log_epoch,
                first: first_log_block,
                state_home,
                boot_home: Some(boot_home),
                txid: receipt.txid,
                commit_lsn: receipt.commit_lsn,
            },
        )?;
        let state = super::boot_epoch_v1::verify_boot_pair(
            sb,
            first_log_block,
            state_home,
            boot_home,
            begin,
            redos,
            commit,
            readback,
            boot_readback,
            receipt.txid,
            receipt.commit_lsn,
        )?;
        if state.last_boot_epoch != ticket.target_boot_epoch {
            return Err(Error::Conflict);
        }
        let outcome = self.confirm_inner(ticket, receipt, readback, true, true, |t, r| {
            verify_native(t, r, boot_readback)
        })?;
        self.paired_confirmed = true;
        Ok(outcome)
    }

    /// Caller must obtain a stable read-back from the actual native file
    /// owner. The independent verifier authenticates the complete commit
    /// identity, exact after-image and real redo/FLUSH before releasing it.
    /// A mismatch or UNKNOWN preserves the pending transition and fences new
    /// publication/restart. The role2/8 shared controller epoch is a separate
    /// protected registry transition, not inferred from this block's slots.
    pub fn confirm(
        &mut self,
        ticket: PreparedEpoch,
        receipt: CommitEvidence,
        readback: &[u8],
        verify_commit: impl FnOnce(&PreparedEpoch, &CommitEvidence) -> Result<(), Error>,
    ) -> Result<Outcome, Error> {
        self.confirm_inner(ticket, receipt, readback, false, false, verify_commit)
    }
    fn confirm_inner(
        &mut self,
        ticket: PreparedEpoch,
        receipt: CommitEvidence,
        readback: &[u8],
        paired: bool,
        redo_verified: bool,
        verify_commit: impl FnOnce(&PreparedEpoch, &CommitEvidence) -> Result<(), Error>,
    ) -> Result<Outcome, Error> {
        if self.paired_store && ticket.change.allocates_boot() && !paired {
            return Err(Error::Unauthorized);
        }
        if !redo_verified
            && (self.paired_store
                || matches!(ticket.change, Change::InstallConfig { .. })
                || self.pending.is_some_and(|p| p.placement.is_some()))
        {
            return Err(Error::Unauthorized);
        }
        // The prior receipt is historical, not current startup authority.
        // Never return its successful outcome while a newer transaction
        // fences boot/service generation reads (even if bytes still match).
        if self.pending.is_some_and(|p| p.ticket != ticket) {
            return Err(Error::Busy);
        }
        if let Some((old, r, outcome)) = self.last
            && old == ticket
        {
            return if r == receipt && hash(readback) == old.after_digest {
                Ok(outcome)
            } else {
                Err(Error::Conflict)
            };
        }
        let p = self.pending.ok_or(Error::Stale)?;
        if p.ticket != ticket
            || receipt.fs_uuid != ticket.fs_uuid
            || receipt.log_epoch == 0
            || receipt.txid == 0
            || receipt.commit_lsn == 0
            || receipt.after_digest != ticket.after_digest
        {
            return Err(Error::Conflict);
        }
        if hash(readback) != ticket.after_digest
            || SecurityStateStoreV2::decode(readback)? != p.after
        {
            return Err(Error::Unknown);
        }
        verify_commit(&ticket, &receipt)?;
        self.committed = p.after;
        if matches!(p.outcome, Outcome::Boot { .. }) {
            self.boot_confirmed = true;
        }
        self.last = Some((ticket, receipt, p.outcome));
        self.last_placement = p.placement;
        self.pending = None;
        Ok(p.outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> SecurityStateStoreV2 {
        SecurityStateStoreV2 {
            fs_uuid: [1; 16],
            state_generation: 7,
            rule_min_generation: 2,
            security_min_generation: 3,
            key_generation: 1,
            isolated_service_bitmap: 0,
            last_boot_epoch: 9,
            offline_config_generation: 1,
            offline_config_hash: [2; 32],
            service_generations: [4; 16],
        }
    }
    fn slots() -> [SlotBinding; ROLE_COUNT] {
        core::array::from_fn(|i| SlotBinding {
            role: ROLES[i],
            slot: (i + 3) as u8,
        })
    }
    fn receipt(t: PreparedEpoch, txid: u64) -> CommitEvidence {
        CommitEvidence {
            fs_uuid: t.fs_uuid,
            log_epoch: 2,
            txid,
            commit_lsn: 10 + txid,
            after_digest: t.after_digest,
        }
    }
    #[test]
    fn boot_unknown_preserves_exact_after_image_and_never_burns_second_epoch() {
        let old = state().encode().unwrap();
        let mut q = DurableEpochGate::recovered(&old, slots(), |_| Ok(())).unwrap();
        assert_eq!(q.boot_epoch(), None);
        let t = q
            .prepare(Change::AllocateBoot, |_| panic!("not a service restart"))
            .unwrap();
        assert_eq!(t.target_boot_epoch, 10);
        let after = q.after_image(t).unwrap();
        assert_eq!(q.prepare(Change::AllocateBoot, |_| panic!("retry")), Ok(t));
        let r = receipt(t, 1);
        assert_eq!(
            q.confirm(t, r, &old, |_, _| panic!("old block not a proof")),
            Err(Error::Unknown)
        );
        assert_eq!(
            q.confirm(t, r, &after, |_, _| Err(Error::Unknown)),
            Err(Error::Unknown)
        );
        assert_eq!(q.boot_epoch(), None);
        assert_eq!(q.after_image(t), Ok(after));
        assert_eq!(
            q.confirm(t, r, &after, |_, _| Ok(())),
            Ok(Outcome::Boot { epoch: 10 })
        );
        assert_eq!(q.boot_epoch(), Some(10));
        assert_eq!(
            q.prepare(Change::AllocateBoot, |_| panic!("exact replay")),
            Ok(t)
        );
        assert_eq!(
            q.confirm(t, r, &after, |_, _| panic!("duplicate effect")),
            Ok(Outcome::Boot { epoch: 10 })
        );
        // Real cold recovery of this committed image allocates the next
        // BootEpoch once. It is not a repeat allocation within the old boot.
        let mut new = DurableEpochGate::recovered(&after, slots(), |_| Ok(())).unwrap();
        assert_eq!(
            new.prepare(Change::AllocateBoot, |_| Ok(()))
                .unwrap()
                .target_boot_epoch,
            11
        );
    }
    #[test]
    fn only_exact_stopped_slot_generation_changes_and_isolation_cannot_be_cleared() {
        let old = state().encode().unwrap();
        let mut q = DurableEpochGate::recovered(&old, slots(), |_| Ok(())).unwrap();
        let boot = q.prepare(Change::AllocateBoot, |_| Ok(())).unwrap();
        let raw = q.after_image(boot).unwrap();
        q.confirm(boot, receipt(boot, 1), &raw, |_, _| Ok(()))
            .unwrap();
        let stop = StopEvidence {
            role: Role::Security,
            generation: 4,
            digest: [5; 32],
        };
        let change = Change::Restart(stop);
        assert_eq!(q.prepare(change, |_| Err(Error::Busy)), Err(Error::Busy));
        let t = q.prepare(change, |_| Ok(())).unwrap();
        let after = q.after_image(t).unwrap();
        let decoded = SecurityStateStoreV2::decode(&after).unwrap();
        assert_eq!(decoded.service_generations[4], 5);
        assert_eq!(decoded.last_boot_epoch, 10);
        assert_eq!(decoded.state_generation, 9);
        assert_eq!(q.service_generation(Role::Security), Err(Error::Busy));
        assert_eq!(q.boot_epoch(), None);
        assert_eq!(
            q.running_service_generation(Role::Security),
            Err(Error::Busy)
        );
        assert_eq!(q.running_service_generation(Role::Operations), Ok(4));
        // A retry of the historical boot receipt cannot return a new success
        // while the restart transaction is pending/UNKNOWN.
        assert_eq!(
            q.confirm(boot, receipt(boot, 1), &raw, |_, _| panic!(
                "historical receipt"
            )),
            Err(Error::Busy)
        );
        assert_eq!(q.after_image(t), Ok(after));
        assert_eq!(
            q.prepare(Change::Isolate(stop), |_| Ok(())),
            Err(Error::Busy)
        );
        assert_eq!(
            q.confirm(t, receipt(t, 2), &after, |_, _| Ok(())),
            Ok(Outcome::Service {
                role: Role::Security,
                generation: 5,
                isolated: false
            })
        );
        assert_eq!(q.service_generation(Role::Security), Ok(5));
        let stop = StopEvidence {
            generation: 5,
            ..stop
        };
        let restart_ticket = t;
        let restart_image = after;
        let t = q.prepare(Change::Isolate(stop), |_| Ok(())).unwrap();
        let after = q.after_image(t).unwrap();
        assert_eq!(
            q.confirm(
                restart_ticket,
                receipt(restart_ticket, 2),
                &restart_image,
                |_, _| panic!("old service receipt")
            ),
            Err(Error::Busy)
        );
        assert_eq!(q.service_generation(Role::Security), Err(Error::Busy));
        q.confirm(t, receipt(t, 3), &after, |_, _| Ok(())).unwrap();
        assert_eq!(
            q.service_generation(Role::Security),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            q.prepare(Change::Restart(stop), |_| panic!("isolated")),
            Err(Error::Unauthorized)
        );
        let mut bad = slots();
        bad[1].slot = bad[0].slot;
        assert!(DurableEpochGate::recovered(&old, bad, |_| Ok(())).is_err());
    }
}
