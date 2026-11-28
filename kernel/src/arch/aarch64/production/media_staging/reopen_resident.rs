//! Authenticate each resident redo scope before replay or retirement.

use super::super::role_restart;
use super::{
    BootLogRecovery, BootPolicy, Disk, Policies, authority, verify_replay_homes, volume, workspace,
};
use cyxia_kernel_core::security::{
    Error,
    boot_epoch_v1::{BootEpochStoreV1, TlsBootPolicy},
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::{BLOCK_BYTES as BLOCK, SecurityStateStoreV2},
    file_media_unified_v1::{
        ACL_INODE, BASELINE_SYSTEM_BLOCKS, BOOT_INODE, BUSINESS_INODES, CANONICAL_BUSINESS_START,
        CATALOG_INODE, PROTECTION_INODE, RECEIPTS_INODE, REQUEST_INODE, SECURITY_INODE, SLOT_INODE,
    },
    file_media_v0199::{BITMAP_START, DATA_START, INODE_START, SuperblockV1},
    file_mount_v1::{Acl, MountEvidence},
    file_structure_v1::{INODE_BYTES, INODES},
    offline_config_v1::Principal,
    recovery_proof_store::RecoveryLocator,
    recovery_v1::{
        RedoTransaction,
        resident::{Journal, Record, head_epoch},
    },
};

const RECEIPTS: u32 = volume::RECEIPTS_HOME;
const ACL: u32 = RECEIPTS + 7;
const ACL_BYTES: usize = 64;
const BUSINESS_INODE_PAGES: u32 = BUSINESS_INODES / (BLOCK / INODE_BYTES) as u32;
const ACL_PAGES: u32 = (INODES * ACL_BYTES / BLOCK) as u32;
const SYSTEM_RIGHTS: u32 = (1 << 8) | (1 << 9) | (1 << 13);

type Recovered = (SuperblockV1, MountEvidence, BootLogRecovery);

pub(super) fn reconcile(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    policies: &Policies<'_>,
    snapshots: volume::SnapshotLayout,
    locator: Option<RecoveryLocator>,
) -> Result<Option<Recovered>, Error> {
    let mut raw = [0; BLOCK];
    disk.read(volume::FIRST_LOG_BLOCK, &mut raw)?;
    let Some(epoch) = head_epoch(&raw)? else {
        // Retain the previous boot-only compatibility path for volumes
        // interrupted by older forward retirement of the six-block pair.
        return Ok(None);
    };
    if epoch != checkpoint.log_epoch && epoch.checked_add(1) != Some(checkpoint.log_epoch) {
        return Err(Error::Conflict);
    }
    let expected = volume::read_checkpoint_for(
        disk,
        &mut raw,
        policies.current.config(),
        volume::Checkpoints::Resident,
    )?;
    if checkpoint != expected {
        return Err(Error::Conflict);
    }
    volume::verify_resident_layout(disk, checkpoint, snapshots)?;
    let carrier = locator
        .map(|locator| Carrier::read(disk, locator, &mut raw))
        .transpose()?;
    disk.read(volume::SECURITY_HOME, &mut raw)?;
    let physical = SecurityStateStoreV2::decode(&raw)?;
    if epoch != checkpoint.log_epoch {
        disk.read((checkpoint.generation & 1) as u32, &mut raw)?;
        let prior = SuperblockV1::decode(&raw)?;
        let policy = resident_policy(policies, &physical, prior.generation)?;
        let mounted = volume::validate_resident_homes_for_layout(
            disk,
            checkpoint,
            prior.generation,
            policy,
            snapshots,
        )?;
        let mut chain = Chain::new(prior, policies, snapshots, carrier);
        // SAFETY: synchronous cold staging alone owns the recovery workspace.
        let verified =
            Journal::inspect(disk, unsafe { workspace() }, checkpoint, Some(prior), |r| {
                chain.observe(r)
            })?;
        if let Some(state) = chain.current {
            let missing_lsns = checkpoint.checkpoint_lsn - verified.evidence().last_commit_lsn;
            if !mounted.security.no_rollback_from(&state)
                || mounted.security.state_generation - state.state_generation > missing_lsns / 3
                || missing_lsns == 0 && mounted.security != state
            {
                return Err(Error::Conflict);
            }
        }
        verified.retire_checkpointed()?;
        return Ok(Some((
            checkpoint,
            mounted,
            BootLogRecovery::RetiredCheckpointed,
        )));
    }
    let base = match authority::recovery_log_for(disk, checkpoint, |epoch, state| {
        policies.policy_for(state, epoch).map(|_| ())
    }) {
        Ok(authority::BootLog::Committed(base)) => base,
        // BootPair preparation uses its existing exact old/new policy
        // reconciliation. Never classify an uncertain read as preparation.
        Err(Error::Invalid | Error::Conflict | Error::Stale) => return Ok(None),
        Err(error) => return Err(error),
        Ok(_) => return Err(Error::Conflict),
    };
    let policy = resident_policy(policies, &base, checkpoint.generation)?;
    let mut chain = Chain::new(checkpoint, policies, snapshots, carrier);
    // Read-only inspection bounds every allowed home in every transaction,
    // including preparations and images overwritten later in the chain.
    let mut journal = Journal::inspect(disk, unsafe { workspace() }, checkpoint, None, |record| {
        chain.observe(record)
    })?;
    let committed = chain.current.ok_or(Error::Conflict)?;
    let before = checkpoint.generation - 1;
    let old_policy = if physical == committed || physical == base {
        BootPolicy::Resident(policy)
    } else {
        policies.policy_for(&physical, before)?
    };
    let old = old_policy.state(before, &base)?;
    if !committed.no_rollback_from(&old)
        || physical != committed && physical != base && physical != old
    {
        return Err(Error::Stale);
    }
    verify_replay_homes(&mut journal.raw_view(), &old, &committed)?;

    let next = SuperblockV1 {
        generation: checkpoint
            .generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?,
        log_epoch: checkpoint
            .log_epoch
            .checked_add(1)
            .ok_or(Error::Exhausted)?,
        checkpoint_lsn: journal.evidence().last_commit_lsn,
        ..checkpoint
    };
    let preflight = volume::validate_resident_homes_for_layout(
        &mut journal.view(),
        next,
        checkpoint.generation,
        policy,
        snapshots,
    )?;
    if preflight.security != committed
        || chain.file_changed && !preflight.permits_replay_of_file_writes()
    {
        return Err(Error::Conflict);
    }
    if snapshots.signed_unified() {
        journal.check_home_targets(|home| {
            if home >= CANONICAL_BUSINESS_START && volume::resident_history_owns(home) {
                return Err(Error::Unauthorized);
            }
            Ok(())
        })?;
    }
    volume::verify_resident_receipt_commits(checkpoint, |slot, receipt| {
        journal.verify_receipt(RECEIPTS, slot, receipt)
    })?;
    let selected = journal.checkpoint(|disk, former| {
        if former != checkpoint {
            return Err(Error::Conflict);
        }
        let mounted = volume::validate_resident_homes_for_layout(
            disk,
            next,
            checkpoint.generation,
            policy,
            snapshots,
        )?;
        if mounted != preflight {
            return Err(Error::Conflict);
        }
        Ok(())
    })?;
    if selected != next {
        return Err(Error::Conflict);
    }
    Ok(Some((next, preflight, BootLogRecovery::Replayed)))
}

fn resident_policy<'a>(
    policies: &Policies<'a>,
    state: &SecurityStateStoreV2,
    epoch: u64,
) -> Result<TlsBootPolicy<'a>, Error> {
    match policies.policy_for(state, epoch)? {
        BootPolicy::Resident(policy) => Ok(policy),
        #[cfg(not(cyxia_startup_catalog))]
        BootPolicy::Staging(_) => Err(Error::Conflict),
    }
}

struct Carrier {
    locator: RecoveryLocator,
    inode: [u8; INODE_BYTES],
    acl: [u8; ACL_BYTES],
}

impl Carrier {
    fn read(
        io: &mut impl EpochBlockIo,
        locator: RecoveryLocator,
        raw: &mut [u8; BLOCK],
    ) -> Result<Self, Error> {
        let (block, offset) = locate(locator.inode_slot(), INODE_START, INODE_BYTES);
        io.read(block, raw)?;
        let inode = raw[offset..offset + INODE_BYTES].try_into().unwrap();
        let (block, offset) = locate(locator.inode_slot(), ACL, ACL_BYTES);
        io.read(block, raw)?;
        let acl: [u8; ACL_BYTES] = raw[offset..offset + ACL_BYTES].try_into().unwrap();
        locator.verify_file_metadata(&inode, &acl)?;
        Ok(Self {
            locator,
            inode,
            acl,
        })
    }

    fn authorize(&self, block: u32, contents: &[u8; BLOCK]) -> Result<(), Error> {
        if self.locator.physical_blocks().contains(&block) {
            return Err(Error::Unauthorized);
        }
        for (base, entry) in [(INODE_START, &self.inode[..]), (ACL, &self.acl[..])] {
            let (home, offset) = locate(self.locator.inode_slot(), base, entry.len());
            if block == home && contents[offset..offset + entry.len()] != *entry {
                return Err(Error::Unauthorized);
            }
        }
        let page_bits = 8 * BLOCK as u32;
        for carrier in self.locator.physical_blocks() {
            let bit = (carrier % page_bits) as usize;
            if block == BITMAP_START + carrier / page_bits
                && contents[bit / 8] & (1 << (bit % 8)) == 0
            {
                return Err(Error::Unauthorized);
            }
        }
        Ok(())
    }
}

fn locate(inode: u32, first: u32, bytes: usize) -> (u32, usize) {
    let at = inode as usize * bytes;
    (first + (at / BLOCK) as u32, at % BLOCK)
}

struct Chain<'a, 'p> {
    checkpoint: SuperblockV1,
    policies: &'p Policies<'a>,
    unified: bool,
    carrier: Option<Carrier>,
    tx: Option<RedoTransaction>,
    current: Option<SecurityStateStoreV2>,
    state: Option<SecurityStateStoreV2>,
    images: u32,
    file_change: bool,
    file_changed: bool,
}

impl<'a, 'p> Chain<'a, 'p> {
    fn new(
        checkpoint: SuperblockV1,
        policies: &'p Policies<'a>,
        snapshots: volume::SnapshotLayout,
        carrier: Option<Carrier>,
    ) -> Self {
        Self {
            checkpoint,
            policies,
            unified: snapshots.signed_unified(),
            carrier,
            tx: None,
            current: None,
            state: None,
            images: 0,
            file_change: false,
            file_changed: false,
        }
    }

    fn observe(&mut self, record: Record<'_>) -> Result<(), Error> {
        match record {
            Record::Begin(tx) => {
                if self.current.is_none() && tx.log_blocks != authority::BOOT_LOG_BLOCKS {
                    return Err(Error::Conflict);
                }
                self.images = 0;
                self.state = None;
                self.file_change = false;
                self.tx = Some(tx);
            }
            Record::Image { home, contents } => {
                let tx = self.tx.ok_or(Error::Conflict)?;
                match self.current {
                    None => self.boot_image(home, contents)?,
                    Some(current) if home == volume::SECURITY_HOME && tx.log_blocks == 4 => {
                        let next = SecurityStateStoreV2::decode(contents)?;
                        role_restart::verify_successor(current, next)?;
                        self.state = Some(next);
                    }
                    Some(_) => self.file_image(home, contents)?,
                }
                self.images += 1;
            }
            Record::End { committed } => {
                if committed {
                    self.current = self.state.or(self.current);
                    self.file_changed |= self.file_change;
                }
                self.tx = None;
            }
        }
        Ok(())
    }

    fn boot_image(&mut self, home: u32, contents: &[u8; BLOCK]) -> Result<(), Error> {
        match (self.images, home) {
            (0, volume::SECURITY_HOME) => {
                let state = SecurityStateStoreV2::decode(contents)?;
                self.policies
                    .policy_for(&state, self.checkpoint.generation)?;
                self.state = Some(state);
            }
            (1, volume::BOOT_HOME) => {
                if !BootEpochStoreV1::decode(contents)?.matches(&self.state.ok_or(Error::Conflict)?)
                {
                    return Err(Error::Conflict);
                }
            }
            _ => return Err(Error::Conflict),
        }
        Ok(())
    }

    fn file_image(&mut self, home: u32, contents: &[u8; BLOCK]) -> Result<(), Error> {
        if let Some(carrier) = &self.carrier {
            carrier.authorize(home, contents)?;
        }
        if (RECEIPTS..ACL).contains(&home) {
            return Ok(());
        }
        self.file_change = true;
        if (BITMAP_START..INODE_START).contains(&home) {
            return self.bitmap(home, contents);
        }
        if (ACL..ACL + ACL_PAGES).contains(&home) {
            return self.acl(home, contents);
        }
        if (INODE_START..INODE_START + BUSINESS_INODE_PAGES).contains(&home)
            || home >= CANONICAL_BUSINESS_START
        {
            return Ok(());
        }
        // Boot, SecurityState, immutable inode rows, and the four snapshot
        // objects have their own protected owners.
        Err(Error::Unauthorized)
    }

    fn bitmap(&self, home: u32, contents: &[u8; BLOCK]) -> Result<(), Error> {
        if home != BITMAP_START {
            return Ok(());
        }
        let limit = if self.unified {
            CANONICAL_BUSINESS_START
        } else {
            DATA_START + BASELINE_SYSTEM_BLOCKS
        } as usize;
        for bit in 0..CANONICAL_BUSINESS_START as usize {
            if (contents[bit / 8] & (1 << (bit % 8)) != 0) != (bit < limit) {
                return Err(Error::Unauthorized);
            }
        }
        Ok(())
    }

    fn acl(&self, home: u32, contents: &[u8; BLOCK]) -> Result<(), Error> {
        let first = (home - ACL) as usize * BLOCK / ACL_BYTES;
        let owner = self
            .policies
            .current
            .config()
            .ok_or(Error::Unauthorized)?
            .principals()[0];
        for (offset, entry) in contents.chunks_exact(ACL_BYTES).enumerate() {
            let slot = (first + offset) as u16;
            if u32::from(slot) < BUSINESS_INODES {
                continue;
            }
            let live = matches!(
                slot,
                BOOT_INODE | RECEIPTS_INODE | ACL_INODE | SECURITY_INODE
            ) || self.unified
                && matches!(
                    slot,
                    CATALOG_INODE | SLOT_INODE | REQUEST_INODE | PROTECTION_INODE
                );
            let expected = Acl {
                inode_id: u32::from(slot),
                state: u32::from(live),
                inode_generation: u64::from(live),
                principal: if live {
                    owner
                } else {
                    Principal {
                        id: 0,
                        generation: 0,
                    }
                },
                owner_rights: 0,
                system_rights: if live { SYSTEM_RIGHTS } else { 0 },
                acl_generation: u64::from(live),
                parent: 0,
            };
            if Acl::decode(entry)? != expected {
                return Err(Error::Unauthorized);
            }
        }
        Ok(())
    }
}
