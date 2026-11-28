//! Replay one independently authorized protection admission and settlement.
//! Cold replay restores receipt custody while the live write gate stays closed.

use super::{BLOCK, Error, RedoTransaction, SuperblockV1};
use crate::security::{
    epoch_redo_v0199::EpochBlockIo,
    file_media_unified_v1::{
        SNAP_CONTROL_CACHE_KIB, SNAP_OP_FREEZE_SET, SNAP_OP_OPEN_WRITES, SNAPSHOT_CATALOG_BLOCK,
        SNAPSHOT_PROTECTION_BLOCK, SNAPSHOT_REQUEST_START,
        catalog_candidate::CatalogEntry,
        protection_candidate::{ProtectionRecord, RestorePhase},
        request_store::{
            RECORD_BYTES, RequestRecord, RequestState, RequestStoreHeader, record_location,
            record_partition,
        },
    },
    file_mount_v1::MountedSnapshots,
    snapshot_protection_tx_v1::frozen_protection,
    snapshot_service_v4::{FileReqKey, Operation, RECOVERY_SLOT},
};
use sha2::{Digest, Sha256};

// BEGIN, two two-block REDO images, COMMIT.
const GROUP_BLOCKS: u32 = 1 + 2 * 2 + 1;
// The reassertion changes no raw request or header bytes.
const RESUME_BLOCKS: u32 = 1 + 2 + 1;
type Page = [u8; BLOCK];

struct Admission {
    header: Option<RequestStoreHeader>,
    pending: RequestRecord,
    record_home: u32,
    record_offset: usize,
    prior_page_digest: [u8; 32],
    pending_page_digest: [u8; 32],
}

struct Settlement {
    terminal: RequestRecord,
    page_digest: [u8; 32],
}

struct Effect {
    settlement: Settlement,
    protection: ProtectionRecord,
}

enum ImagePrefix {
    Header(RequestStoreHeader),
    Admission(Admission),
    Settlement(Settlement),
    Effect(Effect),
}

/// The verified journal's observer owns a single staged prefix. Exact active
/// and retired log geometry is still checked by the surrounding journal.
#[derive(Default)]
pub struct ProtectionReplay {
    prefix: Option<ImagePrefix>,
    admission: Option<(Admission, bool)>,
    effect: Option<(Effect, bool)>,
    settlement_blocked: bool,
}

const _: () = assert!(
    core::mem::size_of::<ProtectionReplay>() + core::mem::size_of::<MountedSnapshots>()
        <= SNAP_CONTROL_CACHE_KIB as usize * 1024
);

impl ProtectionReplay {
    pub const fn is_snapshot_home(home: u32) -> bool {
        home >= SNAPSHOT_CATALOG_BLOCK && home <= SNAPSHOT_PROTECTION_BLOCK
    }

    pub const fn in_progress(&self) -> bool {
        self.prefix.is_some()
    }

    pub const fn touched(&self) -> bool {
        self.admission.is_some() || self.in_progress()
    }

    pub fn role_restart(&mut self) -> Result<(), Error> {
        if self.in_progress() {
            return Err(Error::Conflict);
        }
        if self.admission.is_some() && self.effect.is_none() {
            self.settlement_blocked = true;
        }
        Ok(())
    }

    pub fn committed_operation(&self) -> Option<(u16, u64)> {
        self.effect
            .as_ref()
            .filter(|(_, committed)| *committed)
            .map(|(effect, _)| {
                let receipt = effect.settlement.terminal;
                (receipt.operation, receipt.commit_lsn)
            })
    }

    pub fn image(
        &mut self,
        tx: RedoTransaction,
        index: u32,
        home: u32,
        page: &Page,
        principal_generation: u64,
    ) -> Result<(), Error> {
        if !matches!(tx.log_blocks, GROUP_BLOCKS | RESUME_BLOCKS)
            || self.effect.is_some()
            || self.settlement_blocked
        {
            return Err(Error::Unauthorized);
        }
        self.prefix =
            Some(match (index, self.prefix.take(), &self.admission) {
                (0, None, None)
                    if tx.log_blocks == GROUP_BLOCKS && home == SNAPSHOT_REQUEST_START =>
                {
                    let header = RequestStoreHeader::decode(page)?.ok_or(Error::Conflict)?;
                    if header.fs_uuid != tx.fs_uuid || header.generation <= 1 {
                        return Err(Error::Conflict);
                    }
                    ImagePrefix::Header(header)
                }
                (0, None, None) if tx.log_blocks == RESUME_BLOCKS => ImagePrefix::Admission(
                    read_admission(tx.fs_uuid, None, home, page, principal_generation)?,
                ),
                (1, Some(ImagePrefix::Header(header)), None) => ImagePrefix::Admission(
                    read_admission(tx.fs_uuid, Some(header), home, page, principal_generation)?,
                ),
                (0, None, Some((admission, true)))
                    if tx.log_blocks == GROUP_BLOCKS && home == admission.record_home =>
                {
                    let at = admission.record_offset;
                    let row = RequestRecord::decode(&page[at..at + RECORD_BYTES])?;
                    admission.pending.permits_transition(&row)?;
                    if row.state != RequestState::Done
                        || (row.key.fs_uuid, row.log_epoch, row.txid, row.commit_lsn)
                            != (tx.fs_uuid, tx.log_epoch, tx.txid, tx.commit_lsn)
                    {
                        return Err(Error::Conflict);
                    }
                    // Only the admitted row can change. All seven sibling
                    // receipts, including retired ones, keep their exact bytes.
                    let mut pending = [0; RECORD_BYTES];
                    admission.pending.encode(&mut pending)?;
                    if row_digest(page, at, &pending) != admission.pending_page_digest {
                        return Err(Error::Conflict);
                    }
                    ImagePrefix::Settlement(Settlement {
                        terminal: row,
                        page_digest: digest(page),
                    })
                }
                (1, Some(ImagePrefix::Settlement(settlement)), Some((admission, true)))
                    if home == SNAPSHOT_PROTECTION_BLOCK =>
                {
                    let protection = ProtectionRecord::decode(page)?;
                    let terminal = settlement.terminal;
                    let (prior_generation, restore) = protection_binding(&admission.pending)?;
                    let result_generation =
                        u64::from_le_bytes(terminal.payload()[..8].try_into().unwrap());
                    let cleanup = u32::from_le_bytes(terminal.payload()[8..12].try_into().unwrap());
                    if protection.fs_uuid != tx.fs_uuid
                        || protection.object_generation <= 1
                        || prior_generation.checked_add(1) != Some(protection.protection_generation)
                        || protection.protection_generation != result_generation
                        || u32::from(protection.cleanup_frozen) != cleanup
                    {
                        return Err(Error::Conflict);
                    }
                    if restore.is_some() {
                        if !protection.writes_open
                            || protection.restore_phase != RestorePhase::Idle
                            || protection.live_view_epoch != terminal.new_live_view_epoch
                            || protection.reopen_proof_digest != terminal.result_digest
                        {
                            return Err(Error::Conflict);
                        }
                    } else if !protection.cleanup_frozen
                        || protection.writes_open
                        || protection.restore_phase == RestorePhase::Prepared
                    {
                        return Err(Error::Conflict);
                    }
                    ImagePrefix::Effect(Effect {
                        settlement,
                        protection,
                    })
                }
                _ => return Err(Error::Unauthorized),
            });
        Ok(())
    }

    pub fn finish(&mut self, committed: bool, retiring: bool) -> Result<(), Error> {
        match self.prefix.take() {
            None => {}
            Some(ImagePrefix::Admission(admission)) => {
                self.admission = Some((admission, committed))
            }
            Some(ImagePrefix::Effect(effect)) => self.effect = Some((effect, committed)),
            Some(ImagePrefix::Header(_)) if !committed => {}
            Some(ImagePrefix::Settlement(settlement))
                if !committed && settlement.terminal.operation == SNAP_OP_FREEZE_SET => {}
            // An obsolete, already checkpointed extent can have lost part
            // of its newest transaction during backwards retirement.
            Some(_) if retiring && !committed => {}
            Some(_) => {
                return Err(if committed {
                    Error::Conflict
                } else {
                    Error::Unknown
                });
            }
        }
        Ok(())
    }

    /// Verify a committed overlay against the protected prior checkpoint and
    /// its retained RESTORE result. On a cut during checkpoint the raw homes
    /// can be either prior or the exact committed after-images. Prepared
    /// after-images never qualify as either kind of committed home.
    pub fn verify(
        &self,
        io: &mut impl EpochBlockIo,
        checkpoint: SuperblockV1,
        mounted: Option<&MountedSnapshots>,
        page: &mut Page,
    ) -> Result<(), Error> {
        let Some((admission, admitted)) = &self.admission else {
            return Ok(());
        };
        let mounted = mounted.ok_or(Error::Conflict)?;
        let (generation, restore_key) = protection_binding(&admission.pending)?;
        if mounted.writes_open() {
            return Err(Error::Conflict);
        }

        io.read(SNAPSHOT_REQUEST_START, page)?;
        let materialized = RequestStoreHeader::decode(page)?.ok_or(Error::Conflict)?;
        if let Some(header) = admission.header {
            let mut prior = header;
            prior.generation -= 1;
            prior.watermarks[RECOVERY_SLOT as usize].highest_accepted_seq -= 1;
            if materialized != prior && (!*admitted || materialized != header) {
                return Err(Error::Conflict);
            }
        } else {
            let key = admission.pending.key;
            let mark = materialized.watermarks[RECOVERY_SLOT as usize];
            if materialized.fs_uuid != key.fs_uuid
                || materialized.generation <= 1
                || mark.client_generation != key.client_generation
                || mark.highest_accepted_seq != key.request_seq
            {
                return Err(Error::Conflict);
            }
        }

        io.read(admission.record_home, page)?;
        let physical = digest(page);
        let committed_effect = self.effect.as_ref().filter(|(_, committed)| *committed);
        let prior = admission.header.is_some() && physical == admission.prior_page_digest;
        let pending_exists = *admitted || admission.header.is_none();
        if !prior
            && !(pending_exists && physical == admission.pending_page_digest)
            && !committed_effect
                .is_some_and(|(effect, _)| effect.settlement.page_digest == physical)
        {
            return Err(Error::Conflict);
        }

        let visible = mounted.protection.ok_or(Error::Conflict)?;
        if mounted.requests.nonterminal != usize::from(pending_exists && committed_effect.is_none())
        {
            return Err(Error::Conflict);
        }
        io.read(SNAPSHOT_PROTECTION_BLOCK, page)?;
        let materialized = ProtectionRecord::decode(page)?;
        let Some(restore_key) = restore_key else {
            let effect = self.effect.as_ref().map(|(effect, _)| effect.protection);
            let expected = committed_effect.map_or(materialized, |(effect, _)| effect.protection);
            if visible != expected || mounted.has_open_proof() {
                return Err(Error::Conflict);
            }
            if committed_effect.is_some() && materialized == expected {
                return Ok(());
            }
            let frozen = frozen_protection(materialized).map_err(|_| Error::Conflict)?;
            if materialized.protection_generation != generation
                || effect.is_some_and(|after| frozen != after)
            {
                return Err(Error::Conflict);
            }
            return Ok(());
        };

        let catalog = mounted.catalog.as_ref().ok_or(Error::Conflict)?;
        let restore = mounted.completed_restore().ok_or(Error::Conflict)?;
        let source = restore.snapshot_key.ok_or(Error::Conflict)?;
        if restore.key != restore_key
            || restore.new_live_view_epoch != admission.pending.old_live_view_epoch
            || restore.commit_lsn > checkpoint.checkpoint_lsn
            || restore.log_epoch >= checkpoint.log_epoch
            || !catalog.has_periodic_coverage()
            || !matches!(catalog.entries.get(source.slot as usize),
                Some(CatalogEntry::Active(entry))
                    if entry.identity.snapshot_id == source.snapshot_id
                        && entry.identity.slot_generation == source.slot_generation)
        {
            return Err(Error::Conflict);
        }
        let (prior, changed) = if let Some((effect, _)) = &self.effect {
            let mut prior = effect.protection;
            prior.object_generation -= 1;
            prior.protection_generation = generation;
            prior.restore_phase = RestorePhase::RestoredFrozen;
            prior.writes_open = false;
            prior.restore_obligation_digest = restore.result_digest;
            prior.reopen_proof_digest = [0; 32];
            (prior, Some(effect.protection))
        } else {
            (visible, None)
        };
        let expected = committed_effect.map_or(prior, |(effect, _)| effect.protection);
        if visible != expected
            || prior.live_view_epoch != restore.new_live_view_epoch
            || prior.protection_generation != generation
            || prior.restore_phase != RestorePhase::RestoredFrozen
            || prior.restore_obligation_digest != restore.result_digest
            || mounted.has_open_proof() != committed_effect.is_some()
        {
            return Err(Error::Conflict);
        }
        if materialized != prior && (committed_effect.is_none() || Some(materialized) != changed) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

fn digest(page: &Page) -> [u8; 32] {
    Sha256::digest(page).into()
}

fn row_digest(page: &Page, at: usize, row: &[u8; RECORD_BYTES]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(&page[..at]);
    digest.update(row);
    digest.update(&page[at + RECORD_BYTES..]);
    digest.finalize().into()
}

fn protection_binding(record: &RequestRecord) -> Result<(u64, Option<FileReqKey>), Error> {
    if record.state != RequestState::Pending
        || !matches!(record.operation, SNAP_OP_FREEZE_SET | SNAP_OP_OPEN_WRITES)
    {
        return Err(Error::Unauthorized);
    }
    match Operation::decode(record.operation, record.payload())? {
        Operation::FreezeSet {
            protection_generation,
            ..
        } => Ok((protection_generation, None)),
        Operation::OpenWrites {
            protection_generation,
            restore,
        } => Ok((protection_generation, Some(restore))),
        _ => Err(Error::Unauthorized),
    }
}

fn read_admission(
    fs_uuid: [u8; 16],
    header: Option<RequestStoreHeader>,
    home: u32,
    page: &Page,
    principal_generation: u64,
) -> Result<Admission, Error> {
    let first = record_partition(RECOVERY_SLOT).ok_or(Error::Invalid)?.start;
    if record_location(first)?.0 != home {
        return Err(Error::Unauthorized);
    }
    let mark = header.map(|header| header.watermarks[RECOVERY_SLOT as usize]);
    let mut pending = None;
    for (at, bytes) in page.chunks_exact(RECORD_BYTES).enumerate() {
        if bytes.iter().all(|&byte| byte == 0) {
            continue;
        }
        let record = RequestRecord::decode(bytes)?;
        if record.key.fs_uuid != fs_uuid || record.key.client_slot != RECOVERY_SLOT {
            return Err(Error::Unauthorized);
        }
        if !record.state.terminal() {
            protection_binding(&record)?;
            if record.key.client_generation != principal_generation
                || mark.is_some_and(|mark| {
                    record.key.client_generation != mark.client_generation
                        || record.key.request_seq != mark.highest_accepted_seq
                })
                || header.is_none() && record.operation != SNAP_OP_FREEZE_SET
                || pending.replace((record, at * RECORD_BYTES)).is_some()
            {
                return Err(Error::Conflict);
            }
        }
    }
    let (pending, record_offset) = pending.ok_or(Error::Conflict)?;
    Ok(Admission {
        header,
        pending,
        record_home: home,
        record_offset,
        prior_page_digest: row_digest(page, record_offset, &[0; RECORD_BYTES]),
        pending_page_digest: digest(page),
    })
}
