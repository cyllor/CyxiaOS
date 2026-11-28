//! Exact, exclusively owned resident journal and interruption-safe retirement.

use super::{
    BLOCK, END, EpochBlockIo, Error, FIRST, Header, OLD_CONTINUATION, OLD_RECORD, RecoveryEvidence,
    RecoveryWorkspace, RedoTransaction, RedoWriter, Row, Sha256, SuperblockV1, after_image_home,
    begin_count, checkpoint_scanned, has_later_log_header, hash, read_exact_image, read_record,
    read_record_with_preparation, same_superblocks, u16at, u32at, u64at, verify_commit,
};
use crate::security::{
    file_index_v0199::{FileStreamIndexV4, STREAMS_PER_GROUP},
    file_media_v0199::{BLOCK_COUNT, FileReceiptV4, RECEIPT_BYTES, probe_snapshot_media_pair},
    file_receipt_store_v0199::{RECEIPT_STORE_BYTES, home_closure},
};
use sha2::Digest;

#[path = "snapshot.rs"]
pub mod snapshot;

/// Classify the first block before selecting the active or checkpointed
/// inspection path. The entire extent is independently verified by inspect.
pub fn head_epoch(raw: &[u8; BLOCK]) -> Result<Option<u64>, Error> {
    if raw.iter().all(|&byte| byte == 0) {
        return Ok(None);
    }
    if u32at(raw, 0) != super::MAGIC || u16at(raw, 6) != 1 || !has_later_log_header(raw, 0) {
        return Err(Error::Conflict);
    }
    Ok(Some(u64at(raw, 32)))
}

/// A structurally verified transaction cursor and the complete images on its
/// exact contiguous extent. A preparation has no COMMIT and is never replayed.
pub enum Record<'a> {
    Begin(RedoTransaction),
    Image {
        home: u32,
        contents: &'a [u8; BLOCK],
    },
    End {
        committed: bool,
    },
}

pub struct Journal<'a, I> {
    io: &'a mut I,
    work: &'a mut RecoveryWorkspace,
    checkpoint: SuperblockV1,
    extent_end: u32,
    preparation: Option<u32>,
    retired: bool,
}

impl<'a, I: EpochBlockIo> Journal<'a, I> {
    /// The selected checkpoint is independently authorized by the caller.
    /// If `prior` is supplied, the extent is obsolete and this session can
    /// only retire it. Visit every available image before any media mutation.
    pub fn inspect(
        io: &'a mut I,
        work: &'a mut RecoveryWorkspace,
        checkpoint: SuperblockV1,
        prior: Option<SuperblockV1>,
        mut observe: impl FnMut(Record<'_>) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        work.evidence = None;
        work.count = 0;
        work.obsolete.fill(0);
        work.resident_begins.fill(0);
        io.read(0, &mut work.first)?;
        io.read(1, &mut work.second)?;
        let selected = probe_snapshot_media_pair(&work.first, &work.second)?;
        let first = SuperblockV1::decode(&work.first)?;
        let second = SuperblockV1::decode(&work.second)?;
        work.selected = u32::from(first.generation < second.generation);
        let (actual, former) = if work.selected == 0 {
            (first, second)
        } else {
            (second, first)
        };
        if actual != checkpoint
            || selected.generation != checkpoint.generation
            || prior.is_some_and(|prior| prior != former || prior == checkpoint)
        {
            return Err(Error::Conflict);
        }
        let base = prior.unwrap_or(checkpoint);
        let mut at = FIRST;
        let mut last_lsn = base.checkpoint_lsn;
        let mut txid = base.generation;
        let mut transactions = 0;
        let mut preparation = None;
        let mut extent_end = FIRST;
        'chain: while at < END {
            let Some(begin) = exact_record(io, at, base.log_epoch, &mut work.raw)? else {
                require_zero(io, at + 1, (&mut work.raw[..BLOCK]).try_into().unwrap())?;
                break;
            };
            if begin.kind != 1 || begin.txid != txid || last_lsn.checked_add(1) != Some(begin.lsn) {
                return Err(Error::Conflict);
            }
            let count = begin_count(&work.raw)?;
            let commit_at = at + 1 + 2 * count as u32;
            let commit_lsn = begin
                .lsn
                .checked_add(count as u64 + 1)
                .ok_or(Error::Exhausted)?;
            if commit_at >= END || prior.is_some() && commit_lsn > checkpoint.checkpoint_lsn {
                return Err(Error::Conflict);
            }
            observe(Record::Begin(RedoTransaction {
                fs_uuid: base.fs_uuid,
                log_epoch: base.log_epoch,
                txid,
                begin_lsn: begin.lsn,
                commit_lsn,
                first_log_block: at,
                log_blocks: commit_at + 1 - at,
            }))?;
            work.obsolete[(at - FIRST) as usize] = OLD_RECORD;
            let mut ordered = Sha256::new();
            for i in 0..count {
                let pos = at + 1 + 2 * i as u32;
                let Some((redo, missing_continuation)) =
                    read_record_with_preparation(io, pos, &mut work.raw, true)?
                else {
                    if work.raw[..BLOCK].iter().any(|&byte| byte != 0) {
                        return Err(Error::Conflict);
                    }
                    // The first block of a two-block record is erased first.
                    // Without it the payload tail supplies no home authority.
                    let tail: &mut [u8; BLOCK] = (&mut work.raw[..BLOCK]).try_into().unwrap();
                    io.read(pos + 1, tail)?;
                    if tail[64..].iter().any(|&byte| byte != 0)
                        || has_later_log_header(tail, base.log_epoch)
                    {
                        return Err(Error::Conflict);
                    }
                    let has_tail = tail[..64].iter().any(|&byte| byte != 0);
                    if has_tail {
                        work.obsolete[(pos + 1 - FIRST) as usize] = OLD_CONTINUATION;
                    }
                    extent_end = if has_tail { pos + 2 } else { pos };
                    require_zero(io, pos + 2, tail)?;
                    preparation = Some(at);
                    observe(Record::End { committed: false })?;
                    break 'chain;
                };
                if redo.kind != 2
                    || redo.txid != begin.txid
                    || redo.epoch != base.log_epoch
                    || has_later_log_header(&work.raw[BLOCK..], redo.epoch)
                    || begin.lsn.checked_add(i as u64 + 1) != Some(redo.lsn)
                {
                    return Err(Error::Conflict);
                }
                let home = after_image_home(&work.raw, i, count)?;
                if work.pending[..i].iter().any(|row| row.home == home) {
                    return Err(Error::Conflict);
                }
                if missing_continuation {
                    // A first-half REDO may survive a cut before its
                    // continuation. No later bytes, including COMMIT, may
                    // survive. There is no complete image to authorize.
                    work.obsolete[(pos - FIRST) as usize] = OLD_RECORD;
                    extent_end = pos + 1;
                    require_zero(io, pos + 2, (&mut work.raw[..BLOCK]).try_into().unwrap())?;
                    preparation = Some(at);
                    observe(Record::End { committed: false })?;
                    break 'chain;
                }
                let contents = work.raw[64..4160].try_into().unwrap();
                observe(Record::Image { home, contents })?;
                ordered.update(u64::from(home).to_le_bytes());
                ordered.update(contents);
                work.pending[i] = Row {
                    home,
                    log: pos,
                    commit_lsn: 0,
                    digest: hash(&work.raw),
                };
                work.obsolete[(pos - FIRST) as usize] = OLD_RECORD;
                work.obsolete[(pos + 1 - FIRST) as usize] = OLD_CONTINUATION;
            }
            let Some(commit) = exact_record(io, commit_at, base.log_epoch, &mut work.raw)? else {
                require_zero(
                    io,
                    commit_at + 1,
                    (&mut work.raw[..BLOCK]).try_into().unwrap(),
                )?;
                extent_end = commit_at;
                preparation = Some(at);
                observe(Record::End { committed: false })?;
                break;
            };
            verify_commit(&work.raw, begin, commit, count, ordered.finalize().into())?;
            observe(Record::End { committed: true })?;
            work.obsolete[(commit_at - FIRST) as usize] = OLD_RECORD;
            if prior.is_none() {
                work.resident_begins[transactions as usize] = at as u16;
                work.publish_rows(count, commit.lsn)?;
            }
            last_lsn = commit.lsn;
            txid = txid.checked_add(1).ok_or(Error::Exhausted)?;
            transactions += 1;
            at = commit_at + 1;
            extent_end = at;
        }
        work.evidence = Some(RecoveryEvidence {
            superblock: checkpoint,
            last_commit_lsn: last_lsn,
            transactions,
            distinct_home_blocks: work.count as u32,
            incomplete_tail: preparation.is_some(),
        });
        Ok(Self {
            io,
            work,
            checkpoint,
            extent_end,
            preparation,
            retired: prior.is_some(),
        })
    }

    pub fn evidence(&self) -> RecoveryEvidence {
        self.work.evidence.expect("verified resident journal")
    }

    /// Hand the clean, current resident extent to its sole append owner.
    /// Inspection already verified both superblocks and the entire suffix.
    pub fn into_writer(self) -> Result<RedoWriter<'a, I>, Error> {
        if self.retired || self.preparation.is_some() || self.work.checkpoint_required {
            return Err(Error::Unknown);
        }
        let transactions = u64::from(self.evidence().transactions);
        self.work.last_txid = self
            .checkpoint
            .generation
            .checked_add(transactions)
            .and_then(|next| next.checked_sub(1))
            .ok_or(Error::Exhausted)?;
        self.work.next_log_block = self.extent_end;
        self.work.retire_after = None;
        self.work.obsolete.fill(0);
        Ok(RedoWriter {
            io: self.io,
            workspace: self.work,
        })
    }

    pub fn view(&mut self) -> impl EpochBlockIo + '_ {
        HomeView {
            journal: self,
            overlay: true,
        }
    }

    pub fn raw_view(&mut self) -> impl EpochBlockIo + '_ {
        HomeView {
            journal: self,
            overlay: false,
        }
    }

    pub fn check_home_targets(
        &self,
        mut verify: impl FnMut(u32) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.work.rows[..self.work.count]
            .iter()
            .try_for_each(|row| verify(row.home))
    }

    /// Prove the active receipt's full bytes are in its own independently
    /// verified transaction, including both halves of a straddling receipt
    /// and the index home. Later appends may have touched the same pages.
    pub fn verify_receipt(
        &mut self,
        receipts_home: u32,
        slot: usize,
        receipt: &FileReceiptV4,
    ) -> Result<(), Error> {
        if self.retired
            || receipt.fs_uuid != self.checkpoint.fs_uuid
            || receipt.log_epoch != self.checkpoint.log_epoch
            || receipt.commit_lsn <= self.checkpoint.checkpoint_lsn
            || receipt.commit_lsn > self.evidence().last_commit_lsn
        {
            return Err(Error::Conflict);
        }
        let ordinal = receipt
            .txid
            .checked_sub(self.checkpoint.generation)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(Error::Conflict)?;
        let first = u32::from(
            *self
                .work
                .resident_begins
                .get(ordinal)
                .ok_or(Error::Conflict)?,
        );
        if first == 0 {
            return Err(Error::Conflict);
        }
        let raw = &mut self.work.raw;
        let begin = exact_record(self.io, first, receipt.log_epoch, raw)?.ok_or(Error::Conflict)?;
        let count = begin_count(raw)?;
        if begin.kind != 1
            || begin.txid != receipt.txid
            || first + 1 + 2 * count as u32 >= END
            || begin.lsn.checked_add(count as u64 + 1) != Some(receipt.commit_lsn)
        {
            return Err(Error::Conflict);
        }
        let closure = home_closure(slot).ok_or(Error::Invalid)?;
        let expected = receipt.encode()?;
        let at = slot * RECEIPT_BYTES % BLOCK;
        let first_len = (BLOCK - at).min(RECEIPT_BYTES);
        let base = u64::from(receipts_home);
        let wanted = [
            (
                base + closure.receipt.first as u64,
                at,
                &expected[..first_len],
            ),
            (
                closure.receipt.second.map_or(0, |page| base + page as u64),
                0,
                &expected[first_len..],
            ),
            (base + (RECEIPT_STORE_BYTES / BLOCK) as u64, 0, &[][..]),
        ];
        let mut seen = if closure.receipt.second.is_none() {
            2
        } else {
            0
        };
        for i in 0..count {
            let block = first + 1 + 2 * i as u32;
            // Only the relevant receipt/stream images need continuation
            // readback. Every record was CRC- and COMMIT-verified in inspect.
            self.io
                .read(block, (&mut raw[..BLOCK]).try_into().unwrap())?;
            let home = u64at(raw, 40);
            let Some((bit, (_, offset, bytes))) = wanted
                .iter()
                .enumerate()
                .find(|(_, (target, _, _))| *target != 0 && *target == home)
            else {
                continue;
            };
            let record =
                exact_record(self.io, block, receipt.log_epoch, raw)?.ok_or(Error::Conflict)?;
            if record.kind != 2
                || record.txid != receipt.txid
                || begin.lsn.checked_add(i as u64 + 1) != Some(record.lsn)
                || u64::from(after_image_home(raw, i, count)?) != home
                || &raw[64 + offset..64 + offset + bytes.len()] != *bytes
            {
                return Err(Error::Conflict);
            }
            if bit == 2 {
                let index = FileStreamIndexV4::decode(&raw[64..4160])?;
                let group = &index.groups[receipt.group_id as usize];
                let stream = &index.streams
                    [receipt.group_id as usize * STREAMS_PER_GROUP + receipt.stream_slot as usize];
                if index.fs_uuid != receipt.fs_uuid
                    || group.flags == 0
                    || stream.flags == 0
                    || group.manifest_principal_id != receipt.owner_principal_id
                    || receipt.group_generation > group.generation
                    || receipt.issued_boot_epoch > group.boot_epoch
                    || receipt.group_generation == group.generation
                        && receipt.issued_boot_epoch != group.boot_epoch
                    || receipt.stream_generation != u64::from(stream.generation)
                    || receipt.request_seq <= stream.retired_through
                    || receipt.request_seq > stream.issued_hi
                {
                    return Err(Error::Conflict);
                }
            }
            seen |= 1 << bit;
            if seen == 7 {
                return Ok(());
            }
        }
        Err(Error::Conflict)
    }

    pub fn checkpoint(
        self,
        verify_post_replay: impl FnOnce(&mut I, SuperblockV1) -> Result<(), Error>,
    ) -> Result<SuperblockV1, Error> {
        let e = self.evidence();
        if self.retired || e.transactions == 0 {
            return Err(Error::Conflict);
        }
        same_superblocks(self.io, self.work)?;
        let committed_end = self.preparation.unwrap_or(self.extent_end);
        retire(
            self.io,
            &self.work.obsolete,
            (&mut self.work.raw[..BLOCK]).try_into().unwrap(),
            committed_end,
            self.extent_end,
        )?;
        // A previous COMMIT's FLUSH response could have been lost.
        self.io.flush().map_err(|_| Error::Unknown)?;
        let (_, next) = checkpoint_scanned(self.io, self.work, verify_post_replay)?;
        retire(
            self.io,
            &self.work.obsolete,
            (&mut self.work.raw[..BLOCK]).try_into().unwrap(),
            FIRST,
            committed_end,
        )?;
        Ok(next)
    }

    pub fn retire_checkpointed(self) -> Result<(), Error> {
        if !self.retired {
            return Err(Error::Conflict);
        }
        same_superblocks(self.io, self.work)?;
        self.io.flush().map_err(|_| Error::Unknown)?;
        retire(
            self.io,
            &self.work.obsolete,
            (&mut self.work.raw[..BLOCK]).try_into().unwrap(),
            FIRST,
            self.extent_end,
        )
    }
}

struct HomeView<'j, 'a, I> {
    journal: &'j mut Journal<'a, I>,
    overlay: bool,
}

impl<I: EpochBlockIo> EpochBlockIo for HomeView<'_, '_, I> {
    fn read(&mut self, home: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
        if home >= BLOCK_COUNT {
            return Err(Error::Invalid);
        }
        let journal = &mut self.journal;
        let work = &mut journal.work;
        if self.overlay
            && let Some(&row) = work.rows[..work.count].iter().find(|row| row.home == home)
        {
            read_exact_image(journal.io, row, journal.checkpoint.log_epoch, &mut work.raw)?;
            out.copy_from_slice(&work.raw[64..4160]);
            Ok(())
        } else {
            journal.io.read(home, out)
        }
    }

    fn write(&mut self, _: u32, _: &[u8; BLOCK]) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }

    fn flush(&mut self) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
}

fn exact_record(
    io: &mut impl EpochBlockIo,
    block: u32,
    epoch: u64,
    raw: &mut [u8; 2 * BLOCK],
) -> Result<Option<Header>, Error> {
    match read_record(io, block, raw)? {
        Some(h)
            if h.epoch == epoch && (h.kind != 2 || !has_later_log_header(&raw[BLOCK..], epoch)) =>
        {
            Ok(Some(h))
        }
        None if raw[..BLOCK].iter().all(|&byte| byte == 0) => Ok(None),
        _ => Err(Error::Conflict),
    }
}

fn require_zero(
    io: &mut impl EpochBlockIo,
    first: u32,
    raw: &mut [u8; BLOCK],
) -> Result<(), Error> {
    for block in first..END {
        io.read(block, raw)?;
        if raw.iter().any(|&byte| byte != 0) {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

/// Retire newest records first, keeping the BEGIN geometry until all its
/// records are gone. A split REDO can leave only its inert payload tail.
fn retire(
    io: &mut impl EpochBlockIo,
    marks: &[u8],
    raw: &mut [u8; BLOCK],
    start: u32,
    mut end: u32,
) -> Result<(), Error> {
    let mut erase = |block| {
        io.write(block, &[0; BLOCK]).map_err(|_| Error::Unknown)?;
        io.flush().map_err(|_| Error::Unknown)?;
        io.read(block, raw).map_err(|_| Error::Unknown)?;
        if raw.iter().any(|&byte| byte != 0) {
            return Err(Error::Unknown);
        }
        Ok(())
    };
    while end > start {
        end -= 1;
        let mark = marks[(end - FIRST) as usize];
        if mark == OLD_CONTINUATION
            && end > start
            && marks[(end - 1 - FIRST) as usize] == OLD_RECORD
        {
            erase(end - 1)?;
            erase(end)?;
            end -= 1;
        } else if mark != 0 {
            erase(end)?;
        }
    }
    Ok(())
}
