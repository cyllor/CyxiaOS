//! Baseline-v1 redo append and mount recovery, §9.3–9.5.
//! The mounted-device owner must exclude all other writers throughout scan,
//! replay, post-replay structural/system validation and checkpoint. A
//! successful scan is not a mount. No ordinary service opens on an I/O
//! error, an ambiguous record, or a failed structural/ACL validation.
use super::{
    Error,
    epoch_redo_v0199::{EpochBlockIo, RedoEncoding},
    file_media_v0199::{
        BITMAP_START, BLOCK_COUNT, SUPER_BYTES as BLOCK, SuperblockV1, crc32c_payload,
        crc32c_zeroed, has_later_log_header, preflight_baseline_log,
    },
};
use sha2::{Digest, Sha256};

const FIRST: u32 = 2;
const END: u32 = BITMAP_START;
const LOG_BLOCKS: usize = (END - FIRST) as usize;
const OLD_RECORD: u8 = 1;
const OLD_CONTINUATION: u8 = 2;
const MAX_REDO: usize = 128;
// Each REDO occupies two physical blocks. Includes metadata afterimages.
const MAX_HOME: usize = ((END - FIRST) / 2) as usize;
const MAGIC: u32 = 0x43594c47;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Header {
    kind: u16,
    txid: u64,
    lsn: u64,
    epoch: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Row {
    home: u32,
    log: u32,
    commit_lsn: u64,
    digest: [u8; 32],
}
const EMPTY: Row = Row {
    home: 0,
    log: 0,
    commit_lsn: 0,
    digest: [0; 32],
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryEvidence {
    pub superblock: SuperblockV1,
    pub last_commit_lsn: u64,
    pub transactions: u32,
    pub distinct_home_blocks: u32,
    pub incomplete_tail: bool,
}
pub struct RecoveryWorkspace {
    rows: [Row; MAX_HOME],
    pending: [Row; MAX_REDO],
    count: usize,
    raw: [u8; 2 * BLOCK],
    first: [u8; BLOCK],
    second: [u8; BLOCK],
    evidence: Option<RecoveryEvidence>,
    selected: u32,
    next_log_block: u32,
    last_txid: u64,
    checkpoint_required: bool,
    retire_after: Option<SuperblockV1>,
    obsolete: [u8; LOG_BLOCKS],
}
impl RecoveryWorkspace {
    pub const fn new() -> Self {
        Self {
            rows: [EMPTY; MAX_HOME],
            pending: [EMPTY; MAX_REDO],
            count: 0,
            raw: [0; 2 * BLOCK],
            first: [0; BLOCK],
            second: [0; BLOCK],
            evidence: None,
            selected: 0,
            next_log_block: FIRST,
            last_txid: 0,
            checkpoint_required: false,
            retire_after: None,
            obsolete: [0; LOG_BLOCKS],
        }
    }
    pub fn evidence(&self) -> Option<RecoveryEvidence> {
        self.evidence
    }

    fn publish_rows(&mut self, count: usize, commit_lsn: u64) -> Result<(), Error> {
        for mut row in self.pending[..count].iter().copied() {
            row.commit_lsn = commit_lsn;
            if let Some(previous) = self.rows[..self.count]
                .iter_mut()
                .find(|previous| previous.home == row.home)
            {
                *previous = row;
            } else {
                *self.rows.get_mut(self.count).ok_or(Error::Capacity)? = row;
                self.count += 1;
            }
        }
        Ok(())
    }
}
impl Default for RecoveryWorkspace {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = assert!(core::mem::size_of::<RecoveryWorkspace>() < 128 * 1024);
fn u16at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn read_record(
    io: &mut impl EpochBlockIo,
    block: u32,
    raw: &mut [u8; 2 * BLOCK],
) -> Result<Option<Header>, Error> {
    if !(FIRST..END).contains(&block) {
        return Ok(None);
    }
    let (left, right) = raw.split_at_mut(BLOCK);
    io.read(block, left.try_into().map_err(|_| Error::Invalid)?)?;
    if u32at(left, 0) != MAGIC {
        return Ok(None);
    }
    let kind = u16at(left, 6);
    let (length, padded) = match kind {
        1 => (80, 4096),
        2 => (4160, 8192),
        3 => (128, 4096),
        _ => return Err(Error::Unknown),
    };
    let h = Header {
        kind,
        txid: u64at(left, 16),
        lsn: u64at(left, 24),
        epoch: u64at(left, 32),
    };
    if u16at(left, 4) != 1
        || u32at(left, 8) as usize != length
        || h.txid == 0
        || h.lsn == 0
        || h.epoch == 0
        || u32at(left, 60) != 0
        || u32at(left, 56) != crc32c_zeroed(&left[..64], 56)?
        || kind != 2 && left[40..56].iter().any(|&v| v != 0)
    {
        return Err(Error::Unknown);
    }
    if kind == 2 {
        if block + 1 >= END {
            return Err(Error::Unknown);
        }
        io.read(block + 1, right.try_into().map_err(|_| Error::Invalid)?)?;
    }
    if u32at(raw, 12) != crc32c_payload(&raw[64..length])
        || raw[length..padded].iter().any(|&v| v != 0)
    {
        return Err(Error::Unknown);
    }
    Ok(Some(h))
}
/// A clean/truncated suffix may contain old-epoch residue, but no later
/// selected-epoch record. A malformed aligned candidate fails conservatively
/// in the independent full-area preflight; never infer missing high epochs.
fn no_current_suffix(from: u32, last_current: u32) -> Result<(), Error> {
    if last_current >= from {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn current_record(
    io: &mut impl EpochBlockIo,
    block: u32,
    epoch: u64,
    raw: &mut [u8; 2 * BLOCK],
) -> Result<Option<Header>, Error> {
    match read_record(io, block, raw)? {
        Some(h) if h.epoch == epoch => Ok(Some(h)),
        Some(h) if h.epoch > epoch => Err(Error::Conflict),
        _ => Ok(None),
    }
}
/// Preflight both superblocks and the entire log, then validate a contiguous
/// current-epoch committed prefix. Merge by greatest COMMIT LSN, not physical
/// device completion order. No home or superblock writes occur here.
pub fn scan(
    io: &mut impl EpochBlockIo,
    w: &mut RecoveryWorkspace,
) -> Result<RecoveryEvidence, Error> {
    w.evidence = None;
    w.count = 0;
    w.obsolete.fill(0);
    io.read(0, &mut w.first)?;
    io.read(1, &mut w.second)?;
    let (sb, last_current) = preflight_baseline_log(
        &w.first,
        &w.second,
        &mut w.raw,
        |b, out| io.read(b, out),
        |first, blocks| {
            let index = (first - FIRST) as usize;
            w.obsolete[index] = OLD_RECORD;
            if blocks == 2 {
                w.obsolete[index + 1] = OLD_CONTINUATION;
            }
        },
    )?;
    w.selected = if SuperblockV1::decode(&w.first)? == sb {
        0
    } else {
        1
    };
    let mut at = FIRST;
    let mut last = sb.checkpoint_lsn;
    let mut last_tx = 0u64;
    let mut transactions = 0u32;
    let mut incomplete = false;
    'chain: while at < END {
        let Some(begin) = current_record(io, at, sb.log_epoch, &mut w.raw)? else {
            no_current_suffix(at + 1, last_current)?;
            break;
        };
        if begin.kind != 1 || begin.txid <= last_tx || last.checked_add(1) != Some(begin.lsn) {
            return Err(Error::Conflict);
        }
        let n = u32at(&w.raw, 64) as usize;
        if !(1..=MAX_REDO).contains(&n)
            || u32at(&w.raw, 68) != 0
            || u64at(&w.raw, 72) != n as u64 * BLOCK as u64
        {
            return Err(Error::Conflict);
        }
        let commit_at = at.checked_add(1 + 2 * n as u32).ok_or(Error::Invalid)?;
        if commit_at >= END {
            return Err(Error::Conflict);
        }
        let mut ordered = Sha256::new();
        for i in 0..n {
            let pos = at + 1 + 2 * i as u32;
            let Some(redo) = current_record(io, pos, sb.log_epoch, &mut w.raw)? else {
                no_current_suffix(pos + 1, last_current)?;
                incomplete = true;
                break 'chain;
            };
            if redo.kind != 2
                || redo.txid != begin.txid
                || begin.lsn.checked_add(i as u64 + 1) != Some(redo.lsn)
                || u32at(&w.raw, 48) != i as u32
                || u32at(&w.raw, 52) != n as u32
            {
                return Err(Error::Conflict);
            }
            let home = u32::try_from(u64at(&w.raw, 40)).map_err(|_| Error::Invalid)?;
            if !(BITMAP_START..BLOCK_COUNT).contains(&home)
                || w.pending[..i].iter().any(|r| r.home == home)
            {
                return Err(Error::Conflict);
            }
            ordered.update(u64::from(home).to_le_bytes());
            ordered.update(&w.raw[64..4160]);
            w.pending[i] = Row {
                home,
                log: pos,
                commit_lsn: 0,
                digest: hash(&w.raw),
            };
        }
        let Some(commit) = current_record(io, commit_at, sb.log_epoch, &mut w.raw)? else {
            no_current_suffix(commit_at + 1, last_current)?;
            incomplete = true;
            break;
        };
        let digest: [u8; 32] = ordered.finalize().into();
        if commit.kind != 3
            || commit.txid != begin.txid
            || begin.lsn.checked_add(n as u64 + 1) != Some(commit.lsn)
            || u64at(&w.raw, 64) != begin.txid
            || u64at(&w.raw, 72) != begin.lsn
            || u64at(&w.raw, 80) != commit.lsn - 1
            || u32at(&w.raw, 88) != n as u32
            || u32at(&w.raw, 92) != 0
            || w.raw[96..128] != digest
        {
            return Err(Error::Conflict);
        }
        w.publish_rows(n, commit.lsn)?;
        last = commit.lsn;
        last_tx = commit.txid;
        transactions += 1;
        at = commit_at + 1;
    }
    let e = RecoveryEvidence {
        superblock: sb,
        last_commit_lsn: last,
        transactions,
        distinct_home_blocks: w.count as u32,
        incomplete_tail: incomplete,
    };
    w.evidence = Some(e);
    w.next_log_block = at;
    w.last_txid = last_tx;
    Ok(e)
}
fn same_superblocks(io: &mut impl EpochBlockIo, w: &mut RecoveryWorkspace) -> Result<(), Error> {
    let out: &mut [u8; BLOCK] = (&mut w.raw[..BLOCK]).try_into().unwrap();
    io.read(0, out)?;
    if *out != w.first {
        return Err(Error::Conflict);
    }
    io.read(1, out)?;
    if *out != w.second {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn read_exact_image(
    io: &mut impl EpochBlockIo,
    row: Row,
    epoch: u64,
    raw: &mut [u8; 2 * BLOCK],
) -> Result<(), Error> {
    let h = read_record(io, row.log, raw)?.ok_or(Error::Conflict)?;
    if h.kind != 2
        || h.epoch != epoch
        || u64at(raw, 40) != u64::from(row.home)
        || hash(raw) != row.digest
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// One complete home-block image from the protected file transaction owner.
pub struct RedoImage<'a> {
    pub home: u32,
    pub contents: &'a [u8; BLOCK],
}

/// Position assigned before building after-images that carry a transaction
/// key, such as inode/receipt closure. It becomes durable only after append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedoTransaction {
    pub fs_uuid: [u8; 16],
    pub log_epoch: u64,
    pub txid: u64,
    pub begin_lsn: u64,
    pub commit_lsn: u64,
    pub first_log_block: u32,
    pub log_blocks: u32,
}

/// Verified ordered FLUSH completions and matching device readback.
pub struct CommittedRedo {
    transaction: RedoTransaction,
    ordered_digest: [u8; 32],
}

impl CommittedRedo {
    pub const fn transaction(&self) -> RedoTransaction {
        self.transaction
    }

    pub const fn ordered_digest(&self) -> [u8; 32] {
        self.ordered_digest
    }
}

/// An exclusive serialized append session on an already validated mount.
/// The caller owns authorization, home mapping and I/O slot reservation.
/// The workspace stores the bounded overlay of latest committed images.
pub struct RedoWriter<'a, I> {
    io: &'a mut I,
    workspace: &'a mut RecoveryWorkspace,
}

struct CommittedView<'w, 'a, I>(&'w mut RedoWriter<'a, I>);

impl<I: EpochBlockIo> EpochBlockIo for CommittedView<'_, '_, I> {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
        self.0.read_committed(block, out)
    }

    fn write(&mut self, _: u32, _: &[u8; BLOCK]) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }

    fn flush(&mut self) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
}

impl<'a, I: EpochBlockIo> RedoWriter<'a, I> {
    pub fn open(
        io: &'a mut I,
        workspace: &'a mut RecoveryWorkspace,
        mounted: SuperblockV1,
    ) -> Result<Self, Error> {
        if workspace.checkpoint_required {
            return Err(Error::Unknown);
        }
        let evidence = scan(io, workspace)?;
        if evidence.superblock != mounted || evidence.incomplete_tail {
            workspace.evidence = None;
            return Err(Error::Conflict);
        }
        workspace.retire_after = None;
        Ok(Self { io, workspace })
    }

    pub fn prepare(&self, images: usize) -> Result<RedoTransaction, Error> {
        let w = &self.workspace;
        let e = w.evidence.ok_or(Error::Unknown)?;
        if !(1..=MAX_REDO).contains(&images) {
            return Err(Error::Capacity);
        }
        let log_blocks = 2 + 2 * images as u32;
        if w.next_log_block + log_blocks > END {
            return Err(Error::Capacity);
        }
        let begin_lsn = e.last_commit_lsn.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(RedoTransaction {
            fs_uuid: e.superblock.fs_uuid,
            log_epoch: e.superblock.log_epoch,
            txid: w.last_txid.checked_add(1).ok_or(Error::Exhausted)?,
            begin_lsn,
            commit_lsn: begin_lsn
                .checked_add(images as u64 + 1)
                .ok_or(Error::Exhausted)?,
            first_log_block: w.next_log_block,
            log_blocks,
        })
    }

    /// Bounded scan and independently verified appends in this session.
    pub fn evidence(&self) -> Option<RecoveryEvidence> {
        self.workspace.evidence
    }

    /// Append into a reserved span of blank blocks and verified obsolete
    /// records. A span that strands a nonzero REDO continuation is busy.
    /// The owner holds data/log/flush/completion reservations from BEGIN
    /// through reply. After uncertain I/O the workspace requires recovery.
    pub fn append(
        &mut self,
        plan: RedoTransaction,
        images: &[RedoImage<'_>],
        reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
    ) -> Result<CommittedRedo, Error> {
        if self.prepare(images.len())? != plan {
            return Err(Error::Stale);
        }
        let mut digest = Sha256::new();
        for (index, image) in images.iter().enumerate() {
            if !(BITMAP_START..BLOCK_COUNT).contains(&image.home)
                || images[..index].iter().any(|prior| prior.home == image.home)
                || has_later_log_header(&image.contents[BLOCK - 64..], plan.log_epoch)
            {
                return Err(Error::Conflict);
            }
            digest.update(u64::from(image.home).to_le_bytes());
            digest.update(image.contents);
        }
        let digest = digest.finalize().into();
        reserve(&plan)?;
        same_superblocks(self.io, self.workspace)?;
        let w = &mut self.workspace;
        let scratch: &mut [u8; BLOCK] = (&mut w.raw[..BLOCK]).try_into().unwrap();
        let end = plan.first_log_block + plan.log_blocks;
        if end < END && w.obsolete[(end - FIRST) as usize] == OLD_CONTINUATION {
            self.io.read(end, scratch)?;
            if scratch.iter().any(|&byte| byte != 0) {
                return Err(Error::Busy);
            }
        }
        for block in plan.first_log_block..end {
            self.io.read(block, scratch)?;
            if w.obsolete[(block - FIRST) as usize] == 0 && scratch.iter().any(|&byte| byte != 0) {
                return Err(Error::Busy);
            }
        }
        if self.write_and_verify(plan, images, digest).is_err()
            || self
                .workspace
                .publish_rows(images.len(), plan.commit_lsn)
                .is_err()
        {
            self.workspace.evidence = None;
            self.workspace.checkpoint_required = true;
            return Err(Error::Unknown);
        }
        let w = &mut self.workspace;
        w.next_log_block += plan.log_blocks;
        w.last_txid = plan.txid;
        let e = w.evidence.as_mut().unwrap();
        e.last_commit_lsn = plan.commit_lsn;
        e.transactions += 1;
        e.distinct_home_blocks = w.count as u32;
        Ok(CommittedRedo {
            transaction: plan,
            ordered_digest: digest,
        })
    }

    fn write_and_verify(
        &mut self,
        plan: RedoTransaction,
        images: &[RedoImage<'_>],
        digest: [u8; 32],
    ) -> Result<(), Error> {
        let w = &mut self.workspace;
        let io = &mut self.io;
        let encoding = RedoEncoding {
            epoch: plan.log_epoch,
            txid: plan.txid,
            begin_lsn: plan.begin_lsn,
            count: images.len() as u32,
        };
        let begin_block = plan.first_log_block;
        let commit_block = begin_block + plan.log_blocks - 1;
        let scratch: &mut [u8; BLOCK] = (&mut w.raw[..BLOCK]).try_into().unwrap();
        encoding.begin(scratch)?;
        let begin_digest = hash(scratch);
        io.write(begin_block, scratch)?;
        for (index, image) in images.iter().enumerate() {
            encoding.after_image(&mut w.raw, index as u32, image.home, image.contents)?;
            let log = begin_block + 1 + 2 * index as u32;
            let (left, right) = w.raw.split_at(BLOCK);
            io.write(log, left.try_into().unwrap())?;
            io.write(log + 1, right.try_into().unwrap())?;
            w.pending[index] = Row {
                home: image.home,
                log,
                commit_lsn: plan.commit_lsn,
                digest: hash(&w.raw),
            };
        }
        io.flush()?;
        let scratch: &mut [u8; BLOCK] = (&mut w.raw[..BLOCK]).try_into().unwrap();
        encoding.commit(scratch, digest)?;
        let commit_digest = hash(scratch);
        io.write(commit_block, scratch)?;
        io.flush()?;
        io.read(begin_block, scratch)?;
        if hash(scratch) != begin_digest {
            return Err(Error::Conflict);
        }
        io.read(commit_block, scratch)?;
        if hash(scratch) != commit_digest {
            return Err(Error::Conflict);
        }
        for &row in &w.pending[..images.len()] {
            read_exact_image(*io, row, plan.log_epoch, &mut w.raw)?;
        }
        Ok(())
    }

    /// Consult the verified overlay before the older checkpoint homes.
    pub fn read_committed(&mut self, home: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
        self.read_view(home, None, out)
    }

    /// Read the latest after-image only if it belongs to the required
    /// commit. A checkpoint home carrying identical bytes is insufficient.
    pub fn read_committed_at(
        &mut self,
        home: u32,
        commit_lsn: u64,
        out: &mut [u8; BLOCK],
    ) -> Result<(), Error> {
        self.read_view(home, Some(commit_lsn), out)
    }

    /// Read-only committed home view for preflight before any replay writes.
    /// Journal and superblock reads are not supported by this home view.
    pub fn committed_view(&mut self) -> impl EpochBlockIo + '_ {
        CommittedView(self)
    }

    /// Prove that one exact after-image is in the required verified commit
    /// and that its physical home is either canonical predecessor or has
    /// already been written by an interrupted replay of that same commit.
    pub fn verify_replay_home(
        &mut self,
        home: u32,
        commit_lsn: u64,
        predecessor: &[u8; BLOCK],
        after: &[u8; BLOCK],
    ) -> Result<(), Error> {
        let mut raw = [0; BLOCK];
        self.read_committed_at(home, commit_lsn, &mut raw)?;
        if raw != *after {
            return Err(Error::Conflict);
        }
        self.io.read(home, &mut raw)?;
        if raw != *predecessor && raw != *after {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    fn read_view(
        &mut self,
        home: u32,
        required_commit: Option<u64>,
        out: &mut [u8; BLOCK],
    ) -> Result<(), Error> {
        let w = &mut self.workspace;
        let e = w.evidence.ok_or(Error::Unknown)?;
        if !(BITMAP_START..BLOCK_COUNT).contains(&home) {
            return Err(Error::Invalid);
        }
        let row = w.rows[..w.count].iter().find(|row| row.home == home);
        if required_commit.is_some_and(|lsn| row.is_none_or(|row| row.commit_lsn != lsn)) {
            return Err(Error::Stale);
        }
        let result = if let Some(&row) = row {
            read_exact_image(self.io, row, e.superblock.log_epoch, &mut w.raw)
                .map(|()| &w.raw[64..64 + BLOCK])
        } else {
            let block = &mut w.raw[..BLOCK];
            self.io
                .read(home, block.try_into().unwrap())
                .map(|()| &w.raw[..BLOCK])
        };
        match result {
            Ok(bytes) => {
                out.copy_from_slice(bytes);
                Ok(())
            }
            Err(_) => {
                w.evidence = None;
                w.checkpoint_required = true;
                Err(Error::Unknown)
            }
        }
    }

    /// Replay the same verified view the owner inspected through this
    /// exclusive session. Every retained image is checked again against
    /// that scan before replay makes the first write.
    pub fn checkpoint_verified(
        self,
        verify_post_replay: impl FnOnce(&mut I, SuperblockV1) -> Result<(), Error>,
    ) -> Result<(RecoveryEvidence, SuperblockV1), Error> {
        checkpoint_scanned(self.io, self.workspace, verify_post_replay)
    }
}

/// Idempotent home replay while old checkpoint remains selected. Preflight
/// all retained afterimages before first write, then verify again on use.
/// Any I/O uncertainty leaves the old log authoritative. Caller's exclusive
/// I/O ownership is mandatory; no native concurrency assumed in this module.
pub fn replay_home(
    io: &mut impl EpochBlockIo,
    w: &mut RecoveryWorkspace,
) -> Result<RecoveryEvidence, Error> {
    let e = w.evidence.ok_or(Error::Busy)?;
    same_superblocks(io, w)?;
    for i in 0..w.count {
        read_exact_image(io, w.rows[i], e.superblock.log_epoch, &mut w.raw)?;
    }
    w.checkpoint_required = true;
    w.retire_after = None;
    for i in 0..w.count {
        let row = w.rows[i];
        read_exact_image(io, row, e.superblock.log_epoch, &mut w.raw)
            .map_err(|_| Error::Unknown)?;
        io.write(row.home, w.raw[64..4160].try_into().unwrap())
            .map_err(|_| Error::Unknown)?;
    }
    io.flush().map_err(|_| Error::Unknown)?;
    // Native readback is not a substitute for FLUSH; verify both.
    for i in 0..w.count {
        let row = w.rows[i];
        read_exact_image(io, row, e.superblock.log_epoch, &mut w.raw)
            .map_err(|_| Error::Unknown)?;
        let expected = hash(&w.raw[64..4160]);
        let out: &mut [u8; BLOCK] = (&mut w.raw[..BLOCK]).try_into().unwrap();
        io.read(row.home, out).map_err(|_| Error::Unknown)?;
        if hash(out) != expected {
            return Err(Error::Unknown);
        }
    }
    Ok(e)
}
/// Complete mount recovery under one exclusive file owner. Verify the
/// actual post-replay filesystem structure and protected system/ACL state
/// before advancing the noncurrent superblock. The returned checkpoint is
/// not authority to issue capabilities: the native startup owner verifies
/// the signed config and durable BootEpoch separately.
pub fn recover_checkpoint<I: EpochBlockIo>(
    io: &mut I,
    w: &mut RecoveryWorkspace,
    verify_post_replay: impl FnOnce(&mut I, SuperblockV1) -> Result<(), Error>,
) -> Result<SuperblockV1, Error> {
    recover_checkpoint_with_evidence(io, w, verify_post_replay).map(|(_, next)| next)
}
/// Same exclusive recovery operation, returning the actual scanned chain
/// as well as the durably verified new checkpoint. No second full scan
/// is needed merely to obtain evidence for the completed transaction.
pub fn recover_checkpoint_with_evidence<I: EpochBlockIo>(
    io: &mut I,
    w: &mut RecoveryWorkspace,
    verify_post_replay: impl FnOnce(&mut I, SuperblockV1) -> Result<(), Error>,
) -> Result<(RecoveryEvidence, SuperblockV1), Error> {
    scan(io, w)?;
    checkpoint_scanned(io, w, verify_post_replay)
}

fn checkpoint_scanned<I: EpochBlockIo>(
    io: &mut I,
    w: &mut RecoveryWorkspace,
    verify_post_replay: impl FnOnce(&mut I, SuperblockV1) -> Result<(), Error>,
) -> Result<(RecoveryEvidence, SuperblockV1), Error> {
    let e = w.evidence.ok_or(Error::Unknown)?;
    let next = SuperblockV1 {
        fs_uuid: e.superblock.fs_uuid,
        generation: e
            .superblock
            .generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?,
        checkpoint_lsn: e.last_commit_lsn,
        log_epoch: e
            .superblock
            .log_epoch
            .checked_add(1)
            .ok_or(Error::Exhausted)?,
    };
    replay_home(io, w)?;
    verify_post_replay(io, e.superblock)?;
    same_superblocks(io, w)?;
    // Exact canonical v1 bytes; no format migration or old-log overwrite.
    let out: &mut [u8; BLOCK] = (&mut w.raw[..BLOCK]).try_into().unwrap();
    *out = if w.selected == 0 { w.first } else { w.second };
    out[32..40].copy_from_slice(&next.generation.to_le_bytes());
    out[40..48].copy_from_slice(&next.checkpoint_lsn.to_le_bytes());
    out[48..56].copy_from_slice(&next.log_epoch.to_le_bytes());
    let crc = crc32c_zeroed(out, 76)?;
    out[76..80].copy_from_slice(&crc.to_le_bytes());
    if SuperblockV1::decode(out)? != next {
        return Err(Error::Conflict);
    }
    let dest = 1 - w.selected;
    io.write(dest, out).map_err(|_| Error::Unknown)?;
    io.flush().map_err(|_| Error::Unknown)?;
    io.read(dest, out).map_err(|_| Error::Unknown)?;
    if SuperblockV1::decode(out).map_err(|_| Error::Unknown)? != next {
        return Err(Error::Unknown);
    }
    w.evidence = None;
    w.checkpoint_required = false;
    w.retire_after = Some(next);
    Ok((e, next))
}

/// Clear an unused log epoch after this same owner durably advanced its
/// checkpoint. A fresh scan proves the selected checkpoint and absence of
/// any new committed or incomplete chain. Callers hold exclusive device
/// ownership and the checkpoint progress reservation for the whole operation.
/// An interrupted erase can leave ambiguously framed bytes. The read-only
/// scanner rejects such evidence, even though confirmed homes survive.
pub fn retire_checkpointed_log(
    io: &mut impl EpochBlockIo,
    w: &mut RecoveryWorkspace,
    checkpoint: SuperblockV1,
) -> Result<u32, Error> {
    if w.checkpoint_required || w.retire_after != Some(checkpoint) {
        return Err(Error::Stale);
    }
    let current = scan(io, w)?;
    if current.superblock != checkpoint || current.transactions != 0 || current.incomplete_tail {
        return Err(Error::Conflict);
    }
    same_superblocks(io, w)?;
    w.retire_after = None;
    w.evidence = None;
    w.checkpoint_required = true;
    let scratch: &mut [u8; BLOCK] = (&mut w.raw[..BLOCK]).try_into().unwrap();
    let zero = [0; BLOCK];
    let mut retired = 0;
    for block in FIRST..END {
        io.read(block, scratch).map_err(|_| Error::Unknown)?;
        if *scratch != zero {
            io.write(block, &zero).map_err(|_| Error::Unknown)?;
            retired += 1;
        }
    }
    if retired > 0 {
        io.flush().map_err(|_| Error::Unknown)?;
        for block in FIRST..END {
            io.read(block, scratch).map_err(|_| Error::Unknown)?;
            if *scratch != zero {
                return Err(Error::Unknown);
            }
        }
    }
    w.checkpoint_required = false;
    Ok(retired)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::security::{
        file_index_v0199::{FileStreamIndexV4, GroupIndex, STREAM_COUNT, StreamIndex},
        file_media_v0199::{FileReceiptV4, INODE_START, RECEIPT_BYTES, local_request_id},
        file_receipt_store_v0199::{RECEIPT_STORE_BYTES, scan_receipts_with_index},
        file_structure_v1::{INODE_BYTES, Inode},
    };
    use std::{boxed::Box, collections::BTreeMap, vec::Vec};
    #[derive(Default)]
    struct Disk {
        blocks: BTreeMap<u32, Box<[u8; BLOCK]>>,
        events: Vec<u32>,
        flushes: u32,
        fail_flush: u32,
        fail_write: Option<u32>,
    }
    impl EpochBlockIo for Disk {
        fn read(&mut self, block: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
            if let Some(b) = self.blocks.get(&block) {
                *out = **b;
            } else {
                out.fill(0);
            }
            Ok(())
        }
        fn write(&mut self, block: u32, data: &[u8; BLOCK]) -> Result<(), Error> {
            self.events.push(block);
            if self.fail_write == Some(block) {
                return Err(Error::Unknown);
            }
            self.blocks.insert(block, Box::new(*data));
            Ok(())
        }
        fn flush(&mut self) -> Result<(), Error> {
            self.events.push(u32::MAX);
            self.flushes += 1;
            if self.flushes == self.fail_flush {
                return Err(Error::Unknown);
            }
            Ok(())
        }
    }
    fn p16(b: &mut [u8], i: usize, v: u16) {
        b[i..i + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn p32(b: &mut [u8], i: usize, v: u32) {
        b[i..i + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn p64(b: &mut [u8], i: usize, v: u64) {
        b[i..i + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn superblock() -> [u8; BLOCK] {
        let mut b = [0; BLOCK];
        p32(&mut b, 0, 0x43594653);
        p16(&mut b, 4, 1);
        p16(&mut b, 6, 80);
        p32(&mut b, 8, 4096);
        p32(&mut b, 12, 131072);
        b[16..32].fill(1);
        p64(&mut b, 32, 1);
        p64(&mut b, 48, 1);
        p32(&mut b, 56, 4098);
        p32(&mut b, 60, 4102);
        p32(&mut b, 64, 4118);
        p32(&mut b, 68, 256);
        let c = crc32c_zeroed(&b, 76).unwrap();
        p32(&mut b, 76, c);
        b
    }
    fn seal(b: &mut [u8], kind: u16, len: usize, txid: u64, lsn: u64) {
        p32(b, 0, MAGIC);
        p16(b, 4, 1);
        p16(b, 6, kind);
        p32(b, 8, len as u32);
        p64(b, 16, txid);
        p64(b, 24, lsn);
        p64(b, 32, 1);
        let c = crc32c_payload(&b[64..len]);
        p32(b, 12, c);
        let c = crc32c_zeroed(&b[..64], 56).unwrap();
        p32(b, 56, c);
    }
    fn append(
        d: &mut Disk,
        first: u32,
        txid: u64,
        lsn: u64,
        images: &[(u32, u8)],
        committed: bool,
    ) -> u32 {
        let n = images.len();
        let mut b = [0; BLOCK];
        p32(&mut b, 64, n as u32);
        p64(&mut b, 72, n as u64 * BLOCK as u64);
        seal(&mut b, 1, 80, txid, lsn);
        d.blocks.insert(first, Box::new(b));
        let mut digest = Sha256::new();
        for (i, &(home, value)) in images.iter().enumerate() {
            let mut raw = [0; 2 * BLOCK];
            p64(&mut raw, 40, u64::from(home));
            p32(&mut raw, 48, i as u32);
            p32(&mut raw, 52, n as u32);
            raw[64..4160].fill(value);
            digest.update(u64::from(home).to_le_bytes());
            digest.update(&raw[64..4160]);
            seal(&mut raw, 2, 4160, txid, lsn + i as u64 + 1);
            d.blocks.insert(
                first + 1 + 2 * i as u32,
                Box::new(raw[..BLOCK].try_into().unwrap()),
            );
            d.blocks.insert(
                first + 2 + 2 * i as u32,
                Box::new(raw[BLOCK..].try_into().unwrap()),
            );
        }
        let at = first + 1 + 2 * n as u32;
        if committed {
            let mut c = [0; BLOCK];
            p64(&mut c, 64, txid);
            p64(&mut c, 72, lsn);
            p64(&mut c, 80, lsn + n as u64);
            p32(&mut c, 88, n as u32);
            c[96..128].copy_from_slice(&digest.finalize());
            seal(&mut c, 3, 128, txid, lsn + n as u64 + 1);
            d.blocks.insert(at, Box::new(c));
        }
        at + 1
    }
    fn blank_disk() -> Disk {
        let mut d = Disk::default();
        d.blocks.insert(0, Box::new(superblock()));
        d.blocks.insert(1, Box::new(superblock()));
        d
    }

    fn disk() -> Disk {
        let mut d = blank_disk();
        let next = append(&mut d, 2, 1, 1, &[(7000, 1)], true);
        let next = append(&mut d, next, 2, 4, &[(7000, 2), (7001, 3)], true);
        append(&mut d, next, 3, 8, &[(7001, 4)], false);
        d
    }

    #[test]
    fn writer_recovers_file_inode_and_cross_block_receipt_together() {
        const DATA_HOME: u32 = 7000;
        const RECEIPT_HOME: u32 = 7001;
        const INDEX_HOME: u32 = RECEIPT_HOME + 6;
        let mut d = blank_disk();
        let mut w = RecoveryWorkspace::new();
        let mut data = [5; BLOCK];
        let mut archived_header = [0; BLOCK];
        RedoEncoding {
            epoch: 1,
            txid: 1,
            begin_lsn: 1,
            count: 1,
        }
        .begin(&mut archived_header)
        .unwrap();
        // Ordinary file content may include archival bytes from a journal.
        data[BLOCK - 64..].copy_from_slice(&archived_header[..64]);

        let mut inode_page = [0; BLOCK];
        let inode = &mut inode_page[..INODE_BYTES];
        p32(inode, 0, 0x4359494e);
        p16(inode, 4, 1);
        p64(inode, 8, 1);
        p64(inode, 16, BLOCK as u64);
        p64(inode, 24, 3);
        p16(inode, 32, 1);
        p64(inode, 40, 1);
        p32(inode, 52, DATA_HOME);
        p32(inode, 56, 1);
        let crc = crc32c_zeroed(inode, 252).unwrap();
        p32(inode, 252, crc);

        let sb = SuperblockV1::decode(&superblock()).unwrap();
        let mut writer = RedoWriter::open(&mut d, &mut w, sb).unwrap();
        let plan = writer.prepare(5).unwrap();
        let receipt = FileReceiptV4 {
            fs_uuid: sb.fs_uuid,
            issued_boot_epoch: 1,
            group_id: 0,
            group_generation: 1,
            stream_slot: 0,
            stream_generation: 1,
            request_seq: 1,
            log_epoch: plan.log_epoch,
            txid: plan.txid,
            commit_lsn: plan.commit_lsn,
            write_seq: 3,
            status: 3,
            result: 0,
            completed_prefix: BLOCK as u32,
            operation_digest: hash(b"test durable write"),
            output_digest: hash(&data),
            request_id: local_request_id(0, 0, 1).unwrap(),
            owner_principal_id: 1,
        };
        let mut receipts = [0; RECEIPT_STORE_BYTES];
        let start = 21 * RECEIPT_BYTES;
        receipts[start..start + RECEIPT_BYTES].copy_from_slice(&receipt.encode().unwrap());
        let mut index = FileStreamIndexV4 {
            fs_uuid: sb.fs_uuid,
            global_request_id_hi: 0,
            generation: 2,
            groups: core::array::from_fn(|i| GroupIndex {
                generation: 0,
                flags: 0,
                boot_epoch: 0,
                manifest_principal_id: i as u64 + 1,
            }),
            streams: [StreamIndex {
                generation: 0,
                flags: 0,
                issued_hi: 0,
                retired_through: 0,
            }; STREAM_COUNT],
        };
        index.groups[0].generation = 1;
        index.groups[0].flags = 1;
        index.groups[0].boot_epoch = 1;
        index.streams[0].generation = 1;
        index.streams[0].flags = 1;
        index.streams[0].issued_hi = 1;
        let mut index_image = [0; BLOCK];
        index.encode_into(&mut index_image).unwrap();

        {
            let images = [
                RedoImage {
                    home: DATA_HOME,
                    contents: &data,
                },
                RedoImage {
                    home: INODE_START,
                    contents: &inode_page,
                },
                RedoImage {
                    home: RECEIPT_HOME,
                    contents: receipts[..BLOCK].try_into().unwrap(),
                },
                RedoImage {
                    home: RECEIPT_HOME + 1,
                    contents: receipts[BLOCK..2 * BLOCK].try_into().unwrap(),
                },
                RedoImage {
                    home: INDEX_HOME,
                    contents: &index_image,
                },
            ];
            let committed = writer
                .append(plan, &images, |extent| {
                    assert_eq!((extent.first_log_block, extent.log_blocks), (2, 12));
                    Ok(())
                })
                .unwrap();
            assert_eq!(committed.transaction(), plan);
            let mut read = [0; BLOCK];
            assert_eq!(
                writer.read_committed_at(INDEX_HOME + 1, plan.commit_lsn, &mut read),
                Err(Error::Stale)
            );
            assert_eq!(
                writer.read_committed_at(DATA_HOME, plan.commit_lsn - 1, &mut read),
                Err(Error::Stale)
            );
            assert!(read == [0; BLOCK]);
            writer
                .read_committed_at(DATA_HOME, plan.commit_lsn, &mut read)
                .unwrap();
            assert!(read == data);
            writer.read_committed(INDEX_HOME, &mut read).unwrap();
            assert!(read == index_image);
        }
        assert_eq!(
            d.events,
            [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, u32::MAX, 13, u32::MAX]
        );
        assert!(!d.blocks.contains_key(&DATA_HOME));
        // One home write survives a stop during the ordinary replay.
        d.write(DATA_HOME, &data).unwrap();
        d.flush().unwrap();
        let mut reopened = Disk {
            blocks: d.blocks,
            ..Disk::default()
        };
        let mut independent = RecoveryWorkspace::new();
        let mut writer = RedoWriter::open(&mut reopened, &mut independent, sb).unwrap();
        writer
            .verify_replay_home(DATA_HOME, plan.commit_lsn, &[0; BLOCK], &data)
            .unwrap();
        writer
            .verify_replay_home(INODE_START, plan.commit_lsn, &[0; BLOCK], &inode_page)
            .unwrap();
        {
            let mut view = writer.committed_view();
            let mut raw = [0; BLOCK];
            view.read(INODE_START, &mut raw).unwrap();
            assert_eq!(raw, inode_page);
            assert_eq!(view.write(DATA_HOME, &data), Err(Error::Unauthorized));
            assert_eq!(view.flush(), Err(Error::Unauthorized));
        }
        assert!(writer.io.events.is_empty());
        let (replayed, next) = writer
            .checkpoint_verified(|io, _| {
                let mut block = [0; BLOCK];
                io.read(DATA_HOME, &mut block)?;
                assert_eq!(hash(&block), receipt.output_digest);
                io.read(INODE_START, &mut block)?;
                let inode = Inode::decode(&block[..INODE_BYTES])?;
                assert_eq!(
                    (inode.durable_write_seq, inode.size),
                    (receipt.write_seq, BLOCK as u64)
                );
                let mut recovered = [0; RECEIPT_STORE_BYTES];
                for (offset, dst) in recovered.chunks_exact_mut(BLOCK).enumerate() {
                    io.read(RECEIPT_HOME + offset as u32, dst.try_into().unwrap())?;
                }
                io.read(INDEX_HOME, &mut block)?;
                let summary = scan_receipts_with_index(&recovered, &block, sb.fs_uuid)?;
                assert_eq!(
                    (summary.occupied, summary.unresolved, summary.across_block),
                    (1, 0, 1)
                );
                assert_eq!(
                    FileReceiptV4::decode(&recovered[start..start + RECEIPT_BYTES])?,
                    receipt
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(
            (replayed.transactions, replayed.distinct_home_blocks),
            (1, 5)
        );
        assert_eq!(next.checkpoint_lsn, plan.commit_lsn);
    }

    #[test]
    fn writer_requires_exact_reservation_and_rejects_unproven_log_bytes() {
        let sb = SuperblockV1::decode(&superblock()).unwrap();
        let mut d = blank_disk();
        d.blocks.insert(3, Box::new([4; BLOCK]));
        let mut w = RecoveryWorkspace::new();
        let mut writer = RedoWriter::open(&mut d, &mut w, sb).unwrap();
        assert_eq!(writer.prepare(129), Err(Error::Capacity));
        let plan = writer.prepare(1).unwrap();
        let contents = [0; BLOCK];
        let image = RedoImage {
            home: 7000,
            contents: &contents,
        };
        let images = [image];
        let mut stale = plan;
        stale.commit_lsn += 1;
        assert_eq!(
            writer
                .append(stale, &images, |_| panic!("stale plan"))
                .err(),
            Some(Error::Stale)
        );
        assert_eq!(
            writer.append(plan, &images, |_| Err(Error::Capacity)).err(),
            Some(Error::Capacity)
        );
        assert_eq!(
            writer.append(plan, &images, |_| Ok(())).err(),
            Some(Error::Busy)
        );
        assert!(d.events.is_empty());
        assert!(d.blocks[&3].iter().all(|&byte| byte == 4));
    }

    #[test]
    fn writer_reuses_verified_old_records_after_checkpoint() {
        let sb = SuperblockV1::decode(&superblock()).unwrap();
        let mut d = blank_disk();
        let mut w = RecoveryWorkspace::new();
        let first_data = [31; BLOCK];
        let second_data = [71; BLOCK];
        let first = [
            RedoImage {
                home: 7000,
                contents: &first_data,
            },
            RedoImage {
                home: 7001,
                contents: &first_data,
            },
        ];
        let mut writer = RedoWriter::open(&mut d, &mut w, sb).unwrap();
        let first_plan = writer.prepare(first.len()).unwrap();
        writer.append(first_plan, &first, |_| Ok(())).unwrap();
        let checkpoint = recover_checkpoint(&mut d, &mut w, |_, _| Ok(())).unwrap();
        d.events.clear();
        assert_eq!(checkpoint.checkpoint_lsn, first_plan.commit_lsn);

        let mut reopened = RecoveryWorkspace::new();
        let mut writer = RedoWriter::open(&mut d, &mut reopened, checkpoint).unwrap();
        let next = [
            RedoImage {
                home: 7000,
                contents: &second_data,
            },
            RedoImage {
                home: 7001,
                contents: &second_data,
            },
        ];
        let short = writer.prepare(1).unwrap();
        // A shorter span would leave the old second image tail unframed.
        assert_eq!(
            writer.append(short, &next[..1], |_| Ok(())).err(),
            Some(Error::Busy)
        );
        let plan = writer.prepare(next.len()).unwrap();
        assert_eq!(plan.first_log_block, first_plan.first_log_block);
        assert_eq!(plan.log_epoch, first_plan.log_epoch + 1);
        assert_eq!(plan.begin_lsn, first_plan.commit_lsn + 1);
        writer.append(plan, &next, |_| Ok(())).unwrap();
        assert_eq!(d.events, [2, 3, 4, 5, 6, u32::MAX, 7, u32::MAX]);
        let mut independent = RecoveryWorkspace::new();
        let (evidence, next_checkpoint) =
            recover_checkpoint_with_evidence(&mut d, &mut independent, |io, _| {
                for home in [7000, 7001] {
                    let mut out = [0; BLOCK];
                    io.read(home, &mut out)?;
                    assert!(out == second_data);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(
            (evidence.transactions, evidence.distinct_home_blocks),
            (1, 2)
        );
        assert_eq!(next_checkpoint.checkpoint_lsn, plan.commit_lsn);
    }

    #[test]
    fn interrupted_retirement_keeps_checkpoint_and_rejects_orphaned_record_bytes() {
        let mut d = blank_disk();
        let mut w = RecoveryWorkspace::new();
        let sb = SuperblockV1::decode(&superblock()).unwrap();
        let mut archived = [0; BLOCK];
        RedoEncoding {
            epoch: 1,
            txid: 1,
            begin_lsn: 1,
            count: 1,
        }
        .begin(&mut archived)
        .unwrap();
        let mut data = [1; BLOCK];
        data[BLOCK - 64..].copy_from_slice(&archived[..64]);
        let mut writer = RedoWriter::open(&mut d, &mut w, sb).unwrap();
        let plan = writer.prepare(1).unwrap();
        writer
            .append(
                plan,
                &[RedoImage {
                    home: 7000,
                    contents: &data,
                }],
                |_| Ok(()),
            )
            .unwrap();
        let checkpoint = recover_checkpoint(&mut d, &mut w, |_, _| Ok(())).unwrap();
        d.fail_write = Some(4); // The older REDO start cleared, with its continuation still present.
        assert_eq!(
            retire_checkpointed_log(&mut d, &mut w, checkpoint),
            Err(Error::Unknown)
        );
        assert_eq!(
            RedoWriter::open(&mut d, &mut w, checkpoint).err(),
            Some(Error::Unknown)
        );
        let mut fresh = RecoveryWorkspace::new();
        assert_eq!(scan(&mut d, &mut fresh), Err(Error::Unknown));
        assert_eq!(SuperblockV1::decode(d.blocks[&1].as_ref()), Ok(checkpoint));
        assert!(d.blocks[&7000].as_ref() == &data);
    }

    #[test]
    fn writer_stops_on_uncertain_flush_until_independent_recovery() {
        let sb = SuperblockV1::decode(&superblock()).unwrap();
        for (fail_flush, committed) in [(1, false), (2, true)] {
            let mut d = blank_disk();
            d.fail_flush = fail_flush;
            let mut w = RecoveryWorkspace::new();
            let mut writer = RedoWriter::open(&mut d, &mut w, sb).unwrap();
            let plan = writer.prepare(1).unwrap();
            let data = [9; BLOCK];
            let images = [RedoImage {
                home: 7000,
                contents: &data,
            }];
            assert_eq!(
                writer.append(plan, &images, |_| Ok(())).err(),
                Some(Error::Unknown)
            );
            assert_eq!(writer.prepare(1), Err(Error::Unknown));
            let mut out = [42; BLOCK];
            assert_eq!(writer.read_committed(7000, &mut out), Err(Error::Unknown));
            assert!(out.iter().all(|&byte| byte == 42));
            assert_eq!(
                RedoWriter::open(&mut d, &mut w, sb).err(),
                Some(Error::Unknown)
            );
            assert!(!d.blocks.contains_key(&7000));

            // The test disk accepts writes before a FLUSH can report failure.
            // Reopen determines which records are actually present.
            let mut reopened = Disk {
                blocks: d.blocks,
                ..Disk::default()
            };
            let mut independent = RecoveryWorkspace::new();
            let (evidence, _) =
                recover_checkpoint_with_evidence(&mut reopened, &mut independent, |_, _| Ok(()))
                    .unwrap();
            assert_eq!(evidence.transactions, u32::from(committed));
            assert_eq!(evidence.incomplete_tail, !committed);
            if committed {
                assert!(reopened.blocks[&7000].as_ref() == &data);
            } else {
                assert!(!reopened.blocks.contains_key(&7000));
            }
        }
    }
    #[test]
    fn highest_committed_afterimage_once_then_flush_validate_and_checkpoint() {
        let mut d = disk();
        let mut w = RecoveryWorkspace::new();
        let e = scan(&mut d, &mut w).unwrap();
        assert_eq!(
            (
                e.transactions,
                e.last_commit_lsn,
                e.distinct_home_blocks,
                e.incomplete_tail
            ),
            (2, 7, 2, true)
        );
        let next = recover_checkpoint(&mut d, &mut w, |io, _| {
            assert_eq!(&io.events[..], &[7000, 7001, u32::MAX]);
            assert!(io.blocks[&7000].iter().all(|&v| v == 2));
            assert!(io.blocks[&7001].iter().all(|&v| v == 3));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            (next.generation, next.log_epoch, next.checkpoint_lsn),
            (2, 2, 7)
        );
        assert_eq!(&d.events[..], &[7000, 7001, u32::MAX, 1, u32::MAX]);
        // Old incomplete records remain physically present; a fresh
        // scan of the new checkpoint ignores the now older epoch.
        assert_eq!(scan(&mut d, &mut w).unwrap().transactions, 0);
    }
    #[test]
    fn holes_and_flush_failure_cannot_advance_checkpoint() {
        let mut w = RecoveryWorkspace::new();
        let mut broken = disk();
        // Remove the second transaction's first REDO header while its
        // later commit remains. This is not a harmless truncated tail.
        broken.blocks.remove(&7);
        assert!(scan(&mut broken, &mut w).is_err());
        assert!(broken.events.is_empty());
        assert_eq!(replay_home(&mut broken, &mut w), Err(Error::Busy));
        let mut d = disk();
        d.fail_flush = 1;
        assert_eq!(
            recover_checkpoint(&mut d, &mut w, |_, _| panic!("home not flushed")),
            Err(Error::Unknown)
        );
        assert!(!d.events.contains(&1));
        assert_eq!(SuperblockV1::decode(&*d.blocks[&1]).unwrap().generation, 1);
        let mounted = SuperblockV1::decode(&superblock()).unwrap();
        assert_eq!(
            RedoWriter::open(&mut d, &mut w, mounted).err(),
            Some(Error::Unknown)
        );
        d.fail_flush = 0;
        d.events.clear();
        assert_eq!(
            recover_checkpoint(&mut d, &mut w, |_, _| Err(Error::Unauthorized)),
            Err(Error::Unauthorized)
        );
        assert!(!d.events.contains(&1));
        d.events.clear();
        assert_eq!(
            recover_checkpoint(&mut d, &mut w, |_, _| Ok(()))
                .unwrap()
                .generation,
            2
        );
    }
}
