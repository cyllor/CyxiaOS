//! Frozen baseline-v1 FSYNC for existing files. The serialized
//! file owner holds the mounted volume, live admission, frozen pages and
//! completion resources for all segments. Recovery may query a prior boot's
//! receipt but cannot use it to resume writing.

use sha2::{Digest, Sha256};

use super::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_admission_flow_v1::FileAdmissionFlowV1,
    file_auth_context_v1::{AdmissionLedgerV1, Linearization},
    file_auth_v3::{Completion, operation_digest},
    file_index_v0199::{FileStreamIndexV4, STREAMS_PER_GROUP, SecurityStateStoreV2},
    file_media_unified_v1::FILE_TRANSACTION_WORKSPACE_KIB,
    file_media_v0199::{
        BITMAP_START, BLOCK_COUNT, DATA_START, FileReceiptV4, INODE_START, RECEIPT_BYTES,
        crc32c_zeroed,
    },
    file_mount_v1::{Acl, MountEvidence},
    file_receipt_query_v4::ReceiptKey,
    file_receipt_store_v0199::{RECEIPT_STORE_BYTES, home_closure, scan_receipts_with_index},
    file_service_v4::Request,
    file_structure_v1::{BLOCK, Extent, INODE_BYTES, INODES, Inode, MAX_FILE, SystemKind},
    offline_config_v1::VerifiedOfflineConfig,
    recovery_v1::{CommittedRedo, RecoveryWorkspace, RedoImage, RedoTransaction, RedoWriter},
};

const FSYNC: u16 = 5;
const FSYNC_RIGHT: u32 = 1 << 13;
const ACL_BYTES: usize = 64;
const ISSUED: u16 = 1;
const BOUND: u16 = 2;
const DONE: u16 = 3;
const MAX_DATA_HOMES: usize = 120;
const BLOCKS_PER_BITMAP: u32 = (8 * BLOCK) as u32;
const BITMAP_PAGES: usize = (INODE_START - BITMAP_START) as usize;
const RECEIPT_CLOSURE_PAGES: usize = 2;
// Data, both halves of a straddling receipt, its index, and the final inode
// plus every bitmap page touched by this segment's allocation.
const MAX_SEGMENT_HOMES: usize = MAX_DATA_HOMES + RECEIPT_CLOSURE_PAGES + 2 + BITMAP_PAGES;
const _: () = assert!(MAX_SEGMENT_HOMES <= 128);
const _: () = assert!(BITMAP_PAGES as u32 * BLOCKS_PER_BITMAP == BLOCK_COUNT);
const _: () = assert!(RECEIPT_STORE_BYTES == (RECEIPT_CLOSURE_PAGES + BITMAP_PAGES) * BLOCK);

/// The protected file service resolves the caller's live cap to the v1
/// inode and supplies the authenticated mount and original copied frame.
pub struct FsyncJob<'a> {
    pub config: &'a VerifiedOfflineConfig<'a>,
    pub mounted: &'a MountEvidence,
    pub admission: &'a FileAdmissionFlowV1,
    pub ledger: &'a AdmissionLedgerV1,
    pub inode_id: u16,
    pub cap_selector: u64,
    pub frame: &'a [u8],
    pub key: ReceiptKey,
    /// Bind the new logical size as a little-endian u64 before the pages in
    /// the frozen digest. A growth segment may append multiple free runs.
    /// An unchanged-size job uses the legacy pages-only digest.
    pub grown_size: Option<usize>,
    /// Complete frozen logical file, in order, with zero padding after EOF.
    pub pages: &'a [&'a [u8; BLOCK]],
}

pub struct FsyncWorkspace {
    receipts: [u8; RECEIPT_STORE_BYTES],
    inode_page: [u8; BLOCK],
    scratch: [u8; BLOCK],
}

const _: () = assert!(
    core::mem::size_of::<FsyncWorkspace>() + core::mem::size_of::<RecoveryWorkspace>()
        <= FILE_TRANSACTION_WORKSPACE_KIB as usize * 1024
);

impl FsyncWorkspace {
    pub const fn new() -> Self {
        Self {
            receipts: [0; RECEIPT_STORE_BYTES],
            inode_page: [0; BLOCK],
            scratch: [0; BLOCK],
        }
    }
}

impl Default for FsyncWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

pub enum FsyncProgress {
    Committed {
        receipt: FileReceiptV4,
        redo: CommittedRedo,
    },
    AlreadyDone(FileReceiptV4),
}

fn same_key(receipt: &FileReceiptV4, key: ReceiptKey) -> bool {
    receipt.fs_uuid == key.fs_uuid
        && receipt.issued_boot_epoch == key.issued_boot_epoch
        && receipt.group_id == key.group_id
        && receipt.group_generation == key.group_generation
        && receipt.stream_slot == key.stream_slot
        && receipt.stream_generation == key.stream_generation
        && receipt.request_seq == key.request_seq
}

fn bitmap_bit(block: u32) -> (usize, u8) {
    let bit = (block % BLOCKS_PER_BITMAP) as usize;
    (bit / 8, 1 << (bit % 8))
}

fn first_free_run(bitmap: &[u8; BLOCK], start: u32, end: u32, blocks: u32) -> Option<u32> {
    let mut free = 0;
    for block in start..end {
        let (byte, mask) = bitmap_bit(block);
        if bitmap[byte] & mask != 0 {
            free = 0;
        } else {
            free += 1;
            if free == blocks {
                return Some(block + 1 - blocks);
            }
        }
    }
    None
}

#[derive(Clone, Copy, Default)]
struct FreeRun {
    physical: u32,
    count: u32,
}

fn bitmap_page(block: u32) -> usize {
    (block / BLOCKS_PER_BITMAP) as usize
}

fn block_free(bitmaps: &[[u8; BLOCK]; BITMAP_PAGES], block: u32) -> bool {
    let (byte, mask) = bitmap_bit(block);
    bitmaps[bitmap_page(block)][byte] & mask == 0
}

fn stage_growth_run(
    inode: &mut Inode,
    bitmaps: &mut [[u8; BLOCK]; BITMAP_PAGES],
    physical: u32,
    count: u32,
) -> u8 {
    let mut changed = 0;
    for block in physical..physical + count {
        let page = bitmap_page(block);
        let (byte, mask) = bitmap_bit(block);
        bitmaps[page][byte] |= mask;
        changed |= 1 << page;
    }
    let extent_count = usize::from(inode.extents);
    let last = inode.runs[..extent_count].last().copied();
    if last.is_some_and(|run| run.physical + run.count == physical) {
        inode.runs[extent_count - 1].count += count;
    } else {
        inode.runs[extent_count] = Extent {
            logical: last.map_or(0, |run| run.logical + run.count),
            physical,
            count,
        };
        inode.extents += 1;
    }
    changed
}

fn allocate_growth(
    mut read_bitmap: impl FnMut(u32, &mut [u8; BLOCK]) -> Result<(), Error>,
    inode: &mut Inode,
    bitmaps: &mut [[u8; BLOCK]; BITMAP_PAGES],
    allocation_floor: u32,
    blocks: u32,
) -> Result<u8, Error> {
    let extent_count = usize::from(inode.extents);
    let adjacent = inode.runs[..extent_count]
        .last()
        .map(|run| run.physical + run.count)
        .filter(|&home| (allocation_floor..BLOCK_COUNT).contains(&home));
    let mut loaded = 0u8;
    let mut load_bitmap = |page: usize, bitmaps: &mut [[u8; BLOCK]; BITMAP_PAGES]| {
        if loaded & (1 << page) == 0 {
            read_bitmap(BITMAP_START + page as u32, &mut bitmaps[page])?;
            loaded |= 1 << page;
        }
        Ok::<(), Error>(())
    };

    // Extend the existing extent even when it crosses a bitmap page boundary.
    if let Some(home) = adjacent.filter(|&home| home + blocks <= BLOCK_COUNT) {
        for page in bitmap_page(home)..=bitmap_page(home + blocks - 1) {
            load_bitmap(page, bitmaps)?;
        }
        if (home..home + blocks).all(|block| block_free(bitmaps, block)) {
            return Ok(stage_growth_run(inode, bitmaps, home, blocks));
        }
    }
    let new_extents = inode.runs.len() - extent_count;
    if new_extents == 0 {
        return Err(Error::Capacity);
    }

    // Keep the typical fast path to one bitmap page and one new extent.
    let preferred = bitmap_page(adjacent.unwrap_or(allocation_floor));
    for offset in 0..BITMAP_PAGES {
        let page = (preferred + offset) % BITMAP_PAGES;
        let end = (page as u32 + 1) * BLOCKS_PER_BITMAP;
        let first = (page as u32 * BLOCKS_PER_BITMAP).max(allocation_floor);
        if end <= first {
            continue;
        }
        load_bitmap(page, bitmaps)?;
        if let Some(home) = first_free_run(&bitmaps[page], first, end, blocks) {
            return Ok(stage_growth_run(inode, bitmaps, home, blocks));
        }
    }

    // With every eligible bitmap read, plan a complete allocation before
    // changing any image. Keep the longest runs that fit the remaining
    // extent slots. Equal lengths retain their ascending physical order.
    let mut candidates = inode.runs.map(|_| FreeRun::default());
    let candidates = &mut candidates[..new_extents];
    let mut extension = FreeRun::default();
    let mut run = FreeRun::default();
    for block in allocation_floor..=BLOCK_COUNT {
        if block < BLOCK_COUNT && block_free(bitmaps, block) {
            if run.count == 0 {
                run.physical = block;
            }
            run.count += 1;
            continue;
        }
        if run.count == 0 {
            continue;
        }
        if Some(run.physical) == adjacent {
            extension = run;
        } else if run.count > candidates[new_extents - 1].count {
            let at = candidates
                .iter()
                .position(|item| item.count < run.count)
                .unwrap();
            candidates.copy_within(at..new_extents - 1, at + 1);
            candidates[at] = run;
        }
        run.count = 0;
    }
    let capacity = extension.count + candidates.iter().map(|run| run.count).sum::<u32>();
    if capacity < blocks {
        return Err(Error::Capacity);
    }
    let mut changed = 0;
    let mut remaining = blocks;
    for run in core::iter::once(extension).chain(candidates.iter().copied()) {
        let count = remaining.min(run.count);
        if count != 0 {
            changed |= stage_growth_run(inode, bitmaps, run.physical, count);
            remaining -= count;
        }
        if remaining == 0 {
            break;
        }
    }
    Ok(changed)
}

/// Bind an issued ticket or durably advance one FSYNC prefix on baseline
/// media. The unified snapshot volume requires its COW owner. The final
/// segment updates the inode write sequence and terminal receipt together.
/// On I/O uncertainty the writer requires recovery before further mutations.
pub fn commit_segment<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    job: &FsyncJob<'_>,
    work: &mut FsyncWorkspace,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<FsyncProgress, Error> {
    commit_segment_with_floor(writer, job, work, DATA_START, reserve)
}

/// Commit a segment using the verified mount layout's first eligible data
/// block for new allocation. Existing committed extents retain their homes.
pub fn commit_segment_with_floor<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    job: &FsyncJob<'_>,
    work: &mut FsyncWorkspace,
    allocation_floor: u32,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<FsyncProgress, Error> {
    if !(DATA_START..BLOCK_COUNT).contains(&allocation_floor) {
        return Err(Error::Invalid);
    }
    let ctx = job.admission.ctx();
    let proposal = job.admission.request();
    let registered = job
        .ledger
        .entry_by_admission(job.admission.admission_id())
        .ok_or(Error::Unauthorized)?;
    let request = Request::decode(job.frame, job.cap_selector)?;
    if request.op != FSYNC
        || job.admission.state() != Linearization::Execute
        || registered.completion != Completion::InFlight
        || registered.key.auth_context_id != ctx.auth_context_id
        || registered.key.request_seq != job.key.request_seq
        || registered.proposal_digest != proposal.operation_digest
        || job.ledger.boot_epoch() != ctx.boot_epoch
        || ctx.boot_epoch != job.key.issued_boot_epoch
        || job.key.request_id() != Some(request.request_id)
        || proposal.request_seq != job.key.request_seq
        || proposal.target_id != u64::from(job.inode_id)
        || proposal.required_rights & u64::from(FSYNC_RIGHT) == 0
        || operation_digest(ctx.boot_epoch, job.frame, &proposal)? != proposal.operation_digest
    {
        return Err(Error::Unauthorized);
    }
    let write_seq = u64::from_le_bytes(request.payload.try_into().map_err(|_| Error::Invalid)?);

    if job.mounted.boot.fs_uuid != job.key.fs_uuid {
        return Err(Error::Unauthorized);
    }
    job.config.check_committed(&job.mounted.security)?;
    let system = job.mounted.baseline_system().ok_or(Error::Unauthorized)?;
    let inode_id = usize::from(job.inode_id);
    if inode_id == 0
        || inode_id >= INODES
        || system.iter().any(|object| object.inode == job.inode_id)
    {
        return Err(Error::Unauthorized);
    }

    // The authenticated manifest supplies exact locations, and the mounted
    // journal overlay includes the durable BootEpoch pair for this boot.
    let home = |kind| {
        system
            .iter()
            .find(|object| object.kind == kind)
            .map(|object| object.first_block)
            .ok_or(Error::Invalid)
    };
    writer.read_committed(home(SystemKind::Security)?, &mut work.scratch)?;
    let security = SecurityStateStoreV2::decode(&work.scratch)?;
    job.config.check_committed(&security)?;
    writer.read_committed(home(SystemKind::BootEpoch)?, &mut work.scratch)?;
    let boot = BootEpochStoreV1::decode(&work.scratch)?;
    if !boot.matches(&security)
        || boot.fs_uuid != job.key.fs_uuid
        || boot.boot_epoch != ctx.boot_epoch
    {
        return Err(Error::Stale);
    }

    let inode_offset = inode_id * INODE_BYTES;
    let inode_home = INODE_START + (inode_offset / BLOCK) as u32;
    let inode_at = inode_offset % BLOCK;
    writer.read_committed(inode_home, &mut work.inode_page)?;
    let mut inode = Inode::decode(&work.inode_page[inode_at..inode_at + INODE_BYTES])?;
    let acl_offset = inode_id * ACL_BYTES;
    writer.read_committed(
        home(SystemKind::Acl)? + (acl_offset / BLOCK) as u32,
        &mut work.scratch,
    )?;
    let acl_at = acl_offset % BLOCK;
    let acl = Acl::decode(&work.scratch[acl_at..acl_at + ACL_BYTES])?;
    let principal = job.config.principals()[job.key.group_id as usize];
    if inode.kind != 1
        || inode.generation != proposal.target_generation
        || acl.inode_id != u32::from(job.inode_id)
        || acl.inode_generation != inode.generation
        || acl.parent != inode.parent
        || acl.state != 1
        || acl.acl_generation != proposal.acl_generation
        || acl.principal != principal
        || principal.id != ctx.principal
        || proposal.required_rights & !u64::from(acl.owner_rights) != 0
    {
        return Err(Error::Unauthorized);
    }

    let current_size = usize::try_from(inode.size).map_err(|_| Error::Invalid)?;
    let size = job.grown_size.unwrap_or(current_size);
    let pages = size.div_ceil(BLOCK);
    let old_pages = current_size.div_ceil(BLOCK);
    if job.grown_size.is_some() && (size == 0 || size < current_size || size as u64 > MAX_FILE) {
        return Err(Error::Invalid);
    }
    if job.pages.len() != pages
        || size % BLOCK != 0
            && job
                .pages
                .last()
                .is_some_and(|page| page[size % BLOCK..].iter().any(|&b| b != 0))
    {
        return Err(Error::Invalid);
    }
    let mut frozen = Sha256::new();
    for page in job.pages {
        frozen.update(*page);
    }
    let output_digest: [u8; 32] = if job.pages.is_empty() {
        [0; 32]
    } else {
        frozen.finalize().into()
    };
    let frozen = if job.grown_size.is_some() {
        let mut digest = Sha256::new();
        digest.update((size as u64).to_le_bytes());
        for page in job.pages {
            digest.update(*page);
        }
        digest.finalize().into()
    } else {
        output_digest
    };
    if frozen != proposal.frozen_data_digest {
        return Err(Error::Conflict);
    }

    let receipt_home = home(SystemKind::Receipts)?;
    for (offset, raw) in work.receipts.chunks_exact_mut(BLOCK).enumerate() {
        writer.read_committed(receipt_home + offset as u32, raw.try_into().unwrap())?;
    }
    writer.read_committed(receipt_home + 6, &mut work.scratch)?;
    scan_receipts_with_index(&work.receipts, &work.scratch, boot.fs_uuid)?;
    let index = FileStreamIndexV4::decode(&work.scratch)?;
    let group = index.groups[job.key.group_id as usize];
    let stream =
        index.streams[job.key.group_id as usize * STREAMS_PER_GROUP + job.key.stream_slot as usize];
    if index.groups.map(|group| group.manifest_principal_id)
        != job.config.principals().map(|principal| principal.id)
        || group.generation != job.key.group_generation
        || group.boot_epoch != ctx.boot_epoch
        || group.flags != 1
        || u64::from(stream.generation) != job.key.stream_generation
        || stream.flags != 1
    {
        return Err(Error::Stale);
    }
    // The scanner checked every occupied record, including full key
    // uniqueness, exact owner identity and contiguous sequence custody.
    let (slot, mut receipt) = work
        .receipts
        .chunks_exact(RECEIPT_BYTES)
        .enumerate()
        .filter_map(|(slot, raw)| FileReceiptV4::decode(raw).ok().map(|record| (slot, record)))
        .find(|(_, record)| same_key(record, job.key))
        .ok_or(Error::Stale)?;
    let bind = receipt.status == ISSUED;
    if receipt.owner_principal_id != principal.id
        || (!bind
            && (receipt.operation_digest != proposal.operation_digest
                || receipt.write_seq != write_seq
                || receipt.commit_lsn == 0
                || receipt.completed_prefix as usize > size))
    {
        return Err(Error::Conflict);
    }
    if receipt.status == DONE {
        if receipt.completed_prefix as usize != size
            || receipt.result != 0
            || receipt.output_digest != output_digest
            || job.grown_size.is_some() && current_size != size
            || inode.durable_write_seq < write_seq
        {
            return Err(Error::Conflict);
        }
        return Ok(FsyncProgress::AlreadyDone(receipt));
    }
    if !matches!(receipt.status, ISSUED | BOUND)
        || receipt.result != 0
        || inode.durable_write_seq >= write_seq
    {
        return Err(Error::Busy);
    }
    if job.grown_size.is_some() && current_size == size {
        return Err(Error::Conflict);
    }
    let prefix = receipt.completed_prefix as usize;
    if prefix > current_size || prefix != size && prefix % BLOCK != 0 {
        return Err(Error::Conflict);
    }
    let first = prefix.div_ceil(BLOCK);
    let end = if bind {
        first
    } else {
        (first + MAX_DATA_HOMES).min(job.pages.len())
    };
    let completed = (end * BLOCK).min(size);
    let final_segment = !bind && end == job.pages.len();
    // Every visible byte must be covered by the old file or by this
    // initialized segment. The terminal write sequence advances separately.
    let published_size = current_size.max(completed);
    let update_inode = final_segment || published_size != current_size;
    let checked_pages = if bind {
        pages.min(MAX_DATA_HOMES)
    } else {
        published_size.div_ceil(BLOCK)
    };
    let closure = home_closure(slot).ok_or(Error::Invalid)?;
    // The full store scan is complete. Move just this record's one or two
    // home pages down, and reuse the remaining four pages for the bitmaps.
    let receipt_start = closure.receipt.first * BLOCK;
    let receipt_end = receipt_start + closure.receipt_block_count * BLOCK;
    work.receipts.copy_within(receipt_start..receipt_end, 0);
    let (receipt_images, bitmap_images) = work.receipts.split_at_mut(RECEIPT_CLOSURE_PAGES * BLOCK);
    let bitmaps: &mut [[u8; BLOCK]; BITMAP_PAGES] =
        bitmap_images.as_chunks_mut::<BLOCK>().0.try_into().unwrap();
    // Before binding, check space for the first segment without publishing
    // allocation. Recheck under the exclusive writer on every growth commit.
    let changed_bitmaps = if checked_pages > old_pages {
        let changed = allocate_growth(
            |home, bytes| writer.read_committed(home, bytes),
            &mut inode,
            bitmaps,
            allocation_floor,
            (checked_pages - old_pages) as u32,
        )?;
        if bind { 0 } else { changed }
    } else {
        0
    };
    let count = (end - first)
        + closure.receipt_block_count
        + usize::from(closure.requires_stream_index_block)
        + usize::from(update_inode)
        + changed_bitmaps.count_ones() as usize;
    let plan = writer.prepare(count)?;
    if plan.fs_uuid != boot.fs_uuid
        || plan.log_epoch < receipt.log_epoch
        || plan.begin_lsn <= receipt.commit_lsn
    {
        return Err(Error::Conflict);
    }

    receipt.log_epoch = plan.log_epoch;
    receipt.txid = plan.txid;
    receipt.commit_lsn = plan.commit_lsn;
    receipt.completed_prefix = completed as u32;
    if bind {
        receipt.status = BOUND;
        receipt.operation_digest = proposal.operation_digest;
        receipt.write_seq = write_seq;
    }
    if final_segment {
        receipt.status = DONE;
        receipt.output_digest = output_digest;
    }
    if update_inode {
        let raw = &mut work.inode_page[inode_at..inode_at + INODE_BYTES];
        raw[16..24].copy_from_slice(&(published_size as u64).to_le_bytes());
        if changed_bitmaps != 0 {
            raw[32..34].copy_from_slice(&inode.extents.to_le_bytes());
            for (bytes, run) in raw[48..240].chunks_exact_mut(12).zip(inode.runs) {
                bytes[..4].copy_from_slice(&run.logical.to_le_bytes());
                bytes[4..8].copy_from_slice(&run.physical.to_le_bytes());
                bytes[8..12].copy_from_slice(&run.count.to_le_bytes());
            }
        }
        if final_segment {
            raw[24..32].copy_from_slice(&write_seq.to_le_bytes());
        }
        let crc = crc32c_zeroed(raw, 252)?;
        raw[252..].copy_from_slice(&crc.to_le_bytes());
    }
    let offset = slot * RECEIPT_BYTES % BLOCK;
    receipt_images[offset..offset + RECEIPT_BYTES].copy_from_slice(&receipt.encode()?);
    let mut images: [RedoImage<'_>; MAX_SEGMENT_HOMES] = core::array::from_fn(|_| RedoImage {
        home: 0,
        contents: &[0; BLOCK],
    });
    for (index, (logical, contents)) in (first..end).zip(&job.pages[first..end]).enumerate() {
        let logical = logical as u32;
        let extent = inode.runs[..usize::from(inode.extents)]
            .iter()
            .find(|run| (run.logical..run.logical + run.count).contains(&logical))
            .ok_or(Error::Conflict)?;
        images[index] = RedoImage {
            home: extent.physical + logical - extent.logical,
            contents,
        };
    }
    let mut next = end - first;
    for (offset, contents) in receipt_images
        .as_chunks::<BLOCK>()
        .0
        .iter()
        .take(closure.receipt_block_count)
        .enumerate()
    {
        images[next] = RedoImage {
            home: receipt_home + (closure.receipt.first + offset) as u32,
            contents,
        };
        next += 1;
    }
    // Even unchanged index bytes belong to the receipt's redo closure.
    // A recovered segment must prove the complete jointly committed view.
    images[next] = RedoImage {
        home: receipt_home + 6,
        contents: &work.scratch,
    };
    next += 1;
    if update_inode {
        for (page, contents) in bitmaps.iter().enumerate() {
            if changed_bitmaps & (1 << page) != 0 {
                images[next] = RedoImage {
                    home: BITMAP_START + page as u32,
                    contents,
                };
                next += 1;
            }
        }
        images[next] = RedoImage {
            home: inode_home,
            contents: &work.inode_page,
        };
    }
    let redo = writer.append(plan, &images[..count], reserve)?;
    Ok(FsyncProgress::Committed { receipt, redo })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_inode() -> Inode {
        Inode {
            kind: 1,
            generation: 1,
            size: 0,
            durable_write_seq: 0,
            parent: 0,
            parent_generation: 1,
            extents: 0,
            runs: [Extent {
                logical: 0,
                physical: 0,
                count: 0,
            }; 16],
        }
    }

    fn fragmented_image(home: u32, free: &[u32], out: &mut [u8; BLOCK]) {
        out.fill(u8::MAX);
        for &block in free {
            if home == BITMAP_START + block / BLOCKS_PER_BITMAP {
                let (byte, mask) = bitmap_bit(block);
                out[byte] &= !mask;
            }
        }
    }

    #[test]
    fn reserves_a_contiguous_extent_across_two_bitmap_pages() {
        let free = [BLOCKS_PER_BITMAP - 1, BLOCKS_PER_BITMAP];
        let mut inode = empty_inode();
        let mut bitmaps = [[0; BLOCK]; BITMAP_PAGES];
        assert_eq!(
            allocate_growth(
                |home, out| {
                    fragmented_image(home, &free, out);
                    Ok(())
                },
                &mut inode,
                &mut bitmaps,
                DATA_START,
                2,
            ),
            Ok(0b11)
        );
        assert_eq!(inode.extents, 1);
        assert_eq!(inode.runs[0].physical, free[0]);
        assert_eq!(inode.runs[0].count, 2);
        assert!(bitmaps.iter().flatten().all(|&byte| byte == u8::MAX));
    }

    #[test]
    fn reserves_multiple_runs_when_the_free_space_is_fragmented() {
        let free = [DATA_START + 1, BLOCKS_PER_BITMAP, BLOCKS_PER_BITMAP + 1];
        let mut inode = empty_inode();
        let mut bitmaps = [[0; BLOCK]; BITMAP_PAGES];
        assert_eq!(
            allocate_growth(
                |home, out| {
                    fragmented_image(home, &free, out);
                    Ok(())
                },
                &mut inode,
                &mut bitmaps,
                DATA_START,
                3,
            ),
            Ok(0b11)
        );
        assert_eq!(inode.extents, 2);
        assert_eq!((inode.runs[0].physical, inode.runs[0].count), (free[1], 2));
        assert_eq!(
            inode.runs[1],
            Extent {
                logical: 2,
                physical: free[0],
                count: 1,
            }
        );
        assert!(bitmaps.iter().flatten().all(|&byte| byte == u8::MAX));
    }

    #[test]
    fn exhausted_extent_table_leaves_inode_and_bitmap_bits_untouched() {
        let free = [DATA_START + 1, BLOCKS_PER_BITMAP, 2 * BLOCKS_PER_BITMAP];
        let mut inode = empty_inode();
        inode.extents = 15;
        for (index, run) in inode.runs[..15].iter_mut().enumerate() {
            *run = Extent {
                logical: index as u32,
                physical: DATA_START + 2 * index as u32 + 10,
                count: 1,
            };
        }
        let prior = inode;
        let mut bitmaps = [[0; BLOCK]; BITMAP_PAGES];
        assert_eq!(
            allocate_growth(
                |home, out| {
                    fragmented_image(home, &free, out);
                    Ok(())
                },
                &mut inode,
                &mut bitmaps,
                DATA_START,
                2,
            ),
            Err(Error::Capacity)
        );
        assert_eq!(inode, prior);
        assert!(free.into_iter().all(|block| block_free(&bitmaps, block)));
    }
}
