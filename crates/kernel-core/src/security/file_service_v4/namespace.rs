//! Durable ordinary directory edits with the original FILE_AUTH admission.

use sha2::{Digest, Sha256};

use super::*;
use crate::security::{
    file_admission_flow_v1::FileAdmissionFlowV1,
    file_auth_context_v1::{AdmissionLedgerV1, Linearization},
    file_auth_v3::{Completion, operation_digest},
    file_media_unified_v1::BUSINESS_INODES,
    file_media_v0199::{BITMAP_START, BLOCK_COUNT, DATA_START, INODE_START, crc32c_zeroed},
    file_mount_v1::Acl,
    file_structure_v1::{Extent, INODE_BYTES, INODES, Inode},
};

const CREATE: u16 = 1;
const MKDIR: u16 = 7;
const UNLINK: u16 = 9;
const TRAVERSE: u32 = 1 << 14;
const ADD: u32 = (1 << 10) | TRAVERSE;
const REMOVE: u32 = (1 << 11) | TRAVERSE;
const FILE_RIGHTS: u32 = (1 << 8) | (1 << 9) | (1 << 13);
const DIR_RIGHTS: u32 = (1 << 10) | (1 << 11) | (1 << 12) | TRAVERSE;
const ACL_BYTES: usize = 64;
const ENTRY_BYTES: usize = 128;
const SLOTS_PER_BLOCK: usize = BLOCK / ENTRY_BYTES;
const MAX_DIR_SLOTS: usize = 256;
const BITMAP_PAGES: usize = (INODE_START - BITMAP_START) as usize;
const BLOCKS_PER_BITMAP: u32 = 8 * BLOCK as u32;
const NO_EXTENT: Extent = Extent {
    logical: 0,
    physical: 0,
    count: 0,
};

pub struct NamespaceJob<'a> {
    pub admission: &'a FileAdmissionFlowV1,
    pub ledger: &'a AdmissionLedgerV1,
    pub cap_selector: u64,
    pub frame: &'a [u8],
    pub key: ReceiptKey,
    pub allocation_floor: u32,
}

/// Three pages borrowed from the caller's already accounted v4 staging slot
/// after consuming the small original request. There is no second pool.
pub struct NamespaceStaging {
    parent: [u8; BLOCK],
    child: [u8; BLOCK],
    directory: [u8; BLOCK],
}

impl NamespaceStaging {
    pub const fn new() -> Self {
        Self {
            parent: [0; BLOCK],
            child: [0; BLOCK],
            directory: [0; BLOCK],
        }
    }
}

impl Default for NamespaceStaging {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Object {
    pub inode: u16,
    pub generation: u64,
    pub acl_generation: u64,
}

pub enum NamespaceProgress {
    Bound(CommittedRedo),
    Committed {
        receipt: FileReceiptV4,
        redo: CommittedRedo,
        object: Object,
    },
    AlreadyDone(FileReceiptV4),
}

/// Commit CREATE, MKDIR or UNLINK through the v1 ordinary-file transaction
/// owner. The dispatcher keeps the prepared parent and any child references
/// exclusive across BOUND and the effect. The removal callback checks the
/// live handle table before any bytes become durable. New caps are granted by
/// the EL1 reply path only after the returned transaction is confirmed.
pub fn commit_namespace<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    owner: &Owner<'_>,
    job: &NamespaceJob<'_>,
    work: &mut Workspace,
    staged: &mut NamespaceStaging,
    check_unopened: impl FnOnce(Object) -> Result<(), Error>,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<NamespaceProgress, Error> {
    let request = Request::decode(job.frame, job.cap_selector)?;
    let remove = request.op == UNLINK;
    let required = if remove { REMOVE } else { ADD };
    if !matches!(request.op, CREATE | MKDIR | UNLINK)
        || !(DATA_START..BLOCK_COUNT).contains(&job.allocation_floor)
        || !owner.mounted.may_overwrite_in_place()
    {
        return Err(Error::Unauthorized);
    }
    let proposal = job.admission.request();
    let ctx = job.admission.ctx();
    let registered = job
        .ledger
        .entry_by_admission(job.admission.admission_id())
        .ok_or(Error::Unauthorized)?;
    if job.admission.state() != Linearization::Execute
        || registered.completion != Completion::InFlight
        || job.ledger.boot_epoch() != ctx.boot_epoch
        || registered.key.auth_context_id != ctx.auth_context_id
        || registered.key.request_seq != job.key.request_seq
        || registered.proposal_digest != proposal.operation_digest
        || ctx.boot_epoch != owner.mounted.boot.boot_epoch
        || job.key.issued_boot_epoch != ctx.boot_epoch
        || job.key.request_id() != Some(request.request_id)
        || proposal.request_seq != job.key.request_seq
        || proposal.required_rights != u64::from(required)
        || proposal.frozen_data_digest != [0; 32]
        || operation_digest(ctx.boot_epoch, job.frame, &proposal)? != proposal.operation_digest
    {
        return Err(Error::Unauthorized);
    }
    let system = owner.verify(writer, &mut work.scratch)?;
    if let Some(snapshot) = owner.mounted.snapshot {
        snapshot.verify_current(&mut work.scratch, |block, out| {
            writer.read_committed(block, out)
        })?;
    }
    let inode_limit = if owner.mounted.snapshot.is_some() {
        BUSINESS_INODES as usize
    } else {
        INODES
    };
    let parent = usize::try_from(proposal.target_id).map_err(|_| Error::Invalid)?;
    if parent >= inode_limit || excluded(owner, system, parent) {
        return Err(Error::Unauthorized);
    }
    let base = home(system, SystemKind::Receipts)?;
    let index = work.read_ledger(writer, base, owner)?;
    let (slot, mut receipt) = records(&work.receipts)
        .find(|(_, record)| record_key(record) == job.key)
        .ok_or(Error::Stale)?;
    let group = index.groups[job.key.group_id as usize];
    let stream =
        index.streams[job.key.group_id as usize * STREAMS_PER_GROUP + job.key.stream_slot as usize];
    let principal = owner.config.principals()[job.key.group_id as usize];
    if group.generation != job.key.group_generation
        || group.boot_epoch != ctx.boot_epoch
        || group.flags != 1
        || u64::from(stream.generation) != job.key.stream_generation
        || stream.flags != 1
        || principal.id != ctx.principal
        || receipt.owner_principal_id != principal.id
    {
        return Err(Error::Unauthorized);
    }
    if receipt.status != ISSUED && receipt.operation_digest != proposal.operation_digest {
        return Err(Error::Conflict);
    }
    if receipt.status == DONE {
        return Ok(NamespaceProgress::AlreadyDone(receipt));
    }
    if !matches!(receipt.status, ISSUED | BOUND)
        || receipt.write_seq != 0
        || receipt.completed_prefix != 0
    {
        return Err(Error::Busy);
    }
    let parent_home = inode_home(parent);
    writer.read_committed(parent_home, &mut staged.parent)?;
    let mut directory = Inode::decode(inode_row(&mut staged.parent, parent))?;
    let acl_base = home(system, SystemKind::Acl)?;
    writer.read_committed(acl_home(acl_base, parent), &mut work.scratch)?;
    let acl = Acl::decode(acl_row(&mut work.scratch, parent))?;
    if directory.kind != 2
        || directory.generation != proposal.target_generation
        || acl.inode_id != parent as u32
        || acl.state != 1
        || acl.parent != directory.parent
        || acl.inode_generation != directory.generation
        || acl.acl_generation != proposal.acl_generation
        || acl.principal != principal
        || acl.owner_rights & required != required
    {
        return Err(Error::Unauthorized);
    }
    let name_end = 2 + usize::from(u16::from_le_bytes(request.payload[..2].try_into().unwrap()));
    let name = &request.payload[2..name_end];
    let (found, first_free) = lookup(writer, directory, name, &mut staged.directory)?;
    let slots = directory.size as usize / ENTRY_BYTES;
    let child_kind = if request.op == MKDIR { 2 } else { 1 };
    let (entry_at, child_id, rights) = if remove {
        let (position, child) = found.ok_or(Error::Unauthorized)?;
        (position, child as usize, 0)
    } else {
        if found.is_some() {
            return Err(Error::Conflict);
        }
        let rights =
            u32::from_le_bytes(request.payload[name_end..name_end + 4].try_into().unwrap());
        let allowed = if child_kind == 2 {
            DIR_RIGHTS
        } else {
            FILE_RIGHTS
        };
        if rights & !allowed != 0 {
            return Err(Error::Unauthorized);
        }
        let child = find_free_inode(writer, owner, system, inode_limit, &mut staged.child)?;
        (first_free.unwrap_or(slots), child, rights)
    };
    if entry_at >= MAX_DIR_SLOTS
        || child_id == 0
        || child_id >= inode_limit
        || child_id == parent
        || excluded(owner, system, child_id)
    {
        return Err(Error::Unauthorized);
    }
    let child_home = inode_home(child_id);
    writer.read_committed(child_home, &mut staged.child)?;
    let child = Inode::decode(inode_row(&mut staged.child, child_id))?;
    let child_acl_home = acl_home(acl_base, child_id);
    writer.read_committed(child_acl_home, &mut work.scratch)?;
    let child_acl = Acl::decode(acl_row(&mut work.scratch, child_id))?;
    if child_acl.inode_id != child_id as u32
        || child_acl.inode_generation != child.generation
        || child_acl.system_rights != 0
    {
        return Err(Error::Conflict);
    }
    let generation = if remove {
        if child.kind == 0
            || child.parent != parent as u32
            || child.parent_generation != directory.generation
            || child_acl.state != 1
            || child_acl.parent != parent as u32
        {
            return Err(Error::Conflict);
        }
        check_unopened(Object {
            inode: child_id as u16,
            generation: child.generation,
            acl_generation: child_acl.acl_generation,
        })?;
        if child.kind == 2 && !is_empty_directory(writer, child, &mut staged.directory)? {
            return Err(Error::Busy);
        }
        child.generation
    } else {
        if child.kind != 0 || child_acl.state == 1 {
            return Err(Error::Conflict);
        }
        child.generation.checked_add(1).ok_or(Error::Exhausted)?
    };
    let object = Object {
        inode: child_id as u16,
        generation,
        acl_generation: child_acl
            .acl_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?,
    };
    let closure_count = home_closure(slot)
        .ok_or(Error::Invalid)?
        .receipt_block_count
        + 1;
    if receipt.status == ISSUED {
        let plan = writer.prepare(closure_count)?;
        receipt.status = BOUND;
        receipt.operation_digest = proposal.operation_digest;
        set_position(&mut receipt, plan);
        write_receipt(work, slot, receipt)?;
        let (images, count) = receipt_images(work, base, slot)?;
        return writer
            .append(plan, &images[..count], reserve)
            .map(NamespaceProgress::Bound);
    }

    let closure = home_closure(slot).ok_or(Error::Invalid)?;
    let receipt_at = closure.receipt.first * BLOCK;
    work.receipts.copy_within(
        receipt_at..receipt_at + closure.receipt_block_count * BLOCK,
        0,
    );
    let (receipt_pages, bitmaps) = work.receipts.split_at_mut(2 * BLOCK);
    let bitmaps: &mut [[u8; BLOCK]; BITMAP_PAGES] =
        bitmaps.as_chunks_mut::<BLOCK>().0.try_into().unwrap();
    let mut changed = 0;
    let grows = !remove && entry_at == slots;
    let logical = (entry_at / SLOTS_PER_BLOCK) as u32;
    let dir_home = if grows && slots.is_multiple_of(SLOTS_PER_BLOCK) {
        let block = allocate(writer, bitmaps, job.allocation_floor, &mut changed)?;
        append_extent(&mut directory, logical, block)?;
        for raw in staged.directory.chunks_exact_mut(ENTRY_BYTES) {
            write_entry(raw, None)?;
        }
        block
    } else {
        let block = physical(directory, logical)?;
        writer.read_committed(block, &mut staged.directory)?;
        block
    };
    let entry_at = (entry_at % SLOTS_PER_BLOCK) * ENTRY_BYTES;
    let raw = &mut staged.directory[entry_at..entry_at + ENTRY_BYTES];
    if remove
        && (entry_id(raw)? != Some(child_id as u32)
            || u64::from_le_bytes(raw[8..16].try_into().unwrap()) != generation)
    {
        return Err(Error::Conflict);
    }
    write_entry(raw, (!remove).then_some((object, name)))?;
    if grows {
        directory.size += ENTRY_BYTES as u64;
        encode_inode(inode_row(&mut staged.parent, parent), directory)?;
    }
    if remove {
        free_extents(writer, bitmaps, child, &mut changed)?;
    }
    let child_next = Inode {
        kind: if remove { 0 } else { child_kind },
        generation,
        size: 0,
        durable_write_seq: 0,
        parent: if remove { 0 } else { parent as u32 },
        parent_generation: if remove { 0 } else { directory.generation },
        extents: 0,
        runs: [NO_EXTENT; 16],
    };
    let child_page = if child_home == parent_home {
        &mut staged.parent
    } else {
        &mut staged.child
    };
    encode_inode(inode_row(child_page, child_id), child_next)?;
    let acl = Acl {
        inode_id: child_id as u32,
        state: if remove { 2 } else { 1 },
        inode_generation: generation,
        principal: if remove {
            child_acl.principal
        } else {
            principal
        },
        owner_rights: rights,
        system_rights: 0,
        acl_generation: object.acl_generation,
        parent: if remove { 0 } else { parent as u32 },
    };
    encode_acl(acl_row(&mut work.scratch, child_id), acl)?;
    let separate_parent = grows && child_home != parent_home;
    let count = closure_count + 3 + usize::from(separate_parent) + changed.count_ones() as usize;
    let plan = writer.prepare(count)?;
    if receipt.log_epoch > plan.log_epoch || receipt.commit_lsn >= plan.begin_lsn {
        return Err(Error::Conflict);
    }
    let mut digest = Sha256::new();
    digest.update(b"CYX/FILE-NAMESPACE/v1");
    digest.update(proposal.operation_digest);
    digest.update(object.inode.to_le_bytes());
    digest.update(object.generation.to_le_bytes());
    digest.update(object.acl_generation.to_le_bytes());
    receipt.output_digest = digest.finalize().into();
    receipt.status = DONE;
    set_position(&mut receipt, plan);
    let offset = slot * RECEIPT_BYTES % BLOCK;
    receipt_pages[offset..offset + RECEIPT_BYTES].copy_from_slice(&receipt.encode()?);
    let mut images = core::array::from_fn::<_, 11, _>(|_| RedoImage {
        home: 0,
        contents: &[0; BLOCK],
    });
    let mut next = 0;
    let mut add = |home, contents| {
        images[next] = RedoImage { home, contents };
        next += 1;
    };
    for (offset, raw) in receipt_pages
        .as_chunks::<BLOCK>()
        .0
        .iter()
        .take(closure.receipt_block_count)
        .enumerate()
    {
        add(base + closure.receipt.first as u32 + offset as u32, raw);
    }
    add(base + 6, &work.index);
    add(
        child_home,
        if child_home == parent_home {
            &staged.parent
        } else {
            &staged.child
        },
    );
    if separate_parent {
        add(parent_home, &staged.parent);
    }
    add(child_acl_home, &work.scratch);
    add(dir_home, &staged.directory);
    for (index, page) in bitmaps.iter().enumerate() {
        if changed & (1 << index) != 0 {
            add(BITMAP_START + index as u32, page);
        }
    }
    let redo = writer.append(plan, &images[..next], reserve)?;
    Ok(NamespaceProgress::Committed {
        receipt,
        redo,
        object,
    })
}

fn excluded(owner: &Owner<'_>, system: &[SystemObject; 4], id: usize) -> bool {
    owner.protected_inode == Some(id as u16)
        || system.iter().any(|object| usize::from(object.inode) == id)
}

fn set_position(receipt: &mut FileReceiptV4, plan: RedoTransaction) {
    receipt.log_epoch = plan.log_epoch;
    receipt.txid = plan.txid;
    receipt.commit_lsn = plan.commit_lsn;
}

fn inode_home(id: usize) -> u32 {
    INODE_START + (id * INODE_BYTES / BLOCK) as u32
}
fn acl_home(base: u32, id: usize) -> u32 {
    base + (id * ACL_BYTES / BLOCK) as u32
}

fn inode_row(block: &mut [u8; BLOCK], id: usize) -> &mut [u8] {
    let at = id * INODE_BYTES % BLOCK;
    &mut block[at..at + INODE_BYTES]
}

fn acl_row(block: &mut [u8; BLOCK], id: usize) -> &mut [u8] {
    let at = id * ACL_BYTES % BLOCK;
    &mut block[at..at + ACL_BYTES]
}

fn find_free_inode<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    owner: &Owner<'_>,
    system: &[SystemObject; 4],
    limit: usize,
    raw: &mut [u8; BLOCK],
) -> Result<usize, Error> {
    let mut prior = u32::MAX;
    for id in (1..limit).filter(|&id| !excluded(owner, system, id)) {
        let home = inode_home(id);
        if home != prior {
            writer.read_committed(home, raw)?;
            prior = home;
        }
        let inode = Inode::decode(inode_row(raw, id))?;
        if inode.kind == 0 && inode.generation != u64::MAX {
            return Ok(id);
        }
    }
    Err(Error::Capacity)
}

fn physical(inode: Inode, logical: u32) -> Result<u32, Error> {
    inode.runs[..usize::from(inode.extents)]
        .iter()
        .find_map(|run| {
            let offset = logical.checked_sub(run.logical)?;
            (offset < run.count).then(|| run.physical + offset)
        })
        .ok_or(Error::Conflict)
}

fn append_extent(inode: &mut Inode, logical: u32, physical: u32) -> Result<(), Error> {
    let count = usize::from(inode.extents);
    if let Some(last) = inode.runs[..count].last_mut()
        && last.physical + last.count == physical
    {
        last.count += 1;
    } else {
        *inode.runs.get_mut(count).ok_or(Error::Capacity)? = Extent {
            logical,
            physical,
            count: 1,
        };
        inode.extents += 1;
    }
    Ok(())
}

fn entry_id(raw: &[u8]) -> Result<Option<u32>, Error> {
    let id = u32::from_le_bytes(raw[..4].try_into().unwrap());
    if u32::from_le_bytes(raw[124..].try_into().unwrap()) != crc32c_zeroed(raw, 124)? {
        return Err(Error::Conflict);
    }
    if id == u32::MAX {
        if raw[4..124].iter().any(|&byte| byte != 0) {
            return Err(Error::Invalid);
        }
        return Ok(None);
    }
    let n = usize::from(u16::from_le_bytes(raw[4..6].try_into().unwrap()));
    if id == 0
        || id >= INODES as u32
        || raw[6..8] != [0; 2]
        || n > 63
        || !super::super::valid_component(&raw[16..16 + n])
    {
        return Err(Error::Invalid);
    }
    Ok(Some(id))
}

fn lookup<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    dir: Inode,
    name: &[u8],
    raw: &mut [u8; BLOCK],
) -> Result<(Option<(usize, u32)>, Option<usize>), Error> {
    let mut found = None;
    let mut empty = None;
    let slots = dir.size as usize / ENTRY_BYTES;
    for logical in 0..slots.div_ceil(SLOTS_PER_BLOCK) {
        writer.read_committed(physical(dir, logical as u32)?, raw)?;
        for (index, slot) in raw
            .chunks_exact(ENTRY_BYTES)
            .take(slots - logical * SLOTS_PER_BLOCK)
            .enumerate()
        {
            let index = logical * SLOTS_PER_BLOCK + index;
            if let Some(id) = entry_id(slot)? {
                let len = usize::from(u16::from_le_bytes(slot[4..6].try_into().unwrap()));
                if &slot[16..16 + len] == name && found.replace((index, id)).is_some() {
                    return Err(Error::Conflict);
                }
            } else if empty.is_none() {
                empty = Some(index);
            }
        }
    }
    Ok((found, empty))
}

fn is_empty_directory<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    dir: Inode,
    raw: &mut [u8; BLOCK],
) -> Result<bool, Error> {
    let slots = dir.size as usize / ENTRY_BYTES;
    for logical in 0..slots.div_ceil(SLOTS_PER_BLOCK) {
        writer.read_committed(physical(dir, logical as u32)?, raw)?;
        for slot in raw
            .chunks_exact(ENTRY_BYTES)
            .take(slots - logical * SLOTS_PER_BLOCK)
        {
            if entry_id(slot)?.is_some() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn locate(block: u32) -> (usize, usize, u8) {
    let offset = block % BLOCKS_PER_BITMAP;
    (
        (block / BLOCKS_PER_BITMAP) as usize,
        (offset / 8) as usize,
        1 << (offset % 8),
    )
}

fn allocate<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    bitmaps: &mut [[u8; BLOCK]; BITMAP_PAGES],
    floor: u32,
    changed: &mut u8,
) -> Result<u32, Error> {
    let mut last = BITMAP_PAGES;
    for block in floor..BLOCK_COUNT {
        let (page, offset, bit) = locate(block);
        if page != last {
            writer.read_committed(BITMAP_START + page as u32, &mut bitmaps[page])?;
            last = page;
        }
        if bitmaps[page][offset] & bit == 0 {
            bitmaps[page][offset] |= bit;
            *changed |= 1 << page;
            return Ok(block);
        }
    }
    Err(Error::Capacity)
}

fn free_extents<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    bitmaps: &mut [[u8; BLOCK]; BITMAP_PAGES],
    inode: Inode,
    changed: &mut u8,
) -> Result<(), Error> {
    for run in &inode.runs[..usize::from(inode.extents)] {
        for block in run.physical..run.physical + run.count {
            let (page, offset, bit) = locate(block);
            if *changed & (1 << page) == 0 {
                writer.read_committed(BITMAP_START + page as u32, &mut bitmaps[page])?;
                *changed |= 1 << page;
            }
            if bitmaps[page][offset] & bit == 0 {
                return Err(Error::Conflict);
            }
            bitmaps[page][offset] &= !bit;
        }
    }
    Ok(())
}

fn write_entry(raw: &mut [u8], entry: Option<(Object, &[u8])>) -> Result<(), Error> {
    raw.fill(0);
    let id = if let Some((object, name)) = entry {
        raw[4..6].copy_from_slice(&(name.len() as u16).to_le_bytes());
        raw[8..16].copy_from_slice(&object.generation.to_le_bytes());
        raw[16..16 + name.len()].copy_from_slice(name);
        u32::from(object.inode)
    } else {
        u32::MAX
    };
    raw[..4].copy_from_slice(&id.to_le_bytes());
    seal(raw, 124)
}

fn encode_inode(raw: &mut [u8], inode: Inode) -> Result<(), Error> {
    raw.fill(0);
    raw[..4].copy_from_slice(&0x4359_494eu32.to_le_bytes());
    raw[4..6].copy_from_slice(&inode.kind.to_le_bytes());
    for (at, value) in [
        (8, inode.generation),
        (16, inode.size),
        (24, inode.durable_write_seq),
        (40, inode.parent_generation),
    ] {
        raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    raw[32..34].copy_from_slice(&inode.extents.to_le_bytes());
    raw[36..40].copy_from_slice(&inode.parent.to_le_bytes());
    for (entry, run) in raw[48..240].chunks_exact_mut(12).zip(inode.runs) {
        entry[..4].copy_from_slice(&run.logical.to_le_bytes());
        entry[4..8].copy_from_slice(&run.physical.to_le_bytes());
        entry[8..12].copy_from_slice(&run.count.to_le_bytes());
    }
    seal(raw, 252)?;
    if Inode::decode(raw)? != inode {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn encode_acl(raw: &mut [u8], acl: Acl) -> Result<(), Error> {
    raw.fill(0);
    for (at, value) in [
        (0, acl.inode_id),
        (4, acl.state),
        (32, acl.owner_rights),
        (36, acl.system_rights),
        (48, acl.parent),
    ] {
        raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [
        (8, acl.inode_generation),
        (16, acl.principal.id),
        (24, acl.principal.generation),
        (40, acl.acl_generation),
    ] {
        raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    seal(raw, 60)?;
    if Acl::decode(raw)? != acl {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn seal(raw: &mut [u8], at: usize) -> Result<(), Error> {
    let crc = crc32c_zeroed(raw, at)?;
    raw[at..at + 4].copy_from_slice(&crc.to_le_bytes());
    Ok(())
}
