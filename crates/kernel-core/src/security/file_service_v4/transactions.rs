//! Durable v1 transactions for an authenticated, serialized file owner.

use crate::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_auth_v3::FILE_SERVICE_ROLE,
    file_index_v0199::{FileStreamIndexV4, STREAMS_PER_GROUP, SecurityStateStoreV2},
    file_media_unified_v1::FILE_TRANSACTION_WORKSPACE_KIB,
    file_media_v0199::{FileReceiptV4, RECEIPT_BYTES},
    file_mount_v1::MountEvidence,
    file_receipt_query_v4::{ReceiptKey, ReceiptQueryCaller},
    file_receipt_store_v0199::{RECEIPT_STORE_BYTES, home_closure, scan_receipts_with_index},
    file_structure_v1::{BLOCK, SystemKind, SystemObject},
    offline_config_v1::VerifiedOfflineConfig,
    recovery_v1::{CommittedRedo, RecoveryWorkspace, RedoImage, RedoTransaction, RedoWriter},
};

use super::Request;

#[path = "namespace.rs"]
mod namespace;
pub use namespace::{NamespaceJob, NamespaceProgress, NamespaceStaging, Object, commit_namespace};

const SERVICE_SLOT: usize = (FILE_SERVICE_ROLE - 1) as usize;
const ISSUE: u16 = 10;
const ISSUED: u16 = 1;
const BOUND: u16 = 2;
const DONE: u16 = 3;
const UNKNOWN: u16 = 5;
const ACK: u16 = 12;

/// Supplied by the trusted EL0 role 12 transport after the live role and
/// signed mount were bound. User frames do not supply these identities.
pub struct Owner<'a> {
    pub mounted: &'a MountEvidence,
    pub config: &'a VerifiedOfflineConfig<'a>,
    pub service_generation: u64,
    /// Recovery carrier independently bound by the signed boot owner.
    pub protected_inode: Option<u16>,
}

pub struct Workspace {
    receipts: [u8; RECEIPT_STORE_BYTES],
    index: [u8; BLOCK],
    scratch: [u8; BLOCK],
}

const _: () = assert!(
    core::mem::size_of::<Workspace>() + core::mem::size_of::<RecoveryWorkspace>()
        <= FILE_TRANSACTION_WORKSPACE_KIB as usize * 1024
);

impl Workspace {
    pub const fn new() -> Self {
        Self {
            receipts: [0; RECEIPT_STORE_BYTES],
            index: [0; BLOCK],
            scratch: [0; BLOCK],
        }
    }

    fn read_ledger<I: EpochBlockIo>(
        &mut self,
        writer: &mut RedoWriter<'_, I>,
        base: u32,
        owner: &Owner<'_>,
    ) -> Result<FileStreamIndexV4, Error> {
        let pages = self.receipts.as_chunks_mut::<BLOCK>().0;
        for (offset, raw) in pages.iter_mut().enumerate() {
            writer.read_committed(base + offset as u32, raw)?;
        }
        writer.read_committed(base + pages.len() as u32, &mut self.index)?;
        scan_receipts_with_index(&self.receipts, &self.index, owner.mounted.boot.fs_uuid)?;
        let index = FileStreamIndexV4::decode(&self.index)?;
        if index.groups.map(|group| group.manifest_principal_id)
            != owner.config.principals().map(|principal| principal.id)
            || index
                .groups
                .iter()
                .any(|group| group.boot_epoch > owner.mounted.boot.boot_epoch)
        {
            return Err(Error::Unauthorized);
        }
        Ok(index)
    }
}

impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

impl Owner<'_> {
    fn verify<'a, I: EpochBlockIo>(
        &'a self,
        writer: &mut RedoWriter<'_, I>,
        scratch: &mut [u8; BLOCK],
    ) -> Result<&'a [SystemObject; 4], Error> {
        let system = self.mounted.baseline_system().ok_or(Error::Unauthorized)?;
        let evidence = writer.evidence().ok_or(Error::Unknown)?;
        if evidence.superblock.fs_uuid != self.mounted.boot.fs_uuid
            || evidence.incomplete_tail
            || self.service_generation == 0
        {
            return Err(Error::Unauthorized);
        }
        self.config.check_committed(&self.mounted.security)?;
        writer.read_committed(home(system, SystemKind::Security)?, scratch)?;
        let state = SecurityStateStoreV2::decode(scratch)?;
        self.config.check_committed(&state)?;
        writer.read_committed(home(system, SystemKind::BootEpoch)?, scratch)?;
        let boot = BootEpochStoreV1::decode(scratch)?;
        if boot != self.mounted.boot
            || boot.boot_epoch == 0
            || !boot.matches(&state)
            || state.service_generations[SERVICE_SLOT] != self.service_generation
            || state.isolated_service_bitmap & (1 << SERVICE_SLOT) != 0
        {
            return Err(Error::Stale);
        }
        Ok(system)
    }
}

fn home(system: &[SystemObject; 4], kind: SystemKind) -> Result<u32, Error> {
    system
        .iter()
        .find(|item| item.kind == kind)
        .map(|item| item.first_block)
        .ok_or(Error::Invalid)
}

fn group_id(owner: &Owner<'_>, caller: ReceiptQueryCaller) -> Result<usize, Error> {
    if caller.boot_epoch != owner.mounted.boot.boot_epoch
        || caller.service_generation != owner.service_generation
    {
        return Err(Error::Stale);
    }
    owner
        .config
        .principals()
        .iter()
        .position(|principal| principal.id == caller.principal_id)
        .ok_or(Error::Unauthorized)
}

fn record_key(receipt: &FileReceiptV4) -> ReceiptKey {
    ReceiptKey {
        fs_uuid: receipt.fs_uuid,
        issued_boot_epoch: receipt.issued_boot_epoch,
        group_id: receipt.group_id,
        group_generation: receipt.group_generation,
        stream_slot: receipt.stream_slot,
        stream_generation: receipt.stream_generation,
        request_seq: receipt.request_seq,
    }
}

fn records(bytes: &[u8; RECEIPT_STORE_BYTES]) -> impl Iterator<Item = (usize, FileReceiptV4)> {
    // read_ledger validated every nonempty record before use.
    bytes
        .chunks_exact(RECEIPT_BYTES)
        .enumerate()
        .filter_map(|(slot, raw)| {
            FileReceiptV4::decode(raw)
                .ok()
                .map(|receipt| (slot, receipt))
        })
}

fn receipt_images(
    work: &Workspace,
    base: u32,
    slot: usize,
) -> Result<([RedoImage<'_>; 3], usize), Error> {
    let closure = home_closure(slot).ok_or(Error::Invalid)?;
    let pages = work.receipts.as_chunks::<BLOCK>().0;
    let image = |offset: usize| RedoImage {
        home: base + offset as u32,
        contents: &pages[offset],
    };
    let index = || RedoImage {
        home: base + pages.len() as u32,
        contents: &work.index,
    };
    Ok((
        [
            image(closure.receipt.first),
            closure.receipt.second.map_or_else(index, image),
            index(),
        ],
        closure.receipt_block_count + 1,
    ))
}

/// Exact current ticket and the append that issued it, if freshly allocated.
pub struct Ticket {
    pub key: ReceiptKey,
    pub issued: Option<CommittedRedo>,
}

/// Allocate or replay a ticket for an already authorized, active file stream.
/// The protected transport owns the caller qualification and the allocation
/// rate credit. This operation grants neither a FileCap nor an admission.
pub fn allocate_ticket<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    owner: &Owner<'_>,
    work: &mut Workspace,
    caller: ReceiptQueryCaller,
    frame: &[u8],
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<Ticket, Error> {
    let request = Request::decode(frame, 0)?;
    if request.op != ISSUE {
        return Err(Error::Invalid);
    }
    let group_id = group_id(owner, caller)?;
    let stream_slot = usize::from(request.payload[0]);
    let seq = u64::from_le_bytes(request.payload[8..].try_into().unwrap());
    let base = home(
        owner.verify(writer, &mut work.scratch)?,
        SystemKind::Receipts,
    )?;
    let mut index = work.read_ledger(writer, base, owner)?;
    let group = index.groups[group_id];
    let stream = &mut index.streams[group_id * STREAMS_PER_GROUP + stream_slot];
    if group.boot_epoch != caller.boot_epoch || group.flags != 1 || stream.flags != 1 {
        return Err(Error::Stale);
    }
    let key = ReceiptKey {
        fs_uuid: index.fs_uuid,
        issued_boot_epoch: caller.boot_epoch,
        group_id: group_id as u32,
        group_generation: group.generation,
        stream_slot: stream_slot as u64,
        stream_generation: u64::from(stream.generation),
        request_seq: seq,
    };
    let request_id = key.request_id().ok_or(Error::Exhausted)?;
    if seq <= stream.retired_through {
        return Err(Error::Stale);
    }
    if seq <= stream.issued_hi {
        return records(&work.receipts)
            .any(|(_, receipt)| record_key(&receipt) == key)
            .then_some(Ticket { key, issued: None })
            .ok_or(Error::Stale);
    }
    if stream.issued_hi.checked_add(1) != Some(seq) {
        return Err(Error::Busy);
    }
    let mut occupied = 0;
    for (_, receipt) in
        records(&work.receipts).filter(|(_, receipt)| receipt.group_id == key.group_id)
    {
        occupied += 1;
        if receipt.stream_slot == key.stream_slot
            && matches!(receipt.status, ISSUED | BOUND | UNKNOWN)
        {
            return Err(Error::Busy);
        }
    }
    if occupied >= STREAMS_PER_GROUP {
        return Err(Error::Capacity);
    }
    let slot = work
        .receipts
        .chunks_exact(RECEIPT_BYTES)
        .position(|raw| raw.iter().all(|&byte| byte == 0))
        .ok_or(Error::Capacity)?;
    let receipt = FileReceiptV4 {
        fs_uuid: key.fs_uuid,
        issued_boot_epoch: key.issued_boot_epoch,
        group_id: key.group_id,
        group_generation: key.group_generation,
        stream_slot: key.stream_slot,
        stream_generation: key.stream_generation,
        request_seq: key.request_seq,
        status: ISSUED,
        request_id,
        owner_principal_id: caller.principal_id,
        log_epoch: 0,
        txid: 0,
        commit_lsn: 0,
        write_seq: 0,
        result: 0,
        completed_prefix: 0,
        operation_digest: [0; 32],
        output_digest: [0; 32],
    };
    stream.issued_hi = seq;
    index.generation = index.generation.checked_add(1).ok_or(Error::Exhausted)?;
    index.encode_into(&mut work.index)?;
    write_receipt(work, slot, receipt)?;
    let (images, count) = receipt_images(work, base, slot)?;
    let issued = writer.append(writer.prepare(count)?, &images[..count], reserve)?;
    Ok(Ticket {
        key,
        issued: Some(issued),
    })
}

fn write_receipt(work: &mut Workspace, slot: usize, receipt: FileReceiptV4) -> Result<(), Error> {
    let start = slot * RECEIPT_BYTES;
    work.receipts[start..start + RECEIPT_BYTES].copy_from_slice(&receipt.encode()?);
    Ok(())
}

/// Bind an authorized persistent principal and stream to the current boot.
/// Streams with retained records remain unavailable for new generations.
pub fn bind_stream<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    owner: &Owner<'_>,
    work: &mut Workspace,
    caller: ReceiptQueryCaller,
    slot: u8,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<Option<CommittedRedo>, Error> {
    let group_id = group_id(owner, caller)?;
    if usize::from(slot) >= STREAMS_PER_GROUP {
        return Err(Error::Invalid);
    }
    let base = home(
        owner.verify(writer, &mut work.scratch)?,
        SystemKind::Receipts,
    )?;
    let mut index = work.read_ledger(writer, base, owner)?;
    let group = &mut index.groups[group_id];
    let first = group_id * STREAMS_PER_GROUP;
    let streams = &mut index.streams[first..first + STREAMS_PER_GROUP];
    if group.flags == 2 {
        return Err(Error::Unauthorized);
    }
    let stream = streams[usize::from(slot)];
    if group.flags == 1 && group.boot_epoch == caller.boot_epoch && stream.flags == 1 {
        return Ok(None);
    }
    if stream.issued_hi != stream.retired_through {
        return Err(Error::Busy);
    }
    if group.boot_epoch != caller.boot_epoch {
        group.generation = group.generation.checked_add(1).ok_or(Error::Exhausted)?;
        group.boot_epoch = caller.boot_epoch;
        group.flags = 1;
        // A stream's generation must also change before it can accept work
        // in this group generation. The old full keys remain queryable.
        for inherited in streams.iter_mut().filter(|stream| stream.flags == 1) {
            inherited.flags = 2;
        }
    }
    let stream = &mut streams[usize::from(slot)];
    stream.generation = stream.generation.checked_add(1).ok_or(Error::Exhausted)?;
    stream.flags = 1;
    index.generation = index.generation.checked_add(1).ok_or(Error::Exhausted)?;
    index.encode_into(&mut work.index)?;
    let image = RedoImage {
        home: base + (RECEIPT_STORE_BYTES / BLOCK) as u32,
        contents: &work.index,
    };
    writer
        .append(writer.prepare(1)?, &[image], reserve)
        .map(Some)
}

/// Retire exactly the next terminal receipt for an original persistent
/// principal. The coordinator verifies COMMIT evidence and charges the
/// bound retirement credit before supplying the effect attestation.
pub fn ack_ticket<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    owner: &Owner<'_>,
    work: &mut Workspace,
    caller: ReceiptQueryCaller,
    frame: &[u8],
    prove_result: impl FnOnce(&mut RedoWriter<'_, I>, &FileReceiptV4) -> Result<(), Error>,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<CommittedRedo, Error> {
    let request = Request::decode(frame, 0)?;
    if request.op != ACK {
        return Err(Error::Invalid);
    }
    let key = ReceiptKey::decode(&request.payload[..56])?;
    let group_id = group_id(owner, caller)?;
    if key.request_id() != Some(request.request_id) || key.group_id as usize != group_id {
        return Err(Error::Unauthorized);
    }
    let base = home(
        owner.verify(writer, &mut work.scratch)?,
        SystemKind::Receipts,
    )?;
    let mut index = work.read_ledger(writer, base, owner)?;
    let (slot, receipt) = records(&work.receipts)
        .find(|(_, receipt)| record_key(receipt) == key)
        .ok_or(Error::Stale)?;
    if receipt.owner_principal_id != caller.principal_id
        || receipt.output_digest != request.payload[56..]
    {
        return Err(Error::Conflict);
    }
    let stream = &mut index.streams[group_id * STREAMS_PER_GROUP + key.stream_slot as usize];
    if !matches!(receipt.status, DONE | 4 | 6)
        || stream.retired_through.checked_add(1) != Some(key.request_seq)
    {
        return Err(Error::Busy);
    }
    prove_result(writer, &receipt)?;
    stream.retired_through = key.request_seq;
    index.generation = index.generation.checked_add(1).ok_or(Error::Exhausted)?;
    index.encode_into(&mut work.index)?;
    let start = slot * RECEIPT_BYTES;
    work.receipts[start..start + RECEIPT_BYTES].fill(0);
    let (images, count) = receipt_images(work, base, slot)?;
    writer.append(writer.prepare(count)?, &images[..count], reserve)
}
