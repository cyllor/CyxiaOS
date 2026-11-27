//! Read-only witness over an independently encoded D7 historical export.
//! This opt-in fixture has a compiled test read grant and validates the
//! actual ACL and archived bytes read from an isolated VirtIO device.

use super::{BootInfo, cpu, report, scratch_blk};
use crate::virtio_platform::Board;
use cyxia_driver_virtio::{Transport, queue::BatchMemory};
use cyxia_kernel_core::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    file_media_unified_v1::{
        BLOCK_COUNT, DATA_START, SNAP_CAP_HISTORY_READ, SUPER_BYTES,
        catalog_candidate::CatalogContext,
        history_candidate::{HistoryCaller, HistoryReadGrant, HistorySource, read_history},
        slot_candidate::SlotIdentity,
    },
    file_mount_v1::Acl,
    offline_config_v1::Principal,
    snapshot_read_v4::history_prefix_digest,
};

const UUID: [u8; 16] = *b"CYX-HISTORY-VEC!";
const FILE: &[u8] = b"/readme.txt";
const CATALOG_SHA256: [u8; 32] = [
    0x86, 0x84, 0x46, 0xca, 0xdd, 0x7f, 0x20, 0x31, 0x11, 0x5e, 0x66, 0x01, 0xf1, 0x8c, 0x7f, 0xcd,
    0x89, 0x32, 0x19, 0xbf, 0xbb, 0x1b, 0x0f, 0x0c, 0x79, 0xaf, 0xa6, 0xe2, 0x1e, 0x23, 0x41, 0x6c,
];
const DATA_SHA256: [u8; 32] = [
    0x8f, 0xf5, 0x34, 0x28, 0x93, 0xe8, 0xf7, 0x98, 0xb9, 0xb4, 0x17, 0xbd, 0x8a, 0x02, 0x85, 0x25,
    0xa8, 0xa5, 0x46, 0x89, 0x89, 0x8b, 0xed, 0xd7, 0x47, 0x4e, 0xe8, 0xec, 0xe5, 0x1d, 0x51, 0xc4,
];

static mut DMA: BatchMemory = BatchMemory::zeroed();

fn attach(info: &BootInfo) -> Result<scratch_blk::ScratchBlock, Error> {
    let mut selected = None;
    for resource in info.virtio.get(..info.virtio_count).ok_or(Error::Invalid)? {
        let base = resource.base.0;
        if base < 0x0a000000
            || base
                .checked_add(resource.len)
                .is_none_or(|end| end > 0x0a200000)
        {
            continue;
        }
        // SAFETY: the range is inside the DTB-described mapped VirtIO aperture.
        let Ok(transport) =
            (unsafe { Transport::attach((crate::HIGH + base) as usize, resource.len as usize) })
        else {
            continue;
        };
        if transport.device_id() == 2 && selected.replace(transport).is_some() {
            return Err(Error::Conflict);
        }
    }
    // SAFETY: CPU0 enters this terminal fixture once. DMA stays pinned.
    let dma = unsafe { &mut *core::ptr::addr_of_mut!(DMA) };
    let mut disk = scratch_blk::ScratchBlock::attach(selected.ok_or(Error::Invalid)?, dma, &Board)
        .map_err(|_| Error::Unknown)?;
    if !disk.read_only() || disk.sectors() != u64::from(BLOCK_COUNT) * 8 {
        return Err(Error::Unauthorized);
    }
    let now = cyxia_driver_virtio::Platform::now_ns(&Board);
    disk.set_notify_policy(2, 1, now.saturating_add(1_000_000_000), now)
        .map_err(|_| Error::Invalid)?;
    Ok(disk)
}

pub(super) fn run(info: &BootInfo) -> ! {
    assert_eq!(cpu::slot(), 0);
    let mut disk = attach(info).expect("one read-only test device");
    let mut reads = 0u64;
    let mut read = |block: u32, out: &mut [u8; SUPER_BYTES]| {
        scratch_blk::sectors(&mut disk, u64::from(block) * 8, None, out)?;
        reads += 1;
        Ok(())
    };
    let mut raw = [0; SUPER_BYTES];
    read(DATA_START, &mut raw).expect("read test boot identity");
    let boot = BootEpochStoreV1::decode(&raw).expect("test boot identity");
    read(DATA_START + 8, &mut raw).expect("read test ACL");
    let acl = Acl::decode(&raw[64..128]).expect("test file ACL");
    let source = HistorySource {
        catalog: CatalogContext {
            fs_uuid: UUID,
            catalog_generation: 3,
            slot_store_generation: 2,
            live_view_epoch: 9,
            committed_lsn: 42,
            online_age_ns: 190_000_000_000,
        },
        catalog_sha256: CATALOG_SHA256,
        root_block: 4300,
        data_block: 4301,
        data_sha256: DATA_SHA256,
    };
    let principal = Principal {
        id: 1,
        generation: 1,
    };
    let grant = HistoryReadGrant {
        boot_epoch: 2,
        principal,
        snapshot: SlotIdentity {
            fs_uuid: UUID,
            snapshot_id: 10,
            slot: 0,
            slot_generation: 4,
            captured_live_view_epoch: 8,
            capture_commit_lsn: 33,
            created_online_age_ns: 180_000_000_000,
        },
        snapshot_rights: SNAP_CAP_HISTORY_READ,
        acl_generation: 3,
        prefix: FILE,
        prefix_sha256: history_prefix_digest(FILE),
    };
    let caller = HistoryCaller {
        boot,
        principal,
        file_acl: acl,
    };
    let result =
        read_history(&source, caller, grant, FILE, read, &mut raw).expect("verified archived file");
    assert_eq!(result.bytes, 24);
    report(
        "V020_HISTORY_CANDIDATE_READ",
        result.snapshot.snapshot_id,
        u64::from(result.snapshot.slot),
        result.bytes as u64,
    );
    let word = |at| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
    report("V020_HISTORY_CANDIDATE_BYTES", word(0), word(8), word(16));
    let stats = disk.notify_stats();
    report(
        "V020_HISTORY_CANDIDATE_IO",
        reads,
        stats.published,
        stats.completed,
    );
    super::super::log(b"V020_HISTORY_READONLY_FIXTURE_PASS\n");
    super::super::halt()
}
