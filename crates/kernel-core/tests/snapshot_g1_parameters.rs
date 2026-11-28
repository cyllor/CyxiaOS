//! Cross-check G1 parameter ownership across the unified snapshot codecs.
//! The retention comparison below is a candidate carry-over from V18.

use core::mem::size_of;
use cyxia_kernel_core::{
    control_plane::role_manifest_v0199::CONTROL_POOL_LIMIT,
    frame_meta_v0199 as frames,
    security::{
        file_media_unified_v1::{
            self as unified, UnifiedSystemKind, catalog_candidate::lifecycle::CaptureWorkspace,
        },
        file_media_v0199 as media, file_service_v4 as file_wire, file_structure_v1 as structure,
        snapshot_request_store_v1::{self as requests, RequestStoreHeader, Watermark},
        snapshot_service_v4::{FILE_REQ_KEY_BYTES, PRINCIPALS, SNAPSHOT_KEY_BYTES},
    },
};
use cyxia_prototype::snapshot as legacy;

#[test]
fn d1_geometry_matches_file_format_and_system_object_owners() {
    assert_eq!(
        [
            media::SUPER_BYTES,
            media::BLOCK_COUNT as usize,
            structure::INODES
        ],
        [4096, 131_072, 256]
    );
    assert_eq!(
        [media::BITMAP_START, media::INODE_START, media::DATA_START],
        [4098, 4102, 4118]
    );
    assert_eq!(
        unified::SLOT_MIRROR_BYTES,
        unified::BUSINESS_INODES as usize * structure::INODE_BYTES
    );
    assert_eq!(
        unified::SLOT_MIRROR_BYTES,
        unified::SLOT_MIRROR_BLOCKS as usize * media::SUPER_BYTES
    );
    let kinds = [
        UnifiedSystemKind::SnapshotCatalog,
        UnifiedSystemKind::BootEpoch,
        UnifiedSystemKind::SnapshotSlot,
        UnifiedSystemKind::SnapshotProtection,
        UnifiedSystemKind::SnapshotRequest,
        UnifiedSystemKind::Receipts,
        UnifiedSystemKind::Acl,
        UnifiedSystemKind::Security,
    ];
    assert_eq!(
        kinds.map(UnifiedSystemKind::inode_slot),
        [224, 225, 226, 227, 228, 229, 230, 231]
    );
    assert_eq!(
        kinds.map(UnifiedSystemKind::blocks),
        [1, 1, 120, 1, 16, 7, 4, 1]
    );
    assert_eq!(
        kinds.map(UnifiedSystemKind::fixed_first_block),
        [
            Some(4131),
            None,
            Some(4132),
            Some(4268),
            Some(4252),
            None,
            None,
            None
        ]
    );
    assert_eq!(
        kinds
            .into_iter()
            .map(UnifiedSystemKind::blocks)
            .sum::<u32>(),
        unified::UNIFIED_SYSTEM_BLOCKS
    );
}

#[test]
fn d3_snapshot_frame_and_d7_request_store_use_the_same_quotas() {
    assert_eq!(
        [unified::REQUEST_HEADER, unified::REPLY_HEADER],
        [file_wire::REQUEST_HEADER, file_wire::REPLY_HEADER]
    );
    assert_eq!(
        [
            unified::SNAP_MAX_REQUEST_BYTES,
            unified::SNAP_MAX_REPLY_BYTES
        ],
        [1024, 2048]
    );
    assert_eq!([FILE_REQ_KEY_BYTES, SNAPSHOT_KEY_BYTES], [36, 40]);
    assert_eq!(
        [
            unified::REQUESTS_ORDINARY as usize,
            unified::REQUESTS_MAINTENANCE as usize,
            unified::REQUESTS_RECOVERY as usize,
            unified::REQUEST_RECORD_BYTES,
        ],
        [
            requests::ORDINARY_RECORDS,
            requests::MAINTENANCE_RECORDS,
            requests::RECOVERY_RECORDS,
            requests::RECORD_BYTES,
        ]
    );
    let header = RequestStoreHeader {
        fs_uuid: *b"CYX-G1-QUOTAS-01",
        generation: 1,
        watermarks: [Watermark::EMPTY; PRINCIPALS as usize],
    };
    let mut block = [0; media::SUPER_BYTES];
    header.encode(&mut block).unwrap();
    let counts = block[40..56]
        .chunks_exact(2)
        .map(|field| u16::from_le_bytes(field.try_into().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(counts, [1, 128, 512, 64, 16, 48, 8, 8]);
    assert_eq!(RequestStoreHeader::decode(&block).unwrap(), Some(header));
    for slot in 0..14 {
        assert_eq!(requests::record_partition(slot), Some(0..48));
    }
    assert_eq!(requests::record_partition(14), Some(48..56));
    assert_eq!(requests::record_partition(15), Some(56..64));
    assert_eq!(requests::record_partition(PRINCIPALS), None);
    assert_eq!(requests::record_location(0).unwrap(), (4253, 0..512));
    assert_eq!(requests::record_location(63).unwrap(), (4260, 3584..4096));
    assert!(requests::record_location(requests::RECORDS).is_err());
}

#[test]
fn d5_reserves_fit_the_existing_resource_owner_units() {
    const KIB: usize = 1024;
    assert_eq!(unified::STAGING_SLOT_BYTES, 17 * media::SUPER_BYTES);
    assert_eq!(size_of::<CaptureWorkspace>(), unified::STAGING_SLOT_BYTES);
    assert_eq!(unified::STAGING_MAX_SLOTS, 8);
    assert_eq!(
        unified::STAGING_TOTAL_BYTES,
        unified::STAGING_MAX_SLOTS * size_of::<CaptureWorkspace>()
    );
    assert_eq!(unified::STAGING_TOTAL_BYTES, 544 * KIB);
    assert_eq!(unified::CONTROL_POOL_KIB as usize * KIB, CONTROL_POOL_LIMIT);
    assert_eq!(
        u64::from(unified::PROGRESS_POOL_KIB) * KIB as u64,
        frames::POOL_BYTES
    );
    assert_eq!(unified::FRAME_META_KIB as usize * KIB, frames::TABLE_BYTES);
    assert_eq!(
        unified::SNAP_SHARED_BITMAP_KIB as usize * KIB,
        media::BLOCK_COUNT as usize / 8
    );
    assert_eq!(
        unified::FILE_TRANSACTION_WORKSPACE_KIB as usize * KIB,
        size_of::<legacy::Workspace>()
    );
    assert_eq!(
        [
            unified::SNAP_HANDLES_KIB,
            unified::SNAP_FROZEN_VIEWS_KIB,
            unified::SNAP_CONTROL_CACHE_KIB,
            unified::SNAP_COORDINATION_KIB,
            unified::SNAP_MGMT_CONTROL_KIB,
            unified::CONTROL_UNCOMMITTED_MARGIN_KIB,
            unified::SNAP_COW_VERSION_KIB,
            unified::SNAP_GC_WORKSPACE_KIB,
        ],
        [16, 24, 8, 4, 52, 1283, 128, 48]
    );
}

#[test]
fn d5_candidate_retention_carries_the_legacy_time_units() {
    let legacy_seconds = [
        legacy::SHORT_PERIOD_SECONDS,
        legacy::SHORT_RETENTION_SECONDS,
        legacy::LONG_PERIOD_SECONDS,
        legacy::LONG_RETENTION_SECONDS,
        legacy::MIN_RETENTION_SECONDS,
        legacy::DEFAULT_RETENTION_SECONDS,
        legacy::MAX_RETENTION_SECONDS,
    ];
    assert_eq!(
        legacy_seconds,
        [6, 18, 48, 144, 1, 24, 7 * 24].map(|hours| hours * 3600)
    );
    assert_eq!(
        [
            unified::SHORT_PERIOD_S,
            unified::SHORT_RETENTION_S,
            unified::LONG_PERIOD_S,
            unified::LONG_RETENTION_S,
            unified::ONDEMAND_MIN_S,
            unified::ONDEMAND_DEFAULT_S,
            unified::ONDEMAND_MAX_S,
        ],
        legacy_seconds
    );
    assert_eq!(unified::ONLINE_AGE_GRANULARITY_S, 60);
    assert_eq!(
        [
            unified::PERIODIC_SLOTS,
            unified::ONDEMAND_SLOTS,
            unified::SHORT_TIER_SLOTS,
            unified::LONG_TIER_SLOTS,
            unified::HANDLES_ORDINARY,
            unified::HANDLES_RECOVERY,
            unified::FROZEN_VIEWS_ORDINARY,
            unified::FROZEN_VIEWS_RECOVERY,
        ],
        [6, 2, 3, 3, 112, 16, 56, 8]
    );
}
