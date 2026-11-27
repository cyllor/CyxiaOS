//! Native §9.2.1 format fixture on real VirtIO block (V0.19.9 §9.2/§9.2.1).
//! Boot 1 accepts an exactly 512 MiB all-zero dedicated scratch, runs the
//! frozen file_format_v1 contract with a fixed TEST manifest, and proves the
//! publication FLUSH ordering from the actual device operation trace. Boot 2
//! accepts the persisted image after a forced process stop and validates it
//! on disk without writing. Both boots validate through file_mount_v1 and
//! reject a reformat of existing content before any write.
//!
//! Scope: fixture evidence for the formatter contract only. The manifest is
//! an unsigned fixed test input, not a signed boot catalog; no production
//! format path, production mount or ordinary file authority is established.
use super::*;
use cyxia_kernel_core::security::{
    Error as SecurityError,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_format_v1::{self, FormatManifest, FormatOp, FormatStep, FormatWorkspace},
    file_index_v0199::{BLOCK_BYTES, SecurityStateStoreV2},
    file_media_v0199::{
        BITMAP_START, BLOCK_COUNT, DATA_START, INODE_START, SuperblockV1, probe_snapshot_media_pair,
    },
    file_mount_v1::{self, Acl, Usage, Workspace as MountWorkspace},
    file_structure_v1::{Inode, SystemKind, SystemObject},
    offline_config_v1::Principal,
};
use sha2::{Digest, Sha256};

const UUID: [u8; 16] = *b"CYX-TEST-FORMAT!";
const ROOT: u32 = DATA_START;
const BOOT_HOME: u32 = DATA_START + 1;
const RECEIPTS_HOME: u32 = DATA_START + 2;
const ACL_HOME: u32 = DATA_START + 9;
const SECURITY_HOME: u32 = DATA_START + 13;
const MAGIC: u64 = u64::from_le_bytes(*b"CYXFMT01");
// Exact §9.2.1 device sequence length: 34 metadata writes + FLUSH + 4096 log
// writes + FLUSH + superblock 0 + FLUSH + superblock 1 + FLUSH.
const TRACE_CAP: usize = 4136;
const TRACE_WRITE: u64 = 1 << 32;
const TRACE_FLUSH: u64 = 2 << 32;
const FLUSH_BOUNDARIES: [u64; 4] = [34, 4130, 4131, 4132];
const SYSTEM: [SystemObject; 4] = [
    SystemObject {
        kind: SystemKind::BootEpoch,
        inode: 2,
        generation: 1,
        first_block: BOOT_HOME,
    },
    SystemObject {
        kind: SystemKind::Receipts,
        inode: 3,
        generation: 1,
        first_block: RECEIPTS_HOME,
    },
    SystemObject {
        kind: SystemKind::Acl,
        inode: 4,
        generation: 1,
        first_block: ACL_HOME,
    },
    SystemObject {
        kind: SystemKind::Security,
        inode: 5,
        generation: 1,
        first_block: SECURITY_HOME,
    },
];
static mut FORMAT: FormatWorkspace = FormatWorkspace::new();
static mut MOUNT: MountWorkspace = MountWorkspace::new();
static mut TRACE: [u64; TRACE_CAP] = [0; TRACE_CAP];
static mut TRACE_LEN: usize = 0;
static mut ACL_CHECKS: u64 = 0;

fn record_trace(kind: u64, block: u32) {
    let len = unsafe { *core::ptr::addr_of!(TRACE_LEN) };
    // Overflow means the device performed more than the frozen §9.2.1
    // sequence; fail closed instead of truncating the ordering proof.
    assert!(len < TRACE_CAP, "format device trace overflow");
    unsafe {
        *core::ptr::addr_of_mut!(TRACE).cast::<u64>().add(len) = kind | u64::from(block);
        *core::ptr::addr_of_mut!(TRACE_LEN) = len + 1;
    }
}
struct Disk {
    device: &'static mut super::scratch_blk::ScratchBlock,
    reads: u64,
    writes: u64,
    flushes: u64,
}
impl Disk {
    // Block plumbing (two validated four-sector requests per block, isolated
    // synchronous FLUSH) is shared with the V0.20 media-staging lane.
    fn sectors(
        &mut self,
        first: u64,
        write: Option<&[u8; BLOCK_BYTES]>,
        out: &mut [u8; BLOCK_BYTES],
    ) -> Result<(), SecurityError> {
        super::scratch_blk::sectors(self.device, first, write, out)
    }
    fn flush_device(&mut self) -> Result<(), SecurityError> {
        super::scratch_blk::flush(self.device)
    }
}
impl EpochBlockIo for Disk {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK_BYTES]) -> Result<(), SecurityError> {
        if block >= BLOCK_COUNT {
            return Err(SecurityError::Invalid);
        }
        self.sectors(u64::from(block) * 8, None, out)?;
        self.reads += 1;
        Ok(())
    }
    fn write(&mut self, block: u32, data: &[u8; BLOCK_BYTES]) -> Result<(), SecurityError> {
        if block >= BLOCK_COUNT {
            return Err(SecurityError::Invalid);
        }
        let mut scratch = [0; BLOCK_BYTES];
        self.sectors(u64::from(block) * 8, Some(data), &mut scratch)?;
        record_trace(TRACE_WRITE, block);
        self.writes += 1;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), SecurityError> {
        self.flush_device()?;
        record_trace(TRACE_FLUSH, 0);
        self.flushes += 1;
        Ok(())
    }
}
fn attach(info: &BootInfo) -> Disk {
    let device =
        super::scratch_blk::attach(info).expect("one dedicated modern VirtIO FLUSH scratch device");
    Disk {
        device,
        reads: 0,
        writes: 0,
        flushes: 0,
    }
}
// Fixed TEST manifest. Locations/identities mirror the frozen contract's
// golden host fixture; production boot wiring must supply a signed catalog.
fn manifest() -> FormatManifest {
    FormatManifest {
        fs_uuid: UUID,
        root_block: ROOT,
        system: SYSTEM,
        principals: core::array::from_fn(|i| Principal {
            id: i as u64 + 1,
            generation: 1,
        }),
        security: SecurityStateStoreV2 {
            fs_uuid: UUID,
            state_generation: 1,
            rule_min_generation: 1,
            security_min_generation: 1,
            key_generation: 1,
            isolated_service_bitmap: 0,
            last_boot_epoch: 0,
            offline_config_generation: 1,
            offline_config_hash: [0x5a; 32],
            service_generations: [1; 16],
        },
    }
}
fn fixture_acl(a: Acl, inode: Inode, system: Option<SystemKind>) -> Result<(), SecurityError> {
    // Test-only immutable volume ACL policy: principals[0] owns the root
    // (TRAVERSE) and the four hidden system objects (READ|WRITE|FSYNC).
    // No general user access and no recovery authority is issued.
    let expected = match a.inode_id {
        0 => (1, 1, 1 << 14, 0, 1),
        2..=5 => (1, 1, 0, (1 << 8) | (1 << 9) | (1 << 13), 1),
        _ => (0, 0, 0, 0, 0),
    };
    let live = matches!(a.inode_id, 0 | 2..=5);
    if (
        a.principal.id,
        a.principal.generation,
        a.owner_rights,
        a.system_rights,
        a.acl_generation,
    ) != expected
        || a.parent != 0
        || a.state != u32::from(live)
        || a.inode_generation != u64::from(live)
        || matches!(a.inode_id, 2..=5) != system.is_some()
        || (a.inode_id == 0) != (inode.kind == 2)
        || a.inode_id == 0 && inode.runs[0].physical != ROOT
        || matches!(a.inode_id, 2..=5)
            && inode.runs[0].physical != SYSTEM[(a.inode_id - 2) as usize].first_block
    {
        return Err(SecurityError::Unauthorized);
    }
    unsafe {
        *core::ptr::addr_of_mut!(ACL_CHECKS) += 1;
    }
    Ok(())
}
fn check_mount(
    disk: &mut Disk,
    sb: SuperblockV1,
) -> Result<file_mount_v1::MountEvidence, SecurityError> {
    let w = unsafe { &mut *core::ptr::addr_of_mut!(MOUNT) };
    let principals = core::array::from_fn(|i| Principal {
        id: i as u64 + 1,
        generation: 1,
    });
    let e = file_mount_v1::validate(disk, sb, &SYSTEM, &principals, w, fixture_acl)?;
    if e.security != manifest().security
        || e.boot.fs_uuid != UUID
        || e.boot.boot_epoch != 0
        || e.structure.live_inodes != 5
        || e.structure.data_blocks != 14
        || e.structure.directory_entries != 0
        || e.system_blocks != 13
        || e.receipts.occupied != 0
        || e.usage[0]
            != (Usage {
                inodes: 1,
                blocks: 1,
                directory_slots: 1,
            })
        || e.usage[1..].iter().any(|u| *u != Usage::default())
    {
        return Err(SecurityError::Conflict);
    }
    Ok(e)
}
// Independent expected device-level sequence, checked entry by entry against
// the actual recorded trace (not a recovery source). Returns the write count
// observed before each of the four FLUSH completions.
fn check_trace() -> [u64; 4] {
    let len = unsafe { *core::ptr::addr_of!(TRACE_LEN) };
    assert_eq!(len, TRACE_CAP);
    let trace = unsafe { &*core::ptr::addr_of!(TRACE) };
    let mut at = 0usize;
    let mut check = |entry: u64| {
        assert!(at < TRACE_CAP);
        assert_eq!(trace[at], entry, "device trace step {at}");
        at += 1;
    };
    for b in BITMAP_START..INODE_START {
        check(TRACE_WRITE | u64::from(b));
    }
    for b in INODE_START..DATA_START {
        check(TRACE_WRITE | u64::from(b));
    }
    check(TRACE_WRITE | u64::from(ROOT));
    check(TRACE_WRITE | u64::from(BOOT_HOME));
    for b in RECEIPTS_HOME..RECEIPTS_HOME + 7 {
        check(TRACE_WRITE | u64::from(b));
    }
    for b in ACL_HOME..ACL_HOME + 4 {
        check(TRACE_WRITE | u64::from(b));
    }
    check(TRACE_WRITE | u64::from(SECURITY_HOME));
    check(TRACE_FLUSH);
    for b in 2..BITMAP_START {
        check(TRACE_WRITE | u64::from(b));
    }
    check(TRACE_FLUSH);
    check(TRACE_WRITE);
    check(TRACE_FLUSH);
    check(TRACE_WRITE | 1);
    check(TRACE_FLUSH);
    assert_eq!(at, TRACE_CAP);
    let mut boundaries = [0u64; 4];
    let (mut writes, mut flush) = (0u64, 0usize);
    for &entry in trace.iter() {
        if entry == TRACE_FLUSH {
            boundaries[flush] = writes;
            flush += 1;
        } else {
            writes += 1;
        }
    }
    assert_eq!(flush, 4);
    assert_eq!(boundaries, FLUSH_BOUNDARIES);
    boundaries
}
fn publish_digest(start: usize, digest: &[u8; 32]) {
    for (i, part) in digest.chunks_exact(8).enumerate() {
        SMP_EVIDENCE.words[start + i].store(
            u64::from_le_bytes(part.try_into().unwrap()),
            Ordering::Relaxed,
        );
    }
}
pub(super) fn run(info: &BootInfo) -> ! {
    assert_eq!(cpu::slot(), 0);
    assert_eq!(ONLINE.load(Ordering::Acquire), 15);
    let mut disk = attach(info);
    report(
        "V0199_FORMAT_DEVICE",
        disk.device.sectors(),
        u64::from(BLOCK_COUNT),
        0,
    );
    let m = manifest();
    let mut sb_raw = [0; BLOCK_BYTES];
    disk.read(0, &mut sb_raw).unwrap();
    let zero = sb_raw.iter().all(|&v| v == 0);
    let boot: u64 = if zero { 1 } else { 2 };
    report("V0199_FORMAT_BOOT", boot, u64::from(!zero), 0);
    let w = unsafe { &mut *core::ptr::addr_of_mut!(FORMAT) };
    let sb;
    let boundaries;
    let trace_digest: [u8; 32];
    let trace_len;
    if zero {
        // Boot 1: the dedicated scratch is all zero; run the frozen formatter.
        let e = file_format_v1::format(&mut disk, BLOCK_COUNT, &m, w).unwrap();
        sb = e.superblock;
        assert_eq!(
            sb,
            SuperblockV1 {
                fs_uuid: UUID,
                generation: 1,
                checkpoint_lsn: 0,
                log_epoch: 1
            }
        );
        assert_eq!(
            (e.root_block, e.system_blocks, e.data_blocks),
            (ROOT, 13, 14)
        );
        let step = |op, first, blocks| FormatStep { op, first, blocks };
        assert_eq!(
            w.steps(),
            &[
                step(FormatOp::ScanZero, 0, BLOCK_COUNT),
                step(FormatOp::Bitmap, BITMAP_START, 4),
                step(FormatOp::InodeTable, INODE_START, 16),
                step(FormatOp::RootDirectory, ROOT, 1),
                step(FormatOp::SystemObject, BOOT_HOME, 1),
                step(FormatOp::SystemObject, RECEIPTS_HOME, 7),
                step(FormatOp::SystemObject, ACL_HOME, 4),
                step(FormatOp::SystemObject, SECURITY_HOME, 1),
                step(FormatOp::Flush, 0, 0),
                step(FormatOp::ZeroLog, 2, BITMAP_START - 2),
                step(FormatOp::Flush, 0, 0),
                step(FormatOp::Superblock, 0, 1),
                step(FormatOp::Flush, 0, 0),
                step(FormatOp::Superblock, 1, 1),
                step(FormatOp::Flush, 0, 0),
            ]
        );
        // Full 512 MiB zero scan plus the two superblock readbacks.
        report(
            "V0199_FORMAT_SCAN",
            u64::from(BLOCK_COUNT),
            disk.reads - 1,
            0,
        );
        report(
            "V0199_FORMAT_PUBLISHED",
            sb.generation,
            sb.log_epoch,
            sb.checkpoint_lsn,
        );
        boundaries = check_trace();
        for (i, writes) in boundaries.iter().enumerate() {
            report(
                "V0199_FORMAT_FLUSH",
                (i + 1) as u64,
                *writes,
                (i + 1) as u64,
            );
        }
        let trace_bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::addr_of!(TRACE).cast::<u8>(), TRACE_CAP * 8)
        };
        trace_digest = Sha256::digest(trace_bytes).into();
        trace_len = TRACE_CAP as u64;
        assert_eq!(
            (disk.reads, disk.writes, disk.flushes),
            (1 + u64::from(BLOCK_COUNT) + 2, 4132, 4)
        );
    } else {
        // Boot 2: accept only the persisted frozen TEST image, never any
        // other existing content. No write is permitted in this mode.
        sb = SuperblockV1::decode(&sb_raw).unwrap();
        assert_eq!(sb.fs_uuid, UUID);
        assert_eq!((sb.generation, sb.log_epoch, sb.checkpoint_lsn), (1, 1, 0));
        let mut sb1_raw = [0; BLOCK_BYTES];
        disk.read(1, &mut sb1_raw).unwrap();
        assert_eq!(sb_raw, sb1_raw);
        let probe = probe_snapshot_media_pair(&sb_raw, &sb1_raw).unwrap();
        assert_eq!(probe.generation, 1);
        report(
            "V0199_FORMAT_RECEIVED",
            sb.generation,
            sb.log_epoch,
            sb.checkpoint_lsn,
        );
        boundaries = [0; 4];
        trace_digest = [0; 32];
        trace_len = 0;
        assert_eq!((disk.reads, disk.writes, disk.flushes), (2, 0, 0));
    }
    // Validate the produced/persisted image ON DISK through the frozen mount
    // contract: structure, four system objects, ACLs and receipt store.
    let mounted = check_mount(&mut disk, sb).unwrap();
    report(
        "V0199_FORMAT_MOUNT",
        u64::from(mounted.structure.live_inodes),
        u64::from(mounted.structure.data_blocks),
        u64::from(mounted.structure.directory_entries),
    );
    let reads_after_mount = disk.reads;
    // Mount reads: boot 1 + security 1 + receipts 6 + index 1 + ACL 4 +
    // bitmap 4 + inode pages 16 + root directory 1 = 34 blocks.
    assert_eq!(reads_after_mount, if zero { 131109 } else { 36 });
    // Negative: a reformat of existing content must be rejected before any
    // write, on both the freshly formatted and the persisted image.
    let rejected = file_format_v1::format(&mut disk, BLOCK_COUNT, &m, w);
    assert_eq!(rejected.err(), Some(SecurityError::Conflict));
    assert!(w.steps().is_empty());
    assert_eq!(disk.reads, reads_after_mount + 1);
    assert_eq!(disk.writes, if zero { 4132 } else { 0 });
    assert_eq!(disk.flushes, if zero { 4 } else { 0 });
    report("V0199_FORMAT_REFORMAT_REJECTED", 1, 1, 0);
    // Final readback of the committed superblock pair and system homes from
    // the actual device; the digests bind the QMP page to real disk bytes.
    disk.read(0, &mut sb_raw).unwrap();
    let mut sb1_raw = [0; BLOCK_BYTES];
    disk.read(1, &mut sb1_raw).unwrap();
    assert_eq!(sb_raw, sb1_raw);
    assert_eq!(SuperblockV1::decode(&sb_raw).unwrap(), sb);
    let sb_digest: [u8; 32] = Sha256::digest(sb_raw).into();
    let mut sec_raw = [0; BLOCK_BYTES];
    disk.read(SECURITY_HOME, &mut sec_raw).unwrap();
    assert_eq!(SecurityStateStoreV2::decode(&sec_raw).unwrap(), m.security);
    let sec_digest: [u8; 32] = Sha256::digest(sec_raw).into();
    let mut boot_raw = [0; BLOCK_BYTES];
    disk.read(BOOT_HOME, &mut boot_raw).unwrap();
    assert_eq!(
        BootEpochStoreV1::decode(&boot_raw).unwrap(),
        BootEpochStoreV1 {
            fs_uuid: UUID,
            boot_epoch: 0
        }
    );
    let boot_digest: [u8; 32] = Sha256::digest(boot_raw).into();
    assert_eq!(disk.reads, if zero { 131114 } else { 41 });
    let acl_checks = unsafe { *core::ptr::addr_of!(ACL_CHECKS) };
    assert_eq!(acl_checks, 256);
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(|| (1..REQUIRED).all(|i| GATES[i].quiescent()));
    QUIT.store(true, Ordering::Release);
    wait(|| STOPPED.load(Ordering::Acquire) == 14);
    check_failures();
    let trace_pa = core::ptr::addr_of!(TRACE) as u64 - crate::HIGH;
    let row = [
        MAGIC,
        boot,
        0,
        u64::from(BLOCK_COUNT),
        disk.device.sectors(),
        disk.reads,
        disk.writes,
        disk.flushes,
        trace_len,
        u64::from(ROOT),
        u64::from(mounted.system_blocks),
        u64::from(mounted.structure.data_blocks),
        u64::from(mounted.structure.live_inodes),
        u64::from(mounted.structure.directory_entries),
        mounted.boot.boot_epoch,
        mounted.security.state_generation,
        sb.generation,
        sb.log_epoch,
        sb.checkpoint_lsn,
        mounted.receipts.occupied as u64,
        u64::from(mounted.usage[0].inodes),
        u64::from(mounted.usage[0].blocks),
        u64::from(mounted.usage[0].directory_slots),
        1,
    ];
    for (i, v) in row.into_iter().enumerate() {
        SMP_EVIDENCE.words[i].store(v, Ordering::Relaxed);
    }
    for (i, v) in boundaries.iter().enumerate() {
        SMP_EVIDENCE.words[24 + i].store(*v, Ordering::Relaxed);
    }
    publish_digest(28, &trace_digest);
    publish_digest(32, &sb_digest);
    publish_digest(36, &sec_digest);
    publish_digest(40, &boot_digest);
    SMP_EVIDENCE.words[44].store(acl_checks, Ordering::Relaxed);
    SMP_EVIDENCE.words[45].store(16, Ordering::Relaxed);
    SMP_EVIDENCE.words[46].store(trace_pa, Ordering::Relaxed);
    SMP_EVIDENCE.words[47].store(trace_len * 8, Ordering::Relaxed);
    report("V0199_FORMAT_COMMITTED", boot, disk.flushes, disk.writes);
    SMP_EVIDENCE.words[2].store(1, Ordering::Release);
    super::super::log(
        b"V0199_FORMAT_SCOPE production_format=false signed_catalog=false production_mount=false\n",
    );
    super::super::log(b"V0199_FORMAT_FIXTURE_PASS production=false\n");
    super::super::halt()
}
