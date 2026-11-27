//! V0.20 wave 11 G-B: OPT-IN media staging lane (evidence words 144..151).
//! Compiled only under `v020-production-media-staging`; the G-A
//! `v020-production` build never reads or writes any v1 on-disk layout.
//!
//! After the business CPUs stopped (and after SEC-N), CPU0 attaches ONE
//! dedicated 512 MiB scratch VirtIO-blk device through
//! the shared format-fixture plumbing (`scratch_blk`) and runs, each step only
//! if the previous one passed (fail-closed chain):
//! 1. the frozen `file_format_v1` formatter on all-zero media or, in the
//!    separate reopen-only build, identification of an existing staging pair;
//! 2. readback of every zeroed redo block and `file_mount_v1::validate` on
//!    fresh media, or exact boot-pair replay/checkpoint on repeated boots;
//! 3. the ratified N=8 `file_media_unified_v1` map + on-disk superblock pair.
//!    The envelopes lane writes empty D1.5 heads during format and validates
//!    the snapshot ranges before replay on reopen;
//! 4. paired BootEpoch allocation on the mounted volume. The explicitly
//!    signed lane additionally verifies an immutable public test config;
//! 5. `file_admission_flow_v1::run_admission_flow` under the confirmed epoch.
//!    The file layouts then seal the reread owner ACL, root slot and file
//!    bytes for the client turn under that epoch.
//!
//! The in-vector snapshot SVC 0x40 is routed here and answers EAGAIN: the
//! snapshot backend (catalog/slot payloads, SnapshotStore, live ViewGrant) is
//! golden-vector-pending, so the only honest answer is fail-closed.
//! SecurityAudit v2 uses protected volatile slots (baseline §安0.9). The v1
//! manifest provides no persistent audit object or recovery binding.
//!
//! HONEST SCOPE: golden_vector_pending=1. This proves the lane boots and its
//! fail-closed paths behave. Cross-boot evidence applies only to the supplied
//! throw-away scratch image. Production catalog/config and deployed media are
//! outside this lane. Missing disk => `V020_W11_MEDIA_ABSENT`, words
//! 145..149 stay 0 (word 150 records the 0x40 fail-closed answer, which does
//! not depend on the disk), the boot continues.
//! Serial: `V020_W11_MEDIA_STAGING golden_vector_pending=1` is emitted only
//! when all five disk steps passed and an authenticated 0x40 hit the refusal
//! path. Otherwise `V020_W11_MEDIA_STAGING_INCOMPLETE step=<first failed step>`
//! identifies the missing evidence (1 for absent disk, 6 for absent 0x40). The
//! completion marker carries `media_staging_enabled=1` (word 144: the lane ran)
//! and `staging_ok` from the mount, map, epoch, admission and snapshot rows
//! plus the mode-specific format (145) or reopen (162) row.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * Second DMA user of the production boot: the scratch VirtIO-blk device and
//!   its queue (registered in scratch_blk.rs), driven synchronously by CPU0 in
//!   `stage` only, after the business CPUs stopped; completion IRQs are off.
//! * Workspaces FORMAT/MOUNT (volume.rs), RECOVERY (reopen.rs), and PAIR (authority.rs): static mut in
//!   `.bss.sec_n`, counted as static FrameMeta Arena pages; borrowed only
//!   inside `stage`. The static registration does not track DMA pins.
//! * Signed scratch uses the FrameMeta Control COPY_BUFFER after role loading
//!   and business CPU stop, exclusively on CPU0 for signature verification.
//! * STAGED (atomic): CPU0 only; makes `stage` (and so every workspace borrow
//!   and the one-shot `scratch_blk::attach`) one-shot.
//! * SNAPSHOT_FAIL_CLOSED (atomic): incremented only by the CPU0 in-vector
//!   dispatcher (`snapshot_0x40`), read at the CPU0 seal.
use super::super::{report, scratch_blk};
use super::{EAGAIN, evidence};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_kernel_core::security::{
    Error as SecurityError, epoch_redo_v0199::EpochBlockIo, file_index_v0199::BLOCK_BYTES,
    file_media_v0199::BLOCK_COUNT,
};

#[path = "media_staging/authority.rs"]
mod authority;
#[path = "media_staging/reopen.rs"]
mod reopen;
#[cfg(feature = "v020-production-media-signed")]
#[path = "media_staging/signed.rs"]
mod signed;
#[path = "media_staging/volume.rs"]
mod volume;

static STAGED: AtomicBool = AtomicBool::new(false);
static SNAPSHOT_FAIL_CLOSED: AtomicU64 = AtomicU64::new(0);

/// Result of the one-shot staging run (evidence words 145..149).
#[derive(Clone, Copy, Default)]
pub(super) struct StagingOutcome {
    pub(super) formatted: bool,
    identified: bool,
    reopened: bool,
    prior_epoch: u64,
    pub(super) mount_validated: bool,
    pub(super) unified_map_validated: bool,
    /// `BootEpochAuthority::confirmed_epoch`, 0 = not confirmed.
    pub(super) confirmed_epoch: u64,
    pub(super) admission_flow_ok: bool,
    chain_complete: bool,
    #[cfg(feature = "v020-production-media-signed")]
    receipt_query_digest: Option<[u8; 32]>,
    #[cfg(feature = "v020-production-media-unified")]
    unified_mount_counts: [u64; 3],
    #[cfg(feature = "v020-production-snapshot-catalog")]
    pub(super) snapshot_catalog: Option<super::snapshot_catalog::MountedCatalog>,
    #[cfg(feature = "v020-production-file-read")]
    pub(super) file_read: Option<cyxia_kernel_core::security::file_read_v4::StagedFile>,
}

impl StagingOutcome {
    /// First missing staging result, including the independent in-vector probe.
    fn first_incomplete_step(&self, snapshot_refused: bool) -> Option<u8> {
        let missing = [
            self.formatted || self.identified,
            self.mount_validated,
            self.unified_map_validated,
            self.confirmed_epoch != 0,
            self.admission_flow_ok,
            snapshot_refused,
            #[cfg(feature = "v020-production-file-read")]
            self.file_read.is_some(),
            #[cfg(feature = "v020-production-snapshot-catalog")]
            self.snapshot_catalog.is_some(),
        ]
        .iter()
        .position(|passed| !passed)
        .map(|i| i as u8 + 1);
        missing.or(if self.chain_complete { None } else { Some(9) })
    }

    /// A prepared individual view never authorizes an incomplete combined
    /// mount. Check the full chain before either EL0 service is started.
    #[cfg(any(
        feature = "v020-production-file-read",
        feature = "v020-production-snapshot-catalog"
    ))]
    pub(super) fn services_ready(&self) -> bool {
        self.first_incomplete_step(SNAPSHOT_FAIL_CLOSED.load(Ordering::Relaxed) > 0)
            .is_none()
    }
}

/// EpochBlockIo adapter over the shared scratch plumbing, bounded to the
/// 512 MiB v1 image, with device-operation counters.
struct Disk {
    device: scratch_blk::ScratchBlock,
    reads: u64,
    writes: u64,
    flushes: u64,
}
impl EpochBlockIo for Disk {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK_BYTES]) -> Result<(), SecurityError> {
        if block >= BLOCK_COUNT {
            return Err(SecurityError::Invalid);
        }
        scratch_blk::sectors(&mut self.device, u64::from(block) * 8, None, out)?;
        self.reads += 1;
        Ok(())
    }
    fn write(&mut self, block: u32, data: &[u8; BLOCK_BYTES]) -> Result<(), SecurityError> {
        if block >= BLOCK_COUNT {
            return Err(SecurityError::Invalid);
        }
        let mut scratch = [0; BLOCK_BYTES];
        scratch_blk::sectors(
            &mut self.device,
            u64::from(block) * 8,
            Some(data),
            &mut scratch,
        )?;
        self.writes += 1;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), SecurityError> {
        scratch_blk::flush(&mut self.device)?;
        self.flushes += 1;
        Ok(())
    }
}

/// Staged in-vector snapshot (0x40) backend: authenticated by the caller,
/// then fail-closed (EAGAIN) because the snapshot backend is
/// golden-vector-pending. CPU0 in-vector only.
pub(super) fn snapshot_0x40() -> u64 {
    SNAPSHOT_FAIL_CLOSED.fetch_add(1, Ordering::Relaxed);
    EAGAIN as u64
}

fn step(index: u64, result: Result<u64, SecurityError>) -> Option<u64> {
    let (ok, detail) = match result {
        Ok(v) => (1, v),
        Err(e) => (0, e as u64),
    };
    report("V020_W11_MEDIA_STEP", index, ok, detail);
    result.ok()
}

fn run_chain(disk: &mut Disk, out: &mut StagingOutcome) -> Option<()> {
    const REOPEN: bool = cfg!(feature = "v020-production-media-reopen");
    const LAYOUT: volume::SnapshotLayout = if cfg!(feature = "v020-production-file-volatile-write")
    {
        volume::SnapshotLayout::AllocatedEnvelopesWithWritableFile
    } else if cfg!(feature = "v020-production-file-read") {
        volume::SnapshotLayout::AllocatedEnvelopesWithFile
    } else if cfg!(feature = "v020-production-media-unified") {
        volume::SnapshotLayout::AllocatedEnvelopes
    } else if cfg!(feature = "v020-production-media-envelopes") {
        volume::SnapshotLayout::EmptyEnvelopes
    } else {
        volume::SnapshotLayout::LegacyZero
    };
    #[cfg(feature = "v020-production-media-signed")]
    let verified = {
        // SAFETY: CPU0 has joined the business CPUs; package loading is over.
        // This is the existing FrameMeta Control scratch, exclusively borrowed
        // for this synchronous verification and wiped by the Ed25519 wrapper.
        let scratch = unsafe { &mut *core::ptr::addr_of_mut!(super::COPY_BUFFER.0) };
        signed::verify(signed::WIRE, scratch)
            .inspect_err(|e| report("V020_W13_CONFIG_ERROR", *e as u64, 0, 0))
            .ok()?
    };
    #[cfg(feature = "v020-production-media-signed")]
    let config = Some(&verified);
    #[cfg(not(feature = "v020-production-media-signed"))]
    let config = None;
    let sb = if REOPEN {
        reopen::identify(disk)
    } else {
        volume::format(disk, config, LAYOUT)
    };
    step(1, sb.map(|s| s.generation))?;
    out.formatted = !REOPEN;
    out.identified = REOPEN;
    let sb = sb.ok()?;
    let mounted = if REOPEN {
        reopen::recover(disk, sb, config, LAYOUT)
    } else {
        volume::mount(disk, sb, config, LAYOUT).map(|mounted| (sb, mounted))
    };
    step(2, mounted.map(|(_, m)| u64::from(m.structure.live_inodes)))?;
    let (checkpoint, mounted) = mounted.ok()?;
    out.reopened = REOPEN;
    out.mount_validated = true;
    step(
        3,
        volume::unified_map(disk, checkpoint, LAYOUT).map(u64::from),
    )?;
    out.unified_map_validated = true;
    #[cfg(feature = "v020-production-media-unified")]
    {
        let ordinary = mounted.usage.iter().map(|u| u.inodes).sum::<u32>();
        let hidden = u32::from(mounted.structure.live_inodes).checked_sub(ordinary)?;
        out.unified_mount_counts = [
            u64::from(hidden),
            u64::from(mounted.system_blocks),
            u64::from(mounted.structure.data_blocks),
        ];
    }
    out.prior_epoch = mounted.boot.boot_epoch;
    out.confirmed_epoch = step(
        4,
        authority::boot_epoch(disk, checkpoint, &mounted.security, config),
    )?;
    #[cfg(feature = "v020-production-media-signed")]
    {
        let committed = authority::verified_pair_state(disk, checkpoint, config).ok()?;
        if committed.last_boot_epoch != out.confirmed_epoch {
            return None;
        }
        out.receipt_query_digest =
            Some(volume::confirmed_receipt_query_digest(&mounted, &committed, &verified).ok()?);
    }
    step(
        5,
        authority::admission_flow(out.confirmed_epoch).map(|()| 1),
    )?;
    out.admission_flow_ok = true;
    #[cfg(feature = "v020-production-file-read")]
    {
        use cyxia_kernel_core::security::file_read_v4::StagedFile;

        let file = volume::read_scratch_file(
            disk,
            &mut [0; BLOCK_BYTES],
            LAYOUT,
            verified.principals()[0],
        )
        .ok()?;
        out.file_read = Some(
            StagedFile::new_with_owner_rights(
                out.confirmed_epoch,
                file.acl.principal,
                file.dirent,
                file.data,
                file.acl.owner_rights,
            )
            .ok()?,
        );
    }
    #[cfg(feature = "v020-production-snapshot-catalog")]
    {
        use cyxia_kernel_core::security::{
            file_media_unified_v1::SNAPSHOT_CATALOG_BLOCK, snapshot_list_v4::EmptyCatalog,
        };
        // Re-read the verified catalogue from this same exclusive disk
        // after confirming its BootEpoch. Only the sealed witness survives
        // into the client turn, with no access to the device.
        let catalog = {
            let mut raw = [0; BLOCK_BYTES];
            disk.read(SNAPSHOT_CATALOG_BLOCK, &mut raw).ok()?;
            EmptyCatalog::verify(
                &raw,
                checkpoint.fs_uuid,
                volume::SNAPSHOT_ENVELOPE_GENERATION,
                out.confirmed_epoch,
            )
            .ok()?
        };
        #[cfg(feature = "v020-production-snapshot-read")]
        let catalog = super::snapshot_catalog::MountedCatalog::verify(catalog, |block, raw| {
            disk.read(
                u32::try_from(block).map_err(|_| SecurityError::Invalid)?,
                raw,
            )
        })
        .inspect_err(|error| report("V020_W19_SLOT_ERROR", *error as u64, 0, 0))
        .ok()?;
        out.snapshot_catalog = Some(catalog);
    }
    Some(())
}

/// One-shot staging run on CPU0 after the business CPUs stopped.
pub(super) fn stage(info: &BootInfo) -> StagingOutcome {
    let mut out = StagingOutcome::default();
    if STAGED.swap(true, Ordering::AcqRel) {
        return out;
    }
    let device = match scratch_blk::attach(info) {
        Ok(device) => device,
        Err(e) => {
            super::super::super::log(b"V020_W11_MEDIA_ABSENT golden_vector_pending=1\n");
            report("V020_W11_MEDIA_ATTACH_ERROR", e as u64, 0, 0);
            return out;
        }
    };
    let mut disk = Disk {
        device,
        reads: 0,
        writes: 0,
        flushes: 0,
    };
    out.chain_complete = run_chain(&mut disk, &mut out).is_some();
    report("V020_W11_MEDIA_IO", disk.reads, disk.writes, disk.flushes);
    let queue = disk.device.notify_stats();
    report(
        "V020_W11_MEDIA_QUEUE",
        queue.published,
        queue.completed,
        queue.doorbells,
    );
    let (read_us, write_us, flush_us) = scratch_blk::max_latency_us();
    report(
        "V020_W11_MEDIA_IO_MAX_LATENCY_US",
        read_us,
        write_us,
        flush_us,
    );
    let (worst_sector, slow) = scratch_blk::latency_detail();
    report(
        "V020_W11_MEDIA_IO_WORST_SECTOR",
        worst_sector[0],
        worst_sector[1],
        0,
    );
    report("V020_W11_MEDIA_IO_SLOW_50MS", slow[0], slow[1], slow[2]);
    if let Some((code, sector, site)) = scratch_blk::last_error() {
        report("V020_W11_MEDIA_IO_ERROR", code, sector, site);
    }
    out
}

/// Seal-time evidence: words 144..151 (G-A leaves them all 0).
pub(super) fn publish(outcome: &StagingOutcome) {
    let fail_closed = SNAPSHOT_FAIL_CLOSED.load(Ordering::Relaxed);
    evidence::put(evidence::W11_MEDIA_STAGING_ENABLED, 1);
    evidence::put(
        evidence::W11_STAGING_FORMATTED,
        u64::from(outcome.formatted),
    );
    evidence::put(
        evidence::W11_STAGING_MOUNT_VALIDATED,
        u64::from(outcome.mount_validated),
    );
    evidence::put(
        evidence::W11_STAGING_UNIFIED_MAP,
        u64::from(outcome.unified_map_validated),
    );
    evidence::put(
        evidence::W11_STAGING_CONFIRMED_EPOCH,
        outcome.confirmed_epoch,
    );
    evidence::put(
        evidence::W11_STAGING_ADMISSION_FLOW,
        u64::from(outcome.admission_flow_ok),
    );
    evidence::put(
        evidence::W11_STAGING_SNAPSHOT_FAIL_CLOSED,
        u64::from(fail_closed > 0),
    );
    evidence::put(evidence::W11_STAGING_GOLDEN_VECTOR_PENDING, 1);
    #[cfg(feature = "v020-production-media-reopen")]
    {
        evidence::put(evidence::W12_STAGING_REOPENED, u64::from(outcome.reopened));
        evidence::put(evidence::W12_STAGING_PRIOR_EPOCH, outcome.prior_epoch);
    }
    report(
        "V020_W12_MEDIA_EPOCH",
        outcome.prior_epoch,
        outcome.confirmed_epoch,
        u64::from(outcome.reopened),
    );
    report(
        "V020_W11_MEDIA_SNAPSHOT_0X40",
        fail_closed,
        EAGAIN as u64,
        0,
    );
    #[cfg(feature = "v020-production-media-envelopes")]
    {
        let verified = u64::from(outcome.unified_map_validated);
        let count = verified * volume::SNAPSHOT_ENVELOPE_COUNT as u64;
        let generation = verified * volume::SNAPSHOT_ENVELOPE_GENERATION;
        evidence::put(evidence::W14_SNAPSHOT_ENVELOPES, count);
        evidence::put(evidence::W14_SNAPSHOT_ENVELOPE_GENERATION, generation);
        evidence::put(evidence::W14_SNAPSHOT_ENVELOPE_VERIFIED, verified);
        report("V020_W14_SNAPSHOT_ENVELOPES", count, generation, verified);
    }
    #[cfg(feature = "v020-production-media-unified")]
    {
        let [objects, system_blocks, data_blocks] = outcome.unified_mount_counts;
        evidence::put(evidence::W15_UNIFIED_SYSTEM_INODES, objects);
        evidence::put(evidence::W15_UNIFIED_SYSTEM_BLOCKS, system_blocks);
        evidence::put(evidence::W15_UNIFIED_DATA_BLOCKS, data_blocks);
        report(
            "V020_W15_UNIFIED_MOUNT",
            objects,
            system_blocks,
            data_blocks,
        );
    }
    #[cfg(feature = "v020-production-media-signed")]
    {
        let verified = u64::from(outcome.mount_validated);
        evidence::put(evidence::W13_SIGNED_CONFIG_VERIFIED, verified);
        evidence::put(evidence::W13_SIGNED_BOOT_EPOCH, outcome.confirmed_epoch);
        if let Some(digest) = outcome.receipt_query_digest {
            evidence::put(evidence::W23_RECEIPT_VIEW_BOOT, outcome.confirmed_epoch);
            for (i, bytes) in digest.chunks_exact(8).enumerate() {
                evidence::put(
                    evidence::W23_RECEIPT_VIEW_DIGEST + i,
                    u64::from_le_bytes(bytes.try_into().unwrap()),
                );
            }
            report(
                "V020_W23_RECEIPT_VIEW",
                outcome.confirmed_epoch,
                7,
                u64::from_le_bytes(digest[..8].try_into().unwrap()),
            );
        }
        report(
            "V020_W13_SIGNED_SCRATCH",
            verified,
            outcome.confirmed_epoch,
            outcome.prior_epoch,
        );
        super::super::super::log(
            b"V020_W13_MEDIA_SCOPE test_key=true format_golden=false signed_config=true\n",
        );
    }
    #[cfg(not(feature = "v020-production-media-signed"))]
    if cfg!(feature = "v020-production-media-reopen") {
        super::super::super::log(
            b"V020_W12_MEDIA_SCOPE reopen_only=true format_golden=false signed_config=false\n",
        );
    } else {
        super::super::super::log(
            b"V020_W11_MEDIA_SCOPE persistence=false format_golden=false signed_config=false\n",
        );
    }
    match outcome.first_incomplete_step(fail_closed > 0) {
        None => super::super::super::log(b"V020_W11_MEDIA_STAGING golden_vector_pending=1\n"),
        Some(step) => {
            let mut line = *b"V020_W11_MEDIA_STAGING_INCOMPLETE step=0\n";
            let at = line.len() - 2;
            line[at] = b'0' + step;
            super::super::super::log(&line);
        }
    }
}
