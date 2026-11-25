//! V0.20 wave 11 G-B: OPT-IN media staging lane (evidence words 144..151).
//! Compiled only under `v020-production-media-staging`; the G-A
//! `v020-production` build never reads or writes any v1 on-disk layout.
//!
//! After the business CPUs stopped (and after SEC-N), CPU0 attaches ONE
//! dedicated, throw-away, all-zero 512 MiB scratch VirtIO-blk device through
//! the shared format-fixture plumbing (`scratch_blk`) and runs, each step only
//! if the previous one passed (fail-closed chain):
//! 1. the frozen `file_format_v1` formatter (fixed unsigned TEST manifest);
//! 2. `file_mount_v1::validate` on the written image;
//! 3. the ratified N=8 `file_media_unified_v1` map + on-disk superblock pair;
//! 4. `BootEpochAuthority::{open, allocate, confirmed_epoch}` (staged verify,
//!    no signed config — see authority.rs);
//! 5. `file_admission_flow_v1::run_admission_flow` under the confirmed epoch.
//!
//! The in-vector snapshot SVC 0x40 is routed here and answers EAGAIN: the
//! snapshot backend (catalog/slot payloads, SnapshotStore, live ViewGrant) is
//! golden-vector-pending, so the only honest answer is fail-closed.
//!
//! HONEST SCOPE: golden_vector_pending=1. This proves the lane boots and its
//! fail-closed paths behave; it claims NO persistence (the disk is discarded),
//! NO format correctness against golden vectors, NO signed catalog/config and
//! NO production mount. Missing disk => `V020_W11_MEDIA_ABSENT`, words
//! 145..149 stay 0 (word 150 records the 0x40 fail-closed answer, which does
//! not depend on the disk), the boot continues.
//! Serial: `V020_W11_MEDIA_STAGING golden_vector_pending=1` is emitted only
//! when all five steps passed; otherwise `V020_W11_MEDIA_STAGING_INCOMPLETE
//! step=<first step that did not pass>` (1 also when the disk is absent). The
//! completion marker carries `media_staging_enabled=1` (word 144: the lane ran)
//! and a separate `staging_ok` flag derived from words 145..150.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * Second DMA user of the production boot: the scratch VirtIO-blk device and
//!   its queue (registered in scratch_blk.rs), driven synchronously by CPU0 in
//!   `stage` only, after the business CPUs stopped; completion IRQs are off.
//! * Workspaces FORMAT/MOUNT (volume.rs) and PAIR (authority.rs): static mut in
//!   `.bss.sec_n`, NOT FrameMeta-registered; borrowed only inside `stage`.
//! * STAGED (atomic): CPU0 only; makes `stage` (and so every workspace borrow
//!   and the one-shot `scratch_blk::attach`) one-shot.
//! * SNAPSHOT_FAIL_CLOSED (atomic): incremented only by the CPU0 in-vector
//!   dispatcher (`snapshot_0x40`), read at the CPU0 seal.
use super::super::{report, scratch_blk};
use super::{EAGAIN, evidence};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::block::BatchedBlock;
use cyxia_kernel_core::security::{
    Error as SecurityError, epoch_redo_v0199::EpochBlockIo, file_index_v0199::BLOCK_BYTES,
    file_media_v0199::BLOCK_COUNT,
};

#[path = "media_staging/authority.rs"]
mod authority;
#[path = "media_staging/volume.rs"]
mod volume;

static STAGED: AtomicBool = AtomicBool::new(false);
static SNAPSHOT_FAIL_CLOSED: AtomicU64 = AtomicU64::new(0);

/// Result of the one-shot staging run (evidence words 145..149).
#[derive(Clone, Copy, Default)]
pub(super) struct StagingOutcome {
    pub(super) formatted: bool,
    pub(super) mount_validated: bool,
    pub(super) unified_map_validated: bool,
    /// `BootEpochAuthority::confirmed_epoch`, 0 = not confirmed.
    pub(super) confirmed_epoch: u64,
    pub(super) admission_flow_ok: bool,
}

impl StagingOutcome {
    /// First chain step (1..=5) that did not pass, or `None` if all passed.
    fn first_incomplete_step(&self) -> Option<u8> {
        [
            self.formatted,
            self.mount_validated,
            self.unified_map_validated,
            self.confirmed_epoch != 0,
            self.admission_flow_ok,
        ]
        .iter()
        .position(|passed| !passed)
        .map(|i| i as u8 + 1)
    }
}

/// EpochBlockIo adapter over the shared scratch plumbing, bounded to the
/// 512 MiB v1 image, with device-operation counters.
struct Disk {
    device: BatchedBlock,
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
    let sb = volume::format(disk);
    step(1, sb.map(|s| s.generation))?;
    out.formatted = true;
    let sb = sb.ok()?;
    let mounted = volume::mount(disk, sb);
    step(2, mounted.map(|m| u64::from(m.structure.live_inodes)))?;
    out.mount_validated = true;
    step(3, volume::unified_map(disk, sb).map(u64::from))?;
    out.unified_map_validated = true;
    let security = mounted.ok()?.security;
    out.confirmed_epoch = step(4, authority::boot_epoch(disk, &security))?;
    step(
        5,
        authority::admission_flow(out.confirmed_epoch).map(|()| 1),
    )?;
    out.admission_flow_ok = true;
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
    let _ = run_chain(&mut disk, &mut out);
    report("V020_W11_MEDIA_IO", disk.reads, disk.writes, disk.flushes);
    let (read_us, write_us, flush_us) = scratch_blk::max_latency_us();
    report(
        "V020_W11_MEDIA_IO_MAX_LATENCY_US",
        read_us,
        write_us,
        flush_us,
    );
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
    report(
        "V020_W11_MEDIA_SNAPSHOT_0X40",
        fail_closed,
        EAGAIN as u64,
        0,
    );
    super::super::super::log(
        b"V020_W11_MEDIA_SCOPE persistence=false format_golden=false signed_config=false\n",
    );
    match outcome.first_incomplete_step() {
        None => super::super::super::log(b"V020_W11_MEDIA_STAGING golden_vector_pending=1\n"),
        Some(step) => {
            let mut line = *b"V020_W11_MEDIA_STAGING_INCOMPLETE step=0\n";
            let at = line.len() - 2;
            line[at] = b'0' + step;
            super::super::super::log(&line);
        }
    }
}
