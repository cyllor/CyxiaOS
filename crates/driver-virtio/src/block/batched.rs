//! Multi-request block owner. Returned buffers remain pinned until acknowledge.
use super::{FLUSH, Operation, READ_ONLY, SECTOR_BYTES};
// Keep the exact completed token in the existing pending record until the
// caller acknowledges and the underlying queue releases its pinned DMA slot.
// This sentinel is never a start time and allocates no additional metadata.
const COMPLETED_RETAINED: u64 = u64::MAX;

use core::num::NonZeroU64;

use crate::{
    Error, Platform, Transport,
    queue::{BatchMemory, BatchQueue, MAX_CHAINS, NotifyStats, Token},
    reset::{DeviceState, ResetProof},
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockCompletion {
    pub token: Token,
    pub operation: Operation,
    pub notify_version: u64,
    pub latency_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedBlock {
    pub token: Token,
    pub operation: Operation,
    pub completed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockTerminalCustody {
    /// A confirmed MMIO stop or its error. Neither proves a WRITE or FLUSH.
    pub reset: Option<Result<u64, Error>>,
    pub requests: [Option<RetainedBlock>; MAX_CHAINS],
}

pub type BatchedBlock = BatchedBlockIo<SECTOR_BYTES>;

/// A queue whose read and write commands transfer a fixed whole number of
/// sectors. The header or status and the data must fit in their DMA page.
pub struct BatchedBlockIo<const BYTES: usize> {
    transport: Transport,
    queue: BatchQueue,
    sectors: u64,
    config_generation: u32,
    read_only: bool,
    pending: [Option<(Token, Operation, u64)>; MAX_CHAINS],
    state: DeviceState,
    initial_mmio_reset_ns: Option<u64>,
    reset: Option<Result<u64, Error>>,
    last_completed: u64,
}
impl<const BYTES: usize> BatchedBlockIo<BYTES> {
    pub fn attach(
        t: Transport,
        memory: &'static mut BatchMemory,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        Self::attach_inner(t, memory, None, None, p, None)
    }

    /// Attach a writable device using only VERSION_1 and FLUSH. A read-only
    /// advertisement is rejected before the driver publishes features or a queue.
    pub fn attach_writable(
        t: Transport,
        memory: &'static mut BatchMemory,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        Self::attach_inner(t, memory, Some(false), None, p, None)
    }

    /// Require a writable device with the admitted geometry before publishing
    /// any DMA queue. A mismatched capacity returns `Error::Response`.
    pub fn attach_writable_exact(
        t: Transport,
        memory: &'static mut BatchMemory,
        sectors: u64,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        Self::attach_inner(t, memory, Some(false), Some(sectors), p, None)
    }

    /// Admit the signed writable MMIO boot device under the caller's
    /// Recovery grants. Checkpoints must neither access the device nor
    /// reenter this owner. An interrupted attach publishes no DMA queue.
    pub fn attach_writable_exact_with_checkpoint(
        t: Transport,
        memory: &'static mut BatchMemory,
        sectors: u64,
        p: &impl Platform,
        checkpoint: &mut dyn FnMut() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        Self::attach_inner(t, memory, Some(false), Some(sectors), p, Some(checkpoint))
    }

    /// Require a read-only device with the admitted geometry before publishing
    /// the DMA queue for an archived volume.
    pub fn attach_readonly_exact(
        t: Transport,
        memory: &'static mut BatchMemory,
        sectors: u64,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        Self::attach_inner(t, memory, Some(true), Some(sectors), p, None)
    }

    fn attach_inner(
        mut t: Transport,
        memory: &'static mut BatchMemory,
        expected_read_only: Option<bool>,
        expected_sectors: Option<u64>,
        p: &impl Platform,
        mut checkpoint: Option<&mut dyn FnMut() -> Result<(), Error>>,
    ) -> Result<Self, Error> {
        if BYTES == 0 || BYTES > 4096 - 16 || !BYTES.is_multiple_of(SECTOR_BYTES) {
            return Err(Error::Address);
        }
        let initial_mmio_reset_ns = if let Some(checkpoint) = checkpoint.as_deref_mut() {
            let observed = t.observe_mmio_reset(2, &[0], p, &mut *checkpoint)?;
            checkpoint()?;
            Some(observed)
        } else {
            if t.device_id() != 2 {
                return Err(Error::Device);
            }
            t.set_status(0);
            p.barrier();
            let start = p.now_ms();
            while t.status() != 0 {
                if p.now_ms().wrapping_sub(start) >= 100 {
                    return Err(Error::Timeout);
                }
            }
            None
        };
        t.set_status(3);
        t.select_device_features(1);
        p.barrier();
        let modern = t.device_features() & 1 != 0;
        t.select_device_features(0);
        p.barrier();
        let features = t.device_features();
        let read_only = features & READ_ONLY != 0;
        if !modern
            || features & FLUSH == 0
            || expected_read_only.is_some_and(|expected| expected != read_only)
        {
            t.fail();
            return Err(Error::Features);
        }
        t.select_driver_features(0);
        t.set_driver_features(features & (FLUSH | READ_ONLY));
        t.select_driver_features(1);
        t.set_driver_features(1);
        t.set_status(11);
        p.barrier();
        if t.status() & (8 | 64 | 128) != 8 {
            t.fail();
            return Err(Error::Features);
        }
        let (config_generation, sectors) = match Self::read_capacity(&t, p) {
            Ok(config) => config,
            Err(error) => {
                t.fail();
                p.barrier();
                return Err(error);
            }
        };
        if expected_sectors.is_some_and(|expected| expected != sectors) {
            t.fail();
            p.barrier();
            return Err(Error::Response);
        }
        if let Some(checkpoint) = checkpoint {
            checkpoint()?;
        }
        let queue = BatchQueue::configure(&mut t, memory, 0, p)?;
        t.start(p)?;
        Ok(Self {
            transport: t,
            queue,
            sectors,
            config_generation,
            read_only,
            pending: [None; MAX_CHAINS],
            state: DeviceState::Live,
            initial_mmio_reset_ns,
            reset: None,
            last_completed: 0,
        })
    }
    pub fn sectors(&self) -> u64 {
        self.sectors
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    /// Readback timestamp for the old MMIO queue's stopped state before
    /// this attach admitted DMA. It conveys no result of any old request.
    pub fn initial_mmio_reset_ns(&self) -> Option<u64> {
        self.initial_mmio_reset_ns
    }
    pub fn is_quiescent(&self) -> bool {
        self.state == DeviceState::Live
            && self.pending.iter().all(Option::is_none)
            && self.queue.is_quiescent()
    }

    /// Requests without a verified completion, then verified requests still
    /// held for acknowledgement. Reset alone changes neither count.
    pub fn retained_requests(&self) -> (usize, usize) {
        self.pending
            .iter()
            .flatten()
            .fold((0, 0), |(unknown, completed), (_, _, state)| {
                if *state == COMPLETED_RETAINED {
                    (unknown, completed + 1)
                } else {
                    (unknown + 1, completed)
                }
            })
    }

    /// Read old requests after the owner has permanently fenced submission.
    /// Only a verified and retained block completion sets `completed`.
    pub fn terminal_custody(&self) -> Option<BlockTerminalCustody> {
        matches!(
            self.state,
            DeviceState::RecoveryFenced | DeviceState::ResetAttempted
        )
        .then(|| BlockTerminalCustody {
            reset: self.reset,
            requests: self.pending.map(|request| {
                request.map(|(token, operation, time)| RetainedBlock {
                    token,
                    operation,
                    completed: time == COMPLETED_RETAINED,
                })
            }),
        })
    }

    /// Encode the one-shot block queue's observed DMA stop. The caller
    /// supplies the current boot's verified epoch. Request and durability
    /// obligations are unchanged by the proof.
    pub fn reset_proof(&self, boot_epoch: NonZeroU64) -> Option<ResetProof> {
        let observed = self.reset?.ok()?;
        Some(ResetProof::for_first_generation(
            boot_epoch.get(),
            2,
            0,
            observed,
        ))
    }

    pub fn free(&self) -> usize {
        self.queue.free()
    }
    pub fn notify_stats(&self) -> NotifyStats {
        let mut s = self.queue.stats();
        s.last_completed_version = self.last_completed;
        s
    }
    pub fn current_batch(&self, now: u64) -> u8 {
        self.queue.current_batch(now)
    }
    pub fn set_notify_policy(
        &mut self,
        batch: u8,
        version: u64,
        until: u64,
        now: u64,
    ) -> Result<(), Error> {
        self.queue.install(batch, version, until, now)
    }
    pub fn set_completion_interrupts(&mut self, enabled: bool, p: &impl Platform) {
        self.queue.set_completion_interrupts(enabled, p);
    }
    fn fail(&mut self, p: &impl Platform) {
        self.state = DeviceState::Failed;
        self.queue.poison(&mut self.transport, p);
    }

    /// Stop software submissions when the foreground owner has lost its
    /// execution budget. Preserve every exact token for a recovery owner.
    pub fn fence_for_recovery(&mut self) {
        if matches!(self.state, DeviceState::Live | DeviceState::Failed) {
            self.state = DeviceState::RecoveryFenced;
            self.queue.fence();
        }
    }

    /// Best-effort terminal stop under the existing exclusive MMIO owner.
    /// Completion/FLUSH obligations remain in custody, including after the
    /// device and its old queue read back disabled.
    pub fn stop_failed_mmio(&mut self, p: &impl Platform) -> Option<Result<u64, Error>> {
        self.stop_failed_mmio_with_checkpoint(p, || Ok(()))
    }

    /// End an exclusive upper-layer I/O session that will never run again.
    /// A local abort can strand accepted requests in a healthy transport.
    /// Fence those requests before attempting the same one-shot MMIO stop.
    pub fn stop_abandoned_mmio(
        &mut self,
        p: &impl Platform,
        checkpoint: impl FnMut() -> Result<(), Error>,
    ) -> Option<Result<u64, Error>> {
        if self.pending.iter().any(Option::is_some) {
            self.fence_for_recovery();
        }
        self.stop_failed_mmio_with_checkpoint(p, checkpoint)
    }

    /// The serialized recovery owner can renew its grant before the reset
    /// write and each observation. Refusal consumes the one-shot attempt
    /// without permitting another MMIO access or releasing any request.
    pub fn stop_failed_mmio_with_checkpoint(
        &mut self,
        p: &impl Platform,
        checkpoint: impl FnMut() -> Result<(), Error>,
    ) -> Option<Result<u64, Error>> {
        if !matches!(
            self.state,
            DeviceState::Failed | DeviceState::RecoveryFenced
        ) {
            return None;
        }
        self.state = DeviceState::ResetAttempted;
        self.queue.fence();
        let result = self.transport.observe_mmio_reset(2, &[0], p, checkpoint);
        self.reset = Some(result);
        Some(result)
    }
    fn read_capacity(t: &Transport, p: &impl Platform) -> Result<(u32, u64), Error> {
        for _ in 0..8 {
            let before = t.config_generation();
            p.barrier();
            let lo = t.read_config_u32(0)?;
            let hi = t.read_config_u32(4)?;
            p.barrier();
            let sectors = u64::from(lo) | (u64::from(hi) << 32);
            if t.config_generation() == before && sectors != 0 {
                return Ok((before, sectors));
            }
        }
        Err(Error::Device)
    }
    fn require_capacity(&mut self, p: &impl Platform) -> Result<(), Error> {
        if self.state != DeviceState::Live {
            return Err(Error::Device);
        }
        if self.transport.status() != 15
            || Self::read_capacity(&self.transport, p) != Ok((self.config_generation, self.sectors))
        {
            // Freeze new publications, including previously private batches.
            // Keep unresolved completions pinned; even unchanged capacity
            // after a generation change needs recovery-owner reconciliation.
            self.fail(p);
            return Err(Error::Device);
        }
        Ok(())
    }
    pub fn begin(
        &mut self,
        operation: Operation,
        data: &[u8; BYTES],
        synchronous: bool,
        isolated: bool,
        p: &impl Platform,
    ) -> Result<Token, Error> {
        self.require_capacity(p)?;
        let (kind, sector) = match operation {
            Operation::Read(s) => (0u32, s),
            Operation::Write(s) if !self.read_only => (1, s),
            Operation::Write(_) => return Err(Error::Unsupported),
            Operation::Flush => (4, 0),
        };
        if kind != 4
            && self
                .sectors
                .checked_sub(sector)
                .is_none_or(|remaining| remaining < (BYTES / SECTOR_BYTES) as u64)
        {
            return Err(Error::Address);
        }
        let mut header = [0; 16];
        header[..4].copy_from_slice(&kind.to_le_bytes());
        header[8..16].copy_from_slice(&sector.to_le_bytes());
        let payload = if kind == 1 { data.as_slice() } else { &[] };
        let writable = if kind == 0 { BYTES + 1 } else { 1 };
        let started = p.now_ms();
        // This value is reserved for a verified completion. Check before
        // reserving DMA so a clock fault leaves no new device obligation.
        if started == COMPLETED_RETAINED {
            self.fail(p);
            return Err(Error::Timeout);
        }
        let pending = &mut self.pending;
        // Like the single-request block owner, require an explicit device
        // status write. A correct used length alone is not proof of success.
        match self.queue.enqueue_parts(
            &mut self.transport,
            (&header, payload),
            (writable, Some(0xff)),
            synchronous || isolated || kind == 4,
            p,
            |token| pending[usize::from(token.slot)] = Some((token, operation, started)),
        ) {
            Ok(token) => Ok(token),
            Err(e) => {
                if !matches!(e, Error::Busy | Error::Address) {
                    self.fail(p);
                }
                Err(e)
            }
        }
    }
    pub fn drain(&mut self, p: &impl Platform) -> Result<(), Error> {
        self.require_capacity(p)?;
        let result = self.queue.drain(&mut self.transport, p);
        if result.is_err() {
            self.fail(p);
        }
        result
    }
    pub fn poll(
        &mut self,
        out: &mut [u8; BYTES],
        p: &impl Platform,
    ) -> Result<Option<BlockCompletion>, Error> {
        self.require_capacity(p)?;
        // Sample the deadline before acquiring the used ring. An empty
        // observation made before the deadline cannot justify timing out after
        // a slow IRQ ACK/deschedule: the device may have completed meanwhile.
        // A later poll still uses the original start and 250 ms deadline, and
        // its fresh completion observation always precedes any timeout verdict.
        let observed_ms = p.now_ms();
        let completion =
            match self
                .queue
                .poll_in_place_with_checkpoint(&mut self.transport, p, &mut || {})
            {
                Ok(c) => c,
                Err(e) => {
                    self.fail(p);
                    return Err(e);
                }
            };
        if let Some(c) = completion {
            // The queue acquires DMA and acknowledges the interrupt after its
            // initial status check. A reset in that interval cannot certify a
            // block result or authorize releasing its pinned buffers.
            self.require_capacity(p)?;
            let Some((token, operation, _)) = self.pending[usize::from(c.token.slot)] else {
                self.fail(p);
                return Err(Error::Queue);
            };
            let read = matches!(operation, Operation::Read(_));
            let expected = if read { BYTES + 1 } else { 1 };
            let Ok(response) = self.queue.completed_response(c.token) else {
                self.fail(p);
                return Err(Error::Queue);
            };
            if token != c.token || c.len != expected || response.get8(expected - 1) != 0 {
                self.fail(p);
                return Err(Error::Response);
            }
            if read {
                response.copy_prefix_to(out, BYTES);
            }
            // A device completion is not the caller's acknowledgment.
            // Retain the original token/custody until acknowledge() actually
            // frees the pinned queue buffers, including if the caller fails.
            self.pending[usize::from(token.slot)] = Some((token, operation, COMPLETED_RETAINED));
            self.last_completed = self.last_completed.max(c.version);
            return Ok(Some(BlockCompletion {
                token,
                operation,
                notify_version: c.version,
                latency_ns: c.latency_ns,
            }));
        }
        if self.pending.iter().flatten().any(|(_, _, start)| {
            *start != COMPLETED_RETAINED && observed_ms.wrapping_sub(*start) >= 250
        }) {
            self.fail(p);
            return Err(Error::Timeout);
        }
        Ok(None)
    }
    pub fn acknowledge(&mut self, token: Token) -> Result<(), Error> {
        let at = usize::from(token.slot);
        // Fail closed on an early, stale or forged acknowledgment. Only the
        // exact completion observed by poll() can terminate its DMA custody.
        if !matches!(self.pending.get(at), Some(Some((owned, _, COMPLETED_RETAINED))) if *owned == token)
        {
            return Err(Error::Response);
        }
        // A checked completion remains ACKable after an ordinary failure.
        // Recovery handoff or a reset attempt freezes the entire ledger.
        if matches!(
            self.state,
            DeviceState::RecoveryFenced | DeviceState::ResetAttempted
        ) {
            return Err(Error::Device);
        }
        self.queue.release(token)?;
        self.pending[at] = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Page;
    use core::{
        cell::Cell,
        ptr::{read_volatile, write_volatile},
    };
    use std::boxed::Box;
    struct Host {
        clock: Cell<u64>,
        idle_completion: Cell<Option<(usize, u8, bool)>>,
        idle_clock: Cell<Option<u64>>,
        mmio: usize,
        reset_on_completion_ack: Cell<bool>,
        needs_reset_on_prepare: Cell<bool>,
        request_clock: Option<u64>,
        feature_banks: Option<[u32; 2]>,
        reject_features: bool,
        complete_mmio_reset: bool,
        clock_step_ns: u64,
    }
    unsafe impl Platform for Host {
        fn diagnostic_stage(&self, stage: u64) {
            if stage == crate::DiagnosticStage::QueueCompletionAck as u64
                && self.reset_on_completion_ack.replace(false)
            {
                // The initial queue status check and DMA acquisition already
                // succeeded. Model device reset immediately before IRQ ACK.
                unsafe { write_volatile((self.mmio + 0x70) as *mut u32, 0) };
            }
            if stage == crate::DiagnosticStage::QueueIdleAck as u64 {
                // The device completes after the poll sampled an empty used
                // ring. Model descheduling across the deadline during IRQ ACK.
                if let Some((base, slot, read)) = self.idle_completion.take() {
                    unsafe { complete(base, slot, read, 0) };
                }
                if let Some(now) = self.idle_clock.take() {
                    self.clock.set(now);
                }
            }
        }
        fn physical(&self, a: usize, _: usize) -> Result<u64, Error> {
            Ok(a as u64)
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn barrier(&self) {
            if self.feature_banks.is_some() || self.complete_mmio_reset {
                // Advancing a selector barrier exposes the selected device bank.
                let reg = |offset| (self.mmio + offset) as *mut u32;
                unsafe {
                    match read_volatile(reg(0x70)) {
                        3 => {
                            if let Some(banks) = self.feature_banks {
                                let bank = read_volatile(reg(0x14)) as usize;
                                write_volatile(reg(0x10), banks[bank]);
                            }
                        }
                        0 if self.complete_mmio_reset => write_volatile(reg(0x44), 0),
                        11 if self.reject_features => write_volatile(reg(0x70), 3),
                        _ => {}
                    }
                }
            }
        }
        fn now_ms(&self) -> u64 {
            self.request_clock.unwrap_or(self.clock.get() / 1_000_000)
        }
        fn now_ns(&self) -> u64 {
            if self.needs_reset_on_prepare.replace(false) {
                // The device requested a reset between reservation and drain.
                unsafe { write_volatile((self.mmio + 0x70) as *mut u32, 15 | 64) };
            }
            let now = self.clock.get();
            self.clock.set(now.saturating_add(self.clock_step_ns));
            now
        }
    }
    fn fixture() -> (BatchedBlock, Host, usize) {
        fixture_with_width()
    }
    fn fixture_with_width<const BYTES: usize>() -> (BatchedBlockIo<BYTES>, Host, usize) {
        let mmio = Box::leak(Box::new(Page::zeroed()));
        let p = Host {
            clock: Cell::new(0),
            idle_completion: Cell::new(None),
            idle_clock: Cell::new(None),
            mmio: mmio.address(),
            reset_on_completion_ack: Cell::new(false),
            needs_reset_on_prepare: Cell::new(false),
            request_clock: None,
            feature_banks: None,
            reject_features: false,
            complete_mmio_reset: false,
            clock_step_ns: 0,
        };
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 2);
        mmio.put32(0x34, 16);
        mmio.put32(0x70, 15);
        mmio.put32(0x100, 4096);
        let mut t = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let m = Box::leak(Box::new(BatchMemory::zeroed()));
        let base = m as *mut _ as usize;
        let q = BatchQueue::configure(&mut t, m, 0, &p).unwrap();
        (
            BatchedBlockIo {
                transport: t,
                queue: q,
                sectors: 4096,
                config_generation: 0,
                read_only: false,
                pending: [None; 8],
                state: DeviceState::Live,
                initial_mmio_reset_ns: None,
                reset: None,
                last_completed: 0,
            },
            p,
            base,
        )
    }

    fn attach_fixture(
        low: u32,
        reject_features: bool,
    ) -> (&'static Page, Host, &'static mut BatchMemory) {
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 2);
        mmio.put32(0x34, 16);
        mmio.put32(0x100, 4096);
        let platform = Host {
            clock: Cell::new(0),
            idle_completion: Cell::new(None),
            idle_clock: Cell::new(None),
            mmio: mmio.address(),
            reset_on_completion_ack: Cell::new(false),
            needs_reset_on_prepare: Cell::new(false),
            request_clock: None,
            feature_banks: Some([low, 1]),
            reject_features,
            complete_mmio_reset: false,
            clock_step_ns: 0,
        };
        (mmio, platform, Box::leak(Box::new(BatchMemory::zeroed())))
    }

    #[test]
    fn writable_attach_rejects_read_only_before_publishing_features_or_a_queue() {
        let (mmio, platform, memory) = attach_fixture(FLUSH | READ_ONLY, false);
        mmio.put32(0x20, 0xdead_beef);
        mmio.put32(0x24, 0x1122_3344);
        let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };

        assert!(matches!(
            BatchedBlock::attach_writable(transport, memory, &platform),
            Err(Error::Features)
        ));
        assert_eq!(mmio.get32(0x70), 3 | 128);
        assert_eq!(mmio.get32(0x20), 0xdead_beef);
        assert_eq!(mmio.get32(0x24), 0x1122_3344);
        assert_eq!(mmio.get32(0x44), 0);
        assert_eq!(mmio.get32(0x80), 0);
    }

    #[test]
    fn writable_attach_waits_for_features_ok_before_queue_enable_and_driver_ok() {
        for reject in [false, true] {
            let (mmio, platform, memory) = attach_fixture(u32::MAX & !READ_ONLY, reject);
            let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
            let result = BatchedBlock::attach_writable(transport, memory, &platform);
            if reject {
                assert!(matches!(result, Err(Error::Features)));
                assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (3 | 128, 0));
            } else {
                assert!(!result.unwrap().read_only());
                assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (15, 1));
            }
        }
    }

    #[test]
    fn exact_writable_capacity_is_checked_before_dma_queue_publication() {
        const SCRATCH_SECTORS: u64 = 1_048_576;
        let (mmio, platform, memory) = attach_fixture(FLUSH, false);
        let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        assert!(matches!(
            BatchedBlock::attach_writable_exact(transport, memory, SCRATCH_SECTORS, &platform),
            Err(Error::Response)
        ));
        assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (11 | 128, 0));
        for register in [0x80, 0x84, 0x90, 0x94, 0xa0, 0xa4] {
            assert_eq!(mmio.get32(register), 0);
        }

        let (mmio, platform, memory) = attach_fixture(FLUSH, false);
        mmio.put32(0x100, SCRATCH_SECTORS as u32);
        let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let driver =
            BatchedBlock::attach_writable_exact(transport, memory, SCRATCH_SECTORS, &platform)
                .unwrap();
        assert_eq!(driver.sectors(), SCRATCH_SECTORS);
        assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (15, 1));
    }

    #[test]
    fn signed_attach_refusal_prevents_queue_publication_at_each_reset_boundary() {
        for (refuse_at, status, ready) in [(1, 15, 1), (2, 0, 0), (3, 0, 0), (4, 11, 0)] {
            let (mmio, mut platform, memory) = attach_fixture(FLUSH, false);
            let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
            mmio.put32(0x70, 15);
            mmio.put32(0x44, 1);
            platform.complete_mmio_reset = true;
            let mut checkpoints = 0;

            let result = BatchedBlock::attach_writable_exact_with_checkpoint(
                transport,
                memory,
                4096,
                &platform,
                &mut || {
                    checkpoints += 1;
                    if checkpoints == refuse_at {
                        Err(Error::Busy)
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.err(), Some(Error::Busy));
            assert_eq!(checkpoints, refuse_at);
            assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (status, ready));
            for register in [0x80, 0x84, 0x90, 0x94, 0xa0, 0xa4] {
                assert_eq!(mmio.get32(register), 0);
            }
        }
    }

    #[test]
    fn signed_attach_waits_for_queue_readback_with_one_reset_deadline() {
        use crate::reset::RESET_DEADLINE_NS;
        for ready_at in [RESET_DEADLINE_NS - 1, RESET_DEADLINE_NS] {
            let (mmio, platform, memory) = attach_fixture(FLUSH, false);
            let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
            mmio.put32(0x70, 15);
            mmio.put32(0x44, 1);
            let mut checkpoints = 0;

            let result = BatchedBlock::attach_writable_exact_with_checkpoint(
                transport,
                memory,
                4096,
                &platform,
                &mut || {
                    checkpoints += 1;
                    if checkpoints == 3 {
                        assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (0, 1));
                        assert_eq!(mmio.get32(0x80), 0);
                        mmio.put32(0x44, 0);
                        platform.clock.set(ready_at);
                    }
                    Ok(())
                },
            );
            if ready_at == RESET_DEADLINE_NS {
                assert_eq!(result.err(), Some(Error::Timeout));
                assert_eq!(checkpoints, 3);
                assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (0, 0));
                assert_eq!(mmio.get32(0x80), 0);
            } else {
                let attached = result.unwrap();
                assert_eq!(attached.initial_mmio_reset_ns(), Some(ready_at));
                assert_eq!(checkpoints, 5);
                assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (15, 1));
            }
        }
    }

    #[test]
    fn ordinary_batched_attach_still_supports_read_only_io() {
        let (mmio, platform, memory) = attach_fixture(FLUSH | READ_ONLY, false);
        let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let mut block = BatchedBlock::attach(transport, memory, &platform).unwrap();
        assert_eq!(block.initial_mmio_reset_ns(), None);
        assert!(block.read_only());
        assert_eq!(
            block.begin(Operation::Write(0), &[0; 512], true, true, &platform),
            Err(Error::Unsupported)
        );
        assert!(
            block
                .begin(Operation::Read(0), &[0; 512], true, true, &platform)
                .is_ok()
        );
    }

    #[test]
    fn exact_readonly_attach_checks_access_and_geometry_before_dma() {
        const ARCHIVE_SECTORS: u64 = 1_048_576;
        for (features, sectors, expected_error) in [
            (FLUSH, ARCHIVE_SECTORS, Some(Error::Features)),
            (FLUSH | READ_ONLY, 4096, Some(Error::Response)),
            (FLUSH | READ_ONLY, ARCHIVE_SECTORS, None),
        ] {
            let (mmio, platform, memory) = attach_fixture(features, false);
            mmio.put32(0x100, sectors as u32);
            let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
            let result =
                BatchedBlock::attach_readonly_exact(transport, memory, ARCHIVE_SECTORS, &platform);
            if let Some(error) = expected_error {
                assert_eq!(result.err(), Some(error));
                assert_eq!(mmio.get32(0x44), 0);
                for register in [0x80, 0x84, 0x90, 0x94, 0xa0, 0xa4] {
                    assert_eq!(mmio.get32(register), 0);
                }
            } else {
                let driver = result.unwrap();
                assert!(driver.read_only());
                assert_eq!(driver.sectors(), ARCHIVE_SECTORS);
                assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (15, 1));
            }
        }
    }

    #[test]
    fn capacity_change_stops_dispatch_and_retains_unreconciled_dma() {
        let (mmio, mut platform, memory) = attach_fixture(FLUSH, false);
        let base = memory as *mut _ as usize;
        let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let mut block = BatchedBlock::attach_writable(transport, memory, &platform).unwrap();
        let token = block
            .begin(Operation::Write(0), &[0; 512], true, false, &platform)
            .unwrap();
        let published = block.notify_stats().published;
        mmio.put32(0x100, 2048);
        mmio.put32(0xfc, 1);
        assert_eq!(
            block.begin(Operation::Read(1), &[0; 512], true, false, &platform),
            Err(Error::Device)
        );
        assert_eq!(block.drain(&platform), Err(Error::Device));
        assert_eq!(block.poll(&mut [0; 512], &platform), Err(Error::Device));
        assert_eq!(block.acknowledge(token), Err(Error::Response));
        assert_eq!(block.notify_stats().published, published);
        assert_eq!(block.free(), block.capacity() - 1);
        assert!(!block.is_quiescent());
        assert_ne!(mmio.get32(0x70) & 128, 0);
        assert_eq!(
            unsafe { read_volatile((base + 4098) as *const u16) },
            1u16.to_le()
        );
        platform.complete_mmio_reset = true;
        platform.clock.set(123_000);
        assert_eq!(block.stop_failed_mmio(&platform), Some(Ok(123_000)));
        let custody = block.terminal_custody().unwrap();
        assert_eq!(custody.reset, Some(Ok(123_000)));
        let held = custody.requests[token.slot as usize].unwrap();
        assert_eq!(
            (held.token, held.operation, held.completed),
            (token, Operation::Write(0), false)
        );
        assert_eq!((mmio.get32(0x70), mmio.get32(0x44)), (0, 0));
        assert_eq!(block.stop_failed_mmio(&platform), None);
        assert_eq!(block.terminal_custody(), Some(custody));
        assert_eq!(block.acknowledge(token), Err(Error::Response));
        assert_eq!(block.retained_requests(), (1, 0));
        assert_eq!(block.free(), block.capacity() - 1);
    }

    #[test]
    fn drain_failure_during_begin_preserves_the_reserved_operation() {
        for operation in [Operation::Read(0), Operation::Write(0), Operation::Flush] {
            let (mut block, platform, _) = fixture();
            platform.needs_reset_on_prepare.set(true);

            assert_eq!(
                block.begin(operation, &[0; 512], true, true, &platform),
                Err(Error::Device)
            );
            assert_eq!(block.free(), block.capacity() - 1);
            assert_eq!(block.notify_stats().published, 0);
            block.fence_for_recovery();

            let custody = block.terminal_custody().unwrap();
            assert_eq!(block.retained_requests(), (1, 0));
            assert_eq!(
                custody.requests[0],
                Some(RetainedBlock {
                    token: Token {
                        slot: 0,
                        generation: 1
                    },
                    operation,
                    completed: false,
                })
            );
        }
    }

    #[test]
    fn failed_request_clock_never_leaves_an_unrecorded_published_write() {
        let (mut block, mut platform, _) = fixture();
        platform.request_clock = Some(u64::MAX);

        assert_eq!(
            block.begin(Operation::Write(0), &[0; 512], true, true, &platform),
            Err(Error::Timeout)
        );
        block.fence_for_recovery();
        assert_eq!(block.notify_stats().published, 0);
        assert_eq!(block.free(), block.capacity());
        assert_eq!(block.retained_requests(), (0, 0));
    }

    #[test]
    fn recovery_fence_retains_pending_block_without_more_transport_io() {
        let (mut block, platform, _) = fixture();
        platform.clock.set(1_000_000);
        let read = Operation::Read(0);
        let token = block
            .begin(read, &[0; 512], true, false, &platform)
            .unwrap();
        let published = block.notify_stats().published;

        block.fence_for_recovery();

        let custody = block.terminal_custody().unwrap();
        assert_eq!(custody.reset, None);
        assert_eq!(
            custody.requests[usize::from(token.slot)].unwrap().token,
            token
        );
        assert_eq!(
            block.pending[usize::from(token.slot)],
            Some((token, read, 1))
        );
        assert_eq!(block.retained_requests(), (1, 0));
        assert_eq!(
            block.begin(read, &[0; 512], true, false, &platform),
            Err(Error::Device)
        );
        assert_eq!(block.drain(&platform), Err(Error::Device));
        assert_eq!(block.acknowledge(token), Err(Error::Response));
        assert_eq!(block.notify_stats().published, published);
        assert_eq!(block.transport.status(), 15);
    }

    #[test]
    fn terminal_block_custody_cannot_release_a_request_after_reset_timeout() {
        let (mut block, mut platform, base) = fixture();
        let operation = Operation::Read(0);
        let mut bytes = [0; 512];
        let token = block
            .begin(operation, &bytes, true, false, &platform)
            .unwrap();
        unsafe { complete(base, token.slot, true, 0) };
        assert_eq!(
            block.poll(&mut bytes, &platform).unwrap().unwrap().token,
            token
        );
        block.fence_for_recovery();
        assert_eq!(block.acknowledge(token), Err(Error::Device));
        platform.clock_step_ns = 25_000_000;
        assert_eq!(block.stop_failed_mmio(&platform), Some(Err(Error::Timeout)));
        let custody = block.terminal_custody().unwrap();
        assert_eq!(custody.reset, Some(Err(Error::Timeout)));
        assert_eq!(
            custody.requests[usize::from(token.slot)],
            Some(RetainedBlock {
                token,
                operation,
                completed: true
            })
        );
        assert_eq!(block.acknowledge(token), Err(Error::Device));
        assert_eq!(block.stop_failed_mmio(&platform), None);
        assert_eq!(block.terminal_custody(), Some(custody));
        assert_eq!(block.retained_requests(), (0, 1));
    }

    #[test]
    fn abandoned_block_session_seals_the_exact_retained_request_even_if_transport_is_live() {
        let (mut block, mut platform, _) = fixture();
        let operation = Operation::Read(0);
        let token = block
            .begin(operation, &[0; 512], true, true, &platform)
            .unwrap();
        let published = block.notify_stats().published;
        assert_eq!(published, 1);
        assert_eq!(block.stop_failed_mmio(&platform), None);

        platform.complete_mmio_reset = true;
        platform.clock.set(123_000);
        assert_eq!(
            block.stop_abandoned_mmio(&platform, || Ok(())),
            Some(Ok(123_000)),
        );

        let custody = block.terminal_custody().unwrap();
        assert_eq!(custody.reset, Some(Ok(123_000)));
        assert_eq!(
            custody.requests[usize::from(token.slot)],
            Some(RetainedBlock {
                token,
                operation,
                completed: false
            }),
        );
        assert_eq!(block.retained_requests(), (1, 0));
        assert_eq!(block.acknowledge(token), Err(Error::Response));
        assert_eq!(block.free(), block.capacity() - 1);
        assert_eq!(
            block.begin(operation, &[0; 512], true, true, &platform),
            Err(Error::Device)
        );
        assert_eq!(block.notify_stats().published, published);
        assert_eq!(block.stop_abandoned_mmio(&platform, || Ok(())), None);
    }

    #[test]
    fn abandoned_block_session_without_an_obligation_does_not_reset_a_healthy_queue() {
        let (mut block, platform, _) = fixture();
        assert!(block.is_quiescent());
        assert_eq!(
            block.stop_abandoned_mmio(&platform, || Err(Error::Busy)),
            None
        );
        assert!(block.is_quiescent());
        assert_eq!(block.transport.status(), 15);
        assert!(block.terminal_custody().is_none());
    }

    #[test]
    fn reset_proof_keeps_the_unconfirmed_write_in_custody() {
        let (mut block, mut platform, _) = fixture();
        let operation = Operation::Write(0);
        let token = block
            .begin(operation, &[0; 512], true, true, &platform)
            .unwrap();
        block.fence_for_recovery();
        let epoch = core::num::NonZeroU64::new(7).unwrap();
        assert_eq!(block.reset_proof(epoch), None);

        platform.complete_mmio_reset = true;
        platform.clock.set(123_000);
        assert_eq!(block.stop_failed_mmio(&platform), Some(Ok(123_000)));
        let raw = block.reset_proof(epoch).unwrap().encode();
        assert_eq!(
            u32::from_le_bytes(raw[..4].try_into().unwrap()),
            0x4359_5250
        );
        assert_eq!(
            u64::from_le_bytes(raw[8..16].try_into().unwrap()),
            epoch.get()
        );
        assert_eq!(u32::from_le_bytes(raw[16..20].try_into().unwrap()), 2);
        assert_eq!(&raw[20..24], &[0; 4]);
        assert_eq!(u64::from_le_bytes(raw[56..64].try_into().unwrap()), 123_000);
        assert_eq!(block.reset_proof(epoch).unwrap().encode(), raw);
        assert_eq!(
            block.terminal_custody().unwrap().requests[usize::from(token.slot)],
            Some(RetainedBlock {
                token,
                operation,
                completed: false
            }),
        );
        assert_eq!(block.acknowledge(token), Err(Error::Response));
    }

    #[test]
    fn reset_checkpoints_can_refuse_before_or_after_the_status_write() {
        for refuse_at in [1, 3] {
            let (mut block, platform, _) = fixture();
            let operation = Operation::Write(0);
            let token = block
                .begin(operation, &[0; 512], true, false, &platform)
                .unwrap();
            block.fence_for_recovery();

            let mut checkpoints = 0;
            assert_eq!(
                block.stop_failed_mmio_with_checkpoint(&platform, || {
                    checkpoints += 1;
                    if checkpoints == refuse_at {
                        Err(Error::Busy)
                    } else {
                        Ok(())
                    }
                }),
                Some(Err(Error::Busy))
            );
            assert_eq!(checkpoints, refuse_at);
            let status = if refuse_at == 1 { 15 } else { 0 };
            assert_eq!(block.transport.status(), status);
            assert!(block.transport.queue_enabled());
            assert_eq!(block.stop_failed_mmio(&platform), None);
            assert_eq!(block.retained_requests(), (1, 0));
            assert_eq!(block.reset_proof(core::num::NonZeroU64::MIN), None);
            assert_eq!(
                block.terminal_custody().unwrap().requests[usize::from(token.slot)],
                Some(RetainedBlock {
                    token,
                    operation,
                    completed: false
                }),
            );
        }
    }

    #[test]
    fn reset_checkpoints_do_not_restart_the_device_deadline() {
        let (mut block, mut platform, _) = fixture();
        platform.complete_mmio_reset = true;
        block.fence_for_recovery();

        let mut checkpoints = 0;
        assert_eq!(
            block.stop_failed_mmio_with_checkpoint(&platform, || {
                checkpoints += 1;
                if checkpoints == 2 {
                    platform.clock.set(crate::reset::RESET_DEADLINE_NS);
                }
                Ok(())
            }),
            Some(Err(Error::Timeout))
        );
        assert_eq!(checkpoints, 2);
        assert_eq!(block.transport.status(), 0);
        assert!(!block.transport.queue_enabled());
        assert_eq!(block.stop_failed_mmio(&platform), None);
    }

    #[test]
    fn config_change_prevents_publication_of_a_private_batch_even_at_same_capacity() {
        let (mmio, platform, memory) = attach_fixture(FLUSH, false);
        let transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let mut block = BatchedBlock::attach_writable(transport, memory, &platform).unwrap();
        block.set_notify_policy(2, 1, 1_000_000, 0).unwrap();
        block
            .begin(Operation::Write(0), &[0; 512], false, false, &platform)
            .unwrap();
        assert_eq!(block.notify_stats().published, 0);
        mmio.put32(0xfc, 1);
        assert_eq!(block.drain(&platform), Err(Error::Device));
        assert_eq!(block.notify_stats().published, 0);
        assert!(!block.is_quiescent());
    }
    unsafe fn complete(base: usize, slot: u8, read: bool, status: u8) {
        unsafe { complete_with_status(base, slot, read, Some(status)) }
    }

    unsafe fn complete_with_status(base: usize, slot: u8, read: bool, status: Option<u8>) {
        let bytes = if read { 512 } else { 0 };
        unsafe { complete_transfer(base, slot, bytes, bytes as u32 + 1, status) }
    }

    unsafe fn complete_transfer(
        base: usize,
        slot: u8,
        bytes: usize,
        used_len: u32,
        status: Option<u8>,
    ) {
        unsafe {
            let desc = base + usize::from(slot) * 32 + 16;
            let response = u64::from_le(read_volatile(desc as *const u64)) as usize;
            for i in 0..bytes {
                write_volatile((response + i) as *mut u8, 0x5a);
            }
            if let Some(status) = status {
                write_volatile((response + bytes) as *mut u8, status);
            }
            let used = base + 8192;
            let n = u16::from_le(read_volatile((used + 2) as *const u16));
            let at = used + 4 + usize::from(n % 16) * 8;
            write_volatile(at as *mut u32, u32::from(slot * 2).to_le());
            write_volatile((at + 4) as *mut u32, used_len.to_le());
            write_volatile((used + 2) as *mut u16, n.wrapping_add(1).to_le());
        }
    }
    #[test]
    fn four_sector_transfers_cover_the_full_range_and_keep_exact_custody() {
        const BYTES: usize = 4 * SECTOR_BYTES;
        let (mut b, p, memory) = fixture_with_width::<BYTES>();
        let data = [0x42; BYTES];
        let mut out = [0; BYTES];
        for sector in [4093, u64::MAX] {
            assert_eq!(
                b.begin(Operation::Write(sector), &data, true, true, &p),
                Err(Error::Address)
            );
        }
        assert!(b.is_quiescent());

        let op = Operation::Write(4092);
        let token = b.begin(op, &data, true, true, &p).unwrap();
        let head = memory + usize::from(token.slot) * 32;
        let request = unsafe { u64::from_le(read_volatile(head as *const u64)) } as usize;
        assert_eq!(
            unsafe { ((head + 8) as *const u32).read_volatile() },
            2064u32.to_le()
        );
        assert_eq!(
            unsafe { ((request + 8) as *const u64).read_volatile() },
            4092u64.to_le()
        );
        assert_eq!(
            unsafe { ((request + 16 + BYTES - 1) as *const u8).read_volatile() },
            0x42
        );
        unsafe { complete_transfer(memory, token.slot, 0, 1, Some(0)) };
        let completion = b.poll(&mut out, &p).unwrap().unwrap();
        assert_eq!((completion.token, completion.operation), (token, op));
        assert_eq!(b.free(), 7);
        b.acknowledge(token).unwrap();

        let op = Operation::Read(4092);
        let token = b.begin(op, &data, true, true, &p).unwrap();
        let response = memory + usize::from(token.slot) * 32 + 16;
        assert_eq!(
            unsafe { ((response + 8) as *const u32).read_volatile() },
            2049u32.to_le()
        );
        unsafe { complete_transfer(memory, token.slot, BYTES, 2049, Some(0)) };
        let completion = b.poll(&mut out, &p).unwrap().unwrap();
        assert_eq!((completion.token, completion.operation), (token, op));
        assert_eq!(out, [0x5a; BYTES]);
        assert_eq!(b.free(), 7);
        b.acknowledge(token).unwrap();
        assert!(b.is_quiescent());
    }
    #[test]
    fn four_sector_read_with_short_or_missing_status_keeps_dma_quarantined() {
        const BYTES: usize = 4 * SECTOR_BYTES;
        for (len, status) in [(2048, Some(0)), (2049, None), (2049, Some(1))] {
            let (mut b, p, memory) = fixture_with_width::<BYTES>();
            let mut out = [0xaa; BYTES];
            let token = b.begin(Operation::Read(0), &out, true, true, &p).unwrap();
            unsafe { complete_transfer(memory, token.slot, BYTES, len, status) };
            assert_eq!(b.poll(&mut out, &p), Err(Error::Response));
            assert_eq!(out, [0xaa; BYTES]);
            assert_eq!(b.free(), 7);
            assert_eq!(b.acknowledge(token), Err(Error::Response));
            assert_eq!(
                b.begin(Operation::Read(0), &out, true, true, &p),
                Err(Error::Device)
            );
        }
    }
    #[test]
    fn real_four_sector_batch_retains_buffers_through_ack() {
        let (mut b, p, m) = fixture();
        assert!(b.is_quiescent());
        b.set_notify_policy(4, 9, 1_000_000, 0).unwrap();
        let mut ts = [Token {
            slot: 0,
            generation: 0,
        }; 4];
        for (i, t) in ts.iter_mut().enumerate() {
            *t = b
                .begin(Operation::Read(i as u64), &[0; 512], false, false, &p)
                .unwrap();
        }
        assert_eq!(b.notify_stats().doorbells, 1);
        assert!(!b.is_quiescent());
        assert_eq!(b.notify_stats().last_completed_version, 0);
        unsafe {
            complete(m, ts[2].slot, true, 0);
        }
        let mut out = [0; 512];
        let c = b.poll(&mut out, &p).unwrap().unwrap();
        assert_eq!(c.operation, Operation::Read(2));
        assert_eq!(out, [0x5a; 512]);
        assert_eq!(b.free(), 4);
        assert_eq!(c.notify_version, 9);
        b.acknowledge(c.token).unwrap();
        assert_eq!(b.free(), 5);
        assert!(!b.is_quiescent());
    }
    #[test]
    fn predeadline_empty_poll_cannot_timeout_after_completion_during_ack() {
        let (mut b, p, m) = fixture();
        let token = b
            .begin(Operation::Read(0), &[0; 512], true, true, &p)
            .unwrap();
        p.idle_completion.set(Some((m, token.slot, true)));
        p.idle_clock.set(Some(250_000_000));
        let mut out = [0; 512];
        assert_eq!(b.poll(&mut out, &p), Ok(None));
        assert_eq!(p.clock.get(), 250_000_000);
        let completion = b.poll(&mut out, &p).unwrap().unwrap();
        assert_eq!(completion.token, token);
        assert_eq!(out, [0x5a; 512]);
        assert_eq!(b.notify_stats().errors, 0);
        assert!(
            !b.is_quiescent(),
            "completion still owns DMA until acknowledge"
        );
        b.acknowledge(token).unwrap();
        assert_eq!(b.free(), b.capacity());
        assert!(b.is_quiescent());
    }
    #[test]
    fn empty_queue_observed_after_original_deadline_still_times_out() {
        let (mut b, p, _) = fixture();
        let token = b
            .begin(Operation::Read(0), &[0; 512], true, true, &p)
            .unwrap();
        p.clock.set(249_000_000);
        assert_eq!(b.poll(&mut [0; 512], &p), Ok(None));
        p.clock.set(250_000_000);
        assert_eq!(b.poll(&mut [0; 512], &p), Err(Error::Timeout));
        assert!(!b.is_quiescent());
        assert_eq!(b.free(), b.capacity() - 1);
        assert!(b.acknowledge(token).is_err());
        assert_eq!(
            b.begin(Operation::Read(1), &[0; 512], true, true, &p),
            Err(Error::Device)
        );
    }
    #[test]
    fn stalled_empty_poll_does_not_restart_or_extend_original_deadline() {
        let (mut b, p, _) = fixture();
        b.begin(Operation::Read(0), &[0; 512], true, true, &p)
            .unwrap();
        p.idle_clock.set(Some(250_000_000));
        assert_eq!(b.poll(&mut [0; 512], &p), Ok(None));
        assert_eq!(b.poll(&mut [0; 512], &p), Err(Error::Timeout));
        assert_eq!(b.notify_stats().published, 1);
        assert_eq!(b.notify_stats().completed, 0);
    }
    #[test]
    fn already_completed_flush_wins_over_elapsed_timeout() {
        let (mut b, p, m) = fixture();
        let token = b
            .begin(Operation::Flush, &[0; 512], true, true, &p)
            .unwrap();
        unsafe { complete(m, token.slot, false, 0) };
        p.clock.set(250_000_000);
        let completion = b.poll(&mut [0; 512], &p).unwrap().unwrap();
        assert_eq!(completion.operation, Operation::Flush);
        b.acknowledge(token).unwrap();
    }
    #[test]
    fn native_sec_d06_completion_keeps_exact_token_until_valid_ack() {
        let (mut b, p, m) = fixture();
        let token = b
            .begin(Operation::Flush, &[0; 512], true, true, &p)
            .unwrap();
        // A caller cannot return DMA/descriptor custody before the actual
        // used-ring completion and checked device status are observed.
        assert_eq!(b.acknowledge(token), Err(Error::Response));
        unsafe { complete(m, token.slot, false, 0) };
        let c = b.poll(&mut [0; 512], &p).unwrap().unwrap();
        assert_eq!(c.token, token);
        assert_eq!(c.operation, Operation::Flush);
        assert!(!b.is_quiescent());
        // A delayed ACK does not convert the held completion into a timeout.
        p.clock.set(300_000_000);
        assert_eq!(b.poll(&mut [0; 512], &p), Ok(None));
        let forged = Token {
            generation: token.generation + 1,
            ..token
        };
        assert_eq!(b.acknowledge(forged), Err(Error::Response));
        assert!(!b.is_quiescent());
        b.acknowledge(token).unwrap();
        assert!(b.is_quiescent());
        assert_eq!(b.acknowledge(token), Err(Error::Response));
    }

    #[test]
    fn native_sec_d04_partial_completion_and_timeout_keep_unknown_dma_pinned() {
        let (mut block, platform, memory_base) = fixture();
        block.set_notify_policy(2, 10, 1_000_000, 0).unwrap();
        let first = block
            .begin(Operation::Read(0), &[0; 512], false, false, &platform)
            .unwrap();
        let second = block
            .begin(Operation::Read(1), &[0; 512], false, false, &platform)
            .unwrap();
        assert_ne!(first, second);
        unsafe { complete(memory_base, first.slot, true, 0) };
        let mut out = [0; 512];
        let finished = block.poll(&mut out, &platform).unwrap().unwrap();
        assert_eq!(finished.token, first);
        assert_eq!(out, [0x5a; 512]);
        assert_eq!(block.free(), block.capacity() - 2);
        // Only the first request has a checked device completion. After the
        // other times out, the second request's descriptor and DMA pages must
        // never be reused or inferred cancelled.
        platform.clock.set(250_000_000);
        assert_eq!(block.poll(&mut out, &platform), Err(Error::Timeout));
        assert!(!block.is_quiescent());
        assert_eq!(block.free(), block.capacity() - 2);
        assert_eq!(
            block.begin(Operation::Read(2), &[0; 512], true, true, &platform),
            Err(Error::Device)
        );
        assert_eq!(block.acknowledge(second), Err(Error::Response));
        // The independent first completion is proven; returning its pages
        // does not turn the still-unknown second request into a free slot.
        block.acknowledge(first).unwrap();
        assert!(!block.is_quiescent());
        assert_eq!(block.free(), block.capacity() - 1);
    }

    #[test]
    fn missing_block_status_never_publishes_success_or_releases_dma() {
        for reused in [false, true] {
            for operation in [Operation::Read(1), Operation::Write(1), Operation::Flush] {
                let (mut b, p, m) = fixture();
                if reused {
                    b.set_notify_policy(1, 1, 1_000_000, 0).unwrap();
                    let prior = b
                        .begin(Operation::Read(0), &[0; 512], true, true, &p)
                        .unwrap();
                    unsafe { complete(m, prior.slot, true, 0) };
                    let c = b.poll(&mut [0; 512], &p).unwrap().unwrap();
                    b.acknowledge(c.token).unwrap();
                    assert_eq!(b.free(), b.capacity());
                }
                b.set_notify_policy(1, 2, 1_000_000, 0).unwrap();
                let token = b.begin(operation, &[0; 512], true, true, &p).unwrap();
                assert_eq!(token.slot, 0);
                let mut out = [0xaa; 512];
                // A device publishes a full used record but omits the status
                // byte. Neither a fresh zero nor a released zero is evidence.
                unsafe {
                    complete_with_status(
                        m,
                        token.slot,
                        matches!(operation, Operation::Read(_)),
                        None,
                    )
                };
                assert_eq!(b.poll(&mut out, &p), Err(Error::Response));
                assert_eq!(out, [0xaa; 512]);
                assert_eq!(b.notify_stats().last_completed_version, u64::from(reused));
                assert_eq!(b.acknowledge(token), Err(Error::Response));
                assert!(!b.is_quiescent());
                assert_eq!(b.free(), b.capacity() - 1);
                assert_eq!(
                    b.begin(Operation::Flush, &[0; 512], true, true, &p),
                    Err(Error::Device)
                );
            }
        }
    }

    #[test]
    fn reset_during_completion_ack_never_certifies_block_result() {
        for operation in [Operation::Read(1), Operation::Write(1), Operation::Flush] {
            let (mut b, p, m) = fixture();
            b.set_notify_policy(1, 2, 1_000_000, 0).unwrap();
            let token = b.begin(operation, &[0; 512], true, true, &p).unwrap();
            unsafe { complete(m, token.slot, matches!(operation, Operation::Read(_)), 0) };
            p.reset_on_completion_ack.set(true);
            let mut out = [0xaa; 512];
            assert_eq!(b.poll(&mut out, &p), Err(Error::Device));
            assert!(!p.reset_on_completion_ack.get());
            assert_eq!(out, [0xaa; 512]);
            assert_eq!(b.notify_stats().last_completed_version, 0);
            assert_eq!(b.acknowledge(token), Err(Error::Response));
            assert_eq!(b.free(), b.capacity() - 1);
            assert!(!b.is_quiescent());
            b.transport.set_status(15);
            assert_eq!(
                b.begin(Operation::Flush, &[0; 512], true, true, &p),
                Err(Error::Device)
            );
        }
    }

    #[test]
    fn invalid_device_status_never_releases_or_acknowledges_policy() {
        let (mut b, p, m) = fixture();
        b.set_notify_policy(1, 2, 1_000_000, 0).unwrap();
        let token = b
            .begin(Operation::Write(0), &[7; 512], true, false, &p)
            .unwrap();
        unsafe {
            complete(m, token.slot, false, 1);
        }
        assert_eq!(b.poll(&mut [0; 512], &p), Err(Error::Response));
        assert_eq!(b.notify_stats().last_completed_version, 0);
        assert_eq!(b.free(), 7);
    }
}
