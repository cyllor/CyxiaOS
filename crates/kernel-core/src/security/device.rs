//! SEC-D: bounded descriptor ownership, reliable completion/reset, IRQ routing.
//! This bookkeeper never proves physical DMA cessation by timeout.
use super::Error;

pub const MAX_CHAINS: usize = 8;
pub const NOTIFY_DEADLINE_NS: u64 = 50_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token {
    pub slot: u8,
    pub generation: u64,
    pub submit_id: u64,
    pub device_generation: u64,
    pub queue_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Private,
    Published,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Lease {
    token: Token,
    descriptors: u8,
    pinned_pages: u8,
    state: State,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionProof {
    token: Token,
}
impl CompletionProof {
    #[allow(dead_code)]
    pub(crate) const fn from_driver(token: Token) -> Self {
        Self { token }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReliableReset {
    device_generation: u64,
    queue_generation: u64,
    quiesced: bool,
    dma_stopped: bool,
    reconciled: bool,
}
impl ReliableReset {
    /// Only the privileged native driver may create a proof after actually
    /// stopping the DMA engine and reconciling every in-flight operation.
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_driver(
        device_generation: u64,
        queue_generation: u64,
        quiesced: bool,
        dma_stopped: bool,
        reconciled: bool,
    ) -> Self {
        Self {
            device_generation,
            queue_generation,
            quiesced,
            dma_stopped,
            reconciled,
        }
    }
}
/// A physical queue cannot have more than its negotiated descriptor capacity,
/// nor may its descriptor, DMA pin or completion credit be loaned twice.
pub struct Queue<const N: usize> {
    slots: [Option<Lease>; N],
    generations: [u64; N],
    device_generation: u64,
    queue_generation: u64,
}
impl<const N: usize> Queue<N> {
    pub const fn new(device_generation: u64, queue_generation: u64) -> Self {
        Self {
            slots: [None; N],
            generations: [0; N],
            device_generation,
            queue_generation,
        }
    }
    pub fn prepare(
        &mut self,
        submit_id: u64,
        descriptors: u8,
        pinned_pages: u8,
        credit_reserved: bool,
    ) -> Result<Token, Error> {
        if submit_id == 0
            || descriptors == 0
            || usize::from(descriptors) > MAX_CHAINS
            || pinned_pages == 0
            || !credit_reserved
            || self.device_generation == 0
            || self.queue_generation == 0
        {
            return Err(Error::Invalid);
        }
        if let Some(row) = self
            .slots
            .iter()
            .flatten()
            .find(|r| r.token.submit_id == submit_id)
        {
            return if row.descriptors == descriptors && row.pinned_pages == pinned_pages {
                Ok(row.token)
            } else {
                Err(Error::Conflict)
            };
        }
        // Count all reserved/published/UNKNOWN chains, not only occupied
        // request slots. A queue of eight descriptors cannot admit eight
        // eight-descriptor chains. UNKNOWN still consumes real DMA credit.
        let allocated = self
            .slots
            .iter()
            .flatten()
            .try_fold(0usize, |total, lease| {
                total.checked_add(usize::from(lease.descriptors))
            })
            .ok_or(Error::Capacity)?;
        if allocated
            .checked_add(usize::from(descriptors))
            .is_none_or(|total| total > MAX_CHAINS)
        {
            return Err(Error::Capacity);
        }
        let at = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let next = self.generations[at]
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let token = Token {
            slot: u8::try_from(at).map_err(|_| Error::Capacity)?,
            generation: next,
            submit_id,
            device_generation: self.device_generation,
            queue_generation: self.queue_generation,
        };
        self.generations[at] = next;
        self.slots[at] = Some(Lease {
            token,
            descriptors,
            pinned_pages,
            state: State::Private,
        });
        Ok(token)
    }
    fn lease(&mut self, token: Token) -> Result<&mut Lease, Error> {
        // A newly constructed queue can begin its slot counters at one.
        // Bind every transition to the registered device/queue lifecycle,
        // not just a slot and local submit ID. The native registry must also
        // select the correct physical queue before invoking this component.
        if token.device_generation != self.device_generation
            || token.queue_generation != self.queue_generation
        {
            return Err(Error::Stale);
        }
        let lease = self
            .slots
            .get_mut(token.slot as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::Stale)?;
        if lease.token != token {
            return Err(Error::Stale);
        }
        Ok(lease)
    }
    pub fn publish(&mut self, token: Token) -> Result<(), Error> {
        let lease = self.lease(token)?;
        if lease.state != State::Private {
            return Err(Error::Busy);
        }
        lease.state = State::Published;
        Ok(())
    }
    pub fn timeout(&mut self, token: Token) -> Result<(), Error> {
        let lease = self.lease(token)?;
        if lease.state != State::Published {
            return Err(Error::Busy);
        }
        lease.state = State::Unknown;
        Ok(())
    }
    pub fn complete(&mut self, token: Token, proof: CompletionProof) -> Result<(), Error> {
        if proof.token != token {
            return Err(Error::Unauthorized);
        }
        let state = self.lease(token)?.state;
        if state != State::Published && state != State::Unknown {
            return Err(Error::Busy);
        }
        self.slots[token.slot as usize] = None;
        Ok(())
    }
    pub fn state(&mut self, token: Token) -> Result<State, Error> {
        Ok(self.lease(token)?.state)
    }
    pub fn has_inflight(&self) -> bool {
        self.slots.iter().any(Option::is_some)
    }
    pub fn reset(&mut self, proof: ReliableReset) -> Result<(), Error> {
        if proof.device_generation != self.device_generation
            || proof.queue_generation != self.queue_generation
        {
            return Err(Error::Stale);
        }
        if !proof.quiesced || !proof.dma_stopped || !proof.reconciled {
            return Err(Error::Unknown);
        }
        let next_device = self
            .device_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let next_queue = self
            .queue_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.slots.fill(None);
        self.device_generation = next_device;
        self.queue_generation = next_queue;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqKind {
    VirtioSpi,
    Timer,
    Ipi,
    Watchdog,
}
pub fn validate_irq_route(
    kind: IrqKind,
    target_cpu: u8,
    core_generation: u64,
    healthy_business: u64,
    draining: u64,
    suspect: u64,
    source_quiesced: bool,
) -> Result<(), Error> {
    let bit = 1u64.checked_shl(target_cpu as u32).ok_or(Error::Invalid)?;
    // CPU0 is the single V0.20 control CPU. Ordinary VirtIO SPI work must never
    // be rerouted there even if a damaged mask marks it as healthy business;
    // CPU1-3 are the only ordinary business IRQ targets.
    if target_cpu == 0
        || kind != IrqKind::VirtioSpi
        || core_generation == 0
        || !source_quiesced
        || healthy_business & !crate::control_plane::cpu0_v0199::BUSINESS_MASK != 0
        || bit & healthy_business & !draining & !suspect == 0
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
/// V0.19.9 ordinary SPI route admission; the single authoritative CPU0
/// boundary that validate_irq_route now matches. Native CPU0 never receives
/// ordinary SPI.
pub fn validate_irq_route_v0199(
    kind: IrqKind,
    target_cpu: u8,
    core_generation: u64,
    healthy_business: u64,
    draining: u64,
    suspect: u64,
    source_quiesced: bool,
) -> Result<(), Error> {
    if kind != IrqKind::VirtioSpi
        || !source_quiesced
        || core_generation == 0
        || !crate::control_plane::cpu0_v0199::permits_business(
            u16::from(target_cpu),
            crate::control_plane::cpu0_v0199::BUSINESS_MASK,
            healthy_business,
            draining,
            suspect,
        )
        || healthy_business & !crate::control_plane::cpu0_v0199::BUSINESS_MASK != 0
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub fn must_notify(queued: u8, batch: u8, age_ns: u64, isolated: bool) -> Result<bool, Error> {
    if ![1, 2, 4, 8].contains(&batch) || queued > MAX_CHAINS as u8 {
        return Err(Error::Invalid);
    }
    Ok(queued != 0 && (isolated || queued >= batch || age_ns >= NOTIFY_DEADLINE_NS))
}

/// SEC-D08 (V0.19.9 stable ID): FLUSH gate drill. Baseline: 主§9.3 写入与
/// 确认顺序 (spec L3936–3948: 未协商或不能正确执行 FLUSH 时禁止可写持久配置),
/// SEC-D08 验收行 (L10239–10241), SEC-D 实施契约 block bit9 FLUSH 必选
/// (L10169), SEC-D 核心流程 6 (L10119–10121).
///
/// Contract-only model; the native driver-virtio attach gate already refuses
/// a block device without negotiated FLUSH. This drills the rejection path
/// and the write→FLUSH→ack ordering that the always-FLUSH fixture never
/// exercised. No wire bytes are invented here.
pub const VIRTIO_BLOCK_F_FLUSH: u32 = 1 << 9;

/// Mount admission: a writable persistent configuration requires negotiated
/// block FLUSH (bit9). Without it the writable mount is refused and durability
/// cannot be faked; read-only access (the recovery/diagnostic path) remains
/// admissible. Other feature bits never substitute for FLUSH.
pub fn admit_mount(negotiated_features: u32, writable: bool) -> Result<(), Error> {
    if writable && negotiated_features & VIRTIO_BLOCK_F_FLUSH == 0 {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

/// Real device FLUSH completion evidence, constructed only by the native
/// driver after the FLUSH request actually completed. `through_batch` is the
/// highest write batch the device has flushed; a proof may never cover more
/// than was submitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlushProof {
    through_batch: u64,
}
impl FlushProof {
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_driver(through_batch: u64) -> Self {
        Self { through_batch }
    }
}

/// Write→FLUSH→durable-ACK ordering gate (主§9.3). Device completion order
/// does not replace transaction dependencies: a durable ACK is published only
/// for a batch covered by real FLUSH evidence, in admission order. A FLUSH
/// failure/timeout stops new submissions and leaves unproven batches UNKNOWN
/// forever (fail-closed); it never revokes durability already proven, and it
/// never fabricates success. File-level durability truth still requires the
/// log's two FLUSHes plus the commit chain (file.rs Stage machine); this gate
/// only models the device-level FLUSH evidence leg.
pub struct FlushGate {
    last_written: u64,
    flushed_through: u64,
    acked_through: u64,
    failed: bool,
}
impl Default for FlushGate {
    fn default() -> Self {
        Self::new()
    }
}
impl FlushGate {
    pub const fn new() -> Self {
        Self {
            last_written: 0,
            flushed_through: 0,
            acked_through: 0,
            failed: false,
        }
    }
    /// Admit one write batch after the mount gate passed. After a FLUSH
    /// failure new submissions stop (SEC-D 降级与失败路径, L10144).
    pub fn write(&mut self) -> Result<u64, Error> {
        if self.failed {
            return Err(Error::Unknown);
        }
        self.last_written = self.last_written.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(self.last_written)
    }
    /// Record real FLUSH completion. A proof beyond the submitted batches is
    /// forged evidence; a regressing watermark is stale. Both are refused.
    pub fn flush(&mut self, proof: FlushProof) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Unknown);
        }
        if proof.through_batch > self.last_written {
            return Err(Error::Unauthorized);
        }
        if proof.through_batch < self.flushed_through {
            return Err(Error::Stale);
        }
        self.flushed_through = proof.through_batch;
        Ok(())
    }
    /// FLUSH failure or timeout: sticky fail-closed. Unknown is not success
    /// and not a cancellation of possibly-durable writes (主§9.3, L3946).
    pub fn flush_failed(&mut self) {
        self.failed = true;
    }
    pub const fn flushed_through(&self) -> u64 {
        self.flushed_through
    }
    pub const fn acked_through(&self) -> u64 {
        self.acked_through
    }
    /// Durable success ACK for one batch: only with real FLUSH evidence
    /// covering it and only in serial order. Without evidence the answer is
    /// UNKNOWN, never a fabricated success; a later failure does not revoke
    /// an already-proven (or already-acked) batch.
    pub fn durable_ack(&mut self, batch: u64) -> Result<(), Error> {
        if batch == 0 || batch > self.last_written {
            return Err(Error::Invalid);
        }
        if batch <= self.acked_through {
            return Err(Error::Stale);
        }
        if batch > self.flushed_through {
            return Err(Error::Unknown);
        }
        if batch != self.acked_through.checked_add(1).ok_or(Error::Exhausted)? {
            return Err(Error::Busy);
        }
        self.acked_through = batch;
        Ok(())
    }
}

/// SEC-D10 (V0.19.9 stable ID): ordinary SPI no-progress storm mask.
/// Baseline: SEC-D10 验收行 (spec L10252–10256), SEC-D 实施契约 IRQ 风暴段
/// (L10333–10340: 对齐 100ms 窗口累计 1000 次无有效进展即屏蔽并记录退化;
/// 安静 1000ms 且监督者核验设备/队列/路由代际后恢复; 特殊 ID1020..1023 不作
/// 普通 EOI; Timer/IPI/关键异常不参与可选限流), 安§0.8 (L6989–6991: 唯一阈值
/// 1000 次无进展/100ms), 主§8.6 / A04.
///
/// Contract-only model of the mask/recover decision; the native GICv2
/// mask/EOI path (smp.rs, driver-gicv2 acknowledge/end) is wired separately.
/// Fail-closed choices documented where the baseline is silent: the 1000th
/// no-progress IRQ itself is blocked once the mask engages, and any observed
/// activity (including blocked attempts) restarts the quiet period.
pub const SPI_STORM_WINDOW_MS: u64 = 100;
pub const SPI_STORM_THRESHOLD: u32 = 1000;
pub const SPI_QUIET_RECOVERY_MS: u64 = 1000;
/// GICv2 ordinary SPI range; 1020..1023 are special IDs, never ordinary EOI.
pub const SPI_ORDINARY_MIN: u16 = 32;
pub const SPI_ORDINARY_MAX: u16 = 1019;
pub const SPI_SPECIAL_MIN: u16 = 1020;
pub const SPI_SPECIAL_MAX: u16 = 1023;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqDisposition {
    /// Ordinary SPI delivered (or exempt class passed through).
    Delivered,
    /// Timer/IPI/watchdog: outside the optional storm rate limit.
    Exempt,
    /// Special ID 1020..1023: handled by the measured secure-extension view,
    /// never accounted as an ordinary SPI and never given an ordinary EOI.
    SpecialNoOrdinaryEoi,
}

#[derive(Clone, Copy)]
struct SpiSource {
    irq_id: u16,
    device_generation: u64,
    queue_generation: u64,
    route_generation: u64,
    window_start_ms: u64,
    no_progress: u32,
    last_seen_ms: u64,
    masked: bool,
    degraded: bool,
}

/// Per-SPI storm accounting and mask state for up to N registered sources.
pub struct SpiStormGate<const N: usize> {
    sources: [Option<SpiSource>; N],
}
impl<const N: usize> Default for SpiStormGate<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> SpiStormGate<N> {
    pub const fn new() -> Self {
        Self { sources: [None; N] }
    }
    fn source(&self, irq_id: u16) -> Result<&SpiSource, Error> {
        self.sources
            .iter()
            .flatten()
            .find(|s| s.irq_id == irq_id)
            .ok_or(Error::Stale)
    }
    fn source_mut(&mut self, irq_id: u16) -> Result<&mut SpiSource, Error> {
        self.sources
            .iter_mut()
            .flatten()
            .find(|s| s.irq_id == irq_id)
            .ok_or(Error::Stale)
    }
    /// Register one ordinary SPI with its supervised generations. Special
    /// IDs and non-SPI interrupt numbers are not storm sources.
    pub fn register(
        &mut self,
        irq_id: u16,
        device_generation: u64,
        queue_generation: u64,
        route_generation: u64,
    ) -> Result<(), Error> {
        if !(SPI_ORDINARY_MIN..=SPI_ORDINARY_MAX).contains(&irq_id)
            || device_generation == 0
            || queue_generation == 0
            || route_generation == 0
        {
            return Err(Error::Invalid);
        }
        if let Some(existing) = self.sources.iter().flatten().find(|s| s.irq_id == irq_id) {
            return if existing.device_generation == device_generation
                && existing.queue_generation == queue_generation
                && existing.route_generation == route_generation
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let pos = self
            .sources
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.sources[pos] = Some(SpiSource {
            irq_id,
            device_generation,
            queue_generation,
            route_generation,
            window_start_ms: 0,
            no_progress: 0,
            last_seen_ms: 0,
            masked: false,
            degraded: false,
        });
        Ok(())
    }
    /// One interrupt observation. Masked ordinary SPIs cannot deliver
    /// (fail-closed); ordinary SPIs never target CPU0 (fixed control CPU).
    /// `progress` marks effective device progress, which clears the
    /// no-progress count; only no-progress IRQs accumulate toward the mask.
    pub fn deliver(
        &mut self,
        kind: IrqKind,
        irq_id: u16,
        target_cpu: u8,
        now_ms: u64,
        progress: bool,
    ) -> Result<IrqDisposition, Error> {
        if kind != IrqKind::VirtioSpi {
            return Ok(IrqDisposition::Exempt);
        }
        if (SPI_SPECIAL_MIN..=SPI_SPECIAL_MAX).contains(&irq_id) {
            return Ok(IrqDisposition::SpecialNoOrdinaryEoi);
        }
        if !(SPI_ORDINARY_MIN..=SPI_ORDINARY_MAX).contains(&irq_id) {
            return Err(Error::Invalid);
        }
        if !crate::control_plane::cpu0_v0199::permits_business(
            u16::from(target_cpu),
            crate::control_plane::cpu0_v0199::BUSINESS_MASK,
            crate::control_plane::cpu0_v0199::ONLINE,
            0,
            0,
        ) {
            return Err(Error::Unauthorized);
        }
        let src = self.source_mut(irq_id)?;
        if now_ms < src.last_seen_ms {
            return Err(Error::Invalid);
        }
        src.last_seen_ms = now_ms;
        if src.masked {
            return Err(Error::Unauthorized);
        }
        let window = now_ms - now_ms % SPI_STORM_WINDOW_MS;
        if window != src.window_start_ms {
            src.window_start_ms = window;
            src.no_progress = 0;
        }
        if progress {
            src.no_progress = 0;
            return Ok(IrqDisposition::Delivered);
        }
        src.no_progress += 1;
        if src.no_progress >= SPI_STORM_THRESHOLD {
            src.masked = true;
            src.degraded = true;
            return Err(Error::Unauthorized);
        }
        Ok(IrqDisposition::Delivered)
    }
    /// Supervisor recovery: at least 1000ms of quiet since the last observed
    /// activity AND matching device/queue/route generations. The degradation
    /// record stays for audit; the mask alone is cleared.
    pub fn try_recover(
        &mut self,
        irq_id: u16,
        now_ms: u64,
        device_generation: u64,
        queue_generation: u64,
        route_generation: u64,
    ) -> Result<(), Error> {
        let src = self.source_mut(irq_id)?;
        if !src.masked {
            return Ok(());
        }
        if now_ms < src.last_seen_ms {
            return Err(Error::Invalid);
        }
        if now_ms - src.last_seen_ms < SPI_QUIET_RECOVERY_MS {
            return Err(Error::Busy);
        }
        if src.device_generation != device_generation
            || src.queue_generation != queue_generation
            || src.route_generation != route_generation
        {
            return Err(Error::Stale);
        }
        src.masked = false;
        src.no_progress = 0;
        src.window_start_ms = now_ms - now_ms % SPI_STORM_WINDOW_MS;
        Ok(())
    }
    pub fn is_masked(&self, irq_id: u16) -> Result<bool, Error> {
        Ok(self.source(irq_id)?.masked)
    }
    pub fn is_degraded(&self, irq_id: u16) -> Result<bool, Error> {
        Ok(self.source(irq_id)?.degraded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sec_d01_unreserved_dma_or_credit_denied() {
        let mut q = Queue::<2>::new(1, 1);
        assert_eq!(q.prepare(1, 1, 0, true), Err(Error::Invalid));
        assert_eq!(q.prepare(1, 1, 1, false), Err(Error::Invalid));
    }
    #[test]
    fn sec_d02_bounded_descriptor_chains() {
        let mut q = Queue::<1>::new(1, 1);
        assert_eq!(q.prepare(1, 9, 1, true), Err(Error::Invalid));
        assert!(q.prepare(1, 1, 1, true).is_ok());
        assert_eq!(q.prepare(2, 1, 1, true), Err(Error::Capacity));
    }
    #[test]
    fn v019_sec_d02_aggregate_descriptors_stay_reserved_while_unknown() {
        let mut q = Queue::<2>::new(1, 1);
        let t = q.prepare(1, 5, 1, true).unwrap();
        assert_eq!(q.prepare(2, 4, 1, true), Err(Error::Capacity));
        q.publish(t).unwrap();
        q.timeout(t).unwrap();
        assert_eq!(q.prepare(2, 4, 1, true), Err(Error::Capacity));
        q.complete(t, CompletionProof::from_driver(t)).unwrap();
        assert!(q.prepare(2, 4, 1, true).is_ok());
    }
    #[test]
    fn sec_d03_duplicate_submit_is_not_a_second_lease() {
        let mut q = Queue::<2>::new(1, 1);
        let t = q.prepare(1, 1, 1, true).unwrap();
        assert_eq!(q.prepare(1, 1, 1, true), Ok(t));
        assert_eq!(q.prepare(1, 2, 1, true), Err(Error::Conflict));
    }
    #[test]
    fn sec_d04_timeout_is_unknown_not_dma_release() {
        let mut q = Queue::<1>::new(1, 1);
        let t = q.prepare(1, 1, 1, true).unwrap();
        q.publish(t).unwrap();
        q.timeout(t).unwrap();
        assert!(q.has_inflight());
        assert_eq!(q.state(t), Ok(State::Unknown));
    }
    #[test]
    fn sec_d05_reset_needs_reliable_proof() {
        let mut q = Queue::<1>::new(1, 1);
        let t = q.prepare(1, 1, 1, true).unwrap();
        q.publish(t).unwrap();
        assert_eq!(
            q.reset(ReliableReset::from_driver(1, 1, true, false, true)),
            Err(Error::Unknown)
        );
        assert!(q.has_inflight());
        q.reset(ReliableReset::from_driver(1, 1, true, true, true))
            .unwrap();
        assert!(!q.has_inflight());
    }
    #[test]
    fn sec_d06_old_or_forged_completion_rejected() {
        let mut q = Queue::<1>::new(1, 1);
        let t = q.prepare(1, 1, 1, true).unwrap();
        q.publish(t).unwrap();
        assert_eq!(
            q.complete(
                t,
                CompletionProof::from_driver(Token { generation: 2, ..t })
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            q.complete(
                Token { generation: 2, ..t },
                CompletionProof::from_driver(Token { generation: 2, ..t })
            ),
            Err(Error::Stale)
        );
        q.complete(t, CompletionProof::from_driver(t)).unwrap();
        assert_eq!(
            q.complete(t, CompletionProof::from_driver(t)),
            Err(Error::Stale)
        );
    }
    #[test]
    fn v0199_recreated_queue_rejects_old_lifecycle_completion() {
        let mut old = Queue::<1>::new(1, 1);
        let old_token = old.prepare(7, 1, 1, true).unwrap();
        old.publish(old_token).unwrap();
        old.timeout(old_token).unwrap();
        // The registry obtains reliable reset proof before reconstruction.
        old.reset(ReliableReset::from_driver(1, 1, true, true, true))
            .unwrap();
        let mut fresh = Queue::<1>::new(2, 2);
        let new_token = fresh.prepare(7, 1, 1, true).unwrap();
        fresh.publish(new_token).unwrap();
        assert_eq!(old_token.generation, new_token.generation);
        assert_eq!(old_token.submit_id, new_token.submit_id);
        assert_eq!(
            fresh.complete(old_token, CompletionProof::from_driver(old_token)),
            Err(Error::Stale)
        );
        assert_eq!(
            fresh.complete(new_token, CompletionProof::from_driver(old_token)),
            Err(Error::Unauthorized)
        );
        assert_eq!(fresh.state(new_token), Ok(State::Published));
        assert!(fresh.has_inflight());
        fresh
            .complete(new_token, CompletionProof::from_driver(new_token))
            .unwrap();
        assert!(!fresh.has_inflight());
    }
    #[test]
    fn sec_d07_irq_must_target_healthy_business_only() {
        assert_eq!(
            validate_irq_route(IrqKind::Timer, 1, 1, 0b10, 0, 0, true),
            Err(Error::Unauthorized)
        );
        // CPU0 is the control core; ordinary SPI must never route there.
        assert_eq!(
            validate_irq_route(IrqKind::VirtioSpi, 0, 1, 0b1110, 0, 0, true),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            validate_irq_route(IrqKind::VirtioSpi, 1, 1, 0b10, 0b10, 0, true),
            Err(Error::Unauthorized)
        );
        // CPU1 is now a legal business IRQ target when healthy.
        assert_eq!(
            validate_irq_route(IrqKind::VirtioSpi, 1, 1, 0b10, 0, 0, true),
            Ok(())
        );
        assert_eq!(
            validate_irq_route(IrqKind::VirtioSpi, 2, 1, 0b100, 0, 0, true),
            Ok(())
        );
    }
    #[test]
    fn v0199_irq_route_is_only_to_fixed_business_cpu_after_quiescence() {
        for cpu in 1..=3 {
            assert_eq!(
                validate_irq_route_v0199(IrqKind::VirtioSpi, cpu, 1, 0b1110, 0, 0, true),
                Ok(())
            );
            assert_eq!(
                validate_irq_route_v0199(IrqKind::VirtioSpi, cpu, 1, 0b1110, 1 << cpu, 0, true),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                validate_irq_route_v0199(IrqKind::VirtioSpi, cpu, 1, 0b1110, 0, 1 << cpu, true),
                Err(Error::Unauthorized)
            );
        }
        for cpu in [0, 4, 63, 64] {
            assert_eq!(
                validate_irq_route_v0199(IrqKind::VirtioSpi, cpu, 1, 0b1110, 0, 0, true),
                Err(Error::Unauthorized)
            );
        }
        assert_eq!(
            validate_irq_route_v0199(IrqKind::VirtioSpi, 1, 1, 0b1111, 0, 0, true),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            validate_irq_route_v0199(IrqKind::VirtioSpi, 1, 1, 0b1110, 0, 0, false),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            validate_irq_route_v0199(IrqKind::Timer, 1, 1, 0b1110, 0, 0, true),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn sec_d08_lonely_chain_reaches_notification_deadline() {
        assert_eq!(must_notify(1, 8, 49_999, false), Ok(false));
        assert_eq!(must_notify(1, 8, 50_000, false), Ok(true));
        assert_eq!(must_notify(1, 8, 0, true), Ok(true));
        assert_eq!(must_notify(0, 8, 50_000, true), Ok(false));
    }

    // SEC-D08 (V0.19.9): FLUSH gate drill. The legacy sec_d08 test above keeps
    // its V0.19 topic (D11 notification deadline); these cover the stable ID.

    #[test]
    fn v0199_sec_d08_writable_mount_requires_negotiated_flush() {
        // No FLUSH bit: writable persistent configuration is refused.
        assert_eq!(admit_mount(0, true), Err(Error::Unauthorized));
        assert_eq!(admit_mount(1 << 5, true), Err(Error::Unauthorized)); // READ_ONLY only
        assert_eq!(admit_mount(1, true), Err(Error::Unauthorized)); // VERSION_1 only
        // Negotiated FLUSH admits the writable mount.
        assert_eq!(admit_mount(VIRTIO_BLOCK_F_FLUSH, true), Ok(()));
        assert_eq!(admit_mount(VIRTIO_BLOCK_F_FLUSH | (1 << 5), true), Ok(()));
        // Read-only access remains admissible without FLUSH (recovery path).
        assert_eq!(admit_mount(0, false), Ok(()));
        assert_eq!(VIRTIO_BLOCK_F_FLUSH, 1 << 9);
    }

    #[test]
    fn v0199_sec_d08_write_then_flush_then_ack_order() {
        let mut gate = FlushGate::new();
        let b1 = gate.write().unwrap();
        // Write completion alone is never durable success.
        assert_eq!(gate.durable_ack(b1), Err(Error::Unknown));
        gate.flush(FlushProof::from_driver(b1)).unwrap();
        assert_eq!(gate.durable_ack(b1), Ok(()));
        assert_eq!(gate.acked_through(), 1);
        // A repeated durable ACK is stale, not a second success.
        assert_eq!(gate.durable_ack(b1), Err(Error::Stale));
        // Two more writes, one FLUSH covering both; ACKs stay serial.
        let b2 = gate.write().unwrap();
        let b3 = gate.write().unwrap();
        assert_eq!(gate.durable_ack(b3), Err(Error::Unknown));
        gate.flush(FlushProof::from_driver(b3)).unwrap();
        assert_eq!(gate.durable_ack(b3), Err(Error::Busy)); // out of order
        assert_eq!(gate.durable_ack(b2), Ok(()));
        assert_eq!(gate.durable_ack(b3), Ok(()));
        // Unknown batch ids are invalid, never acknowledged.
        assert_eq!(gate.durable_ack(0), Err(Error::Invalid));
        assert_eq!(gate.durable_ack(4), Err(Error::Invalid));
    }

    #[test]
    fn v0199_sec_d08_flush_proof_cannot_exceed_submitted_or_regress() {
        let mut gate = FlushGate::new();
        let b1 = gate.write().unwrap();
        // Forged evidence covering unwritten batches is refused.
        assert_eq!(
            gate.flush(FlushProof::from_driver(b1 + 1)),
            Err(Error::Unauthorized)
        );
        assert_eq!(gate.flushed_through(), 0);
        assert_eq!(gate.durable_ack(b1), Err(Error::Unknown));
        gate.flush(FlushProof::from_driver(b1)).unwrap();
        // A regressing watermark is stale and cannot undo proven durability.
        assert_eq!(gate.flush(FlushProof::from_driver(0)), Err(Error::Stale));
        assert_eq!(gate.flushed_through(), 1);
        assert_eq!(gate.durable_ack(b1), Ok(()));
    }

    #[test]
    fn v0199_sec_d08_flush_failure_is_fail_closed_not_fake_success() {
        let mut gate = FlushGate::new();
        let b1 = gate.write().unwrap();
        gate.flush(FlushProof::from_driver(b1)).unwrap();
        assert_eq!(gate.durable_ack(b1), Ok(()));
        let b2 = gate.write().unwrap();
        gate.flush_failed();
        // Unproven batch stays UNKNOWN; no new submissions or flush proofs.
        assert_eq!(gate.durable_ack(b2), Err(Error::Unknown));
        assert_eq!(gate.write(), Err(Error::Unknown));
        assert_eq!(gate.flush(FlushProof::from_driver(b2)), Err(Error::Unknown));
        // The failure never revokes durability already proven and acked.
        assert_eq!(gate.acked_through(), 1);
        assert_eq!(gate.durable_ack(b1), Err(Error::Stale));
    }

    // SEC-D10 (V0.19.9): ordinary SPI no-progress storm mask.

    fn storm_gate() -> SpiStormGate<2> {
        let mut gate = SpiStormGate::<2>::new();
        gate.register(40, 1, 1, 1).unwrap();
        gate
    }

    #[test]
    fn v0199_sec_d10_masks_at_1000_not_999() {
        let mut gate = storm_gate();
        for _ in 0..999 {
            assert_eq!(
                gate.deliver(IrqKind::VirtioSpi, 40, 1, 99, false),
                Ok(IrqDisposition::Delivered)
            );
        }
        assert_eq!(gate.is_masked(40), Ok(false));
        // The 1000th no-progress IRQ in the aligned window engages the mask
        // and is itself blocked (fail-closed); later IRQs cannot deliver.
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 99, false),
            Err(Error::Unauthorized)
        );
        assert_eq!(gate.is_masked(40), Ok(true));
        assert_eq!(gate.is_degraded(40), Ok(true));
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 99, false),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn v0199_sec_d10_aligned_windows_and_effective_progress_reset() {
        let mut gate = storm_gate();
        for _ in 0..999 {
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 99, false).unwrap();
        }
        // A new aligned 100ms window restarts the count: no cross-window sum.
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 100, false),
            Ok(IrqDisposition::Delivered)
        );
        assert_eq!(gate.is_masked(40), Ok(false));
        // Effective progress clears the no-progress count mid-window.
        for _ in 0..998 {
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 150, false).unwrap();
        }
        assert_eq!(gate.is_masked(40), Ok(false));
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 150, true),
            Ok(IrqDisposition::Delivered)
        );
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 150, false),
            Ok(IrqDisposition::Delivered)
        );
        assert_eq!(gate.is_masked(40), Ok(false));
        // Clock regression is refused, never counted.
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 149, false),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn v0199_sec_d10_recovery_needs_quiet_and_supervisor_generations() {
        let mut gate = storm_gate();
        for _ in 0..1000 {
            let _ = gate.deliver(IrqKind::VirtioSpi, 40, 1, 99, false);
        }
        assert_eq!(gate.is_masked(40), Ok(true));
        // 999ms quiet is not enough.
        assert_eq!(gate.try_recover(40, 1098, 1, 1, 1), Err(Error::Busy));
        // 1000ms quiet but mismatched supervisor generations stay masked.
        assert_eq!(gate.try_recover(40, 1099, 2, 1, 1), Err(Error::Stale));
        assert_eq!(gate.try_recover(40, 1099, 1, 2, 1), Err(Error::Stale));
        assert_eq!(gate.try_recover(40, 1099, 1, 1, 2), Err(Error::Stale));
        assert_eq!(gate.is_masked(40), Ok(true));
        // Continued blocked activity restarts the quiet period.
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 1500, false),
            Err(Error::Unauthorized)
        );
        assert_eq!(gate.try_recover(40, 2400, 1, 1, 1), Err(Error::Busy));
        // Full quiet plus verified generations recover; degradation is kept.
        gate.try_recover(40, 2500, 1, 1, 1).unwrap();
        assert_eq!(gate.is_masked(40), Ok(false));
        assert_eq!(gate.is_degraded(40), Ok(true));
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 1, 2500, false),
            Ok(IrqDisposition::Delivered)
        );
        // Recovering an unmasked source is a no-op.
        gate.try_recover(40, 2500, 1, 1, 1).unwrap();
    }

    #[test]
    fn v0199_sec_d10_special_ids_exempt_classes_and_cpu0_isolation() {
        let mut gate = storm_gate();
        // Special IDs 1020..1023 never take ordinary EOI or storm accounting,
        // even far beyond the threshold.
        for id in 1020..=1023u16 {
            for _ in 0..1200 {
                assert_eq!(
                    gate.deliver(IrqKind::VirtioSpi, id, 1, 50, false),
                    Ok(IrqDisposition::SpecialNoOrdinaryEoi)
                );
            }
            assert_eq!(gate.register(id, 1, 1, 1), Err(Error::Invalid));
        }
        // Timer/IPI/watchdog bypass the optional rate limit entirely.
        for kind in [IrqKind::Timer, IrqKind::Ipi, IrqKind::Watchdog] {
            for _ in 0..1200 {
                assert_eq!(
                    gate.deliver(kind, 40, 1, 50, false),
                    Ok(IrqDisposition::Exempt)
                );
            }
        }
        assert_eq!(gate.is_masked(40), Ok(false));
        // Ordinary SPI never delivers to CPU0, the fixed control CPU.
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 40, 0, 50, false),
            Err(Error::Unauthorized)
        );
        // Non-SPI numbers and unregistered sources fail closed.
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 31, 1, 50, false),
            Err(Error::Invalid)
        );
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 1024, 1, 50, false),
            Err(Error::Invalid)
        );
        assert_eq!(
            gate.deliver(IrqKind::VirtioSpi, 41, 1, 50, false),
            Err(Error::Stale)
        );
        assert_eq!(gate.register(31, 1, 1, 1), Err(Error::Invalid));
        assert_eq!(gate.register(41, 0, 1, 1), Err(Error::Invalid));
        // A second registered source keeps independent accounting.
        gate.register(41, 1, 1, 1).unwrap();
        for _ in 0..1000 {
            let _ = gate.deliver(IrqKind::VirtioSpi, 41, 2, 99, false);
        }
        assert_eq!(gate.is_masked(41), Ok(true));
        assert_eq!(gate.is_masked(40), Ok(false));
    }
}
