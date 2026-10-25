#![no_std]
//! Canonical, independently authenticated kernel billing envelopes. TLS is a
//! carrier only; possession of its identity cannot authenticate CPU evidence.
use cyxia_prototype::{domains::ObjectKey, learning::{Family, ReplayGroup, capture::RunKey,
    reward::{CpuClass, CpuCoverage, CpuInterval, OBSERVATION_NS}}};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
mod failure;
pub use failure::{Failure, FailedPublication, RootFailure, FAILURE_BYTES, ROOT_FAILURE_BYTES, ROOT_FAILURE_PACKET_BYTES};

pub const PACKET_BYTES: usize = 2048;
pub const HEADER_BYTES: usize = 132;
pub const SIGNATURE_BYTES: usize = 64;
pub const INTERVAL_BYTES: usize = 52;
pub const CHUNK_INTERVALS: usize = 16;
pub const MAX_INTERVALS: usize = 4096;
pub const HELLO: u16 = 1;
pub const FREEZE: u16 = 2;
pub const FROZEN: u16 = 3;
pub const START: u16 = 4;
pub const STARTED: u16 = 5;
pub const CLOSE: u16 = 6;
pub const TRACE: u16 = 7;
pub const SEALED: u16 = 8;
pub const RELEASE: u16 = 9;
pub const RELEASED: u16 = 10;
pub const ACK: u16 = 11;
pub const WORK: u16 = 12;
pub const WORK_RESULT: u16 = 13;
pub const DECLINED: u16 = 14;
pub const OBSERVING: u16 = 15;
pub const TASK_BIND: u16 = 16;
pub const EXCLUDED: u16 = 17;
pub const ABORT_PREPARED: u16 = 18;
pub const PREPARED_ABORTED: u16 = 19;
pub const ROOT_FAILED: u16 = 20;
pub const PREPARATION_SEAL_BYTES: usize = BINDING_BYTES + 8 + 32 + 32 + FAILURE_BYTES;
pub const PREPARATION_PACKET_BYTES: usize = HEADER_BYTES + PREPARATION_SEAL_BYTES + SIGNATURE_BYTES;
pub const SEALED_PACKET_BYTES: usize = HEADER_BYTES + SEAL_BYTES + SIGNATURE_BYTES;
pub const EXCLUDED_PACKET_BYTES: usize = HEADER_BYTES + EXCLUDED_BYTES + SIGNATURE_BYTES;
const MAGIC: &[u8; 8] = b"CXBILL1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Format, Identity, Signature, Stale, Conflict, Capacity, Incomplete, Timing }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint { pub node: [u8; 32], pub boot: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header { pub kind: u16, pub sequence: u64, pub source: Endpoint,
    pub destination: Endpoint, pub session: [u8; 32] }
pub struct Packet<'a> { pub header: Header, pub body: &'a [u8] }

pub struct Keys { signer: SigningKey, peer: VerifyingKey }
impl Keys {
    pub fn new(seed: &[u8; 32], public: &[u8; 32], peer: &[u8; 32]) -> Result<Self, Error> {
        let signer = SigningKey::from_bytes(seed);
        if signer.verifying_key().to_bytes() != *public || public == peer { return Err(Error::Identity); }
        let peer = VerifyingKey::from_bytes(peer).map_err(|_| Error::Identity)?;
        if peer.is_weak() { return Err(Error::Identity); }
        Ok(Self { signer, peer })
    }
    pub fn encode(&self, header: Header, body: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let end = HEADER_BYTES.checked_add(body.len()).ok_or(Error::Capacity)?;
        let size = end.checked_add(SIGNATURE_BYTES).ok_or(Error::Capacity)?;
        if size > PACKET_BYTES || size > output.len() { return Err(Error::Capacity); }
        validate_header(header)?;
        let mut w = Writer::new(&mut output[..end]);
        w.bytes(MAGIC)?; w.u16(header.kind)?; w.u16(body.len() as u16)?; w.u64(header.sequence)?;
        w.bytes(&header.source.node)?; w.bytes(&header.destination.node)?;
        w.u64(header.source.boot)?; w.u64(header.destination.boot)?; w.bytes(&header.session)?;
        w.bytes(body)?;
        let signature = self.signer.sign(&output[..end]).to_bytes();
        output[end..size].copy_from_slice(&signature);
        Ok(size)
    }
    pub fn decode<'a>(&self, bytes: &'a [u8], source_node: [u8; 32], destination: Endpoint,
        session: Option<[u8; 32]>) -> Result<Packet<'a>, Error> {
        if !(HEADER_BYTES + SIGNATURE_BYTES..=PACKET_BYTES).contains(&bytes.len()) { return Err(Error::Format); }
        let end = bytes.len() - SIGNATURE_BYTES;
        let signature = Signature::from_slice(&bytes[end..]).map_err(|_| Error::Format)?;
        self.peer.verify_strict(&bytes[..end], &signature).map_err(|_| Error::Signature)?;
        let mut r = Reader::new(&bytes[..end]);
        if r.take(8)? != MAGIC { return Err(Error::Format); }
        let kind = r.u16()?; let length = usize::from(r.u16()?); let sequence = r.u64()?;
        let source = r.array()?; let target = r.array()?; let source_boot = r.u64()?; let target_boot = r.u64()?;
        let header = Header { kind, sequence, source: Endpoint { node: source, boot: source_boot },
            destination: Endpoint { node: target, boot: target_boot }, session: r.array()? };
        validate_header(header)?;
        if source != source_node || header.destination.node != destination.node
            || (kind != HELLO && header.destination.boot != destination.boot)
            || (kind == HELLO && ![0, destination.boot].contains(&target_boot))
            || session.is_some_and(|s| s != header.session) { return Err(Error::Identity); }
        let body = r.take(length)?; r.end()?;
        Ok(Packet { header, body })
    }
}
fn validate_header(h: Header) -> Result<(), Error> {
    if !(HELLO..=ROOT_FAILED).contains(&h.kind) || h.sequence == 0 || h.source.boot == 0
        || (h.kind != HELLO && (h.destination.boot == 0 || h.session == [0; 32]))
        || h.source.node == [0; 32] || h.destination.node == [0; 32] || h.source.node == h.destination.node {
        return Err(Error::Identity);
    }
    Ok(())
}

/// Retained logical operations outlive a TLS/billing session. Only the
/// authenticated peer boot can reset the receive cursor, and never while an
/// older boot still has unsettled obligations.
#[derive(Clone, Copy)]
pub struct ReceiveCursor { boot: u64, last: u64, digest: [u8; 32] }
impl ReceiveCursor {
    pub const fn new() -> Self { Self { boot: 0, last: 0, digest: [0; 32] } }
    pub fn rebind(&mut self, boot: u64, unsettled: bool) -> Result<(), Error> {
        if boot == 0 || self.boot != 0 && self.boot != boot && unsettled { return Err(Error::Stale); }
        if self.boot != boot { self.boot = boot; self.last = 0; self.digest = [0; 32]; }
        Ok(())
    }
    fn digest(packet: &Packet<'_>) -> [u8; 32] {
        let mut h = Sha256::new(); h.update(packet.header.kind.to_le_bytes()); h.update(packet.body); h.finalize().into()
    }
    /// False means an already accepted operation; the caller may re-ACK it
    /// without repeating any state mutation or importing a raw chunk twice.
    pub fn fresh(&self, packet: &Packet<'_>) -> Result<bool, Error> {
        if packet.header.source.boot != self.boot || packet.header.sequence == 0 { return Err(Error::Stale); }
        if packet.header.sequence <= self.last {
            if packet.header.sequence == self.last && Self::digest(packet) != self.digest { return Err(Error::Conflict); }
            return Ok(false);
        }
        Ok(true)
    }
    pub fn accepted(&mut self, packet: &Packet<'_>) -> Result<(), Error> {
        if !self.fresh(packet)? { return Ok(()); }
        self.last = packet.header.sequence; self.digest = Self::digest(packet); Ok(())
    }
}
impl Default for ReceiveCursor { fn default() -> Self { Self::new() } }

/// Both producers decide before reserving a local root. Once either local
/// owner has accepted FROZEN, cancellation is forbidden; retained obligations
/// can only use the normal closing/release protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arbitration { Accept, YieldUnstarted, Decline }
pub fn arbitrate(local: [u8; 32], peer: [u8; 32], local_pending: bool,
    local_frozen: bool, participant_busy: bool) -> Arbitration {
    if participant_busy || local_frozen { Arbitration::Decline }
    else if !local_pending { Arbitration::Accept }
    else if local > peer { Arbitration::YieldUnstarted }
    else { Arbitration::Decline }
}

/// The origin's immutable trial and the partner's exact protected owner. The
/// same TLS connection or the same seed alone never authorizes another trial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub origin: Endpoint, pub participant: Endpoint, pub session: [u8; 32],
    pub run: RunKey, pub family: Family, pub baseline: bool,
    pub owner: ObjectKey, pub target: ObjectKey, pub group: ReplayGroup,
    pub frozen_scope_hash: [u8; 32],
}
pub const BINDING_BYTES: usize = 284;
impl Binding {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.validate()?;
        let mut w = Writer::new(out);
        w.bytes(&self.origin.node)?; w.u64(self.origin.boot)?;
        w.bytes(&self.participant.node)?; w.u64(self.participant.boot)?; w.bytes(&self.session)?;
        w.u64(self.run.boot_epoch)?; w.u64(self.run.trial_id)?; w.u64(self.run.generation)?;
        w.u16(self.family.domain)?; w.u16(self.family.kind)?; w.u64(u64::from(self.baseline))?;
        for key in [self.owner, self.target] { w.u64(key.id)?; w.u64(key.generation)?; }
        w.u64(self.group.seed)?; w.bytes(&self.group.workload)?; w.bytes(&self.group.initial_image)?;
        w.bytes(&self.frozen_scope_hash)?;
        Ok(w.at)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let origin = Endpoint { node: r.array()?, boot: r.u64()? };
        let participant = Endpoint { node: r.array()?, boot: r.u64()? };
        let session = r.array()?;
        let run = RunKey { boot_epoch: r.u64()?, trial_id: r.u64()?, generation: r.u64()? };
        let family = Family { domain: r.u16()?, kind: r.u16()? };
        let baseline = match r.u64()? { 0 => false, 1 => true, _ => return Err(Error::Format) };
        let owner = ObjectKey { id: r.u64()?, generation: r.u64()? };
        let target = ObjectKey { id: r.u64()?, generation: r.u64()? };
        let group = ReplayGroup { seed: r.u64()?, workload: r.array()?, initial_image: r.array()? };
        let value = Self { origin, participant, session, run, family, baseline, owner, target, group,
            frozen_scope_hash: r.array()? };
        r.end()?; value.validate()?; Ok(value)
    }
    pub fn validate(self) -> Result<(), Error> {
        self.family.index().map_err(|_| Error::Format)?;
        if self.origin.node == [0; 32] || self.participant.node == [0; 32] || self.origin.node == self.participant.node
            || self.origin.boot == 0 || self.participant.boot == 0 || self.run.boot_epoch != self.origin.boot
            || self.run.trial_id == 0 || self.run.generation == 0 || self.owner.id == 0 || self.owner.generation == 0
            || self.target.id == 0 || self.target.generation == 0 || self.session == [0; 32]
            || self.group.workload == [0; 32] || self.group.initial_image == [0; 32]
            || self.frozen_scope_hash == [0; 32] { return Err(Error::Identity); }
        Ok(())
    }
    pub fn hash(self) -> Result<[u8; 32], Error> {
        let mut bytes = [0; BINDING_BYTES]; let n = self.encode(&mut bytes)?;
        Ok(Sha256::digest(&bytes[..n]).into())
    }
}

/// Cancellation is limited to a not-yet-started reservation or a fully sealed
/// baseline hold. Open execution/custody never becomes cancellable by timeout.
pub fn preparation_cancellable(started: bool, sealed_hold: bool, open_credits: usize, unsettled_work: bool) -> bool {
    (!started || sealed_hold) && open_credits == 0 && !unsettled_work
}
/// A capture binding may be installed locally before START is issued. The
/// participant still owns the original FREEZE binding until START, so only
/// that retained identity can cancel its reservation. An acknowledged START
/// without STARTED remains an issued operation and is never cancellable here.
pub fn preparation_abort_binding(reserved: Binding, active: Binding,
    bound_run: Option<RunKey>, permitted_run: Option<RunKey>, start_issued: bool,
    started: bool) -> Result<Binding, Error> {
    reserved.validate()?; active.validate()?;
    if start_issued || started { return Err(Error::Incomplete); }
    if let Some(run) = bound_run {
        if permitted_run != Some(run) || active.run != run
            || (Binding { run: active.run, frozen_scope_hash: active.frozen_scope_hash, ..reserved }) != active {
            return Err(Error::Conflict);
        }
    } else if active != reserved { return Err(Error::Conflict); }
    Ok(reserved)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparationSeal {
    pub binding: Binding, pub drained_ns: u64, pub frozen_other_domains: [u8; 32], pub prior_sealed_binding: [u8; 32],
    pub failure: Option<Failure>,
}
impl PreparationSeal {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.drained_ns == 0 || out.len() < PREPARATION_SEAL_BYTES { return Err(Error::Format); }
        self.binding.encode(&mut out[..BINDING_BYTES])?;
        let mut w = Writer::new(&mut out[BINDING_BYTES..]);
        w.u64(self.drained_ns)?; w.bytes(&self.frozen_other_domains)?; w.bytes(&self.prior_sealed_binding)?;
        if self.failure.is_some_and(|f| f.observed_ns > self.drained_ns
            || f.publication.is_some_and(|p| p.id.boot_epoch != self.binding.participant.boot)) { return Err(Error::Timing); }
        Failure::encode_optional(self.failure, &mut out[PREPARATION_SEAL_BYTES - FAILURE_BYTES..PREPARATION_SEAL_BYTES])?;
        Ok(PREPARATION_SEAL_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let legacy = PREPARATION_SEAL_BYTES - FAILURE_BYTES;
        if bytes.len() != PREPARATION_SEAL_BYTES && bytes.len() != legacy { return Err(Error::Format); }
        let binding = Binding::decode(&bytes[..BINDING_BYTES])?; let mut r = Reader::new(&bytes[BINDING_BYTES..legacy]);
        let value = Self { binding, drained_ns: r.u64()?, frozen_other_domains: r.array()?, prior_sealed_binding: r.array()?,
            failure: if bytes.len() == legacy { None } else { Failure::decode_optional(&bytes[legacy..])? } };
        r.end()?; if value.drained_ns == 0 || value.failure.is_some_and(|f| f.observed_ns > value.drained_ns
            || f.publication.is_some_and(|p| p.id.boot_epoch != binding.participant.boot)) { return Err(Error::Timing); } Ok(value)
    }
}

pub fn encode_interval(value: CpuInterval, out: &mut [u8]) -> Result<(), Error> {
    if value.node == [0; 32] || value.core >= 64 || value.start_ns >= value.end_ns { return Err(Error::Timing); }
    let mut w = Writer::new(out); w.bytes(&value.node)?; w.u16(value.core)?;
    w.u16(value.class as u16)?; w.u64(value.start_ns)?; w.u64(value.end_ns)?;
    Ok(())
}
pub fn decode_interval(bytes: &[u8]) -> Result<CpuInterval, Error> {
    let mut r = Reader::new(bytes); let node = r.array()?; let core = r.u16()?;
    let class = match r.u16()? { 0 => CpuClass::Policy, 1 => CpuClass::ExecutorAction,
        2 => CpuClass::ExecutorWork, 3 => CpuClass::Optional, _ => return Err(Error::Format) };
    let value = CpuInterval { node, core, class, start_ns: r.u64()?, end_ns: r.u64()? }; r.end()?;
    let mut checked = [0; INTERVAL_BYTES]; encode_interval(value, &mut checked)?; Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceSeal {
    pub binding_hash: [u8; 32], pub owner: ObjectKey, pub coverage: CpuCoverage,
    pub count: u64, pub intervals_hash: [u8; 32], pub frozen_other_domains: [u8; 32],
    pub missing_events: u64, pub ordinary_warmup_ns: u64, pub later_workload_ns: u64,
}
pub const SEAL_BYTES: usize = 224;
impl TraceSeal {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.validate()?;
        self.encode_summary(out)
    }
    fn encode_summary(self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out); w.bytes(&self.binding_hash)?;
        w.u64(self.owner.id)?; w.u64(self.owner.generation)?; w.bytes(&self.coverage.node)?;
        for v in [self.coverage.first_ns, self.coverage.observation_ns, self.coverage.observation_end_ns,
            self.coverage.closing_ns, self.coverage.required as u64, self.coverage.reported as u64,
            self.count] { w.u64(v)?; }
        w.bytes(&self.intervals_hash)?; w.bytes(&self.frozen_other_domains)?;
        for v in [self.missing_events, self.ordinary_warmup_ns, self.later_workload_ns] { w.u64(v)?; }
        Ok(w.at)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = Self::decode_summary(bytes)?; value.validate()?; Ok(value)
    }
    fn decode_summary(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes); let binding_hash = r.array()?;
        let owner = ObjectKey { id: r.u64()?, generation: r.u64()? }; let node = r.array()?;
        let coverage = CpuCoverage { node, first_ns: r.u64()?, observation_ns: r.u64()?,
            observation_end_ns: r.u64()?, closing_ns: r.u64()?,
            required: u8::try_from(r.u64()?).map_err(|_| Error::Format)?,
            reported: u8::try_from(r.u64()?).map_err(|_| Error::Format)? };
        let value = Self { binding_hash, owner, coverage, count: r.u64()?, intervals_hash: r.array()?,
            frozen_other_domains: r.array()?, missing_events: r.u64()?, ordinary_warmup_ns: r.u64()?, later_workload_ns: r.u64()? };
        r.end()?; Ok(value)
    }
    pub fn validate(self) -> Result<(), Error> {
        let c = self.coverage;
        if self.binding_hash == [0; 32] || self.owner.id == 0 || self.owner.generation == 0 || c.node == [0; 32]
            || c.observation_ns.checked_sub(c.first_ns).is_none()
            || c.observation_end_ns.checked_sub(c.observation_ns) != Some(OBSERVATION_NS)
            || c.closing_ns < c.observation_end_ns || c.closing_ns - c.observation_end_ns > 5_000_000_000
            || c.required != 3 || c.reported != c.required || self.count > MAX_INTERVALS as u64
            || self.missing_events != 0 || self.frozen_other_domains == [0; 32] { return Err(Error::Incomplete); }
        Ok(())
    }
}

pub const MISSING_EVENTS: u64 = 1;
pub const LATE_CLOSING: u64 = 2;
pub const ROOT_FAULT: u64 = 4;
pub const EXCLUDED_BYTES: usize = SEAL_BYTES + 16 + FAILURE_BYTES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exclusion { pub reasons: u64, pub drained_ns: u64, pub failure: Option<Failure> }
/// A signed, physically drained negative terminal is archival evidence only.
/// Its summary cannot pass TraceSeal::validate or authorize a reward sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExcludedSeal { pub trace: TraceSeal, pub exclusion: Exclusion }
impl ExcludedSeal {
    pub fn validate(self) -> Result<(), Error> {
        let s = self.trace; let c = s.coverage;
        let reasons = if s.missing_events != 0 { MISSING_EVENTS } else { 0 }
            | if c.closing_ns.saturating_sub(c.observation_end_ns) > 5_000_000_000 { LATE_CLOSING } else { 0 }
            | if self.exclusion.failure.is_some() { ROOT_FAULT } else { 0 };
        if let Some(f) = self.exclusion.failure { f.validate()?;
            if f.observed_ns > self.exclusion.drained_ns { return Err(Error::Timing); } }
        if reasons == 0 || self.exclusion.reasons != reasons || self.exclusion.drained_ns != c.closing_ns
            || c.closing_ns == 0 || s.binding_hash == [0; 32] || s.owner.id == 0 || s.owner.generation == 0
            || c.node == [0; 32] || c.first_ns > c.observation_ns
            || c.observation_end_ns.checked_sub(c.observation_ns) != Some(OBSERVATION_NS)
            || c.closing_ns < c.observation_end_ns || c.required != 3 || c.reported != 0
            || s.count > MAX_INTERVALS as u64 || s.frozen_other_domains == [0; 32] { return Err(Error::Incomplete); }
        Ok(())
    }
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.validate()?;
        if out.len() < EXCLUDED_BYTES { return Err(Error::Capacity); }
        self.trace.encode_summary(&mut out[..SEAL_BYTES])?;
        let mut w = Writer::new(&mut out[SEAL_BYTES..]);
        w.u64(self.exclusion.reasons)?; w.u64(self.exclusion.drained_ns)?;
        Failure::encode_optional(self.exclusion.failure, &mut out[SEAL_BYTES + 16..EXCLUDED_BYTES])?;
        Ok(EXCLUDED_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != EXCLUDED_BYTES && bytes.len() != SEAL_BYTES + 16 { return Err(Error::Format); }
        let trace = TraceSeal::decode_summary(&bytes[..SEAL_BYTES])?;
        let mut r = Reader::new(&bytes[SEAL_BYTES..SEAL_BYTES + 16]);
        let value = Self { trace, exclusion: Exclusion { reasons: r.u64()?, drained_ns: r.u64()?,
            failure: if bytes.len() == SEAL_BYTES + 16 { None } else { Failure::decode_optional(&bytes[SEAL_BYTES + 16..])? } } };
        r.end()?; value.validate()?; Ok(value)
    }
}

/// Incremental verification of ordered raw records. A signature over a count
/// or summary is insufficient: all original records must reach this verifier.
pub struct Assembler { binding: Binding, count: usize, hash: Sha256, sealed: Option<TraceSeal>, excluded: Option<ExcludedSeal>,
    first: [u64; 2], last: [u64; 2] }
impl Assembler {
    pub fn new(binding: Binding) -> Result<Self, Error> { binding.validate()?;
        let mut hash = Sha256::new(); hash.update(b"CYXIA_KERNEL_CPU_TRACE_1.3\0");
        Ok(Self { binding, count: 0, hash, sealed: None, excluded: None, first: [u64::MAX; 2], last: [0; 2] }) }
    pub fn append(&mut self, offset: usize, values: &[CpuInterval]) -> Result<(), Error> {
        if self.sealed.is_some() || self.excluded.is_some() || offset != self.count { return Err(Error::Stale); }
        if values.is_empty() || values.len() > CHUNK_INTERVALS || self.count + values.len() > MAX_INTERVALS { return Err(Error::Capacity); }
        // Validate the entire piece before changing the digest or count.
        let mut bytes = [0; INTERVAL_BYTES * CHUNK_INTERVALS];
        for (i, value) in values.iter().copied().enumerate() {
            if value.node != self.binding.participant.node || value.class == CpuClass::Optional { return Err(Error::Identity); }
            encode_interval(value, &mut bytes[i * INTERVAL_BYTES..(i + 1) * INTERVAL_BYTES])?;
        }
        for value in values {
            let class = usize::from(value.class == CpuClass::ExecutorWork);
            self.first[class] = self.first[class].min(value.start_ns); self.last[class] = self.last[class].max(value.end_ns);
        }
        self.hash.update(&bytes[..values.len() * INTERVAL_BYTES]); self.count += values.len(); Ok(())
    }
    pub fn finish(&mut self, seal: TraceSeal) -> Result<(), Error> {
        seal.validate()?;
        if self.excluded.is_some() { return Err(Error::Conflict); }
        self.verify_summary(seal)?;
        if self.sealed.is_some_and(|old| old != seal) { return Err(Error::Conflict); }
        self.sealed = Some(seal); Ok(())
    }
    pub fn finish_excluded(&mut self, excluded: ExcludedSeal) -> Result<(), Error> {
        excluded.validate()?;
        if excluded.exclusion.failure.is_some_and(|f| f.publication.is_some_and(|p|
            p.id.boot_epoch != self.binding.participant.boot)) { return Err(Error::Identity); }
        if self.sealed.is_some() || self.excluded.is_some_and(|old| old != excluded) { return Err(Error::Conflict); }
        self.verify_summary(excluded.trace)?; self.excluded = Some(excluded); Ok(())
    }
    fn verify_summary(&self, seal: TraceSeal) -> Result<(), Error> {
        if seal.binding_hash != self.binding.hash()? || seal.owner != self.binding.owner
            || seal.coverage.node != self.binding.participant.node || seal.count != self.count as u64
            || seal.intervals_hash != <[u8; 32]>::from(self.hash.clone().finalize()) { return Err(Error::Incomplete); }
        for (class, (first, last)) in [(seal.coverage.first_ns, seal.coverage.closing_ns),
            (seal.coverage.observation_ns, seal.coverage.observation_end_ns)].into_iter().enumerate() {
            if self.first[class] != u64::MAX && (self.first[class] < first || self.last[class] > last) { return Err(Error::Timing); }
        }
        Ok(())
    }
    pub fn sealed(&self) -> Option<TraceSeal> { self.sealed }
    pub fn excluded(&self) -> Option<ExcludedSeal> { self.excluded }
    pub fn count(&self) -> usize { self.count }
}

pub struct Writer<'a> { bytes: &'a mut [u8], pub at: usize }
impl<'a> Writer<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self { Self { bytes, at: 0 } }
    pub fn bytes(&mut self, data: &[u8]) -> Result<(), Error> { let end = self.at.checked_add(data.len()).ok_or(Error::Capacity)?;
        self.bytes.get_mut(self.at..end).ok_or(Error::Capacity)?.copy_from_slice(data); self.at = end; Ok(()) }
    pub fn u16(&mut self, value: u16) -> Result<(), Error> { self.bytes(&value.to_le_bytes()) }
    pub fn u64(&mut self, value: u64) -> Result<(), Error> { self.bytes(&value.to_le_bytes()) }
}
pub struct Reader<'a> { bytes: &'a [u8], pub at: usize }
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self { Self { bytes, at: 0 } }
    pub fn take(&mut self, size: usize) -> Result<&'a [u8], Error> { let end = self.at.checked_add(size).ok_or(Error::Format)?;
        let out = self.bytes.get(self.at..end).ok_or(Error::Format)?; self.at = end; Ok(out) }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> { self.take(N)?.try_into().map_err(|_| Error::Format) }
    pub fn u16(&mut self) -> Result<u16, Error> { Ok(u16::from_le_bytes(self.array()?)) }
    pub fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.array()?)) }
    pub fn end(&self) -> Result<(), Error> { if self.at == self.bytes.len() { Ok(()) } else { Err(Error::Format) } }
}
