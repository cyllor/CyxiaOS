//! SEC-N03/04/06/08 bounded local-only TLS service admission.
//!
//! The authoritative native socket driver owns the source address and actual
//! DMA/egress-completion evidence. This bounded bookkeeper cannot fabricate
//! that evidence and never exposes a capability or mutating RPC operation.
//! The active token binds a *specific* verified rustls Session generation;
//! a same-IP reconnect or replayed TLS identity is not that session.
#![forbid(unsafe_code)]
use crate::tls::{EchoProof, Session};
pub const SOURCES: usize = 32;
pub const PENDING: usize = 4;
pub const ACTIVE: usize = 16;
const TOKEN: u64 = 1_000_000_000;
const BURST: u64 = 4 * TOKEN;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Capacity,
    RateLimited,
    Stale,
    Unauthenticated,
    Duplicate,
    Busy,
    Exhausted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingTicket {
    slot: u8,
    generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveTicket {
    slot: u8,
    generation: u64,
}
#[derive(Clone, Copy)]
struct Source {
    ip: u32,
    tokens: u64,
    last_ns: u64,
    last_seen: u64,
    pending: u8,
    active: u8,
}
#[derive(Clone, Copy)]
struct PendingEntry {
    generation: u64,
    ip: u32,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    Draining,
}
#[derive(Clone, Copy)]
struct ActiveEntry {
    generation: u64,
    ip: u32,
    proof: EchoProof,
    state: State,
    /// Exactly one TLS-owned plaintext reply may be outstanding per session.
    /// This is only the TLS queue stage; native NIC/DMA custody is separate.
    tls_egress_pending: bool,
}
/// No heap; full-table eviction requires a refilled, unreferenced LRU source.
/// The native producer must admit a pending slot
/// before creating an expensive TLS handshake and supply actual source IPv4,
/// clock and rate policy (never fields from peer plaintext or AI advice).
///
/// Designated sole authoritative production connection-credit ledger for
/// the single-machine native EL0 Echo service (six-tracks decision
/// "生产级接线门槛" in docs/implementation/v19-security-six-tracks.md,
/// 2026-11-25). The legacy kernel-core `security::network` host-contract
/// rate limiter stays a host-test model: never wire both ledgers on one
/// production connection. `finish_drain` retires credits only after the
/// trusted native adapter supplies real TCP/VirtIO/TLS completion evidence
/// (external entry: native_tcp::finish_session).
pub struct Admission {
    sources: [Option<Source>; SOURCES],
    pending: [Option<PendingEntry>; PENDING],
    active: [Option<ActiveEntry>; ACTIVE],
    sequence: u64,
    clock: u64,
    tokens: u64,
    rate: u16,
    restarting: bool,
}
impl Default for Admission {
    fn default() -> Self {
        Self::new()
    }
}
impl Admission {
    pub const fn new() -> Self {
        Self {
            sources: [None; SOURCES],
            pending: [None; PENDING],
            active: [None; ACTIVE],
            sequence: 0,
            clock: 0,
            tokens: BURST,
            rate: 16,
            restarting: false,
        }
    }
    fn refill(tokens: u64, elapsed_ns: u64, rate: u16) -> u64 {
        tokens
            .saturating_add(elapsed_ns.saturating_mul(u64::from(rate)))
            .min(BURST)
    }
    fn settle(&mut self, now_ns: u64, rate: u16) -> Result<(), Error> {
        if ![4, 8, 16, 32].contains(&rate) || now_ns < self.clock {
            return Err(Error::Invalid);
        }
        self.tokens = Self::refill(self.tokens, now_ns - self.clock, self.rate);
        self.clock = now_ns;
        if rate != self.rate {
            for source in self.sources.iter_mut().flatten() {
                source.tokens =
                    Self::refill(source.tokens, now_ns - source.last_ns, self.rate.min(8));
                source.last_ns = now_ns;
            }
            self.rate = rate;
        }
        Ok(())
    }
    fn can_evict(source: Source, now_ns: u64, rate: u16) -> bool {
        source.pending == 0
            && source.active == 0
            && now_ns >= source.last_ns
            && Self::refill(source.tokens, now_ns - source.last_ns, rate.min(8)) == BURST
    }
    fn source(&self, ip: u32) -> Result<usize, Error> {
        self.sources
            .iter()
            .position(|v| v.is_some_and(|s| s.ip == ip))
            .ok_or(Error::Stale)
    }
    fn pending_entry(&self, key: PendingTicket) -> Result<PendingEntry, Error> {
        let entry = self
            .pending
            .get(key.slot as usize)
            .and_then(|e| *e)
            .ok_or(Error::Stale)?;
        if entry.generation != key.generation {
            return Err(Error::Stale);
        }
        Ok(entry)
    }
    fn active_entry(&self, key: ActiveTicket) -> Result<ActiveEntry, Error> {
        let entry = self
            .active
            .get(key.slot as usize)
            .and_then(|e| *e)
            .ok_or(Error::Stale)?;
        if entry.generation != key.generation {
            return Err(Error::Stale);
        }
        Ok(entry)
    }
    pub fn pending_count(&self) -> usize {
        self.pending.iter().flatten().count()
    }
    pub fn active_count(&self) -> usize {
        self.active.iter().flatten().count()
    }
    pub const fn restarting(&self) -> bool {
        self.restarting
    }

    /// V0.19.9 post-cookie native admission; now_ns and rate are supplied by
    /// the trusted local clock/configuration, not the TLS peer.
    pub fn begin_ns(&mut self, ip: u32, now_ns: u64, rate: u16) -> Result<PendingTicket, Error> {
        if ip == 0 || ![4, 8, 16, 32].contains(&rate) || now_ns < self.clock {
            return Err(Error::Invalid);
        }
        if self.restarting {
            return Err(Error::Busy);
        }
        self.settle(now_ns, rate)?;
        let slot = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        if self.tokens < TOKEN {
            return Err(Error::RateLimited);
        }
        // A source table can have holes after eviction. Remember the
        // first vacant slot but keep searching for the existing IP.
        let mut vacant = None;
        let mut existing = None;
        for (i, source) in self.sources.iter().copied().enumerate() {
            match source {
                Some(s) if s.ip == ip => {
                    existing = Some((i, s));
                    break;
                }
                None if vacant.is_none() => vacant = Some(i),
                _ => {}
            }
        }
        let (source_at, current) = if let Some(pair) = existing {
            pair
        } else {
            let i = vacant
                .or_else(|| {
                    self.sources
                        .iter()
                        .enumerate()
                        .filter_map(|(i, row)| {
                            row.filter(|s| Self::can_evict(*s, now_ns, rate))
                                .map(|s| (i, s.last_seen))
                        })
                        .min_by_key(|&(i, last)| (last, i))
                        .map(|(i, _)| i)
                })
                .ok_or(Error::Capacity)?;
            (
                i,
                Source {
                    ip,
                    tokens: BURST,
                    last_ns: now_ns,
                    last_seen: now_ns,
                    pending: 0,
                    active: 0,
                },
            )
        };
        if current.pending != 0 {
            return Err(Error::Capacity);
        }
        let per = Self::refill(current.tokens, now_ns - current.last_ns, rate.min(8));
        if per < TOKEN {
            return Err(Error::RateLimited);
        }
        let generation = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        let key = PendingTicket {
            slot: u8::try_from(slot).map_err(|_| Error::Exhausted)?,
            generation,
        };
        // All checks complete: no partial token debit, evicted source, or
        // newly occupied slot on a refused admission.
        self.sequence = generation;
        self.tokens -= TOKEN;
        self.sources[source_at] = Some(Source {
            tokens: per - TOKEN,
            last_ns: now_ns,
            last_seen: now_ns,
            pending: 1,
            ..current
        });
        self.pending[slot] = Some(PendingEntry { generation, ip });
        Ok(key)
    }

    /// Integral-second compatibility for historical host fixtures.
    pub fn begin(&mut self, ip: u32, second: u64, rate: u16) -> Result<PendingTicket, Error> {
        self.begin_ns(ip, second.checked_mul(TOKEN).ok_or(Error::Invalid)?, rate)
    }

    /// End a failed/aborted handshake only for its original generation.
    pub fn reject(&mut self, ticket: PendingTicket) -> Result<(), Error> {
        let p = self.pending_entry(ticket)?;
        let at = self.source(p.ip)?;
        let mut source = self.sources[at].ok_or(Error::Stale)?;
        source.pending = source.pending.checked_sub(1).ok_or(Error::Stale)?;
        self.sources[at] = Some(source);
        self.pending[ticket.slot as usize] = None;
        Ok(())
    }
    /// Only a finished, pinned TLS 1.3 exchange on cyxia-echo/1 creates an
    /// active read-only admission. Invalid authentication/full quotas consume
    /// their pending lease; no "true" boolean or peer-provided proof exists.
    pub fn authenticate(
        &mut self,
        ticket: PendingTicket,
        tls: &Session<'_>,
    ) -> Result<ActiveTicket, Error> {
        let p = self.pending_entry(ticket)?;
        let Some(proof) = tls.local_echo_proof() else {
            self.reject(ticket)?;
            return Err(Error::Unauthenticated);
        };
        if self.restarting {
            self.reject(ticket)?;
            return Err(Error::Busy);
        }
        if self.active.iter().flatten().any(|row| row.proof == proof) {
            self.reject(ticket)?;
            return Err(Error::Duplicate);
        }
        let Some(slot) = self.active.iter().position(Option::is_none) else {
            self.reject(ticket)?;
            return Err(Error::Capacity);
        };
        let at = self.source(p.ip)?;
        let mut s = self.sources[at].ok_or(Error::Stale)?;
        let next = s.active.checked_add(1).ok_or(Error::Exhausted)?;
        s.pending = s.pending.checked_sub(1).ok_or(Error::Stale)?;
        s.active = next;
        self.sources[at] = Some(s);
        self.pending[ticket.slot as usize] = None;
        self.active[slot] = Some(ActiveEntry {
            generation: ticket.generation,
            ip: p.ip,
            proof,
            state: State::Open,
            tls_egress_pending: false,
        });
        Ok(ActiveTicket {
            slot: u8::try_from(slot).map_err(|_| Error::Exhausted)?,
            generation: ticket.generation,
        })
    }
    /// Consume real, authenticated TLS plaintext only. The caller supplies no
    /// alternate frame: this prevents a service-side bug from claiming plaintext
    /// it never received from this session. The reply is a *copy*; the caller
    /// still has to pass it through the same TLS Session for encryption.
    pub(crate) fn reply(
        &self,
        key: ActiveTicket,
        tls: &Session<'_>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let active = self.active_entry(key)?;
        if self.restarting || active.state != State::Open {
            return Err(Error::Busy);
        }
        if tls.local_echo_proof() != Some(active.proof) {
            return Err(Error::Unauthenticated);
        }
        let bytes = tls.plaintext();
        let length = crate::echo::next_frame_len(bytes)
            .map_err(|_| Error::Invalid)?
            .ok_or(Error::Busy)?;
        let request = tls
            .accept_local_echo(&bytes[..length])
            .map_err(|_| Error::Invalid)?;
        request.encode_reply(out).map_err(|_| Error::Invalid)
    }

    /// Authoritative application dispatch for the local read-only Echo path.
    /// Copy a *single complete* TLS-owned frame into a bounded response, then
    /// atomically queue it back onto the SAME pinned, negotiated TLS session.
    /// Incoming plaintext is consumed only after rustls accepted its reply.
    /// On WouldBlock, the original authenticated request remains untouched;
    /// the caller may retry after the preceding outbound TLS record drains.
    ///
    /// Success is only a plaintext enqueue, NOT network egress completion or
    /// DMA release. The native socket owner retains credits until real TX ACK.
    pub fn dispatch_echo(
        &mut self,
        key: ActiveTicket,
        tls: &mut Session<'_>,
    ) -> Result<usize, Error> {
        if self.active_entry(key)?.tls_egress_pending {
            return Err(Error::Busy);
        }
        let mut response = [0u8; crate::echo::MAX_FRAME];
        let encoded = self.reply(key, tls, &mut response)?;
        // A single authenticated TLS record may contain several Echo frames.
        // Consume exactly the first checked frame, retaining trailing bytes.
        let consumed = crate::echo::next_frame_len(tls.plaintext())
            .map_err(|_| Error::Invalid)?
            .ok_or(Error::Busy)?;
        match tls.send_plaintext(&response[..encoded]) {
            Ok(()) => {
                // The authenticated TLS-owned bytes are retained across any
                // transient send refusal and released only once encrypted
                // output is accepted into rustls' bounded outgoing buffer.
                tls.consume_plaintext(consumed)
                    .map_err(|_| Error::Invalid)?;
                self.active[key.slot as usize]
                    .as_mut()
                    .ok_or(Error::Stale)?
                    .tls_egress_pending = true;
                Ok(encoded)
            }
            Err(crate::tls::Error::WouldBlock) => Err(Error::Busy),
            Err(_) => Err(Error::Invalid),
        }
    }

    /// Called by the socket owner only after the same verified TLS session
    /// has encrypted its accepted reply and *all ciphertext* has been handed
    /// out of TLS's bounded buffer. This does NOT prove socket TX ACK or DMA
    /// completion: those retain independent native ownership records.
    /// A wrong/restarted TLS session cannot clear another connection's debt.
    pub fn confirm_tls_output_drained(
        &mut self,
        key: ActiveTicket,
        tls: &Session<'_>,
    ) -> Result<(), Error> {
        let row = self.active_entry(key)?;
        if !row.tls_egress_pending {
            return Err(Error::Stale);
        }
        if tls.local_echo_proof() != Some(row.proof) {
            return Err(Error::Unauthenticated);
        }
        if tls.has_pending_plaintext() || !tls.pending_tls().is_empty() {
            return Err(Error::Busy);
        }
        self.active[key.slot as usize]
            .as_mut()
            .ok_or(Error::Stale)?
            .tls_egress_pending = false;
        Ok(())
    }

    /// Verify the exact still-live session identity before any normal
    /// network-credit retirement. Peer identity alone is not connection ID.
    pub(crate) fn verify_session(&self, key: ActiveTicket, tls: &Session<'_>) -> Result<(), Error> {
        let row = self.active_entry(key)?;
        if tls.local_echo_proof() != Some(row.proof) {
            return Err(Error::Unauthenticated);
        }
        Ok(())
    }
    /// Stops admitting new work on this connection but retains active credit.
    pub fn begin_drain(&mut self, key: ActiveTicket) -> Result<(), Error> {
        let row = self
            .active
            .get_mut(key.slot as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::Stale)?;
        if row.generation != key.generation {
            return Err(Error::Stale);
        }
        row.state = State::Draining;
        Ok(())
    }
    /// Caller must be the trusted native adapter AFTER actual TCP/TLS TX,
    /// NIC descriptor, DMA and completion references are reconciled. This
    /// method retires only logical credits; it proves no hardware drain.
    /// Internal final accounting only. External native users must call
    /// native_tcp::finish_session after authoritative TLS/TCP/VirtIO checks.
    pub(crate) fn finish_drain(&mut self, key: ActiveTicket) -> Result<(), Error> {
        let row = self.active_entry(key)?;
        if row.state != State::Draining || row.tls_egress_pending {
            return Err(Error::Busy);
        }
        let at = self.source(row.ip)?;
        let mut source = self.sources[at].ok_or(Error::Stale)?;
        source.active = source.active.checked_sub(1).ok_or(Error::Stale)?;
        self.sources[at] = Some(source);
        self.active[key.slot as usize] = None;
        Ok(())
    }
    /// Stop new TLS and Echo admission; preserve every outstanding token,
    /// including unknown completions, across service restart.
    pub fn begin_restart(&mut self) {
        self.restarting = true;
        for row in self.active.iter_mut().flatten() {
            row.state = State::Draining;
        }
    }
    pub fn finish_restart(&mut self) -> Result<(), Error> {
        if self.pending_count() != 0 || self.active_count() != 0 {
            return Err(Error::Busy);
        }
        // Keep source limits and monotonic serials: a service restart cannot
        // replenish exhausted bursts or reuse stale receipt generations.
        self.restarting = false;
        Ok(())
    }
    pub fn evict_idle_ns(&mut self, ip: u32, now_ns: u64) -> Result<(), Error> {
        let rate = self.rate;
        self.settle(now_ns, rate)?;
        let at = self.source(ip)?;
        let source = self.sources[at].ok_or(Error::Stale)?;
        if !Self::can_evict(source, now_ns, rate) {
            return Err(Error::Busy);
        }
        self.sources[at] = None;
        Ok(())
    }
    pub fn evict_idle(&mut self, ip: u32, second: u64) -> Result<(), Error> {
        self.evict_idle_ns(ip, second.checked_mul(TOKEN).ok_or(Error::Invalid)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wave4_source_lookup_does_not_replace_existing_ip_after_a_hole() {
        let mut gate = Admission::new();
        let first = gate.begin(1, 0, 4).unwrap();
        gate.reject(first).unwrap();
        let second = gate.begin(2, 0, 4).unwrap();
        gate.evict_idle(1, 1).unwrap();
        assert_eq!(gate.begin(2, 1, 4), Err(Error::Capacity));
        assert_eq!(gate.pending_count(), 1);
        gate.reject(second).unwrap();
        let second = gate.begin(2, 1, 4).unwrap();
        let third = gate.begin(3, 1, 4).unwrap();
        assert_eq!(gate.pending_count(), 2);
        gate.reject(second).unwrap();
        gate.reject(third).unwrap();
        assert_eq!(gate.pending_count(), 0);
    }

    #[test]
    fn sec_n03_four_pending_slots_are_bounded_and_released_on_reject() {
        let mut admission = Admission::new();
        let mut keys = [None; PENDING];
        for (i, key) in keys.iter_mut().enumerate() {
            *key = Some(admission.begin(i as u32 + 1, 0, 16).unwrap());
        }
        assert_eq!(admission.pending_count(), PENDING);
        assert_eq!(admission.begin(8, 0, 16), Err(Error::Capacity));
        admission.reject(keys[0].unwrap()).unwrap();
        assert_eq!(admission.pending_count(), PENDING - 1);
        assert_eq!(admission.begin(8, 1, 16).is_ok(), true);
        assert_eq!(admission.pending_count(), PENDING);
    }
    #[test]
    fn sec_n04_aba_replayed_handshake_ticket_cannot_reclaim_new_slot() {
        let mut admission = Admission::new();
        let old = admission.begin(7, 0, 4).unwrap();
        admission.reject(old).unwrap();
        let new = admission.begin(7, 1, 4).unwrap();
        assert_ne!(old, new);
        assert_eq!(admission.reject(old), Err(Error::Stale));
        assert_eq!(admission.pending_count(), 1);
        admission.reject(new).unwrap();
        assert_eq!(admission.pending_count(), 0);
    }
    #[test]
    fn sec_n04_full_source_table_evicts_only_eligible_lru() {
        let mut admission = Admission::new();
        for ip in 1..=SOURCES as u32 {
            let key = admission.begin(ip, u64::from(ip), 16).unwrap();
            admission.reject(key).unwrap();
        }
        let new = admission.begin(33, 33, 16).unwrap();
        assert_eq!(admission.source(1), Err(Error::Stale));
        assert!(admission.source(2).is_ok());
        assert_eq!(admission.sources.iter().flatten().count(), SOURCES);
        admission.reject(new).unwrap();
    }
    #[test]
    fn sec_n04_eviction_advances_global_clock_and_blocks_rewind() {
        let mut gate = Admission::new();
        let ticket = gate.begin(7, 1, 4).unwrap();
        gate.reject(ticket).unwrap();
        gate.evict_idle(7, 10).unwrap();
        assert_eq!(gate.begin(7, 2, 4), Err(Error::Invalid));
        let fresh = gate.begin(7, 10, 4).unwrap();
        gate.reject(fresh).unwrap();
    }
    #[test]
    fn v0199_ns_admission_preserves_rate_debt_and_rejects_duplicate_pending() {
        let mut gate = Admission::new();
        let first = gate.begin_ns(1, 0, 4).unwrap();
        assert_eq!(gate.begin_ns(1, 0, 4), Err(Error::Capacity));
        gate.reject(first).unwrap();
        for ip in 2..=4 {
            let t = gate.begin_ns(ip, 0, 4).unwrap();
            gate.reject(t).unwrap();
        }
        for ip in 5..=40 {
            assert_eq!(gate.begin_ns(ip, 0, 4), Err(Error::RateLimited));
        }
        assert_eq!(gate.sources.iter().flatten().count(), 4);
        assert_eq!(gate.begin_ns(41, 125_000_000, 32), Err(Error::RateLimited));
        let t = gate.begin_ns(41, 140_625_000, 32).unwrap();
        gate.reject(t).unwrap();
        assert_eq!(gate.begin_ns(42, 140_624_999, 32), Err(Error::Invalid));
    }
    #[test]
    fn v0199_eviction_does_not_discard_global_refill() {
        let mut gate = Admission::new();
        for ip in 1..=4 {
            let t = gate.begin_ns(ip, 0, 4).unwrap();
            gate.reject(t).unwrap();
        }
        gate.evict_idle_ns(1, 250_000_000).unwrap();
        let t = gate.begin_ns(5, 250_000_000, 4).unwrap();
        gate.reject(t).unwrap();
        assert_eq!(gate.begin_ns(6, 250_000_000, 4), Err(Error::RateLimited));
    }
    #[test]
    fn sec_n08_restart_never_drops_unknown_pending_or_resets_tokens() {
        let mut admission = Admission::new();
        let mut keys = [None; PENDING];
        for (i, key) in keys.iter_mut().enumerate() {
            *key = Some(admission.begin(i as u32 + 1, 0, 4).unwrap());
            assert_eq!(admission.pending_count(), i + 1);
        }
        admission.begin_restart();
        assert!(admission.restarting());
        assert_eq!(admission.begin(8, 1, 4), Err(Error::Busy));
        assert_eq!(admission.finish_restart(), Err(Error::Busy));
        for key in keys.into_iter().flatten() {
            admission.reject(key).unwrap();
        }
        admission.finish_restart().unwrap();
        // The burst was already exhausted before restart.
        assert_eq!(admission.begin(7, 0, 4), Err(Error::RateLimited));
        let new = admission.begin(7, 1, 4).unwrap();
        admission.reject(new).unwrap();
    }
}
