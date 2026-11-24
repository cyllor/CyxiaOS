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
    tokens: u8,
    last_sec: u64,
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
enum State { Open, Draining }
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
/// No heap or implicit eviction. The native producer must admit a pending slot
/// before creating an expensive TLS handshake and supply actual source IPv4,
/// clock and rate policy (never fields from peer plaintext or AI advice).
pub struct Admission {
    sources: [Option<Source>; SOURCES],
    pending: [Option<PendingEntry>; PENDING],
    active: [Option<ActiveEntry>; ACTIVE],
    sequence: u64,
    clock: u64,
    tokens: u8,
    restarting: bool,
}
impl Default for Admission { fn default() -> Self { Self::new() } }
impl Admission {
    pub const fn new() -> Self {
        Self {
            sources: [None; SOURCES],
            pending: [None; PENDING],
            active: [None; ACTIVE],
            sequence: 0, clock: 0, tokens: 4, restarting: false,
        }
    }
    fn refill(tokens: u8, seconds: u64, rate: u16) -> u8 {
        u64::from(tokens)
            .saturating_add(seconds.saturating_mul(u64::from(rate)))
            .min(4) as u8
    }
    fn source(&self, ip: u32) -> Result<usize, Error> {
        self.sources.iter().position(|v| v.is_some_and(|s| s.ip == ip))
            .ok_or(Error::Stale)
    }
    fn pending_entry(&self, key: PendingTicket) -> Result<PendingEntry, Error> {
        let entry=self.pending.get(key.slot as usize).and_then(|e| *e).ok_or(Error::Stale)?;
        if entry.generation != key.generation { return Err(Error::Stale); }
        Ok(entry)
    }
    fn active_entry(&self, key: ActiveTicket) -> Result<ActiveEntry, Error> {
        let entry=self.active.get(key.slot as usize).and_then(|e| *e).ok_or(Error::Stale)?;
        if entry.generation != key.generation { return Err(Error::Stale); }
        Ok(entry)
    }
    pub fn pending_count(&self) -> usize { self.pending.iter().flatten().count() }
    pub fn active_count(&self) -> usize { self.active.iter().flatten().count() }
    pub const fn restarting(&self) -> bool { self.restarting }

    pub fn begin(&mut self, ip: u32, second: u64, rate: u16) -> Result<PendingTicket, Error> {
        if ip == 0 || ![4, 8, 16, 32].contains(&rate) || second < self.clock {
            return Err(Error::Invalid);
        }
        if self.restarting { return Err(Error::Busy); }
        let slot=self.pending.iter().position(Option::is_none).ok_or(Error::Capacity)?;
        let source_at=if let Some(i)=self.sources.iter().position(|s| s.is_some_and(|s| s.ip == ip)) {
            i
        } else {
            self.sources.iter().position(Option::is_none).ok_or(Error::Capacity)?
        };
        let current=self.sources[source_at].unwrap_or(Source {
            ip, tokens:4, last_sec:second, last_seen:second, pending:0, active:0
        });
        if second < current.last_sec { return Err(Error::Invalid); }
        let global=Self::refill(self.tokens,second-self.clock,rate);
        let per=Self::refill(current.tokens,second-current.last_sec,rate.min(8));
        if global == 0 || per == 0 { return Err(Error::RateLimited); }
        let generation=self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        let pending=current.pending.checked_add(1).ok_or(Error::Exhausted)?;
        let key=PendingTicket {slot:u8::try_from(slot).map_err(|_|Error::Exhausted)?,generation};
        self.sequence=generation;
        self.clock=second;
        self.tokens=global-1;
        self.sources[source_at]=Some(Source{
            tokens:per-1, last_sec:second, last_seen:second, pending, ..current
        });
        self.pending[slot]=Some(PendingEntry{generation,ip});
        Ok(key)
    }

    /// End a failed/aborted handshake only for its original generation.
    pub fn reject(&mut self, ticket: PendingTicket) -> Result<(), Error> {
        let p=self.pending_entry(ticket)?;
        let at=self.source(p.ip)?;
        let mut source=self.sources[at].ok_or(Error::Stale)?;
        source.pending=source.pending.checked_sub(1).ok_or(Error::Stale)?;
        self.sources[at]=Some(source);
        self.pending[ticket.slot as usize]=None;
        Ok(())
    }
    /// Only a finished, pinned TLS 1.3 exchange on cyxia-echo/1 creates an
    /// active read-only admission. Invalid authentication/full quotas consume
    /// their pending lease; no "true" boolean or peer-provided proof exists.
    pub fn authenticate(
        &mut self, ticket: PendingTicket, tls: &Session<'_>,
    ) -> Result<ActiveTicket, Error> {
        let p=self.pending_entry(ticket)?;
        let Some(proof)=tls.local_echo_proof() else {
            self.reject(ticket)?;
            return Err(Error::Unauthenticated);
        };
        if self.restarting {
            self.reject(ticket)?;
            return Err(Error::Busy);
        }
        if self.active.iter().flatten().any(|row|row.proof==proof) {
            self.reject(ticket)?;
            return Err(Error::Duplicate);
        }
        let Some(slot)=self.active.iter().position(Option::is_none) else {
            self.reject(ticket)?;
            return Err(Error::Capacity);
        };
        let at=self.source(p.ip)?;
        let mut s=self.sources[at].ok_or(Error::Stale)?;
        let next=s.active.checked_add(1).ok_or(Error::Exhausted)?;
        s.pending=s.pending.checked_sub(1).ok_or(Error::Stale)?;
        s.active=next;
        self.sources[at]=Some(s);
        self.pending[ticket.slot as usize]=None;
        self.active[slot]=Some(ActiveEntry{
            generation:ticket.generation,ip:p.ip,proof,state:State::Open,
            tls_egress_pending:false,
        });
        Ok(ActiveTicket{slot:u8::try_from(slot).map_err(|_|Error::Exhausted)?,generation:ticket.generation})
    }
    /// Consume real, authenticated TLS plaintext only. The caller supplies no
    /// alternate frame: this prevents a service-side bug from claiming plaintext
    /// it never received from this session. The reply is a *copy*; the caller
    /// still has to pass it through the same TLS Session for encryption.
    pub(crate) fn reply(
        &self, key: ActiveTicket, tls: &Session<'_>, out: &mut [u8],
    ) -> Result<usize, Error> {
        let active=self.active_entry(key)?;
        if self.restarting || active.state!=State::Open {
            return Err(Error::Busy);
        }
        if tls.local_echo_proof() != Some(active.proof) {
            return Err(Error::Unauthenticated);
        }
        let bytes=tls.plaintext();
        let length=crate::echo::next_frame_len(bytes)
            .map_err(|_|Error::Invalid)?.ok_or(Error::Busy)?;
        let request=tls.accept_local_echo(&bytes[..length])
            .map_err(|_|Error::Invalid)?;
        request.encode_reply(out).map_err(|_|Error::Invalid)
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
        &mut self, key: ActiveTicket, tls: &mut Session<'_>,
    ) -> Result<usize, Error> {
        if self.active_entry(key)?.tls_egress_pending {
            return Err(Error::Busy);
        }
        let mut response = [0u8; crate::echo::MAX_FRAME];
        let encoded = self.reply(key, tls, &mut response)?;
        // A single authenticated TLS record may contain several Echo frames.
        // Consume exactly the first checked frame, retaining trailing bytes.
        let consumed=crate::echo::next_frame_len(tls.plaintext())
            .map_err(|_| Error::Invalid)?.ok_or(Error::Busy)?;
        match tls.send_plaintext(&response[..encoded]) {
            Ok(()) => {
                // The authenticated TLS-owned bytes are retained across any
                // transient send refusal and released only once encrypted
                // output is accepted into rustls' bounded outgoing buffer.
                tls.consume_plaintext(consumed).map_err(|_| Error::Invalid)?;
                self.active[key.slot as usize]
                    .as_mut().ok_or(Error::Stale)?.tls_egress_pending=true;
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
        &mut self, key: ActiveTicket, tls: &Session<'_>,
    ) -> Result<(), Error> {
        let row=self.active_entry(key)?;
        if !row.tls_egress_pending {return Err(Error::Stale);}
        if tls.local_echo_proof()!=Some(row.proof) {
            return Err(Error::Unauthenticated);
        }
        if tls.has_pending_plaintext() || !tls.pending_tls().is_empty() {
            return Err(Error::Busy);
        }
        self.active[key.slot as usize].as_mut()
            .ok_or(Error::Stale)?.tls_egress_pending=false;
        Ok(())
    }

    /// Stops admitting new work on this connection but retains active credit.
    pub fn begin_drain(&mut self, key: ActiveTicket) -> Result<(), Error> {
        let row=self.active.get_mut(key.slot as usize)
            .and_then(Option::as_mut).ok_or(Error::Stale)?;
        if row.generation!=key.generation { return Err(Error::Stale); }
        row.state=State::Draining;
        Ok(())
    }
    /// Caller must be the trusted native adapter AFTER actual TCP/TLS TX,
    /// NIC descriptor, DMA and completion references are reconciled. This
    /// method retires only logical credits; it proves no hardware drain.
    pub fn finish_drain(&mut self, key: ActiveTicket) -> Result<(), Error> {
        let row=self.active_entry(key)?;
        if row.state!=State::Draining || row.tls_egress_pending {
            return Err(Error::Busy);
        }
        let at=self.source(row.ip)?;
        let mut source=self.sources[at].ok_or(Error::Stale)?;
        source.active=source.active.checked_sub(1).ok_or(Error::Stale)?;
        self.sources[at]=Some(source);
        self.active[key.slot as usize]=None;
        Ok(())
    }
    /// Stop new TLS and Echo admission; preserve every outstanding token,
    /// including unknown completions, across service restart.
    pub fn begin_restart(&mut self) {
        self.restarting=true;
        for row in self.active.iter_mut().flatten() {
            row.state=State::Draining;
        }
    }
    pub fn finish_restart(&mut self) -> Result<(), Error> {
        if self.pending_count()!=0 || self.active_count()!=0 {
            return Err(Error::Busy);
        }
        // Keep source limits and monotonic serials: a service restart cannot
        // replenish exhausted bursts or reuse stale receipt generations.
        self.restarting=false;
        Ok(())
    }
    pub fn evict_idle(&mut self, ip: u32, second: u64) -> Result<(), Error> {
        let at=self.source(ip)?;
        let s=self.sources[at].ok_or(Error::Stale)?;
        if second < self.clock || second < s.last_sec.saturating_add(1)
            || second < s.last_seen.saturating_add(1)
            || s.pending!=0 || s.active!=0
            || Self::refill(s.tokens,second-s.last_sec,8)!=4
        {
            return Err(Error::Busy);
        }
        self.sources[at]=None;
        // Successful expiry is itself a trusted monotonic-clock observation.
        // A later request cannot rewind to an older instant to mint a fresh
        // four-token burst after eviction.
        self.clock=second;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sec_n03_four_pending_slots_are_bounded_and_released_on_reject() {
        let mut admission=Admission::new();
        let mut keys=[None;PENDING];
        for (i,key) in keys.iter_mut().enumerate() {
            *key=Some(admission.begin(i as u32+1,0,16).unwrap());
        }
        assert_eq!(admission.pending_count(),PENDING);
        assert_eq!(admission.begin(8,0,16),Err(Error::Capacity));
        admission.reject(keys[0].unwrap()).unwrap();
        assert_eq!(admission.pending_count(),PENDING-1);
        assert_eq!(admission.begin(8,1,16).is_ok(),true);
        assert_eq!(admission.pending_count(),PENDING);
    }
    #[test]
    fn sec_n04_aba_replayed_handshake_ticket_cannot_reclaim_new_slot() {
        let mut admission=Admission::new();
        let old=admission.begin(7,0,4).unwrap();
        admission.reject(old).unwrap();
        let new=admission.begin(7,1,4).unwrap();
        assert_ne!(old,new);
        assert_eq!(admission.reject(old),Err(Error::Stale));
        assert_eq!(admission.pending_count(),1);
        admission.reject(new).unwrap();
        assert_eq!(admission.pending_count(),0);
    }
    #[test]
    fn sec_n04_full_source_table_rejects_new_ip_without_eviction() {
        let mut admission=Admission::new();
        for ip in 1..=SOURCES as u32 {
            let key=admission.begin(ip,u64::from(ip),16).unwrap();
            admission.reject(key).unwrap();
        }
        assert_eq!(admission.begin(33,33,16),Err(Error::Capacity));
        admission.evict_idle(1,33).unwrap();
        let new=admission.begin(33,33,16).unwrap();
        admission.reject(new).unwrap();
    }
    #[test]
    fn sec_n04_eviction_advances_global_clock_and_blocks_rewind() {
        let mut gate=Admission::new();
        let ticket=gate.begin(7,1,4).unwrap();
        gate.reject(ticket).unwrap();
        gate.evict_idle(7,10).unwrap();
        assert_eq!(gate.begin(7,2,4),Err(Error::Invalid));
        let fresh=gate.begin(7,10,4).unwrap();
        gate.reject(fresh).unwrap();
    }
    #[test]
    fn sec_n08_restart_never_drops_unknown_pending_or_resets_tokens() {
        let mut admission=Admission::new();
        let mut keys=[None;PENDING];
        for (i,key) in keys.iter_mut().enumerate() {
            *key=Some(admission.begin(7,0,4).unwrap());
            assert_eq!(admission.pending_count(),i+1);
        }
        admission.begin_restart();
        assert!(admission.restarting());
        assert_eq!(admission.begin(8,1,4),Err(Error::Busy));
        assert_eq!(admission.finish_restart(),Err(Error::Busy));
        for key in keys.into_iter().flatten() {
            admission.reject(key).unwrap();
        }
        admission.finish_restart().unwrap();
        // The burst was already exhausted before restart.
        assert_eq!(admission.begin(7,0,4),Err(Error::RateLimited));
        let new=admission.begin(7,1,4).unwrap();
        admission.reject(new).unwrap();
    }
}
