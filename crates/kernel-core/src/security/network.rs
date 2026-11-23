//! SEC-N: bounded native TCP/TLS service admission and exact read-only echo.
//! Cryptographic verification remains the responsibility of the real TLS
//! engine; a wire message cannot manufacture VerifiedTls.
use super::Error;

pub const MAX_SOURCES: usize = 32;
pub const MAX_PENDING: u8 = 4;
pub const MAX_ACTIVE: u8 = 16;
pub const MAX_ECHO: usize = 4096;
pub const TLS13: u16 = 0x0304;
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedTls {
    peer_pin: [u8; 32],
    version: u16,
    suite: u16,
    early_data: bool,
    resumed: bool,
}
impl VerifiedTls {
    /// Must be called only by the native TLS verifier after validating the
    /// actual transcript, peer signature, key exchange and pinned certificate.
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_native_tls(
        peer_pin: [u8; 32], version: u16, suite: u16,
        early_data: bool, resumed: bool,
    ) -> Self {
        Self { peer_pin, version, suite, early_data, resumed }
    }
    pub fn read_only_echo(self, pinned_peer: &[u8;32]) -> Result<ReadOnlyEcho, Error> {
        if self.peer_pin != *pinned_peer
            || self.version != TLS13
            || self.suite != TLS_AES_128_GCM_SHA256
            || self.early_data || self.resumed
        {
            return Err(Error::Unauthorized);
        }
        Ok(ReadOnlyEcho { _private: () })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyEcho { _private: () }
pub struct EchoRequest<'a> {
    pub request_id: u64,
    pub payload: &'a [u8],
}
pub fn parse_read_only_echo<'a>(
    _: ReadOnlyEcho, packet: &'a [u8],
) -> Result<EchoRequest<'a>, Error> {
    if packet.len() < 16 { return Err(Error::Invalid); }
    let version = u16::from_le_bytes([packet[0],packet[1]]);
    let opcode = u16::from_le_bytes([packet[2],packet[3]]);
    let length = u32::from_le_bytes([packet[4],packet[5],packet[6],packet[7]]);
    if version != 1 || opcode != 1 || length > MAX_ECHO as u32 {
        return Err(Error::Invalid);
    }
    let total = 16usize.checked_add(length as usize).ok_or(Error::Invalid)?;
    if packet.len() != total { return Err(Error::Invalid); }
    let request_id = u64::from_le_bytes(packet[8..16].try_into().map_err(|_| Error::Invalid)?);
    Ok(EchoRequest { request_id, payload: &packet[16..] })
}
#[derive(Clone, Copy, Debug)]
struct Source {
    ip: u32,
    tokens: u8,
    last_second: u64,
    last_request: u64,
    inflight: u8,
    active: u8, // successful sessions are still owned by this source
}
pub struct RateLimiter {
    sources: [Option<Source>; MAX_SOURCES],
    global_tokens: u8,
    global_second: u64,
    pending: u8,
    active: u8,
}
impl Default for RateLimiter { fn default() -> Self { Self::new() } }
impl RateLimiter {
    pub const fn new() -> Self {
        Self {
            sources: [None; MAX_SOURCES], global_tokens: 4,
            global_second: 0, pending: 0, active: 0,
        }
    }
    fn refill(tokens: u8, elapsed: u64, rate: u16) -> u8 {
        (u64::from(tokens).saturating_add(elapsed.saturating_mul(rate as u64))).min(4) as u8
    }
    pub fn request_handshake(&mut self, ip: u32, second: u64, rate: u16) -> Result<(), Error> {
        if ![4,8,16,32].contains(&rate) || second < self.global_second {
            return Err(Error::Invalid);
        }
        if self.pending >= MAX_PENDING { return Err(Error::Capacity); }
        let at = if let Some(index) = self.sources.iter().position(|r| r.is_some_and(|r| r.ip == ip)) {
            index
        } else {
            self.sources.iter().position(Option::is_none).ok_or(Error::Capacity)?
        };
        let current = self.sources[at].unwrap_or(Source {
            ip, tokens: 4, last_second: second, last_request: second, inflight: 0, active: 0,
        });
        if second < current.last_second { return Err(Error::Invalid); }
        let global = Self::refill(self.global_tokens, second - self.global_second, rate);
        let per = Self::refill(current.tokens, second - current.last_second, rate.min(8));
        self.global_tokens = global;
        self.global_second = second;
        self.sources[at] = Some(Source {
            tokens: per, last_second: second, last_request: second, ..current
        });
        if global == 0 || per == 0 { return Err(Error::Capacity); }
        let source = self.sources[at].as_mut().ok_or(Error::Invalid)?;
        source.tokens -= 1;
        source.inflight = source.inflight.checked_add(1).ok_or(Error::Exhausted)?;
        self.global_tokens -= 1;
        self.pending += 1;
        Ok(())
    }
    pub fn finish_handshake(&mut self, ip: u32, success: bool) -> Result<(), Error> {
        // Caller supplies the independently authenticated source from the
        // native TCP endpoint, NEVER a source claimed in TLS plaintext.
        let source = self.sources.iter_mut().flatten().find(|s| s.ip == ip)
            .ok_or(Error::Stale)?;
        if source.inflight == 0 || self.pending == 0 { return Err(Error::Stale); }
        // A completed rejected/full handshake no longer owns a pending slot;
        // it must never take a free active slot or silently leave a stale
        // pending credit behind. Native caller closes any unadmitted TLS.
        source.inflight -= 1;
        self.pending -= 1;
        if success {
            if self.active >= MAX_ACTIVE { return Err(Error::Capacity); }
            source.active = source.active.checked_add(1).ok_or(Error::Exhausted)?;
            self.active += 1;
        }
        Ok(())
    }
    /// Reclaim only a genuinely closed session of this authenticated source.
    /// Generic "close one" APIs let one failed peer steal another peer's
    /// active capacity. This caller remains trusted by the native endpoint.
    pub fn close_active_from(&mut self, ip: u32) -> Result<(), Error> {
        let source = self.sources.iter_mut().flatten().find(|s| s.ip == ip)
            .ok_or(Error::Stale)?;
        if source.active == 0 || self.active == 0 { return Err(Error::Stale); }
        source.active -= 1;
        self.active -= 1;
        Ok(())
    }
    /// Source entries are never evicted while an allowance is owed or a
    /// handshake is still live. Eviction cannot reset an exhausted burst.
    pub fn evict_idle(&mut self, ip: u32, second: u64) -> Result<(), Error> {
        let slot = self.sources.iter_mut().find(|r| r.is_some_and(|r| r.ip == ip))
            .ok_or(Error::Stale)?;
        let entry = slot.as_ref().ok_or(Error::Stale)?;
        if second < entry.last_request.saturating_add(1)
            || second < entry.last_second
            || entry.inflight != 0
            || entry.active != 0
            || Self::refill(entry.tokens, second - entry.last_second, 8) != 4
        {
            return Err(Error::Busy);
        }
        *slot = None;
        Ok(())
    }
    pub const fn pending(&self) -> u8 { self.pending }
    pub const fn active(&self) -> u8 { self.active }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proof() -> VerifiedTls {
        VerifiedTls::from_native_tls([3;32], TLS13, TLS_AES_128_GCM_SHA256, false, false)
    }
    fn cap() -> ReadOnlyEcho { proof().read_only_echo(&[3;32]).unwrap() }
    fn packet(payload: &[u8]) -> [u8; 20] {
        let mut bytes = [0u8;20];
        bytes[0..2].copy_from_slice(&1u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[8..16].copy_from_slice(&7u64.to_le_bytes());
        bytes[16..16+payload.len()].copy_from_slice(payload);
        bytes
    }
    #[test] fn sec_n01_wrong_pin_or_suite_refuses_service() {
        assert_eq!(proof().read_only_echo(&[4;32]), Err(Error::Unauthorized));
        let bad = VerifiedTls::from_native_tls([3;32], 0x0303, TLS_AES_128_GCM_SHA256, false, false);
        assert_eq!(bad.read_only_echo(&[3;32]), Err(Error::Unauthorized));
    }
    #[test] fn sec_n02_early_data_and_resumption_refused() {
        for (early,resumed) in [(true,false),(false,true)] {
            let bad = VerifiedTls::from_native_tls([3;32], TLS13, TLS_AES_128_GCM_SHA256, early, resumed);
            assert_eq!(bad.read_only_echo(&[3;32]), Err(Error::Unauthorized));
        }
    }
    #[test] fn sec_n03_handshake_capacity_not_unbounded() {
        let mut limiter=RateLimiter::new();
        for i in 0..4 { limiter.request_handshake(i,0,16).unwrap(); }
        assert_eq!(limiter.pending(),4);
        assert_eq!(limiter.request_handshake(5,0,16),Err(Error::Capacity));
    }
    #[test] fn sec_n04_burst_not_reset_by_repeating_source() {
        let mut limiter=RateLimiter::new();
        for _ in 0..4 {
            limiter.request_handshake(1,0,16).unwrap();
            limiter.finish_handshake(1,false).unwrap();
        }
        assert_eq!(limiter.request_handshake(1,0,16),Err(Error::Capacity));
        assert_eq!(limiter.evict_idle(1,0),Err(Error::Busy));
    }
    #[test] fn sec_n05_echo_rejects_tail_or_opcode() {
        let mut bytes = packet(&[1,2,3,4]);
        assert_eq!(parse_read_only_echo(cap(),&bytes).unwrap().payload,&[1,2,3,4]);
        bytes[2]=2;
        assert!(matches!(parse_read_only_echo(cap(),&bytes),Err(Error::Invalid)));
        bytes[2]=1;
        assert!(matches!(parse_read_only_echo(cap(),&bytes[..19]),Err(Error::Invalid)));
    }
    #[test] fn sec_n06_service_right_is_read_only_by_construction() {
        let bytes = packet(&[1,2,3,4]);
        let request=parse_read_only_echo(cap(),&bytes).unwrap();
        assert_eq!(request.request_id,7);
    }
    #[test] fn sec_n07_oversized_payload_is_rejected_pre_dispatch() {
        let mut bytes = [0u8;16];
        bytes[0]=1; bytes[2]=1; bytes[4..8].copy_from_slice(&4097u32.to_le_bytes());
        assert!(matches!(parse_read_only_echo(cap(),&bytes),Err(Error::Invalid)));
    }
    #[test] fn v019_sec_n03_full_active_pool_releases_new_failed_handshake() {
        let mut limiter = RateLimiter::new();
        for ip in 1..=16 {
            limiter.request_handshake(ip, u64::from(ip), 16).unwrap();
            limiter.finish_handshake(ip, true).unwrap();
        }
        assert_eq!(limiter.active(), 16);
        assert_eq!(limiter.pending(), 0);
        limiter.request_handshake(17, 17, 16).unwrap();
        assert_eq!(limiter.pending(), 1);
        assert_eq!(limiter.finish_handshake(17, true), Err(Error::Capacity));
        assert_eq!(limiter.active(), 16);
        assert_eq!(limiter.pending(), 0);
        assert_eq!(limiter.close_active_from(17), Err(Error::Stale));
    }
    #[test] fn v019_sec_n04_one_source_cannot_steal_other_active_credit() {
        let mut limiter = RateLimiter::new();
        limiter.request_handshake(7, 0, 4).unwrap();
        limiter.finish_handshake(7, true).unwrap();
        assert_eq!(limiter.active(), 1);
        assert_eq!(limiter.close_active_from(8), Err(Error::Stale));
        assert_eq!(limiter.active(), 1);
        limiter.close_active_from(7).unwrap();
        assert_eq!(limiter.active(), 0);
        assert_eq!(limiter.close_active_from(7), Err(Error::Stale));
    }
    #[test] fn v019_sec_n04_connected_source_is_never_evicted_or_replenished_by_forgetting() {
        let mut limiter = RateLimiter::new();
        limiter.request_handshake(7, 0, 4).unwrap();
        limiter.finish_handshake(7, true).unwrap();
        assert_eq!(limiter.evict_idle(7, 10), Err(Error::Busy));
        limiter.close_active_from(7).unwrap();
        limiter.evict_idle(7, 10).unwrap();
        assert_eq!(limiter.active(), 0);
    }
    #[test] fn sec_n08_no_model_is_needed_for_rate_limit_and_echo() {
        let mut limiter = RateLimiter::new();
        limiter.request_handshake(7,0,4).unwrap();
        limiter.finish_handshake(7,true).unwrap();
        assert_eq!(limiter.active(),1);
        limiter.close_active_from(7).unwrap();
        assert_eq!(limiter.active(),0);
    }
}
