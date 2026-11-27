//! SEC-N: bounded native TCP/TLS service admission and exact read-only echo.
//! Cryptographic verification remains the responsibility of the real TLS
//! engine; a wire message cannot manufacture VerifiedTls.
use super::{Error, durable_role_epoch_v0199::ConfirmedBootPolicy};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub mod deployment;
pub mod entropy;
pub mod tls_deadline;
mod tls_packages;

pub const MAX_SOURCES: usize = 32;
pub const MAX_PENDING: u8 = 4;
pub const MAX_ACTIVE: u8 = 16;
pub const MAX_ECHO: usize = 4096;
const TOKEN: u64 = 1_000_000_000;
const BURST: u64 = 4 * TOKEN;
pub const TLS13: u16 = 0x0304;
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;

/// Generations and key catalogue pinned by the owner of the installed TLS
/// Verifier and Signer. The state must come from the confirmed boot pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsInstallation {
    pub verifier_generation: u64,
    pub signer_generation: u64,
    pub key_generation: u64,
    pub key_manifest_hash: [u8; 32],
}

/// Installed TLS identities bound to the live owner of the confirmed signed
/// startup pair. Keeping this witness also retains the immutable epoch borrow.
#[derive(Clone, Copy)]
pub struct ConfirmedTlsBoot<'a> {
    policy: ConfirmedBootPolicy<'a>,
    installation: TlsInstallation,
}

impl ConfirmedTlsBoot<'_> {
    pub fn boot_epoch(&self) -> u64 {
        self.policy.boot_epoch()
    }

    pub fn installation(&self) -> TlsInstallation {
        self.installation
    }
}

impl TlsInstallation {
    pub fn authorize<'a>(
        self,
        policy: ConfirmedBootPolicy<'a>,
    ) -> Result<ConfirmedTlsBoot<'a>, Error> {
        policy.verify_tls_installation(&self)?;
        Ok(ConfirmedTlsBoot {
            policy,
            installation: self,
        })
    }
}

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
        peer_pin: [u8; 32],
        version: u16,
        suite: u16,
        early_data: bool,
        resumed: bool,
    ) -> Self {
        Self {
            peer_pin,
            version,
            suite,
            early_data,
            resumed,
        }
    }
    pub fn read_only_echo(self, pinned_peer: &[u8; 32]) -> Result<ReadOnlyEcho, Error> {
        if self.peer_pin != *pinned_peer
            || self.version != TLS13
            || self.suite != TLS_AES_128_GCM_SHA256
            || self.early_data
            || self.resumed
        {
            return Err(Error::Unauthorized);
        }
        Ok(ReadOnlyEcho { _private: () })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyEcho {
    _private: (),
}
pub struct EchoRequest<'a> {
    pub request_id: u64,
    pub payload: &'a [u8],
}
pub fn parse_read_only_echo<'a>(
    _: ReadOnlyEcho,
    packet: &'a [u8],
) -> Result<EchoRequest<'a>, Error> {
    if packet.len() < 16 {
        return Err(Error::Invalid);
    }
    let version = u16::from_le_bytes([packet[0], packet[1]]);
    let opcode = u16::from_le_bytes([packet[2], packet[3]]);
    let length = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
    if version != 1 || opcode != 1 || length > MAX_ECHO as u32 {
        return Err(Error::Invalid);
    }
    let total = 16usize.checked_add(length as usize).ok_or(Error::Invalid)?;
    if packet.len() != total {
        return Err(Error::Invalid);
    }
    let request_id = u64::from_le_bytes(packet[8..16].try_into().map_err(|_| Error::Invalid)?);
    Ok(EchoRequest {
        request_id,
        payload: &packet[16..],
    })
}
#[derive(Clone, Copy, Debug)]
struct Source {
    ip: u32,
    tokens: u64,
    last_ns: u64,
    last_request: u64,
    inflight: u8,
    active: u8, // successful sessions are still owned by this source
}
/// Legacy host-contract rate limiter (V0.19 single-domain host model).
/// This is NOT the production admission ledger. Single-machine native EL0
/// network services must use `cyxia_net_transport::admission::Admission`
/// as the sole authoritative connection-credit ledger (32 sources,
/// 4 pending, 16 active, bound to the verified TLS session generation).
/// Decision: docs/implementation/v19-security-six-tracks.md,
/// "生产级接线门槛". Never wire both ledgers on one production connection;
/// dual credit accounting on the same session is forbidden.
pub struct RateLimiter {
    sources: [Option<Source>; MAX_SOURCES],
    global_tokens: u64,
    global_ns: u64,
    rate: u16,
    pending: u8,
    active: u8,
}
impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
impl RateLimiter {
    pub const fn new() -> Self {
        Self {
            sources: [None; MAX_SOURCES],
            global_tokens: BURST,
            global_ns: 0,
            rate: 16,
            pending: 0,
            active: 0,
        }
    }
    fn refill(tokens: u64, elapsed_ns: u64, rate: u16) -> u64 {
        tokens
            .saturating_add(elapsed_ns.saturating_mul(u64::from(rate)))
            .min(BURST)
    }
    /// The caller supplies the protected configured rate, never a peer/model
    /// field. Settle old rates before any change, without replenishing bursts.
    fn settle(&mut self, now_ns: u64, rate: u16) -> Result<(), Error> {
        if ![4, 8, 16, 32].contains(&rate) || now_ns < self.global_ns {
            return Err(Error::Invalid);
        }
        self.global_tokens = Self::refill(self.global_tokens, now_ns - self.global_ns, self.rate);
        self.global_ns = now_ns;
        if rate != self.rate {
            for entry in self.sources.iter_mut().flatten() {
                entry.tokens = Self::refill(entry.tokens, now_ns - entry.last_ns, self.rate.min(8));
                entry.last_ns = now_ns;
            }
            self.rate = rate;
        }
        Ok(())
    }
    fn can_evict(entry: Source, now_ns: u64, rate: u16) -> bool {
        entry.inflight == 0
            && entry.active == 0
            && now_ns >= entry.last_ns
            && Self::refill(entry.tokens, now_ns - entry.last_ns, rate.min(8)) == BURST
    }
    /// V0.19.9 protected post-cookie admission. All capacity/debt checks run
    /// before either token is debited or a new source is published.
    pub fn request_handshake_ns(&mut self, ip: u32, now_ns: u64, rate: u16) -> Result<(), Error> {
        if ip == 0 {
            return Err(Error::Invalid);
        }
        self.settle(now_ns, rate)?;
        if self.pending >= MAX_PENDING || self.global_tokens < TOKEN {
            return Err(Error::Capacity);
        }
        let (at, current) = if let Some(at) = self
            .sources
            .iter()
            .position(|r| r.is_some_and(|r| r.ip == ip))
        {
            (at, self.sources[at].ok_or(Error::Stale)?)
        } else {
            let at = self
                .sources
                .iter()
                .position(Option::is_none)
                .or_else(|| {
                    self.sources
                        .iter()
                        .enumerate()
                        .filter_map(|(at, row)| {
                            row.filter(|entry| Self::can_evict(*entry, now_ns, rate))
                                .map(|entry| (at, entry.last_request))
                        })
                        .min_by_key(|&(at, last)| (last, at))
                        .map(|(at, _)| at)
                })
                .ok_or(Error::Capacity)?;
            (
                at,
                Source {
                    ip,
                    tokens: BURST,
                    last_ns: now_ns,
                    last_request: now_ns,
                    inflight: 0,
                    active: 0,
                },
            )
        };
        if current.inflight != 0 {
            return Err(Error::Capacity);
        }
        let per = Self::refill(current.tokens, now_ns - current.last_ns, rate.min(8));
        if per < TOKEN {
            return Err(Error::Capacity);
        }
        self.sources[at] = Some(Source {
            tokens: per - TOKEN,
            last_ns: now_ns,
            last_request: now_ns,
            inflight: 1,
            ..current
        });
        self.global_tokens -= TOKEN;
        self.pending += 1;
        Ok(())
    }
    /// Compatibility for historical host fixtures taking integral seconds.
    /// Native V0.19.9 adapters must use the monotonic nanosecond entry above.
    pub fn request_handshake(&mut self, ip: u32, second: u64, rate: u16) -> Result<(), Error> {
        self.request_handshake_ns(ip, second.checked_mul(TOKEN).ok_or(Error::Invalid)?, rate)
    }
    pub fn finish_handshake(&mut self, ip: u32, success: bool) -> Result<(), Error> {
        // Caller supplies the independently authenticated source from the
        // native TCP endpoint, NEVER a source claimed in TLS plaintext.
        let source = self
            .sources
            .iter_mut()
            .flatten()
            .find(|s| s.ip == ip)
            .ok_or(Error::Stale)?;
        if source.inflight == 0 || self.pending == 0 {
            return Err(Error::Stale);
        }
        // A completed rejected/full handshake no longer owns a pending slot;
        // it must never take a free active slot or silently leave a stale
        // pending credit behind. Native caller closes any unadmitted TLS.
        source.inflight -= 1;
        self.pending -= 1;
        if success {
            if self.active >= MAX_ACTIVE {
                return Err(Error::Capacity);
            }
            source.active = source.active.checked_add(1).ok_or(Error::Exhausted)?;
            self.active += 1;
        }
        Ok(())
    }
    /// Reclaim only a genuinely closed session of this authenticated source.
    /// Generic "close one" APIs let one failed peer steal another peer's
    /// active capacity. This caller remains trusted by the native endpoint.
    pub fn close_active_from(&mut self, ip: u32) -> Result<(), Error> {
        let source = self
            .sources
            .iter_mut()
            .flatten()
            .find(|s| s.ip == ip)
            .ok_or(Error::Stale)?;
        if source.active == 0 || self.active == 0 {
            return Err(Error::Stale);
        }
        source.active -= 1;
        self.active -= 1;
        Ok(())
    }
    /// Source entries are never evicted while an allowance is owed or a
    /// handshake is still live. Eviction cannot reset an exhausted burst.
    pub fn evict_idle_ns(&mut self, ip: u32, now_ns: u64) -> Result<(), Error> {
        let rate = self.rate;
        self.settle(now_ns, rate)?;
        let slot = self
            .sources
            .iter_mut()
            .find(|r| r.is_some_and(|r| r.ip == ip))
            .ok_or(Error::Stale)?;
        let entry = slot.as_ref().ok_or(Error::Stale)?;
        if entry.active != 0 || !Self::can_evict(*entry, now_ns, rate) {
            return Err(Error::Busy);
        }
        *slot = None;
        Ok(())
    }
    pub fn evict_idle(&mut self, ip: u32, second: u64) -> Result<(), Error> {
        self.evict_idle_ns(ip, second.checked_mul(TOKEN).ok_or(Error::Invalid)?)
    }
    pub const fn pending(&self) -> u8 {
        self.pending
    }
    pub const fn active(&self) -> u8 {
        self.active
    }
}

// ---------------------------------------------------------------------------
// SEC-N09/N10/N13 contract mechanisms (V0.19.9 baseline fills).
//
// Baseline citations (docs/design/baselines/v0.19.9-implementation-spec.txt):
// - 主§2.4.1 (~L1421): mandatory order 合法 SYN → 16 keyed /24 SYN-cookie
//   buckets → ACK/cookie validation → D12 dual-bucket/source admission →
//   ≤4 TLS pending → ≤16 active. SYN-ACK creates no NetConn, D12 source or
//   TLS object; per bucket 16/s burst 4; 16-bucket long-term total ≤256/s,
//   any 1s ≤320, initial available ≤64; D12 and SYN budgets are independent.
// - 安§0.8 (~L6985): unified integer token algorithm (monotonic ns,
//   capacity = burst×10^9, refill then debit only when ≥10^9, initially
//   full, clock rollback rejects new admission, any Δ accepts ≤
//   burst+floor(rate×Δ)); bucket index = low 4 bits of
//   HMAC-SHA256(SYN-domain subkey, "CYX/SYN-BUCKET/v1" || IPv4 /24 prefix in
//   network order); cookie MAC subkey derived under the independent label
//   "CYX/SYN-COOKIE/v1" (no cross-purpose key reuse).
// - 安§0.8 SecurityProfile v3 byte table (~L7151): syn_hash_bucket_count=16,
//   rate=16/s/bucket, burst=4, cookie window=30s, time5/MSS3/MAC24,
//   challenge_ack_conn_sec=1, challenge_ack_global_min/max=8/24 per second.
// - SEC-N 实施契约 (~L9680): cookie 32bit time5/MSS3/MAC24, 30s current and
//   previous window only, MAC binds quadruple + client ISN + window + MSS
//   tier; duplicate ACK never creates a new connection; challenge ACK per
//   connection sliding 1s ≤1, global per aligned 1s a uniform random budget
//   8..24 drawn from the independent ACK domain, counts must not be echoed;
//   RFC 5961 §5 ACK boundary check.
// - 主§13.8 (~L6092): frozen N13-A/B and N10-B load conditions (15 attack
//   /24s occupy 15 buckets, the legitimate /24 owns the 16th; per-bucket
//   envelope 4+floor(16Δ), total 64+16·floor(16Δ)).
// - 横切不变量 (~L6565): internal global counters (e.g. challenge ACK total)
//   are never exposed to unauthorized principals; only constant error
//   categories are observable.
// - RFC 5961 §§3.2/4.2/5.2/7 (cited by the baseline): RST/SYN/ACK checks
//   and challenge-ACK throttling.
//
// These are contract-layer structures preparing native wiring; they are not
// the production admission ledger. `RateLimiter` above stays the legacy
// host-contract model and `cyxia_net_transport::admission::Admission` remains
// the sole production connection-credit authority. Nothing here allocates.
//
// Contract choices where the baseline is silent (documented, not wire
// inventions — no byte layout below is claimed as a frozen wire format):
// 1. Cookie u32 bit positions: time in bits 27..31, MSS index in 24..26,
//    MAC in 0..23 (baseline freezes the widths and field order only).
// 2. MAC binding serialization: src_ip BE32 || dst_ip BE32 || src_port BE16
//    || dst_port BE16 || client_isn BE32 || time_counter u8 || mss_index u8
//    (baseline freezes the bound fields, not their encoding). "窗口" is read
//    as the cookie time-window counter, which the MAC must authenticate.
// 3. "Low 4 bits" / "low 24 bits" of an HMAC digest are taken from its
//    big-endian integer representation (digest tail bytes).
// 4. HKDF salt: RFC 5869 default (HashLen zero bytes); the baseline freezes
//    purpose labels, not salts.
// 5. Consumed-cookie anti-replay ledger: 64 bounded slots, retention two
//    cookie windows from consumption, fail-closed (Capacity) when full —
//    never evicts an unexpired entry. The baseline keeps SYN-ACK stateless
//    and dedups at the connection layer ("同四元组在途/TIME_WAIT 先拒绝");
//    this ledger is the contract-layer one-shot guarantee for `consume`.
// 6. Global challenge budget draw: keyed PRF (HMAC-SHA256 under the ACK
//    domain subkey) over the aligned window index, reduced uniformly into
//    8..=24. The baseline freezes the range and alignment, not the draw
//    algorithm; native DRBG wiring may supply the draw instead.
// 7. Challenge connection slots: MAX_ACTIVE+MAX_PENDING = 20, keyed by
//    (conn_id, generation) supplied by the authenticated native connection
//    table (never by wire claims); live entries are never evicted, release
//    is explicit. A new generation of the same conn_id is a fresh instance.
// 8. Clock rollback is checked per bucket / per budget against its own last
//    timestamp (the native gate supplies one monotonic clock).
// 9. Residual: the frozen 5-bit time counter wraps every 32×30s = 960s; a
//    cookie replayed exactly across the wrap passes the window check, so
//    cross-wrap replay resistance rests on the consume ledger plus the
//    native quadruple dedup. Field widths are frozen by the baseline.
// 10. Forged local/loopback source filtering belongs to the frame parser
//     layer (SEC-N 实施契约), not to the token table.

/// SecurityProfile v3 `syn_hash_bucket_count` (安§0.8 byte 131).
pub const SYN_BUCKET_COUNT: usize = 16;
/// SecurityProfile v3 `syn_hash_bucket_rate_sec` (bytes 132–133): 16/s/bucket.
pub const SYN_BUCKET_RATE_SEC: u16 = 16;
/// SecurityProfile v3 `syn_hash_bucket_burst` (byte 134): 4 replies/bucket.
pub const SYN_BUCKET_BURST: u64 = 4;
/// SecurityProfile v3 `syn_cookie_window_sec` (byte 135): 30 s.
pub const SYN_COOKIE_WINDOW_NS: u64 = 30 * TOKEN;
/// Frozen MSS tiers (SEC-N 实施契约 / TcpSchema.v1 `tcp.mss_values`); the
/// 3-bit cookie field indexes this table, default tier 536 when absent.
pub const MSS_TIERS: [u16; 8] = [536, 576, 960, 1200, 1280, 1360, 1440, 1460];
/// SecurityProfile v3 `challenge_ack_conn_sec` (byte 139): sliding 1s ≤1.
pub const CHALLENGE_ACK_CONN_WINDOW_NS: u64 = TOKEN;
/// SecurityProfile v3 `challenge_ack_global_min_sec`/`max_sec` (140–143).
pub const CHALLENGE_ACK_GLOBAL_MIN: u16 = 8;
pub const CHALLENGE_ACK_GLOBAL_MAX: u16 = 24;
/// TcpSchema.v1 `tcp.syn_bucket_label` / `tcp.syn_cookie_label` (SEC-N13).
pub const SYN_BUCKET_LABEL: &[u8] = b"CYX/SYN-BUCKET/v1";
pub const SYN_COOKIE_LABEL: &[u8] = b"CYX/SYN-COOKIE/v1";
/// Bounded challenge-ACK connection slots: 16 active + 4 pending (主§2.4.1).
pub const CHALLENGE_CONN_SLOTS: usize = (MAX_ACTIVE + MAX_PENDING) as usize;
/// Contract choice 5: bounded consumed-cookie ledger (baseline silent).
const SYN_CONSUMED_SLOTS: usize = 64;

/// HMAC-SHA256 (RFC 2104) over the audited `sha2` core; no allocation.
/// Required by 安§0.8 for the keyed bucket mapping and the cookie MAC.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[message])
}

fn hmac_sha256_parts(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    let mut block = Zeroizing::new([0u8; 64]);
    if key.len() > 64 {
        let mut digest = Sha256::digest(key);
        block[..32].copy_from_slice(&digest);
        digest[..].zeroize();
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Zeroizing::new([0x36u8; 64]);
    let mut opad = Zeroizing::new([0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad.as_slice());
    for part in message {
        inner.update(part);
    }
    let mut inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad.as_slice());
    outer.update(inner.as_slice());
    inner[..].zeroize();
    outer.finalize().into()
}

/// HKDF-SHA256 (RFC 5869) Extract+Expand to one 32-byte purpose subkey.
/// Salt is the RFC default of HashLen zero bytes (contract choice 4).
fn hkdf_subkey(secret: &[u8], label: &[u8]) -> [u8; 32] {
    let prk = Zeroizing::new(hmac_sha256(&[0u8; 32], secret));
    hmac_sha256_parts(prk.as_slice(), &[label, &[1]])
}

/// Branchless equality of two 24-bit MAC values (no early exit).
fn ct_eq_mac24(a: u32, b: u32) -> bool {
    let d = (a ^ b) & 0x00FF_FFFF;
    ((d | d >> 8 | d >> 16) & 0xFF) == 0
}

#[derive(Clone, Copy, Debug)]
struct SynBucket {
    tokens_nano: u64,
    last_ns: u64,
}

/// SEC-N09/N13: the 16 fixed keyed /24-prefix SYN-ACK token buckets
/// (主§2.4.1, 安§0.8). Issuing a SYN-ACK debits only the mapped bucket's
/// token; this table holds no NetConn, D12 source entry or TLS object, and
/// its budget is independent of D12. Spoofed-source floods therefore drain
/// only their own bucket and can never occupy admission slots.
pub struct SynAckTokens {
    buckets: [SynBucket; SYN_BUCKET_COUNT],
    bucket_key: [u8; 32],
}
impl SynAckTokens {
    /// Only the native SYN-domain key authority may construct this table.
    /// `syn_domain_key` is the native HKDF output for purpose label
    /// CYX/SYN/v1 (主§13.3); the contract never generates key material, and
    /// entropy failure means no authority constructs/rotates keys, which
    /// stops new cookies (SEC-N 降级路径). Buckets start full (安§0.8).
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_native_syn_domain(syn_domain_key: [u8; 32]) -> Self {
        Self {
            buckets: [SynBucket {
                tokens_nano: SYN_BUCKET_BURST * TOKEN,
                last_ns: 0,
            }; SYN_BUCKET_COUNT],
            bucket_key: syn_domain_key,
        }
    }
    /// 安§0.8: bucket = low 4 bits of HMAC-SHA256(SYN-domain subkey,
    /// "CYX/SYN-BUCKET/v1" || IPv4 first 24 bits in network order).
    /// `src_ip` carries the first octet in the most significant byte; hosts
    /// inside one /24 always share a bucket (collision ⇒ bounded backpressure
    /// only, never a persistent side effect).
    pub fn bucket_of(&self, src_ip: u32) -> usize {
        let mut msg = [0u8; 20]; // 17-byte frozen label + 3 prefix bytes
        msg[..17].copy_from_slice(SYN_BUCKET_LABEL);
        msg[17] = (src_ip >> 24) as u8;
        msg[18] = (src_ip >> 16) as u8;
        msg[19] = (src_ip >> 8) as u8;
        let mac = hmac_sha256(&self.bucket_key, &msg);
        usize::from(mac[31] & 0x0F)
    }
    /// Debit one SYN-ACK token from the mapped bucket, returning its index.
    /// Unified integer algorithm (安§0.8): refill to capacity first, debit
    /// only when ≥10^9 nano-tokens remain; clock rollback rejects issuance.
    /// Envelope: any Δ seconds accept ≤ burst+floor(rate×Δ) per bucket,
    /// hence ≤64+16·floor(16Δ) total, any 1s ≤320, initial ≤64, long-term
    /// ≤256/s. Failure debits nothing.
    pub fn issue_syn_ack(&mut self, src_ip: u32, now_ns: u64) -> Result<usize, Error> {
        let at = self.bucket_of(src_ip);
        let bucket = &mut self.buckets[at];
        if now_ns < bucket.last_ns {
            return Err(Error::Invalid);
        }
        let elapsed = now_ns - bucket.last_ns;
        let refilled =
            u128::from(bucket.tokens_nano) + u128::from(SYN_BUCKET_RATE_SEC) * u128::from(elapsed);
        bucket.tokens_nano = refilled.min(u128::from(SYN_BUCKET_BURST * TOKEN)) as u64;
        bucket.last_ns = now_ns;
        if bucket.tokens_nano < TOKEN {
            return Err(Error::Capacity);
        }
        bucket.tokens_nano -= TOKEN;
        Ok(at)
    }
}

/// TCP quadruple of a half-open flow. Addresses carry the first octet in the
/// most significant byte; the cookie MAC serializes them in network order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SynFlow {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug)]
struct ConsumedSynCookie {
    flow: SynFlow,
    client_isn: u32,
    cookie: u32,
    expires_ns: u64,
}

/// Proof that a cookie passed MAC, window and MSS validation under one key
/// generation. Constructed only by `SynCookieAuthority::validate_cookie`;
/// a wire message cannot manufacture it (same authority pattern as
/// `VerifiedTls`). `consume` is one-shot and generation-bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedSynCookie {
    generation: u64,
    flow: SynFlow,
    client_isn: u32,
    cookie: u32,
    mss_index: u8,
    time_counter: u8,
    validated_ns: u64,
}
impl ValidatedSynCookie {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn flow(&self) -> SynFlow {
        self.flow
    }
    pub const fn client_isn(&self) -> u32 {
        self.client_isn
    }
    pub const fn mss_index(&self) -> u8 {
        self.mss_index
    }
    /// Frozen MSS tier carried by the validated cookie.
    pub const fn mss(&self) -> u16 {
        MSS_TIERS[self.mss_index as usize]
    }
}

/// SEC-N09: stateless SYN-cookie issue/validate plus one-shot, generation-
/// bound consume (SEC-N 实施契约: 32bit time5/MSS3/MAC24, 30s current and
/// previous window, MAC binds quadruple/client ISN/window/MSS tier).
///
/// Native gate order (主§2.4.1): `SynAckTokens::issue_syn_ack` debits the
/// bucket token, `issue_cookie` encodes the SYN-ACK ISN statelessly (no
/// NetConn/source/TLS state), the returning ACK is checked with
/// `validate_cookie` + `consume`, and only then may D12 admission
/// (`RateLimiter` legacy contract / native `Admission`) run. A spoofed flow
/// that never completes the handshake stops at the bucket or the cookie
/// gate and occupies zero admission credit.
pub struct SynCookieAuthority {
    generation: u64,
    cookie_key: [u8; 32],
    consumed: [Option<ConsumedSynCookie>; SYN_CONSUMED_SLOTS],
}
impl SynCookieAuthority {
    /// Only the native SYN-domain key authority may construct this object.
    /// The cookie MAC subkey is HKDF-derived under the independent frozen
    /// label CYX/SYN-COOKIE/v1 (安§0.8, no cross-purpose reuse). Rotating to
    /// a new generation with fresh key material invalidates every older
    /// cookie by MAC mismatch; `generation` must be ≥1.
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) fn from_native_syn_domain(
        generation: u64,
        syn_domain_key: [u8; 32],
    ) -> Result<Self, Error> {
        if generation == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            generation,
            cookie_key: hkdf_subkey(&syn_domain_key, SYN_COOKIE_LABEL),
            consumed: [None; SYN_CONSUMED_SLOTS],
        })
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Stateless cookie encoding (contract choices 1–3): time counter in
    /// bits 27..31, MSS tier index in 24..26, low 24 MAC bits in 0..23.
    /// The caller must already hold a bucket token from `SynAckTokens`.
    pub fn issue_cookie(
        &self,
        flow: &SynFlow,
        client_isn: u32,
        mss_index: u8,
        now_ns: u64,
    ) -> Result<u32, Error> {
        if usize::from(mss_index) >= MSS_TIERS.len() {
            return Err(Error::Invalid);
        }
        let time = cookie_time_counter(now_ns);
        let mac = cookie_mac(&self.cookie_key, flow, client_isn, time, mss_index);
        Ok(u32::from(time) << 27 | u32::from(mss_index) << 24 | mac24_of(&mac))
    }
    /// Verify MAC, time window (current or previous 30s window only) and
    /// extract the frozen MSS tier. Stateless: no admission credit moves.
    pub fn validate_cookie(
        &self,
        flow: &SynFlow,
        client_isn: u32,
        cookie: u32,
        now_ns: u64,
    ) -> Result<ValidatedSynCookie, Error> {
        let time = ((cookie >> 27) & 0x1F) as u8;
        let mss_index = ((cookie >> 24) & 0x07) as u8;
        let current = cookie_time_counter(now_ns);
        if time != current && time != (current.wrapping_sub(1) & 0x1F) {
            return Err(Error::Stale);
        }
        let mac = cookie_mac(&self.cookie_key, flow, client_isn, time, mss_index);
        if !ct_eq_mac24(cookie & 0x00FF_FFFF, mac24_of(&mac)) {
            return Err(Error::Unauthorized);
        }
        Ok(ValidatedSynCookie {
            generation: self.generation,
            flow: *flow,
            client_isn,
            cookie,
            mss_index,
            time_counter: time,
            validated_ns: now_ns,
        })
    }
    /// One-shot exchange of a validated cookie for admission credit.
    /// Replay of the same (flow, client ISN, cookie) inside the retention
    /// window is `Conflict` with no state change; a proof from another key
    /// generation is `Stale`; a full unexpired ledger is fail-closed
    /// `Capacity` (never evicts an unexpired entry). The caller runs D12
    /// admission only after this succeeds.
    pub fn consume(&mut self, proof: ValidatedSynCookie, now_ns: u64) -> Result<(), Error> {
        if proof.generation != self.generation {
            return Err(Error::Stale);
        }
        if now_ns < proof.validated_ns {
            return Err(Error::Invalid);
        }
        let current = cookie_time_counter(now_ns);
        if proof.time_counter != current && proof.time_counter != (current.wrapping_sub(1) & 0x1F) {
            return Err(Error::Stale);
        }
        let mut free: Option<usize> = None;
        for (at, slot) in self.consumed.iter().enumerate() {
            match slot {
                Some(entry) if entry.expires_ns > now_ns => {
                    if entry.flow == proof.flow
                        && entry.client_isn == proof.client_isn
                        && entry.cookie == proof.cookie
                    {
                        return Err(Error::Conflict);
                    }
                }
                _ => {
                    if free.is_none() {
                        free = Some(at);
                    }
                }
            }
        }
        let at = free.ok_or(Error::Capacity)?;
        self.consumed[at] = Some(ConsumedSynCookie {
            flow: proof.flow,
            client_isn: proof.client_isn,
            cookie: proof.cookie,
            expires_ns: now_ns.saturating_add(2 * SYN_COOKIE_WINDOW_NS),
        });
        Ok(())
    }
}

const fn cookie_time_counter(now_ns: u64) -> u8 {
    ((now_ns / SYN_COOKIE_WINDOW_NS) & 0x1F) as u8
}

fn mac24_of(mac: &[u8; 32]) -> u32 {
    u32::from(mac[29]) << 16 | u32::from(mac[30]) << 8 | u32::from(mac[31])
}

/// MAC binding (contract choice 2): quadruple, client ISN, cookie time
/// window counter and MSS tier index, all authenticated together.
fn cookie_mac(
    cookie_key: &[u8; 32],
    flow: &SynFlow,
    client_isn: u32,
    time_counter: u8,
    mss_index: u8,
) -> [u8; 32] {
    let mut binding = [0u8; 18];
    binding[0..4].copy_from_slice(&flow.src_ip.to_be_bytes());
    binding[4..8].copy_from_slice(&flow.dst_ip.to_be_bytes());
    binding[8..10].copy_from_slice(&flow.src_port.to_be_bytes());
    binding[10..12].copy_from_slice(&flow.dst_port.to_be_bytes());
    binding[12..16].copy_from_slice(&client_isn.to_be_bytes());
    binding[16] = time_counter;
    binding[17] = mss_index;
    hmac_sha256(cookie_key, &binding)
}

#[derive(Clone, Copy, Debug)]
struct ChallengeConn {
    conn_id: u64,
    generation: u64,
    last_challenge_ns: Option<u64>,
}

/// SEC-N13 challenge-ACK budget (SEC-N 实施契约, 安§0.8, RFC 5961 §7):
/// per connection a sliding 1s window admits ≤1 challenge ACK; globally
/// each aligned 1s window admits a uniform budget in 8..=24 drawn from the
/// independent ACK domain (contract choice 6). Both limits return the same
/// constant `Capacity` category and no counter is ever exposed (横切不变量:
/// 禁止回显计数). The caller supplies (conn_id, generation) from the
/// authenticated native connection table and routes RFC 5961 events here:
/// §3.2 in-window non-exact RST, §4.2 any SYN in a synchronized state, and
/// §5.2 out-of-range ACK all challenge; the verdict helpers below decide
/// which events qualify.
pub struct ChallengeAckBudget {
    ack_key: [u8; 32],
    last_ns: u64,
    window: u64,
    budget: u16,
    used: u16,
    conns: [Option<ChallengeConn>; CHALLENGE_CONN_SLOTS],
}
impl ChallengeAckBudget {
    /// Only the native ACK-domain key authority may construct this budget.
    /// `ack_key` is the native HKDF output for purpose label CYX/ACK/v1
    /// (主§13.3 frozen domain list); the contract never generates entropy.
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) fn from_native_ack_domain(ack_key: [u8; 32]) -> Self {
        Self {
            ack_key,
            last_ns: 0,
            window: 0,
            budget: Self::draw_budget(&ack_key, 0),
            used: 0,
            conns: [None; CHALLENGE_CONN_SLOTS],
        }
    }
    /// Uniform draw into 8..=24 for one aligned 1s window, keyed by the
    /// ACK-domain subkey (contract choice 6).
    fn draw_budget(ack_key: &[u8; 32], window: u64) -> u16 {
        let mac = hmac_sha256(ack_key, &window.to_be_bytes());
        let draw = u16::from_be_bytes([mac[0], mac[1]]);
        CHALLENGE_ACK_GLOBAL_MIN + draw % (CHALLENGE_ACK_GLOBAL_MAX - CHALLENGE_ACK_GLOBAL_MIN + 1)
    }
    /// Admit one challenge ACK for this connection instance, or refuse with
    /// a constant error category. All checks run before any state commit:
    /// clock rollback → Invalid; per-connection sliding 1s exceeded or
    /// global aligned-window budget spent or no bounded slot → Capacity.
    pub fn allow_challenge(
        &mut self,
        conn_id: u64,
        generation: u64,
        now_ns: u64,
    ) -> Result<(), Error> {
        if now_ns < self.last_ns {
            return Err(Error::Invalid);
        }
        let window = now_ns / TOKEN;
        let (budget, used) = if window == self.window {
            (self.budget, self.used)
        } else {
            (Self::draw_budget(&self.ack_key, window), 0)
        };
        let mut exact: Option<usize> = None;
        let mut older_generation: Option<usize> = None;
        let mut free: Option<usize> = None;
        for (at, row) in self.conns.iter().enumerate() {
            match row {
                Some(c) if c.conn_id == conn_id && c.generation == generation => {
                    exact = Some(at);
                    break;
                }
                Some(c) if c.conn_id == conn_id => {
                    if older_generation.is_none() {
                        older_generation = Some(at);
                    }
                }
                Some(_) => {}
                None => {
                    if free.is_none() {
                        free = Some(at);
                    }
                }
            }
        }
        let at = exact.or(older_generation).or(free).ok_or(Error::Capacity)?;
        let last_challenge_ns = match exact {
            Some(at) => {
                self.conns[at]
                    .as_ref()
                    .ok_or(Error::Stale)?
                    .last_challenge_ns
            }
            // A fresh slot or a new generation of the same conn_id is a new
            // connection instance with no challenge history.
            None => None,
        };
        if let Some(last) = last_challenge_ns
            && now_ns - last < CHALLENGE_ACK_CONN_WINDOW_NS
        {
            return Err(Error::Capacity);
        }
        if used >= budget {
            return Err(Error::Capacity);
        }
        self.window = window;
        self.budget = budget;
        self.used = used + 1;
        self.last_ns = now_ns;
        self.conns[at] = Some(ChallengeConn {
            conn_id,
            generation,
            last_challenge_ns: Some(now_ns),
        });
        Ok(())
    }
    /// Release the slot of a genuinely closed connection instance; only the
    /// exact (conn_id, generation) match is removed (same trust model as
    /// `RateLimiter::close_active_from`). Live entries are never evicted:
    /// eviction would reset a rate limit and enable bypass.
    pub fn release(&mut self, conn_id: u64, generation: u64) -> Result<(), Error> {
        let slot = self
            .conns
            .iter_mut()
            .find(|r| r.is_some_and(|c| c.conn_id == conn_id && c.generation == generation))
            .ok_or(Error::Stale)?;
        *slot = None;
        Ok(())
    }
}

/// RFC 5961 §3.2 RST verdict for synchronized states other than SYN-SENT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RstVerdict {
    /// SEG.SEQ exactly equals RCV.NXT: the reset is authentic.
    Reset,
    /// Strictly inside the receive window but not exact: send a challenge
    /// ACK (through `ChallengeAckBudget`) and drop the segment.
    ChallengeAck,
    /// Outside the receive window: silently drop.
    Drop,
}

/// RFC 5961 §5.2 ACK verdict. `ChallengeAck` means discard the segment and
/// send a challenge ACK (through `ChallengeAckBudget`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckVerdict {
    Accept,
    ChallengeAck,
}

/// Serial-number ≤ (RFC 1982 style, half-space comparison).
const fn seq_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
}
/// Serial-number <.
const fn seq_lt(a: u32, b: u32) -> bool {
    let d = b.wrapping_sub(a);
    d != 0 && d < 0x8000_0000
}

/// RFC 5961 §3.2: exact RCV.NXT → reset; strictly in-window
/// (RCV.NXT < SEG.SEQ < RCV.NXT+RCV.WND) → challenge ACK then drop;
/// anything else → silent drop. With a zero window only the exact match
/// qualifies. Sequence comparisons wrap at 2^32.
pub const fn rst_verdict(rcv_nxt: u32, rcv_wnd: u32, seg_seq: u32) -> RstVerdict {
    if seg_seq == rcv_nxt {
        RstVerdict::Reset
    } else if seq_lt(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt.wrapping_add(rcv_wnd)) {
        RstVerdict::ChallengeAck
    } else {
        RstVerdict::Drop
    }
}

/// RFC 5961 §5.2: an ACK is acceptable only inside
/// (SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT (wrapping arithmetic);
/// anything else is discarded and answered with a challenge ACK.
/// `max_snd_wnd` is the largest window ever advertised by the peer; this
/// prototype forbids window scaling, so it never exceeds 65535.
pub const fn ack_verdict(snd_una: u32, snd_nxt: u32, max_snd_wnd: u32, seg_ack: u32) -> AckVerdict {
    let lower = snd_una.wrapping_sub(max_snd_wnd);
    if seq_le(lower, seg_ack) && seq_le(seg_ack, snd_nxt) {
        AckVerdict::Accept
    } else {
        AckVerdict::ChallengeAck
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proof() -> VerifiedTls {
        VerifiedTls::from_native_tls([3; 32], TLS13, TLS_AES_128_GCM_SHA256, false, false)
    }
    fn cap() -> ReadOnlyEcho {
        proof().read_only_echo(&[3; 32]).unwrap()
    }
    fn packet(payload: &[u8]) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..2].copy_from_slice(&1u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[8..16].copy_from_slice(&7u64.to_le_bytes());
        bytes[16..16 + payload.len()].copy_from_slice(payload);
        bytes
    }
    #[test]
    fn sec_n01_wrong_pin_or_suite_refuses_service() {
        assert_eq!(proof().read_only_echo(&[4; 32]), Err(Error::Unauthorized));
        let bad =
            VerifiedTls::from_native_tls([3; 32], 0x0303, TLS_AES_128_GCM_SHA256, false, false);
        assert_eq!(bad.read_only_echo(&[3; 32]), Err(Error::Unauthorized));
    }
    #[test]
    fn sec_n02_early_data_and_resumption_refused() {
        for (early, resumed) in [(true, false), (false, true)] {
            let bad = VerifiedTls::from_native_tls(
                [3; 32],
                TLS13,
                TLS_AES_128_GCM_SHA256,
                early,
                resumed,
            );
            assert_eq!(bad.read_only_echo(&[3; 32]), Err(Error::Unauthorized));
        }
    }
    #[test]
    fn sec_n03_handshake_capacity_not_unbounded() {
        let mut limiter = RateLimiter::new();
        for i in 1..=4 {
            limiter.request_handshake(i, 0, 16).unwrap();
        }
        assert_eq!(limiter.pending(), 4);
        assert_eq!(limiter.request_handshake(5, 0, 16), Err(Error::Capacity));
    }
    #[test]
    fn sec_n04_burst_not_reset_by_repeating_source() {
        let mut limiter = RateLimiter::new();
        for _ in 0..4 {
            limiter.request_handshake(1, 0, 16).unwrap();
            limiter.finish_handshake(1, false).unwrap();
        }
        assert_eq!(limiter.request_handshake(1, 0, 16), Err(Error::Capacity));
        assert_eq!(limiter.evict_idle(1, 0), Err(Error::Busy));
    }
    #[test]
    fn sec_n05_echo_rejects_tail_or_opcode() {
        let mut bytes = packet(&[1, 2, 3, 4]);
        assert_eq!(
            parse_read_only_echo(cap(), &bytes).unwrap().payload,
            &[1, 2, 3, 4]
        );
        bytes[2] = 2;
        assert!(matches!(
            parse_read_only_echo(cap(), &bytes),
            Err(Error::Invalid)
        ));
        bytes[2] = 1;
        assert!(matches!(
            parse_read_only_echo(cap(), &bytes[..19]),
            Err(Error::Invalid)
        ));
    }
    #[test]
    fn sec_n06_service_right_is_read_only_by_construction() {
        let bytes = packet(&[1, 2, 3, 4]);
        let request = parse_read_only_echo(cap(), &bytes).unwrap();
        assert_eq!(request.request_id, 7);
    }
    #[test]
    fn sec_n07_oversized_payload_is_rejected_pre_dispatch() {
        let mut bytes = [0u8; 16];
        bytes[0] = 1;
        bytes[2] = 1;
        bytes[4..8].copy_from_slice(&4097u32.to_le_bytes());
        assert!(matches!(
            parse_read_only_echo(cap(), &bytes),
            Err(Error::Invalid)
        ));
    }
    #[test]
    fn v019_sec_n03_full_active_pool_releases_new_failed_handshake() {
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
    #[test]
    fn v019_sec_n04_one_source_cannot_steal_other_active_credit() {
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
    #[test]
    fn v019_sec_n04_connected_source_is_never_evicted_or_replenished_by_forgetting() {
        let mut limiter = RateLimiter::new();
        limiter.request_handshake(7, 0, 4).unwrap();
        limiter.finish_handshake(7, true).unwrap();
        assert_eq!(limiter.evict_idle(7, 10), Err(Error::Busy));
        limiter.close_active_from(7).unwrap();
        limiter.evict_idle(7, 10).unwrap();
        assert_eq!(limiter.active(), 0);
    }
    #[test]
    fn v0199_rejected_new_sources_never_occupy_table_and_refill_is_fractional() {
        let mut limiter = RateLimiter::new();
        for ip in 1..=4 {
            limiter.request_handshake_ns(ip, 0, 16).unwrap();
            limiter.finish_handshake(ip, false).unwrap();
        }
        for ip in 5..=40 {
            assert_eq!(
                limiter.request_handshake_ns(ip, 0, 16),
                Err(Error::Capacity)
            );
        }
        assert_eq!(limiter.sources.iter().flatten().count(), 4);
        assert_eq!(
            limiter.request_handshake_ns(41, 62_499_999, 16),
            Err(Error::Capacity)
        );
        limiter.request_handshake_ns(41, 62_500_000, 16).unwrap();
        assert_eq!(limiter.pending(), 1);
        assert_eq!(
            limiter.request_handshake_ns(42, 62_499_999, 16),
            Err(Error::Invalid)
        );
    }
    #[test]
    fn v0199_single_source_pending_and_rate_change_preserve_debt() {
        let mut limiter = RateLimiter::new();
        limiter.request_handshake_ns(1, 0, 4).unwrap();
        assert_eq!(limiter.request_handshake_ns(1, 0, 4), Err(Error::Capacity));
        limiter.finish_handshake(1, false).unwrap();
        for ip in 2..=4 {
            limiter.request_handshake_ns(ip, 0, 4).unwrap();
            limiter.finish_handshake(ip, false).unwrap();
        }
        assert_eq!(
            limiter.request_handshake_ns(5, 125_000_000, 32),
            Err(Error::Capacity)
        );
        limiter.request_handshake_ns(5, 140_625_000, 32).unwrap();
    }
    #[test]
    fn v0199_lru_reuses_only_refilled_unreferenced_sources() {
        let mut limiter = RateLimiter::new();
        limiter.request_handshake(1, 0, 16).unwrap();
        limiter.finish_handshake(1, true).unwrap();
        for ip in 2..=32 {
            limiter.request_handshake(ip, u64::from(ip), 16).unwrap();
            limiter.finish_handshake(ip, false).unwrap();
        }
        limiter.request_handshake(33, 33, 16).unwrap();
        assert!(limiter.sources.iter().flatten().any(|s| s.ip == 1));
        assert!(!limiter.sources.iter().flatten().any(|s| s.ip == 2));
        assert_eq!(limiter.sources.iter().flatten().count(), 32);
    }
    #[test]
    fn sec_n08_no_model_is_needed_for_rate_limit_and_echo() {
        let mut limiter = RateLimiter::new();
        limiter.request_handshake(7, 0, 4).unwrap();
        limiter.finish_handshake(7, true).unwrap();
        assert_eq!(limiter.active(), 1);
        limiter.close_active_from(7).unwrap();
        assert_eq!(limiter.active(), 0);
    }

    // ---------------- SEC-N09/N10/N13 contract mechanism tests ----------------
    // Fixed test keys; the bucket layout below is frozen by these keys
    // (主§13.8 "冻结哈希": 15 attack /24s occupy 15 buckets, the legitimate
    // /24 owns the 16th). No native wiring is exercised here.
    const TEST_SYN_KEY: [u8; 32] = [0x5A; 32];
    const TEST_ACK_KEY: [u8; 32] = [0xA5; 32];

    fn syn_tokens() -> SynAckTokens {
        SynAckTokens::from_native_syn_domain(TEST_SYN_KEY)
    }
    fn cookie_authority(generation: u64) -> SynCookieAuthority {
        SynCookieAuthority::from_native_syn_domain(generation, TEST_SYN_KEY).unwrap()
    }
    fn flow(src_ip: u32) -> SynFlow {
        SynFlow {
            src_ip,
            dst_ip: 0xC0A8_0101,
            src_port: 40000,
            dst_port: 443,
        }
    }
    /// Deterministic one-/24-per-bucket layout under TEST_SYN_KEY.
    fn frozen_prefixes() -> [u32; 16] {
        let table = syn_tokens();
        let mut found = [0u32; 16];
        let mut seen = [false; 16];
        let mut candidate = 0x0A00_0000u32;
        while !seen.iter().all(|s| *s) {
            let b = table.bucket_of(candidate);
            if !seen[b] {
                seen[b] = true;
                found[b] = candidate;
            }
            candidate += 0x100;
        }
        found
    }

    #[test]
    fn sec_n09_spoofed_flood_drains_only_mapped_bucket() {
        let mut tokens = syn_tokens();
        let prefixes = frozen_prefixes();
        let legit = prefixes[7] | 0x09;
        // 1000 spoofed SYNs at one instant, all hosts of one attack /24.
        let mut accepted = 0;
        for host in 0..1000u32 {
            if tokens.issue_syn_ack(prefixes[3] | (host & 0xFF), 0).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 4); // only the mapped bucket's initial burst
        // The untouched bucket still holds its full burst: no cross-bucket
        // drain and no persistent side effect from the collision.
        for _ in 0..4 {
            tokens.issue_syn_ack(legit, 0).unwrap();
        }
        assert_eq!(tokens.issue_syn_ack(legit, 0), Err(Error::Capacity));
    }

    #[test]
    fn sec_n09_four_source_slot_fill_occupies_zero_admission_credit() {
        let mut tokens = syn_tokens();
        let mut limiter = RateLimiter::new();
        let prefixes = frozen_prefixes();
        // Four spoofed sources in one /24 flood for 100s; none completes the
        // three-way handshake (N09 "仅 4 个源填槽攻击").
        let mut total = 0u64;
        for round in 0..100u64 {
            let mut this_second = 0u64;
            for src in 1..=4u32 {
                if tokens
                    .issue_syn_ack(prefixes[2] | src, round * TOKEN)
                    .is_ok()
                {
                    this_second += 1;
                }
            }
            assert!(this_second <= 20); // any 1s ≤ burst+rate = 4+16
            total += this_second;
        }
        assert!(total <= 4 + 16 * 99); // per-bucket envelope over Δ=99s
        // 0 NetConn / 0 D12 source: the independent admission ledger is
        // untouched and a legitimate admission still succeeds afterwards.
        assert_eq!(limiter.pending(), 0);
        assert_eq!(limiter.active(), 0);
        limiter
            .request_handshake_ns(0x0B00_0001, 100 * TOKEN, 16)
            .unwrap();
        assert_eq!(limiter.pending(), 1);
    }

    #[test]
    fn sec_n13_per_bucket_sliding_window_envelope() {
        let ip = frozen_prefixes()[0] | 1;
        // Greedy 1ms-spaced issuance over 2s: accepts ≤ 4+floor(16×2) = 36.
        let mut tokens = syn_tokens();
        let mut accepted = 0;
        for step in 0..=2000u64 {
            if tokens.issue_syn_ack(ip, step * 1_000_000).is_ok() {
                accepted += 1;
            }
        }
        assert!((32..=36).contains(&accepted));
        // Exact fractional refill boundary: after draining at t=0 the 5th
        // token arrives at exactly 1/16s = 62.5ms, not 1ns earlier.
        let mut tokens = syn_tokens();
        for _ in 0..4 {
            tokens.issue_syn_ack(ip, 0).unwrap();
        }
        assert_eq!(tokens.issue_syn_ack(ip, 62_499_999), Err(Error::Capacity));
        tokens.issue_syn_ack(ip, 62_500_000).unwrap();
    }

    #[test]
    fn sec_n13_total_initial_64_and_any_1s_320() {
        let prefixes = frozen_prefixes();
        // Initial instantaneous availability across all 16 buckets is 64.
        let mut tokens = syn_tokens();
        let mut initial = 0;
        for p in prefixes {
            for _ in 0..5 {
                if tokens.issue_syn_ack(p | 1, 0).is_ok() {
                    initial += 1;
                }
            }
        }
        assert_eq!(initial, 64);
        // Greedy issuance across every bucket over 1s: total ≤ 320 and the
        // long-term 256/s floor is reached.
        let mut tokens = syn_tokens();
        let mut accepted = 0;
        for step in 0..=1000u64 {
            for p in prefixes {
                if tokens.issue_syn_ack(p | 1, step * 1_000_000).is_ok() {
                    accepted += 1;
                }
            }
        }
        assert!((256..=320).contains(&accepted));
    }

    #[test]
    fn sec_n13_frozen_bucket_mapping_keyed_and_24_granular() {
        let tokens = syn_tokens();
        let prefixes = frozen_prefixes();
        let mut seen = [false; 16];
        for p in prefixes {
            let b = tokens.bucket_of(p);
            assert!(!seen[b]);
            seen[b] = true;
        }
        // /24 granularity: every host of a prefix shares its bucket.
        for host in [1u32, 7, 128, 255] {
            assert_eq!(
                tokens.bucket_of(prefixes[5] | host),
                tokens.bucket_of(prefixes[5])
            );
        }
        // Keyed mapping: another domain key changes at least one bucket.
        let other = SynAckTokens::from_native_syn_domain([0x5B; 32]);
        assert!(
            prefixes
                .iter()
                .any(|p| other.bucket_of(*p) != tokens.bucket_of(*p))
        );
        assert_eq!(tokens.bucket_of(prefixes[9]), tokens.bucket_of(prefixes[9]));
    }

    #[test]
    fn syn_bucket_clock_rollback_rejects_and_preserves_debt() {
        let mut tokens = syn_tokens();
        let ip = frozen_prefixes()[1] | 1;
        for _ in 0..4 {
            tokens.issue_syn_ack(ip, 10 * TOKEN).unwrap();
        }
        assert_eq!(
            tokens.issue_syn_ack(ip, 10 * TOKEN - 1),
            Err(Error::Invalid)
        );
        // Rollback neither replenishes nor forgives the drained burst.
        assert_eq!(tokens.issue_syn_ack(ip, 10 * TOKEN), Err(Error::Capacity));
    }

    #[test]
    fn sec_n09_cookie_roundtrip_all_mss_tiers() {
        let authority = cookie_authority(1);
        let f = flow(0x0A00_0001);
        for (index, tier) in MSS_TIERS.iter().enumerate() {
            let cookie = authority
                .issue_cookie(&f, 0x1234_5678, index as u8, 0)
                .unwrap();
            let proof = authority
                .validate_cookie(&f, 0x1234_5678, cookie, 0)
                .unwrap();
            assert_eq!(proof.mss_index(), index as u8);
            assert_eq!(proof.mss(), *tier);
            assert_eq!(proof.generation(), 1);
            assert_eq!(proof.client_isn(), 0x1234_5678);
            assert_eq!(proof.flow(), f);
            assert_eq!(cookie >> 27, 0); // time5 at now_ns=0
            assert_eq!((cookie >> 24) & 7, index as u32); // MSS3
        }
        assert_eq!(authority.issue_cookie(&f, 0, 8, 0), Err(Error::Invalid));
    }

    #[test]
    fn sec_n09_cookie_mac_binds_every_field() {
        let authority = cookie_authority(1);
        let f = flow(0x0A00_0001);
        let isn = 0xDEAD_BEEFu32;
        let cookie = authority.issue_cookie(&f, isn, 5, 0).unwrap();
        let mut bad = f;
        bad.src_ip ^= 1;
        assert_eq!(
            authority.validate_cookie(&bad, isn, cookie, 0),
            Err(Error::Unauthorized)
        );
        let mut bad = f;
        bad.dst_ip ^= 1;
        assert_eq!(
            authority.validate_cookie(&bad, isn, cookie, 0),
            Err(Error::Unauthorized)
        );
        let mut bad = f;
        bad.src_port ^= 1;
        assert_eq!(
            authority.validate_cookie(&bad, isn, cookie, 0),
            Err(Error::Unauthorized)
        );
        let mut bad = f;
        bad.dst_port ^= 1;
        assert_eq!(
            authority.validate_cookie(&bad, isn, cookie, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authority.validate_cookie(&f, isn.wrapping_add(1), cookie, 0),
            Err(Error::Unauthorized)
        );
        // Time counter flipped to the other *valid* window: MAC must fail.
        let tampered_time = (cookie & !(0x1F << 27)) | (31u32 << 27);
        assert_eq!(
            authority.validate_cookie(&f, isn, tampered_time, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authority.validate_cookie(&f, isn, cookie ^ (1 << 24), 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authority.validate_cookie(&f, isn, cookie ^ 1, 0),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn sec_n09_cookie_current_and_previous_window_only() {
        let authority = cookie_authority(1);
        let f = flow(0x0A00_0001);
        let w = SYN_COOKIE_WINDOW_NS;
        let cookie = authority.issue_cookie(&f, 77, 0, 5 * w).unwrap();
        authority.validate_cookie(&f, 77, cookie, 5 * w).unwrap();
        authority
            .validate_cookie(&f, 77, cookie, 6 * w - 1)
            .unwrap();
        authority.validate_cookie(&f, 77, cookie, 6 * w).unwrap();
        assert_eq!(
            authority.validate_cookie(&f, 77, cookie, 7 * w),
            Err(Error::Stale)
        );
        // 5-bit counter wrap: window 31 stays valid into window 32 (counter
        // 0, previous 31), then expires.
        let cookie31 = authority.issue_cookie(&f, 78, 0, 31 * w).unwrap();
        authority.validate_cookie(&f, 78, cookie31, 32 * w).unwrap();
        assert_eq!(
            authority.validate_cookie(&f, 78, cookie31, 33 * w),
            Err(Error::Stale)
        );
    }

    #[test]
    fn sec_n09_generation_bound_rotation_and_consume() {
        let gen1 = cookie_authority(1);
        let f = flow(0x0A00_0001);
        let cookie = gen1.issue_cookie(&f, 9, 0, 0).unwrap();
        let proof = gen1.validate_cookie(&f, 9, cookie, 0).unwrap();
        // Rotation with fresh key material invalidates old cookies by MAC.
        let gen2 = SynCookieAuthority::from_native_syn_domain(2, [0x5B; 32]).unwrap();
        assert_eq!(
            gen2.validate_cookie(&f, 9, cookie, 0),
            Err(Error::Unauthorized)
        );
        // Even with identical key material a proof cannot cross generations.
        let mut gen2_same_key =
            SynCookieAuthority::from_native_syn_domain(2, TEST_SYN_KEY).unwrap();
        let proof2 = gen2_same_key.validate_cookie(&f, 9, cookie, 0).unwrap();
        assert_eq!(gen2_same_key.consume(proof, 0), Err(Error::Stale));
        gen2_same_key.consume(proof2, 0).unwrap();
        assert!(SynCookieAuthority::from_native_syn_domain(0, TEST_SYN_KEY).is_err());
    }

    #[test]
    fn sec_n09_consume_one_shot_replay() {
        let mut authority = cookie_authority(1);
        let f = flow(0x0A00_0001);
        let cookie = authority.issue_cookie(&f, 42, 0, 0).unwrap();
        let proof = authority.validate_cookie(&f, 42, cookie, 0).unwrap();
        authority.consume(proof, 0).unwrap();
        assert_eq!(authority.consume(proof, 0), Err(Error::Conflict));
        // Re-validating the same wire cookie never mints a second credit.
        let again = authority
            .validate_cookie(&f, 42, cookie, 1_000_000)
            .unwrap();
        assert_eq!(authority.consume(again, 1_000_000), Err(Error::Conflict));
        // A fresh ISN is a distinct handshake and a distinct credit.
        let cookie2 = authority.issue_cookie(&f, 43, 0, 0).unwrap();
        let proof2 = authority.validate_cookie(&f, 43, cookie2, 0).unwrap();
        authority.consume(proof2, 0).unwrap();
    }

    #[test]
    fn sec_n09_consume_ledger_bounded_fail_closed_and_expiry() {
        let mut authority = cookie_authority(1);
        let f = flow(0x0A00_0001);
        for isn in 0..SYN_CONSUMED_SLOTS as u32 {
            let cookie = authority.issue_cookie(&f, isn, 0, 0).unwrap();
            let proof = authority.validate_cookie(&f, isn, cookie, 0).unwrap();
            authority.consume(proof, 0).unwrap();
        }
        // Full unexpired ledger: fail-closed, never evicts an entry.
        let cookie = authority.issue_cookie(&f, 64, 0, 0).unwrap();
        let proof = authority.validate_cookie(&f, 64, cookie, 0).unwrap();
        assert_eq!(authority.consume(proof, 0), Err(Error::Capacity));
        // Replay detection still works while the ledger is full.
        let replay_cookie = authority.issue_cookie(&f, 0, 0, 0).unwrap();
        let replay = authority.validate_cookie(&f, 0, replay_cookie, 0).unwrap();
        assert_eq!(authority.consume(replay, 0), Err(Error::Conflict));
        // After the two-window retention, expired slots are reusable.
        let later = 2 * SYN_COOKIE_WINDOW_NS;
        let cookie = authority.issue_cookie(&f, 1000, 0, later).unwrap();
        let proof = authority.validate_cookie(&f, 1000, cookie, later).unwrap();
        authority.consume(proof, later).unwrap();
    }

    #[test]
    fn sec_n09_consume_clock_rollback_and_delayed_proof() {
        let mut authority = cookie_authority(1);
        let f = flow(0x0A00_0001);
        let cookie = authority.issue_cookie(&f, 5, 0, 0).unwrap();
        let proof = authority.validate_cookie(&f, 5, cookie, TOKEN).unwrap();
        assert_eq!(authority.consume(proof, TOKEN - 1), Err(Error::Invalid));
        // A proof held beyond the cookie's window validity cannot be
        // consumed late (window re-check at consume time).
        assert_eq!(
            authority.consume(proof, 3 * SYN_COOKIE_WINDOW_NS),
            Err(Error::Stale)
        );
    }

    #[test]
    fn sec_n13_challenge_per_connection_sliding_1s() {
        let mut budget = ChallengeAckBudget::from_native_ack_domain(TEST_ACK_KEY);
        budget.allow_challenge(1, 1, 0).unwrap();
        assert_eq!(
            budget.allow_challenge(1, 1, 999_999_999),
            Err(Error::Capacity)
        );
        budget.allow_challenge(1, 1, TOKEN).unwrap();
        // Sliding from the last challenge, not aligned windows: starting at
        // 0.5s, 1.4s crosses the aligned boundary but is only 0.9s later and
        // must still be refused; 1.5s is exactly 1s after 0.5s and passes.
        let mut sliding = ChallengeAckBudget::from_native_ack_domain(TEST_ACK_KEY);
        sliding.allow_challenge(1, 1, TOKEN / 2).unwrap();
        assert_eq!(
            sliding.allow_challenge(1, 1, TOKEN + 400_000_000),
            Err(Error::Capacity)
        );
        sliding.allow_challenge(1, 1, TOKEN + TOKEN / 2).unwrap();
        assert_eq!(
            sliding.allow_challenge(1, 1, 2 * TOKEN + 400_000_000),
            Err(Error::Capacity)
        );
        sliding
            .allow_challenge(1, 1, 2 * TOKEN + TOKEN / 2)
            .unwrap();
    }

    #[test]
    fn sec_n13_challenge_global_aligned_budget_8_to_24() {
        let mut budget = ChallengeAckBudget::from_native_ack_domain(TEST_ACK_KEY);
        // Exhaust one aligned second with distinct connections (releasing
        // each slot so only the global budget binds) and count the admits.
        let mut admitted = 0u16;
        for conn in 0..100u64 {
            if budget.allow_challenge(conn, 1, 500_000_000).is_ok() {
                admitted += 1;
                budget.release(conn, 1).unwrap();
            }
        }
        assert!((CHALLENGE_ACK_GLOBAL_MIN..=CHALLENGE_ACK_GLOBAL_MAX).contains(&admitted));
        assert_eq!(
            budget.allow_challenge(1000, 1, 500_000_000),
            Err(Error::Capacity)
        );
        // The next aligned second redraws a budget and admits again.
        let mut next = 0u16;
        for conn in 0..100u64 {
            if budget.allow_challenge(conn, 1, TOKEN + 500_000_000).is_ok() {
                next += 1;
                budget.release(conn, 1).unwrap();
            }
        }
        assert!((CHALLENGE_ACK_GLOBAL_MIN..=CHALLENGE_ACK_GLOBAL_MAX).contains(&next));
        // Per-connection and global refusals are one constant category:
        // nothing echoes which limit bound or any counter value.
        let mut b = ChallengeAckBudget::from_native_ack_domain(TEST_ACK_KEY);
        b.allow_challenge(7, 1, 0).unwrap();
        let per_connection = b.allow_challenge(7, 1, 1).unwrap_err();
        for conn in 100..200u64 {
            if b.allow_challenge(conn, 1, 1).is_ok() {
                b.release(conn, 1).unwrap();
            }
        }
        let global = b.allow_challenge(999, 1, 1).unwrap_err();
        assert_eq!(per_connection, global);
    }

    #[test]
    fn sec_n13_challenge_budget_draw_keyed_range_and_variation() {
        let mut seen_mask = 0u32;
        let mut min = CHALLENGE_ACK_GLOBAL_MAX;
        let mut max = CHALLENGE_ACK_GLOBAL_MIN;
        for window in 0..512u64 {
            let b = ChallengeAckBudget::draw_budget(&TEST_ACK_KEY, window);
            assert!((CHALLENGE_ACK_GLOBAL_MIN..=CHALLENGE_ACK_GLOBAL_MAX).contains(&b));
            min = min.min(b);
            max = max.max(b);
            seen_mask |= 1 << (b - CHALLENGE_ACK_GLOBAL_MIN);
        }
        assert_eq!(min, CHALLENGE_ACK_GLOBAL_MIN);
        assert_eq!(max, CHALLENGE_ACK_GLOBAL_MAX);
        assert!(seen_mask.count_ones() >= 8);
        // A different ACK-domain key yields a different draw sequence.
        let mut differences = 0;
        for window in 0..64u64 {
            if ChallengeAckBudget::draw_budget(&TEST_ACK_KEY, window)
                != ChallengeAckBudget::draw_budget(&[0xA6; 32], window)
            {
                differences += 1;
            }
        }
        assert!(differences > 0);
    }

    #[test]
    fn sec_n13_challenge_generation_isolation_and_release() {
        let mut budget = ChallengeAckBudget::from_native_ack_domain(TEST_ACK_KEY);
        budget.allow_challenge(7, 1, 0).unwrap();
        // A new generation of the same conn_id is a fresh instance.
        budget.allow_challenge(7, 2, 1_000_000).unwrap();
        assert_eq!(budget.release(7, 1), Err(Error::Stale));
        budget.release(7, 2).unwrap();
        assert_eq!(budget.release(7, 2), Err(Error::Stale));
        assert_eq!(budget.release(99, 1), Err(Error::Stale));
        // Release is trusted native close evidence; the slot is reusable.
        budget.allow_challenge(7, 2, 2_000_000).unwrap();
    }

    #[test]
    fn sec_n13_challenge_slots_bounded_no_eviction() {
        let mut budget = ChallengeAckBudget::from_native_ack_domain(TEST_ACK_KEY);
        // 20 live instances (16 active + 4 pending) fill the bounded table.
        for conn in 0..CHALLENGE_CONN_SLOTS as u64 {
            budget.allow_challenge(conn, 1, conn * TOKEN).unwrap();
        }
        assert_eq!(
            budget.allow_challenge(20, 1, 20 * TOKEN),
            Err(Error::Capacity)
        );
        // Live entries are never evicted; existing instances keep slots.
        budget.allow_challenge(0, 1, 20 * TOKEN).unwrap();
        budget.release(5, 1).unwrap();
        budget.allow_challenge(20, 1, 20 * TOKEN).unwrap();
    }

    #[test]
    fn sec_n13_challenge_clock_rollback() {
        let mut budget = ChallengeAckBudget::from_native_ack_domain(TEST_ACK_KEY);
        budget.allow_challenge(1, 1, 5 * TOKEN).unwrap();
        assert_eq!(
            budget.allow_challenge(2, 1, 5 * TOKEN - 1),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn sec_n13_rfc5961_rst_boundary() {
        // Exact RCV.NXT resets, even with a zero window.
        assert_eq!(rst_verdict(1000, 0, 1000), RstVerdict::Reset);
        assert_eq!(rst_verdict(1000, 500, 1000), RstVerdict::Reset);
        // Strictly in-window but not exact: challenge ACK then drop.
        assert_eq!(rst_verdict(1000, 500, 1001), RstVerdict::ChallengeAck);
        assert_eq!(rst_verdict(1000, 500, 1499), RstVerdict::ChallengeAck);
        // Window edges and outside: silent drop.
        assert_eq!(rst_verdict(1000, 500, 1500), RstVerdict::Drop);
        assert_eq!(rst_verdict(1000, 500, 999), RstVerdict::Drop);
        assert_eq!(rst_verdict(1000, 0, 1001), RstVerdict::Drop);
        // Wrapping sequence space.
        let nxt = u32::MAX - 10;
        assert_eq!(rst_verdict(nxt, 100, nxt), RstVerdict::Reset);
        assert_eq!(
            rst_verdict(nxt, 100, nxt.wrapping_add(5)),
            RstVerdict::ChallengeAck
        );
        assert_eq!(
            rst_verdict(nxt, 100, nxt.wrapping_add(100)),
            RstVerdict::Drop
        );
        assert_eq!(rst_verdict(nxt, 100, nxt.wrapping_sub(1)), RstVerdict::Drop);
    }

    #[test]
    fn sec_n13_rfc5961_ack_boundary() {
        // Acceptable: (SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT.
        assert_eq!(ack_verdict(2000, 3000, 65535, 2500), AckVerdict::Accept);
        assert_eq!(ack_verdict(2000, 3000, 65535, 3000), AckVerdict::Accept);
        assert_eq!(ack_verdict(2000, 3000, 65535, 2000), AckVerdict::Accept);
        assert_eq!(
            ack_verdict(2000, 3000, 65535, 2000u32.wrapping_sub(65535)),
            AckVerdict::Accept
        );
        // Ahead of SND.NXT or below the lower bound: discard + challenge.
        assert_eq!(
            ack_verdict(2000, 3000, 65535, 3001),
            AckVerdict::ChallengeAck
        );
        assert_eq!(
            ack_verdict(2000, 3000, 65535, 2000u32.wrapping_sub(65536)),
            AckVerdict::ChallengeAck
        );
        // Zero MAX.SND.WND collapses the range to [SND.UNA, SND.NXT].
        assert_eq!(ack_verdict(2000, 3000, 0, 1999), AckVerdict::ChallengeAck);
        assert_eq!(ack_verdict(2000, 3000, 0, 2000), AckVerdict::Accept);
        // Wrapping arithmetic near 2^32.
        let una = u32::MAX - 100;
        let nxt = una.wrapping_add(500);
        assert_eq!(
            ack_verdict(una, nxt, 65535, una.wrapping_add(250)),
            AckVerdict::Accept
        );
        assert_eq!(
            ack_verdict(una, nxt, 65535, nxt.wrapping_add(1)),
            AckVerdict::ChallengeAck
        );
        assert_eq!(
            ack_verdict(una, nxt, 65535, una.wrapping_sub(65536)),
            AckVerdict::ChallengeAck
        );
    }

    #[test]
    fn sec_n13_stray_syn_challenges_through_budget() {
        // RFC 5961 §4.2: any SYN in a synchronized state challenges
        // regardless of sequence; it shares the per-connection/global budget
        // with RST and ACK events.
        let mut budget = ChallengeAckBudget::from_native_ack_domain(TEST_ACK_KEY);
        budget.allow_challenge(3, 1, 0).unwrap(); // stray SYN event
        assert_eq!(budget.allow_challenge(3, 1, 1_000), Err(Error::Capacity));
    }

    #[test]
    fn sec_n10a_overload_only_safe_bounded_backpressure() {
        // N10-A (主§13.8): 32 sources every 0.9s; excess is judged only for
        // safety — bounded rejection, no debt reset, no unsafe eviction.
        let mut limiter = RateLimiter::new();
        let mut admitted = 0u64;
        for round in 0..10u64 {
            let now = round * 900_000_000;
            for ip in 1..=32u32 {
                match limiter.request_handshake_ns(ip, now, 16) {
                    Ok(()) => {
                        admitted += 1;
                        assert!(limiter.pending() <= MAX_PENDING);
                        limiter.finish_handshake(ip, false).unwrap();
                    }
                    Err(Error::Capacity) => {}
                    Err(other) => panic!("unexpected error {other:?}"),
                }
            }
        }
        // Global D12 envelope over Δ=8.1s: ≤ 4 + floor(16×8.1) = 133.
        assert!((1..=133).contains(&admitted));
        assert_eq!(limiter.pending(), 0);
        assert_eq!(limiter.active(), 0);
        // A debt source survives the overload and cannot be evicted to
        // resurrect its burst.
        let debtor = limiter
            .sources
            .iter()
            .flatten()
            .find(|s| s.tokens < 4 * TOKEN)
            .copied()
            .unwrap();
        assert_eq!(
            limiter.evict_idle_ns(debtor.ip, 8_100_000_000),
            Err(Error::Busy)
        );
    }

    #[test]
    fn sec_n09_full_contract_gate_order() {
        // 主§2.4.1 composition: bucket token → stateless cookie → validate →
        // consume → D12. Spoofed/replayed paths never reach D12 credit.
        let mut tokens = syn_tokens();
        let mut authority = cookie_authority(1);
        let mut limiter = RateLimiter::new();
        let f = flow(0x0A00_0001);
        let now = 0u64;
        tokens.issue_syn_ack(f.src_ip, now).unwrap();
        let cookie = authority.issue_cookie(&f, 100, 0, now).unwrap();
        let proof = authority.validate_cookie(&f, 100, cookie, now).unwrap();
        authority.consume(proof, now).unwrap();
        limiter.request_handshake_ns(f.src_ip, now, 16).unwrap();
        limiter.finish_handshake(f.src_ip, true).unwrap();
        assert_eq!(limiter.active(), 1);
        // Replay stops at consume: no new pending credit appears.
        let replay = authority.validate_cookie(&f, 100, cookie, now).unwrap();
        assert_eq!(authority.consume(replay, now), Err(Error::Conflict));
        assert_eq!(limiter.pending(), 0);
        // Spoofed flood drains only SYN buckets; D12 remains untouched.
        for host in 2..=200u32 {
            let _ = tokens.issue_syn_ack(0x0A00_0000 | host, now);
        }
        assert_eq!(limiter.pending(), 0);
        assert_eq!(limiter.active(), 1);
    }

    #[test]
    fn sec_n13_n13b_frozen_15_attack_buckets_legit_16th() {
        // 主§13.8 N13-B profile at contract level: 15 attack /24s at 40 SYN/s
        // each (600/s total) occupy 15 buckets; the legitimate /24 owns the
        // 16th and issues 5/s. Attacks never complete a handshake; only
        // bounded backpressure is promised, never fairness.
        let mut tokens = syn_tokens();
        let prefixes = frozen_prefixes();
        let mut attack_admitted = 0u64;
        let mut legit_admitted = 0u64;
        for step in 0..5000u64 {
            let now = step * 1_000_000;
            if step % 25 == 0 {
                for p in &prefixes[..15] {
                    if tokens.issue_syn_ack(p | 1, now).is_ok() {
                        attack_admitted += 1;
                    }
                }
            }
            if step % 200 == 0 && tokens.issue_syn_ack(prefixes[15] | 1, now).is_ok() {
                legit_admitted += 1;
            }
        }
        // Per-bucket envelope over Δ=4.999s: ≤ 4+floor(16×4.999) = 83 each;
        // total envelope over 5s: ≤ 64+16×floor(16×5) = 1344.
        assert!(attack_admitted <= 15 * 83);
        assert!(attack_admitted + legit_admitted <= 1344);
        assert!(attack_admitted < 15 * 200); // offered 3000, bounded admits
        // The exclusive legitimate bucket is untouched by the attack:
        // every one of the 25 legit SYNs (5/s ≤ 16/s) is admitted.
        assert_eq!(legit_admitted, 25);
    }
}
