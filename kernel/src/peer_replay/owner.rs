use super::*;
use crate::{
    control_pool as pool,
    domain_control::replay as root,
    learning_history::{FrozenScope, TrialKind},
};
use core::{
    cell::UnsafeCell,
    mem::size_of,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use cyxia_peer_billing::{self as wire, Endpoint, Header, Keys, Reader, Writer};
use cyxia_prototype::{
    domains::Action,
    learning::{Family, ReplayGroup},
    policy::Snapshot,
};
use sha2::{Digest, Sha256};

const REQUESTS: usize = 256;
const PAGES: usize = (MAX_INTERVALS * size_of::<CpuInterval>()).div_ceil(4096);
const EMPTY_INTERVAL: CpuInterval = CpuInterval {
    node: [0; 32],
    core: 0,
    start_ns: 0,
    end_ns: 0,
    class: CpuClass::Policy,
};
#[derive(Clone, Copy)]
struct Out {
    bytes: [u8; wire::PACKET_BYTES],
    len: usize,
    sequence: u64,
    kind: u16,
    last_sent: Option<u64>,
}
#[derive(Clone, Copy)]
struct Remote {
    endpoint: Endpoint,
    epoch: u64,
    nonce: [u8; 32],
    echoed: bool,
}
#[derive(Clone, Copy)]
struct Request {
    work: Work,
    result: Option<WorkResult>,
    reported: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TaskBinding {
    key: ObjectKey,
    contract: [u8; 16],
    input: [u8; 32],
    package: [u8; 32],
    sequence: u64,
    acknowledged: bool,
    token: Option<u64>,
    closed: bool,
}
#[derive(Clone, Copy)]
struct Preparation {
    identity: Binding,
    reservation_binding: Binding,
    ready: bool,
    frozen: [u8; 32],
    scope: Option<FrozenScope>,
    reservation: u64,
    start_issued: bool,
    started: bool,
    start_reported: bool,
    observing: bool,
    close_sent: bool,
    released: bool,
    keep_pair: Option<bool>,
}
struct State {
    keys: Keys,
    local: Endpoint,
    peer_node: [u8; 32],
    epoch: u64,
    nonce: [u8; 32],
    remote: Option<Remote>,
    session: Option<[u8; 32]>,
    sequence: u64,
    received: wire::ReceiveCursor,
    ack: Option<u64>,
    out: Option<Out>,
    hello_sent: Option<u64>,
    serial: u64,
    declined: Option<Binding>,
    cancelled: Option<Binding>,
    retry_at: u64,
    origin: Option<Preparation>,
    origin_hold: Option<Preparation>,
    participant: Option<Preparation>,
    spectator: Option<root::Token>,
    pair_hold: Option<Preparation>,
    abort_for: Option<root::Preparation>,
    abort_binding: Option<Binding>,
    abort_complete: bool,
    abort_packet: [u8; wire::PREPARATION_PACKET_BYTES],
    abort_packet_len: usize,
    abort_peer: bool,
    abort_peer_receipt: Option<wire::PreparationSeal>,
    prior_sealed: [u8; 32],
    origin_failure: Option<wire::Failure>,
    participant_failure: Option<wire::Failure>,
    failure_sent_for: Option<Binding>,
    failure_packet: [u8; wire::ROOT_FAILURE_PACKET_BYTES],
    failure_packet_len: usize,
    failure_packet_sequence: u64,
    failure_packet_hash: [u8; 32],
    archived_late: Option<(RunKey, [u8; 32])>,
    requests: [Option<Request>; REQUESTS],
    results: [Option<WorkResult>; REQUESTS],
    issued: [bool; REQUESTS],
    tasks: [Option<TaskBinding>; REQUESTS],
    assembler: Option<wire::Assembler>,
    seal: Option<PartnerEvidence>,
    seal_packet: [u8; wire::EXCLUDED_PACKET_BYTES],
    seal_packet_len: usize,
    trace_cursor: usize,
    seal_sent: bool,
    export_excluded: bool,
    participant_release: bool,
    fault: Option<learning::Error>,
    service_idle: bool,
    service_at: u64,
}
pub(super) const META_PAGES: usize = size_of::<State>().div_ceil(4096);
struct Setup {
    bank: Option<pool::Allocation>,
    bank_pin: Option<pool::Lease>,
    metadata: Option<pool::Allocation>,
    metadata_pin: Option<pool::Lease>,
    mapping: Option<pool::Allocation>,
    mapping_pin: Option<pool::Lease>,
    fields: bool,
    rows: usize,
}
struct Cell(UnsafeCell<Setup>);
unsafe impl Sync for Cell {}
static SETUP: Cell = Cell(UnsafeCell::new(Setup {
    bank: None,
    bank_pin: None,
    metadata: None,
    metadata_pin: None,
    mapping: None,
    mapping_pin: None,
    fields: false,
    rows: 0,
}));
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
const MAP_PAGES: usize = (REQUESTS * 4 * size_of::<AtomicU64>()).div_ceil(4096);
static MAP_ADDRESS: AtomicUsize = AtomicUsize::new(0);
pub(super) const TOTAL_PAGES: usize = PAGES + META_PAGES + MAP_PAGES;
static GATE: AtomicBool = AtomicBool::new(false);
static BANK: AtomicUsize = AtomicUsize::new(0);
struct LedgerCell(UnsafeCell<Option<ledger::Ledger>>);
unsafe impl Sync for LedgerCell {}
static LEDGER: LedgerCell = LedgerCell(UnsafeCell::new(None));
static LEDGER_GATE: AtomicBool = AtomicBool::new(false);
static LEDGER_FAMILY: AtomicU64 = AtomicU64::new(0);
static LEDGER_KIND: AtomicU64 = AtomicU64::new(0);
static LEDGER_TARGET_ID: AtomicU64 = AtomicU64::new(0);
static LEDGER_TARGET_GENERATION: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static DROPPED_OPEN: AtomicU64 = AtomicU64::new(0);
// A successful root release cannot be undone by a contended owner lock. Keep
// its exact token until the retained RELEASED response has been enqueued.
static ROOT_RELEASED: AtomicU64 = AtomicU64::new(0);
static ROOT_RELEASED_AT: AtomicU64 = AtomicU64::new(0);
struct Guard(&'static AtomicBool);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn lock(gate: &'static AtomicBool) -> Result<Guard, DomainError> {
    gate.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| DomainError::Busy)?;
    Ok(Guard(gate))
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, DomainError>) -> Result<T, DomainError> {
    let _guard = lock(&GATE)?;
    let address = ADDRESS.load(Ordering::Acquire);
    if address == 0 {
        return Err(DomainError::NotReady);
    }
    f(unsafe { &mut *(address as *mut State) })
}
fn ledger_with<T>(
    f: impl FnOnce(&mut ledger::Ledger) -> Result<T, learning::Error>,
) -> Result<T, learning::Error> {
    let _guard = lock(&LEDGER_GATE).map_err(|_| learning::Error::Unknown)?;
    let l = unsafe { &mut *LEDGER.0.get() }
        .as_mut()
        .ok_or(learning::Error::Stale)?;
    // Most segments have no abandoned lease. Under translated execution an
    // unconditional RMW is a synchronous helper even when the counter is zero.
    // A concurrent increment after the zero load remains published for the
    // next ledger borrower; a nonzero observation still drains atomically.
    let take_pending = |counter: &AtomicU64| {
        if counter.load(Ordering::Acquire) == 0 {
            0
        } else {
            counter.swap(0, Ordering::AcqRel)
        }
    };
    let lost = take_pending(&DROPPED);
    let open = take_pending(&DROPPED_OPEN);
    l.missing = l.missing.saturating_add(lost);
    l.open = l.open.saturating_sub(open as usize);
    f(l)
}
fn now() -> u64 {
    crate::domain_platform::now_ns()
}
fn cpu0() -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() == 0 {
        Ok(())
    } else {
        Err(DomainError::Auth)
    }
}
fn mechanism() -> Result<(), DomainError> {
    cpu0()?;
    crate::domain_tasks::authorize_service_turn()
}
fn domain(_: wire::Error) -> DomainError {
    DomainError::Format
}
fn learn(e: DomainError) -> learning::Error {
    if e == DomainError::Busy {
        learning::Error::Unknown
    } else {
        learning::Error::Evidence
    }
}
fn stored(index: usize) -> *mut CpuInterval {
    (BANK.load(Ordering::Acquire) as *mut CpuInterval).wrapping_add(index)
}
fn unsupported(family: Family, target: ObjectKey, action: Action) -> Result<(), DomainError> {
    with(|s| {
        if s.participant.is_some_and(|p| {
            p.identity.family
                == (Family {
                    domain: 16,
                    kind: 2,
                })
        }) && family
            == (Family {
                domain: 16,
                kind: 1,
            })
            && target
                == (ObjectKey {
                    id: crate::unified::abi::OFFER_SERVICE_ID,
                    generation: 1,
                })
            && action == Action::OfferCpu(100)
        {
            Ok(())
        } else {
            Err(DomainError::Auth)
        }
    })
}
fn no_stop(
    token: root::Token,
    target: ObjectKey,
    snapshot: Snapshot,
) -> Result<root::Receipt, DomainError> {
    if !fixture_stop_authorized(token) {
        return Err(DomainError::Auth);
    }
    crate::domain_network::baseline_stop_quotes(token, target, snapshot)
}
fn no_first(_: root::Token, _: Snapshot) -> Result<(), DomainError> {
    Err(DomainError::Auth)
}
fn no_preparation(_: root::Preparation) -> Result<(), DomainError> {
    Err(DomainError::Auth)
}
fn no_unactivated(_: root::Preparation, _: &FrozenScope) -> Result<(), DomainError> {
    Err(DomainError::Auth)
}

pub fn init(boot: u64) -> Result<(), DomainError> {
    cpu0()?;
    if boot == 0 {
        return Err(DomainError::Stale);
    }
    {
        let _guard = lock(&GATE)?;
        let address = ADDRESS.load(Ordering::Acquire);
        if address != 0 {
            if unsafe { (*(address as *const State)).local.boot } != boot {
                return Err(DomainError::Stale);
            }
        } else {
            let setup = unsafe { &mut *SETUP.0.get() };
            if setup.bank.is_none() {
                setup.bank = Some(pool::allocate(OWNER, PAGES)?);
            }
            let bank = setup.bank.ok_or(DomainError::NotReady)?;
            if setup.bank_pin.is_none() {
                setup.bank_pin = Some(pool::pin(bank)?);
            }
            if setup.metadata.is_none() {
                setup.metadata = Some(pool::allocate(OWNER, META_PAGES)?);
            }
            let metadata = setup.metadata.ok_or(DomainError::NotReady)?;
            if setup.metadata_pin.is_none() {
                setup.metadata_pin = Some(pool::pin(metadata)?);
            }
            if setup.mapping.is_none() {
                setup.mapping = Some(pool::allocate(OWNER, MAP_PAGES)?);
            }
            let mapping = setup.mapping.ok_or(DomainError::NotReady)?;
            if setup.mapping_pin.is_none() {
                setup.mapping_pin = Some(pool::pin(mapping)?);
            }
            let map = pool::span(mapping)?.0 as *mut AtomicU64;
            let base = pool::span(metadata)?.0;
            if !base.is_multiple_of(core::mem::align_of::<State>()) {
                return Err(DomainError::Range);
            }
            let state = base as *mut State;
            // Initialize in the real pool, a bounded row piece per turn. No
            // 64 KiB temporary is ever materialized on a kernel stack.
            if !setup.fields {
                let keys = Keys::new(
                    include_bytes!(concat!(env!("OUT_DIR"), "/billing.seed")),
                    include_bytes!(concat!(env!("OUT_DIR"), "/billing.pub")),
                    include_bytes!(concat!(env!("OUT_DIR"), "/peer.billing.pub")),
                )
                .map_err(domain)?;
                macro_rules! field {
                    ($name:ident, $value:expr) => {
                        unsafe {
                            core::ptr::addr_of_mut!((*state).$name).write($value);
                        }
                    };
                }
                field!(keys, keys);
                field!(
                    local,
                    Endpoint {
                        node: *include_bytes!(concat!(env!("OUT_DIR"), "/local.pin32")),
                        boot
                    }
                );
                field!(
                    peer_node,
                    *include_bytes!(concat!(env!("OUT_DIR"), "/peer.pin32"))
                );
                field!(epoch, 0);
                field!(nonce, [0; 32]);
                field!(remote, None);
                field!(session, None);
                field!(sequence, 0);
                field!(received, wire::ReceiveCursor::new());
                field!(ack, None);
                field!(out, None);
                field!(hello_sent, None);
                field!(serial, 0);
                field!(declined, None);
                field!(cancelled, None);
                field!(retry_at, 0);
                field!(origin, None);
                field!(origin_hold, None);
                field!(participant, None);
                field!(abort_for, None);
                field!(abort_binding, None);
                field!(abort_complete, false);
                field!(abort_packet, [0; wire::PREPARATION_PACKET_BYTES]);
                field!(abort_packet_len, 0);
                field!(abort_peer, false);
                field!(abort_peer_receipt, None);
                field!(prior_sealed, [0; 32]);
                field!(origin_failure, None);
                field!(participant_failure, None);
                field!(failure_sent_for, None);
                field!(failure_packet, [0; wire::ROOT_FAILURE_PACKET_BYTES]);
                field!(failure_packet_len, 0);
                field!(failure_packet_sequence, 0);
                field!(failure_packet_hash, [0; 32]);
                field!(archived_late, None);
                field!(spectator, None);
                field!(pair_hold, None);
                field!(assembler, None);
                field!(seal, None);
                field!(seal_packet, [0; wire::EXCLUDED_PACKET_BYTES]);
                field!(seal_packet_len, 0);
                field!(trace_cursor, 0);
                field!(seal_sent, false);
                field!(export_excluded, false);
                field!(participant_release, false);
                field!(fault, None);
                field!(service_idle, false);
                field!(service_at, 0);
                setup.fields = true;
            }
            let end = (setup.rows + 16).min(REQUESTS);
            for i in setup.rows..end {
                unsafe {
                    core::ptr::addr_of_mut!((*state).requests)
                        .cast::<Option<Request>>()
                        .add(i)
                        .write(None);
                    core::ptr::addr_of_mut!((*state).results)
                        .cast::<Option<WorkResult>>()
                        .add(i)
                        .write(None);
                    core::ptr::addr_of_mut!((*state).issued)
                        .cast::<bool>()
                        .add(i)
                        .write(false);
                    core::ptr::addr_of_mut!((*state).tasks)
                        .cast::<Option<TaskBinding>>()
                        .add(i)
                        .write(None);
                    for field in 0..4 {
                        map.add(i * 4 + field).write(AtomicU64::new(0));
                    }
                }
            }
            setup.rows = end;
            if end < REQUESTS {
                return Err(DomainError::Again);
            }
            BANK.store(pool::span(bank)?.0, Ordering::Release);
            MAP_ADDRESS.store(map as usize, Ordering::Release);
            ADDRESS.store(base, Ordering::Release);
        }
    }
    root::register_owner(root::OwnerChecks {
        owner: OWNER,
        baseline: unsupported,
        stop_offer: no_stop,
        settled,
        before_first: no_first,
        prepared_settled: no_preparation,
        unactivated_settled: no_unactivated,
    })
}
pub fn family() -> Option<u16> {
    let f = LEDGER_FAMILY.load(Ordering::Acquire);
    (f != 0).then_some(f as u16)
}
pub(crate) fn captures(owner: ObjectKey, class: CpuClass) -> bool {
    let domain = LEDGER_FAMILY.load(Ordering::Acquire);
    if domain == 0 {
        return false;
    }
    ledger::fixed_relevance(
        cyxia_prototype::learning::Family {
            domain: domain as u16,
            kind: LEDGER_KIND.load(Ordering::Relaxed) as u16,
        },
        ObjectKey {
            id: LEDGER_TARGET_ID.load(Ordering::Relaxed),
            generation: LEDGER_TARGET_GENERATION.load(Ordering::Relaxed),
        },
        owner,
        class,
    )
    .unwrap_or(true)
}
#[path = "attempt.rs"]
mod attempts;
pub use attempts::{Attempt, attempt, finish};
pub fn transport(epoch: Option<u64>) {
    let _ = with(|s| {
        let epoch = epoch.unwrap_or(0);
        if s.epoch == epoch {
            return Ok(());
        }
        s.epoch = epoch;
        s.remote = None;
        s.session = None;
        s.hello_sent = None;
        s.ack = None;
        let mut h = Sha256::new();
        h.update(b"CYXIA_EL1_BILLING_SESSION_1.3\0");
        h.update(s.local.node);
        h.update(s.local.boot.to_le_bytes());
        h.update(epoch.to_le_bytes());
        h.update(now().to_le_bytes());
        s.nonce = h.finalize().into();
        if let Some(out) = s.out.as_mut() {
            out.last_sent = None;
        }
        Ok(())
    });
}
fn header(s: &mut State, kind: u16) -> Result<Header, DomainError> {
    s.sequence = s.sequence.checked_add(1).ok_or(DomainError::Overflow)?;
    Ok(Header {
        kind,
        sequence: s.sequence,
        source: s.local,
        destination: s.remote.map_or(
            Endpoint {
                node: s.peer_node,
                boot: 0,
            },
            |r| r.endpoint,
        ),
        session: s.session.unwrap_or([0; 32]),
    })
}
fn queue(s: &mut State, kind: u16, bytes: &[u8]) -> Result<(), DomainError> {
    if s.out.is_some() || s.session.is_none() {
        return Err(DomainError::Busy);
    }
    let h = header(s, kind)?;
    let mut out = Out {
        bytes: [0; wire::PACKET_BYTES],
        len: 0,
        sequence: h.sequence,
        kind,
        last_sent: None,
    };
    out.len = s.keys.encode(h, bytes, &mut out.bytes).map_err(domain)?;
    if kind == wire::TASK_BIND && bytes.len() == 136 {
        let id = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        if let Some(task) = id
            .checked_sub(1)
            .and_then(|i| s.tasks.get_mut(i as usize))
            .and_then(Option::as_mut)
        {
            task.sequence = h.sequence;
        }
    }
    s.out = Some(out);
    Ok(())
}
fn queue_binding(
    s: &mut State,
    kind: u16,
    binding: Binding,
    suffix: &[u8],
) -> Result<(), DomainError> {
    let mut bytes = [0; 512];
    let n = binding.encode(&mut bytes).map_err(domain)?;
    if n + suffix.len() > bytes.len() {
        return Err(DomainError::Capacity);
    }
    bytes[n..n + suffix.len()].copy_from_slice(suffix);
    queue(s, kind, &bytes[..n + suffix.len()])
}
fn hello(s: &mut State, output: &mut [u8]) -> Result<(usize, u64), DomainError> {
    let mut body = [0; 72];
    let mut w = Writer::new(&mut body);
    w.u64(s.epoch).map_err(domain)?;
    w.bytes(&s.nonce).map_err(domain)?;
    w.bytes(&s.remote.map_or([0; 32], |r| r.nonce))
        .map_err(domain)?;
    let h = header(s, wire::HELLO)?;
    let n = s.keys.encode(h, &body, output).map_err(domain)?;
    s.hello_sent = Some(now());
    Ok((n, h.sequence))
}
fn receive_hello(s: &mut State, packet: wire::Packet<'_>) -> Result<(), DomainError> {
    let mut r = Reader::new(packet.body);
    let epoch = r.u64().map_err(domain)?;
    let nonce = r.array().map_err(domain)?;
    let echo = r.array().map_err(domain)?;
    r.end().map_err(domain)?;
    if epoch == 0 || nonce == [0; 32] || ![[0; 32], s.nonce].contains(&echo) {
        return Err(DomainError::Stale);
    }
    s.received
        .rebind(
            packet.header.source.boot,
            s.origin.is_some() || s.participant.is_some() || s.pair_hold.is_some(),
        )
        .map_err(domain)?;
    if let Some(old) = s.remote {
        if old.endpoint != packet.header.source || old.epoch != epoch || old.nonce != nonce {
            // The local TCP epoch must retire before another remote session
            // can rebind this authenticated kernel channel.
            return Err(DomainError::Stale);
        }
    }
    let was_ready = s.session.is_some();
    s.remote = Some(Remote {
        endpoint: packet.header.source,
        epoch,
        nonce,
        echoed: echo == s.nonce,
    });
    if echo == s.nonce {
        let mut h = Sha256::new();
        h.update(b"CYXIA_BILLING_PAIR_1.3\0");
        let local = (s.local, s.epoch, s.nonce);
        let peer = (packet.header.source, epoch, nonce);
        for (endpoint, epoch, nonce) in if s.local.node < s.peer_node {
            [local, peer]
        } else {
            [peer, local]
        } {
            h.update(endpoint.node);
            h.update(endpoint.boot.to_le_bytes());
            h.update(epoch.to_le_bytes());
            h.update(nonce);
        }
        s.session = Some(h.finalize().into());
        if !was_ready {
            if let Some(old) = s.out.take() {
                let body_end = old.len - wire::SIGNATURE_BYTES;
                let h = Header {
                    kind: old.kind,
                    sequence: old.sequence,
                    source: s.local,
                    destination: packet.header.source,
                    session: s.session.ok_or(DomainError::NotReady)?,
                };
                let mut renewed = Out {
                    bytes: [0; wire::PACKET_BYTES],
                    len: 0,
                    sequence: old.sequence,
                    kind: old.kind,
                    last_sent: None,
                };
                renewed.len = s
                    .keys
                    .encode(
                        h,
                        &old.bytes[wire::HEADER_BYTES..body_end],
                        &mut renewed.bytes,
                    )
                    .map_err(domain)?;
                s.out = Some(renewed);
            }
        }
    }
    // Even the side whose peer already echoed needs to send its own echo.
    if echo == [0; 32] || !was_ready {
        s.hello_sent = None;
    }
    Ok(())
}
fn matches_prepare(a: Binding, b: Binding) -> bool {
    a.origin == b.origin
        && a.participant == b.participant
        && a.owner == b.owner
        && a.target == b.target
        && a.family == b.family
        && a.baseline == b.baseline
        && a.group == b.group
}
fn receive(s: &mut State, bytes: &[u8]) -> Result<(), DomainError> {
    let packet = s
        .keys
        .decode(bytes, s.peer_node, s.local, None)
        .map_err(domain)?;
    if packet.header.kind == wire::HELLO {
        return receive_hello(s, packet);
    }
    if s.session != Some(packet.header.session)
        || s.remote.is_none_or(|r| r.endpoint != packet.header.source)
    {
        return Err(DomainError::Stale);
    }
    if packet.header.kind == wire::ACK {
        let mut r = Reader::new(packet.body);
        let seq = r.u64().map_err(domain)?;
        r.end().map_err(domain)?;
        if s.out.as_ref().is_some_and(|o| o.sequence == seq) {
            if s.out.as_ref().is_some_and(|o| o.kind == wire::TASK_BIND) {
                for task in s.tasks.iter_mut().flatten().filter(|t| t.sequence == seq) {
                    task.acknowledged = true;
                }
            }
            s.out = None;
        }
        return Ok(());
    }
    // Reauthentication changes the signed session envelope, never the
    // retained operation sequence or body. Lost ACK retries therefore remain
    // idempotent even for already imported raw trace chunks.
    if !s.received.fresh(&packet).map_err(domain)? {
        s.ack = Some(packet.header.sequence);
        return Ok(());
    }
    dispatch(s, packet.header.kind, packet.body)?;
    if packet.header.kind == wire::ROOT_FAILED && s.failure_packet_len == 0 {
        if bytes.len() != wire::ROOT_FAILURE_PACKET_BYTES {
            return Err(DomainError::Format);
        }
        s.failure_packet[..bytes.len()].copy_from_slice(bytes);
        s.failure_packet_len = bytes.len();
        s.failure_packet_sequence = packet.header.sequence;
        s.failure_packet_hash = Sha256::digest(bytes).into();
    }
    if matches!(packet.header.kind, wire::SEALED | wire::EXCLUDED) {
        if s.seal
            .is_none_or(|seal| !seal_packet_length(seal, bytes.len()))
        {
            return Err(DomainError::Format);
        }
        s.seal_packet[..bytes.len()].copy_from_slice(bytes);
        s.seal_packet_len = bytes.len();
    }
    if packet.header.kind == wire::PREPARED_ABORTED
        || packet.header.kind == wire::DECLINED
            && s.abort_binding
                .is_some_and(|b| Binding::decode(packet.body).ok() == Some(b))
    {
        if bytes.len() > s.abort_packet.len() {
            return Err(DomainError::Format);
        }
        s.abort_packet[..bytes.len()].copy_from_slice(bytes);
        s.abort_packet_len = bytes.len();
        s.abort_complete = true;
    }
    s.received.accepted(&packet).map_err(domain)?;
    s.ack = Some(packet.header.sequence);
    Ok(())
}
fn dispatch(s: &mut State, kind: u16, body: &[u8]) -> Result<(), DomainError> {
    match kind {
        wire::FREEZE => {
            let b = Binding::decode(body).map_err(domain)?;
            if b.origin != s.remote.ok_or(DomainError::NotReady)?.endpoint
                || b.participant != s.local
                || b.owner != OWNER
            {
                return Err(DomainError::Auth);
            }
            if s.participant.is_some_and(|old| old.identity == b) {
                return Ok(());
            }
            if let Some(hold) = s.pair_hold {
                if s.participant.is_some()
                    || b.baseline
                    || !hold.identity.baseline
                    || b.origin != hold.identity.origin
                    || b.participant != hold.identity.participant
                    || b.family != hold.identity.family
                    || b.group != hold.identity.group
                    || b.run.trial_id <= hold.reservation
                    || b.family
                        != (Family {
                            domain: 16,
                            kind: 2,
                        })
                        && b.target != hold.identity.target
                {
                    if s.declined.is_some_and(|old| old != b) {
                        return Err(DomainError::Busy);
                    }
                    s.declined = Some(b);
                    return Ok(());
                }
                s.participant = Some(Preparation {
                    identity: b,
                    reservation_binding: b,
                    ready: false,
                    frozen: hold.frozen,
                    scope: None,
                    reservation: b.run.trial_id,
                    start_issued: false,
                    started: false,
                    start_reported: false,
                    observing: false,
                    close_sent: false,
                    released: false,
                    keep_pair: None,
                });
                s.failure_sent_for = None;
                return Ok(());
            }
            match wire::arbitrate(
                s.local.node,
                s.peer_node,
                s.origin.is_some(),
                s.origin.is_some_and(|p| p.ready || p.scope.is_some()),
                s.participant.is_some(),
            ) {
                wire::Arbitration::Decline => {
                    if s.declined.is_some_and(|old| old != b) {
                        return Err(DomainError::Busy);
                    }
                    s.declined = Some(b);
                    return Ok(());
                }
                wire::Arbitration::YieldUnstarted => {
                    s.cancelled = s.origin.map(|p| p.identity);
                    s.origin = None;
                    if s.out.as_ref().is_some_and(|out| out.kind == wire::FREEZE) {
                        s.out = None;
                    }
                }
                wire::Arbitration::Accept => {}
            }
            s.participant = Some(Preparation {
                identity: b,
                reservation_binding: b,
                ready: false,
                frozen: [0; 32],
                scope: None,
                reservation: b.run.trial_id,
                start_issued: false,
                started: false,
                start_reported: false,
                observing: false,
                close_sent: false,
                released: false,
                keep_pair: None,
            });
            s.requests.fill(None);
            s.results.fill(None);
            s.issued.fill(false);
            s.tasks.fill(None);
            s.trace_cursor = 0;
            s.seal_sent = false;
            s.export_excluded = false;
            s.participant_release = false;
            s.prior_sealed = [0; 32];
            s.participant_failure = None;
            s.failure_sent_for = None;
        }
        wire::DECLINED => {
            let b = Binding::decode(body).map_err(domain)?;
            if s.cancelled == Some(b) {
                return Ok(());
            }
            let p = s.origin.ok_or(DomainError::Stale)?;
            if p.identity != b || p.ready || p.scope.is_some() {
                return Err(DomainError::Conflict);
            }
            s.cancelled = Some(b);
            s.origin = None;
            if s.out.as_ref().is_some_and(|out| out.kind == wire::FREEZE) {
                s.out = None;
            }
            s.retry_at = now().saturating_add(250_000_000);
        }
        wire::FROZEN => {
            if body.len() != wire::BINDING_BYTES + 32 {
                return Err(DomainError::Format);
            }
            let b = Binding::decode(&body[..wire::BINDING_BYTES]).map_err(domain)?;
            let p = s.origin.as_mut().ok_or(DomainError::Stale)?;
            if p.identity != b {
                return Err(DomainError::Stale);
            }
            p.frozen = body[wire::BINDING_BYTES..]
                .try_into()
                .map_err(|_| DomainError::Format)?;
            if p.frozen == [0; 32] {
                return Err(DomainError::Format);
            }
            p.ready = true;
        }
        wire::ROOT_FAILED => {
            let failure = wire::RootFailure::decode(body).map_err(domain)?;
            let p = s
                .origin
                .filter(|p| {
                    failure
                        .belongs_to(p.reservation_binding, p.identity)
                        .is_ok()
                })
                .or_else(|| {
                    s.origin_hold.filter(|p| {
                        failure
                            .belongs_to(p.reservation_binding, p.identity)
                            .is_ok()
                    })
                })
                .ok_or(DomainError::Stale)?;
            failure
                .retain(&mut s.origin_failure, p.reservation_binding, p.identity)
                .map_err(domain)?;
            // A failure is not cancellation or START completion. Preparation
            // requests the real abort; an issued START retains its obligations.
        }
        wire::START => {
            if s.abort_peer {
                return Err(DomainError::Stale);
            }
            if body.len() != wire::BINDING_BYTES + 8 {
                return Err(DomainError::Format);
            }
            let b = Binding::decode(&body[..wire::BINDING_BYTES]).map_err(domain)?;
            let p = s.participant.as_mut().ok_or(DomainError::Stale)?;
            if !p.ready || !matches_prepare(p.identity, b) {
                return Err(DomainError::Stale);
            }
            if p.started {
                return if p.identity == b {
                    Ok(())
                } else {
                    Err(DomainError::Conflict)
                };
            }
            let delay = u64::from_le_bytes(body[wire::BINDING_BYTES..].try_into().unwrap());
            if delay > 6_000_000_000 {
                return Err(DomainError::Range);
            }
            let at = now();
            let observation = at.checked_add(delay).ok_or(DomainError::Overflow)?;
            let _guard = lock(&LEDGER_GATE)?;
            if unsafe { &*LEDGER.0.get() }.is_some() {
                return Err(DomainError::Busy);
            }
            let mut ledger = ledger::Ledger::new(b, at, observation, p.frozen)
                .map_err(|_| DomainError::Format)?;
            if let Some(failure) = s.participant_failure {
                ledger.fail(failure).map_err(|_| DomainError::Conflict)?;
            }
            unsafe {
                *LEDGER.0.get() = Some(ledger);
            }
            DROPPED.store(0, Ordering::Release);
            DROPPED_OPEN.store(0, Ordering::Release);
            LEDGER_KIND.store(u64::from(b.family.kind), Ordering::Relaxed);
            LEDGER_TARGET_ID.store(b.target.id, Ordering::Relaxed);
            LEDGER_TARGET_GENERATION.store(b.target.generation, Ordering::Relaxed);
            LEDGER_FAMILY.store(u64::from(b.family.domain), Ordering::Release);
            p.identity = b;
            p.started = true;
        }
        wire::STARTED => {
            let b = Binding::decode(body).map_err(domain)?;
            let p = s.origin.as_mut().ok_or(DomainError::Stale)?;
            if p.identity != b {
                return Err(DomainError::Stale);
            }
            p.started = true;
        }
        wire::OBSERVING => {
            let b = Binding::decode(body).map_err(domain)?;
            let p = s.origin.as_mut().ok_or(DomainError::Stale)?;
            if p.identity != b || !p.started {
                return Err(DomainError::Stale);
            }
            p.observing = true;
        }
        wire::WORK => {
            let mut r = Reader::new(body);
            let hash: [u8; 32] = r.array().map_err(domain)?;
            let id = r.u64().map_err(domain)?;
            r.end().map_err(domain)?;
            let p = s.participant.ok_or(DomainError::Stale)?;
            if !p.started
                || p.close_sent
                || hash != p.identity.hash().map_err(domain)?
                || !(1..REQUESTS as u64).contains(&id)
                || id <= 100 && !p.observing
            {
                return Err(DomainError::Stale);
            }
            if s.requests[id as usize - 1].is_none() {
                let at = now();
                s.requests[id as usize - 1] = Some(Request {
                    work: Work {
                        run: p.identity.run,
                        id,
                        family: p.identity.family.domain,
                        kind: p.identity.family.kind,
                        arrived_ns: at,
                        deadline_ns: at.checked_add(5_000_000_000).ok_or(DomainError::Overflow)?,
                        seed: p.identity.group.seed,
                    },
                    result: None,
                    reported: false,
                });
            }
        }
        wire::WORK_RESULT => {
            let mut r = Reader::new(body);
            let hash: [u8; 32] = r.array().map_err(domain)?;
            let value = read_result(&mut r)?;
            r.end().map_err(domain)?;
            let p = s.origin.ok_or(DomainError::Stale)?;
            if !p.started
                || hash != p.identity.hash().map_err(domain)?
                || !(1..REQUESTS as u64).contains(&value.id)
            {
                return Err(DomainError::Stale);
            }
            let cell = &mut s.results[value.id as usize - 1];
            if cell.is_some_and(|old| old != value) {
                return Err(DomainError::Conflict);
            }
            *cell = Some(value);
        }
        wire::TASK_BIND => {
            let mut r = Reader::new(body);
            let hash: [u8; 32] = r.array().map_err(domain)?;
            let id = r.u64().map_err(domain)?;
            let task = read_task(&mut r)?;
            r.end().map_err(domain)?;
            let (binding, expected) = if let Some(p) = s.origin.filter(|p| {
                p.started
                    && p.identity.family
                        == (Family {
                            domain: 16,
                            kind: 1,
                        })
            }) {
                if !(1..REQUESTS as u64).contains(&id) || !s.issued[id as usize - 1] {
                    return Err(DomainError::Auth);
                }
                (
                    p.identity,
                    replay_key(p.identity.run, id, s.peer_node, p.identity.participant.boot),
                )
            } else if let Some(p) = s.participant.filter(|p| {
                p.started
                    && p.identity.family
                        == (Family {
                            domain: 16,
                            kind: 2,
                        })
            }) {
                if id != 1 {
                    return Err(DomainError::Auth);
                }
                (p.identity, p.identity.target)
            } else {
                return Err(DomainError::Auth);
            };
            if hash != binding.hash().map_err(domain)? || task.key != expected {
                return Err(DomainError::Auth);
            }
            validate_task(task, binding, id)?;
            let cell = &mut s.tasks[id as usize - 1];
            if cell.is_some_and(|old| {
                old.key != task.key
                    || old.contract != task.contract
                    || old.input != task.input
                    || old.package != task.package
            }) {
                return Err(DomainError::Conflict);
            }
            if cell.is_none() {
                *cell = Some(task);
            }
        }
        wire::CLOSE => {
            let b = Binding::decode(body).map_err(domain)?;
            let p = s.participant.as_mut().ok_or(DomainError::Stale)?;
            if p.identity != b || !p.started {
                return Err(DomainError::Stale);
            }
            p.close_sent = true;
        }
        wire::TRACE => {
            let p = s.origin.ok_or(DomainError::Stale)?;
            let mut r = Reader::new(body);
            let hash: [u8; 32] = r.array().map_err(domain)?;
            let offset = r.u64().map_err(domain)? as usize;
            let count = r.u64().map_err(domain)? as usize;
            if hash != p.identity.hash().map_err(domain)?
                || count == 0
                || count > wire::CHUNK_INTERVALS
            {
                return Err(DomainError::Format);
            }
            let mut values = [EMPTY_INTERVAL; wire::CHUNK_INTERVALS];
            for value in &mut values[..count] {
                *value = wire::decode_interval(r.take(wire::INTERVAL_BYTES).map_err(domain)?)
                    .map_err(domain)?;
            }
            r.end().map_err(domain)?;
            let assembler = s.assembler.as_mut().ok_or(DomainError::Stale)?;
            assembler.append(offset, &values[..count]).map_err(domain)?;
            for (i, value) in values[..count].iter().copied().enumerate() {
                unsafe {
                    stored(offset + i).write(value);
                }
            }
        }
        wire::SEALED => {
            let p = s.origin.ok_or(DomainError::Stale)?;
            let seal = TraceSeal::decode(body).map_err(domain)?;
            if s.origin_failure
                .is_some_and(|f| !f.after_closing(seal.coverage.closing_ns))
            {
                return Err(DomainError::Conflict);
            }
            if seal.frozen_other_domains != p.frozen {
                return Err(DomainError::Conflict);
            }
            s.assembler
                .as_mut()
                .ok_or(DomainError::Stale)?
                .finish(seal)
                .map_err(domain)?;
            s.seal = Some(PartnerEvidence {
                binding: p.identity,
                seal,
                exclusion: None,
            });
        }
        wire::EXCLUDED => {
            let p = s.origin.ok_or(DomainError::Stale)?;
            let excluded = wire::ExcludedSeal::decode(body).map_err(domain)?;
            if excluded.exclusion.failure != s.origin_failure
                && !s.origin_failure.is_some_and(|f| {
                    excluded.exclusion.failure.is_none()
                        && f.after_closing(excluded.trace.coverage.closing_ns)
                })
            {
                return Err(DomainError::Conflict);
            }
            if excluded.trace.frozen_other_domains != p.frozen {
                return Err(DomainError::Conflict);
            }
            s.assembler
                .as_mut()
                .ok_or(DomainError::Stale)?
                .finish_excluded(excluded)
                .map_err(domain)?;
            s.seal = Some(PartnerEvidence {
                binding: p.identity,
                seal: excluded.trace,
                exclusion: Some(excluded.exclusion),
            });
        }
        wire::ABORT_PREPARED => {
            let b = Binding::decode(body).map_err(domain)?;
            if s.participant
                .is_some_and(|p| p.identity == b && !p.started && p.scope.is_none())
            {
                s.abort_peer = true;
            } else if let Some(hold) = s.pair_hold.filter(|p| p.identity == b) {
                s.participant = Some(hold);
                s.pair_hold = None;
                s.abort_peer = true;
            } else {
                return Err(DomainError::Stale);
            }
        }
        wire::PREPARED_ABORTED => {
            let seal = wire::PreparationSeal::decode(body).map_err(domain)?;
            if s.abort_for.is_none() || s.abort_binding != Some(seal.binding) {
                return Err(DomainError::Stale);
            }
            if seal.failure != s.origin_failure {
                return Err(DomainError::Conflict);
            }
            let prior = s
                .origin_hold
                .map(|p| p.identity.hash())
                .transpose()
                .map_err(domain)?
                .unwrap_or([0; 32]);
            if seal.prior_sealed_binding != prior {
                return Err(DomainError::Conflict);
            }
            if s.origin
                .is_some_and(|p| p.ready && p.frozen != seal.frozen_other_domains)
            {
                return Err(DomainError::Conflict);
            }
            if s.out
                .as_ref()
                .is_some_and(|o| o.kind == wire::ABORT_PREPARED)
            {
                s.out = None;
            }
            s.abort_complete = true;
        }
        wire::RELEASE => {
            if body.len() != wire::BINDING_BYTES + 8 {
                return Err(DomainError::Format);
            }
            let b = Binding::decode(&body[..wire::BINDING_BYTES]).map_err(domain)?;
            let keep = match u64::from_le_bytes(body[wire::BINDING_BYTES..].try_into().unwrap()) {
                0 => false,
                1 => true,
                _ => return Err(DomainError::Format),
            };
            let p = s.participant.as_mut().ok_or(DomainError::Stale)?;
            if p.identity != b || !s.seal_sent {
                return Err(DomainError::Stale);
            }
            if keep && (!b.baseline || s.export_excluded)
                || p.keep_pair.is_some_and(|old| old != keep)
            {
                return Err(DomainError::Conflict);
            }
            p.keep_pair = Some(keep);
            s.participant_release = true;
        }
        wire::RELEASED => {
            let b = Binding::decode(body).map_err(domain)?;
            let p = s.origin.as_mut().ok_or(DomainError::Stale)?;
            if p.identity != b || s.seal.is_none() {
                return Err(DomainError::Stale);
            }
            p.released = true;
        }
        _ => return Err(DomainError::Unsupported),
    }
    Ok(())
}

pub fn broker(
    phase: u64,
    token: u64,
    payload: &mut [u8; 4096],
    len: usize,
    connected: bool,
    epoch: u64,
) -> (u64, usize, u64) {
    let result = (|| {
        cpu0()?;
        if !connected || epoch == 0 {
            return Err(DomainError::NotReady);
        }
        with(|s| {
            if s.epoch != epoch {
                return Err(DomainError::Stale);
            }
            match phase {
                21 => {
                    if s.hello_sent.is_none()
                        || s.session.is_none()
                            && s.hello_sent
                                .is_some_and(|at| now().saturating_sub(at) >= 100_000_000)
                    {
                        return hello(s, payload);
                    }
                    if let Some(sequence) = s.ack.take() {
                        let h = header(s, wire::ACK)?;
                        let n = s
                            .keys
                            .encode(h, &sequence.to_le_bytes(), payload)
                            .map_err(domain)?;
                        return Ok((n, h.sequence));
                    }
                    let out = s.out.as_mut().ok_or(DomainError::Again)?;
                    if out
                        .last_sent
                        .is_some_and(|at| now().saturating_sub(at) < 100_000_000)
                    {
                        return Err(DomainError::Again);
                    }
                    payload[..out.len].copy_from_slice(&out.bytes[..out.len]);
                    Ok((out.len, out.sequence))
                }
                22 => {
                    receive(s, &payload[..len])?;
                    Ok((0, 0))
                }
                23 => {
                    if let Some(o) = s.out.as_mut().filter(|o| o.sequence == token) {
                        o.last_sent = Some(now());
                    }
                    Ok((0, 0))
                }
                25 => {
                    let request = s
                        .requests
                        .iter()
                        .flatten()
                        .find(|r| r.result.is_none())
                        .ok_or(DomainError::Again)?;
                    encode_work(request.work, payload).map(|n| (n, 0))
                }
                26 => {
                    let mut r = Reader::new(&payload[..len]);
                    let run = read_run(&mut r)?;
                    let result = read_result(&mut r)?;
                    r.end().map_err(domain)?;
                    complete_work(s, run, result)?;
                    Ok((0, 0))
                }
                29 => {
                    if len != 32 {
                        return Err(DomainError::Format);
                    }
                    let mut r = Reader::new(&payload[..len]);
                    let values = [
                        r.u64().map_err(domain)?,
                        r.u64().map_err(domain)?,
                        r.u64().map_err(domain)?,
                        r.u64().map_err(domain)?,
                    ];
                    s.service_idle = values == [0; 4];
                    s.service_at = now();
                    Ok((0, 0))
                }
                30 => {
                    bind_task(s, &payload[..len])?;
                    Ok((0, 0))
                }
                _ => Err(DomainError::Unsupported),
            }
        })
    })();
    match result {
        Ok((n, value)) => (0, n, value),
        Err(DomainError::Busy | DomainError::Again | DomainError::NotReady) => (1, 0, 0),
        Err(DomainError::NotFound | DomainError::Stale) => (4, 0, 0),
        Err(_) => (3, 0, 0),
    }
}
fn read_run(r: &mut Reader<'_>) -> Result<RunKey, DomainError> {
    Ok(RunKey {
        boot_epoch: r.u64().map_err(domain)?,
        trial_id: r.u64().map_err(domain)?,
        generation: r.u64().map_err(domain)?,
    })
}
fn encode_work(work: Work, bytes: &mut [u8]) -> Result<usize, DomainError> {
    let mut w = Writer::new(bytes);
    for v in [
        work.run.boot_epoch,
        work.run.trial_id,
        work.run.generation,
        work.id,
        work.family as u64,
        work.kind as u64,
        work.arrived_ns,
        work.deadline_ns,
        work.seed,
    ] {
        w.u64(v).map_err(domain)?;
    }
    Ok(w.at)
}
fn read_result(r: &mut Reader<'_>) -> Result<WorkResult, DomainError> {
    let result = WorkResult {
        id: r.u64().map_err(domain)?,
        outcome: r.u64().map_err(domain)?,
        target: ObjectKey {
            id: r.u64().map_err(domain)?,
            generation: r.u64().map_err(domain)?,
        },
        started_ns: r.u64().map_err(domain)?,
        finished_ns: r.u64().map_err(domain)?,
    };
    if !(1..=3).contains(&result.outcome) || result.started_ns > result.finished_ns {
        return Err(DomainError::Format);
    }
    Ok(result)
}
fn write_result(result: WorkResult, w: &mut Writer<'_>) -> Result<(), DomainError> {
    for v in [
        result.id,
        result.outcome,
        result.target.id,
        result.target.generation,
        result.started_ns,
        result.finished_ns,
    ] {
        w.u64(v).map_err(domain)?;
    }
    Ok(())
}
fn complete_work(s: &mut State, run: RunKey, result: WorkResult) -> Result<(), DomainError> {
    let index = result.id.checked_sub(1).ok_or(DomainError::Range)? as usize;
    let request = s
        .requests
        .get_mut(index)
        .and_then(Option::as_mut)
        .ok_or(DomainError::NotFound)?;
    if request.work.run != run
        || result.started_ns < request.work.arrived_ns
        || result.finished_ns > now()
    {
        return Err(DomainError::Stale);
    }
    if request.result.is_some_and(|old| old != result) {
        return Err(DomainError::Conflict);
    }
    request.result = Some(result);
    Ok(())
}
pub fn local_ready() -> Result<(Endpoint, Endpoint, [u8; 32]), DomainError> {
    with(|s| {
        Ok((
            s.local,
            s.remote.ok_or(DomainError::NotReady)?.endpoint,
            s.session.ok_or(DomainError::NotReady)?,
        ))
    })
}
pub fn local_idle() -> Result<bool, DomainError> {
    with(|s| {
        Ok(s.service_idle
            && now().saturating_sub(s.service_at) <= 100_000_000
            && crate::unified_task::replay_idle())
    })
}
pub fn fixture_stop_authorized(token: root::Token) -> bool {
    with(|s| {
        Ok(s.spectator == Some(token)
            && s.participant.is_some_and(|p| {
                p.identity.family
                    == (Family {
                        domain: 16,
                        kind: 2,
                    })
                    && (s.abort_peer
                        || p.close_sent
                            && (!p.identity.baseline
                                || s.participant_failure.is_some()
                                || s.participant_release && p.keep_pair == Some(false)))
            }))
    })
    .unwrap_or(false)
}
fn replay_key(run: RunKey, id: u64, node: [u8; 32], boot: u64) -> ObjectKey {
    let mut h = Sha256::new();
    h.update(b"CYXIA_REAL_PEER_WORK_1.3\0");
    for v in [run.boot_epoch, run.trial_id, run.generation, id] {
        h.update(v.to_le_bytes());
    }
    h.update(node);
    let hash: [u8; 32] = h.finalize().into();
    ObjectKey {
        id: u64::from_le_bytes(hash[..8].try_into().unwrap()).max(1),
        generation: boot,
    }
}
fn read_task(r: &mut Reader<'_>) -> Result<TaskBinding, DomainError> {
    Ok(TaskBinding {
        key: ObjectKey {
            id: r.u64().map_err(domain)?,
            generation: r.u64().map_err(domain)?,
        },
        contract: r.array().map_err(domain)?,
        input: r.array().map_err(domain)?,
        package: r.array().map_err(domain)?,
        sequence: 0,
        acknowledged: false,
        token: None,
        closed: false,
    })
}
fn validate_task(task: TaskBinding, binding: Binding, id: u64) -> Result<(), DomainError> {
    if task.contract == [0; 16]
        || task.input
            != <[u8; 32]>::from(Sha256::digest(work_wire::payload(binding.group.seed, id).0))
        || task.package != crate::unified_task::package_digest()
    {
        return Err(DomainError::Conflict);
    }
    Ok(())
}
fn bind_task(s: &mut State, bytes: &[u8]) -> Result<(), DomainError> {
    let mut r = Reader::new(bytes);
    let task = read_task(&mut r)?;
    r.end().map_err(domain)?;
    let selected = if let Some(p) = s.participant.filter(|p| {
        p.started
            && p.identity.family
                == (Family {
                    domain: 16,
                    kind: 1,
                })
    }) {
        s.requests
            .iter()
            .flatten()
            .find(|v| {
                v.result.is_none()
                    && replay_key(v.work.run, v.work.id, s.local.node, s.local.boot) == task.key
            })
            .map(|v| (p.identity, v.work.id))
    } else {
        s.origin
            .filter(|p| {
                p.started
                    && p.identity.family
                        == (Family {
                            domain: 16,
                            kind: 2,
                        })
                    && p.identity.target == task.key
            })
            .map(|p| (p.identity, 1))
    };
    let (binding, id) = selected.ok_or(DomainError::NotFound)?;
    validate_task(task, binding, id)?;
    let index = id as usize - 1;
    if let Some(old) = s.tasks[index] {
        if old.key != task.key
            || old.contract != task.contract
            || old.input != task.input
            || old.package != task.package
        {
            return Err(DomainError::Conflict);
        }
        return if old.acknowledged {
            Ok(())
        } else {
            Err(DomainError::Again)
        };
    }
    if s.out.is_some() {
        return Err(DomainError::Busy);
    }
    let mut body = [0; 136];
    let mut w = Writer::new(&mut body);
    w.bytes(&binding.hash().map_err(domain)?).map_err(domain)?;
    w.u64(id).map_err(domain)?;
    w.bytes(bytes).map_err(domain)?;
    s.tasks[index] = Some(task);
    if let Err(error) = queue(s, wire::TASK_BIND, &body) {
        s.tasks[index] = None;
        return Err(error);
    }
    Err(DomainError::Again)
}
/// Actual resource admission binds its fresh monotone token to the previously
/// kernel-signed immutable intent. No thread-id-only alias enters a scope.
pub fn accept_remote(
    contract: [u8; 16],
    input: [u8; 32],
    package: [u8; 32],
    token: u64,
) -> Result<(), DomainError> {
    let (participant, mapping) = with(|s| {
        let relevant = s.origin.is_some_and(|p| {
            p.started
                && p.identity.family
                    == (Family {
                        domain: 16,
                        kind: 1,
                    })
        }) || s.participant.is_some_and(|p| {
            p.started
                && p.identity.family
                    == (Family {
                        domain: 16,
                        kind: 2,
                    })
        });
        if !relevant {
            return Ok((false, None));
        }
        let (index, task) = s
            .tasks
            .iter_mut()
            .enumerate()
            .find_map(|(i, t)| {
                t.as_mut()
                    .filter(|t| t.contract == contract && t.input == input && t.package == package)
                    .map(|t| (i, t))
            })
            .ok_or(DomainError::Again)?;
        if task.token.is_some_and(|old| old != token) || task.closed {
            return Err(DomainError::Conflict);
        }
        task.token = Some(token);
        Ok((
            s.participant.is_some(),
            s.origin.map(|p| (index, p.identity.run)),
        ))
    })?;
    if participant {
        ledger_with(|l| l.register_remote(token)).map_err(|e| {
            if e == learning::Error::Unknown {
                DomainError::Busy
            } else {
                DomainError::Conflict
            }
        })?;
    }
    if let Some((index, run)) = mapping {
        let map = MAP_ADDRESS.load(Ordering::Acquire) as *const AtomicU64;
        if map.is_null() {
            return Err(DomainError::NotReady);
        }
        for (field, value) in [run.boot_epoch, run.trial_id, run.generation]
            .into_iter()
            .enumerate()
        {
            unsafe { &*map.add(index * 4 + field) }.store(value, Ordering::Relaxed);
        }
        unsafe { &*map.add(index * 4 + 3) }.store(token, Ordering::Release);
    }
    Ok(())
}
pub fn abort_remote(token: u64) {
    let _ = with(|s| {
        for task in s
            .tasks
            .iter_mut()
            .flatten()
            .filter(|t| t.token == Some(token) && !t.closed)
        {
            task.token = None;
        }
        Ok(())
    });
}
pub fn close_remote(token: u64) -> Result<(), DomainError> {
    with(|s| {
        for task in s
            .tasks
            .iter_mut()
            .flatten()
            .filter(|t| t.token == Some(token))
        {
            task.closed = true;
        }
        Ok(())
    })
}
pub fn source_for(run: RunKey, key: ObjectKey) -> Result<Option<ObjectKey>, learning::Error> {
    if key.id != 0x100 {
        return Ok(None);
    }
    let map = MAP_ADDRESS.load(Ordering::Acquire) as *const AtomicU64;
    if map.is_null() {
        return Ok(None);
    }
    for index in 0..REQUESTS {
        let stamp = unsafe { &*map.add(index * 4 + 3) };
        if stamp.load(Ordering::Acquire) != key.generation {
            continue;
        }
        let values = core::array::from_fn::<_, 3, _>(|field| {
            unsafe { &*map.add(index * 4 + field) }.load(Ordering::Relaxed)
        });
        if stamp.load(Ordering::Acquire) != key.generation {
            return Err(learning::Error::Unknown);
        }
        if values != [run.boot_epoch, run.trial_id, run.generation] {
            return Err(learning::Error::Stale);
        }
        return Ok(Some(REMOTE_WORK_OWNER));
    }
    Ok(None)
}
pub fn prepare(
    family: Family,
    seed: u64,
    kind: TrialKind,
    group: ReplayGroup,
    target: ObjectKey,
) -> Result<bool, DomainError> {
    mechanism()?;
    with(|s| {
        if s.participant.is_some()
            || s.pair_hold.is_some()
            || s.declined.is_some()
            || now() < s.retry_at
        {
            return Err(DomainError::Busy);
        }
        // Conflict means the preparation is terminal, not transport Busy. The
        // original error, even Failed(Busy), remains in the signed failure.
        if s.origin_failure.is_some() {
            return Err(DomainError::Conflict);
        }
        if let Some(p) = s.origin {
            return if p.identity.family == family
                && p.identity.group == group
                && p.identity.baseline == (kind == TrialKind::Baseline)
                && p.identity.target == target
            {
                Ok(p.ready)
            } else {
                Err(DomainError::Busy)
            };
        }
        let peer = s.remote.ok_or(DomainError::NotReady)?.endpoint;
        let session = s.session.ok_or(DomainError::NotReady)?;
        s.serial = s.serial.checked_add(1).ok_or(DomainError::Overflow)?;
        let mut h = Sha256::new();
        h.update(b"CYXIA_PEER_PREPARATION_1.3\0");
        h.update(group.workload);
        h.update(group.initial_image);
        h.update(seed.to_le_bytes());
        let identity = Binding {
            origin: s.local,
            participant: peer,
            session,
            run: RunKey {
                boot_epoch: s.local.boot,
                trial_id: s.serial,
                generation: s.serial,
            },
            family,
            baseline: kind == TrialKind::Baseline,
            owner: OWNER,
            target,
            group,
            frozen_scope_hash: h.finalize().into(),
        };
        queue_binding(s, wire::FREEZE, identity, &[])?;
        s.origin = Some(Preparation {
            identity,
            reservation_binding: identity,
            ready: false,
            frozen: [0; 32],
            scope: None,
            reservation: identity.run.trial_id,
            start_issued: false,
            started: false,
            start_reported: false,
            observing: false,
            close_sent: false,
            released: false,
            keep_pair: None,
        });
        s.results.fill(None);
        s.issued.fill(false);
        s.tasks.fill(None);
        s.seal = None;
        s.seal_packet_len = 0;
        s.assembler = None;
        s.fault = None;
        Ok(false)
    })
}
pub fn bind_scope(scope: &FrozenScope) -> Result<(), DomainError> {
    with(|s| {
        if s.origin_failure.is_some() {
            return Err(DomainError::Conflict);
        }
        let p = s.origin.as_mut().ok_or(DomainError::NotReady)?;
        if !p.ready
            || p.identity.group != scope.group
            || p.identity.family != scope.family
            || p.identity.target != scope.target
            || p.identity.baseline != (scope.kind == TrialKind::Baseline)
            || scope.key.boot_epoch != s.local.boot
        {
            return Err(DomainError::Conflict);
        }
        if p.scope.is_some_and(|old| old != *scope) {
            return Err(DomainError::Conflict);
        }
        p.scope = Some(*scope);
        p.identity.run = scope.key;
        p.identity.frozen_scope_hash = scope.frozen_scope_hash;
        Ok(())
    })
}
pub fn start(run: RunKey) -> Result<bool, DomainError> {
    mechanism()?;
    with(|s| {
        if s.abort_for.is_some() {
            return Err(DomainError::Conflict);
        }
        let p = s.origin.ok_or(DomainError::NotReady)?;
        let scope = p.scope.ok_or(DomainError::NotReady)?;
        if p.identity.run != run {
            return Err(DomainError::Stale);
        }
        if p.started {
            return Ok(true);
        }
        if s.assembler.is_none() {
            s.assembler = Some(wire::Assembler::new(p.identity).map_err(domain)?);
        }
        if s.out.is_none() {
            queue_binding(
                s,
                wire::START,
                p.identity,
                &scope.observation_ns.saturating_sub(now()).to_le_bytes(),
            )?;
            s.origin.as_mut().ok_or(DomainError::Stale)?.start_issued = true;
        }
        Ok(false)
    })
}
pub fn take_work() -> Result<Option<Work>, DomainError> {
    with(|s| {
        Ok(s.requests
            .iter()
            .flatten()
            .find(|r| r.result.is_none())
            .map(|r| r.work))
    })
}
pub fn finish_work(run: RunKey, result: WorkResult) -> Result<(), DomainError> {
    cpu0()?;
    with(|s| complete_work(s, run, result))
}
/// Submit exactly one already frozen remote business request, preserving its
/// original id through transport loss. The caller owns logical arrival time.
pub fn submit_work(run: RunKey, id: u64) -> Result<(), DomainError> {
    mechanism()?;
    with(|s| {
        let p = s.origin.ok_or(DomainError::NotReady)?;
        if !p.started
            || p.close_sent
            || p.identity.run != run
            || !(1..REQUESTS as u64).contains(&id)
        {
            return Err(DomainError::Stale);
        }
        if id <= 100 && !p.observing {
            return Err(DomainError::Again);
        }
        if s.issued[id as usize - 1] {
            return Ok(());
        }
        let mut bytes = [0; 40];
        bytes[..32].copy_from_slice(&p.identity.hash().map_err(domain)?);
        bytes[32..].copy_from_slice(&id.to_le_bytes());
        queue(s, wire::WORK, &bytes)?;
        s.issued[id as usize - 1] = true;
        Ok(())
    })
}
pub fn work_result(run: RunKey, id: u64) -> Result<Option<WorkResult>, DomainError> {
    with(|s| {
        if s.origin.is_none_or(|p| p.identity.run != run) || !(1..REQUESTS as u64).contains(&id) {
            return Err(DomainError::Stale);
        }
        Ok(s.results[id as usize - 1])
    })
}
pub fn close(run: RunKey) -> Result<bool, DomainError> {
    mechanism()?;
    with(|s| {
        let p = s.origin.ok_or(DomainError::NotReady)?;
        if p.identity.run != run {
            return Err(DomainError::Stale);
        }
        if s.seal.is_some() {
            return Ok(true);
        }
        if !p.close_sent && s.out.is_none() {
            queue_binding(s, wire::CLOSE, p.identity, &[])?;
            s.origin.as_mut().unwrap().close_sent = true;
        }
        Ok(false)
    })
}
pub fn release(run: RunKey) -> Result<bool, DomainError> {
    mechanism()?;
    with(|s| {
        let p = s.origin.ok_or(DomainError::NotReady)?;
        if p.identity.run != run || s.seal.is_none() {
            return Err(DomainError::Stale);
        }
        if p.released && s.out.is_none() {
            if late_receipt(s, run)?
                .is_some_and(|v| s.archived_late != Some((v.key, v.packet_hash)))
            {
                return Ok(false);
            }
            s.origin_hold = if p.keep_pair == Some(true) {
                Some(p)
            } else {
                None
            };
            if p.keep_pair != Some(true) {
                s.origin_failure = None;
                s.failure_packet_len = 0;
            }
            s.origin = None;
            s.assembler = None;
            s.seal = None;
            s.seal_packet_len = 0;
            return Ok(true);
        }
        let keep = p.keep_pair.ok_or(DomainError::NotReady)?;
        if s.out.is_none() {
            queue_binding(s, wire::RELEASE, p.identity, &u64::from(keep).to_le_bytes())?;
        }
        Ok(false)
    })
}
/// The producer decides only after validating and archiving its own trial.
/// A rejected local baseline must not leave its partner frozen for a candidate
/// that will never be issued.
pub fn set_pair_continuation(run: RunKey, keep: bool) -> Result<(), DomainError> {
    cpu0()?;
    with(|s| {
        let p = s.origin.as_mut().ok_or(DomainError::NotReady)?;
        let seal = s.seal.ok_or(DomainError::NotReady)?;
        if p.identity.run != run
            || seal.binding.run != run
            || keep && (!p.identity.baseline || seal.exclusion.is_some())
        {
            return Err(DomainError::Auth);
        }
        if p.keep_pair.is_some_and(|old| old != keep) {
            return Err(DomainError::Conflict);
        }
        p.keep_pair = Some(keep);
        Ok(())
    })
}
fn retained_partner_raw(run: RunKey) -> Result<PartnerEvidence, DomainError> {
    with(|s| {
        let seal = s.seal.ok_or(DomainError::NotReady)?;
        if seal.binding.run != run || s.fault.is_some() {
            return Err(DomainError::Stale);
        }
        Ok(seal)
    })
}
pub fn retained_partner(run: RunKey) -> Result<PartnerEvidence, learning::Error> {
    retained_partner_raw(run).map_err(learn)
}
fn late_receipt(s: &State, run: RunKey) -> Result<Option<LateFailureReceipt>, DomainError> {
    let p = s.origin.ok_or(DomainError::Stale)?;
    if p.identity.run != run {
        return Err(DomainError::Stale);
    }
    let Some(failure) = s.origin_failure else {
        return Ok(None);
    };
    let Some(seal) = s.seal else {
        return Ok(None);
    };
    if !failure.after_closing(seal.seal.coverage.closing_ns) {
        return Ok(None);
    }
    if seal.binding != p.identity
        || s.failure_packet_len != wire::ROOT_FAILURE_PACKET_BYTES
        || s.failure_packet_sequence == 0
        || s.failure_packet_hash == [0; 32]
    {
        return Err(DomainError::Stale);
    }
    let notice = wire::RootFailure::decode(
        &s.failure_packet[wire::HEADER_BYTES..s.failure_packet_len - wire::SIGNATURE_BYTES],
    )
    .map_err(domain)?;
    if notice.binding != p.identity || notice.failure != failure {
        return Err(DomainError::Conflict);
    }
    Ok(Some(LateFailureReceipt {
        key: run,
        binding: notice.binding,
        failure,
        packet_hash: s.failure_packet_hash,
        packet_bytes: s.failure_packet_len,
        sequence: s.failure_packet_sequence,
        closing_ns: seal.seal.coverage.closing_ns,
    }))
}
pub fn late_failure(run: RunKey) -> Result<Option<LateFailureReceipt>, DomainError> {
    with(|s| Ok(late_receipt(s, run)?.filter(|v| s.archived_late != Some((v.key, v.packet_hash)))))
}
pub fn copy_late_packet(
    receipt: LateFailureReceipt,
    offset: usize,
    out: &mut [u8],
) -> Result<usize, DomainError> {
    if out.len() > 256 {
        return Err(DomainError::Capacity);
    }
    with(|s| {
        if late_receipt(s, receipt.key)? != Some(receipt) || offset > receipt.packet_bytes {
            return Err(DomainError::Stale);
        }
        let count = out.len().min(receipt.packet_bytes - offset);
        out[..count].copy_from_slice(&s.failure_packet[offset..offset + count]);
        Ok(count)
    })
}
pub fn late_archived(
    export: crate::learning_replay::late_archive::Export,
) -> Result<(), DomainError> {
    let receipt = export.receipt();
    if export.digest() == [0; 32] {
        return Err(DomainError::Auth);
    }
    with(|s| {
        if s.archived_late == Some((receipt.key, receipt.packet_hash)) {
            return Ok(());
        }
        if late_receipt(s, receipt.key)? != Some(receipt) {
            return Err(DomainError::Stale);
        }
        s.archived_late = Some((receipt.key, receipt.packet_hash));
        Ok(())
    })
}
pub fn partner(run: RunKey) -> Result<PartnerSeal, learning::Error> {
    let evidence = retained_partner(run)?;
    if evidence.exclusion.is_some() {
        return Err(learning::Error::DataIncomplete);
    }
    Ok(PartnerSeal {
        binding: evidence.binding,
        seal: evidence.seal,
    })
}
pub fn partner_bounded(run: RunKey) -> Result<Option<PartnerSeal>, learning::Error> {
    let evidence = match retained_partner_raw(run) {
        Ok(value) => value,
        Err(DomainError::Busy) => return Ok(None),
        Err(error) => return Err(learn(error)),
    };
    if evidence.exclusion.is_some() {
        return Err(learning::Error::DataIncomplete);
    }
    Ok(Some(PartnerSeal {
        binding: evidence.binding,
        seal: evidence.seal,
    }))
}
pub fn copy_intervals(
    run: RunKey,
    offset: usize,
    out: &mut [CpuInterval],
) -> Result<usize, learning::Error> {
    if out.len() > wire::CHUNK_INTERVALS {
        return Err(learning::Error::Capacity);
    }
    copy_intervals_raw(run, offset, out).map_err(learn)
}
pub fn copy_intervals_bounded(
    run: RunKey,
    offset: usize,
    out: &mut [CpuInterval],
) -> Result<Option<usize>, learning::Error> {
    if out.len() > wire::CHUNK_INTERVALS {
        return Err(learning::Error::Capacity);
    }
    match copy_intervals_raw(run, offset, out) {
        Ok(count) => Ok(Some(count)),
        Err(DomainError::Busy) => Ok(None),
        Err(error) => Err(learn(error)),
    }
}
fn copy_intervals_raw(
    run: RunKey,
    offset: usize,
    out: &mut [CpuInterval],
) -> Result<usize, DomainError> {
    with(|s| {
        let p = s.seal.ok_or(DomainError::NotReady)?;
        if p.binding.run != run || offset > p.seal.count as usize {
            return Err(DomainError::Stale);
        }
        let n = out.len().min(p.seal.count as usize - offset);
        for (i, value) in out[..n].iter_mut().enumerate() {
            *value = unsafe { stored(offset + i).read() };
        }
        Ok(n)
    })
}
fn seal_packet_length(seal: PartnerEvidence, bytes: usize) -> bool {
    bytes == seal.packet_bytes()
        || seal.exclusion.is_some_and(|e| e.failure.is_none())
            && bytes == wire::EXCLUDED_PACKET_BYTES - wire::FAILURE_BYTES
}
pub fn seal_packet_bytes(run: RunKey) -> Result<usize, learning::Error> {
    with(|s| {
        if s.seal
            .is_none_or(|p| p.binding.run != run || !seal_packet_length(p, s.seal_packet_len))
        {
            return Err(DomainError::Stale);
        }
        Ok(s.seal_packet_len)
    })
    .map_err(learn)
}
pub fn copy_seal_packet(
    run: RunKey,
    offset: usize,
    out: &mut [u8],
) -> Result<usize, learning::Error> {
    if out.len() > 256 {
        return Err(learning::Error::Capacity);
    }
    with(|s| {
        if s.seal
            .is_none_or(|p| p.binding.run != run || !seal_packet_length(p, s.seal_packet_len))
            || offset > s.seal_packet_len
        {
            return Err(DomainError::Stale);
        }
        let n = out.len().min(s.seal_packet_len - offset);
        out[..n].copy_from_slice(&s.seal_packet[offset..offset + n]);
        Ok(n)
    })
    .map_err(learn)
}
pub fn attest(
    run: RunKey,
    intervals: &[CpuInterval],
    coverage: CpuCoverage,
) -> Result<(), learning::Error> {
    with(|s| {
        let p = s.seal.ok_or(DomainError::NotReady)?;
        if p.binding.run != run
            || p.exclusion.is_some()
            || p.seal.coverage != coverage
            || p.seal.count as usize != intervals.len()
            || s.fault.is_some()
        {
            return Err(DomainError::Conflict);
        }
        for (i, value) in intervals.iter().enumerate() {
            if *value != unsafe { stored(i).read() } {
                return Err(DomainError::Conflict);
            }
        }
        Ok(())
    })
    .map_err(learn)
}
pub fn settled(token: root::Token) -> Result<(), DomainError> {
    let aborting = with(|s| Ok(s.spectator == Some(token) && s.abort_peer))?;
    if aborting {
        let _ = cancellation_ready()?;
        return Ok(());
    }
    with(|s| {
        if s.spectator != Some(token)
            || !s.participant_release
            || !s.seal_sent
            || s.out.is_some()
            || s.requests
                .iter()
                .flatten()
                .any(|r| r.result.is_none() || !r.reported)
        {
            return Err(DomainError::Busy);
        }
        Ok(())
    })?;
    ledger_with(|l| {
        if l.open == 0 && (l.sealed.is_some() || l.excluded.is_some()) {
            Ok(())
        } else {
            Err(learning::Error::Unknown)
        }
    })
    .map_err(|_| DomainError::Busy)
}
/// Root calls this while locked; this proof reads only peer/ledger gates.
/// A fault does not waive any real credit, task, result or signed export.
pub fn faulted_settled(token: root::Token, error: DomainError) -> Result<(), DomainError> {
    let failure = with(|s| {
        let f = s.participant_failure.ok_or(DomainError::Busy)?;
        if s.spectator != Some(token)
            || f.root_token != token.id
            || f.error != error as u64 + 1
            || !s.participant_release
            || !s.seal_sent
            || s.out.is_some()
            || s.failure_sent_for != s.participant.map(|p| p.identity)
            || s.requests
                .iter()
                .flatten()
                .any(|r| r.result.is_none() || !r.reported)
            || s.tasks
                .iter()
                .flatten()
                .any(|t| t.token.is_some() && !t.closed)
        {
            return Err(DomainError::Busy);
        }
        Ok(f)
    })?;
    ledger_with(|l| {
        if l.open == 0
            && (l
                .excluded
                .is_some_and(|e| e.exclusion.failure == Some(failure))
                || l.sealed
                    .map(|v| v.coverage.closing_ns)
                    .or_else(|| l.excluded.map(|v| v.trace.coverage.closing_ns))
                    .is_some_and(|closing| failure.after_closing(closing)))
        {
            Ok(())
        } else {
            Err(learning::Error::Unknown)
        }
    })
    .map_err(|_| DomainError::Busy)
}

/// Begin a signed cancellation of actual pre-capture peer custody. Keeping a
/// prior baseline frozen counts as custody even before a candidate FREEZE was
/// transmitted. A started candidate can never enter this path.
pub fn abort_prepared(preparation: root::Preparation) -> Result<bool, DomainError> {
    abort_inactive(preparation, None)
}
pub fn abort_unactivated(
    preparation: root::Preparation,
    scope: &FrozenScope,
) -> Result<bool, DomainError> {
    if scope.key.boot_epoch != preparation.boot_epoch
        || scope.key.trial_id != preparation.trial_id
        || scope.family != preparation.family
        || scope.group.seed != preparation.seed
        || scope.kind != preparation.kind
    {
        return Err(DomainError::Conflict);
    }
    abort_inactive(preparation, Some(scope))
}
fn abort_inactive(
    preparation: root::Preparation,
    scope: Option<&FrozenScope>,
) -> Result<bool, DomainError> {
    mechanism()?;
    with(|s| {
        if s.abort_for.is_some_and(|old| old != preparation) {
            return Err(DomainError::Busy);
        }
        if s.abort_for.is_none() {
            let current = s.origin.or(s.origin_hold);
            if let Some(p) = current {
                if p.identity.family != preparation.family
                    || p.identity.group.seed != preparation.seed
                {
                    return Err(DomainError::Stale);
                }
                if s.origin.is_none()
                    && (!p.identity.baseline || preparation.kind != TrialKind::Candidate)
                {
                    return Err(DomainError::Auth);
                }
                s.abort_binding = Some(if s.origin.is_some() {
                    if p.scope.is_some_and(|old| scope != Some(&old)) {
                        return Err(DomainError::Conflict);
                    }
                    if let Some(scope) = scope {
                        if p.identity.group != scope.group
                            || p.identity.target != scope.target
                            || p.identity.baseline != (scope.kind == TrialKind::Baseline)
                        {
                            return Err(DomainError::Conflict);
                        }
                    }
                    wire::preparation_abort_binding(
                        p.reservation_binding,
                        p.identity,
                        p.scope.map(|v| v.key),
                        scope.map(|v| v.key),
                        p.start_issued,
                        p.started,
                    )
                    .map_err(|e| {
                        if e == wire::Error::Incomplete {
                            DomainError::Busy
                        } else {
                            DomainError::Conflict
                        }
                    })?
                } else {
                    p.identity
                });
            }
            s.abort_for = Some(preparation);
            s.abort_complete = current.is_none();
        }
        if s.abort_complete {
            return Ok(true);
        }
        let binding = s.abort_binding.ok_or(DomainError::Stale)?;
        if s.origin.is_none() && s.origin_hold.is_none() && s.cancelled == Some(binding) {
            // Stable arbitration declined this unstarted reservation. No root
            // or workload ownership was ever granted for it.
            s.abort_complete = true;
            return Ok(true);
        }
        if s.out.is_none() {
            queue_binding(s, wire::ABORT_PREPARED, binding, &[])?;
        }
        Ok(false)
    })
}
pub fn prepared_packet_bytes(preparation: root::Preparation) -> Result<usize, DomainError> {
    with(|s| {
        if s.abort_for != Some(preparation) || !s.abort_complete {
            return Err(DomainError::Busy);
        }
        Ok(s.abort_packet_len)
    })
}
pub fn copy_prepared_packet(
    preparation: root::Preparation,
    offset: usize,
    out: &mut [u8],
) -> Result<usize, DomainError> {
    if out.len() > 256 {
        return Err(DomainError::Capacity);
    }
    with(|s| {
        if s.abort_for != Some(preparation) || !s.abort_complete || offset > s.abort_packet_len {
            return Err(DomainError::Stale);
        }
        let n = out.len().min(s.abort_packet_len - offset);
        out[..n].copy_from_slice(&s.abort_packet[offset..offset + n]);
        Ok(n)
    })
}
pub fn release_prepared(preparation: root::Preparation) -> Result<(), DomainError> {
    mechanism()?;
    with(|s| {
        if s.abort_for != Some(preparation) || !s.abort_complete {
            return Err(DomainError::Busy);
        }
        if s.origin.is_some_and(|p| p.started || p.start_issued) {
            return Err(DomainError::Conflict);
        }
        if s.out
            .as_ref()
            .is_some_and(|o| matches!(o.kind, wire::FREEZE | wire::START | wire::ABORT_PREPARED))
        {
            return Err(DomainError::Busy);
        }
        s.origin = None;
        s.origin_hold = None;
        s.abort_for = None;
        s.abort_binding = None;
        s.abort_complete = false;
        s.abort_packet_len = 0;
        s.seal = None;
        s.assembler = None;
        s.seal_packet_len = 0;
        s.origin_failure = None;
        s.failure_packet_len = 0;
        Ok(())
    })
}
fn cancellation_ready() -> Result<[u8; 32], DomainError> {
    let (p, held, unresolved, out, prior) = with(|s| {
        let p = s.participant.ok_or(DomainError::Stale)?;
        if !s.abort_peer {
            return Err(DomainError::Auth);
        }
        Ok((
            p,
            s.pair_hold.is_some(),
            s.requests
                .iter()
                .flatten()
                .any(|r| r.result.is_none() || !r.reported)
                || s.tasks
                    .iter()
                    .flatten()
                    .any(|t| t.token.is_some() && !t.closed),
            s.out.is_some(),
            s.prior_sealed,
        ))
    })?;
    if out {
        return Err(DomainError::Busy);
    }
    let _guard = lock(&LEDGER_GATE)?;
    let l = unsafe { &*LEDGER.0.get() };
    let open = l.as_ref().map_or(0, |l| l.open);
    let sealed = l
        .as_ref()
        .is_some_and(|l| l.sealed.is_some() || l.excluded.is_some());
    if !wire::preparation_cancellable(p.started, sealed, open, unresolved) || held && !sealed {
        return Err(DomainError::Busy);
    }
    if let Some(l) = l {
        if !sealed {
            return Err(DomainError::Busy);
        }
        l.binding.hash().map_err(domain)
    } else {
        Ok(prior)
    }
}
fn poll_prepared_abort(p: Preparation, token: Option<root::Token>) -> Result<(), DomainError> {
    if with(|s| Ok(s.abort_peer_receipt.is_some()))? {
        return finish_prepared_abort();
    }
    let prior = cancellation_ready()?;
    if let Some(token) = token {
        if ROOT_RELEASED.load(Ordering::Acquire) != token.id {
            if !root::release_spectator_prepared(token)? {
                return Ok(());
            }
            ROOT_RELEASED_AT.store(now(), Ordering::Release);
            ROOT_RELEASED.store(token.id, Ordering::Release);
        }
    }
    let at = if token.is_some() {
        ROOT_RELEASED_AT.load(Ordering::Acquire)
    } else {
        now()
    };
    with(|s| {
        if s.abort_peer_receipt.is_none() {
            s.abort_peer_receipt = Some(wire::PreparationSeal {
                binding: p.identity,
                drained_ns: at,
                frozen_other_domains: p.frozen,
                prior_sealed_binding: prior,
                failure: s.participant_failure,
            });
        }
        Ok(())
    })?;
    finish_prepared_abort()
}
fn finish_prepared_abort() -> Result<(), DomainError> {
    {
        let _guard = lock(&LEDGER_GATE)?;
        unsafe {
            *LEDGER.0.get() = None;
        }
    }
    crate::learning_replay::pause_for_peer(false)?;
    with(|s| {
        let seal = s.abort_peer_receipt.ok_or(DomainError::NotReady)?;
        let mut body = [0; wire::PREPARATION_SEAL_BYTES];
        let n = seal.encode(&mut body).map_err(domain)?;
        queue(s, wire::PREPARED_ABORTED, &body[..n])?;
        s.participant = None;
        s.pair_hold = None;
        s.spectator = None;
        s.participant_release = false;
        s.abort_peer = false;
        s.abort_peer_receipt = None;
        s.prior_sealed = [0; 32];
        s.participant_failure = None;
        s.failure_sent_for = None;
        ROOT_RELEASED.store(0, Ordering::Release);
        Ok(())
    })
}

/// Preserve the original root rejection once, then notify the origin through
/// the same signed, retransmitted outbox as the freeze protocol. A terminal
/// Busy is data here, not an instruction to retry the consumed PlanId.
fn propagate_root_failure(
    p: Preparation,
    token: root::Token,
    status: root::Status,
) -> Result<bool, DomainError> {
    let Some(error) = status.fault else {
        return Ok(false);
    };
    let retained = with(|s| Ok(s.participant_failure))?;
    let failure = if let Some(old) = retained {
        if old.root_token != token.id || old.error != error as u64 + 1 {
            return Err(DomainError::Conflict);
        }
        old
    } else {
        let rejected = root::spectator_rejected(token)?;
        if let Some(value) = rejected.filter(|v| {
            v.receipt().state() == cyxia_prototype::policy::ExecutionState::Failed(error)
        }) {
            wire::Failure::rejected(
                token.id,
                value.receipt(),
                value.snapshot(),
                value.target(),
                value.plan_hash(),
                value.received_ns(),
                value.observed_ns(),
                value.wall_deadline_ns(),
            )
            .map_err(domain)?
        } else {
            wire::Failure {
                root_token: token.id,
                error: error as u64 + 1,
                observed_ns: now(),
                publication: None,
            }
        }
    };
    with(|s| {
        if s.spectator != Some(token) {
            return Err(DomainError::Stale);
        }
        if s.participant_failure.is_some_and(|old| old != failure) {
            return Err(DomainError::Conflict);
        }
        s.participant_failure = Some(failure);
        Ok(())
    })?;
    // A sealed baseline hold keeps its original historical window. Its new
    // preparation failure is carried by the later signed cancellation, not
    // by rewriting the already sealed raw CPU evidence.
    if p.started {
        ledger_with(|l| {
            if l.closing.is_some() {
                Ok(())
            } else {
                l.fail(failure)
            }
        })
        .map_err(|e| {
            if e == learning::Error::Unknown {
                DomainError::Busy
            } else {
                DomainError::Conflict
            }
        })?;
    }
    with(|s| {
        if s.failure_sent_for != Some(p.identity) && s.out.is_none() {
            let notice = wire::RootFailure {
                binding: p.identity,
                failure,
            };
            let mut bytes = [0; wire::ROOT_FAILURE_BYTES];
            let len = notice.encode(&mut bytes).map_err(domain)?;
            queue(s, wire::ROOT_FAILED, &bytes[..len])?;
            s.failure_sent_for = Some(p.identity);
        }
        Ok(true)
    })
}

/// Called in an actual bounded CPU0 service piece. Root operations are outside
/// the transport gate: the settled callback acquires it in the reverse path.
pub fn poll() -> Result<(), DomainError> {
    mechanism()?;
    with(|s| {
        if s.out.is_none() {
            if let Some(binding) = s.declined {
                queue_binding(s, wire::DECLINED, binding, &[])?;
                s.declined = None;
            }
        }
        Ok(())
    })?;
    let pending = with(|s| {
        Ok((
            s.participant,
            s.spectator,
            s.participant_release,
            s.pair_hold,
            s.abort_peer,
        ))
    })?;
    let Some(p) = pending.0 else {
        if let (Some(token), Some(hold)) = (pending.1, pending.3) {
            let status = root::poll(token)?;
            propagate_root_failure(hold, token, status)?;
        }
        return Ok(());
    };
    if pending.4 {
        return poll_prepared_abort(p, pending.1);
    }
    if pending
        .1
        .is_some_and(|token| ROOT_RELEASED.load(Ordering::Acquire) == token.id)
    {
        return finish_participant_release(p);
    }
    if pending.3.is_some() {
        let token = pending.1.ok_or(DomainError::Stale)?;
        let status = root::poll(token)?;
        if propagate_root_failure(p, token, status)? {
            return Ok(());
        }
        if with(|s| Ok(s.out.is_some()))? {
            return Ok(());
        }
        let prior = pending
            .3
            .ok_or(DomainError::Stale)?
            .identity
            .hash()
            .map_err(domain)?;
        let token = root::advance_spectator(
            pending.1.ok_or(DomainError::Stale)?,
            p.identity.run.trial_id,
        )?;
        {
            let _guard = lock(&LEDGER_GATE)?;
            unsafe {
                *LEDGER.0.get() = None;
            }
        }
        with(|s| {
            s.spectator = Some(token);
            s.pair_hold = None;
            s.participant_release = false;
            s.prior_sealed = prior;
            s.requests.fill(None);
            s.results.fill(None);
            s.issued.fill(false);
            s.tasks.fill(None);
            s.trace_cursor = 0;
            s.seal_sent = false;
            s.export_excluded = false;
            s.fault = None;
            Ok(())
        })?;
        return Ok(());
    }
    if pending.1.is_none() {
        crate::learning_replay::pause_for_peer(true)?;
        if !crate::learning_replay::quiescent() {
            return Ok(());
        }
        if !local_idle()? {
            return Ok(());
        }
        let token = if p.identity.family
            == (Family {
                domain: 16,
                kind: 2,
            }) {
            root::reserve_spectator_with_fixture(
                OWNER,
                p.identity.run.trial_id,
                ObjectKey {
                    id: crate::unified::abi::OFFER_SERVICE_ID,
                    generation: 1,
                },
                Action::OfferCpu(100),
            )?
        } else {
            root::reserve_spectator(OWNER, p.identity.run.trial_id)?
        };
        with(|s| {
            s.spectator = Some(token);
            Ok(())
        })?;
        return Ok(());
    }
    let token = pending.1.unwrap();
    if !p.ready {
        let status = root::poll(token)?;
        if propagate_root_failure(p, token, status)? {
            return Ok(());
        }
        if status.phase == root::Phase::Frozen {
            with(|s| {
                let mut p = s.participant.ok_or(DomainError::Stale)?;
                if s.out.is_some() {
                    return Ok(());
                }
                p.frozen = status.frozen_other_domains;
                p.ready = true;
                queue_binding(s, wire::FROZEN, p.identity, &p.frozen)?;
                s.participant = Some(p);
                Ok(())
            })?;
        }
        return Ok(());
    }
    let status = root::poll(token)?;
    let root_failed = propagate_root_failure(p, token, status)?;
    if p.started && !p.close_sent {
        let observing =
            ledger_with(|l| Ok(now() >= l.observation)).map_err(|_| DomainError::Busy)?;
        with(|s| {
            if s.out.is_some() {
                return Ok(());
            }
            if !p.start_reported {
                queue_binding(s, wire::STARTED, p.identity, &[])?;
                s.participant
                    .as_mut()
                    .ok_or(DomainError::Stale)?
                    .start_reported = true;
            } else if observing && !p.observing {
                queue_binding(s, wire::OBSERVING, p.identity, &[])?;
                s.participant.as_mut().ok_or(DomainError::Stale)?.observing = true;
            } else if let Some((i, result)) = s
                .requests
                .iter()
                .enumerate()
                .filter_map(|(i, r)| {
                    r.as_ref()
                        .and_then(|r| (!r.reported).then_some(r.result).flatten().map(|v| (i, v)))
                })
                .next()
            {
                let mut bytes = [0; 80];
                let mut w = Writer::new(&mut bytes);
                w.bytes(&p.identity.hash().map_err(domain)?)
                    .map_err(domain)?;
                write_result(result, &mut w)?;
                let n = w.at;
                queue(s, wire::WORK_RESULT, &bytes[..n])?;
                s.requests[i].as_mut().unwrap().reported = true;
            }
            Ok(())
        })?;
    }
    if p.close_sent {
        let drained = with(|s| {
            Ok(s.requests
                .iter()
                .flatten()
                .all(|r| r.result.is_some() && r.reported)
                && s.tasks
                    .iter()
                    .flatten()
                    .all(|t| t.token.is_none() || t.closed))
        })?;
        if (!p.identity.baseline || root_failed) && !root::stop_spectator_fixture(token)? {
            return Ok(());
        }
        let sealed = ledger_with(|l| {
            if l.closing.is_none() {
                // This poll is itself inside the final paid service credit.
                // Stop opening future segments, then let that actual credit
                // return before sealing; never invent its end timestamp.
                if drained
                    && now() >= l.observation + cyxia_prototype::learning::reward::OBSERVATION_NS
                {
                    LEDGER_FAMILY.store(0, Ordering::Release);
                }
                l.close(now(), drained)?;
            }
            if l.sealed.is_none() && l.excluded.is_none() {
                let at = l.hash_cursor();
                let n = (l.count - at).min(wire::CHUNK_INTERVALS);
                let mut values = [EMPTY_INTERVAL; wire::CHUNK_INTERVALS];
                for (i, v) in values[..n].iter_mut().enumerate() {
                    *v = unsafe { stored(at + i).read() };
                }
                l.hash_piece(at, &values[..n])?;
            }
            Ok(l.sealed
                .map(|seal| PartnerEvidence {
                    binding: l.binding,
                    seal,
                    exclusion: None,
                })
                .or_else(|| {
                    l.excluded.map(|e| PartnerEvidence {
                        binding: l.binding,
                        seal: e.trace,
                        exclusion: Some(e.exclusion),
                    })
                }))
        });
        match sealed {
            Ok(Some(evidence)) => with(|s| {
                let seal = evidence.seal;
                if s.out.is_some() {
                    return Ok(());
                }
                if s.trace_cursor < seal.count as usize {
                    let at = s.trace_cursor;
                    let n = (seal.count as usize - at).min(wire::CHUNK_INTERVALS);
                    let mut bytes = [0; 1024];
                    let mut w = Writer::new(&mut bytes);
                    w.bytes(&p.identity.hash().map_err(domain)?)
                        .map_err(domain)?;
                    w.u64(at as u64).map_err(domain)?;
                    w.u64(n as u64).map_err(domain)?;
                    for i in 0..n {
                        let mut raw = [0; wire::INTERVAL_BYTES];
                        wire::encode_interval(unsafe { stored(at + i).read() }, &mut raw)
                            .map_err(domain)?;
                        w.bytes(&raw).map_err(domain)?;
                    }
                    let count = w.at;
                    queue(s, wire::TRACE, &bytes[..count])?;
                    s.trace_cursor += n;
                } else if !s.seal_sent {
                    let mut bytes = [0; wire::EXCLUDED_BYTES];
                    let n = evidence
                        .encode(&mut bytes)
                        .map_err(|_| DomainError::Format)?;
                    queue(
                        s,
                        if evidence.exclusion.is_some() {
                            wire::EXCLUDED
                        } else {
                            wire::SEALED
                        },
                        &bytes[..n],
                    )?;
                    s.seal_sent = true;
                    s.export_excluded = evidence.exclusion.is_some();
                }
                Ok(())
            })?,
            Ok(None) | Err(learning::Error::Unknown) => {}
            Err(error) => {
                with(|s| {
                    s.fault = Some(error);
                    Ok(())
                })?;
            }
        }
    }
    if pending.2 && settled(token).is_ok() {
        // Keep the actual seal and root lease until the peer authenticated all
        // raw records and explicitly requested release.
        if p.keep_pair == Some(true) {
            with(|s| {
                queue_binding(s, wire::RELEASED, p.identity, &[])?;
                s.pair_hold = Some(p);
                s.participant = None;
                Ok(())
            })?;
        } else {
            if !root::stop_spectator_fixture(token)? {
                return Ok(());
            }
            root::release_spectator(token)?;
            ROOT_RELEASED.store(token.id, Ordering::Release);
            finish_participant_release(p)?;
        }
    }
    Ok(())
}
fn finish_participant_release(p: Preparation) -> Result<(), DomainError> {
    {
        let _guard = lock(&LEDGER_GATE)?;
        unsafe {
            *LEDGER.0.get() = None;
        }
    }
    crate::learning_replay::pause_for_peer(false)?;
    with(|s| {
        if s.out.is_some() {
            return Err(DomainError::Busy);
        }
        queue_binding(s, wire::RELEASED, p.identity, &[])?;
        s.participant = None;
        s.spectator = None;
        s.participant_release = false;
        s.participant_failure = None;
        s.failure_sent_for = None;
        ROOT_RELEASED.store(0, Ordering::Release);
        Ok(())
    })
}
