//! Root authority for real paired replay. A reservation quiesces optimization,
//! waits for old leases/obligations, and retains exact baseline publications.
//! A digest describes observed configuration; it never certifies workload reset.
use super::*;
pub use crate::learning_history::TrialKind;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU64, Ordering},
};
use cyxia_prototype::learning::{
    self, Family as LearningFamily,
    reward::{Adoption, BaselineAdoption},
};
#[path = "replay/config_diagnostic.rs"]
mod config_diagnostic;
#[path = "replay/fixture.rs"]
mod fixture;
#[path = "replay/lifecycle.rs"]
pub(crate) mod lifecycle;
#[path = "replay/verification.rs"]
mod verification;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub id: u64,
    pub boot_epoch: u64,
    pub owner: ObjectKey,
}
/// Protected preparation custody, before any capture or policy publication.
/// This identity is deliberately distinct from a capture RunKey or ApplyId.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preparation {
    pub id: u64,
    pub boot_epoch: u64,
    pub owner: ObjectKey,
    pub trial_id: u64,
    pub family: LearningFamily,
    pub seed: u64,
    pub kind: TrialKind,
    pub started_ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparationClose {
    preparation: Preparation,
    error: Error,
    failed_ns: u64,
    drained_ns: u64,
    model_hash: [u8; 32],
    observed_model_hash: [u8; 32],
    root_token: Option<Token>,
}
impl PreparationClose {
    pub fn preparation(self) -> Preparation {
        self.preparation
    }
    pub fn error(self) -> Error {
        self.error
    }
    pub fn failed_ns(self) -> u64 {
        self.failed_ns
    }
    pub fn drained_ns(self) -> u64 {
        self.drained_ns
    }
    pub fn model_hash(self) -> [u8; 32] {
        self.model_hash
    }
    pub fn observed_model_hash(self) -> [u8; 32] {
        self.observed_model_hash
    }
    pub fn root_token(self) -> Option<Token> {
        self.root_token
    }
}
#[derive(Clone, Copy)]
struct Preparing {
    identity: Preparation,
    gate: bool,
    ready: bool,
    claimed: bool,
    cursor: usize,
    inherited: Option<Token>,
    bound: Option<Token>,
    model: ModelBinding,
    failure: Option<(Error, u64)>,
    close: Option<PreparationClose>,
    archived: bool,
}
#[derive(Clone, Copy)]
pub struct Request {
    pub owner: ObjectKey,
    pub trial_id: u64,
    pub family: LearningFamily,
    pub target: ObjectKey,
    pub baseline: Action,
    pub kind: TrialKind,
    /// One-shot owners freeze and warm their original state before opening.
    pub not_before_ns: u64,
    pub on_first: fn(Token, Snapshot) -> Result<(), Error>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Quiescing,
    Scanning,
    Frozen,
    Running,
    Restoring,
    Complete,
    Faulted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub action: Action,
    pub apply: ApplyId,
    pub stamp: PolicyStamp,
    pub snapshot: Snapshot,
    pub state: ExecutionState,
    pub executor_generation: u64,
    pub issued_ns: u64,
    pub accepted_ns: u64,
    pub started_ns: Option<u64>,
    pub observed_ns: u64,
    pub approved_deadline_ns: u64,
}
/// The Registry refused this exact Plan before PUBLISH. This is a retained
/// negative fact, never an Apply receipt or a deterministic-baseline adoption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RejectedPublication {
    token: Token,
    receipt: policy::PlanReceipt,
    snapshot: Snapshot,
    header: PlanHeader,
    decision: Decision,
    model: ModelBinding,
    received_ns: u64,
    observed_ns: u64,
    wall_deadline_ns: u64,
    plan_hash: [u8; 32],
}
impl RejectedPublication {
    pub fn token(self) -> Token {
        self.token
    }
    pub fn receipt(self) -> policy::PlanReceipt {
        self.receipt
    }
    pub fn snapshot(self) -> Snapshot {
        self.snapshot
    }
    pub fn header(self) -> PlanHeader {
        self.header
    }
    pub fn decision(self) -> Decision {
        self.decision
    }
    pub fn action(self) -> Action {
        self.decision.action
    }
    pub fn target(self) -> ObjectKey {
        self.decision.envelope.target
    }
    pub fn model(self) -> ModelBinding {
        self.model
    }
    pub fn received_ns(self) -> u64 {
        self.received_ns
    }
    pub fn observed_ns(self) -> u64 {
        self.observed_ns
    }
    pub fn wall_deadline_ns(self) -> u64 {
        self.wall_deadline_ns
    }
    pub fn plan_hash(self) -> [u8; 32] {
        self.plan_hash
    }
}
/// Under the publication gate, no action for this trial was published and the
/// ordinary owner proved its real work drained. This negative capability is
/// not an execution receipt and cannot form a learning label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnpublishedClose {
    token: Token,
    family: LearningFamily,
    target: ObjectKey,
    first: Snapshot,
    closed_ns: u64,
    capture: Option<learning::capture::RunKey>,
}
impl UnpublishedClose {
    pub fn capture_key(self) -> Option<learning::capture::RunKey> {
        self.capture
    }
    pub fn facts(self) -> (Token, LearningFamily, ObjectKey, Snapshot, u64) {
        (
            self.token,
            self.family,
            self.target,
            self.first,
            self.closed_ns,
        )
    }
}
impl Receipt {
    pub fn baseline(self, target_request_id: Option<u64>) -> Result<BaselineAdoption, Error> {
        if self.state != ExecutionState::Applied {
            return Err(Error::NotReady);
        }
        Ok(BaselineAdoption {
            owner_boot: self.apply.boot_epoch,
            receipt_sequence: self.apply.plan_seq,
            target: self.apply.target,
            executor_generation: self.executor_generation,
            snapshot: self.snapshot,
            actual: self.action,
            executed: self.state,
            issued_ns: self.issued_ns,
            accepted_ns: self.accepted_ns,
            target_request_id,
            started_ns: self.started_ns.ok_or(Error::NotReady)?,
            finished_ns: self.observed_ns,
            installed_until_ns: self.stamp.installed_until_ns,
            approved_deadline_ns: self.approved_deadline_ns,
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub phase: Phase,
    pub frozen_other_domains: [u8; 32],
    pub first: Option<Snapshot>,
    pub selected: Option<Action>,
    pub receipt: Option<Receipt>,
    pub closing: Option<Receipt>,
    pub unpublished: Option<UnpublishedClose>,
    pub fault: Option<Error>,
}
#[derive(Clone, Copy)]
struct Configuration {
    family: LearningFamily,
    target: ObjectKey,
    action: Action,
}
#[derive(Clone, Copy)]
pub struct OwnerChecks {
    pub owner: ObjectKey,
    pub baseline: fn(LearningFamily, ObjectKey, Action) -> Result<(), Error>,
    /// Stop-offer is a deterministic operation, outside the AI Action ABI.
    /// Its implementation must keep old quotes' TTL and report actual custody.
    pub stop_offer: fn(Token, ObjectKey, Snapshot) -> Result<Receipt, Error>,
    /// Authenticate real pre-owned warmup before opening the first capture.
    /// Busy is a readiness result, not a first candidate or an execution ack.
    pub before_first: fn(Token, Snapshot) -> Result<(), Error>,
    /// The registered ordinary owner has drained its real work and retained
    /// all terminal receipts. This check must not reenter the root gate.
    pub settled: fn(Token) -> Result<(), Error>,
    /// Exact preparation identity and actual resource drain, without root reentry.
    pub prepared_settled: fn(Preparation) -> Result<(), Error>,
    pub unactivated_settled:
        fn(Preparation, &crate::learning_history::FrozenScope) -> Result<(), Error>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Spectator {
    owner: ObjectKey,
    trial_id: u64,
    fixture: Option<fixture::Fixed>,
}
/// Scheduling custody for the current actually committed candidate. First
/// identity stays in Root; a renewal cannot replace unresolved custody here.
#[derive(Clone, Copy)]
struct CandidatePublication {
    token: Token,
    apply: ApplyId,
    stamp: PolicyStamp,
    family: LearningFamily,
    state: ExecutionState,
}
pub(crate) const CANDIDATE_PUBLICATION_BYTES: usize =
    core::mem::size_of::<Option<CandidatePublication>>();
const _: () = assert!(CANDIDATE_PUBLICATION_BYTES <= 128);
struct Root {
    registered: [Option<OwnerChecks>; 4],
    serial: u64,
    preparing: Option<Preparing>,
    request: Option<Request>,
    spectator: Option<Spectator>,
    token: Option<Token>,
    advanced_from: Option<Token>,
    fixture: fixture::Ledger,
    phase: Phase,
    model: Option<ModelBinding>,
    first: Option<Snapshot>,
    first_ready: bool,
    lifecycle: lifecycle::CloseGate,
    rejected: Option<RejectedPublication>,
    digest: [u8; 32],
    hashing: Option<Sha256>,
    configs: [Option<Configuration>; 512],
    count: usize,
    family: usize,
    ordinal: usize,
    cursor: usize,
    selected: Option<Action>,
    initial: Option<ApplyId>,
    candidate_publication: Option<CandidatePublication>,
    renew_after: u64,
    baseline: [Option<Receipt>; 32],
    baseline_count: usize,
    closing: Option<Receipt>,
    unpublished: Option<UnpublishedClose>,
    stop_closing: Option<Snapshot>,
    fault: Option<Error>,
}
impl Root {
    const fn new() -> Self {
        Self {
            registered: [None; 4],
            serial: 0,
            preparing: None,
            request: None,
            spectator: None,
            token: None,
            advanced_from: None,
            fixture: fixture::Ledger::new(),
            phase: Phase::Complete,
            model: None,
            first: None,
            first_ready: false,
            lifecycle: lifecycle::CloseGate::new(),
            rejected: None,
            digest: [0; 32],
            hashing: None,
            configs: [None; 512],
            count: 0,
            family: 0,
            ordinal: 0,
            cursor: 0,
            selected: None,
            initial: None,
            candidate_publication: None,
            renew_after: 0,
            baseline: [None; 32],
            baseline_count: 0,
            closing: None,
            unpublished: None,
            stop_closing: None,
            fault: None,
        }
    }
}
struct Cell(UnsafeCell<Root>);
unsafe impl Sync for Cell {}
static ROOT: Cell = Cell(UnsafeCell::new(Root::new()));
static BASELINE_ACTIVATION_PENDING: AtomicBool = AtomicBool::new(false);
/// Called only by the root gate's guard, before releasing exclusion. A first
/// snapshot already exists even if on_first cannot yet acquire its owner gate
/// or bind capture/history. Neither that Busy nor a read-only borrow may lose
/// its retry opportunity. Published nonterminal executions and restorations
/// retain that opportunity until their cached, real receipt becomes terminal.
pub(super) fn publish_baseline_activation_hint() {
    debug_assert!(super::CLAIMED.load(Ordering::Relaxed));
    let r = root();
    let baseline = r.request.is_some_and(|q| q.kind == TrialKind::Baseline);
    let activating = baseline
        && r.phase == Phase::Frozen
        && r.initial.is_none()
        && r.baseline_count == 0
        && r.fault.is_none();
    let executing = |receipt: &Receipt| {
        receipt.stamp.version != 0
            && matches!(
                receipt.state,
                ExecutionState::Pending | ExecutionState::Unknown
            )
    };
    let candidate = r.candidate_publication.is_some_and(|initial| {
        let Some(first_apply) = r.initial else {
            return false;
        };
        r.phase == Phase::Running
            && r.fault.is_none()
            && r.first_ready
            && r.token == Some(initial.token)
            && first_apply.boot_epoch == initial.apply.boot_epoch
            && first_apply.controller_epoch == initial.apply.controller_epoch
            && first_apply.action_index == initial.apply.action_index
            && first_apply.target == initial.apply.target
            && initial.apply.boot_epoch == initial.token.boot_epoch
            && initial.stamp.version != 0
            && matches!(
                initial.state,
                ExecutionState::Pending | ExecutionState::Unknown
            )
            && r.first.is_some_and(|first| {
                first.sequence == first_apply.plan_seq
                    && (initial.apply == first_apply && first.taken_ns == initial.stamp.snapshot_ns
                        || initial.apply.plan_seq > first_apply.plan_seq
                            && initial.stamp.snapshot_ns > first.taken_ns
                            && r.selected.is_some_and(|action| !action.one_shot()))
            })
            && r.request.is_some_and(|q| {
                q.kind == TrialKind::Candidate
                    && q.owner == initial.token.owner
                    && q.family == initial.family
                    && q.target == initial.apply.target
            })
    });
    let pending = r.token.is_some()
        && r.request.is_some()
        && r.first.is_some()
        && r.phase != Phase::Complete
        && r.unpublished.is_none()
        && r.lifecycle.closing().is_none()
        && (activating
            || candidate
            || baseline
                && r.baseline
                    .iter()
                    .take(r.baseline_count)
                    .flatten()
                    .any(executing)
            || r.closing.as_ref().is_some_and(executing));
    if pending != BASELINE_ACTIVATION_PENDING.load(Ordering::Relaxed) {
        BASELINE_ACTIVATION_PENDING.store(pending, Ordering::Release);
    }
}
/// Scheduling hint only: service_step still needs real paid service authority
/// and revalidates the original token, snapshot, model and deadline.
pub fn baseline_activation_pending() -> bool {
    BASELINE_ACTIVATION_PENDING.load(Ordering::Acquire)
}
/// Existing control-gate entry only. The diagnostic never queries an owner,
/// reads a new clock or changes an admission result.
pub(super) fn preparation_admission(s: &State, reason: u64, at: u64) {
    let r = root();
    let Some(q) = r.request else {
        return;
    };
    if q.kind != TrialKind::Candidate || r.phase != Phase::Running {
        return;
    }
    let Some(token) = r.token else {
        return;
    };
    let first = r.first.unwrap_or_default();
    crate::domain_evidence::preparation_admission([
        cyxia_arch_aarch64::cpu::slot() as u64,
        at,
        reason,
        s.boot,
        s.sequence,
        s.job.as_ref().map_or(0, |job| job.sequence),
        s.owner.prepared_count as u64,
        token.id,
        q.trial_id,
        r.phase as u64 + 1,
        u64::from(q.family.domain),
        u64::from(q.family.kind),
        q.target.id,
        q.target.generation,
        first.sequence,
        first.taken_ns,
        u64::from(r.first_ready),
        r.initial.map_or(0, |apply| apply.plan_seq),
        token.boot_epoch,
        token.owner.id,
        token.owner.generation,
        1,
    ]);
}
static ACTIVATING: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static ACTIVATION_TOKEN: AtomicU64 = AtomicU64::new(0);
static ACTIVATION_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
/// Diagnostic-only ABI, independent of the 64-word producer evidence. Root's
/// gate serializes writers. Transient failures update this snapshot until the
/// first permanent error or actual version-zero terminal receipt is retained.
/// 0 seqlock; 1 magic; 2 recorded failures; 3 latched; 4 stage; 5 error+1;
/// 6 observed ns; 7 token; 8 trial; 9 closing; 10 first_ready; 11 baseline count;
/// 12..16 first Snapshot (sequence,taken,ledger,core); 16..20 used Snapshot;
/// 20/21 current ledger/core; 22 root sequence; 23 Registry version;
/// 24 actual PlanReceipt version; 25 state (0 absent,1 Pending,2 Applied,
/// 3 Failed,4 Unknown); 26 receipt error+1; 27 root phase+1;
/// 28..31 previous transient (stage,error+1,observed ns); 31 activation attempts.
#[repr(C, align(64))]
pub struct RootEvidence([AtomicU64; 32]);
#[used]
#[unsafe(no_mangle)]
pub static REPLAY_ROOT_EVIDENCE: RootEvidence = RootEvidence([const { AtomicU64::new(0) }; 32]);
#[derive(Default)]
struct PublicationTrace {
    // 1 eligibility, 2 activation callback, 3 legal, 4 current, 5 stability,
    // 6 observation, 7 target features, 8 dependencies, 9 candidates,
    // 10 registration, 11 wire, 12 submit, 13 receipt, 14 stop-offer owner,
    // 15 placement fallback, 16 exact previously-published receipt.
    stage: u64,
    used: Snapshot,
    receipt: Option<policy::PlanReceipt>,
}
fn publication_failure(
    s: &State,
    token: Token,
    closing: bool,
    trace: &PublicationTrace,
    error: Error,
) {
    let evidence = &REPLAY_ROOT_EVIDENCE.0;
    if evidence[3].load(Ordering::Acquire) != 0 {
        return;
    }
    let r = root();
    let first = r.first.unwrap_or_default();
    let state = trace.receipt.map(|v| v.state());
    let (state_word, receipt_error) = match state {
        None => (0, 0),
        Some(ExecutionState::Pending) => (1, 0),
        Some(ExecutionState::Applied) => (2, 0),
        Some(ExecutionState::Failed(e)) => (3, e as u64 + 1),
        Some(ExecutionState::Unknown) => (4, 0),
    };
    let terminal = !matches!(error, Error::Busy | Error::Again | Error::NotReady)
        || trace
            .receipt
            .is_some_and(|v| v.version == 0 && v.state().terminal());
    let previous = [
        evidence[4].load(Ordering::Relaxed),
        evidence[5].load(Ordering::Relaxed),
        evidence[6].load(Ordering::Relaxed),
    ];
    let values: [u64; 31] = [
        0x4359_5252_4f54_3133,
        evidence[2].load(Ordering::Relaxed).saturating_add(1),
        u64::from(terminal),
        trace.stage,
        error as u64 + 1,
        now(),
        token.id,
        r.request.map_or(0, |q| q.trial_id),
        u64::from(closing),
        u64::from(r.first_ready),
        r.baseline_count as u64,
        first.sequence,
        first.taken_ns,
        first.ledger_generation,
        first.core_generation,
        trace.used.sequence,
        trace.used.taken_ns,
        trace.used.ledger_generation,
        trace.used.core_generation,
        s.owner.context.ledger_generation,
        s.owner.context.core_generation,
        s.sequence,
        s.registry.version(),
        trace.receipt.map_or(0, |v| v.version),
        state_word,
        receipt_error,
        r.phase as u64 + 1,
        previous[0],
        previous[1],
        previous[2],
        if ACTIVATION_TOKEN.load(Ordering::Relaxed) == token.id {
            ACTIVATION_ATTEMPTS.load(Ordering::Relaxed)
        } else {
            0
        },
    ];
    evidence[0].fetch_add(1, Ordering::AcqRel);
    for (i, value) in values.into_iter().enumerate() {
        evidence[i + 1].store(value, Ordering::Relaxed);
    }
    evidence[0].fetch_add(1, Ordering::Release);
}
// All accesses, including these parent-only gate hooks, hold super::CLAIMED.
fn root() -> &'static Root {
    unsafe { &*ROOT.0.get() }
}
fn root_mut() -> &'static mut Root {
    unsafe { &mut *ROOT.0.get() }
}
fn authorized(s: &State) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() == 0 {
        crate::domain_tasks::authorize_service_turn()
    } else {
        require_control(&s.owner)?;
        crate::smp::prototype_runtime::authorize_learning_turn()
    }
}
fn exact(r: &Root, t: Token) -> Result<Request, Error> {
    if r.token != Some(t) {
        return Err(Error::Stale);
    }
    r.request.ok_or(Error::Stale)
}
fn same_request(a: Request, b: Request) -> bool {
    a.owner == b.owner
        && a.trial_id == b.trial_id
        && a.family == b.family
        && a.target == b.target
        && a.kind == b.kind
        && a.baseline == b.baseline
        && a.not_before_ns == b.not_before_ns
        && core::ptr::fn_addr_eq(a.on_first, b.on_first)
}
fn fail(r: &mut Root, e: Error) -> Error {
    r.fault.get_or_insert(e);
    r.phase = Phase::Faulted;
    e
}
pub fn register_owner(checks: OwnerChecks) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 || checks.owner.id == 0 || checks.owner.generation == 0
    {
        return Err(Error::Auth);
    }
    with(|_| {
        let r = root_mut();
        if let Some(old) = r
            .registered
            .iter()
            .flatten()
            .find(|o| o.owner == checks.owner)
        {
            return if old.owner == checks.owner
                && core::ptr::fn_addr_eq(old.baseline, checks.baseline)
                && core::ptr::fn_addr_eq(old.stop_offer, checks.stop_offer)
                && core::ptr::fn_addr_eq(old.before_first, checks.before_first)
                && core::ptr::fn_addr_eq(old.settled, checks.settled)
                && core::ptr::fn_addr_eq(old.prepared_settled, checks.prepared_settled)
                && core::ptr::fn_addr_eq(old.unactivated_settled, checks.unactivated_settled)
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let slot = r
            .registered
            .iter_mut()
            .find(|o| o.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(checks);
        Ok(())
    })
}
/// Block new AI work before local owners read/reset an initial image. Network
/// preparations first obtain a peer reservation using stable NodeID arbitration;
/// their identity alone must not freeze both local roots into a mutual wait.
pub fn begin_preparation(
    owner: ObjectKey,
    trial_id: u64,
    family: LearningFamily,
    seed: u64,
    kind: TrialKind,
) -> Result<Preparation, Error> {
    with(|s| {
        authorized(s)?;
        family_index(family.domain, family.kind)?;
        if owner.id == 0
            || owner.generation == 0
            || trial_id == 0
            || !root().registered.iter().flatten().any(|o| o.owner == owner)
        {
            return Err(Error::Auth);
        }
        if let Some(old) = root().preparing {
            let p = old.identity;
            return if p.owner == owner
                && p.trial_id == trial_id
                && p.family == family
                && p.seed == seed
                && p.kind == kind
            {
                Ok(p)
            } else {
                Err(Error::Busy)
            };
        }
        let r = root_mut();
        if r.spectator.is_some() {
            return Err(Error::Busy);
        }
        if let Some(q) = r.request {
            if r.phase != Phase::Complete
                || q.owner != owner
                || q.family != family
                || q.kind != TrialKind::Baseline
                || kind != TrialKind::Candidate
                || trial_id <= q.trial_id
                || r.closing.is_none_or(|c| c.state != ExecutionState::Applied)
            {
                return Err(Error::Busy);
            }
        }
        if s.model_gate.as_ref().is_none_or(|g| {
            g.permit().is_some() || g.closing().is_some() || g.restoration_request().is_some()
        }) || crate::learning_canary::owns_output()
        {
            return Err(Error::Busy);
        }
        r.serial = r.serial.checked_add(1).ok_or(Error::Overflow)?;
        let identity = Preparation {
            id: r.serial,
            boot_epoch: s.boot,
            owner,
            trial_id,
            family,
            seed,
            kind,
            started_ns: now(),
        };
        let gate = !matches!(family.domain, 10 | 12 | 16);
        r.preparing = Some(Preparing {
            identity,
            gate,
            ready: !gate,
            claimed: false,
            cursor: 0,
            inherited: r.token,
            bound: None,
            model: s.registry.model(),
            failure: None,
            close: None,
            archived: false,
        });
        Ok(identity)
    })
}
pub fn verify_preparation(preparation: Preparation) -> Result<(), Error> {
    with(|_| {
        if root().preparing.is_some_and(|p| p.identity == preparation) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    })
}
fn trace_preparation(
    p: Preparation,
) -> crate::learning_evidence::execution_trace::PreparationIdentity {
    crate::learning_evidence::execution_trace::PreparationIdentity {
        id: p.id,
        boot_epoch: p.boot_epoch,
        owner: p.owner,
        trial: p.trial_id,
        family: p.family,
        seed: p.seed,
        kind: if p.kind == TrialKind::Baseline { 2 } else { 1 },
        started_ns: p.started_ns,
    }
}
pub fn poll_preparation(preparation: Preparation, service_entry_ns: u64) -> Result<bool, Error> {
    with(|s| {
        let mut trace = crate::learning_evidence::execution_trace::RootPreparationTrace::new(
            trace_preparation(preparation),
            service_entry_ns,
        );
        let result = (|| {
            authorized(s)?;
            trace.stage = 2;
            let p = root_mut().preparing.as_mut().ok_or(Error::Stale)?;
            if p.identity != preparation || p.failure.is_some() {
                return Err(Error::Stale);
            }
            trace.stage = 3;
            if p.model != s.registry.model() {
                return Err(Error::Stale);
            }
            trace.cursor_before = p.cursor;
            trace.cursor_after = p.cursor;
            trace.stage = 4;
            if p.ready {
                return Ok(true);
            }
            trace.stage = 5;
            if s.job.is_some() || s.owner.prepared_count != 0 {
                trace.job = s.job.is_some();
                trace.prepared_count = s.owner.prepared_count;
                p.cursor = 0;
                trace.cursor_after = p.cursor;
                return Ok(false);
            }
            let end = (p.cursor + 8).min(s.owner.desired.len());
            trace.stage = 6;
            trace.scan_end = end;
            if s.owner.desired[p.cursor..end]
                .iter()
                .enumerate()
                .any(|(offset, value)| {
                    let Some(d) = value else {
                        return false;
                    };
                    let blocks = execution_blocks_replacement(d);
                    let (live, predicate_at) = if blocks || d.action.one_shot() {
                        (false, None)
                    } else {
                        let at = now();
                        (d.stamp.live(at), Some(at))
                    };
                    if blocks || live {
                        trace.blocker = Some(
                            crate::learning_evidence::execution_trace::PreparationBlocker {
                                slot: p.cursor + offset,
                                apply: d.apply,
                                stamp: d.stamp,
                                state: d.state,
                                started: d.started,
                                execution_observed: d.execution_observed,
                                reason: if !blocks {
                                    4
                                } else if !d.state.terminal() {
                                    1
                                } else {
                                    2
                                },
                                predicate_at,
                            },
                        );
                        true
                    } else {
                        false
                    }
                })
            {
                p.cursor = 0;
                trace.cursor_after = p.cursor;
                return Ok(false);
            }
            p.cursor = end;
            trace.cursor_after = p.cursor;
            trace.stage = 7;
            if end == s.owner.desired.len() {
                p.ready = true;
                trace.stage = 8;
            }
            Ok(p.ready)
        })();
        crate::learning_evidence::execution_trace::preparation_root(trace, result);
        result
    })
}
pub fn claim_preparation(preparation: Preparation) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let p = root_mut().preparing.as_mut().ok_or(Error::Stale)?;
        if p.identity != preparation || !p.ready || p.failure.is_some() {
            return Err(Error::Busy);
        }
        p.claimed = true;
        Ok(())
    })
}
/// Only an identity that never reached an owner may be returned for a peer.
/// Prepared resources use the separate drained, durably archived close path.
pub fn withdraw_preparation(preparation: Preparation) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let p = root().preparing.ok_or(Error::Stale)?;
        if p.identity != preparation || p.claimed || p.bound.is_some() || p.inherited.is_some() {
            return Err(Error::Busy);
        }
        root_mut().preparing = None;
        Ok(())
    })
}
pub fn close_preparation(
    preparation: Preparation,
    error: Error,
    failed_ns: u64,
) -> Result<PreparationClose, Error> {
    with(|s| {
        authorized(s)?;
        let mut p = root().preparing.ok_or(Error::Stale)?;
        if p.identity != preparation || failed_ns < preparation.started_ns || failed_ns > now() {
            return Err(Error::Stale);
        }
        if p.failure.is_some_and(|old| old != (error, failed_ns)) {
            return Err(Error::Conflict);
        }
        if let Some(close) = p.close {
            return Ok(close);
        }
        p.failure = Some((error, failed_ns));
        p.gate = true;
        root_mut().preparing = Some(p);
        if p.bound.is_some()
            && (root().token != p.bound
                || root().first_ready
                || root().initial.is_some()
                || root().baseline_count != 0)
        {
            return Err(Error::Conflict);
        }
        if s.job.is_some() || s.owner.prepared_count != 0 {
            return Err(Error::Busy);
        }
        let end = (p.cursor + 8).min(s.owner.desired.len());
        if s.owner.desired[p.cursor..end]
            .iter()
            .flatten()
            .any(execution_blocks_replacement)
        {
            root_mut().preparing.as_mut().unwrap().cursor = 0;
            return Err(Error::Busy);
        }
        root_mut().preparing.as_mut().unwrap().cursor = end;
        if end != s.owner.desired.len() {
            return Err(Error::Again);
        }
        if p.claimed {
            let check = root()
                .registered
                .iter()
                .flatten()
                .find(|o| o.owner == preparation.owner)
                .ok_or(Error::Auth)?
                .prepared_settled;
            check(preparation)?;
        }
        if crate::learning_evidence::current_config()
            .map_err(|_| Error::Busy)?
            .is_some()
        {
            return Err(Error::Busy);
        }
        let close = PreparationClose {
            preparation,
            error,
            failed_ns,
            drained_ns: now(),
            model_hash: p.model.model_hash,
            observed_model_hash: s.registry.model().model_hash,
            root_token: p.bound.or(p.inherited),
        };
        root_mut().preparing.as_mut().unwrap().close = Some(close);
        Ok(close)
    })
}
pub fn abort_preparation(
    preparation: Preparation,
    error: Error,
    failed_ns: u64,
) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let started = root().first_ready;
        let p = root_mut().preparing.as_mut().ok_or(Error::Stale)?;
        if p.identity != preparation || failed_ns < preparation.started_ns || failed_ns > now() {
            return Err(Error::Stale);
        }
        if p.failure.is_some_and(|old| old != (error, failed_ns)) {
            return Err(Error::Conflict);
        }
        if p.bound.is_some() && started {
            return Err(Error::Conflict);
        }
        p.failure = Some((error, failed_ns));
        p.gate = true;
        Ok(())
    })
}
pub fn verify_preparation_close(close: PreparationClose) -> Result<(), Error> {
    with(|_| {
        if root()
            .preparing
            .is_some_and(|p| p.identity == close.preparation && p.close == Some(close))
        {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    })
}
pub(crate) fn mark_preparation_archived(
    proof: crate::learning_replay::preparation_archive::Export,
) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let p = root_mut().preparing.as_mut().ok_or(Error::Stale)?;
        if p.close != Some(proof.close())
            || proof.bytes() == 0
            || proof.digest() == [0; 32]
            || proof.object().id == 0
            || proof.object().generation == 0
            || proof.offset().checked_add(proof.bytes() as u64).is_none()
        {
            return Err(Error::Conflict);
        }
        p.archived = true;
        Ok(())
    })
}
pub fn preparation_archived(preparation: Preparation) -> bool {
    with(|_| {
        Ok(root()
            .preparing
            .is_some_and(|p| p.identity == preparation && p.archived))
    })
    .unwrap_or(false)
}
pub fn release_preparation(preparation: Preparation) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let p = root().preparing.ok_or(Error::Stale)?;
        if p.identity != preparation || p.close.is_none() || !p.archived {
            return Err(Error::Busy);
        }
        if let Some(token) = p.bound.or(p.inherited) {
            if root().token != Some(token) || root().spectator.is_some() {
                return Err(Error::Stale);
            }
            let r = root_mut();
            r.request = None;
            r.token = None;
            r.phase = Phase::Complete;
            r.fault = None;
            r.first = None;
            r.first_ready = false;
        }
        root_mut().preparing = None;
        Ok(())
    })
}
fn preparation_matches(r: &Root, request: Request) -> Result<(), Error> {
    if let Some(p) = r.preparing {
        if p.identity.owner != request.owner
            || p.identity.trial_id != request.trial_id
            || p.identity.family != request.family
            || p.identity.kind != request.kind
            || !p.ready
            || !p.claimed
            || p.failure.is_some()
        {
            return Err(Error::Auth);
        }
    }
    Ok(())
}
pub fn reserve(request: Request) -> Result<Token, Error> {
    with(|s| {
        authorized(s)?;
        let checks = *root()
            .registered
            .iter()
            .flatten()
            .find(|o| o.owner == request.owner)
            .ok_or(Error::NotReady)?;
        if request.owner != checks.owner
            || request.trial_id == 0
            || request.target.id == 0
            || request.target.generation == 0
            || request.baseline.domain() != request.family.domain
            || request.baseline.kind() != request.family.kind
        {
            return Err(Error::Auth);
        }
        learning::baseline::validate(request.baseline).map_err(|_| Error::Schema)?;
        family_index(request.family.domain, request.family.kind)?;
        (checks.baseline)(request.family, request.target, request.baseline)?;
        let r = root_mut();
        if r.spectator.is_some() {
            return Err(Error::Busy);
        }
        if let Some(old) = r.request {
            return if old.owner == request.owner
                && old.trial_id == request.trial_id
                && old.family == request.family
                && old.target == request.target
                && old.kind == request.kind
                && old.baseline == request.baseline
                && old.not_before_ns == request.not_before_ns
                && core::ptr::fn_addr_eq(old.on_first, request.on_first)
            {
                r.token.ok_or(Error::Stale)
            } else {
                Err(Error::Busy)
            };
        }
        if s.model_gate.as_ref().is_none_or(|g| {
            g.permit().is_some() || g.closing().is_some() || g.restoration_request().is_some()
        }) || crate::learning_canary::owns_output()
        {
            return Err(Error::Busy);
        }
        preparation_matches(r, request)?;
        r.serial = r.serial.checked_add(1).ok_or(Error::Overflow)?;
        let token = Token {
            id: r.serial,
            boot_epoch: s.boot,
            owner: request.owner,
        };
        r.request = Some(request);
        r.token = Some(token);
        r.advanced_from = None;
        r.phase = Phase::Quiescing;
        r.model = Some(s.registry.model());
        r.first = None;
        r.first_ready = false;
        r.lifecycle = lifecycle::CloseGate::new();
        r.rejected = None;
        r.digest = [0; 32];
        r.count = 0;
        r.family = 0;
        r.ordinal = 0;
        r.cursor = 0;
        r.selected = None;
        r.initial = None;
        r.candidate_publication = None;
        r.renew_after = 0;
        r.baseline_count = 0;
        r.closing = None;
        r.unpublished = None;
        r.stop_closing = None;
        r.fault = None;
        r.hashing = None;
        if let Some(p) = r.preparing.as_mut() {
            p.bound = Some(token);
        }
        Ok(token)
    })
}
/// Retain the exact frozen other-domain state across a paired workload reset.
/// A successful handover is idempotent even if the caller's next bind is Busy.
pub fn advance(old: Token, request: Request) -> Result<Token, Error> {
    with(|s| {
        authorized(s)?;
        if root().advanced_from == Some(old)
            && root().request.is_some_and(|q| same_request(q, request))
        {
            return root().token.ok_or(Error::Stale);
        }
        let prior = exact(root(), old)?;
        if root().phase != Phase::Complete
            || root().fault.is_some()
            || root()
                .closing
                .is_none_or(|r| r.state != ExecutionState::Applied)
            || root().model != Some(s.registry.model())
        {
            return Err(Error::Busy);
        }
        if prior.owner != request.owner
            || prior.family != request.family
            || prior.baseline != request.baseline
            || prior.kind != TrialKind::Baseline
            || request.kind != TrialKind::Candidate
            || request.trial_id <= prior.trial_id
            || request.target.id == 0
            || request.target.generation == 0
        {
            return Err(Error::Auth);
        }
        let check = root()
            .registered
            .iter()
            .flatten()
            .find(|v| v.owner == request.owner)
            .ok_or(Error::Auth)?
            .baseline;
        check(request.family, request.target, request.baseline)?;
        let r = root_mut();
        preparation_matches(r, request)?;
        r.serial = r.serial.checked_add(1).ok_or(Error::Overflow)?;
        let token = Token {
            id: r.serial,
            boot_epoch: s.boot,
            owner: request.owner,
        };
        r.advanced_from = Some(old);
        r.request = Some(request);
        r.token = Some(token);
        r.phase = Phase::Frozen;
        r.first = None;
        r.first_ready = false;
        r.lifecycle = lifecycle::CloseGate::new();
        r.rejected = None;
        r.selected = None;
        r.initial = None;
        r.candidate_publication = None;
        r.renew_after = 0;
        r.cursor = 0;
        r.baseline_count = 0;
        r.closing = None;
        r.unpublished = None;
        r.stop_closing = None;
        if let Some(p) = r.preparing.as_mut() {
            p.bound = Some(token);
        }
        Ok(token)
    })
}
pub(super) fn allows(domain: u16, kind: u16, target: ObjectKey) -> bool {
    let r = root();
    if r.lifecycle.closing().is_some()
        || r.spectator.is_some()
        || r.preparing
            .is_some_and(|p| p.gate && (p.bound.is_none() || p.failure.is_some()))
    {
        return false;
    }
    let Some(q) = r.request else {
        return true;
    };
    r.phase == Phase::Running
        && q.kind == TrialKind::Candidate
        && q.family == (LearningFamily { domain, kind })
        && q.target == target
        && (!q.baseline.one_shot() || r.initial.is_none())
        && (r.initial.is_none() || now() >= r.renew_after)
}
pub(super) fn allows_action(action: Action, target: ObjectKey) -> bool {
    let r = root();
    if r.lifecycle.closing().is_some()
        || r.spectator.is_some()
        || r.preparing
            .is_some_and(|p| p.gate && (p.bound.is_none() || p.failure.is_some()))
    {
        return false;
    }
    if r.request.is_none() {
        return true;
    }
    allows(action.domain(), action.kind(), target) && root().selected.is_none_or(|a| a == action)
}
pub fn active() -> bool {
    with(|_| {
        Ok(root().request.is_some()
            || root().spectator.is_some()
            || root().preparing.is_some_and(|p| p.gate))
    })
    .unwrap_or(true)
}
pub(super) fn model_change_allowed() -> bool {
    root().request.is_none()
        && root().spectator.is_none()
        && root().preparing.is_none_or(|p| !p.gate)
}

/// A partner contributes real work and billing while all of its policy
/// configuration stays frozen. It has no selected family or action permit.
pub fn reserve_spectator(owner: ObjectKey, trial_id: u64) -> Result<Token, Error> {
    reserve_spectator_inner(owner, trial_id, None)
}
pub fn reserve_spectator_with_fixture(
    owner: ObjectKey,
    trial_id: u64,
    target: ObjectKey,
    action: Action,
) -> Result<Token, Error> {
    if action != Action::OfferCpu(100) || target.id == 0 || target.generation == 0 {
        return Err(Error::Auth);
    }
    reserve_spectator_inner(owner, trial_id, Some(fixture::Fixed { target, action }))
}
fn reserve_spectator_inner(
    owner: ObjectKey,
    trial_id: u64,
    fixed: Option<fixture::Fixed>,
) -> Result<Token, Error> {
    with(|s| {
        authorized(s)?;
        if trial_id == 0 || !root().registered.iter().flatten().any(|o| o.owner == owner) {
            return Err(Error::Auth);
        }
        if let Some(f) = fixed {
            let check = root()
                .registered
                .iter()
                .flatten()
                .find(|o| o.owner == owner)
                .ok_or(Error::Auth)?
                .baseline;
            check(
                LearningFamily {
                    domain: f.action.domain(),
                    kind: f.action.kind(),
                },
                f.target,
                f.action,
            )?;
        }
        let r = root_mut();
        if r.request.is_some() || r.preparing.is_some_and(|p| p.gate) {
            return Err(Error::Busy);
        }
        if let Some(old) = r.spectator {
            return if old
                == (Spectator {
                    owner,
                    trial_id,
                    fixture: fixed,
                }) {
                r.token.ok_or(Error::Stale)
            } else {
                Err(Error::Busy)
            };
        }
        if s.model_gate.as_ref().is_none_or(|g| {
            g.permit().is_some() || g.closing().is_some() || g.restoration_request().is_some()
        }) || crate::learning_canary::owns_output()
        {
            return Err(Error::Busy);
        }
        r.serial = r.serial.checked_add(1).ok_or(Error::Overflow)?;
        let token = Token {
            id: r.serial,
            boot_epoch: s.boot,
            owner,
        };
        r.spectator = Some(Spectator {
            owner,
            trial_id,
            fixture: fixed,
        });
        r.token = Some(token);
        r.advanced_from = None;
        r.fixture = fixture::Ledger::new();
        r.phase = Phase::Quiescing;
        r.model = Some(s.registry.model());
        r.first = None;
        r.first_ready = false;
        r.lifecycle = lifecycle::CloseGate::new();
        r.rejected = None;
        r.digest = [0; 32];
        r.count = 0;
        r.family = 0;
        r.ordinal = 0;
        r.cursor = 0;
        r.selected = None;
        r.initial = None;
        r.candidate_publication = None;
        r.renew_after = 0;
        r.baseline_count = 0;
        r.closing = None;
        r.unpublished = None;
        r.stop_closing = None;
        r.fault = None;
        r.hashing = None;
        Ok(token)
    })
}
pub fn advance_spectator(old: Token, trial_id: u64) -> Result<Token, Error> {
    with(|s| {
        authorized(s)?;
        if root().advanced_from == Some(old)
            && root()
                .spectator
                .is_some_and(|q| q.owner == old.owner && q.trial_id == trial_id)
        {
            return root().token.ok_or(Error::Stale);
        }
        if root().token != Some(old) {
            return Err(Error::Stale);
        }
        let q = root().spectator.ok_or(Error::Stale)?;
        if q.owner != old.owner
            || trial_id <= q.trial_id
            || root().phase != Phase::Frozen
            || root().fault.is_some()
        {
            return Err(Error::Busy);
        }
        let settled = root()
            .registered
            .iter()
            .flatten()
            .find(|v| v.owner == q.owner)
            .ok_or(Error::Auth)?
            .settled;
        settled(old)?;
        let r = root_mut();
        r.serial = r.serial.checked_add(1).ok_or(Error::Overflow)?;
        let token = Token {
            id: r.serial,
            boot_epoch: s.boot,
            owner: q.owner,
        };
        r.spectator = Some(Spectator { trial_id, ..q });
        r.advanced_from = Some(old);
        r.token = Some(token);
        r.stop_closing = None;
        Ok(token)
    })
}
pub fn stop_spectator_fixture(token: Token) -> Result<bool, Error> {
    with(|s| {
        authorized(s)?;
        if root().token != Some(token) || root().spectator.is_none() {
            return Err(Error::Stale);
        }
        fixture::stop(s, token)
    })
}
pub fn release_spectator(token: Token) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let r = root();
        if r.token != Some(token) || r.spectator.is_none_or(|v| v.owner != token.owner) {
            return Err(Error::Stale);
        }
        if !fixture::closed(r) {
            return Err(Error::Busy);
        }
        if let Some(fault) = r.fault {
            if r.phase != Phase::Faulted {
                return Err(Error::Busy);
            }
            // A started partner still owns real work after a root fault. Only
            // its protected, excluded, fully exported ledger can authorize
            // release; the original fixture must also have truly stopped.
            crate::peer_replay::faulted_settled(token, fault)?;
        } else if r.phase != Phase::Frozen {
            return Err(Error::Busy);
        }
        let checks = *r
            .registered
            .iter()
            .flatten()
            .find(|o| o.owner == token.owner)
            .ok_or(Error::NotReady)?;
        (checks.settled)(token)?;
        let r = root_mut();
        r.spectator = None;
        r.token = None;
        r.phase = Phase::Complete;
        Ok(())
    })
}
/// A peer reservation that never opened its observation may be abandoned only
/// after its registered owner proves zero live work/credits and its real fixed
/// fixture has stopped. A root scan/configuration fault is retained in the
/// signed negative preparation receipt, rather than turned into an adoption.
pub fn release_spectator_prepared(token: Token) -> Result<bool, Error> {
    with(|s| {
        authorized(s)?;
        if root().token != Some(token) || root().spectator.is_none_or(|p| p.owner != token.owner) {
            return Err(Error::Stale);
        }
        if s.job.is_some()
            || s.owner.prepared_count != 0
            || s.owner
                .desired
                .iter()
                .flatten()
                .any(execution_blocks_replacement)
        {
            return Ok(false);
        }
        if !fixture::stop(s, token)? {
            return Ok(false);
        }
        let check = root()
            .registered
            .iter()
            .flatten()
            .find(|o| o.owner == token.owner)
            .ok_or(Error::Auth)?
            .settled;
        check(token)?;
        let r = root_mut();
        r.spectator = None;
        r.token = None;
        r.phase = Phase::Complete;
        r.fault = None;
        Ok(true)
    })
}

/// Runs at the first real candidate-generation entry, before encoding. The
/// pre-registered owner may activate only its already-frozen manifest here.
pub struct Prefix {
    cpu_started: u64,
    attempt: Option<crate::learning_evidence::OwnerAttempt>,
}
impl Drop for Prefix {
    fn drop(&mut self) {
        if let Some(mut attempt) = self.attempt.take() {
            let (first, last, _) = crate::domain_tasks::finish_cpu_interval(self.cpu_started);
            let _ = crate::learning_evidence::finish_attempt(&mut attempt, first, last);
        }
    }
}
/// Only the synchronous, same-CPU pre-registered callback may use this entry.
pub fn activation(token: Token) -> bool {
    ACTIVATING.load(core::sync::atomic::Ordering::Acquire) == cyxia_arch_aarch64::cpu::slot() + 1
        && root().token == Some(token)
}
fn activate(token: Token, q: Request, snapshot: Snapshot) -> Result<Prefix, Error> {
    if ACTIVATION_TOKEN.load(Ordering::Relaxed) != token.id {
        ACTIVATION_TOKEN.store(token.id, Ordering::Relaxed);
        ACTIVATION_ATTEMPTS.store(0, Ordering::Relaxed);
    }
    ACTIVATION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let cpu_started = cyxia_arch_aarch64::timer::cpu_ticks();
    let first = root().first;
    let snapshot = first.unwrap_or(snapshot);
    if first.is_none() {
        let before = root()
            .registered
            .iter()
            .flatten()
            .find(|o| o.owner == q.owner)
            .ok_or(Error::NotReady)?
            .before_first;
        before(token, snapshot)?;
        root_mut().first = Some(snapshot);
    }
    ACTIVATING.store(
        cyxia_arch_aarch64::cpu::slot() + 1,
        core::sync::atomic::Ordering::Release,
    );
    let result = (q.on_first)(token, snapshot);
    ACTIVATING.store(0, core::sync::atomic::Ordering::Release);
    let attempt = crate::learning_evidence::attempt(q.target, learning::reward::CpuClass::Policy)
        .ok()
        .flatten();
    let prefix = Prefix {
        cpu_started,
        attempt,
    };
    if let Err(e) = result {
        drop(prefix);
        return if matches!(e, Error::Busy | Error::Again | Error::NotReady) {
            Err(e)
        } else {
            Err(fail(root_mut(), e))
        };
    }
    root_mut().first_ready = true;
    // Capture/history readiness is not workload activation. Retain the exact
    // preparation until CPU0 has actually completed all owner activations.
    Ok(prefix)
}
/// Only this candidate's first unpublished attempt owns a fixed preparation
/// before capture callbacks can freeze its snapshot or return a retry.
/// Legitimate one-shot prewarming waits have not started that attempt yet.
pub(super) fn first_preparation(
    boot: u64,
    snapshot: Snapshot,
    domain: u16,
    kind: u16,
    target: ObjectKey,
) -> bool {
    let r = root();
    r.phase == Phase::Running
        && r.fault.is_none()
        && r.initial.is_none()
        && r.token.is_some_and(|token| token.boot_epoch == boot)
        && r.first.is_none_or(|first| first == snapshot)
        && r.request.is_some_and(|q| {
            q.kind == TrialKind::Candidate
                && q.family == (LearningFamily { domain, kind })
                && q.target == target
                && snapshot.taken_ns >= q.not_before_ns
        })
}
pub(super) fn first(
    snapshot: Snapshot,
    domain: u16,
    kind: u16,
    target: ObjectKey,
) -> Result<(Snapshot, Option<Prefix>), Error> {
    let r = root();
    let Some(q) = r.request else {
        return Ok((snapshot, None));
    };
    if !allows(domain, kind, target) {
        return Err(Error::Busy);
    }
    let r = root();
    if r.first_ready {
        // Until a job has actually been registered, retries retain the exact
        // first identity and deadline. A later job already has a fresh sequence.
        let original = r.first.filter(|first| first.sequence == snapshot.sequence);
        return Ok((original.unwrap_or(snapshot), None));
    }
    if snapshot.taken_ns < q.not_before_ns {
        return Err(Error::Again);
    }
    let prefix = activate(r.token.ok_or(Error::Stale)?, q, snapshot)?;
    Ok((root().first.ok_or(Error::Stale)?, Some(prefix)))
}
/// A first decision that failed before proposal construction cannot restart
/// the same captured trial under a new sequence or refreshed deadline.
pub(super) fn reject_preparation(
    identity: preparation::Identity,
    snapshot: Snapshot,
    error: Error,
) {
    let r = root_mut();
    if r.first == Some(snapshot)
        && r.initial.is_none()
        && r.request.is_some_and(|q| {
            q.family.domain == identity.domain
                && q.family.kind == identity.kind
                && q.target == identity.target
        })
    {
        fail(r, error);
    }
}
/// A completed, unpublished first job has exhausted its original attempt.
/// Its captured scope cannot acquire a new first sequence or deadline.
pub(super) fn reject_first_job(boot: u64, sequence: u64, set: &CandidateSet, error: Error) {
    let r = root_mut();
    if r.phase == Phase::Running
        && r.token.is_some_and(|token| token.boot_epoch == boot)
        && sequence == set.snapshot.sequence
        && r.first == Some(set.snapshot)
        && r.initial.is_none()
        && r.request.is_some_and(|q| {
            q.kind == TrialKind::Candidate
                && q.target == set.target
                && set.get(0).is_some_and(|first| {
                    q.family.domain == first.action.domain() && q.family.kind == first.action.kind()
                })
        })
    {
        fail(r, error);
    }
}
pub(super) fn published(
    plan: &Plan,
    boot: u64,
    first_stamp: Option<PolicyStamp>,
) -> Result<(), Error> {
    let r = root_mut();
    let Some(q) = r.request else {
        return Ok(());
    };
    if r.lifecycle.closing().is_some() || r.unpublished.is_some() {
        return Err(Error::Auth);
    }
    for d in plan.iter() {
        if d.action.domain() != q.family.domain
            || d.action.kind() != q.family.kind
            || d.envelope.target != q.target
        {
            return Err(Error::Auth);
        }
        if r.phase == Phase::Running && q.kind == TrialKind::Candidate {
            if r.selected.is_some_and(|a| a != d.action) {
                return Err(Error::Conflict);
            }
            r.selected = Some(d.action);
            r.renew_after = if d.action.one_shot() {
                u64::MAX
            } else {
                plan.header
                    .active_until_local_ns
                    .saturating_sub(2_000_000_000)
            };
        }
        // A baseline PUBLISH is just as irrevocable as a model proposal. This
        // latch is set under the same root gate immediately before Desired,
        // even if the caller later fails to retrieve the receipt.
        let apply = ApplyId {
            boot_epoch: boot,
            controller_epoch: plan.header.controller_epoch,
            plan_seq: plan.header.plan_seq,
            action_index: 0,
            target: q.target,
        };
        let first = r.initial.is_none();
        if first {
            r.initial = Some(apply);
        }
        if q.kind == TrialKind::Candidate
            && (first
                || r.phase == Phase::Running
                    && !d.action.one_shot()
                    && r.candidate_publication.is_some_and(|old| {
                        old.state.terminal()
                            && r.token == Some(old.token)
                            && old.stamp.version != 0
                            && old.apply.boot_epoch == apply.boot_epoch
                            && old.apply.controller_epoch == apply.controller_epoch
                            && old.apply.target == apply.target
                            && apply.plan_seq > old.apply.plan_seq
                            && first_stamp.is_some_and(|stamp| {
                                stamp.version > old.stamp.version
                                    && stamp.snapshot_ns > old.stamp.snapshot_ns
                            })
                    }))
        {
            r.candidate_publication =
                r.token
                    .zip(first_stamp)
                    .map(|(token, stamp)| CandidatePublication {
                        token,
                        apply,
                        stamp,
                        family: q.family,
                        state: ExecutionState::Pending,
                    });
        }
    }
    Ok(())
}
/// Called after Control has finalized the real execution state, including
/// pre-executor refusal and deadline conversion. No Registry query or retry.
pub(super) fn candidate_execution(apply: ApplyId, stamp: PolicyStamp, state: ExecutionState) {
    let r = root_mut();
    if let Some(initial) = r.candidate_publication.as_mut()
        && r.token == Some(initial.token)
        && r.initial.is_some_and(|first| {
            first.boot_epoch == apply.boot_epoch
                && first.controller_epoch == apply.controller_epoch
                && first.action_index == apply.action_index
                && first.target == apply.target
                && first.plan_seq <= apply.plan_seq
        })
        && initial.apply == apply
        && initial.stamp == stamp
        && !initial.state.terminal()
    {
        initial.state = state;
    }
}
/// Copies the original pre-executor refusal under the already-held root gate.
/// An executor-returned Stale does not enter this diagnostic path.
pub(super) fn candidate_stale(e: &crate::learning_evidence::execution_trace::ControlDenial) {
    let r = root();
    let (Some(q), Some(token), Some(first), Some(initial)) =
        (r.request, r.token, r.first, r.initial)
    else {
        return;
    };
    if q.kind != TrialKind::Candidate
        || r.phase != Phase::Running
        || e.error != Error::Stale
        || !matches!(e.flags, 1 | 2 | 4)
        || token.owner != q.owner
        || token.boot_epoch != e.apply.boot_epoch
        || initial.boot_epoch != e.apply.boot_epoch
        || initial.controller_epoch != e.apply.controller_epoch
        || initial.action_index != e.apply.action_index
        || initial.target != e.apply.target
        || first.sequence != initial.plan_seq
        || e.apply.plan_seq < initial.plan_seq
        || e.stamp.version == 0
        || e.stamp.snapshot_ns < first.taken_ns
        || q.target != e.apply.target
        || q.family.domain != e.action.domain()
        || q.family.kind != e.action.kind()
    {
        return;
    }
    crate::domain_evidence::candidate_stale([
        token.id,
        token.boot_epoch,
        token.owner.id,
        token.owner.generation,
        q.trial_id,
        first.sequence,
        first.taken_ns,
        first.ledger_generation,
        first.core_generation,
        e.apply.boot_epoch,
        e.apply.controller_epoch,
        e.apply.plan_seq,
        u64::from(e.apply.action_index),
        e.apply.target.id,
        e.apply.target.generation,
        e.stamp.version,
        e.stamp.snapshot_ns,
        e.stamp.installed_until_ns,
        e.observed_ns,
        e.expected_core,
        e.current_core,
        e.expected_ledger,
        e.current_ledger,
        e.flags,
        e.error as u64 + 1,
        u64::from(q.family.domain),
        u64::from(q.family.kind),
        initial.plan_seq,
        r.phase as u64 + 1,
        u64::from(r.first_ready),
        u64::from(initial.action_index),
    ]);
}
fn hash_config(h: &mut Sha256, c: Configuration) -> Result<(), Error> {
    let mut b = [0u8; 32];
    let n = learning::baseline::encode(c.action, &mut b).map_err(|_| Error::Schema)?;
    h.update(c.family.domain.to_le_bytes());
    h.update(c.family.kind.to_le_bytes());
    h.update(c.target.id.to_le_bytes());
    h.update(c.target.generation.to_le_bytes());
    h.update(&b[..n]);
    Ok(())
}
fn receipt(
    s: &State,
    id: ApplyId,
    stamp: PolicyStamp,
    snapshot: Snapshot,
    action: Action,
) -> Result<Receipt, Error> {
    let i = locate(&s.owner, action, id.target).ok_or(Error::NotFound)?;
    let d = s.owner.desired[i].ok_or(Error::NotFound)?;
    if d.apply != id || d.stamp != stamp || d.action != action {
        return Err(Error::Stale);
    }
    let generation = s.owner.family_epochs[family_index(action.domain(), action.kind())?];
    if generation == 0 {
        return Err(Error::NotReady);
    }
    Ok(Receipt {
        action,
        apply: id,
        stamp,
        snapshot,
        state: d.state,
        executor_generation: generation,
        issued_ns: snapshot.taken_ns,
        accepted_ns: d.published,
        started_ns: d.first_entry_ns,
        observed_ns: d.observed_ns,
        approved_deadline_ns: d
            .published
            .checked_add(execution_limit(action))
            .ok_or(Error::Overflow)?,
    })
}
fn latest(s: &State, r: &Root) -> Result<Option<Receipt>, Error> {
    let Some(q) = r.request else {
        return Ok(None);
    };
    let Some(i) = locate_family(&s.owner, q.family.domain, q.family.kind, q.target) else {
        return Ok(None);
    };
    let Some(d) = s.owner.desired[i] else {
        return Ok(None);
    };
    if r.first
        .is_none_or(|first| d.stamp.snapshot_ns < first.taken_ns)
    {
        return Ok(None);
    }
    receipt(
        s,
        d.apply,
        d.stamp,
        Snapshot {
            sequence: d.apply.plan_seq,
            taken_ns: d.stamp.snapshot_ns,
            core_generation: d.core_generation,
            ledger_generation: d.ledger_generation,
        },
        d.action,
    )
    .map(Some)
}
fn check_configs(s: &State, r: &mut Root) -> Result<(), Error> {
    for _ in 0..4 {
        if r.count == 0 {
            break;
        }
        if r.cursor >= r.count {
            r.cursor = 0;
        }
        let c = r.configs[r.cursor].ok_or(Error::Conflict)?;
        if fixture::skip_config(r, c) {
            r.cursor += 1;
            continue;
        }
        let f =
            s.owner.families[family_index(c.family.domain, c.family.kind)?].ok_or(Error::Stale)?;
        let actual = (f.current)(c.family.domain, c.family.kind, c.target);
        match actual {
            Ok(a) if a == c.action => (),
            Err(Error::Busy | Error::Again | Error::NotReady) => return Err(Error::Busy),
            _ => {
                config_diagnostic::record(
                    config_diagnostic::Context {
                        phase: r.phase as u64 + 1,
                        cursor: r.cursor as u64,
                        count: r.count as u64,
                        token: r.token.map_or(0, |t| t.id),
                        boot: r.token.map_or(0, |t| t.boot_epoch),
                        trial: r
                            .request
                            .map_or(r.spectator.map_or(0, |q| q.trial_id), |q| q.trial_id),
                        kind: r
                            .request
                            .map_or(0, |q| if q.kind == TrialKind::Candidate { 1 } else { 2 }),
                        first: r.first,
                        ledger: s.owner.context.ledger_generation,
                        core: s.owner.context.core_generation,
                        fault: r.fault,
                    },
                    c.family,
                    c.target,
                    c.action,
                    actual,
                    now(),
                );
                return Err(fail(r, Error::Conflict));
            }
        }
        r.cursor += 1;
    }
    Ok(())
}
/// Bounded service/control polling. No poll can silently discard UNKNOWN.
pub fn poll(token: Token) -> Result<Status, Error> {
    with(|s| {
        authorized(s)?;
        if root().token != Some(token) || (root().request.is_none() && root().spectator.is_none()) {
            return Err(Error::Stale);
        }
        // A version-zero Registry failure is terminal even when its domain
        // code is Busy. Expose that retained spectator failure instead of
        // reissuing the same positive fixture forever. The separate stop /
        // release_prepared entries still reconcile its original obligations.
        if root().spectator.is_some() && root().fault.is_some() {
            return status(s, root());
        }
        if let Err(error) = fixture::poll(s, token) {
            if root().spectator.is_some() {
                if root().fault.is_none()
                    && !matches!(error, Error::Busy | Error::Again | Error::NotReady)
                {
                    fail(root_mut(), error);
                }
                if root().fault.is_some() {
                    return status(s, root());
                }
            }
            return Err(error);
        }
        let r = root_mut();
        if r.token != Some(token) || (r.request.is_none() && r.spectator.is_none()) {
            return Err(Error::Stale);
        }
        let q = r.request;
        let at = now();
        if r.model != Some(s.registry.model()) {
            return Err(fail(r, Error::Stale));
        }
        match r.phase {
            Phase::Quiescing => {
                if s.job.is_some() {
                    return status(s, r);
                }
                let end = (r.cursor + 8).min(s.owner.desired.len());
                for d in s.owner.desired[r.cursor..end].iter().flatten() {
                    if execution_blocks_replacement(d)
                        || (!fixture::skip_wait(r, d) && !d.action.one_shot() && d.stamp.live(at))
                    {
                        r.cursor = 0;
                        return status(s, r);
                    }
                }
                r.cursor = end;
                if end == s.owner.desired.len() && fixture::ready(r) {
                    r.phase = Phase::Scanning;
                    r.cursor = 0;
                    let mut h = Sha256::new();
                    h.update(b"CYXIA_NATIVE_FROZEN_CONFIGURATION_1.3\0");
                    h.update(s.registry.model().model_hash);
                    // Dynamic object identity and selected parameters are read
                    // from actual owners below. Trial IDs are not reset proof.
                    r.hashing = Some(h);
                }
            }
            Phase::Scanning => {
                for _ in 0..4 {
                    if r.family == 18 {
                        r.digest = r.hashing.take().ok_or(Error::Conflict)?.finalize().into();
                        r.phase = Phase::Frozen;
                        r.cursor = 0;
                        break;
                    }
                    let Some(f) = s.owner.families[r.family] else {
                        r.family += 1;
                        r.ordinal = 0;
                        continue;
                    };
                    // Placement requests are ephemeral work, not a persistent
                    // parameter. Its frozen fallback rule is in the image and
                    // the workload owner's manifest, never a fake object row.
                    if (f.domain, f.kind) == (16, 2) {
                        r.family += 1;
                        r.ordinal = 0;
                        continue;
                    }
                    let Some(target) = (f.target)(f.domain, f.kind, r.ordinal) else {
                        r.family += 1;
                        r.ordinal = 0;
                        continue;
                    };
                    let action = (f.current)(f.domain, f.kind, target)?;
                    if !q.is_some_and(|q| {
                        target == q.target && f.domain == q.family.domain && f.kind == q.family.kind
                    }) {
                        if r.count == r.configs.len() {
                            return Err(fail(r, Error::Capacity));
                        }
                        let c = Configuration {
                            family: LearningFamily {
                                domain: f.domain,
                                kind: f.kind,
                            },
                            target,
                            action,
                        };
                        hash_config(r.hashing.as_mut().ok_or(Error::Conflict)?, c)?;
                        r.configs[r.count] = Some(c);
                        r.count += 1;
                    }
                    r.ordinal += 1;
                }
            }
            Phase::Frozen | Phase::Running | Phase::Restoring => {
                // A retained configuration fault excludes the trial, but
                // cannot prevent its real restoration receipt from settling.
                // Keep that fault for verify_scope/adoption and advance gates.
                if r.phase != Phase::Restoring || r.fault.is_none() {
                    check_configs(s, r)?;
                }
                for i in 0..r.baseline_count {
                    let old = r.baseline[i].ok_or(Error::Conflict)?;
                    if !old.state.terminal() && old.action != Action::OfferCpu(0) {
                        r.baseline[i] =
                            Some(receipt(s, old.apply, old.stamp, old.snapshot, old.action)?);
                    }
                }
                if let Some(old) = r.closing {
                    if !old.state.terminal() && old.action != Action::OfferCpu(0) {
                        r.closing =
                            Some(receipt(s, old.apply, old.stamp, old.snapshot, old.action)?);
                    }
                }
                if r.phase == Phase::Restoring
                    && r.closing
                        .is_some_and(|v| v.state == ExecutionState::Applied)
                {
                    r.phase = Phase::Complete;
                }
            }
            _ => (),
        }
        status(s, r)
    })
}
fn status(s: &State, r: &Root) -> Result<Status, Error> {
    Ok(Status {
        phase: r.phase,
        frozen_other_domains: r.digest,
        first: r.first,
        selected: r.selected,
        receipt: if r.request.is_some_and(|q| q.kind == TrialKind::Baseline) {
            r.baseline_count.checked_sub(1).and_then(|i| r.baseline[i])
        } else {
            latest(s, r)?
        },
        closing: r.closing,
        unpublished: r.unpublished,
        fault: r.fault,
    })
}

pub fn start_candidate(token: Token) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let r = root_mut();
        let q = exact(r, token)?;
        if r.lifecycle.closing().is_some() {
            return Err(Error::Auth);
        }
        if q.kind == TrialKind::Candidate && r.phase == Phase::Running {
            return Ok(());
        }
        if q.kind != TrialKind::Candidate || r.phase != Phase::Frozen || r.digest == [0; 32] {
            return Err(Error::Conflict);
        }
        r.phase = Phase::Running;
        Ok(())
    })
}

struct BaselineScope {
    token: Token,
    action: Action,
    target: ObjectKey,
    model: ModelBinding,
    snapshot: Snapshot,
    task_publication: Option<crate::domain_tasks::BaselinePublication>,
}
impl PublicationScope for BaselineScope {
    fn legal(&self, f: Family, action: Action, target: ObjectKey, at: u64) -> Result<(), Error> {
        match self.task_publication.as_ref() {
            Some(task) => task.validate(action, target, at),
            None => (f.legal)(action, target, at),
        }
    }
    fn dependencies(
        &self,
        owner: &Owner,
        action: Action,
        target: ObjectKey,
        at: u64,
    ) -> Result<[Option<BoundDependency>; 2], Error> {
        baseline_dependencies(owner, action, target, at, self.task_publication.as_ref())
    }
    fn authorize_baseline(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        at: u64,
    ) -> Result<(), Error> {
        self.authorize(active, set, at)
    }
    fn authorize_executor(&self, owner: &Owner) -> Result<(), Error> {
        if let Some(task) = self.task_publication.as_ref() {
            task.authorize_service_turn()
        } else if cyxia_arch_aarch64::cpu::slot() == 0 {
            crate::domain_tasks::authorize_service_turn()
        } else {
            require_control(owner)
        }
    }
    fn authorize(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        _: u64,
    ) -> Result<(), Error> {
        self.bound()?;
        if active != self.model
            || set.model != active
            || set.canary_permit().is_some()
            || set.baseline_action() != Some(self.action)
            || set.target != self.target
            || set.snapshot != self.snapshot
        {
            return Err(Error::Auth);
        }
        Ok(())
    }
    fn selection(
        &self,
        _: &Owner,
        _: Family,
        action: Action,
        target: ObjectKey,
        _: u64,
    ) -> Result<(), Error> {
        self.bound()?;
        if action != self.action || target != self.target {
            return Err(Error::Auth);
        }
        Ok(())
    }
    fn authorize_recovery(
        &mut self,
        active: ModelBinding,
        plan: &Plan,
        _: u64,
    ) -> Result<(), Error> {
        self.check(active, plan)
    }
    fn commit(
        &mut self,
        _: &Owner,
        model: ModelBinding,
        plan: &Plan,
        _: &[PolicyStamp],
        boot: u64,
        _: u64,
    ) -> Result<(), Error> {
        if boot != self.token.boot_epoch {
            return Err(Error::Stale);
        }
        self.check(model, plan)
    }
}
fn baseline_dependencies(
    owner: &Owner,
    action: Action,
    target: ObjectKey,
    at: u64,
    task: Option<&crate::domain_tasks::BaselinePublication>,
) -> Result<[Option<BoundDependency>; 2], Error> {
    let Some(task) = task else {
        return bind_dependencies(owner, action, target, at);
    };
    if !matches!(action.domain(), 1 | 8) {
        return Ok([None; 2]);
    }
    // Preserve the registered prerequisite contract. Both task-owner edges
    // (D13 -> D01 and D05 -> D08) read their real owners through this same gate.
    owner.dependencies[usize::from(action.domain() - 1)].ok_or(Error::NotReady)?;
    bind_dependency_list(
        owner,
        action,
        at,
        task.prerequisites(action, target)?,
        |f, key| task.current(f.domain, key),
        |_, value, key| task.validate(value, key, at),
    )
}
impl BaselineScope {
    fn bound(&self) -> Result<(), Error> {
        let r = root();
        if r.token != Some(self.token) {
            return Err(Error::Stale);
        }
        if r.model != Some(self.model) {
            return Err(Error::Stale);
        }
        if r.lifecycle.closing().is_some() || r.unpublished.is_some() {
            return Err(Error::Auth);
        }
        if let Some(q) = r.request {
            if self.action != q.baseline {
                return Err(Error::Auth);
            }
            if self.target == q.target {
                return Ok(());
            }
        } else if r
            .spectator
            .and_then(|q| q.fixture)
            .is_some_and(|f| f.target == self.target && f.action == self.action)
        {
            return Ok(());
        }
        Err(Error::Auth)
    }
    fn check(&self, model: ModelBinding, plan: &Plan) -> Result<(), Error> {
        self.bound()?;
        if model != self.model
            || plan.len() != 1
            || plan.header.active_model_generation != model.generation
        {
            return Err(Error::Stale);
        }
        let d = plan.iter().next().ok_or(Error::Format)?;
        if d.action != self.action
            || d.envelope.target != self.target
            || d.envelope.model_hash != model.model_hash
        {
            return Err(Error::Auth);
        }
        Ok(())
    }
}
fn publish_baseline(s: &mut State, token: Token, closing: bool) -> Result<Receipt, Error> {
    let mut trace = PublicationTrace {
        stage: 1,
        ..PublicationTrace::default()
    };
    let result = publish_baseline_traced(s, token, closing, &mut trace);
    if let Err(error) = result {
        publication_failure(s, token, closing, &trace, error);
    }
    result
}
fn publish_baseline_traced(
    s: &mut State,
    token: Token,
    closing: bool,
    trace: &mut PublicationTrace,
) -> Result<Receipt, Error> {
    // The CoreSet object's identity is the boot-bound key. Its mutable core
    // generation belongs in Snapshot/Envelope, not in the object's identity.
    let q = exact(root(), token)?;
    if root().lifecycle.closing().is_some() || root().unpublished.is_some() {
        return Err(Error::Auth);
    }
    let at = now();
    let action = q.baseline;
    let cost_owner = q.target;
    if at < q.not_before_ns && !closing {
        return Err(Error::Again);
    }
    if let Some(i) = locate_family(&s.owner, q.family.domain, q.family.kind, q.target) {
        if s.owner.desired[i]
            .as_ref()
            .is_some_and(execution_blocks_replacement)
        {
            return Err(Error::Busy);
        }
    }
    let activating = !closing && !root().first_ready;
    let mut _prefix = if activating {
        None
    } else {
        Some(Prefix {
            cpu_started: cyxia_arch_aarch64::timer::cpu_ticks(),
            attempt: crate::learning_evidence::attempt(
                cost_owner,
                learning::reward::CpuClass::Policy,
            )
            .ok()
            .flatten(),
        })
    };
    trace.stage = 3;
    let mut publication_started = if activating {
        None
    } else {
        Some(policy::Clock::read(&mut NativeClock))
    };
    // A renewal does not acquire a new Snapshot/Plan identity until its live
    // task owner is reserved. A first activation retains root.first instead;
    // its callback must finish outside the task gate before we can reserve it.
    let mut task_publication = if activating {
        None
    } else {
        crate::domain_tasks::reserve_baseline_publication(action, q.target)?
    };
    let sequence = s.sequence.checked_add(1).ok_or(Error::Overflow)?;
    let mut snapshot = Snapshot {
        sequence,
        taken_ns: at,
        core_generation: s.owner.context.core_generation,
        ledger_generation: s.owner.context.ledger_generation,
    };
    trace.used = if !closing {
        root().first.unwrap_or(snapshot)
    } else {
        snapshot
    };
    if activating {
        trace.stage = 2;
        _prefix = Some(activate(token, q, snapshot)?);
        trace.stage = 3;
        publication_started = Some(policy::Clock::read(&mut NativeClock));
        task_publication = crate::domain_tasks::reserve_baseline_publication(action, q.target)?;
    }
    if !closing && root().baseline_count == 0 {
        snapshot = root().first.ok_or(Error::Stale)?;
    }
    trace.used = snapshot;
    if action == Action::OfferCpu(0) {
        // The asynchronous owner must see the same command and original
        // deadline on every retry. Closing is a distinct real command.
        let stop_snapshot = if closing {
            if let Some(old) = root().stop_closing {
                old
            } else {
                root_mut().stop_closing = Some(snapshot);
                s.sequence = sequence;
                snapshot
            }
        } else {
            let first = root().first.ok_or(Error::NotReady)?;
            s.sequence = s.sequence.max(first.sequence);
            first
        };
        trace.stage = 14;
        trace.used = stop_snapshot;
        let actual = (root()
            .registered
            .iter()
            .flatten()
            .find(|o| o.owner == q.owner)
            .ok_or(Error::NotReady)?
            .stop_offer)(token, q.target, stop_snapshot)?;
        if actual.action != action
            || actual.apply.target != q.target
            || actual.apply.boot_epoch != token.boot_epoch
            || actual.state != ExecutionState::Applied
            || actual.stamp.installed_until_ns != 0
        {
            return Err(Error::NotReady);
        }
        return Ok(actual);
    }
    publish_value_traced(
        s,
        token,
        q.target,
        action,
        snapshot,
        trace,
        BaselineAdmission {
            task: task_publication,
            started: publication_started.ok_or(Error::NotReady)?,
        },
    )
}
fn publish_value(
    s: &mut State,
    token: Token,
    target: ObjectKey,
    action: Action,
    snapshot: Snapshot,
) -> Result<Receipt, Error> {
    let mut trace = PublicationTrace {
        used: snapshot,
        ..PublicationTrace::default()
    };
    let publication_started = policy::Clock::read(&mut NativeClock);
    let result =
        crate::domain_tasks::reserve_baseline_publication(action, target).and_then(|task| {
            publish_value_traced(
                s,
                token,
                target,
                action,
                snapshot,
                &mut trace,
                BaselineAdmission {
                    task,
                    started: publication_started,
                },
            )
        });
    if let Err(error) = result {
        publication_failure(s, token, false, &trace, error);
    }
    result
}
struct BaselineAdmission {
    task: Option<crate::domain_tasks::BaselinePublication>,
    started: policy::PublicationTime,
}
fn publish_value_traced(
    s: &mut State,
    token: Token,
    target: ObjectKey,
    action: Action,
    snapshot: Snapshot,
    trace: &mut PublicationTrace,
    admission: BaselineAdmission,
) -> Result<Receipt, Error> {
    let BaselineAdmission {
        task: task_publication,
        started: publication_started,
    } = admission;
    trace.used = snapshot;
    trace.stage = 16;
    let at = snapshot.taken_ns;
    let sequence = snapshot.sequence;
    // The normal root may have committed before the caller observed its
    // receipt. Retry the original identity, never issue a replacement command.
    if let Some(index) = locate(&s.owner, action, target) {
        if let Some(old) = s.owner.desired[index] {
            if old.apply.boot_epoch == s.boot && old.apply.plan_seq == sequence {
                if old.action != action || old.stamp.snapshot_ns != at {
                    return Err(Error::Conflict);
                }
                return receipt(s, old.apply, old.stamp, snapshot, action);
            }
        }
    }
    if now() > at.checked_add(50_000_000).ok_or(Error::Overflow)? {
        return Err(Error::Expired);
    }
    let f =
        s.owner.families[family_index(action.domain(), action.kind())?].ok_or(Error::NotReady)?;
    trace.stage = 3;
    match task_publication.as_ref() {
        Some(task) => task.validate(action, target, at)?,
        None => (f.legal)(action, target, at)?,
    }
    trace.stage = 4;
    let current = match task_publication.as_ref() {
        Some(task) => task.current(f.domain, target)?,
        None => (f.current)(f.domain, f.kind, target)?,
    };
    trace.stage = 5;
    ensure_stability(&mut s.owner, current, target, at)?;
    trace.stage = 8;
    let dependencies =
        baseline_dependencies(&s.owner, action, target, at, task_publication.as_ref())?;
    let model = s.registry.model();
    // A fixed owner-approved baseline does not consume model observations or
    // scores. Missing workload statistics remain missing; the exact action is
    // separately registered, then checked by the same native executor below.
    trace.stage = 10;
    let set_hash =
        s.registry
            .register_baseline(s.registry.publisher(), snapshot, target, model, action)?;
    let controller = s.registry.publisher().controller_epoch;
    let header = PlanHeader {
        plan_seq: sequence,
        base_plan_version: s.registry.version(),
        active_model_generation: model.generation,
        controller_epoch: controller,
        snapshot_seq: sequence,
        active_until_local_ns: if action.one_shot() {
            0
        } else {
            at.checked_add(POLICY_NS).ok_or(Error::Overflow)?
        },
    };
    let decision = Decision {
        action,
        candidate_index: 0,
        envelope: Envelope {
            controller_epoch: controller,
            decision_seq: sequence,
            snapshot_seq: sequence,
            target: target,
            ledger_generation: snapshot.ledger_generation,
            core_generation: snapshot.core_generation,
            expires_local_ns: at.checked_add(WINDOW_NS).ok_or(Error::Overflow)?,
            model_hash: model.model_hash,
            candidate_set_hash: set_hash,
        },
    };
    let mut bytes = [0; 384];
    trace.stage = 11;
    let n = policy_wire::encode_plan(header, &[decision], &mut bytes)?;
    s.sequence = sequence;
    // Candidate/manifest work is already charged by Prefix. The publication
    // cap starts at the actual input-to-root boundary, while its wall deadline
    // and immutable snapshot still come from the original generation.
    let mut executor = Executor {
        owner: &mut s.owner,
        scope: BaselineScope {
            token,
            action,
            target: target,
            model,
            snapshot,
            task_publication,
        },
        model,
        evidence: None,
        job: sequence,
        boot: s.boot,
        publication_started,
        publication_debit: policy::CpuTime {
            cpu: publication_started.cpu.cpu,
            ns: 0,
        },
        wall_deadline: at.checked_add(50_000_000).ok_or(Error::Overflow)?,
        dependencies,
        scores: [0; 32],
        score_count: 0,
        provenance: submission::Facts::disabled(),
    };
    trace.stage = 12;
    let published = s.registry.submit_job(
        publisher(controller),
        &bytes[..n],
        publication_started,
        executor.wall_deadline,
        &mut NativeClock,
        &mut executor,
    )?;
    trace.receipt = Some(published);
    if published.version == 0 {
        let error = match published.state() {
            ExecutionState::Failed(e) => e,
            _ => Error::Conflict,
        };
        if matches!(published.state(), ExecutionState::Failed(_)) {
            let rejected = RejectedPublication {
                token,
                receipt: published,
                snapshot,
                header,
                decision,
                model,
                received_ns: publication_started.wall_ns,
                observed_ns: now(),
                wall_deadline_ns: executor.wall_deadline,
                plan_hash: Sha256::digest(&bytes[..n]).into(),
            };
            // In particular Failed(Busy) is a sealed Registry outcome. It
            // must not be retried with new features under the same PlanId.
            root_mut().rejected.get_or_insert(rejected);
            return Err(fail(root_mut(), error));
        }
        return Err(error);
    }
    let apply = ApplyId {
        boot_epoch: s.boot,
        controller_epoch: controller,
        plan_seq: sequence,
        action_index: 0,
        target: target,
    };
    trace.stage = 13;
    let stamp = PolicyStamp::for_action(action, published.version, at, at)?;
    receipt(s, apply, stamp, snapshot, action)
}
pub fn baseline_apply(token: Token) -> Result<Receipt, Error> {
    with(|s| {
        authorized(s)?;
        let r = root_mut();
        let q = exact(r, token)?;
        if q.kind != TrialKind::Baseline || !matches!(r.phase, Phase::Frozen | Phase::Running) {
            return Err(Error::Conflict);
        }
        if r.baseline_count == r.baseline.len() {
            return Err(Error::Capacity);
        }
        if let Some(old) = r.baseline_count.checked_sub(1).and_then(|i| r.baseline[i]) {
            if !old.state.terminal() {
                return Ok(old);
            }
            if old.action.one_shot() || old.action == Action::OfferCpu(0) {
                return Ok(old);
            }
            let at = now();
            // A proposal rejected before executor entry installed no lease.
            // While a prior real installation still covers this instant, a
            // later renewal may make one independent decision. Keep the failed
            // receipt in its original slot; never refresh or revive its stamp.
            let unstarted_failed_renewal = matches!(old.state, ExecutionState::Failed(_))
                && old.started_ns.is_none()
                && r.baseline[..r.baseline_count - 1]
                    .iter()
                    .flatten()
                    .any(|prior| {
                        prior.state == ExecutionState::Applied
                            && prior.started_ns.is_some()
                            && prior.action == old.action
                            && prior.apply.target == old.apply.target
                            && prior.apply.boot_epoch == old.apply.boot_epoch
                            && prior.stamp.live(at)
                    });
            if !unstarted_failed_renewal
                && old.stamp.installed_until_ns > at.saturating_add(1_000_000_000)
            {
                return Ok(old);
            }
        }
        let value = publish_baseline(s, token, false)?;
        let r = root_mut();
        r.baseline[r.baseline_count] = Some(value);
        r.baseline_count += 1;
        r.phase = Phase::Running;
        Ok(value)
    })
}
pub fn restore(token: Token) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let r = root();
        let q = exact(r, token)?;
        if r.phase == Phase::Complete {
            return if r.closing.is_some() || r.unpublished.is_some() {
                Ok(())
            } else {
                Err(Error::NotReady)
            };
        }
        // An unactivated close has already proved no publication and frozen
        // future effects. It can only finish through close_unactivated.
        if r.lifecycle.closing().is_some() {
            return Err(Error::Auth);
        }
        if let Some(old) = r.closing {
            if !old.state.terminal() || old.state == ExecutionState::Applied {
                // A prior poll may have entered Faulted before refreshing this
                // exact receipt. Resume reconciliation without republishing or
                // discarding the fault; UNKNOWN still cannot become Complete.
                root_mut().phase = if old.state == ExecutionState::Applied {
                    Phase::Complete
                } else {
                    Phase::Restoring
                };
                return Ok(());
            }
        }
        // Recovery and placement are decisions about one existing obligation.
        // Closing them cannot issue a second decision on that request. The
        // original receipt and the registered owner's real drain witness suffice.
        if matches!(q.baseline, Action::RecoveryRecipe(_) | Action::Placement(_)) {
            let checks = *r
                .registered
                .iter()
                .flatten()
                .find(|o| o.owner == q.owner)
                .ok_or(Error::NotReady)?;
            (checks.settled)(token)?;
            let original = if q.kind == TrialKind::Baseline {
                root()
                    .baseline_count
                    .checked_sub(1)
                    .and_then(|i| root().baseline[i])
            } else {
                latest(s, root())?
            }
            .or(latest(s, root())?);
            let Some(original) = original else {
                // `published` is called atomically before desired roots are
                // installed. Under this gate, both absence facts plus the real
                // owner's drain witness prove no command remains to execute.
                if root().initial.is_some() || s.job.is_some() || s.owner.prepared_count != 0 {
                    return Err(Error::Busy);
                }
                if locate_family(&s.owner, q.family.domain, q.family.kind, q.target)
                    .and_then(|i| s.owner.desired[i].as_ref())
                    .is_some_and(execution_blocks_replacement)
                {
                    return Err(Error::Busy);
                }
                let first = root().first.ok_or(Error::NotReady)?;
                root_mut().unpublished = Some(UnpublishedClose {
                    token,
                    family: q.family,
                    target: q.target,
                    first,
                    closed_ns: now(),
                    capture: None,
                });
                root_mut().phase = Phase::Complete;
                return Ok(());
            };
            if !original.state.terminal() {
                return Err(Error::Busy);
            }
            let r = root_mut();
            r.closing = Some(original);
            r.phase = Phase::Complete;
            return Ok(());
        }
        root_mut().phase = Phase::Restoring;
        let value = publish_baseline(s, token, true)?;
        root_mut().closing = Some(value);
        #[cfg(not(test))]
        if let Some(first) = root().first {
            crate::learning_evidence::execution_trace::closing(
                value.apply.target,
                first.taken_ns,
                value.apply,
                value.stamp,
                value.accepted_ns,
                value.approved_deadline_ns,
                now(),
            );
        }
        Ok(())
    })
}
/// A Registry terminal rejection remains terminal even when its original
/// domain error is Busy/Again/NotReady. CPU0 uses this retained fact when
/// deciding whether to retry an operation or close the real failed trial.
pub fn retained_fault(token: Token) -> Result<Option<Error>, Error> {
    with(|s| {
        authorized(s)?;
        exact(root(), token)?;
        Ok(root().fault)
    })
}
pub fn rejected(token: Token) -> Result<Option<RejectedPublication>, Error> {
    with(|s| {
        authorized(s)?;
        exact(root(), token)?;
        Ok(root().rejected)
    })
}
/// A partner preparation has no local capture RunKey. Its signed negative
/// protocol may retain this exact Registry rejection, while ordinary history
/// continues to require verify_rejected against a real local capture.
pub fn spectator_rejected(token: Token) -> Result<Option<RejectedPublication>, Error> {
    with(|s| {
        authorized(s)?;
        let r = root();
        if r.token != Some(token) || r.spectator.is_none_or(|q| q.owner != token.owner) {
            return Err(Error::Stale);
        }
        if r.rejected.is_some_and(|proof| proof.token != token) {
            return Err(Error::Conflict);
        }
        Ok(r.rejected)
    })
}
pub fn verify_rejected(
    run: learning::capture::RunKey,
    proof: &RejectedPublication,
) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let r = root();
        let q = exact(r, proof.token)?;
        if r.rejected.as_ref() != Some(proof)
            || proof.receipt.version != 0
            || !matches!(proof.receipt.state(), ExecutionState::Failed(_))
            || run.boot_epoch != proof.token.boot_epoch
            || run.trial_id != q.trial_id
            || proof.decision.envelope.target != q.target
            || proof.decision.action.domain() != q.family.domain
            || proof.decision.action.kind() != q.family.kind
        {
            return Err(Error::Auth);
        }
        let config = crate::learning_evidence::current_config()
            .map_err(|_| Error::Busy)?
            .ok_or(Error::Stale)?;
        if config.key != run {
            return Err(Error::Stale);
        }
        Ok(())
    })
}

fn capture_matches(
    r: &Root,
    token: Token,
    scope: &crate::learning_history::FrozenScope,
) -> Result<(), Error> {
    let q = exact(r, token)?;
    if q.family != scope.family
        || q.target != scope.target
        || q.kind != scope.kind
        || scope.key.boot_epoch != token.boot_epoch
        || scope.key.trial_id != q.trial_id
        || r.first.is_none_or(|first| first.taken_ns != scope.first_ns)
        || r.digest != scope.frozen_other_domains
    {
        return Err(Error::Stale);
    }
    let config = crate::learning_evidence::current_config()
        .map_err(|_| Error::Busy)?
        .ok_or(Error::Stale)?;
    if config.key != scope.key
        || config.family != scope.family
        || config.first_ns != scope.first_ns
        || config.observation_ns != scope.observation_ns
        || config.frozen_scope_hash != scope.frozen_scope_hash
    {
        return Err(Error::Stale);
    }
    Ok(())
}
/// Known PUBLISH is sufficient regardless of its current completion state.
/// In particular a Pending owner may need activation to produce its receipt;
/// waiting for it to settle before activating would deadlock real work.
fn has_publication(s: &State, r: &Root, token: Token) -> Result<bool, Error> {
    let q = exact(r, token)?;
    if r.initial.is_some() || r.baseline_count != 0 || r.closing.is_some() {
        return Ok(true);
    }
    if let Some(index) = locate_family(&s.owner, q.family.domain, q.family.kind, q.target) {
        if s.owner.desired[index].is_some_and(|d| {
            r.first
                .is_some_and(|first| d.stamp.snapshot_ns >= first.taken_ns)
        }) {
            return Ok(true);
        }
    }
    if q.baseline == Action::OfferCpu(0) {
        return crate::domain_network::baseline_stop_custody(
            token,
            q.target,
            r.first.ok_or(Error::NotReady)?,
        );
    }
    Ok(false)
}
pub fn publication_started(token: Token) -> Result<bool, Error> {
    with(|s| {
        authorized(s)?;
        has_publication(s, root(), token)
    })
}
/// Freeze the absence of PUBLISH before the ordinary owner changes to its
/// aborting state. An unknown/pending publication is a real obligation, never
/// permission to retract a prepared workload. The same gate prevents a later
/// C1 proposal, deterministic baseline or restoration from crossing this cut.
pub fn begin_unactivated_close(
    token: Token,
    preparation: Preparation,
    scope: &crate::learning_history::FrozenScope,
) -> Result<bool, Error> {
    with(|s| {
        authorized(s)?;
        let r = root();
        capture_matches(r, token, scope)?;
        let p = r.preparing.ok_or(Error::Stale)?;
        if p.identity != preparation
            || p.bound != Some(token)
            || preparation.seed != scope.group.seed
            || r.lifecycle.activated().is_some()
        {
            return Err(Error::Conflict);
        }
        if let Some(key) = r.lifecycle.closing() {
            return if key == scope.key {
                Ok(true)
            } else {
                Err(Error::Stale)
            };
        }
        let published = has_publication(s, r, token)?;
        let q = exact(r, token)?;
        let unresolved = s.job.is_some()
            || s.owner.prepared_count != 0
            || locate_family(&s.owner, q.family.domain, q.family.kind, q.target)
                .and_then(|i| s.owner.desired[i].as_ref())
                .is_some_and(execution_blocks_replacement);
        let r = root_mut();
        let closing = r.lifecycle.begin(scope.key, published, unresolved)?;
        if closing {
            r.phase = Phase::Faulted;
        }
        Ok(closing)
    })
}
/// CPU0 calls this only after the exact owner's activate returned Ok. Retiring
/// preparation metadata grants no execution/publication receipt and keeps the
/// replay reservation, its original fault and all existing obligations intact.
pub(crate) fn finish_work_activation(
    token: Token,
    preparation: Preparation,
    scope: &crate::learning_history::FrozenScope,
) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    with(|s| {
        authorized(s)?;
        let r = root();
        capture_matches(r, token, scope)?;
        if !r.first_ready || r.lifecycle.closing().is_some() || r.unpublished.is_some() {
            return Err(Error::Conflict);
        }
        if r.lifecycle.activated() == Some(scope.key) && r.preparing.is_none() {
            return Ok(());
        }
        let p = r.preparing.ok_or(Error::Stale)?;
        if p.identity != preparation || p.bound != Some(token) {
            return Err(Error::Stale);
        }
        let r = root_mut();
        r.lifecycle.finish_activation(scope.key)?;
        r.preparing = None;
        Ok(())
    })
}
pub fn release(token: Token) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let r = root_mut();
        let q = exact(r, token)?;
        let known_one_shot_failure =
            matches!(q.baseline, Action::RecoveryRecipe(_) | Action::Placement(_))
                && r.closing
                    .is_some_and(|v| matches!(v.state, ExecutionState::Failed(_)));
        // A failed one-shot may leave custody only after its ordinary owner has
        // proved all work drained in restore(). Its failed receipt remains failed
        // and is archived as excluded; Pending/Unknown cannot take this path.
        if r.phase != Phase::Complete
            || (!known_one_shot_failure
                && r.unpublished.is_none()
                && r.closing.is_none_or(|v| v.state != ExecutionState::Applied))
        {
            return Err(Error::Busy);
        }
        if locate_family(&s.owner, q.family.domain, q.family.kind, q.target)
            .and_then(|i| s.owner.desired[i].as_ref())
            .is_some_and(execution_blocks_replacement)
        {
            return Err(Error::Busy);
        }
        r.request = None;
        r.token = None;
        r.lifecycle = lifecycle::CloseGate::new();
        if r.preparing.is_some_and(|p| p.bound == Some(token)) {
            r.preparing = None;
        }
        Ok(())
    })
}
pub fn verify_unpublished_close(proof: UnpublishedClose) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let r = root();
        let q = exact(r, proof.token)?;
        if r.unpublished != Some(proof)
            || r.phase != Phase::Complete
            || r.initial.is_some()
            || r.closing.is_some()
            || s.job.is_some()
            || s.owner.prepared_count != 0
            || q.family != proof.family
            || q.target != proof.target
            || r.first != Some(proof.first)
            || latest(s, r)?.is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    })
}
/// The first capture is real, but no policy/work activation was completed.
/// Preserve that capture and prove actual unactivated custody drained; never
/// manufacture an execution receipt for the failed setup operation.
pub fn close_unactivated(
    token: Token,
    scope: &crate::learning_history::FrozenScope,
    preparation: Preparation,
) -> Result<UnpublishedClose, Error> {
    with(|s| {
        authorized(s)?;
        let r = root();
        let q = exact(r, token)?;
        let p = r.preparing.ok_or(Error::Stale)?;
        if p.identity != preparation
            || p.bound != Some(token)
            || r.lifecycle.activated().is_some()
            || r.lifecycle.closing() != Some(scope.key)
            || r.initial.is_some()
            || r.baseline_count != 0
            || q.family != scope.family
            || q.target != scope.target
            || scope.key.boot_epoch != preparation.boot_epoch
            || scope.key.trial_id != preparation.trial_id
            || r.first.is_none_or(|first| first.taken_ns != scope.first_ns)
            || latest(s, r)?.is_some()
        {
            return Err(Error::Conflict);
        }
        if let Some(proof) = r.unpublished {
            return if proof.capture == Some(scope.key) {
                Ok(proof)
            } else {
                Err(Error::Conflict)
            };
        }
        if s.job.is_some() || s.owner.prepared_count != 0 {
            return Err(Error::Busy);
        }
        if has_publication(s, r, token)? {
            return Err(Error::Conflict);
        }
        if locate_family(&s.owner, q.family.domain, q.family.kind, q.target)
            .and_then(|i| s.owner.desired[i].as_ref())
            .is_some_and(execution_blocks_replacement)
        {
            return Err(Error::Busy);
        }
        let config = crate::learning_evidence::current_config()
            .map_err(|_| Error::Busy)?
            .ok_or(Error::Stale)?;
        if config.key != scope.key {
            return Err(Error::Stale);
        }
        let check = r
            .registered
            .iter()
            .flatten()
            .find(|o| o.owner == preparation.owner)
            .ok_or(Error::Auth)?
            .unactivated_settled;
        check(preparation, scope)?;
        let proof = UnpublishedClose {
            token,
            family: q.family,
            target: q.target,
            first: r.first.ok_or(Error::Stale)?,
            closed_ns: now(),
            capture: Some(scope.key),
        };
        let r = root_mut();
        r.unpublished = Some(proof);
        r.phase = Phase::Complete;
        if let Some(p) = r.preparing.as_mut() {
            p.gate = true;
        }
        Ok(proof)
    })
}
pub(crate) fn mark_unactivated_archived(
    token: Token,
    proof: crate::learning_replay::archive::Export,
) -> Result<(), Error> {
    with(|s| {
        authorized(s)?;
        let r = root_mut();
        let q = exact(r, token)?;
        let close = r.unpublished.ok_or(Error::Stale)?;
        if close.capture != Some(proof.key())
            || proof.unpublished() != Some(close)
            || proof.bytes() == 0
            || proof.digest() == [0; 32]
            || r.phase != Phase::Complete
            || r.initial.is_some()
            || r.lifecycle.activated().is_some()
            || r.lifecycle.closing() != Some(proof.key())
        {
            return Err(Error::Conflict);
        }
        let p = r.preparing.as_mut().ok_or(Error::Stale)?;
        if p.bound != Some(token)
            || p.identity.trial_id != q.trial_id
            || p.identity.family != q.family
        {
            return Err(Error::Stale);
        }
        p.archived = true;
        Ok(())
    })
}
pub fn verify_scope(
    token: Token,
    scope: &crate::learning_history::FrozenScope,
) -> Result<(), learning::Error> {
    verify_scope_raw(token, scope).map_err(verification::evidence_error)
}
pub fn verify_scope_bounded(
    token: Token,
    scope: &crate::learning_history::FrozenScope,
) -> Result<bool, learning::Error> {
    verification::bounded_lookup(verify_scope_raw(token, scope))
}
fn verify_scope_raw(
    token: Token,
    scope: &crate::learning_history::FrozenScope,
) -> Result<(), Error> {
    fn check(
        r: &Root,
        token: Token,
        scope: &crate::learning_history::FrozenScope,
        model: Option<ModelBinding>,
    ) -> Result<(), Error> {
        let q = exact(r, token)?;
        if r.fault.is_some()
            || r.digest == [0; 32]
            || scope.key.boot_epoch != token.boot_epoch
            || scope.key.trial_id != q.trial_id
            || scope.kind != q.kind
            || scope.family != q.family
            || scope.target != q.target
            || scope.frozen_other_domains != r.digest
            || r.model != model
            || r.first.is_none_or(|f| f.taken_ns != scope.first_ns)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    if activation(token) {
        return check(root(), token, scope, root().model);
    }
    with(|s| check(root(), token, scope, Some(s.registry.model())))
}
pub fn verify_baseline(token: Token, b: &BaselineAdoption) -> Result<(), learning::Error> {
    verify_baseline_raw(token, b).map_err(verification::evidence_error)
}
pub fn verify_baseline_bounded(
    token: Token,
    b: &BaselineAdoption,
) -> Result<bool, learning::Error> {
    verification::bounded_lookup(verify_baseline_raw(token, b))
}
fn verify_baseline_raw(token: Token, b: &BaselineAdoption) -> Result<(), Error> {
    with(|_| {
        let r = root_mut();
        let q = exact(r, token)?;
        if q.kind != TrialKind::Baseline || b.actual != q.baseline || b.target != q.target {
            return Err(Error::Auth);
        }
        let v = r.baseline[..r.baseline_count]
            .iter()
            .flatten()
            .find(|v| v.apply.plan_seq == b.receipt_sequence)
            .ok_or(Error::NotFound)?;
        let expected = v.baseline(b.target_request_id)?;
        if expected.owner_boot != b.owner_boot
            || expected.executor_generation != b.executor_generation
            || expected.snapshot != b.snapshot
            || expected.executed != b.executed
            || expected.issued_ns != b.issued_ns
            || expected.accepted_ns != b.accepted_ns
            || expected.started_ns != b.started_ns
            || expected.finished_ns != b.finished_ns
            || expected.installed_until_ns != b.installed_until_ns
            || expected.approved_deadline_ns != b.approved_deadline_ns
        {
            return Err(Error::Conflict);
        }
        Ok(())
    })
}
pub fn verify_adoption(token: Token, a: &Adoption<'_>) -> Result<(), learning::Error> {
    verify_adoption_raw(token, a).map_err(verification::evidence_error)
}
pub fn verify_adoption_bounded(token: Token, a: &Adoption<'_>) -> Result<bool, learning::Error> {
    verification::bounded_lookup(verify_adoption_raw(token, a))
}
fn verify_adoption_raw(token: Token, a: &Adoption<'_>) -> Result<(), Error> {
    with(|s| {
        let r = root_mut();
        let q = exact(r, token)?;
        if q.kind != TrialKind::Candidate
            || a.apply.target != q.target
            || a.actual.domain() != q.family.domain
            || a.actual.kind() != q.family.kind
            || r.selected != Some(a.actual)
            || r.model != Some(a.candidates.model)
            || a.apply.boot_epoch != token.boot_epoch
            || r.first
                .is_none_or(|f| a.candidates.snapshot.taken_ns < f.taken_ns)
            || r.fault.is_some()
        {
            return Err(Error::Auth);
        }
        if r.model != Some(s.registry.model()) {
            return Err(Error::Stale);
        }
        Ok(())
    })
}

/// A read-only legal comparison collected by the root from actual owners.
/// This capability is never a publication permit or an extra replay label.
pub struct ValidationProbe {
    token: Token,
    family: LearningFamily,
    current: Action,
    set: CandidateSet,
}
impl ValidationProbe {
    pub fn token(&self) -> Token {
        self.token
    }
    pub fn family(&self) -> LearningFamily {
        self.family
    }
    pub fn current(&self) -> Action {
        self.current
    }
    pub fn candidates(&self) -> &CandidateSet {
        &self.set
    }
}
/// Same-value renewals deliberately have only the retained selected action.
/// Validation still needs an actual legal comparison (including an offer
/// after the real zero-to-positive startup). Build that comparison separately
/// without publishing or changing any member of the frozen experiment.
pub fn validation_probe(token: Token) -> Result<ValidationProbe, Error> {
    with(|s| {
        authorized(s)?;
        let q = exact(root(), token)?;
        if q.kind != TrialKind::Candidate
            || root().phase != Phase::Running
            || root().fault.is_some()
        {
            return Err(Error::NotReady);
        }
        let latest = latest(s, root())?.ok_or(Error::NotReady)?;
        let at = now();
        if latest.state != ExecutionState::Applied
            || (!latest.action.one_shot() && !latest.stamp.live(at))
        {
            return Err(Error::Again);
        }
        let index = family_index(q.family.domain, q.family.kind)?;
        let f = s.owner.families[index].ok_or(Error::NotReady)?;
        let current = (f.current)(f.domain, f.kind, q.target)?;
        if current != latest.action {
            return Err(Error::Stale);
        }
        let observed = (f.observe)(f.domain, q.target)?;
        let stability_slot = ensure_stability(&mut s.owner, current, q.target, at)?;
        let stability = s.owner.stability[stability_slot]
            .as_ref()
            .ok_or(Error::Stale)?;
        let (options, n) = tiers(current);
        let mut legal = [None; 32];
        let mut legal_count = 0;
        for action in options[..n].iter().flatten().copied() {
            match (f.legal)(action, q.target, at) {
                Ok(()) => {
                    legal[legal_count] = Some(action);
                    legal_count += 1;
                }
                Err(
                    Error::Busy | Error::Again | Error::NotReady | Error::Stale | Error::NotFound,
                ) => return Err(Error::Again),
                Err(_) => (),
            }
        }
        legal[..legal_count].sort_unstable_by_key(|v| v.map(Action::order));
        if !legal[..legal_count].contains(&Some(current)) {
            return Err(Error::NotReady);
        }
        let hold = if matches!(current, Action::ControlSet(_) | Action::UnauthRate(_)) {
            1_000_000_000
        } else {
            WINDOW_NS
        };
        let held = at.saturating_sub(stability.last_change_ns()) >= hold;
        let queued = queued_control_wcet_us(s, index, at)?;
        let mut choices = [Candidate {
            action: current,
            features: RawFeatures::default(),
        }; 32];
        let mut count = 0;
        for action in legal[..legal_count].iter().flatten().copied() {
            if action != current
                && (stability.frozen()
                    || (!categorical(action)
                        && (!held
                            || !cyxia_prototype::domains::stability::adjacent(
                                current,
                                action,
                                &legal[..legal_count],
                            )?)))
            {
                continue;
            }
            let mut target_features = (f.target_features)(action, q.target)?;
            if let Action::ControlSet(mask) = action {
                let cores = u64::from(mask.count_ones());
                if cores == 0 {
                    return Err(Error::Range);
                }
                target_features.values[2] = Some(queued.div_ceil(cores));
            }
            let mut common = s.owner.context.common;
            common[2] = queued / 2_500;
            common[6] = 0;
            choices[count] = Candidate {
                action,
                features: RawFeatures {
                    common,
                    domain: observed.values,
                    domain_present: observed.present,
                    target: target_features,
                    control_capacity: if let Action::ControlSet(mask) = action {
                        Some(u64::from(mask.count_ones()) * 1000)
                    } else {
                        None
                    },
                },
            };
            count += 1;
        }
        if count < 2 {
            return Err(Error::Again);
        }
        let sequence = s.sequence.checked_add(1).ok_or(Error::Overflow)?;
        let snapshot = Snapshot {
            sequence,
            taken_ns: at,
            core_generation: s.owner.context.core_generation,
            ledger_generation: s.owner.context.ledger_generation,
        };
        let set = CandidateSet::new(
            snapshot,
            q.target,
            s.registry.model(),
            &choices[..count],
            Some(current),
        )?;
        s.sequence = sequence;
        Ok(ValidationProbe {
            token,
            family: q.family,
            current,
            set,
        })
    })
}
