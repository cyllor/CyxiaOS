//! CPU0 owns workloads and closure; prepaid C1 turns verify immutable evidence.
use super::{
    Error, Split, archive::Archive, data, domain_error, evidence_error, late_archive, native_error,
    preparation_archive,
};
use crate::{
    control_pool as pool,
    domain_control::{self, replay as root},
    learning_evidence as capture,
    learning_history::{self as history, FrozenScope, TrialKind},
    learning_workload as work,
    smp::prototype_runtime as runtime,
};
use core::{
    cell::UnsafeCell,
    mem::{MaybeUninit, align_of, size_of},
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use cyxia_prototype::{
    domains::{Action, Error as DomainError, ObjectKey},
    learning::{
        Family,
        capture::{FrozenRequest, RunKey, Seal},
        reward::{
            self, Adoption, BaselineAdoption, CpuClass, CpuInterval, OBSERVATION_NS,
            ReplayVerification, RewardWorkspace, Trial, VerifiedReplay,
        },
    },
    model::MODEL_BYTES,
    policy::{CandidateSet, ExecutionState, Snapshot},
};
use root::lifecycle::WorkActivation;
use sha2::{Digest, Sha256};
#[path = "diagnostic.rs"]
mod diagnostic;
use diagnostic::Site;
#[path = "schemas.rs"]
mod schemas;
const OWNER: ObjectKey = ObjectKey {
    id: 0x4c45_524f_574e,
    generation: 1,
};
const META_PAGES: usize = 3;
// Use the same reserved input, stack and metadata allowance as the real
// driver gate, plus every producer-owned bank that remains live. This is a
// conservative bound of actual reservations, not a fabricated measured peak.
pub(super) const WORKSPACE_PEAK_BYTES: usize = 1024 * 1024
    - crate::domain_control::learning_driver::MAX_SOURCE_BYTES
    + data::OWNED_BYTES
    + META_PAGES * 4096
    + crate::learning_prewarm::OWNED_BYTES
    + crate::domain_control::core_replay::OWNED_BYTES
    + crate::learning_evidence::HANDOFF_BYTES
    + crate::domain_tasks::CAPTURE_CREDIT_BYTES
    + crate::domain_services::SOURCE_IDENTITY_BYTES;
const RECORD_LIMIT: usize = 8;
const SECOND: u64 = 1_000_000_000;
const FAMILIES: [Family; 18] = [
    Family { domain: 1, kind: 1 },
    Family { domain: 1, kind: 2 },
    Family { domain: 2, kind: 1 },
    Family { domain: 3, kind: 1 },
    Family { domain: 4, kind: 1 },
    Family { domain: 5, kind: 1 },
    Family { domain: 6, kind: 1 },
    Family { domain: 7, kind: 1 },
    Family { domain: 8, kind: 1 },
    Family { domain: 9, kind: 1 },
    Family {
        domain: 10,
        kind: 1,
    },
    Family {
        domain: 11,
        kind: 1,
    },
    Family {
        domain: 12,
        kind: 1,
    },
    Family {
        domain: 13,
        kind: 1,
    },
    Family {
        domain: 14,
        kind: 1,
    },
    Family {
        domain: 15,
        kind: 1,
    },
    Family {
        domain: 16,
        kind: 1,
    },
    Family {
        domain: 16,
        kind: 2,
    },
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Phase {
    Prepare,
    Reserve,
    Freeze,
    Start,
    Activate,
    Run,
    Drain,
    CloseSources,
    Seal,
    Verify,
    Archive,
    RetireCapture,
    RetireHistory,
    Release,
    ReleaseWork,
    ReleasePermit,
    Restart,
    Complete,
    Failed,
    PreparationAbort,
    PreparationArchive,
    PreparationReleaseWork,
    PreparationReleaseRoot,
    PreparationReleasePermit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub family: Family,
    pub group: u8,
    pub kind: TrialKind,
    pub trial_id: u64,
    pub run: Option<RunKey>,
    pub verified: u64,
    pub excluded: u64,
    pub last_error: Option<Error>,
}
// Overlay of the real idle 512 KiB worker input loan; no second reward bank.
struct Scratch {
    reward: MaybeUninit<RewardWorkspace>,
    records: [MaybeUninit<history::replay::Record>; RECORD_LIMIT],
    sets: [MaybeUninit<CandidateSet>; RECORD_LIMIT],
    baseline: [MaybeUninit<BaselineAdoption>; RECORD_LIMIT],
    verification: MaybeUninit<ReplayVerification>,
    delivery: MaybeUninit<Option<VerifiedReplay>>,
}
// A late packet can exist only after the regular journal is durable and its
// capture/history have retired. Reuse that writer's storage instead of
// reserving both headers/hash states throughout every trial.
enum Journal {
    Regular(Archive),
    Late(late_archive::Archive),
}
impl Journal {
    fn done(&self) -> bool {
        match self {
            Self::Regular(value) => value.done(),
            Self::Late(value) => value.done(),
        }
    }
}
const _: () = assert!(size_of::<late_archive::Archive>() <= size_of::<Archive>());
struct State {
    schemas: schemas::Preparation,
    phase: Phase,
    family: usize,
    group: u8,
    kind: TrialKind,
    trial_id: u64,
    prepared: Option<work::Prepared>,
    token: Option<root::Token>,
    permit: Option<capture::StartPermit>,
    scope: Option<FrozenScope>,
    first_ready: bool,
    partial_start: bool,
    work_activation: WorkActivation,
    frozen: [u8; 32],
    not_before: u64,
    cursor: usize,
    baseline_seq: u64,
    seal: Option<Seal>,
    closing: Option<root::Receipt>,
    unpublished: Option<root::UnpublishedClose>,
    records: usize,
    retained: usize,
    export_index: usize,
    record_started: bool,
    loan: Option<runtime::LearningInputLoan>,
    scratch: usize,
    initialized: usize,
    model: Option<domain_control::NativeModelPin>,
    verification: Option<Result<[u8; 32], Error>>,
    archive: Option<Journal>,
    segment: u16,
    late_segment: u16,
    verified: u64,
    excluded: u64,
    last_error: Option<Error>,
    partner: Option<crate::peer_replay::PartnerSeal>,
    peer_staged: usize,
    root_phase: u64,
    archived: u64,
    preparation: Option<root::Preparation>,
    prepare_claimed: bool,
    prepare_error: Option<(DomainError, u64)>,
    prepare_close: Option<root::PreparationClose>,
    prepare_archive: Option<preparation_archive::Archive>,
    prepare_segment: u16,
    pair_group: Option<cyxia_prototype::learning::ReplayGroup>,
    retry_group: Option<cyxia_prototype::learning::ReplayGroup>,
}
const _: () = assert!(size_of::<State>() <= META_PAGES * 4096);
impl State {
    const fn new() -> Self {
        Self {
            schemas: schemas::Preparation::new(),
            phase: Phase::Prepare,
            family: 0,
            group: 0,
            kind: TrialKind::Baseline,
            trial_id: 1,
            prepared: None,
            token: None,
            permit: None,
            scope: None,
            first_ready: false,
            partial_start: false,
            work_activation: WorkActivation::new(),
            frozen: [0; 32],
            not_before: 0,
            cursor: 0,
            baseline_seq: 0,
            seal: None,
            closing: None,
            unpublished: None,
            records: 0,
            retained: 0,
            export_index: 0,
            record_started: false,
            loan: None,
            scratch: 0,
            initialized: 0,
            model: None,
            verification: None,
            archive: None,
            segment: 0,
            late_segment: 0,
            verified: 0,
            excluded: 0,
            last_error: None,
            partner: None,
            peer_staged: 0,
            root_phase: 0,
            archived: 0,
            preparation: None,
            prepare_claimed: false,
            prepare_error: None,
            prepare_close: None,
            prepare_archive: None,
            prepare_segment: 0,
            pair_group: None,
            retry_group: None,
        }
    }
    fn split(&self) -> Split {
        if self.group < 8 {
            Split::Training
        } else {
            Split::Validation
        }
    }
}
struct Setup {
    allocation: Option<pool::Allocation>,
    pin: Option<pool::Lease>,
}
struct Cell(UnsafeCell<Setup>);
unsafe impl Sync for Cell {}
static SETUP: Cell = Cell(UnsafeCell::new(Setup {
    allocation: None,
    pin: None,
}));
const SCOPE_HASH_CAPACITY: usize = 4096;
struct ScopeHashBytes(UnsafeCell<[u8; SCOPE_HASH_CAPACITY]>);
unsafe impl Sync for ScopeHashBytes {}
// on_first reaches this storage only while holding this owner's non-reentrant
// gate. The buffer is kernel-only and every byte in the hashed prefix is
// overwritten before use.
static SCOPE_HASH_BYTES: ScopeHashBytes = ScopeHashBytes(UnsafeCell::new([0; SCOPE_HASH_CAPACITY]));
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static GATE: AtomicBool = AtomicBool::new(false);
static PAUSED: AtomicBool = AtomicBool::new(false);
/// Stable native-reader ABI, all values observed from actual owners. Word 0
/// is a seqlock; 1 magic; 2 phase; 3/4 family; 5 group; 6 candidate=1/baseline=2;
/// 7 trial; 8 boot; 9 capture generation; 10 verified sides; 11 exclusions;
/// 12 error+1; 13 root phase+1; 14 first; 15 observation; 16 closing;
/// 17 durable archives; 18 data phase+1; 19 labels; 20 pending baseline;
/// 21 data error+1; 22 peer pause; 23 signed peer interval count;
/// 24..42 actual training counts; 42..60 validation counts; 60 sampled time;
/// 61 history rows; 62 retained rows; 63 current archive readback complete.
#[repr(C, align(64))]
pub struct NativeEvidence([AtomicU64; 64]);
#[used]
#[unsafe(no_mangle)]
pub static REPLAY_V13_EVIDENCE: NativeEvidence = NativeEvidence([const { AtomicU64::new(0) }; 64]);
fn publish_evidence() {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return;
    }
    let Ok(mut words) = with(|s| {
        let mut words = [0; 64];
        let family = FAMILIES[s.family.min(17)];
        words[1] = 0x4359_5250_4c59_3133;
        words[2] = s.phase as u64;
        words[3] = u64::from(family.domain);
        words[4] = u64::from(family.kind);
        words[5] = u64::from(s.group);
        words[6] = if s.kind == TrialKind::Candidate { 1 } else { 2 };
        words[7] = s.trial_id;
        if let Some(scope) = s.scope {
            words[8] = scope.key.boot_epoch;
            words[9] = scope.key.generation;
            words[14] = scope.first_ns;
            words[15] = scope.observation_ns;
        } else if let Some(p) = s.preparation {
            words[8] = p.boot_epoch;
        }
        words[10] = s.verified;
        words[11] = s.excluded;
        words[12] = s.last_error.map_or(0, |e| e as u64 + 1);
        words[13] = s.root_phase;
        words[16] = s
            .seal
            .map_or(s.prepare_close.map_or(0, |p| p.drained_ns()), |v| {
                v.closing_ns
            });
        words[17] = s.archived;
        words[22] = u64::from(PAUSED.load(Ordering::Acquire));
        words[23] = s.partner.map_or(0, |v| v.seal.count);
        words[60] = crate::domain_platform::now_ns();
        words[61] = s.records as u64;
        words[62] = s.retained as u64;
        words[63] = u64::from(
            s.archive.as_ref().is_some_and(Journal::done)
                || s.prepare_archive
                    .as_ref()
                    .is_some_and(preparation_archive::Archive::done),
        );
        Ok(words)
    }) else {
        return;
    };
    let Ok(data) = data::status() else {
        return;
    };
    words[18] = data.phase as u64 + 1;
    words[19] = data.paired as u64;
    words[20] = u64::from(data.pending_baseline);
    words[21] = data.last_error.map_or(0, |e| e as u64 + 1);
    for i in 0..18 {
        words[24 + i] = u64::from(data.training[i]);
        words[42 + i] = u64::from(data.validation[i]);
    }
    REPLAY_V13_EVIDENCE.0[0].fetch_add(1, Ordering::AcqRel);
    for (i, value) in words.into_iter().enumerate().skip(1) {
        REPLAY_V13_EVIDENCE.0[i].store(value, Ordering::Relaxed);
    }
    REPLAY_V13_EVIDENCE.0[0].fetch_add(1, Ordering::Release);
}
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn lock() -> Result<Guard, DomainError> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| DomainError::Busy)?;
    Ok(Guard)
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, DomainError>) -> Result<T, DomainError> {
    let _guard = lock()?;
    let base = ADDRESS.load(Ordering::Acquire);
    if base == 0 {
        return Err(DomainError::NotReady);
    }
    f(unsafe { &mut *(base as *mut State) })
}
pub fn init() -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    if ADDRESS.load(Ordering::Acquire) == 0 {
        let _guard = lock()?;
        let setup = unsafe { &mut *SETUP.0.get() };
        if setup.allocation.is_none() {
            setup.allocation = Some(pool::allocate(OWNER, META_PAGES)?);
        }
        let allocation = setup.allocation.ok_or(DomainError::NotReady)?;
        if setup.pin.is_none() {
            setup.pin = Some(pool::pin(allocation)?);
        }
        let base = pool::span(allocation)?.0;
        if !base.is_multiple_of(align_of::<State>()) {
            return Err(DomainError::Range);
        }
        unsafe {
            core::ptr::write(base as *mut State, State::new());
        }
        ADDRESS.store(base, Ordering::Release);
    }
    data::init()?;
    work::init()?;
    crate::service_windows::init()?;
    capture::register_source_classifier(classify_source)
        .map_err(|e| domain_error(evidence_error(e)))?;
    root::register_owner(root::OwnerChecks {
        owner: work::OWNER,
        baseline: check_baseline,
        stop_offer: crate::domain_network::baseline_stop_quotes,
        settled,
        before_first: work::before_first,
        prepared_settled: work::settled_prepared,
        unactivated_settled: work::settled_unactivated,
    })
}
pub fn status() -> Result<Status, DomainError> {
    with(|s| {
        Ok(Status {
            phase: s.phase,
            family: FAMILIES[s.family.min(17)],
            group: s.group,
            kind: s.kind,
            trial_id: s.trial_id,
            run: s.scope.map(|v| v.key),
            verified: s.verified,
            excluded: s.excluded,
            last_error: s.last_error,
        })
    })
}
pub fn pause_for_peer(paused: bool) -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    PAUSED.store(paused, Ordering::Release);
    Ok(())
}
pub fn quiescent() -> bool {
    with(|s| {
        Ok(matches!(s.phase, Phase::Prepare | Phase::Complete)
            && s.token.is_none()
            && s.scope.is_none()
            && s.preparation
                .is_none_or(|p| matches!(p.family.domain, 10 | 12 | 16)))
    })
    .unwrap_or(false)
        && work::quiescent()
}
fn classify_source(
    run: RunKey,
    key: ObjectKey,
    class: CpuClass,
) -> Result<capture::SourceDisposition, Error> {
    if let Some(source) = crate::domain_tasks::replay::source_for(run, key)? {
        return Ok(capture::SourceDisposition::Measure(source));
    }
    if let Some(source) = crate::peer_replay::source_for(run, key)? {
        return Ok(capture::SourceDisposition::Measure(source));
    }
    if work::outside_source(run, key, class)? {
        return Ok(capture::SourceDisposition::Outside);
    }
    Err(Error::DataIncomplete)
}
fn check_baseline(family: Family, target: ObjectKey, action: Action) -> Result<(), DomainError> {
    with(|s| {
        let p = s.prepared.ok_or(DomainError::NotReady)?;
        if p.family == family && p.target == target && p.baseline == action {
            Ok(())
        } else {
            Err(DomainError::Auth)
        }
    })
}
fn settled(token: root::Token) -> Result<(), DomainError> {
    let run = with(|s| {
        if s.token != Some(token) {
            return Err(DomainError::Stale);
        }
        s.scope.map(|v| v.key).ok_or(DomainError::NotReady)
    })?;
    work::settled(run)
}
fn poll_root(token: root::Token) -> Result<root::Status, DomainError> {
    let status = root::poll(token)?;
    let _ = with(|s| {
        if s.token == Some(token) {
            s.root_phase = status.phase as u64 + 1;
        }
        Ok(())
    });
    Ok(status)
}
fn scope_hash(
    token: root::Token,
    trial_id: u64,
    prepared: work::Prepared,
    frozen: [u8; 32],
    first_ns: u64,
    observation_ns: u64,
) -> Result<[u8; 32], DomainError> {
    let bytes = unsafe { &mut *SCOPE_HASH_BYTES.0.get() };
    let mut used = 0usize;
    let mut append = |value: &[u8]| -> Result<(), DomainError> {
        let end = used.checked_add(value.len()).ok_or(DomainError::Overflow)?;
        let destination = bytes.get_mut(used..end).ok_or(DomainError::Capacity)?;
        destination.copy_from_slice(value);
        used = end;
        Ok(())
    };
    append(b"CYXIA_NATIVE_WORKLOAD_SCOPE_1.3\0")?;
    for value in [
        token.boot_epoch,
        trial_id,
        prepared.family.domain as u64,
        prepared.family.kind as u64,
        prepared.target.id,
        prepared.target.generation,
        prepared.group.seed,
        first_ns,
        observation_ns,
    ] {
        append(&value.to_le_bytes())?;
    }
    append(&prepared.group.workload)?;
    append(&prepared.group.initial_image)?;
    append(&frozen)?;
    for source in &prepared.sources[..prepared.source_count] {
        for value in [
            source.owner.id,
            source.owner.generation,
            source.class as u64,
            source.allowed_cores,
        ] {
            append(&value.to_le_bytes())?;
        }
    }
    for request in prepared.requests {
        for value in [
            request.id,
            request.owner.id,
            request.owner.generation,
            request.offset_ns,
        ] {
            append(&value.to_le_bytes())?;
        }
    }
    let input = &bytes[..used];
    Ok(cyxia_arch_aarch64::sha256::digest(input).unwrap_or_else(|| Sha256::digest(input).into()))
}
fn on_first(token: root::Token, snapshot: Snapshot) -> Result<(), DomainError> {
    if !root::activation(token) {
        return Err(DomainError::Auth);
    }
    with(|s| {
        if s.token != Some(token) || !matches!(s.phase, Phase::Start | Phase::Run) {
            return Err(DomainError::Stale);
        }
        let schemas = s.schemas.ready().ok_or(DomainError::NotReady)?;
        let p = s.prepared.ok_or(DomainError::NotReady)?;
        let observation_ns = if p.baseline.one_shot() {
            snapshot.taken_ns
        } else {
            snapshot
                .taken_ns
                .checked_add(6 * SECOND)
                .ok_or(DomainError::Overflow)?
        };
        let mut requests = [FrozenRequest {
            id: 0,
            owner: ObjectKey {
                id: 0,
                generation: 0,
            },
            arrived_ns: 0,
        }; work::REQUESTS];
        if p.source_count == 0 || p.source_count > p.sources.len() {
            return Err(DomainError::Capacity);
        }
        for (i, r) in p.requests.iter().enumerate() {
            if r.offset_ns >= OBSERVATION_NS {
                return Err(DomainError::Range);
            }
            requests[i] = FrozenRequest {
                id: r.id,
                owner: r.owner,
                arrived_ns: observation_ns
                    .checked_add(r.offset_ns)
                    .ok_or(DomainError::Overflow)?,
            };
        }
        let scope_hash = scope_hash(
            token,
            s.trial_id,
            p,
            s.frozen,
            snapshot.taken_ns,
            observation_ns,
        )?;
        let permit = s.permit.as_ref().ok_or(DomainError::NotReady)?;
        let key = capture::start_authorized(
            permit,
            snapshot.taken_ns,
            observation_ns,
            scope_hash,
            &p.sources[..p.source_count],
            &requests,
        )
        .map_err(|e| domain_error(evidence_error(e)))?;
        let scope = FrozenScope {
            key,
            kind: s.kind,
            family: p.family,
            target: p.target,
            group: p.group,
            schemas,
            frozen_other_domains: s.frozen,
            frozen_scope_hash: scope_hash,
            first_ns: snapshot.taken_ns,
            warmed_from_ns: observation_ns
                .checked_sub(SECOND)
                .ok_or(DomainError::Range)?,
            observation_ns,
        };
        s.scope = Some(scope);
        #[cfg(not(test))]
        capture::execution_trace::begin(key, p.family, p.target, snapshot.taken_ns);
        let bound = (|| {
            work::bind_scope(&scope)?;
            history::begin_authorized(scope, p.checks, permit)
                .map_err(|e| domain_error(evidence_error(e)))
        })();
        if let Err(error) = bound {
            // Capture already owns this exact run. Keep its manifest and all
            // actual intervals even when a later owner/history binding fails.
            // No CPU0 workload activation has occurred at this boundary.
            if !matches!(
                error,
                DomainError::Busy | DomainError::Again | DomainError::NotReady
            ) {
                s.last_error.get_or_insert(native_error(error));
                s.phase = Phase::Drain;
            }
            return Err(error);
        }
        s.first_ready = true;
        s.cursor = 0;
        s.phase = Phase::Activate;
        Ok(())
    })
}
fn retain_error(error: DomainError, trace: Option<&mut diagnostic::Attempt>) {
    let retained = with(|s| Ok(s.token))
        .ok()
        .flatten()
        .and_then(|token| root::retained_fault(token).ok().flatten());
    if retained.is_none()
        && matches!(
            error,
            DomainError::Busy | DomainError::Again | DomainError::NotReady
        )
    {
        return;
    }
    if let Some(trace) = trace {
        trace.retain(error, retained, crate::domain_platform::now_ns());
    }
    let error = retained.unwrap_or(error);
    let preparation = with(|s| {
        s.last_error.get_or_insert(native_error(error));
        if s.scope.is_some() && matches!(s.phase, Phase::Start | Phase::Activate | Phase::Run) {
            s.phase = Phase::Drain;
        } else if s.scope.is_none() && s.preparation.is_some() {
            let original = *s
                .prepare_error
                .get_or_insert((error, crate::domain_platform::now_ns()));
            if !matches!(
                s.phase,
                Phase::PreparationArchive
                    | Phase::PreparationReleaseWork
                    | Phase::PreparationReleaseRoot
                    | Phase::PreparationReleasePermit
            ) {
                s.phase = Phase::PreparationAbort;
            }
            return Ok(s.preparation.map(|p| (p, original)));
        } else if s.scope.is_none() {
            s.phase = Phase::Failed;
        }
        Ok(None)
    });
    if let Ok(Some((preparation, (error, at)))) = preparation {
        let _ = root::abort_preparation(preparation, error, at);
    }
}
fn diagnostic_evidence_error(
    trace: &mut diagnostic::Attempt,
    error: capture::Error,
) -> DomainError {
    let (category, nested) = match error {
        capture::Error::NotReady => (1, None),
        capture::Error::Busy => (2, None),
        capture::Error::Owner => (3, None),
        capture::Error::Stale => (4, None),
        capture::Error::Capacity => (5, None),
        capture::Error::Capture(error) => (6, Some(error)),
    };
    trace.nested(category, nested);
    domain_error(evidence_error(error))
}
/// A facade may perform real work before a later facade returns Busy. Mark
/// entry first and retry the same identity until the whole activation returns
/// Ok; only then retire root preparation metadata. This never arms a new run.
fn activate_work() -> Result<(), DomainError> {
    let (scope, token, preparation, complete) = with(|s| {
        let values = (
            s.scope.ok_or(DomainError::NotReady)?,
            s.token.ok_or(DomainError::NotReady)?,
            s.preparation.ok_or(DomainError::NotReady)?,
            s.work_activation.complete(),
        );
        s.work_activation.enter();
        Ok(values)
    })?;
    if !complete {
        work::activate(scope.key, scope.observation_ns)?;
        with(|s| s.work_activation.finish())?;
    }
    root::finish_work_activation(token, preparation, &scope)
}
pub fn service_step() -> Result<bool, DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    crate::domain_tasks::authorize_service_turn()?;
    let mut trace = diagnostic::Attempt::new(crate::domain_platform::now_ns());
    let result = service(&mut trace);
    if let Err(error) = result {
        retain_error(error, Some(&mut trace));
    }
    publish_evidence();
    result
}
fn service(trace: &mut diagnostic::Attempt) -> Result<bool, DomainError> {
    let phase = with(|s| {
        trace.words[3] = s.phase as u64 + 1;
        trace.words[10] = s.trial_id;
        trace.words[11] = s
            .scope
            .map_or(s.token.map_or(0, |t| t.boot_epoch), |v| v.key.boot_epoch);
        trace.words[12] = s.scope.map_or(0, |v| v.key.generation);
        trace.words[13] = s.token.map_or(0, |t| t.id);
        let family = FAMILIES[s.family.min(17)];
        trace.words[14] = u64::from(family.domain);
        trace.words[15] = u64::from(family.kind);
        trace.words[16] = if s.kind == TrialKind::Candidate { 1 } else { 2 };
        if let Some(p) = s.prepared.as_ref() {
            trace.words[17] = p.target.id;
            trace.words[18] = p.target.generation;
            trace.words[26] = p.requests.get(s.cursor).map_or(0, |r| r.id);
        }
        trace.words[19] = s.cursor as u64;
        trace.words[20] = s.baseline_seq;
        trace.words[21] = s.scope.map_or(0, |v| v.first_ns);
        trace.words[22] = s.scope.map_or(0, |v| v.observation_ns);
        trace.words[23] = s.root_phase;
        trace.words[25] = u64::from(s.first_ready)
            | u64::from(s.work_activation.entered()) << 1
            | u64::from(s.work_activation.complete()) << 2
            | u64::from(s.partial_start) << 3;
        Ok(s.phase)
    })?;
    trace.site(Site::OtherPhase);
    if matches!(phase, Phase::Reserve | Phase::Freeze | Phase::Start)
        && with(|s| Ok(s.scope.is_none()))?
    {
        trace.site(Site::Prewarm);
        work::prewarm_step()?;
    }
    match phase {
        Phase::Prepare => {
            trace.site(Site::Prepare);
            let (existing, claimed) = with(|s| Ok((s.preparation, s.prepare_claimed)))?;
            // The dedicated storage-fault image proves ordinary file/recovery
            // behavior. Do not start an unrelated learning trial whose archive
            // I/O would race the fault boundary and make it non-reproducible.
            if (crate::storage_fault_capture::PROFILE || PAUSED.load(Ordering::Acquire))
                && !claimed
                && work::quiescent()
            {
                if let Some(p) = existing {
                    root::withdraw_preparation(p)?;
                    with(|s| {
                        s.preparation = None;
                        Ok(())
                    })?;
                }
                return Ok(false);
            }
            // This runs under the existing CPU0 service credit, before any
            // trial first timestamp. Immutable source hashing must not turn
            // the synchronous first-publication callback into an overrun.
            let schemas_ready = with(|s| {
                if s.schemas.ready().is_some() {
                    return Ok(true);
                }
                s.schemas.step();
                Ok(false)
            })?;
            if !schemas_ready {
                return Ok(false);
            }
            let (family, seed, kind) =
                with(|s| Ok((FAMILIES[s.family], u64::from(s.group) + 1, s.kind)))?;
            let preparation = if let Some(p) = existing {
                p
            } else {
                let trial = with(|s| Ok(s.trial_id))?;
                let p = root::begin_preparation(work::OWNER, trial, family, seed, kind)?;
                with(|s| {
                    s.preparation = Some(p);
                    Ok(())
                })?;
                p
            };
            if !root::poll_preparation(preparation)? {
                return Ok(false);
            }
            with(|s| {
                root::claim_preparation(preparation)?;
                s.prepare_claimed = true;
                Ok(())
            })?;
            work::bind_preparation(preparation)?;
            let Some(prepared) = work::prepare(family, seed, kind)? else {
                return Ok(false);
            };
            with(|s| {
                s.prepared = Some(prepared);
                Ok(())
            })?;
            crate::service_windows::register_replay(family, prepared.target, prepared.boundary)?;
            with(|s| {
                if s.permit.is_none() {
                    s.permit = Some(
                        capture::prepare_start(work::OWNER, s.trial_id, family)
                            .map_err(|e| domain_error(evidence_error(e)))?,
                    );
                }
                s.not_before = if prepared.baseline.one_shot() {
                    crate::domain_platform::now_ns().saturating_add(SECOND)
                } else {
                    0
                };
                s.phase = Phase::Reserve;
                Ok(())
            })?;
        }
        Phase::Reserve => {
            trace.site(Site::Reserve);
            let request = with(|s| {
                let p = s.prepared.ok_or(DomainError::NotReady)?;
                Ok(root::Request {
                    owner: work::OWNER,
                    trial_id: s.trial_id,
                    family: p.family,
                    target: p.target,
                    baseline: p.baseline,
                    kind: s.kind,
                    not_before_ns: s.not_before,
                    on_first,
                })
            })?;
            let old = with(|s| Ok(s.token))?;
            let token = if let Some(token) = old {
                root::advance(token, request)?
            } else {
                root::reserve(request)?
            };
            work::bind_root(token)?;
            with(|s| {
                s.token = Some(token);
                s.phase = Phase::Freeze;
                Ok(())
            })?;
        }
        Phase::Freeze => {
            trace.site(Site::Freeze);
            let token = with(|s| s.token.ok_or(DomainError::NotReady))?;
            let status = poll_root(token)?;
            if let Some(error) = status.fault {
                return Err(error);
            }
            if status.phase != root::Phase::Frozen {
                return Ok(false);
            }
            with(|s| {
                s.frozen = status.frozen_other_domains;
                s.phase = Phase::Start;
                Ok(())
            })?;
        }
        Phase::Start => {
            trace.site(Site::Start);
            let (token, kind, ready) =
                with(|s| Ok((s.token.ok_or(DomainError::NotReady)?, s.kind, s.first_ready)))?;
            if ready {
                return Ok(true);
            }
            if kind == TrialKind::Candidate {
                root::start_candidate(token)?;
                with(|s| {
                    if s.phase == Phase::Start {
                        s.phase = Phase::Run;
                    }
                    Ok(())
                })?;
            } else {
                let _ = root::baseline_apply(token)?;
            }
        }
        Phase::Activate => {
            trace.site(Site::ActivateSetup);
            let (scope, token, kind) = with(|s| {
                Ok((
                    s.scope.ok_or(DomainError::NotReady)?,
                    s.token.ok_or(DomainError::NotReady)?,
                    s.kind,
                ))
            })?;
            trace.site(Site::ActivateRoot);
            let status = poll_root(token)?;
            trace.words[23] = status.phase as u64 + 1;
            trace.receipt(
                status
                    .receipt
                    .map(|r| (r.apply.plan_seq, r.stamp.version, r.state)),
            );
            if let Some(error) = status.fault {
                trace.site(Site::ActivateFault);
                return Err(error);
            }
            // The first callback only bound capture/history. A transient
            // pre-publication failure must not start business work (and mutate
            // its ledger) before retrying the original fixed baseline.
            trace.site(Site::ActivatePublished);
            if kind == TrialKind::Baseline && !root::publication_started(token)? {
                trace.site(Site::ActivateBaseline);
                let _ = root::baseline_apply(token)?;
            }
            trace.site(Site::ActivateWork);
            activate_work()?;
            trace.site(Site::ActivateWindows);
            crate::service_windows::prepare_started(
                scope.family,
                scope.target,
                scope.frozen_scope_hash,
                scope.first_ns,
                scope.observation_ns,
            )?;
            trace.site(Site::ActivateCommit);
            with(|s| {
                s.phase = Phase::Run;
                s.cursor = 0;
                Ok(())
            })?;
        }
        Phase::Run => {
            trace.site(Site::RunSetup);
            let (scope, token, kind, cursor, p, ready) = with(|s| {
                Ok((
                    s.scope,
                    s.token.ok_or(DomainError::NotReady)?,
                    s.kind,
                    s.cursor,
                    s.prepared.ok_or(DomainError::NotReady)?,
                    s.first_ready,
                ))
            })?;
            if !ready || scope.is_none() {
                trace.site(Site::RunWaitingRoot);
                let status = poll_root(token)?;
                if let Some(error) = status.fault {
                    trace.site(Site::RunWaitingFault);
                    return Err(error);
                }
                return Ok(false);
            }
            let scope = scope.ok_or(DomainError::NotReady)?;
            if cursor < p.requests.len() {
                let request = p.requests[cursor];
                trace.site(Site::RunRequest);
                let token = capture::request(request.owner, request.id)
                    .map_err(|e| diagnostic_evidence_error(trace, e))?;
                trace.site(Site::RunArm);
                capture::arm_scheduled(token).map_err(|e| diagnostic_evidence_error(trace, e))?;
                trace.site(Site::RunRequestCommit);
                with(|s| {
                    s.cursor += 1;
                    Ok(())
                })?;
            }
            trace.site(Site::RunWork);
            let _ = work::poll(scope.key)?;
            trace.site(Site::RunRoot);
            let status = poll_root(token)?;
            trace.words[23] = status.phase as u64 + 1;
            trace.receipt(
                status
                    .receipt
                    .map(|r| (r.apply.plan_seq, r.stamp.version, r.state)),
            );
            if let Some(error) = status.fault {
                trace.site(Site::RunFault);
                return Err(error);
            }
            if let Some(receipt) = status.receipt {
                if kind == TrialKind::Baseline && receipt.state == ExecutionState::Applied {
                    trace.site(Site::RunBaselineCursor);
                    let old = with(|s| Ok(s.baseline_seq))?;
                    if old != receipt.apply.plan_seq {
                        trace.site(Site::RunBaselineReceipt);
                        let baseline =
                            receipt.baseline(p.baseline.one_shot().then_some(p.requests[0].id))?;
                        trace.site(Site::RunBaselineRecord);
                        history::record_baseline(scope.key, &baseline)
                            .map_err(|e| diagnostic_evidence_error(trace, e))?;
                        trace.site(Site::RunBaselineCommit);
                        with(|s| {
                            s.baseline_seq = receipt.apply.plan_seq;
                            Ok(())
                        })?;
                    }
                }
            }
            if crate::domain_platform::now_ns()
                >= scope.observation_ns.saturating_add(OBSERVATION_NS)
            {
                trace.site(Site::RunClose);
                with(|s| {
                    s.phase = Phase::Drain;
                    Ok(())
                })?;
            } else if kind == TrialKind::Baseline {
                trace.site(Site::RunRenew);
                let _ = root::baseline_apply(token)?;
            }
        }
        Phase::Drain => {
            trace.site(Site::Drain);
            let (scope, token) = with(|s| {
                Ok((
                    s.scope.ok_or(DomainError::NotReady)?,
                    s.token.ok_or(DomainError::NotReady)?,
                ))
            })?;
            if !with(|s| Ok(s.work_activation.entered()))? {
                let preparation = with(|s| s.preparation.ok_or(DomainError::NotReady))?;
                // Freeze the root before changing the owner to aborting. A
                // real Pending/Unknown publication returns false and retains
                // the original activation/drain obligation.
                let unpublished = root::begin_unactivated_close(token, preparation, &scope)?;
                if unpublished {
                    with(|s| {
                        s.partial_start = true;
                        Ok(())
                    })?;
                } else {
                    activate_work()?;
                }
            } else {
                // Entry without completion may already have performed an
                // effect. Complete that same activation, then drain normally.
                activate_work()?;
            }
            if with(|s| Ok(s.partial_start))? {
                let preparation = with(|s| {
                    let permit = s.permit.as_ref().ok_or(DomainError::NotReady)?;
                    history::begin_excluded_authorized(
                        scope,
                        permit,
                        s.last_error.unwrap_or(Error::DataIncomplete),
                    )
                    .map_err(|e| domain_error(evidence_error(e)))?;
                    s.preparation.ok_or(DomainError::NotReady)
                })?;
                if !work::abort_unactivated(preparation, &scope)? {
                    return Ok(false);
                }
                let proof = root::close_unactivated(token, &scope, preparation)?;
                if proof.capture_key() != Some(scope.key) {
                    return Err(DomainError::Stale);
                }
                with(|s| {
                    s.unpublished = Some(proof);
                    s.closing = None;
                    s.phase = Phase::CloseSources;
                    s.cursor = 0;
                    Ok(())
                })?;
                return Ok(true);
            }
            let reuse = matches!((scope.family.domain, scope.family.kind), (14, 1) | (16, 2));
            let drained = if reuse {
                work::drain(scope.key)?
            } else {
                root::lifecycle::restore_and_drain(
                    || root::restore(token),
                    || work::drain(scope.key),
                )?
            };
            if reuse && drained {
                let _ = root::restore(token)?;
            }
            let status = poll_root(token)?;
            if !drained || status.phase != root::Phase::Complete {
                return Ok(false);
            }
            let exclusion = match (status.closing, status.unpublished) {
                (Some(closing), None) => match closing.state {
                    ExecutionState::Applied => None,
                    ExecutionState::Failed(error) if reuse => Some(native_error(error)),
                    _ => return Ok(false),
                },
                (None, Some(proof)) if reuse => {
                    root::verify_unpublished_close(proof)?;
                    Some(Error::DataIncomplete)
                }
                _ => return Ok(false),
            };
            with(|s| {
                if let Some(error) = exclusion {
                    s.last_error.get_or_insert(error);
                }
                s.closing = status.closing;
                s.unpublished = status.unpublished;
                s.phase = Phase::CloseSources;
                s.cursor = 0;
                Ok(())
            })?;
        }
        Phase::CloseSources => {
            let (scope, token) = with(|s| {
                Ok((
                    s.scope.ok_or(DomainError::NotReady)?,
                    s.token.ok_or(DomainError::NotReady)?,
                ))
            })?;
            if let Some(rejected) = root::rejected(token)? {
                history::record_rejected(scope.key, &rejected)
                    .map_err(|e| domain_error(evidence_error(e)))?;
            }
            let (p, cursor) = with(|s| Ok((s.prepared.ok_or(DomainError::NotReady)?, s.cursor)))?;
            if cursor < p.source_count {
                let source = p.sources[cursor];
                let token = capture::source(source.owner, source.class)
                    .map_err(|e| domain_error(evidence_error(e)))?;
                capture::close_source(token).map_err(|e| domain_error(evidence_error(e)))?;
                with(|s| {
                    s.cursor += 1;
                    Ok(())
                })?;
            } else {
                with(|s| {
                    s.phase = Phase::Seal;
                    Ok(())
                })?;
            }
        }
        Phase::Seal => {
            let incomplete = with(|s| Ok(s.last_error.is_some()))?
                || capture::status()
                    .map_err(|e| domain_error(evidence_error(e)))?
                    .0
                    .fault
                    .is_some();
            let seal = match capture::seal(incomplete) {
                Ok(seal) => seal,
                Err(capture::Error::Capture(Error::Deadline | Error::DataIncomplete)) => {
                    capture::seal(true).map_err(|e| domain_error(evidence_error(e)))?
                }
                Err(error) => return Err(domain_error(evidence_error(error))),
            };
            history::replay::seal(seal).map_err(|e| domain_error(evidence_error(e)))?;
            let records = history::status()
                .map_err(|e| domain_error(evidence_error(e)))?
                .records;
            with(|s| {
                s.seal = Some(seal);
                s.records = records;
                s.retained = 0;
                s.export_index = 0;
                s.record_started = false;
                s.verification = None;
                s.partner = None;
                s.peer_staged = 0;
                s.phase = Phase::Verify;
                Ok(())
            })?;
        }
        Phase::Archive => {
            // The external I/O hook owns actual suspension/reacquisition of
            // CPU0 service credit while waiting for storage completion.
            return Ok(false);
        }
        Phase::RetireCapture => {
            with(|s| {
                capture::retire_exported(s.seal.ok_or(DomainError::NotReady)?)
                    .map_err(|e| domain_error(evidence_error(e)))?;
                s.phase = Phase::RetireHistory;
                Ok(())
            })?;
        }
        Phase::RetireHistory => {
            with(|s| {
                history::replay::retire_exported(s.seal.ok_or(DomainError::NotReady)?)
                    .map_err(|e| domain_error(evidence_error(e)))?;
                s.phase = Phase::ReleaseWork;
                Ok(())
            })?;
        }
        Phase::Release => {
            with(|s| {
                let keep =
                    s.kind == TrialKind::Baseline && s.verification.is_some_and(|v| v.is_ok());
                if !keep {
                    root::release(s.token.ok_or(DomainError::NotReady)?)?;
                    s.token = None;
                }
                s.phase = Phase::ReleasePermit;
                Ok(())
            })?;
        }
        Phase::ReleaseWork => {
            with(|s| {
                let run = s.scope.map(|v| v.key).ok_or(DomainError::NotReady)?;
                if s.partial_start {
                    work::release_unactivated(
                        s.preparation.ok_or(DomainError::NotReady)?,
                        s.scope.as_ref().ok_or(DomainError::NotReady)?,
                    )?;
                } else {
                    if matches!(FAMILIES[s.family].domain, 10 | 12 | 16) {
                        crate::peer_replay::set_pair_continuation(
                            run,
                            s.kind == TrialKind::Baseline
                                && s.verification.is_some_and(|v| v.is_ok()),
                        )?;
                    }
                    // Keep driving the real RELEASE handshake even while a
                    // post-seal failure is waiting for its separate journal.
                    // The peer owner retains its original scope/seal/raw
                    // packet until late_archived accepts a durable Export.
                    work::release(run)?;
                }
                s.phase = Phase::Release;
                Ok(())
            })?;
        }
        Phase::ReleasePermit => {
            with(|s| {
                capture::release_start(s.permit.as_ref().ok_or(DomainError::NotReady)?)
                    .map_err(|e| domain_error(evidence_error(e)))?;
                let accepted = s.verification.is_some_and(|v| v.is_ok());
                if accepted && s.kind == TrialKind::Baseline {
                    s.pair_group = s.prepared.map(|p| p.group);
                } else if accepted {
                    s.pair_group = None;
                }
                if !accepted {
                    s.retry_group = s.pair_group.or(s.prepared.map(|p| p.group));
                }
                if accepted {
                    s.verified += 1;
                } else {
                    s.excluded += 1;
                }
                if !accepted {
                    s.kind = TrialKind::Baseline;
                } else if s.kind == TrialKind::Baseline {
                    s.kind = TrialKind::Candidate;
                } else {
                    s.kind = TrialKind::Baseline;
                    s.group += 1;
                    if s.group == 12 {
                        s.group = 0;
                        s.family += 1;
                    }
                }
                s.trial_id = s.trial_id.checked_add(1).ok_or(DomainError::Overflow)?;
                if accepted {
                    s.prepared = None;
                }
                s.permit = None;
                s.scope = None;
                s.first_ready = false;
                s.partial_start = false;
                s.work_activation = WorkActivation::new();
                s.frozen = [0; 32];
                s.seal = None;
                s.closing = None;
                s.unpublished = None;
                s.archive = None;
                s.verification = None;
                s.baseline_seq = 0;
                s.last_error = None;
                s.partner = None;
                s.peer_staged = 0;
                if s.token.is_none() {
                    s.root_phase = 0;
                }
                s.preparation = None;
                s.prepare_claimed = false;
                s.phase = if !accepted {
                    Phase::Restart
                } else if s.family == FAMILIES.len() {
                    Phase::Complete
                } else {
                    Phase::Prepare
                };
                Ok(())
            })?;
        }
        Phase::PreparationAbort => {
            let (preparation, (error, failed), claimed) = with(|s| {
                Ok((
                    s.preparation.ok_or(DomainError::NotReady)?,
                    s.prepare_error.ok_or(DomainError::NotReady)?,
                    s.prepare_claimed,
                ))
            })?;
            root::abort_preparation(preparation, error, failed)?;
            if claimed && !work::abort_prepared(preparation)? {
                return Ok(false);
            }
            let close = root::close_preparation(preparation, error, failed)?;
            with(|s| {
                s.prepare_close = Some(close);
                s.phase = Phase::PreparationArchive;
                Ok(())
            })?;
        }
        Phase::PreparationArchive => return Ok(false),
        Phase::PreparationReleaseWork => {
            with(|s| {
                let preparation = s.preparation.ok_or(DomainError::NotReady)?;
                let export = s
                    .prepare_archive
                    .as_ref()
                    .ok_or(DomainError::NotReady)?
                    .export()?;
                root::mark_preparation_archived(export)?;
                if s.prepare_claimed {
                    work::release_prepared(preparation)?;
                }
                s.phase = Phase::PreparationReleaseRoot;
                Ok(())
            })?;
        }
        Phase::PreparationReleaseRoot => {
            with(|s| {
                root::release_preparation(s.preparation.ok_or(DomainError::NotReady)?)?;
                s.token = None;
                s.phase = Phase::PreparationReleasePermit;
                Ok(())
            })?;
        }
        Phase::PreparationReleasePermit => {
            with(|s| {
                if let Some(permit) = s.permit.as_ref() {
                    capture::release_start(permit).map_err(|e| domain_error(evidence_error(e)))?;
                }
                s.retry_group = s.pair_group.or(s.prepared.map(|p| p.group));
                s.excluded += 1;
                s.kind = TrialKind::Baseline;
                s.trial_id = s.trial_id.checked_add(1).ok_or(DomainError::Overflow)?;
                s.permit = None;
                s.prepared = None;
                s.preparation = None;
                s.prepare_claimed = false;
                s.prepare_error = None;
                s.prepare_close = None;
                s.prepare_archive = None;
                s.first_ready = false;
                s.partial_start = false;
                s.work_activation = WorkActivation::new();
                s.scope = None;
                s.last_error = None;
                s.root_phase = 0;
                s.frozen = [0; 32];
                s.baseline_seq = 0;
                s.closing = None;
                s.unpublished = None;
                s.phase = if s.retry_group.is_some() {
                    Phase::Restart
                } else {
                    Phase::Prepare
                };
                Ok(())
            })?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}
pub fn service_io(progress: &mut dyn FnMut()) {
    if cyxia_arch_aarch64::cpu::slot() != 0
        || with(|s| {
            Ok(
                !(matches!(s.phase, Phase::Archive | Phase::PreparationArchive)
                    || s.phase == Phase::ReleaseWork
                        && !s.partial_start
                        && matches!(FAMILIES[s.family].domain, 10 | 12 | 16)),
            )
        })
        .unwrap_or(true)
    {
        return;
    }
    let result = crate::domain_tasks::service_io_piece(None, progress, |yield_io| {
        with(|s| {
            if s.phase == Phase::ReleaseWork {
                let run = s.scope.ok_or(DomainError::NotReady)?.key;
                let replace = match s.archive.as_ref() {
                    Some(Journal::Late(_)) => false,
                    Some(Journal::Regular(old)) if !old.done() => {
                        return Err(DomainError::Conflict);
                    }
                    _ => true,
                };
                if replace {
                    let Some(receipt) = crate::peer_replay::late_failure(run)? else {
                        return Ok(false);
                    };
                    // Regular Export's last use was before RetireCapture.
                    // The already closed file and its persisted bytes remain
                    // intact when only the finished writer is replaced.
                    s.archive = Some(Journal::Late(late_archive::Archive::new(
                        receipt,
                        s.late_segment,
                    )?));
                }
                let Some(Journal::Late(archive)) = s.archive.as_mut() else {
                    return Err(DomainError::Conflict);
                };
                let progressed = archive.step(yield_io)?;
                if archive.done() {
                    // This capability is available only after the new raw
                    // signed packet was fsynced, read back and closed. Busy
                    // leaves the completed archive available for exact retry.
                    crate::peer_replay::late_archived(archive.export()?)?;
                    s.late_segment = archive.segment();
                    s.archived += 1;
                    s.archive = None;
                }
                return Ok(progressed);
            }
            if s.phase == Phase::PreparationArchive {
                if s.prepare_archive.is_none() {
                    let p = s.preparation.ok_or(DomainError::NotReady)?;
                    let close = s.prepare_close.ok_or(DomainError::NotReady)?;
                    let facts = if s.prepare_claimed {
                        work::prepared_failure(p)?
                    } else {
                        work::PreparedFailure {
                            target: None,
                            group: None,
                            queued_at: 0,
                            fault: None,
                            drained_at: close.drained_ns(),
                        }
                    };
                    s.prepare_archive = Some(preparation_archive::Archive::new(
                        s.prepare_close.ok_or(DomainError::NotReady)?,
                        facts,
                        s.prepared.as_ref(),
                        s.prepare_segment,
                    )?);
                }
                let archive = s.prepare_archive.as_mut().ok_or(DomainError::NotReady)?;
                let progressed = archive.step(s.prepared.as_ref(), yield_io)?;
                if archive.done() {
                    s.prepare_segment = archive.segment();
                    s.archived += 1;
                    s.phase = Phase::PreparationReleaseWork;
                }
                return Ok(progressed);
            }
            if s.phase != Phase::Archive {
                return Ok(false);
            }
            if s.archive.is_none() {
                let prepared = s.prepared.ok_or(DomainError::NotReady)?;
                s.archive = Some(Journal::Regular(Archive::new(
                    s.scope.ok_or(DomainError::NotReady)?,
                    s.seal.ok_or(DomainError::NotReady)?,
                    s.records,
                    s.segment,
                    s.verification.ok_or(DomainError::NotReady)?,
                    &prepared.sources[..prepared.source_count],
                    s.partner,
                    s.closing,
                    s.unpublished,
                    if s.partial_start {
                        Some(s.preparation.ok_or(DomainError::NotReady)?)
                    } else {
                        None
                    },
                )?));
            }
            let Some(Journal::Regular(archive)) = s.archive.as_mut() else {
                return Err(DomainError::Conflict);
            };
            let progressed = archive.step(yield_io)?;
            if archive.done() {
                if s.partial_start {
                    root::mark_unactivated_archived(
                        s.token.ok_or(DomainError::NotReady)?,
                        archive.export()?,
                    )?;
                }
                s.segment = archive.segment();
                s.archived += 1;
                s.phase = Phase::RetireCapture;
            }
            Ok(progressed)
        })
    });
    if let Some(Err(error)) = result {
        retain_error(error, None);
    }
    publish_evidence();
}
// Keep mutually exclusive phase work off one shared native stack frame. In
// particular a validation probe owns a full CandidateSet, whereas verification
// borrows records from the input loan and never needs that probe temporary.
#[inline(never)]
pub fn control_step() -> Result<bool, DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 1 {
        return Err(DomainError::Auth);
    }
    runtime::authorize_learning_turn()?;
    match with(|s| Ok(s.phase))? {
        Phase::Run => control_probe_step(),
        Phase::Restart => control_restart_step(),
        Phase::Complete => control_complete_step(),
        Phase::Verify => control_verify_step(),
        _ => Ok(false),
    }
}

#[inline(never)]
fn control_probe_step() -> Result<bool, DomainError> {
    let (token, scope) = with(|s| {
        Ok((
            s.token,
            s.scope
                .filter(|scope| s.first_ready && scope.kind == TrialKind::Candidate),
        ))
    })?;
    let (Some(token), Some(scope)) = (token, scope) else {
        return Ok(false);
    };
    if !data::needs_probe(scope.family).map_err(domain_error)? {
        return Ok(false);
    }
    let proof = match root::validation_probe(token) {
        Ok(proof) => proof,
        Err(DomainError::Busy | DomainError::Again | DomainError::NotReady) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    if proof.token() != token || proof.family() != scope.family {
        return Err(DomainError::Stale);
    }
    history::replay::record_probe(scope.key, &proof)
        .map_err(|e| domain_error(evidence_error(e)))?;
    data::retain_probe(proof).map_err(domain_error)
}

#[inline(never)]
fn control_restart_step() -> Result<bool, DomainError> {
    let (family, group) = with(|s| {
        Ok((
            FAMILIES[s.family],
            s.retry_group
                .or(s.prepared.as_ref().map(|p| p.group))
                .ok_or(DomainError::NotReady)?,
        ))
    })?;
    data::retry_pair(family, group).map_err(domain_error)?;
    with(|s| {
        s.prepared = None;
        s.retry_group = None;
        s.pair_group = None;
        s.phase = Phase::Prepare;
        Ok(())
    })?;
    Ok(true)
}

#[inline(never)]
fn control_complete_step() -> Result<bool, DomainError> {
    let released = with(|s| {
        if let Some(loan) = s.loan.as_mut() {
            runtime::abandon_learning_input(loan)?;
            s.loan = None;
            s.scratch = 0;
            s.initialized = 0;
            return Ok(true);
        }
        Ok(false)
    })?;
    if released {
        return Ok(true);
    }
    data::control_step()
}

#[inline(never)]
fn control_verify_step() -> Result<bool, DomainError> {
    let result = with(verification_step);
    if let Err(error) = result {
        if !matches!(
            error,
            DomainError::Busy | DomainError::Again | DomainError::NotReady
        ) {
            with(|s| {
                let error = native_error(error);
                s.verification = Some(Err(error));
                s.last_error = Some(error);
                Ok(())
            })?;
            return Ok(true);
        }
    }
    result
}

// Record decoding and full verification are separate calls: their large
// mutually exclusive scratch values must not remain live across each other.
#[inline(never)]
fn verification_step(s: &mut State) -> Result<bool, DomainError> {
    let seal = s.seal.ok_or(DomainError::NotReady)?;
    if s.verification.is_some() {
        if let Some(pin) = s.model.as_ref() {
            domain_control::release_job_model(pin)?;
            s.model = None;
            return Ok(true);
        }
        s.phase = Phase::Archive;
        return Ok(true);
    }
    if let Some(error) = seal.exclusion.or(s.last_error) {
        s.verification = Some(Err(error));
        return Ok(true);
    }
    if matches!(FAMILIES[s.family].domain, 10 | 12 | 16) {
        if s.partner.is_none() {
            let partner = crate::peer_replay::partner(seal.key).map_err(domain_error)?;
            history::replay::partner_frozen(
                s.scope.as_ref().ok_or(DomainError::NotReady)?,
                &partner,
            )
            .map_err(domain_error)?;
            if partner
                .seal
                .count
                .checked_add(u64::from(seal.intervals))
                .is_none_or(|n| n > reward::MAX_CPU_INTERVALS as u64)
            {
                return Err(DomainError::Capacity);
            }
            s.partner = Some(partner);
            return Ok(true);
        }
        if s.peer_staged < s.partner.ok_or(DomainError::NotReady)?.seal.count as usize {
            let mut rows = [CpuInterval {
                node: [0; 32],
                core: 0,
                start_ns: 0,
                end_ns: 0,
                class: CpuClass::Policy,
            }; 16];
            let count = crate::peer_replay::copy_intervals(seal.key, s.peer_staged, &mut rows)
                .map_err(domain_error)?;
            if count == 0
                || s.peer_staged + count
                    > s.partner.ok_or(DomainError::NotReady)?.seal.count as usize
            {
                return Err(DomainError::Stale);
            }
            capture::stage_intervals(seal, s.peer_staged, &rows[..count])
                .map_err(|e| domain_error(evidence_error(e)))?;
            s.peer_staged += count;
            return Ok(true);
        }
    }
    if s.loan.is_none() {
        s.loan = Some(runtime::borrow_learning_input()?);
        return Ok(true);
    }
    if s.scratch == 0 {
        let (base, len) =
            runtime::learning_input_span(s.loan.as_ref().ok_or(DomainError::NotReady)?)?;
        if len < size_of::<Scratch>() || !base.is_multiple_of(align_of::<Scratch>()) {
            return Err(DomainError::Capacity);
        }
        s.scratch = base;
        return Ok(true);
    }
    if s.initialized < size_of::<RewardWorkspace>() {
        let n = (size_of::<RewardWorkspace>() - s.initialized).min(4096);
        // All scalar fields in RewardWorkspace are integers or bool. No
        // reference exists until these charged pieces initialize it fully.
        unsafe {
            core::ptr::write_bytes((s.scratch as *mut u8).add(s.initialized), 0, n);
        }
        s.initialized += n;
        return Ok(true);
    }
    if s.model.is_none() {
        s.model = Some(domain_control::learning_coordinator::pin_active().map_err(domain_error)?);
        return Ok(true);
    }
    if s.export_index < s.records {
        return export_record_step(s, seal);
    }
    match verify(s) {
        Ok(Some(hash)) => s.verification = Some(Ok(hash)),
        Ok(None) => (),
        Err(error) => {
            s.verification = Some(Err(error));
            s.last_error = Some(error);
        }
    }
    Ok(true)
}

#[inline(never)]
fn export_record_step(s: &mut State, seal: Seal) -> Result<bool, DomainError> {
    let p = s.scratch as *mut Scratch;
    if s.retained == RECORD_LIMIT {
        s.verification = Some(Err(Error::Capacity));
        return Ok(true);
    }
    if !s.record_started {
        unsafe {
            if s.export_index == 0 {
                // One walk per real sealed side. These small continuations
                // contain no references or independent allocations.
                core::ptr::addr_of_mut!((*p).verification).write(MaybeUninit::new(
                    ReplayVerification::new(if s.kind == TrialKind::Candidate {
                        reward::ReplayKind::Candidate
                    } else {
                        reward::ReplayKind::Baseline
                    }),
                ));
                core::ptr::addr_of_mut!((*p).delivery).write(MaybeUninit::new(None));
            }
            history::replay::Record::init_at(
                core::ptr::addr_of_mut!((*p).records[s.retained]).cast(),
                seal.key,
                s.export_index,
            );
        }
        s.record_started = true;
        return Ok(true);
    }
    let record =
        unsafe { (&mut *core::ptr::addr_of_mut!((*p).records[s.retained])).assume_init_mut() };
    if record
        .copy_piece()
        .map_err(|e| domain_error(evidence_error(e)))?
    {
        return Ok(true);
    }
    if s.kind == TrialKind::Baseline {
        let baseline = record
            .baseline()
            .map_err(|e| domain_error(evidence_error(e)))?;
        unsafe {
            core::ptr::addr_of_mut!((*p).baseline[s.retained]).write(MaybeUninit::new(baseline));
        }
        s.retained += 1;
    } else if record
        .published()
        .map_err(|e| domain_error(evidence_error(e)))?
    {
        let set = record
            .candidates()
            .map_err(|e| domain_error(evidence_error(e)))?;
        unsafe {
            core::ptr::addr_of_mut!((*p).sets[s.retained]).write(MaybeUninit::new(set));
        }
        s.retained += 1;
    }
    s.export_index += 1;
    s.record_started = false;
    Ok(true)
}

#[inline(never)]
fn verify(s: &mut State) -> Result<Option<[u8; 32]>, Error> {
    if s.records == 0 || s.retained == 0 {
        return Err(Error::DataIncomplete);
    }
    let scope = s.scope.as_ref().ok_or(Error::State)?;
    let seal = s.seal.ok_or(Error::State)?;
    let prepared = s.prepared.as_ref().ok_or(Error::State)?;
    let model = s.model.as_ref().ok_or(Error::State)?;
    let address = model
        .physical_address()
        .checked_add(crate::HIGH)
        .ok_or(Error::Capacity)?;
    let bytes = unsafe { &*(address as *const [u8; MODEL_BYTES]) };
    let scratch = s.scratch as *mut Scratch;
    let mut adoptions: [MaybeUninit<Adoption<'_>>; RECORD_LIMIT] =
        [const { MaybeUninit::uninit() }; RECORD_LIMIT];
    if s.kind == TrialKind::Candidate {
        for (i, slot) in adoptions[..s.retained].iter_mut().enumerate() {
            let record =
                unsafe { (&*core::ptr::addr_of!((*scratch).records[i])).assume_init_ref() };
            let set = unsafe { (&*core::ptr::addr_of!((*scratch).sets[i])).assume_init_ref() };
            if set.model != model.binding() {
                return Err(Error::Stale);
            }
            slot.write(
                record
                    .adoption(
                        set,
                        bytes,
                        prepared
                            .baseline
                            .one_shot()
                            .then_some(prepared.requests[0].id),
                        &[],
                    )
                    .map_err(evidence_error)?,
            );
        }
    }
    let adoption_slice: &[Adoption<'_>] = if s.kind == TrialKind::Candidate {
        unsafe { core::slice::from_raw_parts(adoptions.as_ptr().cast(), s.retained) }
    } else {
        &[]
    };
    let baseline_slice: &[BaselineAdoption] = if s.kind == TrialKind::Baseline {
        unsafe {
            core::slice::from_raw_parts(core::ptr::addr_of!((*scratch).baseline).cast(), s.retained)
        }
    } else {
        &[]
    };
    let delivery =
        unsafe { (&mut *core::ptr::addr_of_mut!((*scratch).delivery)).assume_init_mut() };
    if let Some(verified) = delivery.take() {
        let hash = verified.evidence_hash();
        let probe = adoption_slice.first().map(|a| a.candidates);
        return match data::accept_bounded(verified, s.split(), probe) {
            Ok(()) => Ok(Some(hash)),
            Err(data::AcceptFailure::Busy(verified)) => {
                *delivery = Some(verified);
                Ok(None)
            }
            Err(data::AcceptFailure::Rejected(error, _verified)) => Err(error),
        };
    }
    let workspace = unsafe { (&mut *core::ptr::addr_of_mut!((*scratch).reward)).assume_init_mut() };
    let verification =
        unsafe { (&mut *core::ptr::addr_of_mut!((*scratch).verification)).assume_init_mut() };
    let result = capture::with_sealed_trace(seal, |trace| {
        let mut coverage = [trace.coverage(); 2];
        let mut nodes = [coverage[0].node; 2];
        let status = trace.status();
        let mut count = 1;
        let mut frozen = scope.frozen_other_domains;
        let mut warmup = status.ordinary_warmup_ns;
        let mut later = status.later_workload_ns;
        if let Some(peer) = s.partner.as_ref() {
            count = 2;
            coverage[1] = peer.seal.coverage;
            nodes[1] = coverage[1].node;
            frozen = history::replay::partner_frozen(scope, peer)?;
            warmup = warmup
                .checked_add(peer.seal.ordinary_warmup_ns)
                .ok_or(Error::Numeric)?;
            later = later
                .checked_add(peer.seal.later_workload_ns)
                .ok_or(Error::Numeric)?;
        }
        let trial = Trial {
            id: scope.key.trial_id,
            family: scope.family,
            group: scope.group,
            frozen_other_domains: frozen,
            schemas: scope.schemas,
            local_node: nodes[0],
            controlled_nodes: &nodes[..count],
            observation_ns: scope.observation_ns,
            observation_end_ns: scope.observation_ns + OBSERVATION_NS,
            warmed_from_ns: scope.warmed_from_ns,
            closing_ns: seal.closing_ns,
            requests: trace.requests(),
            adoptions: adoption_slice,
            coverage: &coverage[..count],
            cpu: if s.partner.is_some() {
                trace.staged_intervals()
            } else {
                trace.intervals()
            },
            baseline: baseline_slice,
            joint_policy: &[],
            correct: true,
            frozen: true,
            closing: ExecutionState::Applied,
            ordinary_warmup_cpu_ns: warmup,
            later_workload_cpu_ns: later,
            peak_workspace_bytes: WORKSPACE_PEAK_BYTES as u64,
        };
        let authority = history::replay::Incremental::new(&trace, model, s.partner)?;
        verification.step(&trial, &authority, workspace)
    });
    let verified = match result {
        // No continuation step ran when the real capture gate was busy.
        Err(capture::Error::Busy) => return Ok(None),
        Err(error) => return Err(evidence_error(error)),
        Ok(verified) => verified,
    };
    if let Some(verified) = verified {
        // Acceptance runs on the next charged turn. Keep the unique checked
        // capability in the same loan until the actual data owner accepts it.
        *delivery = Some(verified);
    }
    Ok(None)
}
const _: () = assert!(size_of::<State>() <= META_PAGES * 4096);
const _: () = assert!(size_of::<Scratch>() <= cyxia_prototype::learning::worker_wire::INPUT_LIMIT);
const _: () = assert!(
    data::OWNED_BYTES + META_PAGES * 4096 + crate::learning_prewarm::OWNED_BYTES
        <= crate::domain_control::learning_driver::MAX_SOURCE_BYTES
);
const _: () = assert!(WORKSPACE_PEAK_BYTES <= 1024 * 1024);
