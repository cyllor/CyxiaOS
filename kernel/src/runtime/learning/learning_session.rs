//! A single protected, pool-backed native validation/governance session.
//! Numerical work is performed by the independently mapped EL0 worker. This
//! owner only prepares bounded pieces and imports authenticated completions in
//! the runtime's real prepaid C1 extra turns. Absent replay measurements cannot
//! promote a model. CPU0 safety maintenance retains all unknown worker loans.
use crate::{
    control_pool as pool,
    domain_control::{
        self, NativeModelPin, governance as root, learning_coordinator as coordinator,
        learning_driver::ValidationDelivery,
    },
    smp::prototype_runtime as runtime,
};
use core::{
    cell::UnsafeCell,
    mem::{align_of, size_of},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use cyxia_prototype::{
    domains::{ApplyId, Error as DomainError, ObjectKey},
    learning::{
        Error, FAMILIES,
        governance::{
            CanaryPermit, Governance, GovernanceInit, InitValue, Role, Stage, WINDOW_NS,
            WorkReceipt,
        },
        reward::{RewardWorkspace, WorkRequest},
        score::{EncoderState, PreparedScore, Scored},
        score_wire,
        worker_wire::JobBinding,
    },
    model::MODEL_BYTES,
    policy::{CandidateSet, ModelBinding},
};

const OWNER: ObjectKey = ObjectKey {
    id: 0x4c45_5345_5353,
    generation: 1,
};
const GOV_OWNER: ObjectKey = ObjectKey {
    id: 0x4c45_474f_564e,
    generation: 1,
};
pub const WORKSPACE_METADATA_PAGES: usize = 6;
const META_PAGES: usize = WORKSPACE_METADATA_PAGES;
const GOV_PAGES: usize = 35;
const PAGE: usize = 4096;
const SET_OFFSET: usize = PAGE;
const STATE_OFFSET: usize = 3 * PAGE;
const WORKSPACE: u32 = 1024 * 1024;
type NativeGovernance = Governance<'static, 'static>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Turn {
    Idle,
    Progress,
    Waiting,
    Retry,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    PinActive,
    PrepareInit,
    Initialize,
    FinishInit,
    Manage,
    BorrowInput,
    PrepareScore,
    StartEncoder,
    Encode,
    FinishEncoding,
    Seal,
    Submit,
    Wait,
    Read,
    Receipt,
    Accept,
    Consume,
    CloseScore,
    CleanupScore,
    Release,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub stage: Option<Stage>,
    pub job: Option<ObjectKey>,
    pub pending: Option<(ApplyId, u64)>,
    pub binding: Option<ModelBinding>,
    pub completed: u64,
    pub rejected: u64,
    pub steps: u64,
    pub last_error: Option<Error>,
}

// Anchors and candidate sets occupy disjoint regions from mutable state.
// After Governance borrows delivery.candidate, no &mut Anchors is formed and
// no anchor is changed until the Governance and encoder lifetimes have ended.
struct Anchors {
    delivery: Option<ValidationDelivery>,
    active: Option<NativeModelPin>,
}
struct State {
    phase: Phase,
    governance_ready: bool,
    init: Option<GovernanceInit<'static, 'static>>,
    shadow_window: u64,
    shadow_seen: bool,
    family_cursor: usize,
    permit: Option<CanaryPermit>,
    last_canary_window: Option<u64>,
    role: Role,
    binding: Option<JobBinding>,
    reserved: bool,
    submitted: bool,
    input: Option<runtime::LearningInputLoan>,
    input_base: usize,
    input_bytes: usize,
    allocation: Option<pool::Allocation>,
    set_ready: bool,
    encoder: Option<EncoderState<'static>>,
    prepared: Option<PreparedScore>,
    report: [u8; score_wire::RESULT_BYTES],
    scored: Option<Scored>,
    cost: Option<WorkReceipt>,
    pending: Option<(ApplyId, u64)>,
    requested: Option<Error>,
    cancel_sent: bool,
    completed: u64,
    rejected: u64,
    steps: u64,
    last_error: Option<Error>,
}
const _: () = assert!(size_of::<Anchors>() <= PAGE);
const _: () = assert!(size_of::<CandidateSet>() <= 2 * PAGE);
const _: () = assert!(size_of::<State>() <= META_PAGES * PAGE - STATE_OFFSET);
const _: () = assert!(size_of::<NativeGovernance>() <= GOV_PAGES * PAGE);

struct Setup {
    metadata: Option<pool::Allocation>,
    metadata_pin: Option<pool::Lease>,
    governance: Option<pool::Allocation>,
    governance_pin: Option<pool::Lease>,
}
struct SetupCell(UnsafeCell<Setup>);
unsafe impl Sync for SetupCell {}
static SETUP: SetupCell = SetupCell(UnsafeCell::new(Setup {
    metadata: None,
    metadata_pin: None,
    governance: None,
    governance_pin: None,
}));
static GATE: AtomicBool = AtomicBool::new(false);
static BASE: AtomicUsize = AtomicUsize::new(0);
static GOVERNANCE_BASE: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicBool = AtomicBool::new(false);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn guard() -> Result<Guard, DomainError> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| DomainError::Busy)?;
    Ok(Guard)
}
fn native_error(error: DomainError) -> Error {
    match error {
        DomainError::Busy | DomainError::Again | DomainError::NotReady => Error::Unknown,
        DomainError::Stale => Error::Stale,
        DomainError::Capacity => Error::Capacity,
        DomainError::Budget => Error::Budget,
        DomainError::Expired => Error::Deadline,
        DomainError::Overflow | DomainError::Range => Error::Numeric,
        DomainError::Conflict => Error::Conflict,
        DomainError::Schema => Error::Schema,
        _ => Error::Evidence,
    }
}
fn now() -> u64 {
    crate::domain_platform::now_ns()
}
fn key(s: &State) -> Option<ObjectKey> {
    s.binding.map(|b| ObjectKey {
        id: b.job_id,
        generation: b.boot_epoch,
    })
}
fn state_pointer(base: usize) -> *mut State {
    (base + STATE_OFFSET) as *mut State
}
fn anchors(base: usize) -> &'static Anchors {
    // The caller holds GATE. These immutable anchors have permanent real pins;
    // only the explicit post-Governance release phase may mutate their fields.
    unsafe { &*(base as *const Anchors) }
}
fn governance_pointer() -> *mut NativeGovernance {
    GOVERNANCE_BASE.load(Ordering::Acquire) as *mut NativeGovernance
}
fn governance(s: &State) -> Result<&'static NativeGovernance, Error> {
    if !s.governance_ready {
        return Err(Error::State);
    }
    Ok(unsafe { &*governance_pointer() })
}
fn governance_mut(s: &State) -> Result<&'static mut NativeGovernance, Error> {
    if !s.governance_ready || s.encoder.is_some() {
        return Err(Error::State);
    }
    // GATE excludes all other access. Encoder borrows have ended before any
    // mutable Governance access; no mutable reference escapes this module.
    Ok(unsafe { &mut *governance_pointer() })
}

/// Reserve the real banks on CPU0. Large values are never constructed here;
/// every initialization write happens later inside a prepaid C1 turn.
pub fn init() -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    let _guard = guard()?;
    if BASE.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let setup = unsafe { &mut *SETUP.0.get() };
    if setup.metadata.is_none() {
        let a = runtime::learning_session_workspace()?;
        if a.owner() != OWNER || a.pages() != META_PAGES {
            return Err(DomainError::Range);
        }
        setup.metadata = Some(a);
    }
    let metadata = setup.metadata.ok_or(DomainError::NotReady)?;
    if setup.metadata_pin.is_none() {
        setup.metadata_pin = Some(pool::pin(metadata)?);
    }
    if setup.governance.is_none() {
        setup.governance = Some(pool::allocate(GOV_OWNER, GOV_PAGES)?);
    }
    let bank = setup.governance.ok_or(DomainError::NotReady)?;
    if setup.governance_pin.is_none() {
        setup.governance_pin = Some(pool::pin(bank)?);
    }
    let (base, _, bytes) = pool::span(metadata)?;
    let (gov, _, gov_bytes) = pool::span(bank)?;
    if bytes != META_PAGES * PAGE
        || gov_bytes != GOV_PAGES * PAGE
        || !(base + STATE_OFFSET).is_multiple_of(align_of::<State>())
        || !(base + SET_OFFSET).is_multiple_of(align_of::<CandidateSet>())
        || !gov.is_multiple_of(align_of::<NativeGovernance>())
    {
        return Err(DomainError::Range);
    }
    GOVERNANCE_BASE.store(gov, Ordering::Release);
    BASE.store(base, Ordering::Release);
    Ok(())
}

#[inline(never)]
fn initialize_metadata(base: usize) {
    let p = state_pointer(base);
    // Write fields directly, without a six-page temporary or a reference to
    // uninitialized State. The candidate-set region remains uninitialized.
    unsafe {
        core::ptr::addr_of_mut!((*(base as *mut Anchors)).delivery).write(None);
        core::ptr::addr_of_mut!((*(base as *mut Anchors)).active).write(None);
        macro_rules! write {
            ($field:ident, $value:expr) => {
                core::ptr::addr_of_mut!((*p).$field).write($value)
            };
        }
        write!(phase, Phase::Idle);
        write!(governance_ready, false);
        write!(init, None);
        write!(shadow_window, 0);
        write!(shadow_seen, false);
        write!(family_cursor, 0);
        write!(permit, None);
        write!(last_canary_window, None);
        write!(role, Role::Shadow);
        write!(binding, None);
        write!(reserved, false);
        write!(submitted, false);
        write!(input, None);
        write!(input_base, 0);
        write!(input_bytes, 0);
        write!(allocation, None);
        write!(set_ready, false);
        write!(encoder, None);
        write!(prepared, None);
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!((*p).report).cast::<u8>(),
            0,
            score_wire::RESULT_BYTES,
        );
        write!(scored, None);
        write!(cost, None);
        write!(pending, None);
        write!(requested, None);
        write!(cancel_sent, false);
        write!(completed, 0);
        write!(rejected, 0);
        write!(steps, 0);
        write!(last_error, None);
    }
    READY.store(true, Ordering::Release);
}

/// Suitable for the protected dataset provider's validation callback. Busy
/// always returns the same non-clonable delivery to its current custodian.
pub fn accept(delivery: ValidationDelivery) -> Result<(), (Error, ValidationDelivery)> {
    if let Err(e) = runtime::authorize_learning_turn() {
        return Err((native_error(e), delivery));
    }
    let _guard = match guard() {
        Ok(g) => g,
        Err(e) => return Err((native_error(e), delivery)),
    };
    let base = BASE.load(Ordering::Acquire);
    if base == 0 || !READY.load(Ordering::Acquire) {
        return Err((Error::Unknown, delivery));
    }
    let s = unsafe { &mut *state_pointer(base) };
    if s.governance_ready
        && governance(s).is_ok_and(|g| g.stage() == Stage::Active)
        && s.phase == Phase::Manage
        && s.binding.is_none()
        && s.pending.is_none()
    {
        // A new validated generation can replace this completed session only
        // after all old Governance borrows and its exact pins are released.
        s.phase = Phase::Release;
        return Err((Error::Unknown, delivery));
    }
    if s.phase != Phase::Idle || anchors(base).delivery.is_some() {
        return Err((Error::Unknown, delivery));
    }
    if delivery.candidate().is_err() {
        return Err((Error::Evidence, delivery));
    }
    unsafe {
        core::ptr::addr_of_mut!((*(base as *mut Anchors)).delivery).write(Some(delivery));
    }
    s.requested = None;
    s.last_error = None;
    s.family_cursor = 0;
    s.shadow_seen = false;
    s.permit = None;
    s.last_canary_window = None;
    s.phase = Phase::PinActive;
    Ok(())
}

#[inline(never)]
fn prepare_init(s: &mut State, base: usize) -> Result<(), Error> {
    let anchor = anchors(base);
    let candidate = anchor.delivery.as_ref().ok_or(Error::State)?.candidate()?;
    let pin = anchor.active.as_ref().ok_or(Error::State)?;
    let address = pin
        .physical_address()
        .checked_add(crate::HIGH)
        .ok_or(Error::Numeric)?;
    let old = unsafe { &*(address as *const [u8; MODEL_BYTES]) };
    let future = (now() / WINDOW_NS).checked_add(1).ok_or(Error::Numeric)?;
    s.init = Some(coordinator::prepare_governance(candidate, old, future)?);
    s.shadow_window = future;
    s.phase = Phase::Initialize;
    Ok(())
}

#[inline(never)]
fn initialize_governance(s: &mut State) -> Result<(), Error> {
    let init = s.init.as_mut().ok_or(Error::State)?;
    if init.completed_pieces() + 1 == init.total_pieces() {
        let future = (now() / WINDOW_NS).checked_add(1).ok_or(Error::Numeric)?;
        init.set_start_window(future)?;
        s.shadow_window = future;
    }
    let Some(piece) = init.peek() else {
        s.phase = Phase::FinishInit;
        return Ok(());
    };
    if piece
        .offset
        .checked_add(piece.value.byte_len())
        .is_none_or(|n| n > init.bytes())
        || piece.offset % piece.value.alignment() != 0
    {
        return Err(Error::Evidence);
    }
    let p = unsafe { governance_pointer().cast::<u8>().add(piece.offset) };
    unsafe {
        macro_rules! write {
            ($value:expr) => {
                core::ptr::write(p.cast(), $value)
            };
        }
        match piece.value {
            InitValue::Candidate(v) => write!(v),
            InitValue::Old(v) => write!(v),
            InitValue::Binding(v) => write!(v),
            InitValue::OptionalBinding(v) => write!(v),
            InitValue::Stage(v) => write!(v),
            InitValue::U64(v) => write!(v),
            InitValue::U16(v) => write!(v),
            InitValue::Bool(v) => write!(v),
            InitValue::U32(v) => write!(v),
            InitValue::Target(v) => write!(v),
            InitValue::Permit(v) => write!(v),
            InitValue::Restoration(v) => write!(v),
            InitValue::OptionalU64(v) => write!(v),
            InitValue::Usize(v) => write!(v),
            InitValue::OptionalUsize(v) => write!(v),
            InitValue::U8(v) => write!(v),
            InitValue::Fault(v) => write!(v),
            InitValue::Submission(v) => write!(v),
            InitValue::Second(v) => write!(v),
            InitValue::Incomplete(v) => write!(v),
        }
    }
    init.commit(piece.sequence)?;
    if init.completed_pieces() == init.total_pieces() {
        s.phase = Phase::FinishInit;
    }
    Ok(())
}
fn finish_init(s: &mut State) -> Result<(), Error> {
    let init = s.init.as_mut().ok_or(Error::State)?;
    let future = (now() / WINDOW_NS).checked_add(1).ok_or(Error::Numeric)?;
    if init.start_window() < future {
        init.set_start_window(future)?;
        s.shadow_window = future;
        s.phase = Phase::Initialize;
        return Ok(());
    }
    let complete = coordinator::finish_governance(&mut s.init)?;
    if complete.bytes() != size_of::<NativeGovernance>()
        || complete.alignment() != align_of::<NativeGovernance>()
    {
        return Err(Error::Evidence);
    }
    s.governance_ready = true;
    s.phase = Phase::Manage;
    Ok(())
}
fn family(index: usize) -> (u16, u16) {
    match index {
        0 => (1, 1),
        1 => (1, 2),
        2..=15 => (index as u16, 1),
        16 => (16, 1),
        _ => (16, 2),
    }
}

fn maintenance(s: &mut State) -> Result<(), Error> {
    if !s.governance_ready || s.encoder.is_some() {
        return Ok(());
    }
    let gov = governance_mut(s)?;
    root::tick(gov)?;
    if let Some((apply, version)) = s.pending {
        if root::reconcile(gov, apply, version)?.terminal() {
            s.pending = None;
        }
    }
    if let Some(reason) = s.requested {
        if gov.stage() == Stage::Active {
            coordinator::rollback(gov)?;
        } else if !matches!(gov.stage(), Stage::Rejected | Stage::Restoring) {
            root::abort(gov, reason)?;
        }
        s.requested = None;
    }
    if gov.stage() == Stage::Restoring && s.pending.is_none() {
        let _ = root::restore(gov)?;
    }
    Ok(())
}

fn manage(s: &mut State) -> Result<Turn, Error> {
    let at = now();
    let stage = governance(s)?.stage();
    match stage {
        Stage::Shadow => {
            let window = at / WINDOW_NS;
            if window < s.shadow_window {
                return Ok(Turn::Retry);
            }
            if window > s.shadow_window {
                if window != s.shadow_window.checked_add(1).ok_or(Error::Numeric)? || !s.shadow_seen
                {
                    return Err(Error::DataIncomplete);
                }
                root::close_shadow_window(governance_mut(s)?)?;
                s.shadow_window = window;
                s.shadow_seen = false;
                return Ok(Turn::Progress);
            }
            if s.shadow_seen || at % WINDOW_NS >= WINDOW_NS / 2 {
                return Ok(Turn::Retry);
            }
            s.role = Role::Shadow;
            s.phase = Phase::BorrowInput;
            Ok(Turn::Progress)
        }
        Stage::Ready => {
            let target = crate::domain_services::canary_target().map_err(native_error)?;
            if !crate::learning_canary::prepare_baseline(target.key)? {
                return Ok(Turn::Retry);
            }
            let permit = root::begin_canary(governance_mut(s)?)?;
            s.permit = Some(permit);
            crate::learning_canary::begin(permit)?;
            Ok(Turn::Progress)
        }
        Stage::Canary => {
            let permit = s.permit.ok_or(Error::State)?;
            if at < permit.start_ns {
                return Ok(Turn::Retry);
            }
            let window = (at - permit.start_ns) / WINDOW_NS;
            if s.pending.is_some()
                || s.last_canary_window == Some(window)
                || at % WINDOW_NS >= WINDOW_NS / 2
            {
                return Ok(Turn::Retry);
            }
            s.role = Role::Canary;
            s.phase = Phase::BorrowInput;
            Ok(Turn::Progress)
        }
        Stage::Frozen => match coordinator::promote(governance_mut(s)?) {
            Ok(_) => {
                s.completed = s.completed.checked_add(1).ok_or(Error::Numeric)?;
                Ok(Turn::Progress)
            }
            Err(Error::DataIncomplete | Error::Unknown) => {
                s.last_error = Some(Error::DataIncomplete);
                Ok(Turn::Retry)
            }
            Err(e) => Err(e),
        },
        Stage::Restoring => Ok(Turn::Retry),
        Stage::Rejected => {
            crate::learning_canary::request_release();
            s.phase = Phase::Release;
            Ok(Turn::Progress)
        }
        // The Active bank owns the model independently. Retain this session's
        // rollback capability while allowing another real dataset to compute.
        Stage::Active => {
            crate::learning_canary::request_release();
            Ok(Turn::Idle)
        }
    }
}

#[inline(never)]
fn prepare_score(s: &mut State, base: usize) -> Result<Turn, Error> {
    if s.role == Role::Shadow && now() / WINDOW_NS != s.shadow_window {
        // A missing real owner snapshot cannot keep an idle input loan in an
        // already incomplete Shadow window indefinitely.
        return Err(Error::DataIncomplete);
    }
    let (domain, kind) = if s.role == Role::Canary {
        (15, 1)
    } else {
        family(s.family_cursor)
    };
    // This disjoint, two-page region has no live encoder borrow. Root writes
    // directly into the real loan and only success permits a CandidateSet
    // reference. Returning the six-KiB object through several Result frames
    // would exceed the native C stack when combined with owner callbacks.
    s.set_ready = false;
    let destination =
        unsafe { &mut *((base + SET_OFFSET) as *mut core::mem::MaybeUninit<CandidateSet>) };
    let result = root::prepare_score_into(destination, governance(s)?, s.role, domain, kind, 0);
    let binding = match result {
        Ok(v) => v,
        Err(Error::DataIncomplete) if s.role == Role::Shadow => {
            s.family_cursor = (s.family_cursor + 1) % FAMILIES;
            // No proposal was reserved. Keep the unique idle input loan and
            // try another real family on the next charged turn.
            return Ok(Turn::Progress);
        }
        Err(e) => return Err(e),
    };
    s.set_ready = true;
    s.binding = Some(binding);
    s.reserved = true;
    s.phase = Phase::StartEncoder;
    Ok(Turn::Progress)
}
#[inline(never)]
fn start_encoder(s: &mut State, base: usize) -> Result<(), Error> {
    if !s.set_ready {
        return Err(Error::State);
    }
    let set = unsafe { &*((base + SET_OFFSET) as *const CandidateSet) };
    let encoder = governance(s)?.prepare_score(
        set,
        s.role,
        s.binding.ok_or(Error::State)?,
        WORKSPACE,
        now(),
    )?;
    if encoder.input_len() > s.input_bytes {
        return Err(Error::Capacity);
    }
    s.encoder = Some(encoder);
    s.phase = Phase::Encode;
    Ok(())
}
fn input_span(s: &State) -> Result<(usize, usize), Error> {
    let (base, bytes) = runtime::learning_input_span(s.input.as_ref().ok_or(Error::State)?)
        .map_err(native_error)?;
    if base != s.input_base || bytes != s.input_bytes {
        return Err(Error::Evidence);
    }
    Ok((base, bytes))
}

#[inline(never)]
fn step(s: &mut State, base: usize) -> Result<Turn, Error> {
    match s.phase {
        Phase::Idle => return Ok(Turn::Idle),
        Phase::PinActive => {
            let pin = coordinator::pin_active()?;
            unsafe {
                core::ptr::addr_of_mut!((*(base as *mut Anchors)).active).write(Some(pin));
            }
            s.phase = Phase::PrepareInit;
        }
        Phase::PrepareInit => prepare_init(s, base)?,
        Phase::Initialize => initialize_governance(s)?,
        Phase::FinishInit => finish_init(s)?,
        Phase::Manage => return manage(s),
        Phase::BorrowInput => {
            if s.input.is_none() {
                s.input = Some(runtime::borrow_learning_input().map_err(native_error)?);
            }
            let (address, bytes) =
                runtime::learning_input_span(s.input.as_ref().ok_or(Error::State)?)
                    .map_err(native_error)?;
            s.input_base = address;
            s.input_bytes = bytes;
            s.phase = Phase::PrepareScore;
        }
        Phase::PrepareScore => return prepare_score(s, base),
        Phase::StartEncoder => start_encoder(s, base)?,
        Phase::Encode => {
            let (address, bytes) = input_span(s)?;
            let out = unsafe { core::slice::from_raw_parts_mut(address as *mut u8, bytes) };
            if s.encoder.as_mut().ok_or(Error::State)?.step(out)?.done {
                s.phase = Phase::FinishEncoding;
            }
        }
        Phase::FinishEncoding => {
            let (address, bytes) = input_span(s)?;
            let input = unsafe { core::slice::from_raw_parts(address as *const u8, bytes) };
            s.prepared = Some(s.encoder.take().ok_or(Error::State)?.finish(input)?);
            s.phase = Phase::Seal;
        }
        Phase::Seal => {
            s.allocation = Some(
                runtime::seal_learning_input(s.input.as_mut().ok_or(Error::State)?)
                    .map_err(native_error)?,
            );
            s.phase = Phase::Submit;
        }
        Phase::Submit => {
            let submitted = root::submit_score(
                governance(s)?,
                s.prepared.as_ref().ok_or(Error::State)?,
                s.allocation.ok_or(Error::State)?,
            )?;
            if Some(submitted) != key(s) {
                return Err(Error::Evidence);
            }
            s.submitted = true;
            s.phase = Phase::Wait;
        }
        Phase::Wait => match runtime::query_learning(key(s).ok_or(Error::State)?)
            .map_err(native_error)?
        {
            runtime::LearningStatus::Pending | runtime::LearningStatus::Running => {
                return Ok(Turn::Waiting);
            }
            runtime::LearningStatus::Complete { bytes } if bytes == score_wire::RESULT_BYTES => {
                s.phase = Phase::Read
            }
            runtime::LearningStatus::DataIncomplete => return Err(Error::DataIncomplete),
            runtime::LearningStatus::Cancelled => return Err(Error::State),
            _ => return Err(Error::Validation),
        },
        Phase::Read => {
            runtime::read_learning_result(key(s).ok_or(Error::State)?, 0, &mut s.report)
                .map_err(native_error)?;
            s.phase = Phase::Receipt;
        }
        Phase::Receipt => {
            if s.cost.is_none() {
                s.cost = Some(
                    runtime::take_learning_score_receipt(key(s).ok_or(Error::State)?)
                        .map_err(native_error)?,
                );
            }
            s.phase = Phase::Accept;
        }
        Phase::Accept => {
            s.scored = Some(root::accept_score(
                governance(s)?,
                s.prepared.as_mut().ok_or(Error::State)?,
                &s.report,
                s.cost.as_ref().ok_or(Error::State)?,
            )?);
            s.phase = Phase::Consume;
        }
        Phase::Consume => {
            if s.role == Role::Shadow {
                root::record_shadow(governance_mut(s)?, &mut s.scored, &mut s.cost)?;
                s.shadow_seen = true;
                s.family_cursor = (s.family_cursor + 1) % FAMILIES;
            } else {
                match root::publish_canary(governance_mut(s)?, &mut s.scored, &mut s.cost)? {
                    root::CanaryPublication::Published { apply, version } => {
                        s.pending = Some((apply, version));
                        s.last_canary_window =
                            Some((now() - s.permit.ok_or(Error::State)?.start_ns) / WINDOW_NS);
                    }
                    root::CanaryPublication::Rejected(error) => {
                        s.last_error = Some(error);
                        s.requested = Some(error);
                    }
                }
            }
            s.phase = Phase::CloseScore;
        }
        Phase::CloseScore => {
            root::close_score(key(s).ok_or(Error::State)?)?;
            clear_score(s);
            s.phase = Phase::Manage;
        }
        Phase::CleanupScore => return cleanup_score(s),
        Phase::Release => return release(s, base),
    }
    Ok(Turn::Progress)
}

fn clear_score(s: &mut State) {
    s.encoder = None;
    s.prepared = None;
    s.scored = None;
    s.cost = None;
    s.input = None;
    s.allocation = None;
    s.binding = None;
    s.reserved = false;
    s.submitted = false;
    s.set_ready = false;
    s.input_base = 0;
    s.input_bytes = 0;
    s.cancel_sent = false;
}
fn cleanup_score(s: &mut State) -> Result<Turn, Error> {
    s.encoder = None;
    if s.submitted {
        let job = key(s).ok_or(Error::State)?;
        if matches!(
            runtime::query_learning(job).map_err(native_error)?,
            runtime::LearningStatus::Pending | runtime::LearningStatus::Running
        ) {
            if !s.cancel_sent {
                runtime::cancel_learning(job).map_err(native_error)?;
                s.cancel_sent = true;
                return Ok(Turn::Progress);
            }
            return Ok(Turn::Waiting);
        }
    }
    if s.reserved {
        root::close_score(key(s).ok_or(Error::State)?)?;
        s.reserved = false;
    }
    if !s.submitted {
        if let Some(input) = s.input.as_mut() {
            runtime::abandon_learning_input(input).map_err(native_error)?;
        }
    }
    clear_score(s);
    s.phase = if s.governance_ready {
        Phase::Manage
    } else {
        Phase::Release
    };
    Ok(Turn::Progress)
}
fn release(s: &mut State, base: usize) -> Result<Turn, Error> {
    if s.binding.is_some() || s.input.is_some() || s.pending.is_some() {
        return Err(Error::Unknown);
    }
    s.encoder = None;
    s.init = None;
    if s.governance_ready {
        if !matches!(governance(s)?.stage(), Stage::Active | Stage::Rejected) {
            return Err(Error::Unknown);
        }
        // End every borrow before mutating/moving any anchor. The object has
        // no owned allocation; its long-lived model pins are released below.
        unsafe {
            core::ptr::drop_in_place(governance_pointer());
        }
        s.governance_ready = false;
        return Ok(Turn::Progress);
    }
    let p = base as *mut Anchors;
    let active = unsafe { &mut *core::ptr::addr_of_mut!((*p).active) };
    if let Some(pin) = active.as_ref() {
        domain_control::release_job_model(pin).map_err(native_error)?;
        *active = None;
        return Ok(Turn::Progress);
    }
    let delivery = unsafe { &mut *core::ptr::addr_of_mut!((*p).delivery) };
    if let Some(value) = delivery.as_mut() {
        value.release()?;
        *delivery = None;
        return Ok(Turn::Progress);
    }
    s.requested = None;
    s.phase = Phase::Idle;
    Ok(Turn::Progress)
}

/// One bounded step. Retry is distinct from Waiting: the native driver must
/// not apply its idle 100 ms sleep to a prepared score's 50 ms deadline.
#[inline(never)]
pub fn turn() -> Result<Turn, DomainError> {
    runtime::authorize_learning_turn()?;
    let _guard = guard()?;
    let base = BASE.load(Ordering::Acquire);
    if base == 0 {
        return Ok(Turn::Idle);
    }
    if !READY.load(Ordering::Acquire) {
        initialize_metadata(base);
        return Ok(Turn::Progress);
    }
    let s = unsafe { &mut *state_pointer(base) };
    if s.requested.is_some() && s.encoder.is_some() {
        s.encoder = None;
        s.phase = Phase::CleanupScore;
    }
    let result = maintenance(s).and_then(|_| {
        if s.governance_ready
            && matches!(
                governance(s)?.stage(),
                Stage::Frozen | Stage::Restoring | Stage::Rejected
            )
            && (s.binding.is_some() || s.input.is_some())
        {
            // Revocation stops a score which has no execution authority, but
            // cancellation does not make an unknown EL0 context reusable.
            s.encoder = None;
            s.phase = Phase::CleanupScore;
        } else if !s.governance_ready && s.requested.is_some() {
            s.phase = Phase::Release;
        }
        step(s, base)
    });
    match result {
        Ok(progress) => {
            if progress == Turn::Progress {
                s.steps = s.steps.checked_add(1).ok_or(DomainError::Overflow)?;
            }
            Ok(progress)
        }
        Err(Error::Unknown) => Ok(Turn::Retry),
        Err(error) => {
            s.last_error = Some(error);
            s.requested.get_or_insert(error);
            if !matches!(s.phase, Phase::CleanupScore | Phase::Release) {
                s.rejected = s.rejected.checked_add(1).ok_or(DomainError::Overflow)?;
                s.encoder = None;
                s.phase = if s.binding.is_some() || s.input.is_some() {
                    Phase::CleanupScore
                } else if s.governance_ready {
                    Phase::Manage
                } else {
                    Phase::Release
                };
            }
            Ok(Turn::Retry)
        }
    }
}

pub fn status() -> Result<Status, DomainError> {
    let _guard = guard()?;
    let base = BASE.load(Ordering::Acquire);
    if base == 0 || !READY.load(Ordering::Acquire) {
        return Err(DomainError::NotReady);
    }
    let s = unsafe { &*state_pointer(base) };
    Ok(Status {
        phase: s.phase,
        stage: governance(s).ok().map(Governance::stage),
        job: key(s),
        pending: s.pending,
        binding: anchors(base).delivery.as_ref().map(|d| d.binding),
        completed: s.completed,
        rejected: s.rejected,
        steps: s.steps,
        last_error: s.last_error,
    })
}
pub fn request_abort(reason: Error) -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    let _guard = guard()?;
    let base = BASE.load(Ordering::Acquire);
    if base == 0 || !READY.load(Ordering::Acquire) {
        return Err(DomainError::NotReady);
    }
    let s = unsafe { &mut *state_pointer(base) };
    s.requested.get_or_insert(reason);
    Ok(())
}

/// Measurements remain real protected-owner inputs. The root independently
/// authenticates exact frozen requests and baseline; no callback or sample is
/// synthesized when this ingress is absent. Caller retains its real pinned
/// workspace and pays this call through the same native extra credit.
pub fn observe_second(
    second: u16,
    baseline: &[WorkRequest],
    candidate: &[WorkRequest],
    workspace: &mut RewardWorkspace,
) -> Result<(), Error> {
    runtime::authorize_learning_turn().map_err(native_error)?;
    let _guard = guard().map_err(native_error)?;
    let base = BASE.load(Ordering::Acquire);
    if base == 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::DataIncomplete);
    }
    let s = unsafe { &mut *state_pointer(base) };
    let permit = s.permit.ok_or(Error::State)?;
    let closed = permit
        .start_ns
        .checked_add(
            u64::from(second)
                .checked_add(1)
                .ok_or(Error::Numeric)?
                .checked_mul(1_000_000_000)
                .ok_or(Error::Numeric)?,
        )
        .ok_or(Error::Numeric)?;
    if now() < closed || closed > permit.expires_ns {
        return Err(Error::Deadline);
    }
    root::observe_second(governance_mut(s)?, second, baseline, candidate, workspace)
}
pub fn observe_second_bounded(
    second: u16,
    baseline: &[WorkRequest],
    candidate: &[WorkRequest],
    latencies: &mut [u64],
) -> Result<(), Error> {
    runtime::authorize_learning_turn().map_err(native_error)?;
    let _guard = guard().map_err(native_error)?;
    let base = BASE.load(Ordering::Acquire);
    if base == 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::DataIncomplete);
    }
    let s = unsafe { &mut *state_pointer(base) };
    let permit = s.permit.ok_or(Error::State)?;
    let closed = permit
        .start_ns
        .checked_add(
            u64::from(second)
                .checked_add(1)
                .ok_or(Error::Numeric)?
                .checked_mul(1_000_000_000)
                .ok_or(Error::Numeric)?,
        )
        .ok_or(Error::Numeric)?;
    if now() < closed || closed > permit.expires_ns {
        return Err(Error::Deadline);
    }
    root::observe_second_bounded(governance_mut(s)?, second, baseline, candidate, latencies)
}
pub fn extend(windows: u16) -> Result<(), Error> {
    runtime::authorize_learning_turn().map_err(native_error)?;
    let _guard = guard().map_err(native_error)?;
    let base = BASE.load(Ordering::Acquire);
    if base == 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::DataIncomplete);
    }
    let s = unsafe { &mut *state_pointer(base) };
    root::extend(governance_mut(s)?, windows)?;
    // Root retains the exact new permit; the normal next prepare fetches it.
    // The original local interval remains valid for already-published work.
    if let Some(permit) = s.permit.as_mut() {
        permit.expires_ns = permit
            .start_ns
            .checked_add(u64::from(windows) * WINDOW_NS)
            .ok_or(Error::Numeric)?;
        permit.windows = windows;
        permit.quota = windows;
        crate::learning_canary::changed_permit(*permit)?;
    }
    Ok(())
}

/// Called with a real CPU0 service credit when extra execution is unavailable.
/// It never scores, publishes a candidate, acknowledges an input, or releases
/// any model/worker pin. Even an unknown stopped role keeps its exact custody.
pub fn safety_turn() -> Result<Turn, DomainError> {
    crate::domain_tasks::authorize_service_turn()?;
    let _guard = guard()?;
    let base = BASE.load(Ordering::Acquire);
    if base == 0 || !READY.load(Ordering::Acquire) {
        return Ok(Turn::Idle);
    }
    let s = unsafe { &mut *state_pointer(base) };
    if !s.governance_ready {
        return Ok(Turn::Idle);
    }
    if s.encoder.is_some() {
        let score_expired = s.set_ready && {
            let set = unsafe { &*((base + SET_OFFSET) as *const CandidateSet) };
            now().saturating_sub(set.snapshot.taken_ns) > 50_000_000
        };
        let permit_expired = s.permit.is_some_and(|p| now() >= p.expires_ns);
        if s.requested.is_none() && !score_expired && !permit_expired {
            return Ok(Turn::Waiting);
        }
        if score_expired || permit_expired {
            s.requested.get_or_insert(Error::Deadline);
        }
        // This is an EL1 preparation, not a running numerical context. The
        // gate proves its owner is not accessing the input now. End only the
        // encoder borrow; keep the exact input/model loans for C1 cleanup.
        s.encoder = None;
        s.phase = Phase::CleanupScore;
    }
    let result = (|| {
        let gov = governance_mut(s)?;
        root::safety_tick(gov)?;
        if let Some((apply, version)) = s.pending {
            if root::safety_reconcile(gov, apply, version)?.terminal() {
                s.pending = None;
            }
        }
        if let Some(reason) = s.requested {
            if gov.stage() != Stage::Active {
                root::safety_abort(gov, reason)?;
                s.requested = None;
            }
        }
        if gov.stage() == Stage::Restoring && s.pending.is_none() {
            root::safety_restore(gov)?;
        }
        Ok::<(), Error>(())
    })();
    match result {
        Ok(()) => Ok(Turn::Progress),
        Err(Error::Unknown) => Ok(Turn::Retry),
        Err(e) => {
            s.last_error = Some(e);
            Ok(Turn::Retry)
        }
    }
}

#[cfg(test)]
pub mod test_support {
    pub fn with_gate<R>(f: impl FnOnce() -> R) -> R {
        let _guard = super::guard().expect("test acquires the real session gate");
        f()
    }
    pub fn sizes() -> [usize; 4] {
        [
            core::mem::size_of::<super::Anchors>(),
            core::mem::size_of::<super::CandidateSet>(),
            core::mem::size_of::<super::State>(),
            core::mem::size_of::<super::NativeGovernance>(),
        ]
    }
}
