//! Real ordinary warmup CPU custody before a one-shot policy exists. Only the
//! registered member, paid control worker and CPU0 owner can record. The original core and
//! timestamps survive authenticated import and durable raw-trace export.
use crate::{control_pool as pool, learning_evidence as evidence};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    learning::{self, Family, capture::RunKey, reward::CpuClass},
};
#[path = "learning_prewarm/diagnostic.rs"]
mod diagnostic;
pub const DIAGNOSTIC_BYTES: usize = diagnostic::BYTES;
#[cfg(test)]
pub fn first_failure_snapshot() -> [u64; 32] {
    diagnostic::LEARNING_PREWARM_FIRST_FAILURE.snapshot()
}
pub const PROGRESS_BYTES: usize = 4 * core::mem::size_of::<AtomicU64>();
static READY_FIRST: AtomicU64 = AtomicU64::new(0);
static READY_RECENT: AtomicU64 = AtomicU64::new(0);
static READY_EARLIEST: AtomicU64 = AtomicU64::new(0);
static READY_REASON: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy)]
pub struct ProgressStatus {
    pub session: u64,
    pub active: bool,
    pub open: u64,
    pub lost: bool,
    pub completed_before: u64,
    pub completed_after: u64,
    pub latest: u64,
    pub started: u64,
    pub first: u64,
    pub times: [u64; 16],
    pub heads: [u64; 4],
    pub tails: [u64; 4],
    pub ready_first: u64,
    pub ready_recent: u64,
    pub ready_earliest: u64,
    pub ready_reason: u64,
}
pub fn admission_observation() -> (bool, u64, u64) {
    (
        ACTIVE.load(Ordering::Acquire),
        OPEN.load(Ordering::Acquire) as u64,
        SESSION.load(Ordering::Acquire),
    )
}
/// Bounded diagnostic observation. Counts and slots can be in flight; no
/// snapshot or equality flag authorizes an interval, first timestamp or label.
pub fn progress_status() -> ProgressStatus {
    let before = COMPLETED.load(Ordering::Acquire);
    let times = core::array::from_fn(|i| COMPLETION_TIMES[i].load(Ordering::Acquire));
    ProgressStatus {
        session: SESSION.load(Ordering::Acquire),
        active: ACTIVE.load(Ordering::Acquire),
        open: OPEN.load(Ordering::Acquire) as u64,
        lost: LOST.load(Ordering::Acquire),
        completed_before: before,
        completed_after: COMPLETED.load(Ordering::Acquire),
        latest: LAST_COMPLETED.load(Ordering::Acquire),
        started: STARTED.load(Ordering::Acquire),
        first: FIRST.load(Ordering::Acquire),
        times,
        heads: core::array::from_fn(|i| HEAD[i].load(Ordering::Acquire) as u64),
        tails: core::array::from_fn(|i| TAIL[i].load(Ordering::Acquire) as u64),
        ready_first: READY_FIRST.load(Ordering::Acquire),
        ready_recent: READY_RECENT.load(Ordering::Acquire),
        ready_earliest: READY_EARLIEST.load(Ordering::Acquire),
        ready_reason: READY_REASON.load(Ordering::Acquire),
    }
}
/// Paid CPU0 continuation of an uncommitted CoreSet freeze. No FIRST or
/// scope exists here; a real frozen session can never reopen through this API.
pub(crate) fn resume_unfrozen_control() -> Result<bool, Error> {
    cpu0()?;
    let _guard = lock()?;
    let setup = unsafe { &*SETUP.0.get() };
    if setup
        .preparation
        .is_none_or(|p| (p.family.domain, p.family.kind) != (1, 2))
        || setup.aborted_ns != 0
        || !control_family()
        || SESSION.load(Ordering::Acquire) == 0
        || FIRST.load(Ordering::Acquire) != 0
        || LOST.load(Ordering::Acquire)
        || OPEN.load(Ordering::SeqCst) != 0
        || ACTIVE.load(Ordering::SeqCst)
    {
        return Ok(false);
    }
    ACTIVE.store(true, Ordering::SeqCst);
    Ok(true)
}
/// Nonfreezing observation under the same warm owner gate and exact existing
/// readiness predicate. It cannot create FIRST, close ACTIVE or consume work.
pub fn ready_for_core_first(first_ns: u64) -> Result<bool, Error> {
    let _guard = lock()?;
    if !control_family()
        || SESSION.load(Ordering::Acquire) == 0
        || first_ns < SECOND
        || first_ns > now()
    {
        return Ok(false);
    }
    if LOST.load(Ordering::Acquire) {
        return Err(Error::Capacity);
    }
    Ok(readiness_met(first_ns))
}
fn readiness_met(first_ns: u64) -> bool {
    let completed = COMPLETED.load(Ordering::Acquire);
    let latest = LAST_COMPLETED.load(Ordering::Acquire);
    let (mut recent, mut earliest) = (0, u64::MAX);
    for entry in &COMPLETION_TIMES {
        let at = entry.load(Ordering::Acquire);
        if at != 0 && at >= first_ns - SECOND && at <= first_ns {
            recent += 1;
            earliest = earliest.min(at);
        }
    }
    let mut reason = 0;
    if first_ns.saturating_sub(STARTED.load(Ordering::Acquire)) < SECOND {
        reason |= 1;
    }
    if completed < 10 {
        reason |= 2;
    }
    if latest > first_ns {
        reason |= 4;
    }
    if first_ns.saturating_sub(latest) > 200_000_000 {
        reason |= 8;
    }
    if recent < 10 {
        reason |= 16;
    }
    if latest.saturating_sub(earliest) < 800_000_000 {
        reason |= 32;
    }
    READY_FIRST.store(first_ns, Ordering::Relaxed);
    READY_RECENT.store(recent, Ordering::Relaxed);
    READY_EARLIEST.store(earliest, Ordering::Relaxed);
    READY_REASON.store(reason, Ordering::Release);
    reason == 0
}
const OWNER: ObjectKey = ObjectKey {
    id: 0x5052_4557_4152_4d,
    generation: 1,
};
const CORES: usize = 4;
// Every actual C slice remains separate, including setup/verification/cleanup.
// Two control workers need room for eight numerical slices per evaluation;
// the CPU0/CPU3 echo owners retain their original bounded capacities.
const ROWS: [usize; CORES] = [128, 256, 256, 128];
const OFFSET: [usize; CORES] = [0, 128, 384, 640];
pub const MAX_ROWS: usize = 768;
pub const OWNED_BYTES: usize = MAX_ROWS * core::mem::size_of::<Row>();
const SECOND: u64 = 1_000_000_000;
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Row {
    event: u64,
    session: u64,
    first: u64,
    last: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawRow {
    pub owner: ObjectKey,
    pub core: u16,
    pub event: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}
struct Setup {
    allocation: Option<pool::Allocation>,
    pin: Option<pool::Lease>,
    preparation: Option<crate::domain_control::replay::Preparation>,
    aborted_ns: u64,
}
struct Cell(UnsafeCell<Setup>);
unsafe impl Sync for Cell {}
static SETUP: Cell = Cell(UnsafeCell::new(Setup {
    allocation: None,
    pin: None,
    preparation: None,
    aborted_ns: 0,
}));
static GATE: AtomicBool = AtomicBool::new(false);
static BASE: AtomicUsize = AtomicUsize::new(0);
static INITIALIZED: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static OPEN: AtomicUsize = AtomicUsize::new(0);
static SESSION: AtomicU64 = AtomicU64::new(0);
static SERIAL: AtomicU64 = AtomicU64::new(0);
static EVENT: AtomicU64 = AtomicU64::new(0);
static FAMILY: AtomicU64 = AtomicU64::new(0);
static MEMBER_ID: AtomicU64 = AtomicU64::new(0);
static MEMBER_GENERATION: AtomicU64 = AtomicU64::new(0);
static STARTED: AtomicU64 = AtomicU64::new(0);
static COMPLETED: AtomicU64 = AtomicU64::new(0);
static LAST_COMPLETED: AtomicU64 = AtomicU64::new(0);
static COMPLETION_TIMES: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static FIRST: AtomicU64 = AtomicU64::new(0);
static LOST: AtomicBool = AtomicBool::new(false);
static HEAD: [AtomicUsize; CORES] = [const { AtomicUsize::new(0) }; CORES];
static TAIL: [AtomicUsize; CORES] = [const { AtomicUsize::new(0) }; CORES];
static FROZEN_TAIL: [AtomicUsize; CORES] = [const { AtomicUsize::new(0) }; CORES];
static BOOT: AtomicU64 = AtomicU64::new(0);
static TRIAL: AtomicU64 = AtomicU64::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn lock() -> Result<Guard, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    Ok(Guard)
}
fn now() -> u64 {
    crate::domain_platform::now_ns()
}
fn cpu0() -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    crate::domain_tasks::authorize_service_turn()
}
fn source(bank: usize) -> ObjectKey {
    match bank {
        0 => crate::learning_workload::OWNER,
        1 | 2 => crate::domain_control::core_replay::CORE_OWNER,
        3 => crate::learning_workload::TASK_OWNER,
        _ => unreachable!(),
    }
}
fn control_family() -> bool {
    FAMILY.load(Ordering::Acquire) == ((1 << 16) | 2)
}
fn run() -> RunKey {
    RunKey {
        boot_epoch: BOOT.load(Ordering::Acquire),
        trial_id: TRIAL.load(Ordering::Acquire),
        generation: GENERATION.load(Ordering::Acquire),
    }
}
fn row(bank: usize, at: usize) -> *mut Row {
    (BASE.load(Ordering::Acquire) as *mut Row).wrapping_add(OFFSET[bank] + at % ROWS[bank])
}
fn next(value: &AtomicU64) -> Result<u64, Error> {
    value
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .map(|old| old + 1)
        .map_err(|_| Error::Overflow)
}
fn capture_error(error: evidence::Error) -> Error {
    match error {
        evidence::Error::Busy | evidence::Error::NotReady => Error::Busy,
        evidence::Error::Stale => Error::Stale,
        evidence::Error::Capacity => Error::Capacity,
        _ => Error::Conflict,
    }
}
/// Each retry initializes at most one page under the real service credit.
pub fn init() -> Result<(), Error> {
    cpu0()?;
    let _guard = lock()?;
    if BASE.load(Ordering::Acquire) == 0 {
        let setup = unsafe { &mut *SETUP.0.get() };
        if setup.allocation.is_none() {
            setup.allocation = Some(pool::allocate(OWNER, OWNED_BYTES.div_ceil(4096))?);
        }
        let allocation = setup.allocation.ok_or(Error::NotReady)?;
        if setup.pin.is_none() {
            setup.pin = Some(pool::pin(allocation)?);
        }
        let (base, _, bytes) = pool::span(allocation)?;
        if bytes < OWNED_BYTES || !base.is_multiple_of(core::mem::align_of::<Row>()) {
            return Err(Error::Range);
        }
        BASE.store(base, Ordering::Release);
    }
    let first = INITIALIZED.load(Ordering::Acquire);
    if first < OWNED_BYTES {
        let end = (first + 4096).min(OWNED_BYTES);
        unsafe {
            core::ptr::write_bytes(
                (BASE.load(Ordering::Acquire) + first) as *mut u8,
                0,
                end - first,
            );
        }
        INITIALIZED.store(end, Ordering::Release);
        if end < OWNED_BYTES {
            return Err(Error::Again);
        }
    }
    for owner in [source(0), source(1), source(3)] {
        evidence::register_recorded_core_owner(owner, attest).map_err(capture_error)?;
    }
    Ok(())
}
pub fn begin(family: Family, member: ObjectKey) -> Result<(), Error> {
    init()?;
    let _guard = lock()?;
    let setup = unsafe { &mut *SETUP.0.get() };
    if setup.preparation.is_none_or(|p| p.family != family) || setup.aborted_ns != 0 {
        return Err(Error::Auth);
    }
    if !matches!((family.domain, family.kind), (1, 2) | (14, 1) | (16, 2))
        || member.id == 0
        || member.generation == 0
        || (family.domain, family.kind) == (1, 2)
            && member != crate::domain_control::core_replay::CORE_OWNER
    {
        return Err(Error::Auth);
    }
    let packed = (u64::from(family.domain) << 16) | u64::from(family.kind);
    if SESSION.load(Ordering::Acquire) != 0 {
        return if FAMILY.load(Ordering::Acquire) == packed
            && MEMBER_ID.load(Ordering::Acquire) == member.id
            && MEMBER_GENERATION.load(Ordering::Acquire) == member.generation
        {
            Ok(())
        } else {
            Err(Error::Busy)
        };
    }
    if OPEN.load(Ordering::SeqCst) != 0 {
        return Err(Error::Busy);
    }
    let serial = next(&SERIAL)?;
    FAMILY.store(packed, Ordering::Relaxed);
    MEMBER_ID.store(member.id, Ordering::Relaxed);
    MEMBER_GENERATION.store(member.generation, Ordering::Relaxed);
    for bank in 0..CORES {
        HEAD[bank].store(0, Ordering::Relaxed);
        TAIL[bank].store(0, Ordering::Relaxed);
        FROZEN_TAIL[bank].store(0, Ordering::Relaxed);
    }
    STARTED.store(now(), Ordering::Relaxed);
    COMPLETED.store(0, Ordering::Relaxed);
    LAST_COMPLETED.store(0, Ordering::Relaxed);
    for at in &COMPLETION_TIMES {
        at.store(0, Ordering::Relaxed);
    }
    FIRST.store(0, Ordering::Relaxed);
    LOST.store(false, Ordering::Relaxed);
    GENERATION.store(0, Ordering::Relaxed);
    SESSION.store(serial, Ordering::Release);
    ACTIVE.store(true, Ordering::SeqCst);
    Ok(())
}
pub fn active() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}
pub struct Attempt {
    session: u64,
    bank: usize,
    earliest_ns: u64,
    pending: bool,
    task: Option<ObjectKey>,
    finish_attempted: bool,
}
struct FailureOperands {
    first: u64,
    last: u64,
    clock: u64,
    current_session: u64,
    ring: Option<(usize, usize, u64, u64)>,
    flags: u64,
    observed_cpu: Option<usize>,
}
impl FailureOperands {
    fn empty() -> Self {
        Self {
            first: 0,
            last: 0,
            clock: 0,
            current_session: 0,
            ring: None,
            flags: 0,
            observed_cpu: None,
        }
    }
}
/// Read-only snapshot only on a failure path. Original predicate operands are
/// passed through; no extra clock reads or predicate/LOST changes occur here.
fn first_failure(
    site: u64,
    error: Option<Error>,
    attempt: Option<&Attempt>,
    facts: FailureOperands,
) {
    let bank = attempt.map_or(usize::MAX, |a| a.bank);
    let (head, tail, old_last, cutoff) = facts.ring.unwrap_or_else(|| {
        if bank < CORES {
            (
                HEAD[bank].load(Ordering::Acquire),
                TAIL[bank].load(Ordering::Acquire),
                0,
                0,
            )
        } else {
            (0, 0, 0, 0)
        }
    });
    let mut words = [0; 32];
    words[1] = diagnostic::MAGIC;
    words[2] = 1;
    words[3] = site;
    words[4] = error.map_or(0, |e| e as u64 + 1);
    words[5] = bank as u64;
    words[6] = facts
        .observed_cpu
        .unwrap_or_else(cyxia_arch_aarch64::cpu::slot) as u64;
    words[7] = attempt.map_or(0, |a| a.session);
    words[8] = facts.current_session;
    words[9] = facts.first;
    words[10] = facts.last;
    words[11] = attempt.map_or(0, |a| a.earliest_ns);
    words[12] = facts.clock;
    words[13] = head as u64;
    words[14] = tail as u64;
    words[15] = if bank < CORES { ROWS[bank] as u64 } else { 0 };
    words[16] = old_last;
    words[17] = cutoff;
    words[18] = OPEN.load(Ordering::SeqCst) as u64;
    words[19] = u64::from(ACTIVE.load(Ordering::SeqCst));
    words[20] = u64::from(LOST.load(Ordering::Acquire));
    words[21] = COMPLETED.load(Ordering::Acquire);
    words[22] = LAST_COMPLETED.load(Ordering::Acquire);
    words[23] = FIRST.load(Ordering::Acquire);
    words[24] = STARTED.load(Ordering::Acquire);
    words[25] = u64::from(attempt.is_some_and(|a| a.finish_attempted));
    words[26] = facts.flags;
    words[27] = BOOT.load(Ordering::Acquire);
    words[28] = TRIAL.load(Ordering::Acquire);
    words[29] = GENERATION.load(Ordering::Acquire);
    diagnostic::LEARNING_PREWARM_FIRST_FAILURE.record(&words);
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.pending {
            LOST.store(true, Ordering::Release);
            first_failure(
                1,
                None,
                Some(self),
                FailureOperands {
                    current_session: SESSION.load(Ordering::Acquire),
                    flags: 8,
                    ..FailureOperands::empty()
                },
            );
            OPEN.fetch_sub(1, Ordering::SeqCst);
            self.pending = false;
        }
    }
}
fn attempt(bank: usize) -> Option<Attempt> {
    OPEN.fetch_add(1, Ordering::SeqCst);
    if !ACTIVE.load(Ordering::SeqCst) {
        OPEN.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    let session = SESSION.load(Ordering::Acquire);
    if session == 0 {
        OPEN.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    Some(Attempt {
        session,
        bank,
        earliest_ns: 0,
        pending: true,
        task: None,
        finish_attempted: false,
    })
}
pub fn attempt_task(member: ObjectKey) -> Option<Attempt> {
    if cyxia_arch_aarch64::cpu::slot() != 3
        || control_family()
        || member.id != MEMBER_ID.load(Ordering::Acquire)
        || member.generation != MEMBER_GENERATION.load(Ordering::Acquire)
    {
        return None;
    }
    let mut token = attempt(3)?;
    token.task = Some(member);
    Some(token)
}
/// Only a real still-live C1/C2 reservation can open an ordinary evaluation
/// interval. Its actual original CPU remains in the protected raw ring.
pub fn attempt_control(
    witness: &crate::domain_control::core_replay::PaidWorkWitness,
) -> Option<Attempt> {
    let core = usize::from(witness.core());
    if !control_family()
        || !matches!(core, 1 | 2)
        || cyxia_arch_aarch64::cpu::slot() != core
        || witness.credit().cpu != witness.core()
    {
        return None;
    }
    let mut attempt = attempt(core)?;
    attempt.earliest_ns = witness.credit().started_ns;
    Some(attempt)
}
pub fn attempt_service() -> Option<Attempt> {
    if cpu0().is_err() {
        return None;
    }
    attempt(0)
}
/// The task gate already authenticated this non-constructible paid witness.
/// Reentering its service-authority lock here would discard real staging CPU.
pub fn attempt_paid_service(_: &crate::domain_tasks::PaidServiceWitness) -> Option<Attempt> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return None;
    }
    attempt(0)
}
pub(crate) fn cancel_unstarted(
    attempt: &mut Attempt,
    proof: &crate::domain_tasks::Cancellation,
) -> Result<(), Error> {
    if !attempt.pending
        || attempt.session != SESSION.load(Ordering::Acquire)
        || attempt.finish_attempted
        || attempt
            .task
            .is_none_or(|owner| !proof.matches(owner, attempt.bank as u16))
    {
        return Err(Error::Auth);
    }
    attempt.pending = false;
    OPEN.fetch_sub(1, Ordering::SeqCst);
    Ok(())
}
pub fn finish(attempt: &mut Attempt, first_ns: u64, last_ns: u64) -> Result<(), Error> {
    attempt.finish_attempted = true;
    let core = cyxia_arch_aarch64::cpu::slot();
    let mut current_session = 0;
    let mut session_observed = false;
    let mut observed_clock = 0;
    let mut clock_observed = false;
    if !attempt.pending
        || {
            current_session = SESSION.load(Ordering::Acquire);
            session_observed = true;
            attempt.session != current_session
        }
        || core != attempt.bank
        || first_ns < attempt.earliest_ns
        || first_ns > last_ns
        || {
            observed_clock = now();
            clock_observed = true;
            last_ns > observed_clock
        }
    {
        first_failure(
            2,
            Some(Error::Auth),
            Some(attempt),
            FailureOperands {
                first: first_ns,
                last: last_ns,
                clock: observed_clock,
                current_session,
                ring: None,
                flags: u64::from(clock_observed) | (u64::from(session_observed) << 3),
                observed_cpu: Some(core),
            },
        );
        return Err(Error::Auth);
    }
    let bank = attempt.bank;
    let head = HEAD[bank].load(Ordering::Relaxed);
    let mut tail = TAIL[bank].load(Ordering::Acquire);
    while head.saturating_sub(tail) >= ROWS[bank] {
        let old = unsafe { *row(bank, tail) };
        if old.last >= last_ns.saturating_sub(SECOND) {
            LOST.store(true, Ordering::Release);
            first_failure(
                3,
                Some(Error::Capacity),
                Some(attempt),
                FailureOperands {
                    first: first_ns,
                    last: last_ns,
                    clock: observed_clock,
                    current_session,
                    ring: Some((head, tail, old.last, last_ns.saturating_sub(SECOND))),
                    flags: 15,
                    observed_cpu: Some(core),
                },
            );
            return Err(Error::Capacity);
        }
        tail += 1;
        TAIL[bank].store(tail, Ordering::Release);
    }
    let next_head = head.checked_add(1).ok_or(Error::Overflow)?;
    let event = next(&EVENT)?;
    unsafe {
        row(bank, head).write(Row {
            event,
            session: attempt.session,
            first: first_ns,
            last: last_ns,
        });
    }
    HEAD[bank].store(next_head, Ordering::Release);
    attempt.pending = false;
    OPEN.fetch_sub(1, Ordering::SeqCst);
    Ok(())
}
/// Call only after the actual echo owner checked its immutable payload.
pub fn completed() -> Result<(), Error> {
    cpu0()?;
    if control_family() {
        return Err(Error::Auth);
    }
    completed_at()
}
/// The C worker calls this only after independent EL0 evaluation and root
/// verification completed, while the exact reservation is still live.
pub fn completed_control(
    witness: &crate::domain_control::core_replay::PaidWorkWitness,
) -> Result<(), Error> {
    if !control_family()
        || cyxia_arch_aarch64::cpu::slot() != usize::from(witness.core())
        || !matches!(witness.core(), 1 | 2)
    {
        return Err(Error::Auth);
    }
    crate::domain_tasks::verify_control_credit(witness.credit())?;
    completed_at()
}
fn completed_at() -> Result<(), Error> {
    if !active() {
        return Err(Error::Busy);
    }
    let n = next(&COMPLETED)?;
    let at = now();
    COMPLETION_TIMES[(n as usize - 1) % 16].store(at, Ordering::Release);
    LAST_COMPLETED.fetch_max(at, Ordering::AcqRel);
    Ok(())
}
/// The root's registered readiness callback stops new admission before first.
/// The original in-flight credits must return; elapsed time cannot settle them.
pub fn freeze(first_ns: u64) -> Result<(), Error> {
    let _guard = lock()?;
    let current_session = SESSION.load(Ordering::Acquire);
    if current_session == 0 {
        return Err(Error::NotReady);
    }
    let observed_clock = now();
    if first_ns > observed_clock || first_ns < SECOND {
        return Err(Error::NotReady);
    }
    let old = FIRST.load(Ordering::Acquire);
    if old != 0 {
        return if old == first_ns {
            Ok(())
        } else {
            Err(Error::Stale)
        };
    }
    if LOST.load(Ordering::Acquire) {
        first_failure(
            4,
            Some(Error::Capacity),
            None,
            FailureOperands {
                first: first_ns,
                clock: observed_clock,
                current_session,
                flags: 9,
                ..FailureOperands::empty()
            },
        );
        return Err(Error::Capacity);
    }
    if !readiness_met(first_ns) {
        // A paid credit that took too long to return may leave the old warm
        // window stale. Reopen ordinary preparation only after that credit
        // really returned; no policy/capture has been issued at this point.
        if !ACTIVE.load(Ordering::SeqCst) && OPEN.load(Ordering::SeqCst) == 0 {
            ACTIVE.store(true, Ordering::SeqCst);
        }
        return Err(Error::Again);
    }
    ACTIVE.store(false, Ordering::SeqCst);
    if OPEN.load(Ordering::SeqCst) != 0 {
        READY_REASON.store(64, Ordering::Release);
        return Err(Error::Busy);
    }
    let mut present = 0u64;
    for bank in 0..CORES {
        let mut tail = TAIL[bank].load(Ordering::Acquire);
        let head = HEAD[bank].load(Ordering::Acquire);
        while tail < head && unsafe { (*row(bank, tail)).last } <= first_ns - SECOND {
            tail += 1;
        }
        if tail != head {
            present |= 1u64 << bank;
        }
        TAIL[bank].store(tail, Ordering::Release);
        FROZEN_TAIL[bank].store(tail, Ordering::Release);
    }
    // CoreSet warms actual control evaluations on whichever healthy C worker
    // ran them. Recovery/Placement warm actual business work on CPU3 instead.
    let ready = present & 1 != 0
        && if control_family() {
            present & 6 != 0
        } else {
            present & 8 != 0
        };
    if !ready {
        READY_REASON.store(128, Ordering::Release);
        ACTIVE.store(true, Ordering::SeqCst);
        return Err(Error::NotReady);
    }
    FIRST.store(first_ns, Ordering::Release);
    Ok(())
}
pub fn activate(key: RunKey, first_ns: u64) -> Result<(), Error> {
    let _guard = lock()?;
    if FIRST.load(Ordering::Acquire) != first_ns
        || ACTIVE.load(Ordering::SeqCst)
        || OPEN.load(Ordering::SeqCst) != 0
        || key.boot_epoch == 0
        || key.trial_id == 0
        || key.generation == 0
    {
        return Err(Error::Auth);
    }
    if GENERATION.load(Ordering::Acquire) != 0 {
        return if run() == key {
            Ok(())
        } else {
            Err(Error::Stale)
        };
    }
    BOOT.store(key.boot_epoch, Ordering::Relaxed);
    TRIAL.store(key.trial_id, Ordering::Relaxed);
    GENERATION.store(key.generation, Ordering::Release);
    Ok(())
}
fn raw(bank: usize, at: usize) -> RawRow {
    let r = unsafe { *row(bank, at) };
    RawRow {
        owner: source(bank),
        core: bank as u16,
        event: r.event,
        first_ns: r
            .first
            .max(FIRST.load(Ordering::Acquire).saturating_sub(SECOND)),
        last_ns: r.last,
    }
}
fn attest(
    key: RunKey,
    owner: ObjectKey,
    event: u64,
    core: u16,
    first: u64,
    last: u64,
) -> Result<(), learning::Error> {
    if key != run() || ACTIVE.load(Ordering::SeqCst) || LOST.load(Ordering::Acquire) {
        return Err(learning::Error::Evidence);
    }
    let bank = usize::from(core);
    if bank >= CORES || owner != source(bank) {
        return Err(learning::Error::Evidence);
    }
    let tail = TAIL[bank].load(Ordering::Acquire);
    if tail >= HEAD[bank].load(Ordering::Acquire) {
        return Err(learning::Error::Stale);
    }
    let expected = raw(bank, tail);
    if expected.event != event
        || expected.first_ns != first
        || expected.last_ns != last
        || unsafe { (*row(bank, tail)).session } != SESSION.load(Ordering::Acquire)
    {
        return Err(learning::Error::Evidence);
    }
    Ok(())
}
pub fn poll(key: RunKey) -> Result<bool, Error> {
    cpu0()?;
    if key != run() {
        return Err(Error::Stale);
    }
    if LOST.load(Ordering::Acquire) {
        return Err(Error::Capacity);
    }
    for _ in 0..8 {
        // One CORE_OWNER spans two real CPUs. Merge retained events in their
        // actual monotonically assigned order, rather than importing one CPU
        // completely and presenting an older event from the other afterward.
        let Some(bank) = (0..CORES)
            .filter(|&b| TAIL[b].load(Ordering::Acquire) < HEAD[b].load(Ordering::Acquire))
            .min_by_key(|&b| unsafe { (*row(b, TAIL[b].load(Ordering::Acquire))).event })
        else {
            return Ok(true);
        };
        let tail = TAIL[bank].load(Ordering::Acquire);
        let r = raw(bank, tail);
        evidence::record_on_core(
            key,
            r.owner,
            CpuClass::ExecutorWork,
            r.event,
            r.core,
            r.first_ns,
            r.last_ns,
        )
        .map_err(capture_error)?;
        TAIL[bank].store(tail + 1, Ordering::Release);
    }
    drain(key)
}
pub fn drain(key: RunKey) -> Result<bool, Error> {
    if key != run() {
        return Err(Error::Stale);
    }
    if LOST.load(Ordering::Acquire) {
        return Err(Error::Capacity);
    }
    Ok(!ACTIVE.load(Ordering::SeqCst)
        && OPEN.load(Ordering::SeqCst) == 0
        && (0..CORES).all(|b| TAIL[b].load(Ordering::Acquire) == HEAD[b].load(Ordering::Acquire)))
}
pub fn row_count(key: RunKey) -> Result<usize, Error> {
    if SESSION.load(Ordering::Acquire) == 0 {
        return Ok(0);
    }
    if key != run() {
        return Err(Error::Stale);
    }
    Ok((0..CORES)
        .map(|b| HEAD[b].load(Ordering::Acquire) - FROZEN_TAIL[b].load(Ordering::Acquire))
        .sum())
}
pub fn copy_rows(key: RunKey, offset: usize, out: &mut [RawRow]) -> Result<usize, Error> {
    if out.len() > 16 || offset > row_count(key)? {
        return Err(Error::Range);
    }
    let mut written = 0;
    let mut skip = offset;
    for bank in 0..CORES {
        for at in FROZEN_TAIL[bank].load(Ordering::Acquire)..HEAD[bank].load(Ordering::Acquire) {
            if skip != 0 {
                skip -= 1;
                continue;
            }
            if written == out.len() {
                return Ok(written);
            }
            out[written] = raw(bank, at);
            written += 1;
        }
    }
    Ok(written)
}
pub fn release(key: RunKey) -> Result<(), Error> {
    cpu0()?;
    let _guard = lock()?;
    if !drain(key)? {
        return Err(Error::Busy);
    }
    SESSION.store(0, Ordering::Release);
    GENERATION.store(0, Ordering::Release);
    MEMBER_ID.store(0, Ordering::Release);
    MEMBER_GENERATION.store(0, Ordering::Release);
    let setup = unsafe { &mut *SETUP.0.get() };
    setup.preparation = None;
    setup.aborted_ns = 0;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedSummary {
    pub session: u64,
    pub started_ns: u64,
    pub frozen_ns: u64,
    pub completed: u64,
    pub lost: bool,
    pub rows: usize,
}
/// Bind the real pre-capture reservation before any warm workload is admitted.
/// A Preparation is deliberately distinct from a capture RunKey.
pub fn bind_preparation(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<(), Error> {
    cpu0()?;
    crate::domain_control::replay::verify_preparation(preparation)?;
    let _guard = lock()?;
    let setup = unsafe { &mut *SETUP.0.get() };
    if setup.preparation.is_some_and(|old| old != preparation)
        || setup.preparation.is_none() && SESSION.load(Ordering::Acquire) != 0
    {
        return Err(Error::Busy);
    }
    setup.preparation = Some(preparation);
    Ok(())
}
/// The adapter first stops new workload requests and drains accepted work.
/// This closes only CPU custody; an outstanding credit cannot be erased.
pub fn freeze_abort(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<bool, Error> {
    cpu0()?;
    let _guard = lock()?;
    let setup = unsafe { &mut *SETUP.0.get() };
    if setup.preparation.is_none() && SESSION.load(Ordering::Acquire) == 0 {
        setup.preparation = Some(preparation);
    }
    if setup.preparation != Some(preparation) || GENERATION.load(Ordering::Acquire) != 0 {
        return Err(Error::Stale);
    }
    ACTIVE.store(false, Ordering::SeqCst);
    if OPEN.load(Ordering::SeqCst) != 0 {
        return Ok(false);
    }
    if setup.aborted_ns == 0 {
        setup.aborted_ns = now();
        for bank in 0..CORES {
            FROZEN_TAIL[bank].store(TAIL[bank].load(Ordering::Acquire), Ordering::Release);
        }
    }
    Ok(true)
}
pub fn summary_prepared(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<Option<PreparedSummary>, Error> {
    let _guard = lock()?;
    let setup = unsafe { &*SETUP.0.get() };
    if SESSION.load(Ordering::Acquire) == 0 && setup.preparation.is_none() {
        return Ok(None);
    }
    if setup.preparation != Some(preparation)
        || GENERATION.load(Ordering::Acquire) != 0
        || ACTIVE.load(Ordering::SeqCst)
        || OPEN.load(Ordering::SeqCst) != 0
        || setup.aborted_ns == 0
    {
        return Err(Error::Busy);
    }
    let session = SESSION.load(Ordering::Acquire);
    if session == 0 {
        return Ok(None);
    }
    Ok(Some(PreparedSummary {
        session,
        started_ns: STARTED.load(Ordering::Acquire),
        frozen_ns: setup.aborted_ns,
        completed: COMPLETED.load(Ordering::Acquire),
        lost: LOST.load(Ordering::Acquire),
        rows: (0..CORES)
            .map(|bank| {
                HEAD[bank].load(Ordering::Acquire) - FROZEN_TAIL[bank].load(Ordering::Acquire)
            })
            .sum(),
    }))
}
pub fn copy_prepared(
    preparation: crate::domain_control::replay::Preparation,
    index: usize,
) -> Result<RawRow, Error> {
    let summary = summary_prepared(preparation)?.ok_or(Error::NotReady)?;
    if index >= summary.rows {
        return Err(Error::Range);
    }
    let _guard = lock()?;
    let setup = unsafe { &*SETUP.0.get() };
    if setup.preparation != Some(preparation) || SESSION.load(Ordering::Acquire) != summary.session
    {
        return Err(Error::Stale);
    }
    let mut skip = index;
    for bank in 0..CORES {
        let tail = FROZEN_TAIL[bank].load(Ordering::Acquire);
        let len = HEAD[bank].load(Ordering::Acquire) - tail;
        if skip < len {
            let row = unsafe { *row(bank, tail + skip) };
            return Ok(RawRow {
                owner: source(bank),
                core: bank as u16,
                event: row.event,
                first_ns: row.first,
                last_ns: row.last,
            });
        }
        skip -= len;
    }
    Err(Error::Range)
}
pub fn release_prepared(
    preparation: crate::domain_control::replay::Preparation,
) -> Result<(), Error> {
    cpu0()?;
    if !crate::domain_control::replay::preparation_archived(preparation) {
        return Err(Error::Busy);
    }
    let _guard = lock()?;
    let setup = unsafe { &mut *SETUP.0.get() };
    if setup.preparation != Some(preparation)
        || setup.aborted_ns == 0
        || GENERATION.load(Ordering::Acquire) != 0
        || ACTIVE.load(Ordering::SeqCst)
        || OPEN.load(Ordering::SeqCst) != 0
    {
        return Err(Error::Busy);
    }
    SESSION.store(0, Ordering::Release);
    MEMBER_ID.store(0, Ordering::Release);
    MEMBER_GENERATION.store(0, Ordering::Release);
    setup.preparation = None;
    setup.aborted_ns = 0;
    Ok(())
}
