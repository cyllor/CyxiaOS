//! Protected single-replay publication history. Entries come from actual root
//! proposal/PUBLISH/executor hooks, not a caller's reconstructed ring buffer.
//! Missing scope, baseline, partner, or completion evidence excludes labels.
pub use crate::learning_evidence::{Error, PoolCheck};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use cyxia_arch_aarch64::cpu;
use cyxia_prototype::{
    domains::{Action, ApplyId, ObjectKey, PolicyStamp},
    learning::{
        self, Family, ReplayGroup, Schemas,
        capture::{RunKey, Seal},
        reward::{Adoption, BaselineAdoption, CpuInterval, Trial},
    },
    policy::{CandidateSet, ExecutionState, ModelBinding, Snapshot},
    policy_wire,
};
use sha2::{Digest, Sha256};
#[path = "learning_history/replay.rs"]
pub mod replay;
#[path = "learning_history/rejection.rs"]
#[cfg_attr(test, allow(dead_code))]
mod rejection;

pub const RECORDS: usize = 64;
// A full ordinary journal must still retain the root's first terminal
// rejection before the failed trial can be durably archived and released.
const DATA_RECORDS: usize = RECORDS - 1;
pub const INPUT_BYTES: usize = 4096;
pub const SLOT_BYTES: usize = 6144;
pub const STORAGE_BYTES: usize = RECORDS * SLOT_BYTES;
const INPUT: usize = 2048;
const ACTIONS: usize = 512;
const CONCURRENT: usize = 1280;
// The protected root's one-shot trigger is distinct from row 352, which
// always retains the later, actually observed publication ingress time.
const LOGICAL_ISSUED: usize = 488;
const LOGICAL_PRESENT: usize = 496;
const PROPOSED: u64 = 1;
const PUBLISHED: u64 = 2;
const STARTED: u64 = 4;
const OBSERVED: u64 = 8;
const SHARED: u64 = 16;
const BASELINE: u64 = 32;
const PROBE: u64 = 64;

/// All fields are bytes: after the actual pool owner has zeroed the allocation
/// in charged chunks it may establish this reference. Never construct this
/// 384 KiB value on an EL1 stack or substitute a separately backed static.
#[repr(C, align(64))]
pub struct Storage {
    bytes: [u8; STORAGE_BYTES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrialKind {
    Candidate,
    Baseline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenScope {
    pub key: RunKey,
    pub kind: TrialKind,
    pub family: Family,
    pub target: ObjectKey,
    pub group: ReplayGroup,
    pub schemas: Schemas,
    pub frozen_other_domains: [u8; 32],
    pub frozen_scope_hash: [u8; 32],
    pub first_ns: u64,
    pub warmed_from_ns: u64,
    pub observation_ns: u64,
}
/// These are actual protected replay/owner lookups. No default implementation
/// exists. A replay cannot be armed by merely presenting nonzero digests.
#[derive(Clone, Copy)]
pub struct ReplayChecks {
    pub frozen: fn(&FrozenScope) -> Result<(), learning::Error>,
    pub issued: fn(RunKey, &Adoption<'_>) -> Result<(), learning::Error>,
    pub baseline: fn(RunKey, &BaselineAdoption) -> Result<(), learning::Error>,
    pub closing: fn(&FrozenScope, &Trial<'_>) -> Result<(), learning::Error>,
}
pub struct Publish<'a> {
    pub decision_seq: u64,
    pub apply: ApplyId,
    pub plan_version: u64,
    pub stamp: PolicyStamp,
    pub model: ModelBinding,
    pub selected: u16,
    pub scores: &'a [i16],
    pub received_ns: u64,
    pub published_ns: u64,
    pub expires_local_ns: u64,
    pub active_until_local_ns: u64,
    pub approved_deadline_ns: u64,
    pub concurrent: &'a [ApplyId],
}
#[derive(Clone, Copy)]
pub struct Execution {
    pub apply: ApplyId,
    pub stamp: PolicyStamp,
    pub state: ExecutionState,
    pub observed_ns: u64,
    /// Supplied at the actual executor entry, never inferred from a late poll.
    pub started_ns: Option<u64>,
    pub executor_generation: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub run: Option<RunKey>,
    pub records: usize,
    pub fault: Option<learning::Error>,
    pub published: usize,
    pub applied: usize,
    pub unresolved: usize,
}
struct Owner {
    storage: *mut Storage,
    node: [u8; 32],
    boot_epoch: u64,
    high_generation: u64,
    scope: Option<FrozenScope>,
    checks: Option<ReplayChecks>,
    used: usize,
    fault: Option<learning::Error>,
    sealed: Option<Seal>,
}
struct Cell(UnsafeCell<Owner>);
unsafe impl Sync for Cell {}
static OWNER: Cell = Cell(UnsafeCell::new(Owner {
    storage: core::ptr::null_mut(),
    node: [0; 32],
    boot_epoch: 0,
    high_generation: 0,
    scope: None,
    checks: None,
    used: 0,
    fault: None,
    sealed: None,
}));
static GATE: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static RUN: AtomicU64 = AtomicU64::new(0);
static LOST: AtomicU64 = AtomicU64::new(0);
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
fn with<T>(f: impl FnOnce(&mut Owner, &mut Storage) -> Result<T, Error>) -> Result<T, Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let _guard = lock()?;
    let owner = unsafe { &mut *OWNER.0.get() };
    let storage = unsafe { owner.storage.as_mut() }.ok_or(Error::NotReady)?;
    if owner
        .scope
        .is_some_and(|s| s.key.generation == LOST.load(Ordering::Acquire))
    {
        owner.fault.get_or_insert(learning::Error::DataIncomplete);
    }
    f(owner, storage)
}
fn record(f: impl FnOnce(&mut Owner, &mut Storage) -> Result<bool, Error>) -> Result<bool, Error> {
    let generation = RUN.load(Ordering::Acquire);
    if generation == 0 || !READY.load(Ordering::Acquire) {
        return Ok(false);
    }
    let result = with(|owner, storage| {
        if owner.scope.map(|s| s.key.generation) != Some(generation) {
            return Err(Error::Stale);
        }
        let result = f(owner, storage);
        if result.is_err() {
            owner.fault.get_or_insert(learning::Error::DataIncomplete);
        }
        result
    });
    if result == Err(Error::Busy) {
        LOST.store(generation, Ordering::Release);
    }
    result
}
fn fail<T>(error: learning::Error) -> Result<T, Error> {
    Err(Error::Capture(error))
}
fn learn(error: Error) -> learning::Error {
    match error {
        Error::Capture(e) => e,
        // Read-only verification retains the sealed rows across contention;
        // a Busy reader is not a missing observation from a recording hook.
        Error::Busy => learning::Error::Unknown,
        Error::Stale => learning::Error::Stale,
        _ => learning::Error::DataIncomplete,
    }
}
fn now() -> u64 {
    crate::domain_platform::now_ns()
}
fn u16_at(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().expect("fixed history field"))
}
fn u64_at(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().expect("fixed history field"))
}
fn put16(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
fn bytes32(b: &[u8], p: usize) -> [u8; 32] {
    b[p..p + 32].try_into().expect("fixed history hash")
}
fn row(storage: &Storage, i: usize) -> &[u8] {
    &storage.bytes[i * SLOT_BYTES..(i + 1) * SLOT_BYTES]
}
fn row_mut(storage: &mut Storage, i: usize) -> &mut [u8] {
    &mut storage.bytes[i * SLOT_BYTES..(i + 1) * SLOT_BYTES]
}
fn find_decision(owner: &Owner, storage: &Storage, id: u64) -> Option<usize> {
    (0..owner.used)
        .find(|i| u64_at(row(storage, *i), 0) & PROPOSED != 0 && u64_at(row(storage, *i), 8) == id)
}
fn model(b: &[u8]) -> ModelBinding {
    ModelBinding {
        generation: u64_at(b, 80),
        model_hash: bytes32(b, 88),
        schema_hash: bytes32(b, 120),
    }
}
fn snapshot(b: &[u8]) -> Snapshot {
    Snapshot {
        sequence: u64_at(b, 152),
        taken_ns: u64_at(b, 160),
        ledger_generation: u64_at(b, 168),
        core_generation: u64_at(b, 176),
    }
}
fn target(b: &[u8]) -> ObjectKey {
    ObjectKey {
        id: u64_at(b, 184),
        generation: u64_at(b, 192),
    }
}
fn write_id(b: &mut [u8], p: usize, id: ApplyId) {
    for (i, v) in [
        id.boot_epoch,
        id.controller_epoch,
        id.plan_seq,
        u64::from(id.action_index),
        id.target.id,
        id.target.generation,
    ]
    .into_iter()
    .enumerate()
    {
        put64(b, p + i * 8, v);
    }
}
fn read_id(b: &[u8], p: usize) -> ApplyId {
    ApplyId {
        boot_epoch: u64_at(b, p),
        controller_epoch: u64_at(b, p + 8),
        plan_seq: u64_at(b, p + 16),
        action_index: u64_at(b, p + 24) as u16,
        target: ObjectKey {
            id: u64_at(b, p + 32),
            generation: u64_at(b, p + 40),
        },
    }
}
fn stamp(b: &[u8]) -> PolicyStamp {
    PolicyStamp {
        version: u64_at(b, 320),
        snapshot_ns: u64_at(b, 328),
        installed_until_ns: u64_at(b, 336),
    }
}
fn write_stamp(b: &mut [u8], s: PolicyStamp) {
    put64(b, 320, s.version);
    put64(b, 328, s.snapshot_ns);
    put64(b, 336, s.installed_until_ns);
}
fn state(state: ExecutionState) -> (u64, u64) {
    match state {
        ExecutionState::Pending => (0, 0),
        ExecutionState::Applied => (1, 0),
        ExecutionState::Unknown => (2, 0),
        ExecutionState::Failed(error) => (3, error as u64),
    }
}
fn write_action(b: &mut [u8], index: usize, action: Action) -> Result<(), Error> {
    let p = ACTIONS + index * 24;
    b[p..p + 24].fill(0);
    let baseline = u64_at(b, 0) & BASELINE != 0;
    let n = if baseline {
        learning::baseline::encode(action, &mut b[p + 8..p + 24]).map_err(Error::Capture)?
    } else {
        policy_wire::encode_payload(action, 0, &mut b[p + 8..p + 24])
            .map_err(|_| Error::Capture(learning::Error::Evidence))?
    };
    put16(b, p, action.domain());
    put16(b, p + 2, action.kind());
    put16(b, p + 4, n as u16);
    Ok(())
}
fn action(b: &[u8], index: usize) -> Result<Action, Error> {
    if index >= usize::from(u16_at(b, 204)) {
        return fail(learning::Error::Evidence);
    }
    let p = ACTIONS + index * 24;
    let n = usize::from(u16_at(b, p + 4));
    if n > 16 {
        return fail(learning::Error::Evidence);
    }
    if u64_at(b, 0) & BASELINE != 0 {
        return learning::baseline::decode(u16_at(b, p), u16_at(b, p + 2), &b[p + 8..p + 8 + n])
            .map_err(Error::Capture);
    }
    policy_wire::decode_payload(u16_at(b, p), u16_at(b, p + 2), &b[p + 8..p + 8 + n])
        .map(|(action, _)| action)
        .map_err(|_| Error::Capture(learning::Error::Evidence))
}
fn shared_hash(intervals: &[CpuInterval]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CYXIA_ROOT_SHARED_POLICY_1.3\0");
    h.update((intervals.len() as u64).to_le_bytes());
    for c in intervals {
        h.update(c.node);
        for v in [u64::from(c.core), c.start_ns, c.end_ns, c.class as u64] {
            h.update(v.to_le_bytes());
        }
    }
    h.finalize().into()
}

pub fn install(
    storage: &'static mut Storage,
    node: [u8; 32],
    boot_epoch: u64,
    allocation: ObjectKey,
    check: PoolCheck,
) -> Result<(), (Error, &'static mut Storage)> {
    if cpu::slot() != 0 {
        return Err((Error::Owner, storage));
    }
    if node == [0; 32] || boot_epoch == 0 || allocation.id == 0 || allocation.generation == 0 {
        return Err((Error::Owner, storage));
    }
    if let Err(error) = check(allocation, storage as *mut Storage as usize, STORAGE_BYTES) {
        return Err((error, storage));
    }
    let _guard = match lock() {
        Ok(g) => g,
        Err(e) => return Err((e, storage)),
    };
    if READY.load(Ordering::Relaxed) || (0..RECORDS).any(|i| u64_at(row(storage, i), 0) != 0) {
        return Err((Error::Stale, storage));
    }
    let owner = unsafe { &mut *OWNER.0.get() };
    owner.storage = storage as *mut Storage;
    owner.node = node;
    owner.boot_epoch = boot_epoch;
    READY.store(true, Ordering::Release);
    Ok(())
}

pub fn begin_run(scope: FrozenScope, checks: ReplayChecks) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Owner);
    }
    begin_inner(scope, checks)
}
pub fn begin_authorized(
    scope: FrozenScope,
    checks: ReplayChecks,
    permit: &crate::learning_evidence::StartPermit,
) -> Result<(), Error> {
    if !matches!(cpu::slot(), 0 | 1 | 2) {
        return Err(Error::Owner);
    }
    crate::learning_evidence::validate_start_permit(permit, scope.key)?;
    begin_inner(scope, checks)
}
/// Retain only the facts of an already started capture after startup failed.
/// No frozen-workload witness or publication receipt is manufactured here.
/// Existing rows remain byte-for-byte intact, and the permanent fault prevents
/// this scope from ever certifying an adopted sample or full replay.
pub fn begin_excluded_authorized(
    scope: FrozenScope,
    permit: &crate::learning_evidence::StartPermit,
    reason: learning::Error,
) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Owner);
    }
    crate::learning_evidence::validate_start_permit(permit, scope.key)?;
    let config = crate::learning_evidence::current_config()?.ok_or(Error::NotReady)?;
    if config.key != scope.key
        || config.family != scope.family
        || config.first_ns != scope.first_ns
        || config.observation_ns != scope.observation_ns
        || config.frozen_scope_hash != scope.frozen_scope_hash
    {
        return fail(learning::Error::Evidence);
    }
    with(|owner, _| {
        if let Some(old) = owner.scope {
            if old != scope {
                return Err(Error::Stale);
            }
            if owner.sealed.is_some() {
                return Err(Error::Stale);
            }
            owner.fault.get_or_insert(reason);
            return Ok(());
        }
        if scope.key.boot_epoch != owner.boot_epoch
            || config.node != owner.node
            || scope.key.generation <= owner.high_generation
            || owner.sealed.is_some()
        {
            return Err(Error::Stale);
        }
        owner.scope = Some(scope);
        owner.checks = None;
        owner.used = 0;
        owner.high_generation = scope.key.generation;
        owner.fault = Some(reason);
        LOST.store(0, Ordering::Release);
        RUN.store(scope.key.generation, Ordering::Release);
        Ok(())
    })
}
fn begin_inner(scope: FrozenScope, checks: ReplayChecks) -> Result<(), Error> {
    scope.family.index()?;
    scope.schemas.validate()?;
    if scope.key.boot_epoch == 0
        || scope.key.trial_id == 0
        || scope.key.generation == 0
        || scope.target.id == 0
        || scope.target.generation == 0
        || scope.group.workload == [0; 32]
        || scope.group.initial_image == [0; 32]
        || scope.frozen_other_domains == [0; 32]
        || scope.frozen_scope_hash == [0; 32]
        || scope.first_ns > scope.observation_ns
        || scope.observation_ns.checked_sub(scope.warmed_from_ns) != Some(1_000_000_000)
    {
        return fail(learning::Error::Evidence);
    }
    (checks.frozen)(&scope)?;
    let config = crate::learning_evidence::current_config()?.ok_or(Error::NotReady)?;
    if config.key != scope.key
        || config.family != scope.family
        || config.first_ns != scope.first_ns
        || config.observation_ns != scope.observation_ns
        || config.frozen_scope_hash != scope.frozen_scope_hash
    {
        return fail(learning::Error::Evidence);
    }
    with(|owner, _| {
        if owner.scope == Some(scope) {
            let old = owner.checks.ok_or(Error::NotReady)?;
            return if core::ptr::fn_addr_eq(old.frozen, checks.frozen)
                && core::ptr::fn_addr_eq(old.issued, checks.issued)
                && core::ptr::fn_addr_eq(old.baseline, checks.baseline)
                && core::ptr::fn_addr_eq(old.closing, checks.closing)
            {
                Ok(())
            } else {
                fail(learning::Error::Conflict)
            };
        }
        if scope.key.boot_epoch != owner.boot_epoch
            || config.node != owner.node
            || scope.key.generation <= owner.high_generation
        {
            return Err(Error::Stale);
        }
        if owner.scope.is_some() {
            return fail(learning::Error::Unknown);
        }
        owner.scope = Some(scope);
        owner.checks = Some(checks);
        owner.used = 0;
        owner.fault = None;
        owner.high_generation = scope.key.generation;
        LOST.store(0, Ordering::Release);
        RUN.store(scope.key.generation, Ordering::Release);
        Ok(())
    })
}

pub fn record_proposal(
    decision_seq: u64,
    set: &CandidateSet,
    input: &[u8; INPUT_BYTES],
    input_hash: [u8; 32],
) -> Result<bool, Error> {
    record(|owner, storage| {
        let scope = owner.scope.ok_or(Error::NotReady)?;
        let first = set
            .get(0)
            .ok_or(Error::Capture(learning::Error::Evidence))?;
        if scope.kind != TrialKind::Candidate
            || set.target != scope.target
            || first.action.domain() != scope.family.domain
            || first.action.kind() != scope.family.kind
        {
            return Ok(false);
        }
        if !matches!(cpu::slot(), 1 | 2) {
            return Err(Error::Owner);
        }
        if decision_seq == 0
            || set.len() > 32
            || <[u8; 32]>::from(Sha256::digest(input)) != input_hash
        {
            return fail(learning::Error::Evidence);
        }
        if let Some(i) = find_decision(owner, storage, decision_seq) {
            let r = row(storage, i);
            return if bytes32(r, 16) == set.hash()
                && bytes32(r, 48) == input_hash
                && snapshot(r) == set.snapshot
                && model(r) == set.model
                && &r[INPUT..INPUT + INPUT_BYTES] == input
            {
                Ok(true)
            } else {
                fail(learning::Error::Conflict)
            };
        }
        if owner.used >= DATA_RECORDS {
            return Err(Error::Capacity);
        }
        let r = row_mut(storage, owner.used);
        r[..INPUT].fill(0);
        put64(r, 8, decision_seq);
        r[16..48].copy_from_slice(&set.hash());
        r[48..80].copy_from_slice(&input_hash);
        put64(r, 80, set.model.generation);
        r[88..120].copy_from_slice(&set.model.model_hash);
        r[120..152].copy_from_slice(&set.model.schema_hash);
        for (i, v) in [
            set.snapshot.sequence,
            set.snapshot.taken_ns,
            set.snapshot.ledger_generation,
            set.snapshot.core_generation,
            set.target.id,
            set.target.generation,
        ]
        .into_iter()
        .enumerate()
        {
            put64(r, 152 + i * 8, v);
        }
        put16(r, 200, first.action.domain());
        put16(r, 202, first.action.kind());
        put16(r, 204, set.len() as u16);
        for (i, c) in set.iter().enumerate() {
            write_action(r, i, c.action)?;
        }
        if first.action.one_shot() {
            if scope.first_ns != scope.observation_ns || set.snapshot.taken_ns != scope.first_ns {
                return fail(learning::Error::Evidence);
            }
            put64(r, LOGICAL_ISSUED, scope.first_ns);
            put64(r, LOGICAL_PRESENT, 1);
        }
        r[INPUT..INPUT + INPUT_BYTES].copy_from_slice(input);
        put64(r, 0, PROPOSED);
        owner.used += 1;
        Ok(true)
    })
}

pub fn record_publish(p: Publish<'_>) -> Result<bool, Error> {
    record(|owner, storage| {
        let Some(i) = find_decision(owner, storage, p.decision_seq) else {
            return Ok(false);
        };
        if !matches!(cpu::slot(), 1 | 2) {
            return Err(Error::Owner);
        }
        let r = row_mut(storage, i);
        let selected = action(r, p.selected as usize)?;
        p.stamp
            .validate_action(selected)
            .map_err(|_| Error::Capture(learning::Error::Evidence))?;
        if p.model != model(r)
            || p.apply.target != target(r)
            || p.apply.boot_epoch != owner.boot_epoch
            || p.apply.controller_epoch == 0
            || p.apply.plan_seq == 0
            || p.plan_version == 0
            || p.plan_version != p.stamp.version
            || p.stamp.snapshot_ns != snapshot(r).taken_ns
            || p.active_until_local_ns != p.stamp.installed_until_ns
            || p.scores.len() != usize::from(u16_at(r, 204))
            || p.concurrent.is_empty()
            || p.concurrent.len() > 16
            || p.concurrent.get(usize::from(p.apply.action_index)) != Some(&p.apply)
            || p.received_ns < snapshot(r).taken_ns
            || p.published_ns < p.received_ns
            || p.published_ns > now()
            || p.expires_local_ns < p.published_ns
            || p.expires_local_ns
                > snapshot(r)
                    .taken_ns
                    .checked_add(100_000_000)
                    .ok_or(Error::Capacity)?
            || p.approved_deadline_ns < p.published_ns
        {
            return fail(learning::Error::Evidence);
        }
        for (index, id) in p.concurrent.iter().enumerate() {
            if id.boot_epoch != p.apply.boot_epoch
                || id.controller_epoch != p.apply.controller_epoch
                || id.plan_seq != p.apply.plan_seq
                || usize::from(id.action_index) != index
                || p.concurrent[..index].contains(id)
            {
                return fail(learning::Error::Evidence);
            }
        }
        // D16's pending-request deadline is distinct from ordinary parameter
        // APPLY. The issued/request-owner check additionally binds its actual
        // 4 s queue deadline; PUBLISH does not restart that timer.
        let deadline_bound = match selected {
            Action::ControlSet(_) => 200_000_000,
            Action::RecoveryRecipe(_) => 1_000_000_000,
            Action::Placement(_) => 4_000_000_000,
            _ => 50_000_000,
        };
        if p.approved_deadline_ns - p.published_ns > deadline_bound {
            return fail(learning::Error::Deadline);
        }
        if u64_at(r, 0) & PUBLISHED != 0 {
            return if read_id(r, 272) == p.apply
                && stamp(r) == p.stamp
                && u64_at(r, 344) == p.plan_version
                && u16_at(r, 206) == p.selected
                && u64_at(r, 352) == p.received_ns
                && u64_at(r, 360) == p.published_ns
                && u64_at(r, 368) == p.expires_local_ns
                && u64_at(r, 376) == p.active_until_local_ns
                && u64_at(r, 384) == p.approved_deadline_ns
                && u64_at(r, 440) as usize == p.concurrent.len()
                && p.scores
                    .iter()
                    .enumerate()
                    .all(|(j, v)| u16_at(r, 208 + j * 2) as i16 == *v)
                && p.concurrent
                    .iter()
                    .enumerate()
                    .all(|(j, id)| read_id(r, CONCURRENT + j * 48) == *id)
            {
                Ok(true)
            } else {
                fail(learning::Error::Conflict)
            };
        }
        put16(r, 206, p.selected);
        for (j, score) in p.scores.iter().enumerate() {
            put16(r, 208 + j * 2, *score as u16);
        }
        write_id(r, 272, p.apply);
        write_stamp(r, p.stamp);
        for (p, v) in [
            (344, p.plan_version),
            (352, p.received_ns),
            (360, p.published_ns),
            (368, p.expires_local_ns),
            (376, p.active_until_local_ns),
            (384, p.approved_deadline_ns),
            (440, p.concurrent.len() as u64),
        ] {
            put64(r, p, v);
        }
        for (j, id) in p.concurrent.iter().enumerate() {
            write_id(r, CONCURRENT + j * 48, *id);
        }
        if p.concurrent.len() == 1 {
            r[448..480].copy_from_slice(&shared_hash(&[]));
            put64(r, 480, 0);
            put64(r, 0, u64_at(r, 0) | SHARED);
        }
        put64(r, 0, u64_at(r, 0) | PUBLISHED);
        Ok(true)
    })
}

pub fn record_execution(event: Execution) -> Result<bool, Error> {
    record(|owner, storage| {
        let Some(i) = (0..owner.used).find(|i| {
            let r = row(storage, *i);
            u64_at(r, 0) & PUBLISHED != 0 && read_id(r, 272) == event.apply
        }) else {
            return Ok(false);
        };
        if cpu::slot() != 0 {
            return Err(Error::Owner);
        }
        let r = row_mut(storage, i);
        if stamp(r) != event.stamp
            || event.observed_ns > now()
            || event.observed_ns < u64_at(r, 360)
        {
            return fail(learning::Error::Evidence);
        }
        if let Some(started) = event.started_ns {
            if started < u64_at(r, 360) || started > event.observed_ns {
                return fail(learning::Error::Evidence);
            }
            if u64_at(r, 0) & STARTED != 0 {
                if started < u64_at(r, 400) {
                    return fail(learning::Error::Stale);
                }
                // A Busy attempt consumed real executor CPU. Preserve the
                // first actual entry; subsequent retries do not restart time.
            } else {
                put64(r, 400, started);
                put64(r, 0, u64_at(r, 0) | STARTED);
            }
        }
        if let Some(generation) = event.executor_generation {
            if generation == 0 || (u64_at(r, 392) != 0 && u64_at(r, 392) != generation) {
                return fail(learning::Error::Stale);
            }
            put64(r, 392, generation);
        }
        let (tag, code) = state(event.state);
        if u64_at(r, 0) & OBSERVED != 0 && matches!(u64_at(r, 424), 1 | 3) {
            return if (u64_at(r, 424), u64_at(r, 432)) == (tag, code) {
                Ok(true)
            } else {
                fail(learning::Error::Conflict)
            };
        }
        if u64_at(r, 408) > event.observed_ns {
            return fail(learning::Error::Stale);
        }
        put64(r, 408, event.observed_ns);
        put64(r, 424, tag);
        put64(r, 432, code);
        if matches!(tag, 1 | 3) {
            put64(r, 416, event.observed_ns);
        }
        put64(r, 0, u64_at(r, 0) | OBSERVED);
        Ok(true)
    })
}

/// The root's actual common-span owner supplies this list after its intervals
/// close. A multi-action plan with no such record stays DataIncomplete.
pub fn record_shared_policy(decision_seq: u64, intervals: &[CpuInterval]) -> Result<bool, Error> {
    record(|owner, storage| {
        let i = find_decision(owner, storage, decision_seq).ok_or(Error::Stale)?;
        let r = row_mut(storage, i);
        if u64_at(r, 0) & PUBLISHED == 0
            || intervals.len() > learning::reward::MAX_CPU_INTERVALS
            || (u64_at(r, 440) > 1 && intervals.is_empty())
            || intervals.iter().any(|c| {
                c.class != learning::reward::CpuClass::Policy
                    || c.node != owner.node
                    || c.core >= 64
                    || c.start_ns > c.end_ns
                    || c.end_ns > now()
            })
        {
            return fail(learning::Error::Evidence);
        }
        let hash = shared_hash(intervals);
        if u64_at(r, 0) & SHARED != 0 {
            return if bytes32(r, 448) == hash && u64_at(r, 480) == intervals.len() as u64 {
                Ok(true)
            } else {
                fail(learning::Error::Conflict)
            };
        }
        r[448..480].copy_from_slice(&hash);
        put64(r, 480, intervals.len() as u64);
        put64(r, 0, u64_at(r, 0) | SHARED);
        Ok(true)
    })
}

fn adoption_metadata(run: RunKey, adoption: &Adoption<'_>, verify_payload: bool) -> Result<ReplayChecks, Error> {
    with(|owner, storage| {
        let scope = owner.scope.ok_or(Error::NotReady)?;
        if scope.key != run {
            return Err(Error::Stale);
        }
        if let Some(error) = owner.fault {
            return fail(error);
        }
        let checks = owner.checks.ok_or(Error::NotReady)?;
        let i = find_decision(owner, storage, adoption.decision_seq)
            .ok_or(Error::Capture(learning::Error::DataIncomplete))?;
        let r = row(storage, i);
        if u64_at(r, 0) & (PROPOSED | PUBLISHED | STARTED | OBSERVED | SHARED)
            != PROPOSED | PUBLISHED | STARTED | OBSERVED | SHARED
            || u64_at(r, 392) == 0
            || u64_at(r, 424) != 1
        {
            return fail(learning::Error::DataIncomplete);
        }
        if read_id(r, 272) != adoption.apply
            || u64_at(r, 344) != adoption.plan_version
            || u64_at(r, 392) != adoption.executor_generation
            || bytes32(r, 16) != adoption.candidates.hash()
            || snapshot(r) != adoption.candidates.snapshot
            || target(r) != adoption.candidates.target
            || model(r) != adoption.candidates.model
            || (verify_payload && <[u8; 32]>::from(Sha256::digest(adoption.model)) != model(r).model_hash)
            || u16_at(r, 206) != adoption.selected
            || action(r, adoption.selected as usize)? != adoption.actual
            || adoption.executed != ExecutionState::Applied
            || adoption.scores.len() != usize::from(u16_at(r, 204))
            || !adoption
                .scores
                .iter()
                .enumerate()
                .all(|(j, v)| u16_at(r, 208 + j * 2) as i16 == *v)
            || adoption.issued_ns != decision_issued(r)?
            || adoption.accepted_ns != u64_at(r, 360)
            || adoption.expires_local_ns != u64_at(r, 368)
            || adoption.active_until_local_ns != u64_at(r, 376)
            || adoption.started_ns != u64_at(r, 400)
            || adoption.finished_ns != u64_at(r, 416)
            || adoption.installed_until_ns != stamp(r).installed_until_ns
            || adoption.approved_deadline_ns != u64_at(r, 384)
            || adoption.concurrent.len() != u64_at(r, 440) as usize
            || !adoption
                .concurrent
                .iter()
                .enumerate()
                .all(|(j, id)| read_id(r, CONCURRENT + j * 48) == *id)
            || adoption.shared_policy_intervals.len() != u64_at(r, 480) as usize
            || (verify_payload && shared_hash(adoption.shared_policy_intervals) != bytes32(r, 448))
        {
            return fail(learning::Error::Evidence);
        }
        Ok(checks)
    })
}
pub fn verify_adoption(run: RunKey, adoption: &Adoption<'_>) -> Result<(), learning::Error> {
    let checks = adoption_metadata(run, adoption, true).map_err(learn)?;
    // Issuance and one-shot request ownership remain real owner lookups.
    (checks.issued)(run, adoption)
}

fn decision_issued(r: &[u8]) -> Result<u64, Error> {
    let selected = action(r, u16_at(r, 206) as usize)?;
    if selected.one_shot() {
        let trigger = u64_at(r, LOGICAL_ISSUED);
        if u64_at(r, LOGICAL_PRESENT) != 1
            || trigger != snapshot(r).taken_ns
            || trigger > u64_at(r, 352)
        {
            return fail(learning::Error::Evidence);
        }
        Ok(trigger)
    } else {
        if u64_at(r, LOGICAL_PRESENT) != 0 || u64_at(r, LOGICAL_ISSUED) != 0 {
            return fail(learning::Error::Evidence);
        }
        Ok(u64_at(r, 352))
    }
}

fn same_baseline(r: &[u8], baseline: &BaselineAdoption) -> Result<bool, Error> {
    let request = u64_at(r, 440);
    Ok(u64_at(r, 0) == (BASELINE | OBSERVED)
        && u64_at(r, 8) == baseline.receipt_sequence
        && snapshot(r) == baseline.snapshot
        && target(r) == baseline.target
        && action(r, 0)? == baseline.actual
        && u64_at(r, 344) == baseline.owner_boot
        && u64_at(r, 352) == baseline.issued_ns
        && u64_at(r, 360) == baseline.accepted_ns
        && u64_at(r, 376) == baseline.installed_until_ns
        && u64_at(r, 384) == baseline.approved_deadline_ns
        && u64_at(r, 392) == baseline.executor_generation
        && u64_at(r, 400) == baseline.started_ns
        && u64_at(r, 416) == baseline.finished_ns
        && baseline.target_request_id == (request != 0).then_some(request)
        && (u64_at(r, 424), u64_at(r, 432)) == state(baseline.executed))
}
fn baseline_recorded(
    owner: &mut Owner,
    storage: &Storage,
    baseline: &BaselineAdoption,
) -> Result<bool, Error> {
    let Some(i) = (0..owner.used).find(|i| {
        let r = row(storage, *i);
        u64_at(r, 0) & BASELINE != 0 && u64_at(r, 8) == baseline.receipt_sequence
    }) else {
        return Ok(false);
    };
    if same_baseline(row(storage, i), baseline)? {
        return Ok(true);
    }
    owner.fault.get_or_insert(learning::Error::DataIncomplete);
    fail(learning::Error::Conflict)
}

/// Explicit deterministic-baseline evidence is separate from model proposals.
/// The first insertion requires the real owner's exact receipt. An unchanged
/// retry refers to that immutable row even after the owner advances its state.
pub fn record_baseline(run: RunKey, baseline: &BaselineAdoption) -> Result<bool, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Owner);
    }
    let checks = with(|owner, storage| {
        if owner.scope.map(|s| (s.key, s.kind)) != Some((run, TrialKind::Baseline)) {
            return Err(Error::Stale);
        }
        if baseline_recorded(owner, storage, baseline)? {
            return Ok(None);
        }
        if owner.sealed.is_some() {
            return Err(Error::Stale);
        }
        owner.checks.map(Some).ok_or(Error::NotReady)
    })?;
    let Some(checks) = checks else {
        return Ok(false);
    };
    (checks.baseline)(run, baseline)?;
    // The producer retains this complete receipt until insertion succeeds.
    // Unlike a one-way observation hook, a contended gate loses no evidence.
    with(|owner, storage| {
        if owner.scope.map(|s| (s.key, s.kind)) != Some((run, TrialKind::Baseline)) {
            return Err(Error::Stale);
        }
        let result = (|| {
            if baseline_recorded(owner, storage, baseline)? {
                return Ok(false);
            }
            if owner.sealed.is_some() {
                return Err(Error::Stale);
            }
            if baseline.owner_boot != owner.boot_epoch
                || baseline.target != owner.scope.ok_or(Error::NotReady)?.target
                || baseline.receipt_sequence == 0
                || baseline.finished_ns > now()
                || baseline.target_request_id == Some(0)
            {
                return fail(learning::Error::Evidence);
            }
            if owner.used >= DATA_RECORDS {
                return Err(Error::Capacity);
            }
            let r = row_mut(storage, owner.used);
            r[..INPUT].fill(0);
            put64(r, 0, BASELINE);
            put64(r, 8, baseline.receipt_sequence);
            for (i, v) in [
                baseline.snapshot.sequence,
                baseline.snapshot.taken_ns,
                baseline.snapshot.ledger_generation,
                baseline.snapshot.core_generation,
                baseline.target.id,
                baseline.target.generation,
            ]
            .into_iter()
            .enumerate()
            {
                put64(r, 152 + i * 8, v);
            }
            put16(r, 204, 1);
            write_action(r, 0, baseline.actual)?;
            for (p, v) in [
                (344, baseline.owner_boot),
                (352, baseline.issued_ns),
                (360, baseline.accepted_ns),
                (376, baseline.installed_until_ns),
                (384, baseline.approved_deadline_ns),
                (392, baseline.executor_generation),
                (400, baseline.started_ns),
                (416, baseline.finished_ns),
                (440, baseline.target_request_id.unwrap_or(0)),
            ] {
                put64(r, p, v);
            }
            let (tag, code) = state(baseline.executed);
            put64(r, 424, tag);
            put64(r, 432, code);
            put64(r, 0, BASELINE | OBSERVED);
            owner.used += 1;
            Ok(true)
        })();
        if result.is_err() {
            owner.fault.get_or_insert(learning::Error::DataIncomplete);
        }
        result
    })
}

/// A rejected, version-zero publication is durable negative evidence. Its
/// root capability proves the exact Registry result; it never supplies an
/// Applied baseline adoption or an executor-start timestamp.
#[cfg(not(test))]
pub fn record_rejected(
    run: RunKey,
    proof: &crate::domain_control::replay::RejectedPublication,
) -> Result<bool, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Owner);
    }
    crate::domain_control::replay::verify_rejected(run, proof).map_err(|error| match error {
        cyxia_prototype::domains::Error::Busy
        | cyxia_prototype::domains::Error::Again
        | cyxia_prototype::domains::Error::NotReady => Error::Busy,
        cyxia_prototype::domains::Error::Stale => Error::Stale,
        _ => Error::Capture(learning::Error::Evidence),
    })?;
    let facts = rejection::Facts {
        receipt: proof.receipt(), snapshot: proof.snapshot(), header: proof.header(),
        decision: proof.decision(), model: proof.model(), received_ns: proof.received_ns(),
        observed_ns: proof.observed_ns(), wall_deadline_ns: proof.wall_deadline_ns(),
        plan_hash: proof.plan_hash(),
    };
    with(|owner, storage| {
        let scope = owner.scope.ok_or(Error::NotReady)?;
        if scope.key != run || owner.sealed.is_some()
            || proof.token().boot_epoch != run.boot_epoch
            || facts.receipt.id.boot_epoch != run.boot_epoch
            || facts.decision.envelope.target != scope.target
            || (facts.decision.action.domain(), facts.decision.action.kind())
                != (scope.family.domain, scope.family.kind)
            || facts.model.schema_hash != scope.schemas.feature.hash
            || facts.snapshot.taken_ns < scope.first_ns
            || facts.observed_ns > now()
        {
            return Err(Error::Stale);
        }
        let added = rejection::append(&mut storage.bytes, &mut owner.used, &facts)
            .map_err(|error| match error {
                cyxia_prototype::domains::Error::Capacity => Error::Capacity,
                _ => Error::Capture(learning::Error::Evidence),
            })?;
        owner.fault.get_or_insert(learning::Error::DataIncomplete);
        Ok(added)
    })
}
fn baseline_metadata(run: RunKey, baseline: &BaselineAdoption) -> Result<ReplayChecks, Error> {
    with(|owner, storage| {
        if owner.scope.map(|s| (s.key, s.kind)) != Some((run, TrialKind::Baseline)) {
            return Err(Error::Stale);
        }
        if let Some(error) = owner.fault {
            return fail(error);
        }
        let i = (0..owner.used)
            .find(|i| {
                let r = row(storage, *i);
                u64_at(r, 0) & BASELINE != 0 && u64_at(r, 8) == baseline.receipt_sequence
            })
            .ok_or(Error::Capture(learning::Error::DataIncomplete))?;
        let r = row(storage, i);
        if !same_baseline(r, baseline)? {
            return fail(learning::Error::Evidence);
        }
        owner.checks.ok_or(Error::NotReady)
    })
}
pub fn verify_baseline(run: RunKey, baseline: &BaselineAdoption) -> Result<(), learning::Error> {
    let checks = baseline_metadata(run, baseline).map_err(learn)?;
    (checks.baseline)(run, baseline)
}

pub fn verify_scope(trial: &Trial<'_>, seal: Seal) -> Result<(), learning::Error> {
    let coverage = crate::learning_evidence::coverage(seal).map_err(learn)?;
    verify_scope_coverage(trial, seal, coverage)
}
fn verify_scope_coverage(
    trial: &Trial<'_>,
    seal: Seal,
    coverage: learning::reward::CpuCoverage,
) -> Result<(), learning::Error> {
    verify_scope_with_partner(trial, seal, coverage, None)
}
// Only the native replay authority can supply a partner proof, after checking
// the protected peer bank. Ordinary local attestation always passes None.
fn scope_metadata(
    trial: &Trial<'_>, seal: Seal, coverage: learning::reward::CpuCoverage,
    partner: Option<(learning::reward::CpuCoverage, [u8; 32])>,
) -> Result<(FrozenScope, ReplayChecks), Error> {
    #[cfg(not(test))]
    if trial.peak_workspace_bytes != crate::learning_replay::WORKSPACE_PEAK_BYTES as u64 {
        return fail(learning::Error::Evidence);
    }
    with(|owner, _| {
        let scope = owner.scope.ok_or(Error::NotReady)?;
        if scope.key != seal.key {
            return Err(Error::Stale);
        }
        if let Some(error) = owner.fault {
            return fail(error);
        }
        if seal.exclusion.is_some()
            || seal.frozen_scope_hash != scope.frozen_scope_hash
            || trial.id != scope.key.trial_id
            || trial.family != scope.family
            || trial.group != scope.group
            || trial.schemas != scope.schemas
            || trial.frozen_other_domains
                != partner.map_or(scope.frozen_other_domains, |(_, hash)| hash)
            || trial.local_node != owner.node
            || trial.observation_ns != scope.observation_ns
            || trial.warmed_from_ns != scope.warmed_from_ns
            || trial.closing_ns != seal.closing_ns
            || !trial.correct
            || !trial.frozen
            || trial.closing != ExecutionState::Applied
        {
            return fail(learning::Error::Evidence);
        }
        let roster_matches = if let Some((peer, _)) = partner {
            peer.node != owner.node
                && trial.controlled_nodes == [owner.node, peer.node]
                && trial.coverage == [coverage, peer]
        } else {
            trial.controlled_nodes == [owner.node] && trial.coverage == [coverage]
        };
        if !roster_matches {
            return fail(learning::Error::DataIncomplete);
        }
        if (scope.kind == TrialKind::Candidate
            && (trial.adoptions.is_empty() || !trial.baseline.is_empty()))
            || (scope.kind == TrialKind::Baseline
                && (trial.baseline.is_empty() || !trial.adoptions.is_empty()))
        {
            return fail(learning::Error::DataIncomplete);
        }
        Ok((scope, owner.checks.ok_or(Error::NotReady)?))
    })
}
fn verify_scope_with_partner(
    trial: &Trial<'_>, seal: Seal, coverage: learning::reward::CpuCoverage,
    partner: Option<(learning::reward::CpuCoverage, [u8; 32])>,
) -> Result<(), learning::Error> {
    let (scope, checks) = scope_metadata(trial, seal, coverage, partner).map_err(learn)?;
    (checks.frozen)(&scope)?;
    (checks.closing)(&scope, trial)
}

pub fn status() -> Result<Status, Error> {
    with(|owner, storage| {
        let mut status = Status {
            run: owner.scope.map(|s| s.key),
            records: owner.used,
            fault: owner.fault,
            published: 0,
            applied: 0,
            unresolved: 0,
        };
        for i in 0..owner.used {
            let r = row(storage, i);
            if u64_at(r, 0) & PUBLISHED != 0 {
                status.published += 1;
                if u64_at(r, 0) & OBSERVED == 0 || matches!(u64_at(r, 424), 0 | 2) {
                    status.unresolved += 1;
                } else if u64_at(r, 424) == 1 {
                    status.applied += 1;
                }
            }
        }
        Ok(status)
    })
}
/// Read-only bounded export retains raw input even when the trial is excluded.
pub fn copy_record(
    run: RunKey,
    index: usize,
    offset: usize,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() > 256 {
        return Err(Error::Capacity);
    }
    with(|owner, storage| {
        if owner.scope.map(|s| s.key) != Some(run) || index >= owner.used || offset > SLOT_BYTES {
            return Err(Error::Stale);
        }
        let n = out.len().min(SLOT_BYTES - offset);
        out[..n].copy_from_slice(&row(storage, index)[offset..offset + n]);
        Ok(n)
    })
}
const _: () = assert!(core::mem::size_of::<Storage>() == STORAGE_BYTES);
const _: () = assert!(rejection::SLOT_BYTES == SLOT_BYTES && rejection::PLAN_OFFSET == INPUT);

#[cfg(test)]
pub mod test_support {
    /// Exercise actual short-gate contention without replacing the journal.
    pub fn with_gate<T>(f: impl FnOnce() -> T) -> T {
        let _guard = super::lock().expect("exclusive test history gate");
        f()
    }
}
