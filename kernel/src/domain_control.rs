//! CPU0 owns publication. Isolated EL0 scores immutable candidates; executors
//! report real completion independently, with no inference in business paths.
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::{Action, ApplyId, Error, ObjectKey, POLICY_NS, PolicyStamp, WINDOW_NS},
    features::{RawFeatures, TargetFeatures},
    policy::{
        self, Candidate, CandidateSet, ExecutionState, ModelBinding, Publisher, Registry, Snapshot,
    },
    policy_wire::{self, Decision, Envelope, Plan, PlanHeader},
};
use sha2::{Digest, Sha256};
#[path = "domain_control/dependencies.rs"]
mod dependencies;
pub use cyxia_prototype::policy::{BoundDependency, Prerequisite};
type DependencyResolver = fn(ObjectKey) -> Result<[Option<Prerequisite>; 2], Error>;
type ExecutionObserver = fn(ObjectKey, u64) -> Result<(), Error>;
static ADMISSION: dependencies::AdmissionView = dependencies::AdmissionView::new();
static DEPENDENCY_RESOLVERS: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];
#[path = "../../user/prototype-runtime/abi.rs"]
mod abi;

#[derive(Clone, Copy)]
pub struct Family {
    pub domain: u16,
    pub kind: u16,
    pub target: fn(u16, u16, usize) -> Option<ObjectKey>,
    pub observe: fn(u16, ObjectKey) -> Result<[u64; 4], Error>,
    pub current: fn(u16, u16, ObjectKey) -> Result<Action, Error>,
    pub legal: fn(Action, ObjectKey, u64) -> Result<(), Error>,
    pub target_features: fn(Action, ObjectKey) -> Result<TargetFeatures, Error>,
    pub apply: fn(Action, ApplyId, PolicyStamp, u64) -> Result<ExecutionState, Error>,
    pub reconcile: fn(Action, ApplyId, PolicyStamp, u64) -> Result<ExecutionState, Error>,
}
#[derive(Clone, Copy, Default)]
pub struct Context {
    pub core_generation: u64,
    pub ledger_generation: u64,
    pub control_mask: u64,
    pub business_mask: u64,
    pub healthy_mask: u64,
    pub draining_mask: u64,
    pub common: [u64; 8],
}
#[derive(Clone, Copy)]
struct Desired {
    action: Action,
    previous: Action,
    apply: ApplyId,
    stamp: PolicyStamp,
    state: ExecutionState,
    execution_observed: bool,
    started: bool,
    published: u64,
    last_change: u64,
    direction: i8,
    reversal_start: u64,
    reversals: u8,
    frozen: bool,
    evidence: usize,
    job: u64,
    dependencies: [Option<BoundDependency>; 2],
    core_generation: u64,
    ledger_generation: u64,
}
struct Owner {
    families: [Option<Family>; 18],
    desired: [Option<Desired>; 512],
    context: Context,
    prepared: [usize; 16],
    prepared_count: usize,
    poll_cursor: usize,
    dependencies: [Option<DependencyResolver>; 16],
    execution_observers: [Option<ExecutionObserver>; 16],
}
struct Job {
    set: CandidateSet,
    sequence: u64,
    controller: u64,
    base_version: u64,
    started: u64,
    encode_ns: u64,
    evidence: usize,
    dependencies: [Option<BoundDependency>; 2],
}
struct State {
    registry: Registry,
    owner: Owner,
    boot: u64,
    sequence: u64,
    job: Option<Job>,
    due: [u64; 18],
    cursor: [usize; 18],
    family_cursor: usize,
    started: u64,
}
static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut STATE: State = State {
    registry: Registry::empty(),
    owner: Owner {
        families: [None; 18],
        desired: [None; 512],
        context: Context {
            core_generation: 0,
            ledger_generation: 0,
            control_mask: 0,
            business_mask: 0,
            healthy_mask: 0,
            draining_mask: 0,
            common: [0; 8],
        },
        prepared: [0; 16],
        prepared_count: 0,
        poll_cursor: 0,
        dependencies: [None; 16],
        execution_observers: [None; 16],
    },
    boot: 0,
    sequence: 0,
    job: None,
    due: [0; 18],
    cursor: [0; 18],
    family_cursor: 0,
    started: 0,
};
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        CLAIMED.store(false, Ordering::Release);
    }
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    if CLAIMED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(Error::Busy);
    }
    let _guard = Guard;
    f(unsafe { &mut *core::ptr::addr_of_mut!(STATE) })
}
fn now() -> u64 {
    crate::domain_platform::now_ns()
}
fn family_index(domain: u16, kind: u16) -> Result<usize, Error> {
    match (domain, kind) {
        (1, 1) => Ok(0),
        (1, 2) => Ok(1),
        (2..=15, 1) => Ok(domain as usize),
        (16, 1) => Ok(16),
        (16, 2) => Ok(17),
        _ => Err(Error::Unsupported),
    }
}
fn publisher(epoch: u64) -> Publisher {
    Publisher {
        object: ObjectKey {
            id: 0x43414350,
            generation: epoch,
        },
        controller_epoch: epoch,
    }
}
pub fn init(boot: u64) -> Result<(), Error> {
    with(|s| {
        if s.boot != 0 {
            return if s.boot == boot {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let model = ModelBinding {
            generation: 1,
            model_hash: Sha256::digest(abi::model_bytes()).into(),
            schema_hash: Sha256::digest(include_bytes!("../../crates/prototype/src/features.rs"))
                .into(),
        };
        s.registry.initialize(boot, publisher(1), model)?;
        s.boot = boot;
        s.started = now();
        crate::domain_evidence::initialize(boot, model);
        Ok(())
    })
}
pub fn register(family: Family) -> Result<(), Error> {
    with(|s| {
        let i = family_index(family.domain, family.kind)?;
        if let Some(old) = s.owner.families[i] {
            return if old.domain == family.domain
                && old.kind == family.kind
                && core::ptr::fn_addr_eq(old.target, family.target)
                && core::ptr::fn_addr_eq(old.observe, family.observe)
                && core::ptr::fn_addr_eq(old.current, family.current)
                && core::ptr::fn_addr_eq(old.legal, family.legal)
                && core::ptr::fn_addr_eq(old.target_features, family.target_features)
                && core::ptr::fn_addr_eq(old.apply, family.apply)
                && core::ptr::fn_addr_eq(old.reconcile, family.reconcile)
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        s.owner.families[i] = Some(family);
        crate::domain_evidence::registered(i);
        Ok(())
    })
}
pub fn register_dependencies(consumer: u16, resolver: DependencyResolver) -> Result<(), Error> {
    if !matches!(consumer, 1 | 4 | 8 | 10) {
        return Err(Error::Unsupported);
    }
    with(|s| {
        let slot = &mut s.owner.dependencies[usize::from(consumer - 1)];
        if let Some(old) = *slot {
            return if core::ptr::fn_addr_eq(old, resolver) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        *slot = Some(resolver);
        DEPENDENCY_RESOLVERS[usize::from(consumer - 1)].store(resolver as usize, Ordering::Release);
        Ok(())
    })
}
/// Confirm the exact APPLIED version to the owner of real resource grants.
/// The callback must be idempotent and nonblocking. Busy/Again/NotReady retain
/// the receipt for retry; another policy for this object cannot replace it.
/// Existing grants keep their own confirmation across later policy versions.
pub fn register_execution_observer(domain: u16, observer: ExecutionObserver) -> Result<(), Error> {
    if !matches!(domain, 5 | 9) {
        return Err(Error::Unsupported);
    }
    with(|s| {
        let slot = &mut s.owner.execution_observers[usize::from(domain - 1)];
        if let Some(old) = *slot {
            return if core::ptr::fn_addr_eq(old, observer) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if s.owner
            .desired
            .iter()
            .flatten()
            .any(|d| d.action.domain() == domain)
        {
            return Err(Error::Conflict);
        }
        *slot = Some(observer);
        Ok(())
    })
}
fn execution_blocks_replacement(d: Desired) -> bool {
    !d.state.terminal() || d.state == ExecutionState::Applied && !d.execution_observed
}
fn observe_execution(s: &mut State, d: &mut Desired) {
    if d.state != ExecutionState::Applied || d.execution_observed {
        return;
    }
    let result = s.owner.execution_observers[usize::from(d.action.domain() - 1)]
        .map_or(Ok(()), |observer| observer(d.apply.target, d.stamp.version));
    match result {
        Ok(()) => d.execution_observed = true,
        Err(Error::Busy | Error::Again | Error::NotReady | Error::Stale | Error::NotFound) => {}
        Err(error) => {
            // The resource already exists. Preserve its real APPLIED receipt
            // and obligations while stopping further optimization on a broken
            // owner-confirmation contract.
            s.registry.stop_optimization();
            crate::domain_evidence::observer_failed(d.action.domain(), d.stamp.version, error);
        }
    }
}
/// Call while holding the actual prerequisite owner's resource gate, after
/// checking its initialized baseline, ownership, current capacity and usage.
/// Existing in-flight completion/recovery must not pass through this new-work gate.
pub fn admit_dependency(prerequisite: Prerequisite, consumer: u16, at: u64) -> Result<u64, Error> {
    ADMISSION.admit(prerequisite, consumer, at)
}
/// Resolve before taking a consumer lock. Resolution validates initialized
/// baseline owners; this method never takes the coordinator/policy gate.
pub fn admit_dependencies(consumer: u16, target: ObjectKey) -> Result<(), Error> {
    let address = DEPENDENCY_RESOLVERS
        .get(usize::from(
            consumer.checked_sub(1).ok_or(Error::Unsupported)?,
        ))
        .ok_or(Error::Unsupported)?
        .load(Ordering::Acquire);
    if address == 0 {
        return Err(Error::NotReady);
    }
    // Only register_dependencies writes a statically typed function address;
    // release/acquire publication prevents observing a partially installed resolver.
    let resolver: DependencyResolver = unsafe { core::mem::transmute(address) };
    for prerequisite in resolver(target)?.into_iter().flatten() {
        admit_dependency(prerequisite, consumer, now())?;
    }
    Ok(())
}
fn bind_dependencies(
    owner: &Owner,
    action: Action,
    target: ObjectKey,
    at: u64,
) -> Result<[Option<BoundDependency>; 2], Error> {
    if !matches!(action.domain(), 1 | 4 | 8 | 10) || matches!(action, Action::ControlSet(_)) {
        return Ok([None; 2]);
    }
    let resolver = owner.dependencies[usize::from(action.domain() - 1)].ok_or(Error::NotReady)?;
    let mut bound = [None; 2];
    for (i, prerequisite) in resolver(target)?.into_iter().enumerate() {
        let Some(prerequisite) = prerequisite else {
            continue;
        };
        if !policy::dependency_allowed(prerequisite.domain, action.domain()) {
            return Err(Error::Unsupported);
        }
        let f = owner.families[family_index(prerequisite.domain, 1)?].ok_or(Error::NotReady)?;
        let current = (f.current)(prerequisite.domain, 1, prerequisite.target)?;
        (f.legal)(current, prerequisite.target, at)?;
        let version = admit_dependency(prerequisite, action.domain(), at)?;
        bound[i] = Some(BoundDependency {
            prerequisite,
            version,
        });
    }
    Ok(bound)
}
pub fn publish_context(context: Context) -> Result<(), Error> {
    with(|s| {
        if context.core_generation == 0
            || context.ledger_generation == 0
            || context.control_mask & context.business_mask != 0
        {
            return Err(Error::Conflict);
        }
        if context.core_generation < s.owner.context.core_generation
            || context.ledger_generation < s.owner.context.ledger_generation
        {
            return Err(Error::Stale);
        }
        s.owner.context = context;
        Ok(())
    })
}
fn locate(owner: &Owner, action: Action, key: ObjectKey) -> Option<usize> {
    owner.desired.iter().position(|d| {
        d.is_some_and(|d| {
            d.action.domain() == action.domain()
                && d.action.kind() == action.kind()
                && d.apply.target == key
        })
    })
}
fn tiers(current: Action) -> ([Option<Action>; 32], usize) {
    let mut out = [None; 32];
    let mut n = 0;
    let mut add = |a| {
        out[n] = Some(a);
        n += 1;
    };
    match current {
        Action::CpuWeight(_) => {
            for v in [1, 2, 4, 8] {
                add(Action::CpuWeight(v));
            }
        }
        Action::ControlSet(mask) => {
            add(Action::ControlSet(mask));
            add(Action::ControlSet(mask ^ 4));
        }
        Action::SpawnTokens(_) => {
            for v in [1, 2, 4, 8] {
                add(Action::SpawnTokens(v));
            }
        }
        Action::Cache { .. } => {
            for (pages, batch) in [(64, 4), (256, 16), (1024, 32), (4096, 64)] {
                add(Action::Cache { pages, batch });
            }
        }
        Action::Filesystem { .. } => {
            for (readahead, flush) in [(0, 4), (2, 8), (8, 16), (16, 32)] {
                add(Action::Filesystem { readahead, flush });
            }
        }
        Action::Ipc { .. } => {
            for (budget, batch) in [(8, 1), (32, 4), (64, 8), (128, 16)] {
                add(Action::Ipc { budget, batch });
            }
        }
        Action::IrqTarget(_) => {
            for v in 0..4 {
                add(Action::IrqTarget(v));
            }
        }
        Action::SoftCoalesce(_) => {
            for v in [0, 50, 200, 1000] {
                add(Action::SoftCoalesce(v));
            }
        }
        Action::ServiceBatch(_) => {
            for v in [1, 2, 4, 8] {
                add(Action::ServiceBatch(v));
            }
        }
        Action::IoShare(_) => {
            for v in [100, 250, 500, 750] {
                add(Action::IoShare(v));
            }
        }
        Action::TxBatch(_) => {
            for v in [1, 4, 8, 16] {
                add(Action::TxBatch(v));
            }
        }
        Action::NotifyBatch(_) => {
            for v in [1, 2, 4, 8] {
                add(Action::NotifyBatch(v));
            }
        }
        Action::UnauthRate(_) => {
            for v in [4, 8, 16, 32] {
                add(Action::UnauthRate(v));
            }
        }
        Action::BackgroundBudget(_) => {
            for v in [50, 100, 200, 400] {
                add(Action::BackgroundBudget(v));
            }
        }
        Action::RecoveryRecipe(_) => {
            for v in 0..3 {
                add(Action::RecoveryRecipe(v));
            }
        }
        Action::ConsoleBatch(_) => {
            for v in [1, 8, 32, 64] {
                add(Action::ConsoleBatch(v));
            }
        }
        Action::OfferCpu(_) => {
            for v in [100, 250, 500, 1000] {
                add(Action::OfferCpu(v));
            }
        }
        Action::Placement(_) => {
            for v in 0..3 {
                add(Action::Placement(v));
            }
        }
    }
    (out, n)
}
fn categorical(action: Action) -> bool {
    matches!(
        action,
        Action::IrqTarget(_) | Action::RecoveryRecipe(_) | Action::Placement(_)
    )
}
fn queued_control_wcet_us(s: &State, active_family: usize, at: u64) -> u64 {
    // The current evaluation has not started yet. Other released slots count
    // only when their registered owner exposes an actual, unblocked object.
    // Each mandatory evaluation includes its frozen 2 ms + 0.5 ms bound.
    let mut jobs = 1u64;
    for index in 0..18 {
        if index == active_family || s.due[index] > at {
            continue;
        }
        let Some(f) = s.owner.families[index] else {
            continue;
        };
        let Some(target) = (f.target)(f.domain, f.kind, s.cursor[index])
            .or_else(|| (f.target)(f.domain, f.kind, 0))
        else {
            continue;
        };
        let Ok(current) = (f.current)(f.domain, f.kind, target) else {
            continue;
        };
        if locate(&s.owner, current, target)
            .and_then(|i| s.owner.desired[i])
            .is_some_and(execution_blocks_replacement)
        {
            continue;
        }
        jobs += 1;
    }
    jobs * 2_500
}
pub fn next(controller_epoch: u64) -> Result<Option<[u64; 512]>, Error> {
    with(|s| {
        if s.boot == 0 || s.job.is_some() || s.registry.optimization_stopped() {
            return Ok(None);
        }
        let started = now();
        if s.registry.publisher() != publisher(controller_epoch) {
            s.registry
                .change_publisher(s.registry.publisher(), publisher(controller_epoch))?;
        }
        let start_cursor = s.family_cursor;
        for turn in 0..18 {
            let index = (start_cursor + turn) % 18;
            if started < s.due[index] {
                continue;
            }
            let Some(f) = s.owner.families[index] else {
                continue;
            };
            s.due[index] = started.saturating_add(if index == 1 || index == 16 {
                1_000_000_000
            } else {
                WINDOW_NS
            });
            s.family_cursor = (index + 1) % 18;
            let ordinal = s.cursor[index];
            let target =
                (f.target)(f.domain, f.kind, ordinal).or_else(|| (f.target)(f.domain, f.kind, 0));
            s.cursor[index] = if (f.target)(f.domain, f.kind, ordinal + 1).is_some() {
                ordinal + 1
            } else {
                0
            };
            let Some(target) = target else {
                continue;
            };
            let current = match (f.current)(f.domain, f.kind, target) {
                Ok(v) => v,
                Err(
                    Error::Busy | Error::Again | Error::NotReady | Error::Stale | Error::NotFound,
                ) => continue,
                Err(e) => return Err(e),
            };
            let observed = match (f.observe)(f.domain, target) {
                Ok(v) => v,
                Err(Error::Busy | Error::Again | Error::NotReady) => continue,
                Err(e) => return Err(e),
            };
            let old = locate(&s.owner, current, target).and_then(|i| s.owner.desired[i]);
            if old.is_some_and(execution_blocks_replacement) {
                continue;
            }
            let dependencies = match bind_dependencies(&s.owner, current, target, started) {
                Ok(v) => v,
                Err(
                    Error::Busy | Error::Again | Error::NotReady | Error::Conflict | Error::Stale,
                ) => continue,
                Err(e) => return Err(e),
            };
            let (options, n) = tiers(current);
            let mut legal = [None; 32];
            let mut legal_count = 0;
            for option in options[..n].iter().flatten() {
                if (f.legal)(*option, target, started).is_ok() {
                    legal[legal_count] = Some(*option);
                    legal_count += 1;
                }
            }
            legal[..legal_count].sort_unstable_by_key(|a| a.map(Action::order));
            let Some(current_index) = legal[..legal_count]
                .iter()
                .position(|a| *a == Some(current))
            else {
                continue;
            };
            let hold = if matches!(current, Action::ControlSet(_) | Action::UnauthRate(_)) {
                1_000_000_000
            } else {
                WINDOW_NS
            };
            let held = started.saturating_sub(old.map_or(s.started, |d| d.last_change)) >= hold;
            let queued_wcet_us = queued_control_wcet_us(s, index, started);
            let mut choices = [Candidate {
                action: current,
                features: RawFeatures::default(),
            }; 32];
            let mut count = 0;
            for (i, action) in legal[..legal_count].iter().flatten().copied().enumerate() {
                if action != current
                    && (old.is_some_and(|d| d.frozen)
                        || (!categorical(action) && (!held || i.abs_diff(current_index) > 1)))
                {
                    continue;
                }
                let mut target_features = match (f.target_features)(action, target) {
                    Ok(v) => v,
                    Err(Error::Busy | Error::Again | Error::NotReady) => continue,
                    Err(e) => return Err(e),
                };
                if let Action::ControlSet(mask) = action {
                    let cores = u64::from(mask.count_ones());
                    if cores == 0 {
                        return Err(Error::Range);
                    }
                    target_features.values[2] = Some(queued_wcet_us.div_ceil(cores));
                }
                let mut common = s.owner.context.common;
                common[2] = queued_wcet_us / 2_500;
                common[6] = 0;
                choices[count] = Candidate {
                    action,
                    features: RawFeatures {
                        common,
                        domain: observed,
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
            if count == 0 {
                continue;
            }
            let sequence = s.sequence.checked_add(1).ok_or(Error::Overflow)?;
            let snapshot = Snapshot {
                sequence,
                taken_ns: started,
                ledger_generation: s.owner.context.ledger_generation,
                core_generation: s.owner.context.core_generation,
            };
            let set = CandidateSet::new(
                snapshot,
                target,
                s.registry.model(),
                &choices[..count],
                Some(current),
            )?;
            s.registry.register(publisher(controller_epoch), &set)?;
            let mut input = [0u64; 512];
            input[..16].copy_from_slice(&[
                abi::INPUT_MAGIC,
                3,
                sequence,
                controller_epoch,
                started,
                cyxia_arch_aarch64::timer::frequency(),
                snapshot.core_generation,
                snapshot.ledger_generation,
                u64::from(f.domain),
                u64::from(f.kind),
                target.id,
                target.generation,
                s.registry.version(),
                set.model.generation,
                s.boot,
                set.len() as u64,
            ]);
            for (at, hash) in [(16, set.model.model_hash), (20, set.hash())] {
                for i in 0..4 {
                    input[at + i] = u64::from_le_bytes(hash[i * 8..i * 8 + 8].try_into().unwrap());
                }
            }
            let raw = set.get(0).ok_or(Error::NotReady)?.features;
            input[24..32].copy_from_slice(&raw.common);
            input[32..36].copy_from_slice(&raw.domain);
            input[36..40].copy_from_slice(&[
                sequence,
                sequence,
                sequence,
                if current.one_shot() {
                    0
                } else {
                    started.checked_add(POLICY_NS).ok_or(Error::Overflow)?
                },
            ]);
            for (i, c) in set.iter().enumerate() {
                let at = 64 + i * 10;
                let mut p = [0; 16];
                input[at] = policy_wire::encode_payload(c.action, i as u16, &mut p)? as u64;
                input[at + 1] = u64::from_le_bytes(p[..8].try_into().unwrap());
                input[at + 2] = u64::from_le_bytes(p[8..].try_into().unwrap());
                for j in 0..4 {
                    if let Some(v) = c.features.target.values[j] {
                        input[at + 3 + j] = v;
                        input[at + 7] |= 1 << j;
                    }
                }
                input[at + 8] = c.features.control_capacity.unwrap_or(0);
            }
            input[400..404].copy_from_slice(&[
                s.owner.context.control_mask,
                s.owner.context.business_mask,
                s.owner.context.healthy_mask,
                s.owner.context.draining_mask,
            ]);
            let mut prior = [0; 16];
            input[404] = policy_wire::encode_payload(current, 0, &mut prior)? as u64;
            input[405] = u64::from_le_bytes(prior[..8].try_into().unwrap());
            input[406] = u64::from_le_bytes(prior[8..].try_into().unwrap());
            for (i, binding) in dependencies.into_iter().enumerate() {
                if let Some(binding) = binding {
                    input[408 + i * 4..412 + i * 4].copy_from_slice(&[
                        u64::from(binding.prerequisite.domain),
                        binding.prerequisite.target.id,
                        binding.prerequisite.target.generation,
                        binding.version,
                    ]);
                }
            }
            let evidence = (sequence as usize - 1) % crate::domain_evidence::SLOTS;
            let mut hash = Sha256::new();
            for value in input {
                hash.update(value.to_le_bytes());
            }
            crate::domain_evidence::begin(evidence, &input, hash.finalize().into());
            s.sequence = sequence;
            s.job = Some(Job {
                set,
                sequence,
                controller: controller_epoch,
                base_version: s.registry.version(),
                started,
                encode_ns: now().saturating_sub(started),
                evidence,
                dependencies,
            });
            return Ok(Some(input));
        }
        Ok(None)
    })
}
struct NativeClock;
impl policy::Clock for NativeClock {
    fn now_ns(&mut self) -> u64 {
        now()
    }
}
struct Executor<'a> {
    owner: &'a mut Owner,
    evidence: usize,
    job: u64,
    boot: u64,
    publication_started: u64,
    dependencies: [Option<BoundDependency>; 2],
}
impl policy::Executor for Executor<'_> {
    fn check(&mut self, d: Decision, _: &policy::RegisteredSet, now: u64) -> Result<(), Error> {
        let c = self.owner.context;
        if d.envelope.core_generation != c.core_generation
            || d.envelope.ledger_generation != c.ledger_generation
        {
            return Err(Error::Stale);
        }
        let f = self.owner.families[family_index(d.action.domain(), d.action.kind())?]
            .ok_or(Error::Unsupported)?;
        (f.legal)(d.action, d.envelope.target, now)?;
        if bind_dependencies(self.owner, d.action, d.envelope.target, now)? != self.dependencies {
            return Err(Error::Stale);
        }
        if let Some(i) = locate(self.owner, d.action, d.envelope.target) {
            let old = self.owner.desired[i].ok_or(Error::Stale)?;
            if execution_blocks_replacement(old) {
                return Err(Error::Busy);
            }
            let current = (f.current)(d.action.domain(), d.action.kind(), d.envelope.target)?;
            if old.frozen && current != d.action {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn prepare(&mut self, plan: &Plan, _: u64) -> Result<(), Error> {
        self.owner.prepared_count = 0;
        for d in plan.iter() {
            let i = locate(self.owner, d.action, d.envelope.target)
                .or_else(|| {
                    self.owner.desired.iter().enumerate().position(|(i, d)| {
                        d.is_none()
                            && !self.owner.prepared[..self.owner.prepared_count].contains(&i)
                    })
                })
                .ok_or(Error::Capacity)?;
            self.owner.prepared[self.owner.prepared_count] = i;
            self.owner.prepared_count += 1;
        }
        Ok(())
    }
    fn revalidate(&mut self, plan: &Plan, now: u64) -> Result<(), Error> {
        for d in plan.iter() {
            let c = self.owner.context;
            if d.envelope.core_generation != c.core_generation
                || d.envelope.ledger_generation != c.ledger_generation
            {
                return Err(Error::Stale);
            }
            let f = self.owner.families[family_index(d.action.domain(), d.action.kind())?]
                .ok_or(Error::Unsupported)?;
            (f.legal)(d.action, d.envelope.target, now)?;
            if bind_dependencies(self.owner, d.action, d.envelope.target, now)? != self.dependencies
            {
                return Err(Error::Stale);
            }
        }
        Ok(())
    }
    fn publish(&mut self, plan: &Plan, version: u64, at: u64) -> Result<(), Error> {
        if self.owner.prepared_count != plan.len() {
            return Err(Error::Conflict);
        }
        let mut stamps = [PolicyStamp::default(); 16];
        let mut previous = [Action::CpuWeight(1); 16];
        for (index, d) in plan.iter().enumerate() {
            stamps[index] = PolicyStamp::new(
                version,
                if d.action.one_shot() {
                    d.envelope
                        .expires_local_ns
                        .checked_sub(WINDOW_NS)
                        .ok_or(Error::Format)?
                } else {
                    plan.header
                        .active_until_local_ns
                        .checked_sub(POLICY_NS)
                        .ok_or(Error::Format)?
                },
                at,
            )?;
            let f = self.owner.families[family_index(d.action.domain(), d.action.kind())?]
                .ok_or(Error::Unsupported)?;
            previous[index] = (f.current)(d.action.domain(), d.action.kind(), d.envelope.target)?;
        }
        let commit_ns = now();
        if commit_ns < at {
            return Err(Error::Range);
        }
        if plan.iter().any(|d| commit_ns > d.envelope.expires_local_ns) {
            return Err(Error::Expired);
        }
        if commit_ns.saturating_sub(self.publication_started) > policy::PUBLICATION_BUDGET_NS {
            return Err(Error::Budget);
        }
        for (index, d) in plan.iter().enumerate() {
            let slot = self.owner.prepared[index];
            let old = self.owner.desired[slot];
            let stamp = stamps[index];
            self.owner.desired[slot] = Some(Desired {
                action: d.action,
                previous: previous[index],
                apply: ApplyId {
                    boot_epoch: self.boot,
                    controller_epoch: plan.header.controller_epoch,
                    plan_seq: plan.header.plan_seq,
                    action_index: index as u16,
                    target: d.envelope.target,
                },
                stamp,
                state: ExecutionState::Pending,
                execution_observed: false,
                started: false,
                published: commit_ns,
                last_change: old.map_or(0, |d| d.last_change),
                direction: old.map_or(0, |d| d.direction),
                reversal_start: old.map_or(at, |d| d.reversal_start),
                reversals: old.map_or(0, |d| d.reversals),
                frozen: old.is_some_and(|d| d.frozen),
                evidence: self.evidence,
                job: self.job,
                dependencies: self.dependencies,
                core_generation: d.envelope.core_generation,
                ledger_generation: d.envelope.ledger_generation,
            });
            ADMISSION.publish(
                slot,
                Prerequisite {
                    domain: d.action.domain(),
                    target: d.envelope.target,
                },
                version,
                stamp.installed_until_ns,
                ExecutionState::Pending,
            );
        }
        self.owner.prepared_count = 0;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        self.owner.prepared_count = 0;
    }
}
pub fn accept(output: &[u64; 512], cpu_ns: u64) -> Result<u64, Error> {
    with(|s| {
        let job = s.job.take().ok_or(Error::Stale)?;
        let begin = now();
        let mut selected = u64::MAX;
        let mut decoded_ns = None;
        let result = (|| {
            if begin < job.started
                || begin - job.started > 50_000_000
                || cpu_ns.checked_add(job.encode_ns).ok_or(Error::Overflow)? > 2_000_000
            {
                return Err(Error::Expired);
            }
            if job.set.snapshot.core_generation != s.owner.context.core_generation
                || job.set.snapshot.ledger_generation != s.owner.context.ledger_generation
            {
                return Err(Error::Stale);
            }
            if output[..4] != [abi::OUTPUT_MAGIC, 3, job.sequence, job.controller]
                || output[6] != job.set.len() as u64
                || output[7] != s.boot
            {
                return Err(Error::Format);
            }
            selected = output[4];
            let index = usize::try_from(selected).map_err(|_| Error::Range)?;
            let candidate = job.set.get(index).ok_or(Error::Range)?;
            let mut best = 0;
            let mut best_score = i16::MIN;
            for i in 0..32 {
                let score = ((output[8 + i / 4] >> (16 * (i % 4))) as u16) as i16;
                if i < job.set.len() {
                    if i == 0 || score > best_score {
                        best = i;
                        best_score = score;
                    }
                } else if score != 0 {
                    return Err(Error::Format);
                }
            }
            if best != index {
                return Err(Error::Conflict);
            }
            let header = PlanHeader {
                plan_seq: job.sequence,
                base_plan_version: job.base_version,
                active_model_generation: job.set.model.generation,
                controller_epoch: job.controller,
                snapshot_seq: job.set.snapshot.sequence,
                active_until_local_ns: if candidate.action.one_shot() {
                    0
                } else {
                    job.started.checked_add(POLICY_NS).ok_or(Error::Overflow)?
                },
            };
            let d = Decision {
                action: candidate.action,
                candidate_index: index as u16,
                envelope: Envelope {
                    controller_epoch: job.controller,
                    decision_seq: job.sequence,
                    snapshot_seq: job.set.snapshot.sequence,
                    target: job.set.target,
                    ledger_generation: job.set.snapshot.ledger_generation,
                    core_generation: job.set.snapshot.core_generation,
                    expires_local_ns: job.started.checked_add(WINDOW_NS).ok_or(Error::Overflow)?,
                    model_hash: job.set.model.model_hash,
                    candidate_set_hash: job.set.hash(),
                },
            };
            let mut expected = [0; 384];
            let n = policy_wire::encode_plan(header, &[d], &mut expected)?;
            let mut bytes = [0u8; 384];
            for (i, word) in output[16..64].iter().enumerate() {
                bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
            if output[5] != n as u64 || bytes != expected || output[64..].iter().any(|v| *v != 0) {
                return Err(Error::Conflict);
            }
            let decoding = now().checked_sub(begin).ok_or(Error::Range)?;
            decoded_ns = Some(decoding);
            if cpu_ns
                .checked_add(job.encode_ns)
                .and_then(|v| v.checked_add(decoding))
                .ok_or(Error::Overflow)?
                > 2_000_000
            {
                return Err(Error::Budget);
            }
            let mut executor = Executor {
                owner: &mut s.owner,
                evidence: job.evidence,
                job: job.sequence,
                boot: s.boot,
                publication_started: begin,
                dependencies: job.dependencies,
            };
            let receipt = s.registry.submit_bounded(
                publisher(job.controller),
                &bytes[..n],
                begin,
                &mut NativeClock,
                &mut executor,
            )?;
            if receipt.version == 0 {
                return Err(match receipt.state() {
                    ExecutionState::Failed(e) => e,
                    _ => Error::Conflict,
                });
            }
            Ok(receipt.version)
        })();
        let elapsed = now().saturating_sub(begin);
        if elapsed > policy::PUBLICATION_BUDGET_NS {
            s.registry.stop_optimization();
        }
        match result {
            Ok(version) => {
                crate::domain_evidence::finish(
                    job.evidence,
                    job.sequence,
                    cpu_ns,
                    job.encode_ns,
                    decoded_ns.unwrap_or(elapsed),
                    elapsed,
                    version,
                    ExecutionState::Pending,
                    selected,
                    Some(output),
                );
                Ok(version)
            }
            Err(error) => {
                crate::domain_evidence::finish(
                    job.evidence,
                    job.sequence,
                    cpu_ns,
                    job.encode_ns,
                    decoded_ns.unwrap_or(elapsed),
                    elapsed,
                    0,
                    ExecutionState::Failed(error),
                    selected,
                    Some(output),
                );
                Err(error)
            }
        }
    })
}
pub fn pending_job() -> Result<bool, Error> {
    with(|s| Ok(s.job.is_some()))
}
pub fn abort(cpu_ns: u64) -> Result<(), Error> {
    with(|s| {
        if let Some(job) = s.job.take() {
            crate::domain_evidence::finish(
                job.evidence,
                job.sequence,
                cpu_ns,
                job.encode_ns,
                0,
                0,
                0,
                ExecutionState::Failed(Error::Expired),
                u64::MAX,
                None,
            );
            crate::domain_evidence::aborted();
        }
        Ok(())
    })
}
pub fn poll(at: u64) -> Result<(), Error> {
    with(|s| {
        for scanned in 0..s.owner.desired.len() {
            let i = (s.owner.poll_cursor + scanned) % s.owner.desired.len();
            let Some(mut d) = s.owner.desired[i] else {
                continue;
            };
            if d.state.terminal() && !execution_blocks_replacement(d) {
                continue;
            }
            s.owner.poll_cursor = (i + 1) % s.owner.desired.len();
            if d.state == ExecutionState::Applied {
                observe_execution(s, &mut d);
                s.owner.desired[i] = Some(d);
                break;
            }
            let f = s.owner.families[family_index(d.action.domain(), d.action.kind())?]
                .ok_or(Error::Unsupported)?;
            let was_started = d.started;
            let dependency_status = if d.started {
                Ok(())
            } else if d.core_generation != s.owner.context.core_generation
                || d.ledger_generation != s.owner.context.ledger_generation
            {
                Err(Error::Stale)
            } else {
                bind_dependencies(&s.owner, d.action, d.apply.target, at).and_then(|actual| {
                    if actual == d.dependencies {
                        Ok(())
                    } else {
                        Err(Error::Stale)
                    }
                })
            };
            let result = if let Err(error) = dependency_status {
                Err(error)
            } else if d.started {
                (f.reconcile)(d.action, d.apply, d.stamp, at)
            } else {
                d.started = true;
                (f.apply)(d.action, d.apply, d.stamp, at)
            };
            d.state = match result {
                Ok(state) => state,
                Err(Error::Busy | Error::Again) => {
                    d.started = was_started;
                    ExecutionState::Pending
                }
                Err(Error::Io | Error::NotReady) => ExecutionState::Unknown,
                Err(error) => ExecutionState::Failed(error),
            };
            let deadline = match d.action {
                Action::ControlSet(_) => 200_000_000,
                Action::RecoveryRecipe(_) => 1_000_000_000,
                Action::Placement(_) => 4_000_000_000,
                _ => 50_000_000,
            };
            if !d.state.terminal() && at.saturating_sub(d.published) >= deadline {
                if d.started {
                    d.state = ExecutionState::Unknown;
                } else {
                    // Busy/Again before admission is an authoritative no-effect
                    // refusal. Do not invent an in-flight operation to reconcile.
                    d.state = ExecutionState::Failed(Error::Again);
                }
            }
            if d.state == ExecutionState::Applied && d.previous != d.action {
                d.last_change = at;
                let direction = match d.action.order().cmp(&d.previous.order()) {
                    core::cmp::Ordering::Greater => 1,
                    core::cmp::Ordering::Less => -1,
                    _ => 0,
                };
                if at.saturating_sub(d.reversal_start) >= 1_000_000_000 {
                    d.reversal_start = at;
                    d.reversals = 0;
                }
                if direction != 0 && d.direction != 0 && direction != d.direction {
                    d.reversals = d.reversals.saturating_add(1);
                    if d.reversals > 4 {
                        d.frozen = true;
                    }
                }
                if direction != 0 {
                    d.direction = direction;
                }
            }
            s.owner.desired[i] = Some(d);
            ADMISSION.publish(
                i,
                Prerequisite {
                    domain: d.action.domain(),
                    target: d.apply.target,
                },
                d.stamp.version,
                d.stamp.installed_until_ns,
                d.state,
            );
            s.registry.reconcile(d.apply, d.stamp.version, d.state)?;
            crate::domain_evidence::progress(d.evidence, d.job, d.stamp.version, d.state, at);
            observe_execution(s, &mut d);
            s.owner.desired[i] = Some(d);
            break;
        }
        // Reclaim only an owner-proven dead, terminal object; unknown work is pinned.
        for i in 0..s.owner.desired.len() {
            if let Some(d) = s.owner.desired[i]
                && d.state.terminal()
            {
                let f = s.owner.families[family_index(d.action.domain(), d.action.kind())?]
                    .ok_or(Error::Unsupported)?;
                if matches!(
                    (f.current)(d.action.domain(), d.action.kind(), d.apply.target),
                    Err(Error::Stale | Error::NotFound)
                ) {
                    s.owner.desired[i] = None;
                    ADMISSION.retire(i);
                    break;
                }
            }
        }
        Ok(())
    })
}
