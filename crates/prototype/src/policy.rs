//! Protected candidate registration and transactional plan publication.
use crate::{
    domains::{Action, ApplyId, Error, ObjectKey, POLICY_NS, PolicyStamp, WINDOW_NS},
    features::{self, RawFeatures},
    learning::governance::{CanaryPermit, CommitGate},
    policy_wire::{self, Decision, Plan},
};
use sha2::{Digest, Sha256};

pub const MAX_CANDIDATES: usize = 32;
pub const MAX_REGISTERED: usize = 64;
pub const MAX_PENDING: usize = 64;
pub const TERMINAL_HISTORY: usize = 256;
pub const PUBLICATION_BUDGET_NS: u64 = 500_000;

/// Filter one immutable tier snapshot without changing the preparation
/// semantics of the scalar legality callback. A transient owner result aborts
/// the tier so callers retry the same candidate-set identity; hard rejection
/// removes only that action while preserving order.
pub fn collect_legal_actions(
    options: &[Option<crate::domains::Action>],
    output: &mut [Option<crate::domains::Action>],
    mut legal: impl FnMut(crate::domains::Action) -> Result<(), Error>,
) -> Result<usize, Error> {
    if output.len() < options.len() {
        return Err(Error::Capacity);
    }
    let mut count = 0;
    for option in options.iter().flatten().copied() {
        match legal(option) {
            Ok(()) => {
                output[count] = Some(option);
                count += 1;
            }
            Err(
                error @ (Error::Busy
                | Error::Again
                | Error::NotReady
                | Error::Stale
                | Error::NotFound),
            ) => return Err(error),
            Err(_) => {}
        }
    }
    Ok(count)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prerequisite {
    pub domain: u16,
    pub target: ObjectKey,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundDependency {
    pub prerequisite: Prerequisite,
    /// Zero denotes the owner's verified, initialized deterministic baseline.
    pub version: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ModelBinding {
    pub generation: u64,
    pub model_hash: [u8; 32],
    pub schema_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub sequence: u64,
    pub taken_ns: u64,
    pub ledger_generation: u64,
    pub core_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub action: Action,
    pub features: RawFeatures,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateEntry {
    action: Action,
    target: crate::features::TargetFeatures,
    control_capacity: Option<u64>,
}
#[derive(Clone, Copy, Debug)]
pub struct CandidateSet {
    pub snapshot: Snapshot,
    pub target: ObjectKey,
    pub model: ModelBinding,
    // Candidate construction requires common/domain features to be identical.
    // Store those bytes once rather than copying them through all 32 bounded
    // slots; get/iter reconstruct the unchanged public Candidate value.
    common: [u64; 8],
    domain: [u64; 4],
    domain_present: u8,
    entries: [Option<CandidateEntry>; MAX_CANDIDATES],
    count: usize,
    digest: [u8; 32],
    canary: Option<CanaryPermit>,
}
// This value crosses the protected kernel/EL0 boundary and is copied into a
// retained job. Keeping the complete 32-candidate representation within one
// page is both a bounded-memory contract and a native preparation-cost gate.
const _: () = assert!(core::mem::size_of::<CandidateSet>() <= 4096);
#[inline(always)]
fn append_canonical(dst: &mut [u8], used: &mut usize, src: &[u8]) -> Result<(), Error> {
    let end = used.checked_add(src.len()).ok_or(Error::Capacity)?;
    let target = dst.get_mut(*used..end).ok_or(Error::Capacity)?;
    target.copy_from_slice(src);
    *used = end;
    Ok(())
}
impl CandidateSet {
    pub fn new(
        snapshot: Snapshot,
        target: ObjectKey,
        model: ModelBinding,
        choices: &[Candidate],
        current: Option<Action>,
    ) -> Result<Self, Error> {
        if choices.is_empty() || choices.len() > MAX_CANDIDATES {
            return Err(Error::Capacity);
        }
        if snapshot.sequence == 0
            || snapshot.ledger_generation == 0
            || snapshot.core_generation == 0
            || target.id == 0
            || target.generation == 0
            || model.generation == 0
        {
            return Err(Error::Stale);
        }
        let first = choices[0];
        let mut out = Self {
            snapshot,
            target,
            model,
            common: first.features.common,
            domain: first.features.domain,
            domain_present: first.features.domain_present,
            entries: [None; MAX_CANDIDATES],
            count: 0,
            digest: [0; 32],
            canary: None,
        };
        for candidate in choices {
            features::validate(candidate.action, &candidate.features)?;
            if candidate.action.domain() != first.action.domain()
                || candidate.action.kind() != first.action.kind()
                || candidate.features.common != first.features.common
                || candidate.features.domain != first.features.domain
                || candidate.features.domain_present != first.features.domain_present
            {
                return Err(Error::Conflict);
            }
            if let Some(old) = out.iter().find(|old| old.action == candidate.action) {
                if old != *candidate {
                    return Err(Error::Conflict);
                }
                continue;
            }
            let mut at = out.count;
            while at > 0
                && out.entries[at - 1]
                    .is_some_and(|old| old.action.order() > candidate.action.order())
            {
                out.entries[at] = out.entries[at - 1];
                at -= 1;
            }
            out.entries[at] = Some(CandidateEntry {
                action: candidate.action,
                target: candidate.features.target,
                control_capacity: candidate.features.control_capacity,
            });
            out.count += 1;
        }
        if let Some(current) = current {
            let opening_offer = current == Action::OfferCpu(0)
                && out.count == 1
                && matches!(first.action, Action::OfferCpu(_));
            if !opening_offer && !out.iter().any(|c| c.action == current) {
                return Err(Error::Conflict);
            }
        } else if !first.action.one_shot() || matches!(first.action, Action::ControlSet(_)) {
            return Err(Error::NotReady);
        }
        if first.action.domain() == 14 && !out.iter().any(|c| c.action == Action::RecoveryRecipe(0))
        {
            return Err(Error::Conflict);
        }
        if (first.action.domain(), first.action.kind()) == (16, 2)
            && !out.iter().any(|c| c.action == Action::Placement(2))
        {
            return Err(Error::Conflict);
        }
        out.digest = out.recompute_hash()?;
        Ok(out)
    }
    pub const fn len(&self) -> usize {
        self.count
    }
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub const fn hash(&self) -> [u8; 32] {
        self.digest
    }
    /// Verify this set's immutable entries and current public binding against
    /// its canonical hash without constructing a second candidate array. This
    /// is an integrity check, not model or publication authorization.
    pub fn verify_integrity(&self) -> Result<(), Error> {
        if self.count == 0 || self.count > MAX_CANDIDATES {
            return Err(Error::Capacity);
        }
        if self.recompute_hash()? != self.digest {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub const fn canary_permit(&self) -> Option<CanaryPermit> {
        self.canary
    }
    /// Pure canonical hashing for a verifier; this grants no publication right.
    /// A set already bound to a permit cannot be rebound, even after revocation.
    pub fn hash_for_canary(&self, permit: CanaryPermit) -> Result<[u8; 32], Error> {
        if self.canary.is_some_and(|old| old != permit) {
            return Err(Error::Stale);
        }
        self.recompute_hash_scoped(Some(permit))
    }
    pub fn get(&self, index: usize) -> Option<Candidate> {
        if index >= self.count {
            return None;
        }
        self.entries[index].map(|entry| self.expand(entry))
    }
    pub fn iter(&self) -> impl Iterator<Item = Candidate> + '_ {
        self.entries[..self.count]
            .iter()
            .filter_map(|entry| entry.map(|entry| self.expand(entry)))
    }
    fn expand(&self, entry: CandidateEntry) -> Candidate {
        Candidate {
            action: entry.action,
            features: RawFeatures {
                common: self.common,
                domain: self.domain,
                domain_present: self.domain_present,
                target: entry.target,
                control_capacity: entry.control_capacity,
            },
        }
    }
    fn recompute_hash(&self) -> Result<[u8; 32], Error> {
        self.recompute_hash_scoped(self.canary)
    }
    fn recompute_hash_scoped(&self, canary: Option<CanaryPermit>) -> Result<[u8; 32], Error> {
        // Select the smallest fixed scratch tier that can hold the exact
        // bounded stream. The common single-candidate case no longer clears a
        // maximum-size 5.5 KiB buffer before hashing its ~314 useful bytes.
        let required = 150 + self.count * 164 + usize::from(canary.is_some()) * 121;
        match required {
            0..=512 => self.recompute_hash_bounded::<512>(canary),
            513..=1024 => self.recompute_hash_bounded::<1024>(canary),
            1025..=2048 => self.recompute_hash_bounded::<2048>(canary),
            2049..=4096 => self.recompute_hash_bounded::<4096>(canary),
            _ => self.recompute_hash_bounded::<{ 150 + MAX_CANDIDATES * 164 + 121 }>(canary),
        }
    }
    #[inline(never)]
    fn recompute_hash_bounded<const N: usize>(
        &self,
        canary: Option<CanaryPermit>,
    ) -> Result<[u8; 32], Error> {
        let mut canonical = [0; N];
        let mut used = 0;
        append_canonical(&mut canonical, &mut used, b"CYXIA_CANDIDATES_V1.3\0")?;
        for v in [
            self.snapshot.sequence,
            self.snapshot.taken_ns,
            self.snapshot.ledger_generation,
            self.snapshot.core_generation,
            self.target.id,
            self.target.generation,
            self.model.generation,
            self.count as u64,
        ] {
            append_canonical(&mut canonical, &mut used, &v.to_le_bytes())?;
        }
        append_canonical(&mut canonical, &mut used, &self.model.model_hash)?;
        append_canonical(&mut canonical, &mut used, &self.model.schema_hash)?;
        debug_assert_eq!(used, 150);
        for (index, c) in self.iter().enumerate() {
            append_canonical(&mut canonical, &mut used, &c.action.domain().to_le_bytes())?;
            append_canonical(&mut canonical, &mut used, &c.action.kind().to_le_bytes())?;
            let mut payload = [0; 16];
            let n = policy_wire::encode_payload(c.action, index as u16, &mut payload)?;
            append_canonical(&mut canonical, &mut used, &(n as u16).to_le_bytes())?;
            append_canonical(&mut canonical, &mut used, &payload[..n])?;
            for v in c.features.common.into_iter().chain(c.features.domain) {
                append_canonical(&mut canonical, &mut used, &v.to_le_bytes())?;
            }
            append_canonical(&mut canonical, &mut used, &[c.features.domain_present])?;
            for v in c
                .features
                .target
                .values
                .into_iter()
                .chain([c.features.control_capacity])
            {
                append_canonical(&mut canonical, &mut used, &[u8::from(v.is_some())])?;
                append_canonical(&mut canonical, &mut used, &v.unwrap_or(0).to_le_bytes())?;
            }
        }
        // Both scopes bind raw measurements and their presence mask above.
        // Canary additionally binds this separator, eight u64 little-endian fields in
        // the order below, then the exact 32-byte candidate parameter hash.
        // Permit extensions/replacements therefore cannot revive an old set.
        if let Some(p) = canary {
            append_canonical(&mut canonical, &mut used, b"\0CYXIA_CANARY_SCOPE_V1.3\0")?;
            for value in [
                p.id,
                p.active_generation,
                p.target.id,
                p.target.generation,
                p.start_ns,
                p.expires_ns,
                u64::from(p.windows),
                u64::from(p.quota),
            ] {
                append_canonical(&mut canonical, &mut used, &value.to_le_bytes())?;
            }
            append_canonical(&mut canonical, &mut used, &p.candidate_hash)?;
        }
        #[cfg(feature = "hardware-sha256")]
        if let Some(hash) = cyxia_arch_aarch64::sha256::digest(&canonical[..used]) {
            return Ok(hash);
        }
        Ok(Sha256::digest(&canonical[..used]).into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionState {
    Pending,
    Applied,
    Failed(Error),
    Unknown,
}
impl ExecutionState {
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Failed(_))
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Publisher {
    pub object: ObjectKey,
    pub controller_epoch: u64,
}
/// Opaque proof that one ordinary candidate set was constructed under this
/// registry's current boot, publisher and Active model. The set remains
/// unregistered until `Registry::commit_candidates`, so fallible preparation
/// before that point cannot evict an unrelated retained registration.
pub struct PreparedCandidateSet {
    boot_epoch: u64,
    publisher: Publisher,
    set: CandidateSet,
}
impl PreparedCandidateSet {
    /// Read-only access for scoring and independent pre-registration checks.
    pub const fn candidate_set(&self) -> &CandidateSet {
        &self.set
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlanId {
    pub boot_epoch: u64,
    pub controller_epoch: u64,
    pub plan_seq: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanReceipt {
    pub id: PlanId,
    pub version: u64,
    pub published_ns: u64,
    pub action_count: u16,
    pub actions: [ExecutionState; policy_wire::MAX_ACTIONS],
}
impl PlanReceipt {
    pub fn state(&self) -> ExecutionState {
        let states = &self.actions[..usize::from(self.action_count)];
        if states.contains(&ExecutionState::Unknown) {
            ExecutionState::Unknown
        } else if states.contains(&ExecutionState::Pending) {
            ExecutionState::Pending
        } else if let Some(ExecutionState::Failed(e)) = states
            .iter()
            .find(|s| matches!(s, ExecutionState::Failed(_)))
        {
            ExecutionState::Failed(*e)
        } else {
            ExecutionState::Applied
        }
    }
}
#[derive(Clone, Copy)]
struct StoredPlan {
    receipt: PlanReceipt,
    digest: [u8; 32],
    decisions: [u64; 16],
    targets: [ObjectKey; 16],
    model: Option<ModelBinding>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegistrationPurpose {
    Candidates,
    Baseline,
}

// Every validated Action fits in this private canonical word: five domain
// bits, two kind bits, a 32-bit primary value and a 16-bit secondary value.
// RegisteredSet needs only exact action recovery, not the enum's in-memory
// discriminant. Keeping its bounded action array compact makes registration a
// small copy and keeps the retained table out of the native preparation path's
// cache working set.
const fn pack_registered_action(action: Action) -> u64 {
    let (domain, kind, a, b) = action.order();
    (domain as u64) | ((kind as u64) << 5) | (a << 8) | (b << 40)
}

const fn unpack_registered_action(packed: u64) -> Option<Action> {
    let domain = (packed & 0x1f) as u16;
    let kind = ((packed >> 5) & 0x03) as u16;
    let a = ((packed >> 8) & 0xffff_ffff) as u32;
    let b = ((packed >> 40) & 0xffff) as u16;
    match (domain, kind) {
        (1, 1) => Some(Action::CpuWeight(a as u16)),
        (1, 2) => Some(Action::ControlSet(a as u64)),
        (2, 1) => Some(Action::SpawnTokens(a as u16)),
        (3, 1) => Some(Action::Cache { pages: a, batch: b }),
        (4, 1) => Some(Action::Filesystem {
            readahead: a as u16,
            flush: b,
        }),
        (5, 1) => Some(Action::Ipc {
            budget: a as u16,
            batch: b as u8,
        }),
        (6, 1) => Some(Action::IrqTarget(a as u16)),
        (7, 1) => Some(Action::SoftCoalesce(a as u16)),
        (8, 1) => Some(Action::ServiceBatch(a as u8)),
        (9, 1) => Some(Action::IoShare(a as u16)),
        (10, 1) => Some(Action::TxBatch(a as u8)),
        (11, 1) => Some(Action::NotifyBatch(a as u8)),
        (12, 1) => Some(Action::UnauthRate(a as u16)),
        (13, 1) => Some(Action::BackgroundBudget(a as u16)),
        (14, 1) => Some(Action::RecoveryRecipe(a as u16)),
        (15, 1) => Some(Action::ConsoleBatch(a as u16)),
        (16, 1) => Some(Action::OfferCpu(a as u16)),
        (16, 2) => Some(Action::Placement(a as u16)),
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub struct RegisteredSet {
    pub snapshot: Snapshot,
    pub target: ObjectKey,
    pub model: ModelBinding,
    pub hash: [u8; 32],
    actions: [u64; MAX_CANDIDATES],
    count: usize,
    canary: Option<CanaryPermit>,
    purpose: RegistrationPurpose,
}
impl RegisteredSet {
    pub fn action(&self, index: usize) -> Option<Action> {
        if index >= self.count {
            None
        } else {
            unpack_registered_action(self.actions[index])
        }
    }
    pub const fn canary_permit(&self) -> Option<CanaryPermit> {
        self.canary
    }
    /// A fixed baseline has no model features or scores. Only the protected
    /// baseline executor may authorize this exact registered action.
    pub fn baseline_action(&self) -> Option<Action> {
        if self.purpose == RegistrationPurpose::Baseline {
            self.action(0)
        } else {
            None
        }
    }
    fn validate_model_scope(&self, active: ModelBinding, now_ns: u64) -> Result<(), Error> {
        match self.canary {
            None if self.model == active => Ok(()),
            None => Err(Error::Stale),
            Some(permit) => {
                if permit.id == 0
                    || permit.active_generation != active.generation
                    || self.model.generation != active.generation
                    || self.model.schema_hash != active.schema_hash
                    || permit.candidate_hash == [0; 32]
                    || permit.candidate_hash == active.model_hash
                    || self.model.model_hash != permit.candidate_hash
                    || self.target != permit.target
                    || permit.start_ns >= permit.expires_ns
                    || permit.windows == 0
                    || permit.quota == 0
                    || self.snapshot.taken_ns < permit.start_ns
                    || self.snapshot.taken_ns >= permit.expires_ns
                    || now_ns < permit.start_ns
                    || now_ns >= permit.expires_ns
                {
                    return Err(Error::Stale);
                }
                if self.count == 0
                    || (0..self.count)
                        .any(|index| !matches!(self.action(index), Some(Action::ConsoleBatch(_))))
                {
                    return Err(Error::Auth);
                }
                Ok(())
            }
        }
    }
    /// Read-only authorization against the actual protected gate. Call under
    /// the same root lock as Plan PUBLISH. This does not consume a canary window,
    /// quota or pending slot; Governance::publish does that at the real commit.
    pub fn authorize_with_gate(
        &self,
        active: ModelBinding,
        gate: &CommitGate,
        now_ns: u64,
    ) -> Result<(), Error> {
        // The Active/Canary gate cannot turn a deterministic baseline into an
        // ordinary model proposal, even when its model binding is identical.
        if self.purpose == RegistrationPurpose::Baseline {
            return Err(Error::Auth);
        }
        self.validate_model_scope(active, now_ns)?;
        if gate.active() != active {
            return Err(Error::Stale);
        }
        match self.canary {
            Some(permit) => {
                if gate.permit() != Some(permit) || gate.restoration_pending().is_some() {
                    Err(Error::Stale)
                } else {
                    Ok(())
                }
            }
            None => gate
                .check_active_publication(self.model, self.target)
                .map_err(|_| Error::Busy),
        }
    }
}

/// Execution counters are local to one CPU; they cannot be compared after a
/// migration even when the numerical counter values happen to be ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuTime {
    pub cpu: usize,
    pub ns: u64,
}
/// Protected publication input boundary, or a later observation of it. Wall
/// time governs leases/deadlines; the separate CPU counter governs execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationTime {
    pub wall_ns: u64,
    pub cpu: CpuTime,
}
impl PublicationTime {
    pub fn cpu_elapsed(self, observed: Self) -> Result<u64, Error> {
        if observed.cpu.cpu != self.cpu.cpu {
            return Err(Error::Auth);
        }
        if observed.wall_ns < self.wall_ns {
            return Err(Error::Range);
        }
        observed.cpu.ns.checked_sub(self.cpu.ns).ok_or(Error::Range)
    }
}
pub trait Clock {
    /// Both domains are explicit. A production clock must read actual local
    /// execution time, rather than deriving it from the wall timestamp.
    fn read(&mut self) -> PublicationTime;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SubmissionStage {
    InitialWall = 1,
    FirstValidation = 2,
    InitialBudget = 3,
    Prepare = 4,
    AfterPrepareTime = 5,
    SecondValidation = 6,
    Revalidate = 7,
    AfterRevalidateTime = 8,
    PreModelBudget = 9,
    ModelAuthorization = 10,
    CommitTime = 11,
    FinalBudget = 12,
    FinalModel = 13,
    Publish = 14,
    Complete = 15,
}
/// Original protected submit outcome, copied after its receipt is retained.
/// A successful publication remains successful even if the final cap stops
/// further optimization. This observer supplies no new execution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmissionObservation {
    pub id: PlanId,
    pub version: u64,
    pub published_ns: u64,
    pub stage: SubmissionStage,
    pub preparation_started: bool,
    pub result: Result<(), Error>,
}
/// PREPARE must reserve all resources without starting physical effects. Failed
/// publication is effect-free; cancel_prepared releases only those reservations.
pub trait Executor {
    /// Passive only: no recursive publication, clock or resource operations.
    fn observed_submission(&mut self, _: &SubmissionObservation) {}
    /// Explicit authority for a fixed baseline, independent of model/Canary
    /// authority. An override must verify the live protected reservation,
    /// target and exact deterministic action. Every ordinary executor denies
    /// it by default; normal hard constraints and publication bounds still run.
    fn authorize_baseline(
        &mut self,
        _active: ModelBinding,
        _set: &RegisteredSet,
        _now_ns: u64,
    ) -> Result<(), Error> {
        Err(Error::Auth)
    }
    /// A stopped optimizer may still owe an exact protected baseline restore.
    /// The default denies every new publication. An override must verify the
    /// current restoration request, target, baseline action and Active binding
    /// under the publication gate, without consuming its receipt or resources.
    /// This does not bypass any later model, time, capacity or publish checks.
    fn authorize_recovery(
        &mut self,
        _active: ModelBinding,
        _plan: &Plan,
        _started_ns: u64,
    ) -> Result<(), Error> {
        Err(Error::Budget)
    }
    /// An ordinary executor accepts only the current Active model. Canary
    /// integration must override this using RegisteredSet::authorize_with_gate
    /// and retain that exact gate's lock through publish. The final publish
    /// callback must recheck its actual commit time and atomically perform
    /// Governance::publish before making the prepared root visible.
    fn authorize_model(
        &mut self,
        active: ModelBinding,
        set: &RegisteredSet,
        _now_ns: u64,
    ) -> Result<(), Error> {
        if set.canary.is_none() && set.model == active {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    fn check(&mut self, decision: Decision, set: &RegisteredSet, now_ns: u64) -> Result<(), Error>;
    fn prepare(&mut self, plan: &Plan, version: u64) -> Result<(), Error>;
    fn revalidate(&mut self, plan: &Plan, now_ns: u64) -> Result<(), Error>;
    fn publish(&mut self, plan: &Plan, version: u64, now_ns: u64) -> Result<(), Error>;
    fn cancel_prepared(&mut self, plan: &Plan);
}

pub struct Registry {
    boot_epoch: u64,
    publisher: Publisher,
    model: ModelBinding,
    version: u64,
    plan_high: u64,
    decision_high: u64,
    registered: [Option<RegisteredSet>; MAX_REGISTERED],
    // Registration hashes are scanned on every candidate commit and decision
    // lookup. Keep them contiguous instead of touching one cache line from
    // each much larger RegisteredSet.
    registered_hashes: [[u8; 32]; MAX_REGISTERED],
    registered_count: usize,
    registered_cursor: usize,
    active: [Option<StoredPlan>; MAX_PENDING],
    history: [Option<StoredPlan>; TERMINAL_HISTORY],
    history_cursor: usize,
    optimization_stopped: bool,
}
impl Registry {
    pub const fn empty() -> Self {
        Self {
            boot_epoch: 0,
            publisher: Publisher {
                object: ObjectKey {
                    id: 0,
                    generation: 0,
                },
                controller_epoch: 0,
            },
            model: ModelBinding {
                generation: 0,
                model_hash: [0; 32],
                schema_hash: [0; 32],
            },
            version: 0,
            plan_high: 0,
            decision_high: 0,
            registered: [None; MAX_REGISTERED],
            registered_hashes: [[0; 32]; MAX_REGISTERED],
            registered_count: 0,
            registered_cursor: 0,
            active: [None; MAX_PENDING],
            history: [None; TERMINAL_HISTORY],
            history_cursor: 0,
            optimization_stopped: false,
        }
    }
    pub fn new(boot_epoch: u64, publisher: Publisher, model: ModelBinding) -> Result<Self, Error> {
        let mut value = Self::empty();
        value.initialize(boot_epoch, publisher, model)?;
        Ok(value)
    }
    /// Initialization in pinned static storage avoids a large EL1 stack value.
    pub fn initialize(
        &mut self,
        boot_epoch: u64,
        publisher: Publisher,
        model: ModelBinding,
    ) -> Result<(), Error> {
        if boot_epoch == 0
            || publisher.object.id == 0
            || publisher.object.generation == 0
            || publisher.controller_epoch == 0
            || model.generation == 0
        {
            return Err(Error::Auth);
        }
        if self.boot_epoch != 0 {
            return Err(Error::Conflict);
        }
        self.boot_epoch = boot_epoch;
        self.publisher = publisher;
        self.model = model;
        Ok(())
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    /// A publication overrun never cancels an installed root or its obligations.
    /// It closes admission of subsequent optimization until recovery can prove
    /// the controller healthy; query and reconciliation remain available.
    pub const fn optimization_stopped(&self) -> bool {
        self.optimization_stopped
    }
    pub fn stop_optimization(&mut self) {
        self.optimization_stopped = true;
    }
    pub const fn model(&self) -> ModelBinding {
        self.model
    }
    pub const fn publisher(&self) -> Publisher {
        self.publisher
    }
    fn authorize(&self, publisher: Publisher) -> Result<(), Error> {
        if self.boot_epoch == 0 || publisher != self.publisher {
            Err(Error::Auth)
        } else {
            Ok(())
        }
    }
    pub fn register(&mut self, publisher: Publisher, set: &CandidateSet) -> Result<(), Error> {
        self.authorize(publisher)?;
        if set.model != self.model || set.canary.is_some() {
            return Err(Error::Stale);
        }
        if set.digest != set.recompute_hash()? {
            return Err(Error::Conflict);
        }
        self.store_registered(Self::registered_set(set, set.digest, None))
    }
    /// Construct an ordinary candidate set once while binding its immutable
    /// bytes to the current registry authority. No registration-table entry is
    /// changed until the opaque value is committed.
    pub fn prepare_candidates(
        &self,
        publisher: Publisher,
        snapshot: Snapshot,
        target: ObjectKey,
        model: ModelBinding,
        choices: &[Candidate],
        current: Option<Action>,
    ) -> Result<PreparedCandidateSet, Error> {
        self.authorize(publisher)?;
        if model != self.model {
            return Err(Error::Stale);
        }
        Ok(PreparedCandidateSet {
            boot_epoch: self.boot_epoch,
            publisher,
            set: CandidateSet::new(snapshot, target, model, choices, current)?,
        })
    }
    /// Commit exactly the set produced by `prepare_candidates` without hashing
    /// its complete feature matrix a second time. The opaque value cannot be
    /// constructed or mutated outside this module; all authority is rechecked
    /// here in case model or publisher generations changed in between.
    pub fn commit_candidates(
        &mut self,
        publisher: Publisher,
        prepared: &PreparedCandidateSet,
    ) -> Result<(), Error> {
        self.authorize(publisher)?;
        if prepared.boot_epoch != self.boot_epoch
            || prepared.publisher != publisher
            || prepared.set.model != self.model
            || prepared.set.canary.is_some()
        {
            return Err(Error::Stale);
        }
        self.store_registered(Self::registered_set(
            prepared.candidate_set(),
            prepared.set.digest,
            None,
        ))
    }
    /// Register one deterministic action without claiming that absent domain
    /// measurements were observed as zero or that a model selected it. This
    /// grants no publication authority: submit still requires the executor's
    /// explicit baseline reservation, current owners, generations and bounds.
    pub fn register_baseline(
        &mut self,
        publisher: Publisher,
        snapshot: Snapshot,
        target: ObjectKey,
        model: ModelBinding,
        action: Action,
    ) -> Result<[u8; 32], Error> {
        self.authorize(publisher)?;
        if model != self.model
            || snapshot.sequence == 0
            || snapshot.ledger_generation == 0
            || snapshot.core_generation == 0
            || target.id == 0
            || target.generation == 0
        {
            return Err(Error::Stale);
        }
        // OfferCpu(0) remains the separate real stop-quote owner operation;
        // it cannot be smuggled into the ordinary Action/Plan wire ABI.
        action.validate()?;
        let mut h = Sha256::new();
        h.update(b"CYXIA_FIXED_BASELINE_V1.3\0");
        for value in [
            self.boot_epoch,
            publisher.object.id,
            publisher.object.generation,
            publisher.controller_epoch,
            snapshot.sequence,
            snapshot.taken_ns,
            snapshot.ledger_generation,
            snapshot.core_generation,
            target.id,
            target.generation,
            model.generation,
        ] {
            h.update(value.to_le_bytes());
        }
        h.update(model.model_hash);
        h.update(model.schema_hash);
        h.update(action.domain().to_le_bytes());
        h.update(action.kind().to_le_bytes());
        let mut payload = [0; 16];
        let len = policy_wire::encode_payload(action, 0, &mut payload)?;
        h.update((len as u16).to_le_bytes());
        h.update(&payload[..len]);
        let hash = h.finalize().into();
        let mut actions = [0; MAX_CANDIDATES];
        actions[0] = pack_registered_action(action);
        self.store_registered(RegisteredSet {
            snapshot,
            target,
            model,
            hash,
            actions,
            count: 1,
            canary: None,
            purpose: RegistrationPurpose::Baseline,
        })?;
        Ok(hash)
    }
    /// Bind a candidate set to a permit issued by the actual protected gate.
    /// Success changes only this set's hash/scope and the registration table,
    /// never the Active model or canary quota. Infer/encode only after success.
    /// A failed registration leaves the supplied set unchanged. A previously
    /// scoped set cannot be rebound to an extended or replacement permit.
    pub fn register_canary(
        &mut self,
        publisher: Publisher,
        set: &mut CandidateSet,
        permit: CanaryPermit,
        gate: &CommitGate,
        now_ns: u64,
    ) -> Result<(), Error> {
        self.authorize(publisher)?;
        if set.digest != set.recompute_hash()? {
            return Err(Error::Conflict);
        }
        if now_ns < set.snapshot.taken_ns {
            return Err(Error::Range);
        }
        if now_ns - set.snapshot.taken_ns > WINDOW_NS {
            return Err(Error::Expired);
        }
        let hash = set.hash_for_canary(permit)?;
        let registered = Self::registered_set(set, hash, Some(permit));
        registered.authorize_with_gate(self.model, gate, now_ns)?;
        self.store_registered(registered)?;
        set.canary = Some(permit);
        set.digest = hash;
        Ok(())
    }
    fn registered_set(
        set: &CandidateSet,
        hash: [u8; 32],
        canary: Option<CanaryPermit>,
    ) -> RegisteredSet {
        let mut actions = [0; MAX_CANDIDATES];
        for (i, c) in set.iter().enumerate() {
            actions[i] = pack_registered_action(c.action);
        }
        RegisteredSet {
            snapshot: set.snapshot,
            target: set.target,
            model: set.model,
            hash,
            actions,
            count: set.len(),
            canary,
            purpose: RegistrationPurpose::Candidates,
        }
    }
    fn store_registered(&mut self, registered: RegisteredSet) -> Result<(), Error> {
        if let Some(index) = self.registered_index(registered.hash) {
            let old = self.registered[index].as_ref().ok_or(Error::Conflict)?;
            return if old.canary == registered.canary
                && old.model == registered.model
                && old.purpose == registered.purpose
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let slot = self.registered_cursor;
        self.registered_hashes[slot] = registered.hash;
        self.registered[slot] = Some(registered);
        self.registered_cursor = (self.registered_cursor + 1) % MAX_REGISTERED;
        if self.registered_count < MAX_REGISTERED {
            self.registered_count += 1;
        }
        Ok(())
    }
    fn registered_index(&self, hash: [u8; 32]) -> Option<usize> {
        self.registered_hashes[..self.registered_count]
            .iter()
            .position(|old| *old == hash)
    }
    fn registered_set_by_hash(&self, hash: [u8; 32]) -> Option<&RegisteredSet> {
        self.registered_index(hash)
            .and_then(|index| self.registered[index].as_ref())
    }
    fn clear_registrations(&mut self) {
        self.registered.fill(None);
        self.registered_hashes.fill([0; 32]);
        self.registered_count = 0;
        self.registered_cursor = 0;
    }
    /// Resolve only an exact retained candidate-set registration. This read
    /// does not authorize publication or bypass the final model/permit check.
    pub fn registered_action(&self, hash: [u8; 32], index: usize) -> Result<Action, Error> {
        self.registered_set_by_hash(hash)
            .ok_or(Error::Stale)?
            .action(index)
            .ok_or(Error::Range)
    }
    pub fn change_model(&mut self, publisher: Publisher, next: ModelBinding) -> Result<(), Error> {
        self.prepare_model_change(publisher, next)?.commit();
        Ok(())
    }
    /// Validate a model switch before another protected owner commits its
    /// corresponding gate. The exclusive borrow keeps publisher/model state
    /// stable until commit; dropping the capability changes nothing.
    ///
    /// This preserves change_model's strictly increasing-generation contract.
    /// A coordinating model bank may enforce its stronger exact +1 rule.
    pub fn prepare_model_change(
        &mut self,
        publisher: Publisher,
        next: ModelBinding,
    ) -> Result<PreparedModelChange<'_>, Error> {
        self.authorize(publisher)?;
        if next.generation <= self.model.generation {
            return Err(Error::Stale);
        }
        Ok(PreparedModelChange {
            registry: self,
            next,
        })
    }
    pub fn change_publisher(&mut self, publisher: Publisher, next: Publisher) -> Result<(), Error> {
        self.authorize(publisher)?;
        if next.controller_epoch <= publisher.controller_epoch
            || next.object.id == 0
            || next.object.generation == 0
        {
            return Err(Error::Stale);
        }
        self.publisher = next;
        self.plan_high = 0;
        self.decision_high = 0;
        self.clear_registrations();
        Ok(())
    }
    fn records(&self) -> impl Iterator<Item = &StoredPlan> {
        self.active
            .iter()
            .chain(self.history.iter())
            .filter_map(|r| r.as_ref())
    }
    pub fn query(&self, publisher: Publisher, id: PlanId) -> Result<PlanReceipt, Error> {
        self.authorize(publisher)?;
        self.records()
            .find(|r| r.receipt.id == id)
            .map(|r| r.receipt)
            .ok_or(Error::Stale)
    }
    /// The immutable model used by a successfully published plan. In-flight
    /// UNKNOWN records keep it independently of candidate/evidence ring reuse,
    /// Active changes, canary revocation and later model rollback.
    pub fn query_model(&self, publisher: Publisher, id: PlanId) -> Result<ModelBinding, Error> {
        self.authorize(publisher)?;
        self.records()
            .find(|record| record.receipt.id == id)
            .ok_or(Error::Stale)?
            .model
            .ok_or(Error::NotReady)
    }
    fn finish(&mut self, slot: usize) {
        if self.active[slot].is_some_and(|r| r.receipt.state().terminal()) {
            self.history[self.history_cursor] = self.active[slot].take();
            self.history_cursor = (self.history_cursor + 1) % TERMINAL_HISTORY;
        }
    }
    pub fn reconcile(
        &mut self,
        apply: ApplyId,
        version: u64,
        state: ExecutionState,
    ) -> Result<PlanReceipt, Error> {
        let id = PlanId {
            boot_epoch: apply.boot_epoch,
            controller_epoch: apply.controller_epoch,
            plan_seq: apply.plan_seq,
        };
        if let Some(old) = self.history.iter().flatten().find(|r| r.receipt.id == id) {
            let i = usize::from(apply.action_index);
            if old.receipt.version != version
                || i >= usize::from(old.receipt.action_count)
                || old.targets[i] != apply.target
            {
                return Err(Error::Stale);
            }
            return if old.receipt.actions[i] == state {
                Ok(old.receipt)
            } else {
                Err(Error::Conflict)
            };
        }
        let slot = self
            .active
            .iter()
            .position(|r| r.is_some_and(|r| r.receipt.id == id))
            .ok_or(Error::Stale)?;
        let r = self.active[slot].as_mut().ok_or(Error::Stale)?;
        let i = usize::from(apply.action_index);
        if r.receipt.version == 0
            || r.receipt.version != version
            || i >= usize::from(r.receipt.action_count)
            || r.targets[i] != apply.target
        {
            return Err(Error::Stale);
        }
        if r.receipt.actions[i].terminal() && r.receipt.actions[i] != state {
            return Err(Error::Conflict);
        }
        r.receipt.actions[i] = state;
        let receipt = r.receipt;
        self.finish(slot);
        Ok(receipt)
    }
    fn registered_decision(&self, decision: Decision) -> Result<&RegisteredSet, Error> {
        self.registered_set_by_hash(decision.envelope.candidate_set_hash)
            .ok_or(Error::Stale)
    }
    fn model_scope(&self, plan: &Plan, now: u64) -> Result<ModelBinding, Error> {
        let mut binding = None;
        for d in plan.iter() {
            let set = self.registered_decision(d)?;
            set.validate_model_scope(self.model, now)?;
            if (set.canary.is_some() || set.baseline_action().is_some()) && plan.len() != 1 {
                return Err(Error::Auth);
            }
            if binding.is_some_and(|old| old != set.model) {
                return Err(Error::Conflict);
            }
            binding = Some(set.model);
        }
        binding.ok_or(Error::Format)
    }
    fn authorize_models<E: Executor>(
        &self,
        plan: &Plan,
        now: u64,
        executor: &mut E,
    ) -> Result<ModelBinding, Error> {
        let binding = self.model_scope(plan, now)?;
        for d in plan.iter() {
            let set = self.registered_decision(d)?;
            if set.baseline_action().is_some() {
                executor.authorize_baseline(self.model, set, now)?;
            }
            executor.authorize_model(self.model, set, now)?;
        }
        Ok(binding)
    }
    fn validate<E: Executor>(&self, plan: &Plan, now: u64, executor: &mut E) -> Result<(), Error> {
        if plan.header.active_model_generation != self.model.generation
            || plan.header.base_plan_version != self.version
        {
            return Err(Error::Stale);
        }
        self.authorize_models(plan, now, executor)?;
        for d in plan.iter() {
            let e = d.envelope;
            let set = self.registered_decision(d)?;
            if e.model_hash != set.model.model_hash
                || set.target != e.target
                || set.snapshot.sequence != e.snapshot_seq
                || set.snapshot.core_generation != e.core_generation
                || set.snapshot.ledger_generation != e.ledger_generation
                || set.action(usize::from(d.candidate_index)) != Some(d.action)
            {
                return Err(Error::Conflict);
            }
            if now < set.snapshot.taken_ns {
                return Err(Error::Range);
            }
            let expires = set
                .snapshot
                .taken_ns
                .checked_add(WINDOW_NS)
                .ok_or(Error::Overflow)?;
            if e.expires_local_ns > expires || e.expires_local_ns < set.snapshot.taken_ns {
                return Err(Error::Format);
            }
            if now > e.expires_local_ns || now > expires {
                return Err(Error::Expired);
            }
            let until = if d.action.one_shot() {
                0
            } else {
                set.snapshot
                    .taken_ns
                    .checked_add(POLICY_NS)
                    .ok_or(Error::Overflow)?
            };
            if plan.header.active_until_local_ns != until {
                return Err(Error::Format);
            }
            executor.check(d, set, now)?;
        }
        Ok(())
    }
    pub fn submit<E: Executor, C: Clock>(
        &mut self,
        publisher: Publisher,
        bytes: &[u8],
        clock: &mut C,
        executor: &mut E,
    ) -> Result<PlanReceipt, Error> {
        let started_ns = clock.read();
        self.submit_bounded(publisher, bytes, started_ns, clock, executor)
    }
    /// `started_ns` contains both protected origins before IPC decoding and
    /// validation, so those costs cannot be hidden outside the publication cap.
    pub fn submit_bounded<E: Executor, C: Clock>(
        &mut self,
        publisher: Publisher,
        bytes: &[u8],
        started_ns: PublicationTime,
        clock: &mut C,
        executor: &mut E,
    ) -> Result<PlanReceipt, Error> {
        self.submit_job(publisher, bytes, started_ns, u64::MAX, clock, executor)
    }
    /// A control job may have a tighter wall deadline than its snapshot TTL.
    /// Recheck it after every fallible validation callback, before publication.
    pub fn submit_job<E: Executor, C: Clock>(
        &mut self,
        publisher: Publisher,
        bytes: &[u8],
        started_ns: PublicationTime,
        wall_deadline_ns: u64,
        clock: &mut C,
        executor: &mut E,
    ) -> Result<PlanReceipt, Error> {
        let plan = policy_wire::decode_plan(bytes)?;
        self.authorize(publisher)?;
        if plan.header.controller_epoch != publisher.controller_epoch {
            return Err(Error::Auth);
        }
        let id = PlanId {
            boot_epoch: self.boot_epoch,
            controller_epoch: publisher.controller_epoch,
            plan_seq: plan.header.plan_seq,
        };
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if let Some(old) = self.records().find(|r| r.receipt.id == id) {
            return if old.digest == digest {
                Ok(old.receipt)
            } else {
                Err(Error::Conflict)
            };
        }
        if self.optimization_stopped {
            executor.authorize_recovery(self.model, &plan, started_ns.wall_ns)?;
        }
        for d in plan.iter() {
            if self.records().any(|r| {
                r.receipt.id.controller_epoch == id.controller_epoch
                    && r.decisions[..usize::from(r.receipt.action_count)]
                        .contains(&d.envelope.decision_seq)
            }) {
                return Err(Error::Conflict);
            }
        }
        if id.plan_seq <= self.plan_high
            || plan
                .iter()
                .any(|d| d.envelope.decision_seq <= self.decision_high)
        {
            return Err(Error::Stale);
        }
        let slot = self
            .active
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let next_version = self.version.checked_add(1).ok_or(Error::Overflow)?;
        let mut record = StoredPlan {
            receipt: PlanReceipt {
                id,
                version: 0,
                published_ns: 0,
                action_count: plan.len() as u16,
                actions: [ExecutionState::Pending; 16],
            },
            digest,
            decisions: [0; 16],
            targets: [ObjectKey {
                id: 0,
                generation: 0,
            }; 16],
            model: None,
        };
        for (i, d) in plan.iter().enumerate() {
            record.decisions[i] = d.envelope.decision_seq;
            record.targets[i] = d.envelope.target;
        }
        self.plan_high = id.plan_seq;
        self.decision_high = record.decisions[plan.len() - 1];
        // Identity is protected before the first reservation or executor effect.
        self.active[slot] = Some(record);
        let first = clock.read();
        let mut last_sample = first;
        let mut prepared = false;
        let mut stage = SubmissionStage::InitialWall;
        let result = (|| {
            if first.wall_ns > wall_deadline_ns {
                return Err(Error::Expired);
            }
            stage = SubmissionStage::FirstValidation;
            self.validate(&plan, first.wall_ns, executor)?;
            stage = SubmissionStage::InitialBudget;
            publication_budget(started_ns, first)?;
            prepared = true;
            stage = SubmissionStage::Prepare;
            executor.prepare(&plan, next_version)?;
            stage = SubmissionStage::AfterPrepareTime;
            let now = clock.read();
            last_sample = now;
            if now.wall_ns < first.wall_ns {
                return Err(Error::Range);
            }
            first.cpu_elapsed(now)?;
            stage = SubmissionStage::SecondValidation;
            self.validate(&plan, now.wall_ns, executor)?;
            stage = SubmissionStage::Revalidate;
            executor.revalidate(&plan, now.wall_ns)?;
            // Revalidation may itself take time or wait for an owner. Take a
            // fresh protected timestamp after all callbacks, before PUBLISH.
            stage = SubmissionStage::AfterRevalidateTime;
            let publish_ns = clock.read();
            last_sample = publish_ns;
            if publish_ns.wall_ns < now.wall_ns {
                return Err(Error::Range);
            }
            now.cpu_elapsed(publish_ns)?;
            if publish_ns.wall_ns > wall_deadline_ns
                || plan
                    .iter()
                    .any(|d| publish_ns.wall_ns > d.envelope.expires_local_ns)
            {
                return Err(Error::Expired);
            }
            stage = SubmissionStage::PreModelBudget;
            publication_budget(started_ns, publish_ns)?;
            // Recheck the actual protected model/lease after all hard-constraint
            // callbacks. This is read-only: no canary quota or pending slot is
            // consumed until the executor performs the real atomic publish.
            stage = SubmissionStage::ModelAuthorization;
            let binding = self.authorize_models(&plan, publish_ns.wall_ns, executor)?;
            stage = SubmissionStage::CommitTime;
            let commit_ns = clock.read();
            last_sample = commit_ns;
            if commit_ns.wall_ns < publish_ns.wall_ns {
                return Err(Error::Range);
            }
            publish_ns.cpu_elapsed(commit_ns)?;
            if commit_ns.wall_ns > wall_deadline_ns
                || plan
                    .iter()
                    .any(|d| commit_ns.wall_ns > d.envelope.expires_local_ns)
            {
                return Err(Error::Expired);
            }
            stage = SubmissionStage::FinalBudget;
            publication_budget(started_ns, commit_ns)?;
            // The gate remains locked. Time may have passed during its check,
            // so recheck the immutable permit's bounds at this final timestamp.
            stage = SubmissionStage::FinalModel;
            if self.model_scope(&plan, commit_ns.wall_ns)? != binding {
                return Err(Error::Stale);
            }
            // Publication is one atomic root change under the owner's resource gate.
            stage = SubmissionStage::Publish;
            executor.publish(&plan, next_version, commit_ns.wall_ns)?;
            stage = SubmissionStage::Complete;
            Ok((commit_ns.wall_ns, binding))
        })();
        let observed_stage = stage;
        match result {
            Ok((now, binding)) => {
                self.version = next_version;
                record.receipt.version = next_version;
                record.receipt.published_ns = now;
                record.model = Some(binding);
            }
            Err(error) => {
                if prepared {
                    executor.cancel_prepared(&plan);
                }
                record.receipt.actions[..plan.len()].fill(ExecutionState::Failed(error));
            }
        }
        self.active[slot] = Some(record);
        self.finish(slot);
        // Once PUBLISH succeeded it cannot be represented as a rejected plan,
        // even if its callback exceeded the cap. Retain the real receipt and
        // stop further optimization while existing APPLY/RECONCILE continues.
        let finished_ns = clock.read();
        if publication_budget(started_ns, finished_ns).is_err()
            || last_sample.cpu_elapsed(finished_ns).is_err()
            || record.receipt.version != 0 && finished_ns.wall_ns > wall_deadline_ns
            || matches!(result, Err(Error::Budget | Error::Range))
        {
            self.optimization_stopped = true;
        }
        executor.observed_submission(&SubmissionObservation {
            id: record.receipt.id,
            version: record.receipt.version,
            published_ns: record.receipt.published_ns,
            stage: observed_stage,
            preparation_started: prepared,
            result: result.map(|_| ()),
        });
        Ok(record.receipt)
    }
    pub fn stamp(
        &self,
        decision: Decision,
        version: u64,
        published_ns: u64,
    ) -> Result<PolicyStamp, Error> {
        let set = self
            .registered_set_by_hash(decision.envelope.candidate_set_hash)
            .ok_or(Error::Stale)?;
        PolicyStamp::for_action(
            decision.action,
            version,
            set.snapshot.taken_ns,
            published_ns,
        )
    }
}

/// Prepared under the same root gate as CommitGate and the physical model
/// bank. No fallible checks, allocation or executor callbacks remain here.
pub struct PreparedModelChange<'a> {
    registry: &'a mut Registry,
    next: ModelBinding,
}
impl PreparedModelChange<'_> {
    pub const fn binding(&self) -> ModelBinding {
        self.next
    }
    pub fn commit(self) -> ModelBinding {
        self.registry.model = self.next;
        self.registry.clear_registrations();
        // Previously published plans retain their original model and receipts.
        // UNKNOWN obligations are unaffected by this admission-only switch.
        self.next
    }
}

pub fn publication_budget(
    started: PublicationTime,
    observed: PublicationTime,
) -> Result<(), Error> {
    let elapsed = started.cpu_elapsed(observed)?;
    if elapsed > PUBLICATION_BUDGET_NS {
        Err(Error::Budget)
    } else {
        Ok(())
    }
}

/// Only the fixed prerequisite edges from the 1.3 contract are representable.
pub fn dependency_allowed(prerequisite: u16, consumer: u16) -> bool {
    matches!(
        (prerequisite, consumer),
        (3, 4) | (9, 4) | (5, 8) | (5, 10) | (13, 1)
    )
}

#[cfg(test)]
mod tests {
    use super::{pack_registered_action, unpack_registered_action};
    use crate::domains::Action;

    #[test]
    fn compact_registration_round_trips_every_action_shape() {
        let actions = [
            Action::CpuWeight(8),
            Action::ControlSet(14),
            Action::SpawnTokens(4),
            Action::Cache {
                pages: 4096,
                batch: 64,
            },
            Action::Filesystem {
                readahead: 16,
                flush: 32,
            },
            Action::Ipc {
                budget: 128,
                batch: 16,
            },
            Action::IrqTarget(3),
            Action::SoftCoalesce(1000),
            Action::ServiceBatch(8),
            Action::IoShare(750),
            Action::TxBatch(16),
            Action::NotifyBatch(8),
            Action::UnauthRate(32),
            Action::BackgroundBudget(400),
            Action::RecoveryRecipe(2),
            Action::ConsoleBatch(64),
            Action::OfferCpu(1000),
            Action::Placement(2),
        ];
        for action in actions {
            assert_eq!(
                unpack_registered_action(pack_registered_action(action)),
                Some(action)
            );
        }
    }
}
