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
#[derive(Clone, Copy, Debug)]
pub struct CandidateSet {
    pub snapshot: Snapshot,
    pub target: ObjectKey,
    pub model: ModelBinding,
    entries: [Option<Candidate>; MAX_CANDIDATES],
    count: usize,
    digest: [u8; 32],
    canary: Option<CanaryPermit>,
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
            entries: [None; MAX_CANDIDATES],
            count: 0,
            digest: [0; 32],
            canary: None,
        };
        for candidate in choices {
            features::encode(candidate.action, candidate.features)?;
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
            out.entries[at] = Some(*candidate);
            out.count += 1;
        }
        if let Some(current) = current {
            let opening_offer = current == Action::OfferCpu(0) && out.count == 1
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
        self.entries.get(index).copied().flatten()
    }
    pub fn iter(&self) -> impl Iterator<Item = Candidate> + '_ {
        self.entries[..self.count].iter().filter_map(|c| *c)
    }
    fn recompute_hash(&self) -> Result<[u8; 32], Error> {
        self.recompute_hash_scoped(self.canary)
    }
    fn recompute_hash_scoped(&self, canary: Option<CanaryPermit>) -> Result<[u8; 32], Error> {
        let mut h = Sha256::new();
        h.update(b"CYXIA_CANDIDATES_V1.3\0");
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
            h.update(v.to_le_bytes());
        }
        h.update(self.model.model_hash);
        h.update(self.model.schema_hash);
        for (index, c) in self.iter().enumerate() {
            h.update(c.action.domain().to_le_bytes());
            h.update(c.action.kind().to_le_bytes());
            let mut bytes = [0; 16];
            let n = policy_wire::encode_payload(c.action, index as u16, &mut bytes)?;
            h.update((n as u16).to_le_bytes());
            h.update(&bytes[..n]);
            for v in c.features.common.into_iter().chain(c.features.domain) {
                h.update(v.to_le_bytes());
            }
            h.update([c.features.domain_present]);
            for v in c
                .features
                .target
                .values
                .into_iter()
                .chain([c.features.control_capacity])
            {
                h.update([u8::from(v.is_some())]);
                h.update(v.unwrap_or(0).to_le_bytes());
            }
        }
        // Both scopes bind raw measurements and their presence mask above.
        // Canary additionally binds this separator, eight u64 little-endian fields in
        // the order below, then the exact 32-byte candidate parameter hash.
        // Permit extensions/replacements therefore cannot revive an old set.
        if let Some(p) = canary {
            h.update(b"\0CYXIA_CANARY_SCOPE_V1.3\0");
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
                h.update(value.to_le_bytes());
            }
            h.update(p.candidate_hash);
        }
        Ok(h.finalize().into())
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
        if states.iter().any(|s| *s == ExecutionState::Unknown) {
            ExecutionState::Unknown
        } else if states.iter().any(|s| *s == ExecutionState::Pending) {
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
#[derive(Clone, Copy)]
pub struct RegisteredSet {
    pub snapshot: Snapshot,
    pub target: ObjectKey,
    pub model: ModelBinding,
    pub hash: [u8; 32],
    actions: [Option<Action>; 32],
    count: usize,
    canary: Option<CanaryPermit>,
    purpose: RegistrationPurpose,
}
impl RegisteredSet {
    pub fn action(&self, index: usize) -> Option<Action> {
        if index >= self.count {
            None
        } else {
            self.actions[index]
        }
    }
    pub const fn canary_permit(&self) -> Option<CanaryPermit> {
        self.canary
    }
    /// A fixed baseline has no model features or scores. Only the protected
    /// baseline executor may authorize this exact registered action.
    pub fn baseline_action(&self) -> Option<Action> {
        if self.purpose == RegistrationPurpose::Baseline {
            self.actions[0]
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
                    || self.actions[..self.count]
                        .iter()
                        .any(|action| !matches!(action, Some(Action::ConsoleBatch(_))))
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

pub trait Clock {
    fn now_ns(&mut self) -> u64;
}
/// PREPARE must reserve all resources without starting physical effects. Failed
/// publication is effect-free; cancel_prepared releases only those reservations.
pub trait Executor {
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
        let mut actions = [None; 32];
        actions[0] = Some(action);
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
        let mut actions = [None; 32];
        for (i, c) in set.iter().enumerate() {
            actions[i] = Some(c.action);
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
        if let Some(old) = self
            .registered
            .iter()
            .flatten()
            .find(|old| old.hash == registered.hash)
        {
            return if old.canary == registered.canary
                && old.model == registered.model
                && old.purpose == registered.purpose
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.registered[self.registered_cursor] = Some(registered);
        self.registered_cursor = (self.registered_cursor + 1) % MAX_REGISTERED;
        Ok(())
    }
    /// Resolve only an exact retained candidate-set registration. This read
    /// does not authorize publication or bypass the final model/permit check.
    pub fn registered_action(&self, hash: [u8; 32], index: usize) -> Result<Action, Error> {
        self.registered
            .iter()
            .flatten()
            .find(|set| set.hash == hash)
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
        self.registered.fill(None);
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
        self.registered
            .iter()
            .flatten()
            .find(|set| set.hash == decision.envelope.candidate_set_hash)
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
        let started_ns = clock.now_ns();
        self.submit_bounded(publisher, bytes, started_ns, clock, executor)
    }
    /// `started_ns` comes from the protected caller before IPC decoding and
    /// validation, so those costs cannot be hidden outside the publication cap.
    pub fn submit_bounded<E: Executor, C: Clock>(
        &mut self,
        publisher: Publisher,
        bytes: &[u8],
        started_ns: u64,
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
        started_ns: u64,
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
            executor.authorize_recovery(self.model, &plan, started_ns)?;
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
        let first = clock.now_ns();
        let mut prepared = false;
        let result = (|| {
            if first > wall_deadline_ns {
                return Err(Error::Expired);
            }
            self.validate(&plan, first, executor)?;
            publication_budget(started_ns, first)?;
            prepared = true;
            executor.prepare(&plan, next_version)?;
            let now = clock.now_ns();
            if now < first {
                return Err(Error::Range);
            }
            self.validate(&plan, now, executor)?;
            executor.revalidate(&plan, now)?;
            // Revalidation may itself take time or wait for an owner. Take a
            // fresh protected timestamp after all callbacks, before PUBLISH.
            let publish_ns = clock.now_ns();
            if publish_ns < now {
                return Err(Error::Range);
            }
            if publish_ns > wall_deadline_ns
                || plan
                    .iter()
                    .any(|d| publish_ns > d.envelope.expires_local_ns)
            {
                return Err(Error::Expired);
            }
            publication_budget(started_ns, publish_ns)?;
            // Recheck the actual protected model/lease after all hard-constraint
            // callbacks. This is read-only: no canary quota or pending slot is
            // consumed until the executor performs the real atomic publish.
            let binding = self.authorize_models(&plan, publish_ns, executor)?;
            let commit_ns = clock.now_ns();
            if commit_ns < publish_ns {
                return Err(Error::Range);
            }
            if commit_ns > wall_deadline_ns
                || plan.iter().any(|d| commit_ns > d.envelope.expires_local_ns)
            {
                return Err(Error::Expired);
            }
            publication_budget(started_ns, commit_ns)?;
            // The gate remains locked. Time may have passed during its check,
            // so recheck the immutable permit's bounds at this final timestamp.
            if self.model_scope(&plan, commit_ns)? != binding {
                return Err(Error::Stale);
            }
            // Publication is one atomic root change under the owner's resource gate.
            executor.publish(&plan, next_version, commit_ns)?;
            Ok((commit_ns, binding))
        })();
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
        let finished_ns = clock.now_ns();
        if publication_budget(started_ns, finished_ns).is_err()
            || record.receipt.version != 0 && finished_ns > wall_deadline_ns
            || matches!(result, Err(Error::Budget | Error::Range))
        {
            self.optimization_stopped = true;
        }
        Ok(record.receipt)
    }
    pub fn stamp(
        &self,
        decision: Decision,
        version: u64,
        published_ns: u64,
    ) -> Result<PolicyStamp, Error> {
        let set = self
            .registered
            .iter()
            .flatten()
            .find(|s| s.hash == decision.envelope.candidate_set_hash)
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
        self.registry.registered.fill(None);
        // Previously published plans retain their original model and receipts.
        // UNKNOWN obligations are unaffected by this admission-only switch.
        self.next
    }
}

fn publication_budget(started_ns: u64, now_ns: u64) -> Result<(), Error> {
    let elapsed = now_ns.checked_sub(started_ns).ok_or(Error::Range)?;
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
