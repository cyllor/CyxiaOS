//! Protected candidate registration and transactional plan publication.
use crate::{
    domains::{Action, ApplyId, Error, ObjectKey, POLICY_NS, PolicyStamp, WINDOW_NS},
    features::{self, RawFeatures},
    policy_wire::{self, Decision, Plan},
};
use sha2::{Digest, Sha256};

pub const MAX_CANDIDATES: usize = 32;
pub const MAX_REGISTERED: usize = 64;
pub const MAX_PENDING: usize = 64;
pub const TERMINAL_HISTORY: usize = 256;
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
        };
        for candidate in choices {
            features::encode(candidate.action, candidate.features)?;
            if candidate.action.domain() != first.action.domain()
                || candidate.action.kind() != first.action.kind()
                || candidate.features.common != first.features.common
                || candidate.features.domain != first.features.domain
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
            if !out.iter().any(|c| c.action == current) {
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
    pub fn get(&self, index: usize) -> Option<Candidate> {
        self.entries.get(index).copied().flatten()
    }
    pub fn iter(&self) -> impl Iterator<Item = Candidate> + '_ {
        self.entries[..self.count].iter().filter_map(|c| *c)
    }
    fn recompute_hash(&self) -> Result<[u8; 32], Error> {
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
}
#[derive(Clone, Copy)]
pub struct RegisteredSet {
    pub snapshot: Snapshot,
    pub target: ObjectKey,
    pub model: ModelBinding,
    pub hash: [u8; 32],
    actions: [Option<Action>; 32],
    count: usize,
}
impl RegisteredSet {
    pub fn action(&self, index: usize) -> Option<Action> {
        if index >= self.count {
            None
        } else {
            self.actions[index]
        }
    }
}

pub trait Clock {
    fn now_ns(&mut self) -> u64;
}
/// PREPARE must reserve all resources without starting physical effects. Failed
/// publication is effect-free; cancel_prepared releases only those reservations.
pub trait Executor {
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
        if set.model != self.model {
            return Err(Error::Stale);
        }
        if set.digest != set.recompute_hash()? {
            return Err(Error::Conflict);
        }
        if self
            .registered
            .iter()
            .flatten()
            .any(|old| old.hash == set.digest)
        {
            return Ok(());
        }
        let mut actions = [None; 32];
        for (i, c) in set.iter().enumerate() {
            actions[i] = Some(c.action);
        }
        self.registered[self.registered_cursor] = Some(RegisteredSet {
            snapshot: set.snapshot,
            target: set.target,
            model: set.model,
            hash: set.digest,
            actions,
            count: set.len(),
        });
        self.registered_cursor = (self.registered_cursor + 1) % MAX_REGISTERED;
        Ok(())
    }
    pub fn change_model(&mut self, publisher: Publisher, next: ModelBinding) -> Result<(), Error> {
        self.authorize(publisher)?;
        if next.generation <= self.model.generation {
            return Err(Error::Stale);
        }
        self.model = next;
        self.registered.fill(None);
        Ok(())
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
    fn validate<E: Executor>(&self, plan: &Plan, now: u64, executor: &mut E) -> Result<(), Error> {
        if plan.header.active_model_generation != self.model.generation
            || plan.header.base_plan_version != self.version
        {
            return Err(Error::Stale);
        }
        for d in plan.iter() {
            let e = d.envelope;
            let set = self
                .registered
                .iter()
                .flatten()
                .find(|s| s.hash == e.candidate_set_hash)
                .ok_or(Error::Stale)?;
            if set.model != self.model
                || e.model_hash != self.model.model_hash
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
            self.validate(&plan, first, executor)?;
            prepared = true;
            executor.prepare(&plan, next_version)?;
            let now = clock.now_ns();
            if now < first {
                return Err(Error::Range);
            }
            self.validate(&plan, now, executor)?;
            executor.revalidate(&plan, now)?;
            // Publication is one atomic root change under the owner's resource gate.
            executor.publish(&plan, next_version, now)?;
            Ok(now)
        })();
        match result {
            Ok(now) => {
                self.version = next_version;
                record.receipt.version = next_version;
                record.receipt.published_ns = now;
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
        PolicyStamp::new(version, set.snapshot.taken_ns, published_ns)
    }
}

/// Only the fixed prerequisite edges from the 1.3 contract are representable.
pub fn dependency_allowed(prerequisite: u16, consumer: u16) -> bool {
    matches!(
        (prerequisite, consumer),
        (3, 4) | (9, 4) | (5, 8) | (5, 10) | (13, 1)
    )
}
