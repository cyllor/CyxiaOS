use crate::domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp};

pub const PLACEMENT_CAPACITY: usize = 32;
pub const PLACEMENT_TIMEOUT_NS: u64 = 4_000_000_000;
pub const QUOTE_TTL_NS: u64 = 2_000_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteCapacity {
    pub cpu_milli: u16,
    pub memory_pages: u32,
    pub core_generation: u64,
    pub ledger_generation: u64,
    pub ready: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuQuote {
    pub cpu_milli: u16,
    pub memory_pages: u32,
    pub core_generation: u64,
    pub ledger_generation: u64,
    pub expires_ns: u64,
    pub policy_version: u64,
}
pub trait QuoteBackend {
    fn capacity(&self) -> QuoteCapacity;
    fn publish(&mut self, quote: CpuQuote) -> Result<(), Error>;
}
pub struct QuotePolicy {
    stamp: PolicyStamp,
    cap: u16,
}
impl Default for QuotePolicy {
    fn default() -> Self {
        Self::new()
    }
}
impl QuotePolicy {
    pub const fn new() -> Self {
        Self {
            stamp: PolicyStamp {
                version: 0,
                snapshot_ns: 0,
                installed_until_ns: 0,
            },
            cap: 0,
        }
    }
    pub fn install(&mut self, stamp: PolicyStamp, cap: u16, now: u64) -> Result<(), Error> {
        Action::OfferCpu(cap).validate()?;
        self.stamp.accepts(stamp, now)?;
        if stamp.version == self.stamp.version && cap != self.cap {
            return Err(Error::Conflict);
        }
        self.stamp = stamp;
        self.cap = cap;
        Ok(())
    }
    pub fn publish(&self, now: u64, backend: &mut impl QuoteBackend) -> Result<CpuQuote, Error> {
        if !self.stamp.live(now) {
            return Err(Error::Expired);
        }
        let capacity = backend.capacity();
        if !capacity.ready || capacity.core_generation == 0 || capacity.ledger_generation == 0 {
            return Err(Error::NotReady);
        }
        let cpu_milli = capacity.cpu_milli.min(self.cap);
        if cpu_milli == 0 || capacity.memory_pages == 0 {
            return Err(Error::Capacity);
        }
        let quote = CpuQuote {
            cpu_milli,
            memory_pages: capacity.memory_pages,
            core_generation: capacity.core_generation,
            ledger_generation: capacity.ledger_generation,
            expires_ns: now
                .checked_add(QUOTE_TTL_NS)
                .ok_or(Error::Overflow)?
                .min(self.stamp.installed_until_ns),
            policy_version: self.stamp.version,
        };
        backend.publish(quote)?;
        Ok(quote)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementChoice {
    Local,
    Peer,
    Defer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementRequest {
    pub key: ObjectKey,
    pub payload_hash: [u8; 32],
    pub package_hash: [u8; 32],
    pub cpu_milli: u16,
    pub memory_pages: u32,
    pub isa: u16,
    pub abi: u16,
    pub peer: Option<ObjectKey>,
}
impl PlacementRequest {
    fn validate(&self) -> Result<(), Error> {
        if self.key.id == 0
            || self.key.generation == 0
            || !(1..=900).contains(&self.cpu_milli)
            || self.memory_pages == 0
            || self.isa == 0
            || self.abi == 0
            || self.peer.is_some_and(|p| p.id == 0 || p.generation == 0)
        {
            return Err(Error::Format);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementIntent {
    pub request: PlacementRequest,
    pub choice: PlacementChoice,
    pub apply: Option<ApplyId>,
    pub decided_ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementOutcome {
    Local(ObjectKey),
    Peer {
        node: ObjectKey,
        contract: ObjectKey,
    },
    Rejected(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementStatus {
    Pending,
    Deferred,
    Unknown,
    Complete(PlacementOutcome),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementDurability {
    Committed,
    NotCommitted,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementAdmission {
    Admitted(ObjectKey),
    Rejected(Error),
    Unknown,
}
pub trait PlacementBackend {
    /// Persist full request/hash/target intent before any operation which can
    /// acquire an execution or remote resource obligation.
    fn persist_intent(&mut self, intent: PlacementIntent) -> PlacementDurability;
    fn intent_status(&mut self, intent: PlacementIntent) -> PlacementDurability;
    /// Admitted means actual local Created, not Queued, or a durable peer grant.
    /// Rejected proves that this invocation acquired no execution obligation.
    fn local_admit(&mut self, intent: PlacementIntent) -> PlacementAdmission;
    fn peer_ready(&self, request: PlacementRequest) -> bool;
    fn peer_prepare(&mut self, intent: PlacementIntent) -> PlacementAdmission;
    /// Query the original immutable key. Never issue a second logical start.
    fn reconcile(&mut self, intent: PlacementIntent) -> Option<PlacementOutcome>;
    fn persist_receipt(
        &mut self,
        intent: PlacementIntent,
        outcome: PlacementOutcome,
    ) -> PlacementDurability;
}
#[derive(Clone, Copy)]
struct History {
    request: PlacementRequest,
    intent: Option<IntentMeta>,
    outcome: Option<PlacementOutcome>,
}
// Retain the full immutable request once. Duplicating its two hashes inside
// every intent would exceed the shared 8MiB quota at 4096 retained outcomes.
#[derive(Clone, Copy)]
struct IntentMeta { choice: PlacementChoice, apply: Option<ApplyId>, decided_ns: u64 }
impl From<PlacementIntent> for IntentMeta {
    fn from(intent: PlacementIntent) -> Self { Self { choice: intent.choice, apply: intent.apply, decided_ns: intent.decided_ns } }
}
impl History {
    fn intent(self) -> Option<PlacementIntent> {
        self.intent.map(|meta| PlacementIntent { request: self.request, choice: meta.choice, apply: meta.apply, decided_ns: meta.decided_ns })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Waiting,
    Deferred,
    Intent,
    IntentUnknown,
    ExecutionUnknown,
    Receipt,
}
#[derive(Clone, Copy)]
struct Pending {
    history: usize,
    created: u64,
    deadline: u64,
    phase: Phase,
    last_apply: Option<ApplyId>,
    outcome: Option<PlacementOutcome>,
}
pub struct PlacementQueue<const HISTORY: usize = 4096> {
    history: [Option<History>; HISTORY],
    pending: [Option<Pending>; PLACEMENT_CAPACITY],
    cursor: usize,
    now: u64,
    pub fallbacks: u64,
}
impl<const H: usize> Default for PlacementQueue<H> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const H: usize> PlacementQueue<H> {
    pub const fn new() -> Self {
        Self {
            history: [None; H],
            pending: [None; PLACEMENT_CAPACITY],
            cursor: 0,
            now: 0,
            fallbacks: 0,
        }
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Stale);
        }
        self.now = now;
        Ok(())
    }
    fn history_index(&self, key: ObjectKey) -> Option<usize> {
        self.history
            .iter()
            .position(|h| h.is_some_and(|h| h.request.key == key))
    }
    fn pending_index(&self, h: usize) -> Option<usize> {
        self.pending
            .iter()
            .position(|p| p.is_some_and(|p| p.history == h))
    }
    pub fn submit(
        &mut self,
        request: PlacementRequest,
        now: u64,
    ) -> Result<PlacementStatus, Error> {
        request.validate()?;
        self.time(now)?;
        if let Some(h) = self.history_index(request.key) {
            if self.history[h].unwrap().request != request {
                return Err(Error::Conflict);
            }
            return self.status(request.key);
        }
        let deadline = now
            .checked_add(PLACEMENT_TIMEOUT_NS)
            .ok_or(Error::Overflow)?;
        let p = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let h = self
            .history
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.history[h] = Some(History {
            request,
            intent: None,
            outcome: None,
        });
        self.pending[p] = Some(Pending {
            history: h,
            created: now,
            deadline,
            phase: Phase::Waiting,
            last_apply: None,
            outcome: None,
        });
        Ok(PlacementStatus::Pending)
    }
    pub fn status(&self, key: ObjectKey) -> Result<PlacementStatus, Error> {
        let h = self.history_index(key).ok_or(Error::NotFound)?;
        if let Some(outcome) = self.history[h].unwrap().outcome {
            return Ok(PlacementStatus::Complete(outcome));
        }
        Ok(
            match self
                .pending_index(h)
                .map(|p| self.pending[p].unwrap().phase)
            {
                Some(Phase::Waiting) => PlacementStatus::Pending,
                Some(Phase::Deferred) => PlacementStatus::Deferred,
                _ => PlacementStatus::Unknown,
            },
        )
    }
    pub fn choose(
        &mut self,
        apply: ApplyId,
        choice: PlacementChoice,
        now: u64,
    ) -> Result<PlacementStatus, Error> {
        self.time(now)?;
        let h = self.history_index(apply.target).ok_or(Error::NotFound)?;
        if let Some(intent) = self.history[h].unwrap().intent()
            && intent.apply == Some(apply)
        {
            if intent.choice != choice {
                return Err(Error::Conflict);
            }
            return self.status(apply.target);
        }
        let p = self.pending_index(h).ok_or(Error::Stale)?;
        let pending = self.pending[p].as_mut().unwrap();
        if pending.last_apply == Some(apply) {
            return if choice == PlacementChoice::Defer && pending.phase == Phase::Deferred {
                Ok(PlacementStatus::Deferred)
            } else {
                Err(Error::Conflict)
            };
        }
        if !matches!(pending.phase, Phase::Waiting | Phase::Deferred) {
            return Err(Error::Busy);
        }
        if now >= pending.deadline {
            return Err(Error::Expired);
        }
        let request = self.history[h].unwrap().request;
        if choice == PlacementChoice::Peer && request.peer.is_none() {
            return Err(Error::Auth);
        }
        pending.last_apply = Some(apply);
        if choice == PlacementChoice::Defer {
            pending.phase = Phase::Deferred;
            return Ok(PlacementStatus::Deferred);
        }
        self.history[h].as_mut().unwrap().intent = Some(PlacementIntent {
            request,
            choice,
            apply: Some(apply),
            decided_ns: now,
        }.into());
        pending.phase = Phase::Intent;
        Ok(PlacementStatus::Unknown)
    }
    fn valid_outcome(intent: PlacementIntent, outcome: PlacementOutcome) -> bool {
        match (intent.choice, outcome) {
            (_, PlacementOutcome::Rejected(_)) => true,
            (PlacementChoice::Local, PlacementOutcome::Local(key)) => {
                key.id != 0 && key.generation != 0
            }
            (PlacementChoice::Peer, PlacementOutcome::Peer { node, contract }) => {
                intent.request.peer == Some(node) && contract.id != 0 && contract.generation != 0
            }
            _ => false,
        }
    }
    pub fn poll(
        &mut self,
        now: u64,
        budget: usize,
        backend: &mut impl PlacementBackend,
    ) -> Result<usize, Error> {
        self.time(now)?;
        let mut work = 0;
        for _ in 0..PLACEMENT_CAPACITY {
            if work == budget {
                break;
            }
            let p = self.cursor;
            self.cursor = (p + 1) % PLACEMENT_CAPACITY;
            let Some(mut pending) = self.pending[p] else {
                continue;
            };
            let h = pending.history;
            if matches!(pending.phase, Phase::Waiting | Phase::Deferred) {
                if now < pending.deadline {
                    continue;
                }
                let request = self.history[h].unwrap().request;
                self.history[h].as_mut().unwrap().intent = Some(PlacementIntent {
                    request,
                    choice: PlacementChoice::Local,
                    apply: None,
                    decided_ns: now,
                }.into());
                pending.phase = Phase::Intent;
                self.fallbacks = self.fallbacks.saturating_add(1);
            }
            work += 1;
            let intent = self.history[h].unwrap().intent().ok_or(Error::Conflict)?;
            if matches!(pending.phase, Phase::Intent | Phase::IntentUnknown) {
                let durable = if pending.phase == Phase::Intent {
                    backend.persist_intent(intent)
                } else {
                    backend.intent_status(intent)
                };
                match durable {
                    PlacementDurability::Committed => {
                        // Publish UNKNOWN before calling either admission gate.
                        // A lost reply cannot drive this branch a second time.
                        pending.phase = Phase::ExecutionUnknown;
                        self.pending[p] = Some(pending);
                        let admitted = match intent.choice {
                            PlacementChoice::Local => backend.local_admit(intent),
                            PlacementChoice::Peer if backend.peer_ready(intent.request) => {
                                backend.peer_prepare(intent)
                            }
                            PlacementChoice::Peer => PlacementAdmission::Rejected(Error::NotReady),
                            PlacementChoice::Defer => return Err(Error::Conflict),
                        };
                        pending.outcome = match admitted {
                            PlacementAdmission::Admitted(key) => {
                                Some(if intent.choice == PlacementChoice::Local {
                                    PlacementOutcome::Local(key)
                                } else {
                                    PlacementOutcome::Peer {
                                        node: intent.request.peer.ok_or(Error::Auth)?,
                                        contract: key,
                                    }
                                })
                            }
                            PlacementAdmission::Rejected(e) => Some(PlacementOutcome::Rejected(e)),
                            PlacementAdmission::Unknown => None,
                        };
                        if pending.outcome.is_some() {
                            pending.phase = Phase::Receipt;
                        }
                    }
                    PlacementDurability::NotCommitted => pending.phase = Phase::Intent,
                    PlacementDurability::Unknown => pending.phase = Phase::IntentUnknown,
                }
            } else if pending.phase == Phase::ExecutionUnknown {
                pending.outcome = backend.reconcile(intent);
                if pending.outcome.is_some() {
                    pending.phase = Phase::Receipt;
                }
            }
            if pending.phase == Phase::Receipt {
                let outcome = pending.outcome.ok_or(Error::Conflict)?;
                if !Self::valid_outcome(intent, outcome) {
                    self.pending[p] = Some(pending);
                    return Err(Error::Conflict);
                }
                if backend.persist_receipt(intent, outcome) == PlacementDurability::Committed {
                    self.history[h].as_mut().unwrap().outcome = Some(outcome);
                    self.pending[p] = None;
                    continue;
                }
            }
            self.pending[p] = Some(pending);
        }
        Ok(work)
    }
    pub fn restore_intent(&mut self, intent: PlacementIntent, now: u64) -> Result<(), Error> {
        intent.request.validate()?;
        self.time(now)?;
        if intent.choice == PlacementChoice::Defer
            || intent.apply.is_some_and(|a| a.target != intent.request.key)
            || (intent.choice == PlacementChoice::Peer && intent.request.peer.is_none())
        {
            return Err(Error::Format);
        }
        if let Some(h) = self.history_index(intent.request.key) {
            return if self.history[h].unwrap().intent() == Some(intent) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let h = self
            .history
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let p = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.history[h] = Some(History {
            request: intent.request,
            intent: Some(intent.into()),
            outcome: None,
        });
        // Recovered START intent does not prove whether execution occurred.
        self.pending[p] = Some(Pending {
            history: h,
            created: now,
            deadline: now,
            phase: Phase::ExecutionUnknown,
            last_apply: intent.apply,
            outcome: None,
        });
        Ok(())
    }
    pub fn restore_receipt(
        &mut self,
        intent: PlacementIntent,
        outcome: PlacementOutcome,
        now: u64,
    ) -> Result<(), Error> {
        intent.request.validate()?;
        self.time(now)?;
        if intent.choice == PlacementChoice::Defer
            || intent.apply.is_some_and(|a| a.target != intent.request.key)
            || !Self::valid_outcome(intent, outcome)
        {
            return Err(Error::Format);
        }
        let h = if let Some(h) = self.history_index(intent.request.key) {
            let old = self.history[h].unwrap();
            if old.intent() != Some(intent) || old.outcome.is_some_and(|old| old != outcome) {
                return Err(Error::Conflict);
            }
            h
        } else {
            self.history
                .iter()
                .position(Option::is_none)
                .ok_or(Error::Capacity)?
        };
        self.history[h] = Some(History {
            request: intent.request,
            intent: Some(intent.into()),
            outcome: Some(outcome),
        });
        if let Some(p) = self.pending_index(h) {
            self.pending[p] = None;
        }
        Ok(())
    }
    pub fn pending_count(&self) -> usize {
        self.pending.iter().flatten().count()
    }
    pub fn retained_count(&self) -> usize {
        self.history.iter().flatten().count()
    }
    pub fn waiting(&self, ordinal: usize) -> Option<PlacementRequest> {
        self.pending
            .iter()
            .flatten()
            .filter(|p| matches!(p.phase, Phase::Waiting | Phase::Deferred))
            .nth(ordinal)
            .and_then(|p| self.history[p.history].map(|h| h.request))
    }
    pub fn waiting_age_ns(&self, ordinal: usize, now: u64) -> Option<u64> {
        self.pending
            .iter()
            .flatten()
            .filter(|p| matches!(p.phase, Phase::Waiting | Phase::Deferred))
            .nth(ordinal)
            .map(|p| now.saturating_sub(p.created))
    }
}
