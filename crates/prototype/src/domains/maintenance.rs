//! Optional CPU accounting, whitelisted recovery, and bounded serial output.
use super::{Action, ApplyId, Error, ObjectKey, PolicyStamp, WINDOW_NS};
use crate::policy::ExecutionState;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OptionalStatus {
    pub budget_milli: u16,
    pub committed_milli: u16,
    pub spent_ns: u64,
    pub reserved_ns: u64,
    pub freeze_admission: bool,
    pub overrun: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuDebit {
    id: u64,
    key: ObjectKey,
    window: u64,
    started_ns: u64,
    reserved_ns: u64,
}
#[derive(Clone, Copy)]
struct Group {
    key: ObjectKey,
    status: OptionalStatus,
    stamp: PolicyStamp,
    window: u64,
    carry_ns: u64,
}
pub struct BackgroundBudgets {
    groups: [Option<Group>; 16],
    debits: [Option<CpuDebit>; 64],
    next: u64,
}
impl Default for BackgroundBudgets {
    fn default() -> Self {
        Self::new()
    }
}
impl BackgroundBudgets {
    pub const fn new() -> Self {
        Self {
            groups: [None; 16],
            debits: [None; 64],
            next: 1,
        }
    }
    fn index(&self, key: ObjectKey) -> Result<usize, Error> {
        self.groups
            .iter()
            .position(|g| g.is_some_and(|g| g.key == key))
            .ok_or(Error::Stale)
    }
    pub fn register(
        &mut self,
        key: ObjectKey,
        budget_milli: u16,
        committed_milli: u16,
        now: u64,
    ) -> Result<(), Error> {
        Action::BackgroundBudget(budget_milli).validate()?;
        if key.id == 0 || key.generation == 0 {
            return Err(Error::Auth);
        }
        if committed_milli > budget_milli {
            return Err(Error::Budget);
        }
        if self.index(key).is_ok() {
            return Err(Error::Exists);
        }
        let slot = self
            .groups
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.groups[slot] = Some(Group {
            key,
            status: OptionalStatus {
                budget_milli,
                committed_milli,
                ..OptionalStatus::default()
            },
            stamp: PolicyStamp::default(),
            window: now / WINDOW_NS,
            carry_ns: 0,
        });
        Ok(())
    }
    fn refresh(&mut self, index: usize, now: u64) -> Result<(), Error> {
        let group = self.groups[index].as_mut().ok_or(Error::Stale)?;
        let window = now / WINDOW_NS;
        if window < group.window {
            return Err(Error::Range);
        }
        if window > group.window {
            if self.debits.iter().flatten().any(|d| d.key == group.key) {
                group.status.freeze_admission = true;
                return Err(Error::Busy);
            }
            group.window = window;
            group.status.spent_ns = group.carry_ns;
            group.carry_ns = 0;
            group.status.freeze_admission = group.status.overrun;
        }
        if group.stamp.version != 0 && !group.stamp.live(now) {
            if group.status.committed_milli <= 100 {
                group.status.budget_milli = 100;
            } else {
                group.status.freeze_admission = true;
            }
        }
        Ok(())
    }
    pub fn set_commitment(
        &mut self,
        key: ObjectKey,
        committed_milli: u16,
        now: u64,
    ) -> Result<(), Error> {
        let index = self.index(key)?;
        self.refresh(index, now)?;
        let g = self.groups[index].as_mut().ok_or(Error::Stale)?;
        if committed_milli > g.status.budget_milli {
            return Err(Error::Budget);
        }
        if g.status.freeze_admission && committed_milli > g.status.committed_milli {
            return Err(Error::Busy);
        }
        g.status.committed_milli = committed_milli;
        Ok(())
    }
    pub fn install(
        &mut self,
        key: ObjectKey,
        budget_milli: u16,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        Action::BackgroundBudget(budget_milli).validate()?;
        let index = self.index(key)?;
        self.refresh(index, now)?;
        let g = self.groups[index].as_mut().ok_or(Error::Stale)?;
        g.stamp.accepts(stamp, now)?;
        if g.stamp == stamp {
            return if g.status.budget_milli == budget_milli {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if budget_milli < g.status.committed_milli {
            return Err(Error::Budget);
        }
        if g.status
            .spent_ns
            .checked_add(g.status.reserved_ns)
            .ok_or(Error::Overflow)?
            > u64::from(budget_milli) * WINDOW_NS / 1000
        {
            return Err(Error::Busy);
        }
        g.status.budget_milli = budget_milli;
        g.stamp = stamp;
        g.status.freeze_admission = g.status.overrun;
        Ok(())
    }
    pub fn reserve(
        &mut self,
        key: ObjectKey,
        reserved_ns: u64,
        now: u64,
    ) -> Result<CpuDebit, Error> {
        if reserved_ns == 0 {
            return Err(Error::Range);
        }
        let index = self.index(key)?;
        self.refresh(index, now)?;
        let slot = self
            .debits
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let g = self.groups[index].as_mut().ok_or(Error::Stale)?;
        if g.status.overrun {
            return Err(Error::Budget);
        }
        let total = g
            .status
            .spent_ns
            .checked_add(g.status.reserved_ns)
            .and_then(|v| v.checked_add(reserved_ns))
            .ok_or(Error::Overflow)?;
        if total > u64::from(g.status.budget_milli) * WINDOW_NS / 1000 {
            return Err(Error::Budget);
        }
        let next = self.next.checked_add(1).ok_or(Error::Overflow)?;
        let debit = CpuDebit {
            id: self.next,
            key,
            window: g.window,
            started_ns: now,
            reserved_ns,
        };
        self.next = next;
        self.debits[slot] = Some(debit);
        g.status.reserved_ns += reserved_ns;
        Ok(debit)
    }
    pub fn complete(
        &mut self,
        debit: CpuDebit,
        actual_ns: u64,
        finished_ns: u64,
    ) -> Result<(), Error> {
        let slot = self
            .debits
            .iter()
            .position(|d| *d == Some(debit))
            .ok_or(Error::Stale)?;
        let index = self.index(debit.key)?;
        if finished_ns < debit.started_ns || actual_ns > finished_ns - debit.started_ns {
            return Err(Error::Range);
        }
        let g = self.groups[index].as_mut().ok_or(Error::Stale)?;
        let spent = g
            .status
            .spent_ns
            .checked_add(actual_ns)
            .ok_or(Error::Overflow)?;
        let carry = if finished_ns / WINDOW_NS > debit.window {
            g.carry_ns.checked_add(actual_ns).ok_or(Error::Overflow)?
        } else {
            g.carry_ns
        };
        g.status.reserved_ns = g
            .status
            .reserved_ns
            .checked_sub(debit.reserved_ns)
            .ok_or(Error::Conflict)?;
        g.status.spent_ns = spent;
        g.carry_ns = carry;
        self.debits[slot] = None;
        if actual_ns > debit.reserved_ns {
            g.status.overrun = true;
            g.status.freeze_admission = true;
            return Err(Error::Budget);
        }
        Ok(())
    }
    pub fn status(&self, key: ObjectKey) -> Result<OptionalStatus, Error> {
        Ok(self.groups[self.index(key)?].ok_or(Error::Stale)?.status)
    }
    /// Project the current legal parameters for a control-plane observation.
    /// This never rolls the owner's accounting window or consumes carry-over.
    /// An unsettled old-window debit remains explicitly unreadable for a new
    /// window instead of being erased or replaced with a zero-cost sample.
    pub fn peek_status(&self, key: ObjectKey, now: u64) -> Result<OptionalStatus, Error> {
        let group = self.groups[self.index(key)?].ok_or(Error::Stale)?;
        let window = now / WINDOW_NS;
        if window < group.window {
            return Err(Error::Range);
        }
        let mut status = group.status;
        if window > group.window {
            if self.debits.iter().flatten().any(|debit| debit.key == key) {
                return Err(Error::Busy);
            }
            status.spent_ns = group.carry_ns;
            status.freeze_admission = status.overrun;
        }
        if group.stamp.version != 0 && !group.stamp.live(now) {
            if status.committed_milli <= 100 {
                status.budget_milli = 100;
            } else {
                status.freeze_admission = true;
            }
        }
        Ok(status)
    }
    pub fn current_status(&mut self, key: ObjectKey, now: u64) -> Result<OptionalStatus, Error> {
        let i = self.index(key)?;
        let r = self.refresh(i, now);
        if r.is_err() && r != Err(Error::Busy) {
            r?;
        }
        self.status(key)
    }
    pub fn recover_stopped(&mut self, key: ObjectKey, now: u64) -> Result<(), Error> {
        let i = self.index(key)?;
        if self.debits.iter().flatten().any(|d| d.key == key) {
            return Err(Error::Busy);
        }
        self.refresh(i, now)?;
        let g = self.groups[i].as_mut().ok_or(Error::Stale)?;
        g.status.overrun = false;
        g.status.freeze_admission = !g.stamp.live(now) && g.status.committed_milli > 100;
        Ok(())
    }
}

pub trait RecoveryBackend {
    fn close_admission(&mut self, target: ObjectKey) -> Result<(), Error>;
    fn readonly_drained(&mut self, target: ObjectKey) -> Result<bool, Error>;
    fn request_stop(&mut self, target: ObjectKey) -> Result<(), Error>;
    fn stopped(&mut self, target: ObjectKey) -> Result<bool, Error>;
    fn start_generation(&mut self, target: ObjectKey, next_generation: u64) -> Result<(), Error>;
    fn running(&mut self, target: ObjectKey, generation: u64) -> Result<bool, Error>;
    /// Passive observation after the original step and record update. The
    /// default performs no work and cannot affect the recovery outcome.
    fn observed(&mut self, _: &RecoveryObservation) {}
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryReceipt {
    pub apply: ApplyId,
    pub recipe: u16,
    pub state: ExecutionState,
    pub generation: u64,
    pub started_ns: u64,
    pub finished_ns: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryObservation {
    pub receipt: RecoveryReceipt,
    pub policy: Option<PolicyStamp>,
    pub at_ns: u64,
    pub state_before: ExecutionState,
    pub phase_before: u8,
    pub issued_before: bool,
    pub phase_after: u8,
    pub issued_after: bool,
    /// 1 close,2 readonly drain,3 request stop,4 stopped,5 start,6 running.
    pub method: u8,
    pub result: Result<bool, Error>,
}
#[derive(Clone, Copy)]
struct Service {
    key: ObjectKey,
    recipe: u16,
    last_start: Option<u64>,
    failures: u8,
    isolated: bool,
    restarts: u64,
    seen_epoch: u64,
    seen_plan: u64,
}
#[derive(Clone, Copy)]
struct Recovery {
    receipt: RecoveryReceipt,
    policy: Option<PolicyStamp>,
    phase: u8,
    issued: bool,
    order: u64,
}
pub struct RecoverySupervisor {
    services: [Option<Service>; 16],
    records: [Option<Recovery>; 272],
    sequence: u64,
}
impl Default for RecoverySupervisor {
    fn default() -> Self {
        Self::new()
    }
}
impl RecoverySupervisor {
    pub const fn new() -> Self {
        Self {
            services: [None; 16],
            records: [None; 272],
            sequence: 0,
        }
    }
    pub fn register(&mut self, target: ObjectKey, recipe: u16) -> Result<(), Error> {
        if target.id == 0 || target.generation == 0 || ![1, 2].contains(&recipe) {
            return Err(Error::Auth);
        }
        if self
            .services
            .iter()
            .flatten()
            .any(|s| s.key.id == target.id)
        {
            return Err(Error::Exists);
        }
        let i = self
            .services
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.services[i] = Some(Service {
            key: target,
            recipe,
            last_start: None,
            failures: 0,
            isolated: false,
            restarts: 0,
            seen_epoch: 0,
            seen_plan: 0,
        });
        Ok(())
    }
    fn service(&self, key: ObjectKey) -> Result<usize, Error> {
        self.services
            .iter()
            .position(|s| s.is_some_and(|s| s.key == key))
            .ok_or(Error::Stale)
    }
    pub fn query(&self, apply: ApplyId) -> Result<RecoveryReceipt, Error> {
        self.records
            .iter()
            .flatten()
            .find(|r| r.receipt.apply == apply)
            .map(|r| r.receipt)
            .ok_or(Error::Stale)
    }
    /// Model-selected recovery retains its exact zero-lease admission stamp.
    /// The independent non-model recovery entry remains available to safety
    /// work, and a retry cannot replace its identity or extend a policy window.
    pub fn begin_policy(
        &mut self,
        apply: ApplyId,
        recipe: u16,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<RecoveryReceipt, Error> {
        let action = Action::RecoveryRecipe(recipe);
        if let Some(old) = self
            .records
            .iter()
            .flatten()
            .find(|r| r.receipt.apply == apply)
        {
            return if old.receipt.recipe == recipe && old.policy == Some(stamp) {
                stamp.validate_action(action)?;
                Ok(old.receipt)
            } else {
                Err(Error::Conflict)
            };
        }
        PolicyStamp::default().accepts_action(action, stamp, now)?;
        let receipt = self.begin(apply, recipe, now)?;
        self.records
            .iter_mut()
            .flatten()
            .find(|r| r.receipt.apply == apply)
            .ok_or(Error::Stale)?
            .policy = Some(stamp);
        Ok(receipt)
    }
    pub fn begin(
        &mut self,
        apply: ApplyId,
        recipe: u16,
        now: u64,
    ) -> Result<RecoveryReceipt, Error> {
        if let Ok(old) = self.query(apply) {
            return if old.recipe == recipe {
                Ok(old)
            } else {
                Err(Error::Conflict)
            };
        }
        Action::RecoveryRecipe(recipe).validate()?;
        if apply.boot_epoch == 0
            || apply.controller_epoch == 0
            || apply.plan_seq == 0
            || apply.action_index >= 16
        {
            return Err(Error::Auth);
        }
        let i = self.service(apply.target)?;
        let service = self.services[i].ok_or(Error::Stale)?;
        if apply.controller_epoch < service.seen_epoch
            || (apply.controller_epoch == service.seen_epoch && apply.plan_seq <= service.seen_plan)
        {
            return Err(Error::Stale);
        }
        if recipe != 0 && recipe != service.recipe {
            return Err(Error::Auth);
        }
        if recipe != 0
            && (service.isolated
                || self
                    .records
                    .iter()
                    .flatten()
                    .any(|r| r.receipt.apply.target == apply.target && !r.receipt.state.terminal()))
        {
            return Err(Error::Busy);
        }
        if recipe != 0
            && service
                .last_start
                .is_some_and(|old| now < old || now - old < 1_000_000_000)
        {
            return Err(Error::Again);
        }
        let slot = self
            .records
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                self.records
                    .iter()
                    .enumerate()
                    .filter_map(|(i, r)| {
                        r.filter(|r| r.receipt.state.terminal())
                            .map(|r| (i, r.order))
                    })
                    .min_by_key(|(_, n)| *n)
                    .map(|(i, _)| i)
            })
            .ok_or(Error::Capacity)?;
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        let generation = if recipe == 0 {
            apply.target.generation
        } else {
            apply
                .target
                .generation
                .checked_add(1)
                .ok_or(Error::Overflow)?
        };
        let receipt = RecoveryReceipt {
            apply,
            recipe,
            state: if recipe == 0 {
                ExecutionState::Applied
            } else {
                ExecutionState::Pending
            },
            generation,
            started_ns: now,
            finished_ns: if recipe == 0 { now } else { 0 },
        };
        self.records[slot] = Some(Recovery {
            receipt,
            policy: None,
            phase: 0,
            issued: false,
            order: self.sequence,
        });
        let service = self.services[i].as_mut().ok_or(Error::Stale)?;
        service.seen_epoch = apply.controller_epoch;
        service.seen_plan = apply.plan_seq;
        if recipe != 0 {
            service.last_start = Some(now);
        }
        Ok(receipt)
    }
    pub fn poll<B: RecoveryBackend>(
        &mut self,
        apply: ApplyId,
        now: u64,
        backend: &mut B,
    ) -> Result<RecoveryReceipt, Error> {
        let slot = self
            .records
            .iter()
            .position(|r| r.is_some_and(|r| r.receipt.apply == apply))
            .ok_or(Error::Stale)?;
        let mut r = self.records[slot].ok_or(Error::Stale)?;
        if r.receipt.state.terminal() {
            return Ok(r.receipt);
        }
        if now < r.receipt.started_ns {
            return Err(Error::Range);
        }
        let phase_before = r.phase;
        let issued_before = r.issued;
        let state_before = r.receipt.state;
        let method = match (r.phase, r.issued) {
            (0, _) => 1,
            (1, _) => 2,
            (2, false) => 3,
            (2, true) => 4,
            (3, false) => 5,
            (3, true) => 6,
            _ => 0,
        };
        if now - r.receipt.started_ns >= 1_000_000_000 {
            r.receipt.state = ExecutionState::Unknown;
        }
        let target = apply.target;
        let step = match r.phase {
            0 => backend.close_admission(target).map(|()| true),
            1 => backend.readonly_drained(target),
            2 if !r.issued => backend.request_stop(target).map(|()| {
                r.issued = true;
                false
            }),
            2 => backend.stopped(target),
            3 if !r.issued => backend
                .start_generation(target, r.receipt.generation)
                .map(|()| {
                    r.issued = true;
                    false
                }),
            3 => backend.running(target, r.receipt.generation),
            _ => Err(Error::Conflict),
        };
        match step {
            Ok(true) => {
                r.phase += 1;
                r.issued = false;
                if r.phase == 4 {
                    r.receipt.state = ExecutionState::Applied;
                    r.receipt.finished_ns = now;
                    let i = self.service(target)?;
                    let s = self.services[i].as_mut().ok_or(Error::Stale)?;
                    s.key.generation = r.receipt.generation;
                    s.failures = 0;
                    s.restarts = s.restarts.saturating_add(1);
                }
            }
            Ok(false) | Err(Error::Again) | Err(Error::Busy) => (),
            Err(Error::Io) | Err(Error::NotReady) => {
                r.receipt.state = ExecutionState::Unknown;
                // An ambiguous start/stop is queried, never issued a second time.
                if r.phase == 2 || r.phase == 3 {
                    r.issued = true;
                }
            }
            Err(e) => {
                r.receipt.state = ExecutionState::Failed(e);
                r.receipt.finished_ns = now;
                let i = self.service(target)?;
                let s = self.services[i].as_mut().ok_or(Error::Stale)?;
                s.failures = s.failures.saturating_add(1);
                if s.failures >= 2 {
                    s.isolated = true;
                }
            }
        }
        self.records[slot] = Some(r);
        backend.observed(&RecoveryObservation {
            receipt: r.receipt,
            policy: r.policy,
            at_ns: now,
            state_before,
            phase_before,
            issued_before,
            phase_after: r.phase,
            issued_after: r.issued,
            method,
            result: step,
        });
        Ok(r.receipt)
    }
    pub fn recover_stopped(&mut self, target: ObjectKey) -> Result<(), Error> {
        let i = self.service(target)?;
        if self
            .records
            .iter()
            .flatten()
            .any(|r| r.receipt.apply.target == target && !r.receipt.state.terminal())
        {
            return Err(Error::Busy);
        }
        let s = self.services[i].as_mut().ok_or(Error::Stale)?;
        s.isolated = false;
        s.failures = 0;
        Ok(())
    }
    pub fn restarts(&self, target: ObjectKey) -> Result<u64, Error> {
        Ok(self.services[self.service(target)?]
            .ok_or(Error::Stale)?
            .restarts)
    }
    pub fn isolated(&self, target: ObjectKey) -> Result<bool, Error> {
        Ok(self.services[self.service(target)?]
            .ok_or(Error::Stale)?
            .isolated)
    }
}

pub trait ConsoleHardware {
    /// true means one byte was accepted; false is an effect-free full FIFO.
    /// An error is an uncertain write and poisons ordinary output until recovery.
    fn try_write(&mut self, byte: u8) -> Result<bool, Error>;
    fn now_ns(&mut self) -> u64;
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConsoleReceipt {
    pub chars: u16,
    pub policy_version: u64,
    pub cpu_ns: u64,
    pub tx_full: bool,
    pub wait_ns: u64,
}
pub struct ConsolePump {
    bytes: [u8; 4096],
    ages: [u64; 4096],
    head: usize,
    len: usize,
    audit: [u8; 4096],
    audit_head: usize,
    audit_len: usize,
    stamp: PolicyStamp,
    batch: u16,
    retry_ns: u64,
    poisoned: bool,
    pub calls: u64,
    pub full: u64,
    pub cpu_ns: u64,
    pub written: u64,
}
impl Default for ConsolePump {
    fn default() -> Self {
        Self::new()
    }
}
impl ConsolePump {
    pub const fn new() -> Self {
        Self {
            bytes: [0; 4096],
            ages: [0; 4096],
            head: 0,
            len: 0,
            audit: [0; 4096],
            audit_head: 0,
            audit_len: 0,
            stamp: PolicyStamp {
                version: 0,
                snapshot_ns: 0,
                installed_until_ns: 0,
            },
            batch: 8,
            retry_ns: 0,
            poisoned: false,
            calls: 0,
            full: 0,
            cpu_ns: 0,
            written: 0,
        }
    }
    pub fn install(&mut self, stamp: PolicyStamp, chars: u16, now: u64) -> Result<(), Error> {
        Action::ConsoleBatch(chars).validate()?;
        self.stamp.accepts(stamp, now)?;
        if self.stamp == stamp && self.batch != chars {
            return Err(Error::Conflict);
        }
        self.stamp = stamp;
        self.batch = chars;
        Ok(())
    }
    pub fn enqueue(&mut self, bytes: &[u8], now: u64) -> Result<(), Error> {
        if bytes.len() > 4096 - self.len {
            return Err(Error::Again);
        }
        for (i, b) in bytes.iter().enumerate() {
            let at = (self.head + self.len + i) % 4096;
            self.bytes[at] = *b;
            self.ages[at] = now;
        }
        self.len += bytes.len();
        Ok(())
    }
    pub fn audit_enqueue(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > 4096 - self.audit_len {
            return Err(Error::Capacity);
        }
        for (i, b) in bytes.iter().enumerate() {
            self.audit[(self.audit_head + self.audit_len + i) % 4096] = *b;
        }
        self.audit_len += bytes.len();
        Ok(())
    }
    pub fn audit_read(&self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.audit_len);
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = self.audit[(self.audit_head + i) % 4096];
        }
        n
    }
    pub fn audit_ack(&mut self, n: usize) -> Result<(), Error> {
        if n > self.audit_len {
            return Err(Error::Range);
        }
        self.audit_head = (self.audit_head + n) % 4096;
        self.audit_len -= n;
        Ok(())
    }
    pub const fn queued(&self) -> usize {
        self.len
    }
    pub const fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn current(&self, now: u64) -> u16 {
        if self.stamp.live(now) { self.batch } else { 8 }
    }
    pub fn pump<H: ConsoleHardware>(
        &mut self,
        now: u64,
        hardware: &mut H,
    ) -> Result<ConsoleReceipt, Error> {
        if self.poisoned {
            return Err(Error::Io);
        }
        if now < self.retry_ns || self.len == 0 {
            return Ok(ConsoleReceipt::default());
        }
        let start = hardware.now_ns();
        if start < now {
            self.poisoned = true;
            return Err(Error::Range);
        }
        let mut receipt = ConsoleReceipt {
            wait_ns: start.saturating_sub(self.ages[self.head]),
            ..ConsoleReceipt::default()
        };
        let batch = self.current(start);
        self.calls = self.calls.saturating_add(1);
        let mut failure = None;
        for _ in 0..batch {
            if self.len == 0 {
                break;
            }
            match hardware.try_write(self.bytes[self.head]) {
                Ok(true) => {
                    self.head = (self.head + 1) % 4096;
                    self.len -= 1;
                    receipt.chars += 1;
                }
                Ok(false) => {
                    receipt.tx_full = true;
                    self.full = self.full.saturating_add(1);
                    self.retry_ns = start.checked_add(100_000).ok_or(Error::Overflow)?;
                    break;
                }
                Err(error) => {
                    self.poisoned = true;
                    failure = Some(error);
                    break;
                }
            }
        }
        let end = hardware.now_ns();
        if end < start {
            self.poisoned = true;
            return Err(Error::Range);
        }
        receipt.cpu_ns = end - start;
        if receipt.chars > 0 && self.stamp.live(start) {
            receipt.policy_version = self.stamp.version;
        }
        self.cpu_ns = self.cpu_ns.saturating_add(receipt.cpu_ns);
        self.written = self.written.saturating_add(u64::from(receipt.chars));
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(receipt)
    }
}
