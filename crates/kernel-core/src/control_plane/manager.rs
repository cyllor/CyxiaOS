//! Serialized EL1 management engine coupling ownership, epochs and policy cache.
//! The architecture adapter must authenticate callers, copy EL0 input, generate
//! proof records, program timers/page tables, and enforce dispatch permissions.
//! This engine intentionally has no model function and no blocking operation.
use super::{
    Epochs, Error, Identity, Plane,
    cores::{Limits, Ownership, Proof, Snapshot, Ticket},
    policy::{self, Bank, Selection},
    queue::{QueueError, Receiver},
    wire::{Request, WORDS},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Receipt {
    Accepted(policy::Accepted),
    Draining(Ticket),
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrainReport {
    pub received: usize,
    pub accepted: usize,
    pub rejected: usize,
}
pub struct Manager<const C: usize, const D: usize> {
    ownership: Ownership<C>,
    bank: Bank<D>,
    epochs: Epochs,
    publisher: Identity,
    limits: Limits,
    policy_limits: [policy::Limits; D],
    pending: Option<Ticket>,
    last_time: u64,
}
impl<const C: usize, const D: usize> Manager<C, D> {
    /// Production V0.20 constructor: forbid historical mutable control-core
    /// topology from entering the trusted manager. The fixed control core is
    /// CPU0 (fixed.rs re-exports the cpu0_v0199 constants).
    pub fn new_fixed(
        ownership: Ownership<C>,
        publisher: Identity,
        epochs: Epochs,
        limits: Limits,
        policy_limits: [policy::Limits; D],
    ) -> Result<Self, Error> {
        if !ownership.fixed_control() {
            return Err(Error::Invalid);
        }
        Self::new(ownership, publisher, epochs, limits, policy_limits)
    }
    /// V0.19.9 reference topology: true CPU0 controller with CPU1-3
    /// business cores. Native EL0 scheduling and IRQ migration must be
    /// independently boot-tested before this constructor is selected there.
    pub fn new_v0199_cpu0(
        ownership: Ownership<C>,
        publisher: Identity,
        epochs: Epochs,
        limits: Limits,
        policy_limits: [policy::Limits; D],
    ) -> Result<Self, Error> {
        if !ownership.native_cpu0_v0199()
            || !ownership.fixed_control()
            || super::cpu0_v0199::validate_snapshot(ownership.snapshot()).is_err()
        {
            return Err(Error::Invalid);
        }
        Self::new(ownership, publisher, epochs, limits, policy_limits)
    }
    pub fn new(
        ownership: Ownership<C>,
        publisher: Identity,
        epochs: Epochs,
        limits: Limits,
        policy_limits: [policy::Limits; D],
    ) -> Result<Self, Error> {
        if epochs.cores != ownership.snapshot().generation
            || epochs.resources != limits.resource_epoch
        {
            return Err(Error::Stale);
        }
        Ok(Self {
            ownership,
            bank: Bank::new(publisher, epochs)?,
            epochs,
            publisher,
            limits,
            policy_limits,
            pending: None,
            last_time: 0,
        })
    }
    /// Read-only auxiliary review of independently authenticated Operations
    /// and Security AI suggestions. EL1 builds the trusted scope; a reviewed
    /// candidate is NOT a policy, capability, executor instruction or approval.
    /// Publication remains confined to submit()/the native policy ledger.
    pub fn review_brains<const A: usize>(
        &self,
        pair: &super::fixed::Pair,
        rules: &super::advisory::Controller<A>,
        domain: usize,
        subject: Identity,
        now: u64,
    ) -> Result<super::fixed::Review, Error> {
        self.check_time(now)?;
        let snapshot = self.snapshot();
        let (control, cpu) = if self.ownership.native_cpu0_v0199() {
            (
                super::cpu0_v0199::CONTROL_MASK,
                super::cpu0_v0199::CONTROL_CPU,
            )
        } else {
            (super::fixed::CONTROL_MASK, super::fixed::CONTROL_CPU)
        };
        if !self.ownership.fixed_control()
            || snapshot.control != control
            || snapshot.phase != super::cores::Phase::Stable
            || !snapshot.permits(cpu, Plane::Control)
            || !subject.valid()
        {
            return Err(Error::Denied);
        }
        pair.review(
            rules,
            super::advisory::TrustedScope {
                epochs: self.epochs,
                domain,
                target: subject,
                now_ns: now,
            },
        )
    }
    /// Metered variant of [`Self::review_brains`] — demonstration wiring of
    /// the G1 lock-chain freeze scaffolding ([`super::policy_lock_v0199`]).
    /// This engine has no trusted live clock (every `now` is caller-supplied),
    /// so the caller provides the monotonic section entry `now` and the
    /// observed completion `done_ns`. The review itself is unchanged: same
    /// checks, same result, same error semantics on the happy path. The
    /// elapsed interval is charged to the effective-work budget (≤45μs, spec
    /// L1542); an overrun latches a sticky fail-closed fault in the meter and
    /// closes further metered admission — it never panics and never alters
    /// the review outcome. A regressing `done_ns` keeps the scope open
    /// (Error::Clock) rather than inventing a duration. The production
    /// policy_lock object and IRQ-off enforcement points remain the G1
    /// freeze's deliverable, not this scaffold.
    // Mirrors review_brains' exact engine signature plus the caller-supplied
    // meter; a parameter struct would diverge from the established API.
    #[allow(clippy::too_many_arguments)]
    pub fn review_brains_metered<const A: usize>(
        &self,
        meter: &mut super::policy_lock_v0199::CriticalSectionMeter,
        pair: &super::fixed::Pair,
        rules: &super::advisory::Controller<A>,
        domain: usize,
        subject: Identity,
        now: u64,
        done_ns: u64,
    ) -> Result<super::fixed::Review, Error> {
        meter.begin(super::policy_lock_v0199::SectionKind::EffectiveWork, now)?;
        let review = self.review_brains(pair, rules, domain, subject, now);
        // Settle even when the review failed: the elapsed interval is real
        // either way. The settlement's overrun class is diagnostic; the
        // review result is returned verbatim.
        meter.end(done_ns)?;
        review
    }
    pub const fn epochs(&self) -> Epochs {
        self.epochs
    }
    pub fn snapshot(&self) -> Snapshot {
        self.ownership.snapshot()
    }
    fn check_time(&self, now: u64) -> Result<(), Error> {
        if now < self.last_time {
            Err(Error::Clock)
        } else {
            Ok(())
        }
    }
    fn actor(&self, actor: Identity, cpu: usize) -> Result<(), Error> {
        // SEC-S04: a protected local publisher identity, never an AI proposal
        // or a claimed network identity, is the only admissible submitter.
        let caller =
            crate::security::syscall::ProtectedRole::from_kernel(actor.id, actor.generation);
        let owner = crate::security::syscall::ProtectedRole::from_kernel(
            self.publisher.id,
            self.publisher.generation,
        );
        let authorization = if self.ownership.native_cpu0_v0199() {
            crate::security::syscall::can_publish_cpu0_v0199(
                caller,
                owner,
                cpu,
                self.snapshot().control,
            )
        } else if self.ownership.fixed_control() {
            crate::security::syscall::can_publish_fixed(caller, owner, cpu, self.snapshot().control)
        } else {
            // Historical transition test fixtures are not native V0.19.
            crate::security::syscall::can_publish(caller, owner)
        };
        if authorization.is_err() || !self.snapshot().permits(cpu, Plane::Control) {
            Err(Error::Denied)
        } else {
            Ok(())
        }
    }
    fn env(&self, domain: usize, now: u64) -> Result<policy::Environment, Error> {
        Ok(policy::Environment {
            epochs: self.epochs,
            cores: self.snapshot(),
            now,
            limits: *self.policy_limits.get(domain).ok_or(Error::Invalid)?,
        })
    }
    fn sync(&mut self, now: u64) -> Result<(), Error> {
        self.epochs.cores = self.snapshot().generation;
        self.last_time = now;
        // Even if this returns an error, current core/epoch checks make any old
        // cache entry unusable. There is no unchecked previous-policy fallback.
        self.bank.reconfigure(self.publisher, self.epochs, now)
    }
    pub fn submit(
        &mut self,
        actor: Identity,
        cpu: usize,
        words: [u64; WORDS],
        now: u64,
    ) -> Result<Receipt, Error> {
        self.check_time(now)?;
        self.actor(actor, cpu)?;
        let request = Request::decode(words)?;
        if request.epochs() != self.epochs {
            return Err(Error::Stale);
        }
        let receipt = match request {
            Request::Policy(p) => {
                Receipt::Accepted(self.bank.accept(actor, cpu, p, self.env(p.domain, now)?)?)
            }
            Request::Scale { proposal, .. } => {
                let t = self.ownership.begin(proposal, now, self.limits)?;
                self.pending = Some(t);
                self.sync(now)?;
                Receipt::Draining(t)
            }
        };
        self.last_time = now;
        Ok(receipt)
    }
    /// Called by the controller service loop, never by a business hot path.
    /// Invalid messages consume only their bounded processing slot.
    pub fn drain<const N: usize>(
        &mut self,
        actor: Identity,
        cpu: usize,
        rx: &mut Receiver<'_, N, WORDS>,
        limit: usize,
        now: u64,
    ) -> Result<DrainReport, Error> {
        self.check_time(now)?;
        self.actor(actor, cpu)?;
        if limit == 0 || limit > 64 {
            return Err(Error::Invalid);
        }
        let mut result = DrainReport::default();
        for _ in 0..limit {
            let words = match rx.try_receive() {
                Ok(w) => w,
                Err(QueueError::Empty) => break,
                Err(_) => return Err(Error::Invalid),
            };
            result.received += 1;
            match self.submit(actor, cpu, words, now) {
                Ok(_) => result.accepted += 1,
                Err(_) => result.rejected += 1,
            }
        }
        Ok(result)
    }
    pub fn select(
        &self,
        domain: usize,
        subject: Identity,
        cpu: usize,
        plane: Plane,
        now: u64,
    ) -> Selection {
        if let Err(e) = self.check_time(now) {
            return Selection::SafeExec(e);
        }
        match self.env(domain, now) {
            Ok(env) => self.bank.select(domain, subject, cpu, plane, env),
            Err(e) => Selection::SafeExec(e),
        }
    }
    pub fn acknowledge_drain(
        &mut self,
        ticket: Ticket,
        cpu: usize,
        proof: Proof,
        now: u64,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        self.ownership.acknowledge_drain(ticket, cpu, proof, now)?;
        self.last_time = now;
        Ok(())
    }
    pub fn acknowledge_handoff(
        &mut self,
        ticket: Ticket,
        cpu: usize,
        proof: Proof,
        now: u64,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        self.ownership
            .acknowledge_handoff(ticket, cpu, proof, now)?;
        self.last_time = now;
        Ok(())
    }
    pub fn publish(&mut self, ticket: Ticket, now: u64) -> Result<Snapshot, Error> {
        self.check_time(now)?;
        let s = self.ownership.publish(ticket, now, self.limits)?;
        self.pending = None;
        self.sync(now)?;
        Ok(s)
    }
    /// Metered variant of [`Self::publish`] — a second demonstration wiring of
    /// the G1 lock-chain freeze scaffolding ([`super::policy_lock_v0199`]),
    /// alongside [`Self::review_brains_metered`]. Drain publication is a real
    /// bounded critical section: it swaps the ownership partition and
    /// reconfigures the policy cache, with no allocation, IPC or waiting.
    ///
    /// Same trust model as the review wiring: the engine has no trusted live
    /// clock, so the caller supplies the monotonic section entry `now` and the
    /// observed completion `done_ns`. The publication itself is unchanged —
    /// same checks, same snapshot, same error semantics on the happy path.
    /// The elapsed interval is charged to the effective-work budget (≤45μs,
    /// spec L1542); an overrun latches a sticky fail-closed fault in the meter
    /// and closes further metered admission. It never panics and never alters
    /// the publication outcome. A regressing `done_ns` keeps the scope open
    /// ([`Error::Clock`]) rather than inventing a duration.
    ///
    /// Unlike the read-only review, `publish` mutates engine state. Metering is
    /// observational, never a transaction: if settlement fails with
    /// [`Error::Clock`] the publication has already been applied and is NOT
    /// rolled back; the open scope must be settled by the caller through
    /// [`super::policy_lock_v0199::CriticalSectionMeter::end`] with a corrected
    /// timestamp, and the resulting snapshot re-read via [`Self::snapshot`].
    /// The production policy_lock object and IRQ-off enforcement points remain
    /// the G1 freeze's deliverable, not this scaffold.
    pub fn publish_metered(
        &mut self,
        meter: &mut super::policy_lock_v0199::CriticalSectionMeter,
        ticket: Ticket,
        now: u64,
        done_ns: u64,
    ) -> Result<Snapshot, Error> {
        meter.begin(super::policy_lock_v0199::SectionKind::EffectiveWork, now)?;
        let published = self.publish(ticket, now);
        // Settle even when publication failed: the elapsed interval is real
        // either way. The settlement's overrun class is diagnostic; the
        // publication result is returned verbatim.
        meter.end(done_ns)?;
        published
    }
    pub fn expire(&mut self, now: u64) -> Result<Option<Ticket>, Error> {
        self.check_time(now)?;
        let result = self.ownership.expire(now)?;
        if result.is_some() {
            self.pending = None;
        }
        self.sync(now)?;
        Ok(result)
    }
    pub fn fault(&mut self, cpu: usize, now: u64) -> Result<Ticket, Error> {
        // Safety notification: late delivery cannot suppress CPU quarantine.
        let now = now.max(self.last_time);
        let result = self.ownership.fault(cpu, now);
        if result.is_ok() || self.snapshot().phase == super::cores::Phase::Halted {
            self.pending = None;
            self.sync(now)?;
        }
        result
    }
    pub fn acknowledge_recovery(
        &mut self,
        ticket: Ticket,
        cpu: usize,
        proof: Proof,
        now: u64,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        self.ownership
            .acknowledge_recovery(ticket, cpu, proof, now)?;
        self.last_time = now;
        Ok(())
    }
    pub fn restore(&mut self, ticket: Ticket, now: u64) -> Result<Snapshot, Error> {
        self.check_time(now)?;
        let s = self.ownership.restore(ticket, now, self.limits)?;
        self.sync(now)?;
        Ok(s)
    }
    /// An authenticated controller restart or model publication invalidates ALL
    /// queued old proposals and aborts any migration derived from the old model.
    /// Return the recovery ticket rather than pretending the cores were freed.
    pub fn replace_controller(
        &mut self,
        publisher: Identity,
        controller_epoch: u64,
        model_epoch: u64,
        now: u64,
    ) -> Result<Option<Ticket>, Error> {
        self.check_time(now)?;
        if !publisher.valid()
            || controller_epoch < self.epochs.controller
            || model_epoch < self.epochs.model
            || (publisher != self.publisher && controller_epoch == self.epochs.controller)
            || (controller_epoch == self.epochs.controller && model_epoch == self.epochs.model)
        {
            return Err(Error::Stale);
        }
        let recovery = if let Some(t) = self.pending {
            Some(self.ownership.abort(t, now)?)
        } else {
            None
        };
        if controller_epoch > self.epochs.controller {
            self.ownership.restart_sequence()?;
        }
        self.pending = None;
        self.publisher = publisher;
        self.epochs.controller = controller_epoch;
        self.epochs.model = model_epoch;
        self.sync(now)?;
        Ok(recovery)
    }
    /// Only the trusted resource ledger updates these limits. During a migration
    /// a changed epoch prevents publication; recovery uses these CURRENT values.
    pub fn update_limits(
        &mut self,
        limits: Limits,
        policy_limits: [policy::Limits; D],
        now: u64,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        if limits.resource_epoch <= self.epochs.resources {
            return Err(Error::Stale);
        }
        self.limits = limits;
        self.policy_limits = policy_limits;
        self.epochs.resources = limits.resource_epoch;
        self.sync(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::advisory::{Controller, Rule};
    use crate::control_plane::cores::ScaleProposal;
    use crate::control_plane::fixed::Pair;
    use crate::control_plane::policy_lock_v0199::{
        CriticalSectionMeter, Fault, OverrunClass, SectionKind, WORK_BUDGET_NS,
    };

    fn limits() -> Limits {
        Limits {
            resource_epoch: 1,
            min_control_cores: 1,
            min_control_capacity: 100,
            min_business_capacity: 100,
            committed_business_capacity: 100,
            protected_control: 0,
            protected_business: 0,
            cooldown_ticks: 3,
        }
    }
    fn id(n: u64) -> Identity {
        Identity {
            id: n,
            generation: 1,
        }
    }
    fn epochs() -> Epochs {
        Epochs {
            boot: 1,
            controller: 1,
            model: 1,
            resources: 1,
            cores: 1,
        }
    }
    fn manager() -> Manager<4, 16> {
        let ownership = Ownership::<4>::new_fixed(15, [100; 4], [1, 2, 4, 8], limits()).unwrap();
        let policy_limits = policy::Limits {
            max_units: 8,
            max_budget_ticks: 4,
            max_lifetime: 100,
            allowed_cpus: 15,
        };
        Manager::new_fixed(ownership, id(10), epochs(), limits(), [policy_limits; 16]).unwrap()
    }
    fn rules() -> Controller<15> {
        Controller::new(
            [Rule {
                baseline: 2,
                options: &[1, 2, 4],
            }; 15],
        )
        .unwrap()
    }

    #[test]
    fn metered_review_matches_unmetered_on_happy_path() {
        let m = manager();
        let pair = Pair::new(id(100), id(200)).unwrap();
        let rules = rules();
        let mut meter = CriticalSectionMeter::new();
        let plain = m.review_brains(&pair, &rules, 1, id(20), 10).unwrap();
        let metered = m
            .review_brains_metered(&mut meter, &pair, &rules, 1, id(20), 10, 10 + 1_000)
            .unwrap();
        assert_eq!(plain, metered);
        assert_eq!(meter.settled_count(), 1);
        assert_eq!(meter.overrun_count(), 0);
        assert!(!meter.faulted());
        assert_eq!(meter.active_kind(), None);
    }

    #[test]
    fn metered_review_overrun_latches_fault_without_changing_result() {
        let m = manager();
        let pair = Pair::new(id(100), id(200)).unwrap();
        let rules = rules();
        let mut meter = CriticalSectionMeter::new();
        let plain = m.review_brains(&pair, &rules, 1, id(20), 10).unwrap();
        let done = 10 + WORK_BUDGET_NS + 1;
        // Overrun is diagnostic: the review outcome is returned verbatim.
        let metered = m
            .review_brains_metered(&mut meter, &pair, &rules, 1, id(20), 10, done)
            .unwrap();
        assert_eq!(plain, metered);
        assert!(meter.faulted());
        assert_eq!(meter.overrun_count(), 1);
        assert!(matches!(
            meter.fault(),
            Some(Fault::BudgetOverrun {
                kind: SectionKind::EffectiveWork,
                ..
            })
        ));
        // Fail-closed: further metered admission is denied, while the
        // unmetered production path keeps its existing behavior.
        assert_eq!(
            m.review_brains_metered(&mut meter, &pair, &rules, 1, id(20), done, done + 1),
            Err(Error::Denied)
        );
        assert_eq!(
            m.review_brains(&pair, &rules, 1, id(20), done).unwrap(),
            plain
        );
    }

    #[test]
    fn metered_review_regressing_completion_clock_keeps_scope_open() {
        let m = manager();
        let pair = Pair::new(id(100), id(200)).unwrap();
        let rules = rules();
        let mut meter = CriticalSectionMeter::new();
        assert_eq!(
            m.review_brains_metered(&mut meter, &pair, &rules, 1, id(20), 100, 99),
            Err(Error::Clock)
        );
        assert_eq!(meter.active_kind(), Some(SectionKind::EffectiveWork));
        assert!(!meter.faulted());
        assert_eq!(meter.settled_count(), 0);
    }

    // ---- publish_metered: second real critical section (drain publication) ----

    /// Historical mutable topology (NOT new_fixed): only this path admits a
    /// Scale proposal, so a real drain/publication critical section can run.
    fn mutable_manager() -> Manager<4, 16> {
        let ownership = Ownership::<4>::new(15, 1, [100; 4], [1, 2, 4, 8], limits()).unwrap();
        let policy_limits = policy::Limits {
            max_units: 8,
            max_budget_ticks: 4,
            max_lifetime: 100,
            allowed_cpus: 15,
        };
        Manager::new(ownership, id(10), epochs(), limits(), [policy_limits; 16]).unwrap()
    }
    /// Drive a real Scale admission to a pending drain ticket ready to publish:
    /// CPU1 moves business→control (control mask 1→3), drained and handed off.
    fn drain_ticket(m: &mut Manager<4, 16>, now: u64) -> Ticket {
        let scale = Request::Scale {
            epochs: m.epochs(),
            proposal: ScaleProposal {
                generation: m.snapshot().generation,
                resource_epoch: 1,
                sequence: 1,
                desired_control: 3,
                deadline: 100,
            },
        };
        let t = match m.submit(id(10), 0, scale.encode(), now).unwrap() {
            Receipt::Draining(t) => t,
            _ => panic!("expected draining receipt"),
        };
        m.acknowledge_drain(t, 1, Proof::DRAIN, now + 1).unwrap();
        m.acknowledge_handoff(t, 1, Proof::HANDOFF, now + 1)
            .unwrap();
        t
    }

    #[test]
    fn metered_publish_matches_unmetered_on_happy_path() {
        // Two identical engines driven to the same pre-publication state; one
        // publishes plain, the other metered. The snapshot must be identical.
        let mut plain = mutable_manager();
        let mut metered = mutable_manager();
        let tp = drain_ticket(&mut plain, 10);
        let tm = drain_ticket(&mut metered, 10);
        let mut meter = CriticalSectionMeter::new();
        let s_plain = plain.publish(tp, 12).unwrap();
        let s_metered = metered
            .publish_metered(&mut meter, tm, 12, 12 + 1_000)
            .unwrap();
        assert_eq!(s_plain, s_metered);
        assert_eq!(s_metered.control, 3);
        assert_eq!(metered.snapshot(), plain.snapshot());
        assert_eq!(meter.settled_count(), 1);
        assert_eq!(meter.overrun_count(), 0);
        assert!(!meter.faulted());
        assert_eq!(meter.active_kind(), None);
    }

    #[test]
    fn metered_publish_overrun_latches_fault_without_changing_result() {
        let mut m = mutable_manager();
        let t = drain_ticket(&mut m, 10);
        let mut meter = CriticalSectionMeter::new();
        let done = 12 + WORK_BUDGET_NS + 1;
        // Overrun is diagnostic: the publication outcome is returned verbatim.
        let s = m.publish_metered(&mut meter, t, 12, done).unwrap();
        assert_eq!(s.control, 3);
        assert!(meter.faulted());
        assert_eq!(meter.overrun_count(), 1);
        assert!(matches!(
            meter.fault(),
            Some(Fault::BudgetOverrun {
                kind: SectionKind::EffectiveWork,
                ..
            })
        ));
        // Fail-closed: further metered admission is denied before the engine
        // runs, so engine state is untouched by the denied call.
        let before = m.snapshot();
        assert_eq!(
            m.publish_metered(&mut meter, t, done, done + 1),
            Err(Error::Denied)
        );
        assert_eq!(m.snapshot(), before);
        // The unmetered production path keeps its existing behavior: a consumed
        // ticket still reports the engine's own error, not the meter's.
        assert_eq!(m.publish(t, 13), Err(Error::Stale));
    }

    #[test]
    fn metered_publish_settles_even_when_publication_fails() {
        // No drain/handoff proofs: the engine rejects with NotReady, but the
        // elapsed interval is real and must still settle within budget.
        let mut m = mutable_manager();
        let scale = Request::Scale {
            epochs: m.epochs(),
            proposal: ScaleProposal {
                generation: m.snapshot().generation,
                resource_epoch: 1,
                sequence: 1,
                desired_control: 3,
                deadline: 100,
            },
        };
        let t = match m.submit(id(10), 0, scale.encode(), 10).unwrap() {
            Receipt::Draining(t) => t,
            _ => panic!("expected draining receipt"),
        };
        let mut meter = CriticalSectionMeter::new();
        assert_eq!(
            m.publish_metered(&mut meter, t, 12, 12 + 1_000),
            Err(Error::NotReady)
        );
        assert_eq!(meter.settled_count(), 1);
        assert_eq!(meter.overrun_count(), 0);
        assert!(!meter.faulted());
        assert_eq!(meter.active_kind(), None);
    }

    #[test]
    fn metered_publish_regressing_completion_clock_keeps_scope_open() {
        let mut m = mutable_manager();
        let t = drain_ticket(&mut m, 10);
        let mut meter = CriticalSectionMeter::new();
        // now=50 is before the proposal deadline (100), so publication applies;
        // done_ns=49 regresses and keeps the scope open.
        assert_eq!(m.publish_metered(&mut meter, t, 50, 49), Err(Error::Clock));
        assert_eq!(meter.active_kind(), Some(SectionKind::EffectiveWork));
        assert!(!meter.faulted());
        assert_eq!(meter.settled_count(), 0);
        // Metering is observational, never a transaction: the publication was
        // already applied and is NOT rolled back by the bad completion clock.
        assert_eq!(m.snapshot().control, 3);
        // The caller settles the open scope with a corrected timestamp; the
        // snapshot is re-read from the engine, not from the failed return.
        let s = meter.end(50 + 1_000).unwrap();
        assert_eq!(s.overrun_class, OverrunClass::None);
        assert_eq!(meter.settled_count(), 1);
        assert!(!meter.faulted());
    }
}
