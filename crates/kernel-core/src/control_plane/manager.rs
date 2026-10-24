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
        if actor != self.publisher || !self.snapshot().permits(cpu, Plane::Control) {
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
        self.check_time(now)?;
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
