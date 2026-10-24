//! Kernel-owned validated policy cache. All resource domains use the same API.
//! Acceptance is NOT execution, resource reservation, I/O completion or durability.
//! Executors must still validate objects, authorize operations, and charge their
//! actual resource ledger. No cache operation runs or waits for a model.
use super::{
    Epochs, Error, Identity, Plane,
    cores::{Phase, Snapshot},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub epochs: Epochs,
    pub subject: Identity,
    pub domain: usize,
    pub sequence: u64,
    pub valid_from: u64,
    /// Absolute original expiry. Receiving a late message never renews its TTL.
    pub expires_at: u64,
    pub plane: Plane,
    pub cpus: u64,
    pub units: u64,
    pub budget_ticks: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_units: u64,
    pub max_budget_ticks: u64,
    pub max_lifetime: u64,
    pub allowed_cpus: u64,
}
/// Fresh, trusted EL1 observation. Never deserialize this from a model request.
#[derive(Clone, Copy, Debug)]
pub struct Environment {
    pub epochs: Epochs,
    pub cores: Snapshot,
    pub now: u64,
    pub limits: Limits,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    Policy(Proposal),
    /// Explicitly use deterministic survival rules, NOT an unchecked old plan.
    /// Already accepted I/O and resource-release completions remain executable.
    SafeExec(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub domain: usize,
    pub sequence: u64,
    pub expires_at: u64,
}

pub struct Bank<const D: usize> {
    publisher: Identity,
    epochs: Epochs,
    policies: [Option<Proposal>; D],
    highwater: [u64; D],
    last_time: u64,
}
impl<const D: usize> Bank<D> {
    pub fn new(publisher: Identity, epochs: Epochs) -> Result<Self, Error> {
        if D == 0 || !publisher.valid() || !epochs.valid() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            publisher,
            epochs,
            policies: [None; D],
            highwater: [0; D],
            last_time: 0,
        })
    }
    /// Kernel lifecycle operation. Model, resources, topology or publisher
    /// changes invalidate all plans atomically under the management serializer.
    /// The same controller cannot reset decision high-water marks by publishing
    /// a new model. A different process needs a newer controller epoch.
    pub fn reconfigure(
        &mut self,
        publisher: Identity,
        epochs: Epochs,
        now: u64,
    ) -> Result<(), Error> {
        if now < self.last_time {
            return Err(Error::Clock);
        }
        if !publisher.valid() || !epochs.valid() {
            return Err(Error::Invalid);
        }
        let old = self.epochs;
        if epochs.boot != old.boot
            || epochs.controller < old.controller
            || epochs.model < old.model
            || epochs.resources < old.resources
            || epochs.cores < old.cores
            || (publisher != self.publisher && epochs.controller == old.controller)
        {
            return Err(Error::Stale);
        }
        if epochs == old && publisher == self.publisher {
            self.last_time = now;
            return Ok(());
        }
        if epochs.controller > old.controller {
            self.highwater.fill(0);
        }
        self.policies.fill(None);
        self.publisher = publisher;
        self.epochs = epochs;
        self.last_time = now;
        Ok(())
    }
    fn environment(&self, env: Environment) -> Result<(), Error> {
        if env.now < self.last_time {
            return Err(Error::Clock);
        }
        if env.epochs != self.epochs || env.cores.generation != env.epochs.cores {
            return Err(Error::Stale);
        }
        if env.cores.phase != Phase::Stable {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    fn validate(&self, p: Proposal, env: Environment) -> Result<(), Error> {
        self.environment(env)?;
        if p.domain >= D
            || !p.subject.valid()
            || p.sequence == 0
            || p.cpus == 0
            || p.units == 0
            || p.budget_ticks == 0
        {
            return Err(Error::Invalid);
        }
        if p.epochs != env.epochs {
            return Err(Error::Stale);
        }
        if p.expires_at <= env.now {
            return Err(Error::Expired);
        }
        if p.valid_from > env.now || p.expires_at <= p.valid_from {
            return Err(Error::Invalid);
        }
        let lifetime = p.expires_at - p.valid_from;
        let owned = match p.plane {
            Plane::Control => env.cores.control,
            Plane::Business => env.cores.business,
        };
        if p.cpus & !(owned & env.limits.allowed_cpus) != 0
            || p.units > env.limits.max_units
            || p.budget_ticks > env.limits.max_budget_ticks
            || lifetime > env.limits.max_lifetime
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    /// The actor and CPU are obtained from current kernel execution context.
    pub fn accept(
        &mut self,
        actor: Identity,
        cpu: usize,
        proposal: Proposal,
        env: Environment,
    ) -> Result<Accepted, Error> {
        if actor != self.publisher || !env.cores.permits(cpu, Plane::Control) {
            return Err(Error::Denied);
        }
        self.validate(proposal, env)?;
        if proposal.sequence <= self.highwater[proposal.domain] {
            return Err(Error::Stale);
        }
        // No mutable producer memory survives this copy. Failed validation leaves
        // the previous policy and the anti-replay high-water mark unchanged.
        self.policies[proposal.domain] = Some(proposal);
        self.highwater[proposal.domain] = proposal.sequence;
        self.last_time = env.now;
        Ok(Accepted {
            domain: proposal.domain,
            sequence: proposal.sequence,
            expires_at: proposal.expires_at,
        })
    }
    /// Constant bounded hot-path lookup: no channel reads, model calls or loops.
    /// Expiry and all epochs/ownership/limits are checked again at execution.
    pub fn select(
        &self,
        domain: usize,
        subject: Identity,
        cpu: usize,
        plane: Plane,
        env: Environment,
    ) -> Selection {
        let result = (|| {
            let p = self
                .policies
                .get(domain)
                .copied()
                .flatten()
                .ok_or(Error::NotReady)?;
            self.validate(p, env)?;
            if p.subject != subject {
                return Err(Error::Stale);
            }
            if p.plane != plane || cpu >= 64 || p.cpus & (1u64 << cpu) == 0 {
                return Err(Error::Denied);
            }
            Ok(p)
        })();
        match result {
            Ok(p) => Selection::Policy(p),
            Err(e) => Selection::SafeExec(e),
        }
    }
    /// Revocation does not roll back completed actions or forget replay history.
    pub fn revoke(&mut self, domain: usize) -> Result<(), Error> {
        *self.policies.get_mut(domain).ok_or(Error::Invalid)? = None;
        Ok(())
    }
}
