//! Dynamic exclusive CPU ownership. Core IDs/counts are never chosen here.
//! A caller supplies the AI's desired set; this module only checks constraints.
use super::{Error, Plane};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Offline,
    Ready,
    Draining,
    Quiescent,
    Prepared,
    Quarantined,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Core {
    /// Retained through draining/quarantine until a verified handoff commits.
    pub owner: Option<Plane>,
    pub state: State,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Stable,
    Transition,
    Recovery,
    Halted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub generation: u64,
    pub control: u64,
    pub business: u64,
    pub transition: u64,
    pub quarantined: u64,
    pub online: u64,
    pub phase: Phase,
}
impl Snapshot {
    pub const fn permits(self, cpu: usize, plane: Plane) -> bool {
        if cpu >= 64 {
            return false;
        }
        let mask = match plane {
            Plane::Control => self.control,
            Plane::Business => self.business,
        };
        mask & (1u64 << cpu) != 0
    }
}

/// Measured, kernel-owned commitments. Changing them requires a new epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub resource_epoch: u64,
    pub min_control_cores: u32,
    pub min_control_capacity: u64,
    pub min_business_capacity: u64,
    pub committed_business_capacity: u64,
    pub protected_control: u64,
    pub protected_business: u64,
    pub cooldown_ticks: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaleProposal {
    pub generation: u64,
    pub resource_epoch: u64,
    pub sequence: u64,
    pub desired_control: u64,
    pub deadline: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    generation: u64,
    serial: u64,
}
impl Ticket {
    pub const fn generation(self) -> u64 {
        self.generation
    }
    pub const fn serial(self) -> u64 {
        self.serial
    }
}

/// Proof bits are collected from trusted kernel/architecture completion paths,
/// NOT decoded from a model message. A timeout is never a substitute for proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof(pub u16);
impl Proof {
    pub const TASKS: u16 = 1;
    pub const IRQ: u16 = 2;
    pub const RCU: u16 = 4;
    pub const IPI: u16 = 8;
    pub const WORKERS: u16 = 16;
    pub const REFERENCES: u16 = 32;
    pub const TIMERS: u16 = 64;
    pub const DMA: u16 = 128;
    pub const STOPPED: u16 = 256;
    pub const MAPPINGS: u16 = 512;
    pub const BARRIERS: u16 = 1024;
    pub const DRAIN: Self = Self(255);
    pub const HANDOFF: Self = Self(Self::STOPPED | Self::MAPPINGS | Self::BARRIERS);
    pub const RECOVERY: Self = Self(Self::DRAIN.0 | Self::HANDOFF.0);
    const fn includes(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}
#[derive(Clone, Copy, Debug)]
struct Transition {
    ticket: Ticket,
    changed: u64,
    target: u64,
    deadline: u64,
    resource_epoch: u64,
}
#[derive(Clone, Copy, Debug)]
struct Recovery {
    ticket: Ticket,
    mask: u64,
    proved: u64,
}

pub struct Ownership<const N: usize> {
    cores: [Core; N],
    capacity: [u32; N],
    /// All SMT siblings of one physical core must move together.
    groups: [u64; N],
    online: u64,
    generation: u64,
    serial: u64,
    sequence: u64,
    last_time: u64,
    next_change: u64,
    transition: Option<Transition>,
    recovery: Option<Recovery>,
    halted: bool,
}
impl<const N: usize> Ownership<N> {
    pub fn new(
        online: u64,
        control: u64,
        capacity: [u32; N],
        groups: [u64; N],
        limits: Limits,
    ) -> Result<Self, Error> {
        if N == 0 || N > 64 {
            return Err(Error::Invalid);
        }
        let valid = if N == 64 { u64::MAX } else { (1u64 << N) - 1 };
        if online == 0 || online & !valid != 0 {
            return Err(Error::Invalid);
        }
        for i in 0..N {
            if online & (1 << i) == 0 {
                continue;
            }
            if capacity[i] == 0 || groups[i] & (1 << i) == 0 || groups[i] & !online != 0 {
                return Err(Error::Invalid);
            }
            for j in 0..N {
                if groups[i] & (1 << j) != 0 && groups[i] != groups[j] {
                    return Err(Error::Invalid);
                }
            }
        }
        let mut value = Self {
            cores: [Core {
                owner: None,
                state: State::Offline,
            }; N],
            capacity,
            groups,
            online,
            generation: 1,
            serial: 0,
            sequence: 0,
            last_time: 0,
            next_change: 0,
            transition: None,
            recovery: None,
            halted: false,
        };
        value.validate_partition(control, online & !control, limits)?;
        for i in 0..N {
            if online & (1 << i) != 0 {
                value.cores[i] = Core {
                    owner: Some(if control & (1 << i) != 0 {
                        Plane::Control
                    } else {
                        Plane::Business
                    }),
                    state: State::Ready,
                };
            }
        }
        Ok(value)
    }
    /// Called by Manager only after authenticating a newer controller epoch.
    /// Ticket generations/serials are never reset.
    pub(super) fn restart_sequence(&mut self) -> Result<(), Error> {
        if self.transition.is_some() {
            return Err(Error::Busy);
        }
        self.sequence = 0;
        Ok(())
    }
    pub fn core(&self, cpu: usize) -> Option<Core> {
        self.cores.get(cpu).copied()
    }
    pub fn snapshot(&self) -> Snapshot {
        let mut s = Snapshot {
            generation: self.generation,
            control: 0,
            business: 0,
            transition: 0,
            quarantined: 0,
            online: self.online,
            phase: if self.halted {
                Phase::Halted
            } else if self.recovery.is_some() {
                Phase::Recovery
            } else if self.transition.is_some() {
                Phase::Transition
            } else {
                Phase::Stable
            },
        };
        for (i, c) in self.cores.iter().enumerate() {
            match c.state {
                State::Ready => match c.owner {
                    Some(Plane::Control) => s.control |= 1 << i,
                    Some(Plane::Business) => s.business |= 1 << i,
                    None => {}
                },
                State::Draining | State::Quiescent | State::Prepared => s.transition |= 1 << i,
                State::Quarantined => s.quarantined |= 1 << i,
                State::Offline => {}
            }
        }
        s
    }
    fn capacity_of(&self, mask: u64) -> u64 {
        self.capacity
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, v)| u64::from(*v))
            .sum()
    }
    fn validate_partition(&self, control: u64, business: u64, l: Limits) -> Result<(), Error> {
        if l.resource_epoch == 0
            || l.min_control_cores == 0
            || l.min_control_capacity == 0
            || l.min_business_capacity == 0
            || control & business != 0
            || (control | business) & !self.online != 0
            || l.protected_control & l.protected_business != 0
            || (l.protected_control | l.protected_business) & !self.online != 0
        {
            return Err(Error::Invalid);
        }
        if control.count_ones() < l.min_control_cores
            || self.capacity_of(control) < l.min_control_capacity
            || self.capacity_of(business)
                < l.min_business_capacity.max(l.committed_business_capacity)
            || l.protected_control & !control != 0
            || l.protected_business & !business != 0
        {
            return Err(Error::Denied);
        }
        for g in self.groups {
            if (g & control != 0 && g & !control != 0) || (g & business != 0 && g & !business != 0)
            {
                return Err(Error::Denied);
            }
        }
        Ok(())
    }
    fn time(&self, now: u64) -> Result<(), Error> {
        if now < self.last_time {
            Err(Error::Clock)
        } else {
            Ok(())
        }
    }
    fn next_ticket(&self) -> Result<Ticket, Error> {
        Ok(Ticket {
            generation: self.generation.checked_add(1).ok_or(Error::Exhausted)?,
            serial: self.serial.checked_add(1).ok_or(Error::Exhausted)?,
        })
    }
    fn adopt_ticket(&mut self, t: Ticket, now: u64) {
        self.generation = t.generation;
        self.serial = t.serial;
        self.last_time = now;
    }
    /// VALIDATE + RESERVE are one serialized transaction; failures change nothing.
    /// DRAIN removes all changing cores from BOTH dispatch sets immediately.
    pub fn begin(&mut self, p: ScaleProposal, now: u64, limits: Limits) -> Result<Ticket, Error> {
        self.time(now)?;
        if self.halted {
            return Err(Error::Exhausted);
        }
        if self.transition.is_some() || self.recovery.is_some() {
            return Err(Error::Busy);
        }
        if p.generation != self.generation
            || p.resource_epoch != limits.resource_epoch
            || p.sequence == 0
            || p.sequence <= self.sequence
        {
            return Err(Error::Stale);
        }
        if p.deadline <= now {
            return Err(Error::Expired);
        }
        if now < self.next_change {
            return Err(Error::Busy);
        }
        let old = self.snapshot();
        if old.control == p.desired_control {
            return Err(Error::Invalid);
        }
        let business = self.online & !p.desired_control;
        self.validate_partition(p.desired_control, business, limits)?;
        // Already granted capacity and a surviving controller must remain during
        // migration, not merely at the proposed final partition.
        self.validate_partition(
            old.control & p.desired_control,
            old.business & business,
            limits,
        )?;
        let changed = old.control ^ p.desired_control;
        let ticket = self.next_ticket()?;
        for i in 0..N {
            if changed & (1 << i) != 0 {
                self.cores[i].state = State::Draining;
            }
        }
        self.transition = Some(Transition {
            ticket,
            changed,
            target: p.desired_control,
            deadline: p.deadline,
            resource_epoch: p.resource_epoch,
        });
        self.sequence = p.sequence;
        self.adopt_ticket(ticket, now);
        Ok(ticket)
    }
    fn active(&self, ticket: Ticket, now: u64) -> Result<Transition, Error> {
        self.time(now)?;
        let t = self.transition.ok_or(Error::Stale)?;
        if t.ticket != ticket {
            return Err(Error::Stale);
        }
        if now >= t.deadline {
            return Err(Error::Expired);
        }
        Ok(t)
    }
    fn check_cpu(&self, cpu: usize, mask: u64) -> Result<(), Error> {
        if cpu >= N || mask & (1 << cpu) == 0 {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
    pub fn acknowledge_drain(
        &mut self,
        ticket: Ticket,
        cpu: usize,
        proof: Proof,
        now: u64,
    ) -> Result<(), Error> {
        let t = self.active(ticket, now)?;
        self.check_cpu(cpu, t.changed)?;
        if !proof.includes(Proof::DRAIN) {
            return Err(Error::NotReady);
        }
        match self.cores[cpu].state {
            State::Draining => self.cores[cpu].state = State::Quiescent,
            State::Quiescent | State::Prepared => {}
            _ => return Err(Error::Stale),
        }
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
        let t = self.active(ticket, now)?;
        self.check_cpu(cpu, t.changed)?;
        if !proof.includes(Proof::HANDOFF)
            || !matches!(self.cores[cpu].state, State::Quiescent | State::Prepared)
        {
            return Err(Error::NotReady);
        }
        self.cores[cpu].state = State::Prepared;
        self.last_time = now;
        Ok(())
    }
    pub fn publish(&mut self, ticket: Ticket, now: u64, limits: Limits) -> Result<Snapshot, Error> {
        let t = self.active(ticket, now)?;
        if limits.resource_epoch != t.resource_epoch {
            return Err(Error::Stale);
        }
        self.validate_partition(t.target, self.online & !t.target, limits)?;
        if (0..N).any(|i| t.changed & (1 << i) != 0 && self.cores[i].state != State::Prepared) {
            return Err(Error::NotReady);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Exhausted)?;
        let next_change = now
            .checked_add(limits.cooldown_ticks)
            .ok_or(Error::Exhausted)?;
        for i in 0..N {
            if t.changed & (1 << i) != 0 {
                self.cores[i] = Core {
                    owner: Some(if t.target & (1 << i) != 0 {
                        Plane::Control
                    } else {
                        Plane::Business
                    }),
                    state: State::Ready,
                };
            }
        }
        self.generation = generation;
        self.next_change = next_change;
        self.last_time = now;
        self.transition = None;
        Ok(self.snapshot())
    }
    fn quarantine(&mut self, mask: u64, now: u64) -> Result<Ticket, Error> {
        self.time(now)?;
        if self.halted {
            return Err(Error::Exhausted);
        }
        let mask =
            mask | self.transition.map_or(0, |t| t.changed) | self.recovery.map_or(0, |r| r.mask);
        let ticket = match self.next_ticket() {
            Ok(ticket) => ticket,
            Err(error) => {
                // Exhaustion must not leave a faulted core dispatchable. No
                // wrapping ticket or recovery is permitted after this point.
                for c in &mut self.cores {
                    if c.owner.is_some() {
                        c.state = State::Quarantined;
                    }
                }
                self.transition = None;
                self.recovery = None;
                self.halted = true;
                return Err(error);
            }
        };
        for i in 0..N {
            if mask & (1 << i) != 0 {
                self.cores[i].state = State::Quarantined;
            }
        }
        // Preserve last owner. All earlier ACKs become stale, including recovery
        // ACKs if another fault arrives while restoring the first one.
        self.transition = None;
        self.recovery = Some(Recovery {
            ticket,
            mask,
            proved: 0,
        });
        self.adopt_ticket(ticket, now);
        Ok(ticket)
    }
    pub fn abort(&mut self, ticket: Ticket, now: u64) -> Result<Ticket, Error> {
        self.time(now)?;
        let t = self.transition.ok_or(Error::Stale)?;
        if t.ticket != ticket {
            return Err(Error::Stale);
        }
        self.quarantine(t.changed, now)
    }
    /// Faults quarantine the whole physical group, never just one SMT sibling.
    pub fn fault(&mut self, cpu: usize, now: u64) -> Result<Ticket, Error> {
        self.check_cpu(cpu, self.online)?;
        self.quarantine(self.groups[cpu], now)
    }
    pub fn expire(&mut self, now: u64) -> Result<Option<Ticket>, Error> {
        self.time(now)?;
        if let Some(t) = self.transition
            && now >= t.deadline
        {
            return self.abort(t.ticket, now).map(Some);
        }
        self.last_time = now;
        Ok(None)
    }
    pub fn acknowledge_recovery(
        &mut self,
        ticket: Ticket,
        cpu: usize,
        proof: Proof,
        now: u64,
    ) -> Result<(), Error> {
        self.time(now)?;
        let r = self.recovery.ok_or(Error::Stale)?;
        if r.ticket != ticket {
            return Err(Error::Stale);
        }
        self.check_cpu(cpu, r.mask)?;
        if !proof.includes(Proof::RECOVERY) {
            return Err(Error::NotReady);
        }
        self.recovery = Some(Recovery {
            proved: r.proved | (1 << cpu),
            ..r
        });
        self.last_time = now;
        Ok(())
    }
    /// Restore original owners ONLY after positive stop/mapping/barrier proofs
    /// and revalidation against CURRENT resource commitments and protected IRQs.
    pub fn restore(&mut self, ticket: Ticket, now: u64, limits: Limits) -> Result<Snapshot, Error> {
        self.time(now)?;
        let r = self.recovery.ok_or(Error::Stale)?;
        if r.ticket != ticket {
            return Err(Error::Stale);
        }
        if r.proved != r.mask {
            return Err(Error::NotReady);
        }
        let control = self
            .cores
            .iter()
            .enumerate()
            .filter(|(_, c)| c.owner == Some(Plane::Control))
            .fold(0, |m, (i, _)| m | (1 << i));
        self.validate_partition(control, self.online & !control, limits)?;
        let generation = self.generation.checked_add(1).ok_or(Error::Exhausted)?;
        let next_change = now
            .checked_add(limits.cooldown_ticks)
            .ok_or(Error::Exhausted)?;
        for i in 0..N {
            if r.mask & (1 << i) != 0 {
                self.cores[i].state = State::Ready;
            }
        }
        self.generation = generation;
        self.next_change = next_change;
        self.last_time = now;
        self.recovery = None;
        Ok(self.snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fault_at_epoch_exhaustion_quarantines_every_core() {
        let l = Limits {
            resource_epoch: 1,
            min_control_cores: 1,
            min_control_capacity: 1,
            min_business_capacity: 1,
            committed_business_capacity: 1,
            protected_control: 0,
            protected_business: 0,
            cooldown_ticks: 0,
        };
        let mut o = Ownership::new(3, 1, [1; 2], [1, 2], l).unwrap();
        o.generation = u64::MAX;
        assert_eq!(o.fault(0, 0), Err(Error::Exhausted));
        let s = o.snapshot();
        assert_eq!(s.phase, Phase::Halted);
        assert_eq!(s.control | s.business, 0);
        assert_eq!(s.quarantined, 3);
    }
}
