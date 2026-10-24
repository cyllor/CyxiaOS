//! Local policy/cluster bridge. Remote AI never gets a CoreOwner mutation API.
//! Check CPU, memory and I/O via the same accepted-policy interface, then the
//! owner ledger independently reserves actual capacity. A missing policy denies
//! NEW admission, not completion/release of an already accepted action.
use super::{Error, Quota, Result};
use crate::control_plane::{
    Identity, Plane,
    policy::{Bank, Environment, Selection},
};
pub struct Admission<'a, const D: usize> {
    bank: &'a Bank<D>,
    subject: Identity,
    domains: [usize; 3],
    business_cpu: usize,
}
impl<'a, const D: usize> Admission<'a, D> {
    pub fn new(
        bank: &'a Bank<D>,
        subject: Identity,
        domains: [usize; 3],
        business_cpu: usize,
    ) -> Self {
        Self {
            bank,
            subject,
            domains,
            business_cpu,
        }
    }
    pub fn subject(&self) -> Identity {
        self.subject
    }
    pub fn check(&self, quota: Quota, env: Environment) -> Result<u64> {
        if !quota.valid() || !self.subject.valid() {
            return Err(Error::Invalid);
        }
        // Domains must be distinct: one CPU allowance cannot double as memory.
        if self.domains[0] == self.domains[1]
            || self.domains[0] == self.domains[2]
            || self.domains[1] == self.domains[2]
        {
            return Err(Error::Invalid);
        }
        let quantities = [quota.cpu_ticks, quota.memory_pages, quota.io_units];
        let mut until = u64::MAX;
        for (index, amount) in quantities.into_iter().enumerate() {
            if amount == 0 {
                continue;
            }
            let Selection::Policy(p) = self.bank.select(
                self.domains[index],
                self.subject,
                self.business_cpu,
                Plane::Business,
                env,
            ) else {
                return Err(Error::Policy);
            };
            if amount > if index == 0 { p.budget_ticks } else { p.units } {
                return Err(Error::Policy);
            }
            until = until.min(p.expires_at);
        }
        Ok(until)
    }
}
