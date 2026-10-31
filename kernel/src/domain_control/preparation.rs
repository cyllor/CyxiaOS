//! CPU debit for a preparation interrupted by unavailable target evidence.
//! This is a decision bound, not a second reward/physical CPU charge.
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    policy::{ModelBinding, Snapshot},
};

// The candidate input page is hashed in a fixed non-preemptible tail.
// Enforce the existing 2 ms decision bound immediately before that tail,
// leaving the enclosing 2.5 ms native control credit for rejection and
// settlement without weakening either normative limit.
pub const DECISION_CPU_LIMIT_NS: u64 = 2_000_000;
pub fn check_decision_cpu(elapsed_ns: u64) -> Result<(), Error> {
    if elapsed_ns > DECISION_CPU_LIMIT_NS {
        Err(Error::Budget)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub boot: u64,
    pub controller: u64,
    pub sequence: u64,
    pub domain: u16,
    pub kind: u16,
    pub target: ObjectKey,
    pub model: ModelBinding,
    pub core_generation: u64,
    pub ledger_generation: u64,
    pub work: Option<[u64; 4]>,
}
#[derive(Clone, Copy, Debug)]
pub struct Pending {
    pub identity: Identity,
    pub snapshot: Snapshot,
    pub family: usize,
    pub ordinal: usize,
    spent_ns: u64,
    overflowed: bool,
    first_candidate: bool,
}
// The candidate marker uses existing padding; retain the original footprint.
const _: () = assert!(core::mem::size_of::<Pending>() <= 240);
impl Pending {
    pub fn new(identity: Identity, snapshot: Snapshot, family: usize, ordinal: usize) -> Self {
        Self {
            identity,
            snapshot,
            family,
            ordinal,
            spent_ns: 0,
            overflowed: false,
            first_candidate: false,
        }
    }
    pub fn first_candidate(
        identity: Identity,
        snapshot: Snapshot,
        family: usize,
        ordinal: usize,
    ) -> Self {
        let mut pending = Self::new(identity, snapshot, family, ordinal);
        pending.first_candidate = true;
        pending
    }
    pub fn is_first_candidate(&self) -> bool {
        self.first_candidate
    }
    pub fn check(&self, identity: Identity, at: u64) -> Result<(), Error> {
        if identity != self.identity {
            return Err(Error::Stale);
        }
        if self.overflowed {
            return Err(Error::Overflow);
        }
        if self.spent_ns > 2_000_000 {
            return Err(Error::Budget);
        }
        if at < self.snapshot.taken_ns || at - self.snapshot.taken_ns > 50_000_000 {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub fn charge(&mut self, elapsed_ns: u64) -> Result<(), Error> {
        if self.overflowed {
            return Err(Error::Overflow);
        }
        let Some(total) = self.spent_ns.checked_add(elapsed_ns) else {
            self.overflowed = true;
            return Err(Error::Overflow);
        };
        self.spent_ns = total;
        if total > 2_000_000 {
            Err(Error::Budget)
        } else {
            Ok(())
        }
    }
    pub fn carried(&self, identity: Identity, elapsed_ns: u64) -> Result<u64, Error> {
        if identity != self.identity {
            return Err(Error::Stale);
        }
        if self.overflowed {
            return Err(Error::Overflow);
        }
        self.spent_ns.checked_add(elapsed_ns).ok_or(Error::Overflow)
    }
    pub fn total(&self, identity: Identity, at: u64, elapsed_ns: u64) -> Result<u64, Error> {
        self.check(identity, at)?;
        let total = self.carried(identity, elapsed_ns)?;
        if total > 2_000_000 {
            Err(Error::Budget)
        } else {
            Ok(total)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Rejected {
    pub pending: Pending,
    pub reason: Error,
    pub retired_ns: u64,
}
impl Rejected {
    pub fn words(self, ordinal: u64) -> [u64; 40] {
        let mut words = [0; 40];
        let p = self.pending;
        let i = p.identity;
        words[..18].copy_from_slice(&[
            i.sequence,
            i.boot,
            i.controller,
            u64::from(i.domain),
            u64::from(i.kind),
            i.target.id,
            i.target.generation,
            i.model.generation,
            i.core_generation,
            i.ledger_generation,
            p.snapshot.taken_ns,
            p.spent_ns,
            u64::from(p.overflowed),
            self.reason as u64 + 1,
            self.retired_ns,
            p.family as u64,
            p.ordinal as u64,
            u64::from(i.work.is_some()),
        ]);
        words[18..22].copy_from_slice(&i.work.unwrap_or([0; 4]));
        for offset in 0..4 {
            words[22 + offset] = u64::from_le_bytes(
                i.model.model_hash[offset * 8..offset * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
            words[26 + offset] = u64::from_le_bytes(
                i.model.schema_hash[offset * 8..offset * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
        }
        words[30..34].copy_from_slice(&[
            p.snapshot.sequence,
            p.snapshot.core_generation,
            p.snapshot.ledger_generation,
            ordinal,
        ]);
        words
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retirement {
    pub sequence: u64,
    pub family: usize,
    pub ordinal: usize,
    pub due_ns: u64,
    pub next_family: usize,
}
pub struct Rejections {
    pub rows: [Option<Rejected>; 16],
    pub total: u64,
    pub overwritten: u64,
}
impl Rejections {
    pub const fn new() -> Self {
        Self {
            rows: [None; 16],
            total: 0,
            overwritten: 0,
        }
    }
    pub fn retire(
        &mut self,
        pending: Pending,
        reason: Error,
        retired_ns: u64,
        previous_sequence: u64,
    ) -> Result<Retirement, Error> {
        if pending.family >= 18 || matches!(reason, Error::Busy | Error::Again | Error::NotReady) {
            return Err(Error::Range);
        }
        if pending.identity.sequence > previous_sequence
            && next_sequence(previous_sequence, pending.identity).is_err()
            || self
                .rows
                .iter()
                .flatten()
                .any(|row| row.pending.identity == pending.identity)
        {
            return Err(Error::Stale);
        }
        let total = self.total.checked_add(1).ok_or(Error::Overflow)?;
        let slot = self.total as usize % self.rows.len();
        let period = if pending.family == 1 || pending.family == 16 {
            1_000_000_000
        } else {
            100_000_000
        };
        let due_ns = pending.snapshot.taken_ns.saturating_add(period);
        self.rows[slot] = Some(Rejected {
            pending,
            reason,
            retired_ns,
        });
        self.total = total;
        self.overwritten = total.saturating_sub(self.rows.len() as u64);
        Ok(Retirement {
            sequence: previous_sequence.max(pending.identity.sequence),
            family: pending.family,
            ordinal: pending.ordinal,
            due_ns,
            next_family: (pending.family + 1) % 18,
        })
    }
}
pub fn next_sequence(previous: u64, identity: Identity) -> Result<(), Error> {
    if previous.checked_add(1).ok_or(Error::Overflow)? == identity.sequence {
        Ok(())
    } else {
        Err(Error::Stale)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_gate_preserves_two_millisecond_limit() {
        assert_eq!(check_decision_cpu(DECISION_CPU_LIMIT_NS), Ok(()));
        assert!(matches!(
            check_decision_cpu(DECISION_CPU_LIMIT_NS + 1),
            Err(Error::Budget)
        ));
    }
}
