//! Pure ledger bookkeeping around actual producer entry/exit. The native
//! owner supplies real pool backing and never reconstructs elapsed CPU time.
use cyxia_peer_billing::{self as wire, Binding, TraceSeal};
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        Error, Family,
        reward::{CpuClass, CpuCoverage, CpuInterval, OBSERVATION_NS},
    },
};

/// Immutable relevance that can be checked before borrowing the live ledger.
/// Executor-work relevance also depends on its registered remote-token table
/// and deliberately returns `None` for the owner to resolve under the gate.
pub(crate) fn fixed_relevance(
    family: Family,
    target: ObjectKey,
    owner: ObjectKey,
    class: CpuClass,
) -> Option<bool> {
    match class {
        CpuClass::Policy | CpuClass::ExecutorAction => Some(
            owner == target
                || family
                    == (Family {
                        domain: 16,
                        kind: 2,
                    })
                    && owner
                        == (ObjectKey {
                            id: 16,
                            generation: 1,
                        }),
        ),
        CpuClass::Optional => Some(false),
        CpuClass::ExecutorWork => None,
    }
}
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lease {
    pub generation: u64,
    pub owner: ObjectKey,
    pub class: CpuClass,
    pub core: u16,
}
pub(crate) struct Ledger {
    pub binding: Binding,
    pub first: u64,
    pub observation: u64,
    pub frozen: [u8; 32],
    pub count: usize,
    pub open: usize,
    pub missing: u64,
    pub warmup: u64,
    pub later: u64,
    pub closing: Option<u64>,
    pub sealed: Option<TraceSeal>,
    pub excluded: Option<wire::ExcludedSeal>,
    failure: Option<wire::Failure>,
    hash: Sha256,
    cursor: usize,
    remote_tokens: [u64; 256],
    remote_count: usize,
}
impl Ledger {
    pub fn new(
        binding: Binding,
        first: u64,
        observation: u64,
        frozen: [u8; 32],
    ) -> Result<Self, Error> {
        binding.validate().map_err(|_| Error::Evidence)?;
        if first > observation
            || observation < 1_000_000_000
            || frozen == [0; 32]
            || observation
                .checked_add(OBSERVATION_NS + 5_000_000_000)
                .is_none()
        {
            return Err(Error::Evidence);
        }
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_KERNEL_CPU_TRACE_1.3\0");
        Ok(Self {
            binding,
            first,
            observation,
            frozen,
            count: 0,
            open: 0,
            missing: 0,
            warmup: 0,
            later: 0,
            closing: None,
            sealed: None,
            excluded: None,
            failure: None,
            hash,
            cursor: 0,
            remote_tokens: [0; 256],
            remote_count: 0,
        })
    }
    pub fn fail(&mut self, failure: wire::Failure) -> Result<(), Error> {
        failure.validate().map_err(|_| Error::Evidence)?;
        if failure
            .publication
            .is_some_and(|p| p.id.boot_epoch != self.binding.participant.boot)
            || self.failure.is_some_and(|old| old != failure)
        {
            return Err(Error::Evidence);
        }
        if self.closing.is_some() {
            return Err(Error::Stale);
        }
        self.failure = Some(failure);
        Ok(())
    }
    pub fn register_remote(&mut self, token: u64) -> Result<(), Error> {
        if token == 0 || self.closing.is_some() {
            return Err(Error::Stale);
        }
        if self.remote_tokens[..self.remote_count].contains(&token) {
            return Ok(());
        }
        if self.remote_count == self.remote_tokens.len() {
            return Err(Error::Capacity);
        }
        self.remote_tokens[self.remote_count] = token;
        self.remote_count += 1;
        Ok(())
    }
    fn relevant(&self, owner: ObjectKey, class: CpuClass) -> bool {
        match fixed_relevance(self.binding.family, self.binding.target, owner, class) {
            Some(relevant) => relevant,
            None => {
                // Actual scheduler identities of the shared service and the
                // single remote pure-task executor. Generations are never erased
                // from a lease, even when the physical thread id is reused.
                owner
                    == (ObjectKey {
                        id: 0x101,
                        generation: 1,
                    })
                    || owner.id == 0x100
                        && self.remote_tokens[..self.remote_count].contains(&owner.generation)
            }
        }
    }
    pub fn begin(&mut self, owner: ObjectKey, class: CpuClass, core: u16) -> Option<Lease> {
        if !self.relevant(owner, class) {
            return None;
        }
        if self.closing.is_some() || core >= 64 || owner.generation == 0 {
            self.missing = self.missing.saturating_add(1);
            return None;
        }
        self.open += 1;
        Some(Lease {
            generation: self.binding.run.generation,
            owner,
            class,
            core,
        })
    }
    pub fn dropped(&mut self, lease: Lease) {
        if lease.generation == self.binding.run.generation && self.open != 0 {
            self.open -= 1;
        }
        self.missing = self.missing.saturating_add(1);
    }
    pub fn cancel_unstarted(&mut self, lease: Lease) -> Result<(), Error> {
        if lease.generation != self.binding.run.generation || self.open == 0 {
            return Err(Error::Stale);
        }
        self.open -= 1;
        Ok(())
    }
    /// Returns the actually charged clipped interval. Warmup and later work
    /// retain their real duration but cannot masquerade as observation CPU.
    pub fn finish(
        &mut self,
        lease: Lease,
        first: u64,
        last: u64,
        now: u64,
    ) -> Result<Option<CpuInterval>, Error> {
        if lease.generation != self.binding.run.generation || self.open == 0 {
            return Err(Error::Stale);
        }
        self.open -= 1;
        if first > last
            || last > now
            || self.sealed.is_some()
            || self.excluded.is_some()
            || !self.relevant(lease.owner, lease.class)
        {
            self.missing = self.missing.saturating_add(1);
            return Err(Error::Evidence);
        }
        let end = self.observation + OBSERVATION_NS;
        let (a, b) = if lease.class == CpuClass::ExecutorWork {
            let warm = self.observation - 1_000_000_000;
            self.warmup = self
                .warmup
                .checked_add(last.min(self.observation).saturating_sub(first.max(warm)))
                .ok_or(Error::Numeric)?;
            self.later = self
                .later
                .checked_add(last.saturating_sub(first.max(end)))
                .ok_or(Error::Numeric)?;
            (first.max(self.observation), last.min(end))
        } else {
            (first.max(self.first), last.min(end + 5_000_000_000))
        };
        if a >= b {
            return Ok(None);
        }
        if self.count == wire::MAX_INTERVALS {
            self.missing = self.missing.saturating_add(1);
            return Err(Error::Capacity);
        }
        self.count += 1;
        Ok(Some(CpuInterval {
            node: self.binding.participant.node,
            core: lease.core,
            class: lease.class,
            start_ns: a,
            end_ns: b,
        }))
    }
    pub fn close(&mut self, now: u64, drained: bool) -> Result<(), Error> {
        if !drained || self.open != 0 || now < self.observation + OBSERVATION_NS {
            return Err(Error::Unknown);
        }
        if self.closing.is_none() {
            self.closing = Some(now);
        }
        Ok(())
    }
    pub fn hash_piece(&mut self, offset: usize, values: &[CpuInterval]) -> Result<bool, Error> {
        if self.closing.is_none() || self.open != 0 {
            return Err(Error::DataIncomplete);
        }
        if self.sealed.is_some() || self.excluded.is_some() {
            return Ok(true);
        }
        if offset != self.cursor
            || values.len() > wire::CHUNK_INTERVALS
            || offset + values.len() > self.count
        {
            return Err(Error::Evidence);
        }
        for value in values {
            let mut bytes = [0; wire::INTERVAL_BYTES];
            wire::encode_interval(*value, &mut bytes).map_err(|_| Error::Evidence)?;
            self.hash.update(bytes);
        }
        self.cursor += values.len();
        if self.cursor == self.count {
            let closing = self.closing.ok_or(Error::Unknown)?;
            let reasons = (if self.missing != 0 {
                wire::MISSING_EVENTS
            } else {
                0
            }) | (if closing > self.observation + OBSERVATION_NS + 5_000_000_000 {
                wire::LATE_CLOSING
            } else {
                0
            }) | (if self.failure.is_some() {
                wire::ROOT_FAULT
            } else {
                0
            });
            let seal = TraceSeal {
                binding_hash: self.binding.hash().map_err(|_| Error::Evidence)?,
                owner: self.binding.owner,
                coverage: CpuCoverage {
                    node: self.binding.participant.node,
                    first_ns: self.first,
                    observation_ns: self.observation,
                    observation_end_ns: self.observation + OBSERVATION_NS,
                    closing_ns: closing,
                    required: 3,
                    reported: if reasons == 0 { 3 } else { 0 },
                },
                count: self.count as u64,
                intervals_hash: self.hash.clone().finalize().into(),
                frozen_other_domains: self.frozen,
                missing_events: self.missing,
                ordinary_warmup_ns: self.warmup,
                later_workload_ns: self.later,
            };
            if reasons == 0 {
                seal.validate().map_err(|_| Error::DataIncomplete)?;
                self.sealed = Some(seal);
            } else {
                let excluded = wire::ExcludedSeal {
                    trace: seal,
                    exclusion: wire::Exclusion {
                        reasons,
                        drained_ns: closing,
                        failure: self.failure,
                    },
                };
                excluded.validate().map_err(|_| Error::DataIncomplete)?;
                self.excluded = Some(excluded);
            }
            return Ok(true);
        }
        Ok(false)
    }
    pub fn hash_cursor(&self) -> usize {
        self.cursor
    }
}
