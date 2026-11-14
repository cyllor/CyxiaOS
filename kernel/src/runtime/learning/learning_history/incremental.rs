//! Bounded native attestation over the still-retained capture and journal.
//! A new view is borrowed for each paid turn; no Trial reference is retained.
use super::*;
use cyxia_prototype::learning::reward::{IncrementalAuthority, ReplayPiece};

pub struct Incremental<'a> {
    trace: &'a crate::learning_evidence::SealedTrace<'a>,
    model: &'a [u8; MODEL_BYTES],
    model_binding: ModelBinding,
    #[cfg(not(test))]
    partner: Option<crate::peer_replay::PartnerSeal>,
}
struct Metadata {
    scope: FrozenScope,
    checks: ReplayChecks,
    binding: [u8; 32],
}

// A failed read of a real gate is the only retry condition. In particular a
// protected owner returning Capture(Unknown) retains that terminal error.
fn acquired<T>(result: Result<T, Error>) -> Result<Option<T>, learning::Error> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::Busy) => Ok(None),
        Err(error) => Err(learn(error)),
    }
}
impl<'a> Incremental<'a> {
    /// The private model lease establishes the model source. A caller cannot
    /// authorize arbitrary model bytes by supplying their pointer or digest.
    #[cfg(not(test))]
    pub fn new(
        trace: &'a crate::learning_evidence::SealedTrace<'a>,
        model: &'a crate::domain_control::NativeModelPin,
        partner: Option<crate::peer_replay::PartnerSeal>,
    ) -> Result<Self, learning::Error> {
        let address = model
            .physical_address()
            .checked_add(crate::HIGH)
            .ok_or(learning::Error::Capacity)?;
        Ok(Self {
            trace,
            model: unsafe { &*(address as *const [u8; MODEL_BYTES]) },
            model_binding: model.binding(),
            partner,
        })
    }
    /// Host tests supply their explicit model-owner fixture; this constructor
    /// is not present in the native kernel and cannot authorize native data.
    #[cfg(test)]
    pub fn for_test(
        trace: &'a crate::learning_evidence::SealedTrace<'a>,
        model: &'a [u8; MODEL_BYTES],
        model_binding: ModelBinding,
    ) -> Self {
        Self {
            trace,
            model,
            model_binding,
        }
    }

    fn metadata(&self, trial: &Trial<'_>) -> Result<Option<Metadata>, learning::Error> {
        let seal = self.trace.seal();
        #[cfg(test)]
        let (extra, warmup, later, proof) = (0usize, 0u64, 0u64, None);
        #[cfg(not(test))]
        let (extra, warmup, later, proof) = if let Some(peer) = self.partner {
            let Some(actual) = crate::peer_replay::partner_bounded(seal.key)? else {
                return Ok(None);
            };
            if actual != peer {
                return Err(learning::Error::Stale);
            }
            let Some(scope) = acquired(super::scope())? else {
                return Ok(None);
            };
            (
                usize::try_from(peer.seal.count).map_err(|_| learning::Error::Capacity)?,
                peer.seal.ordinary_warmup_ns,
                peer.seal.later_workload_ns,
                Some((peer.seal.coverage, partner_frozen(&scope, &peer)?)),
            )
        } else {
            (0, 0, 0, None)
        };
        let Some((scope, checks)) =
            acquired(scope_metadata(trial, seal, self.trace.coverage(), proof))?
        else {
            return Ok(None);
        };
        let status = self.trace.status();
        if status.sealed != Some(seal)
            || status.fault.is_some()
            || status.missing_events != 0
            || trial.cpu.len() != seal.intervals as usize + extra
            || trial.requests.len() != seal.requests as usize
            || trial.ordinary_warmup_cpu_ns
                != status
                    .ordinary_warmup_ns
                    .checked_add(warmup)
                    .ok_or(learning::Error::Numeric)?
            || trial.later_workload_cpu_ns
                != status
                    .later_workload_ns
                    .checked_add(later)
                    .ok_or(learning::Error::Numeric)?
            || trial.schemas.feature.hash != self.model_binding.schema_hash
            || !trial.joint_policy.is_empty()
        {
            return Err(learning::Error::Evidence);
        }
        // The native replay root publishes one action at a time. Its actual
        // retained owner supplies empty common spans; caller-supplied joint
        // arrays cannot substitute for a missing common-span owner.
        for adoption in trial.adoptions {
            if adoption.candidates.model != self.model_binding
                || !core::ptr::eq(adoption.model, self.model)
                || !adoption.shared_policy_intervals.is_empty()
                || adoption.concurrent != [adoption.apply]
            {
                return Err(learning::Error::Evidence);
            }
        }
        let Some((used, adopted, baselines)) = acquired(with(|owner, storage| {
            if owner.sealed != Some(seal) || owner.scope != Some(scope) {
                return Err(Error::Stale);
            }
            if let Some(error) = owner.fault {
                return fail(error);
            }
            let (mut adopted, mut baselines) = (0, 0);
            for index in 0..owner.used {
                let flags = u64_at(row(storage, index), 0);
                adopted += usize::from(flags & PUBLISHED != 0);
                baselines += usize::from(flags & BASELINE != 0);
            }
            Ok((owner.used, adopted, baselines))
        }))?
        else {
            return Ok(None);
        };
        if (adopted, baselines) != (trial.adoptions.len(), trial.baseline.len()) {
            return Err(learning::Error::Evidence);
        }
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_NATIVE_INCREMENTAL_AUTHORITY_1.3\0");
        hash.update(seal.event_hash);
        hash.update(seal.frozen_scope_hash);
        for value in [
            seal.key.boot_epoch,
            seal.key.trial_id,
            seal.key.generation,
            seal.closing_ns,
            u64::from(seal.intervals),
            u64::from(seal.requests),
            used as u64,
            adopted as u64,
            baselines as u64,
            self.model_binding.generation,
        ] {
            hash.update(value.to_le_bytes());
        }
        hash.update(self.model_binding.model_hash);
        hash.update(self.model_binding.schema_hash);
        #[cfg(not(test))]
        if let Some(peer) = self.partner {
            hash.update(peer.seal.binding_hash);
            hash.update(peer.seal.intervals_hash);
            hash.update(peer.seal.frozen_other_domains);
            for value in [
                peer.seal.count,
                peer.seal.coverage.first_ns,
                peer.seal.coverage.observation_ns,
                peer.seal.coverage.observation_end_ns,
                peer.seal.coverage.closing_ns,
                peer.seal.ordinary_warmup_ns,
                peer.seal.later_workload_ns,
            ] {
                hash.update(value.to_le_bytes());
            }
        }
        Ok(Some(Metadata {
            scope,
            checks,
            binding: hash.finalize().into(),
        }))
    }

    fn cpu_piece(
        &self,
        trial: &Trial<'_>,
        start: usize,
        end: usize,
    ) -> Result<bool, learning::Error> {
        if start >= end || end > trial.cpu.len() || end - start > 16 {
            return Err(learning::Error::Evidence);
        }
        let local = self.trace.intervals();
        let local_end = end.min(local.len());
        if start < local_end && trial.cpu[start..local_end] != local[start..local_end] {
            return Err(learning::Error::Evidence);
        }
        if end > local.len() {
            #[cfg(test)]
            return Err(learning::Error::Evidence);
            #[cfg(not(test))]
            {
                if self.partner.is_none() {
                    return Err(learning::Error::Evidence);
                }
                let first = start.max(local.len());
                let mut rows = [CpuInterval {
                    node: [0; 32],
                    core: 0,
                    start_ns: 0,
                    end_ns: 0,
                    class: CpuClass::Policy,
                }; 16];
                let Some(count) = crate::peer_replay::copy_intervals_bounded(
                    self.trace.seal().key,
                    first - local.len(),
                    &mut rows[..end - first],
                )?
                else {
                    return Ok(false);
                };
                if count != end - first || trial.cpu[first..end] != rows[..count] {
                    return Err(learning::Error::Evidence);
                }
            }
        }
        Ok(true)
    }
}

impl IncrementalAuthority for Incremental<'_> {
    fn begin(&self, trial: &Trial<'_>) -> Result<Option<[u8; 32]>, learning::Error> {
        Ok(self.metadata(trial)?.map(|metadata| metadata.binding))
    }
    fn attest_piece(
        &self,
        trial: &Trial<'_>,
        binding: [u8; 32],
        piece: ReplayPiece,
    ) -> Result<bool, learning::Error> {
        let Some(metadata) = self.metadata(trial)? else {
            return Ok(false);
        };
        if metadata.binding != binding {
            return Err(learning::Error::Stale);
        }
        let run = metadata.scope.key;
        match piece {
            ReplayPiece::Header => frozen(&metadata),
            ReplayPiece::Adoption { index } => {
                let adoption = trial
                    .adoptions
                    .get(index)
                    .ok_or(learning::Error::Evidence)?;
                let Some(_) = acquired(adoption_metadata(run, adoption, false))? else {
                    return Ok(false);
                };
                let Some(()) = acquired(with(|owner, storage| {
                    let index =
                        find_decision(owner, storage, adoption.decision_seq).ok_or(Error::Stale)?;
                    let row = row(storage, index);
                    if u64_at(row, 480) != 0 || bytes32(row, 448) != shared_hash(&[]) {
                        return fail(learning::Error::Evidence);
                    }
                    Ok(())
                }))?
                else {
                    return Ok(false);
                };
                issued(&metadata, adoption)
            }
            ReplayPiece::Model {
                adoption,
                start,
                end,
            } => {
                let adoption = trial
                    .adoptions
                    .get(adoption)
                    .ok_or(learning::Error::Evidence)?;
                if start >= end
                    || end > MODEL_BYTES
                    || end - start > 256
                    || adoption.model[start..end] != self.model[start..end]
                {
                    return Err(learning::Error::Evidence);
                }
                Ok(true)
            }
            ReplayPiece::Candidate { adoption, index } => {
                let adoption = trial
                    .adoptions
                    .get(adoption)
                    .ok_or(learning::Error::Evidence)?;
                Ok(acquired(candidate_piece(run, adoption, index))?.is_some())
            }
            ReplayPiece::Baseline { index } => {
                let baseline = trial.baseline.get(index).ok_or(learning::Error::Evidence)?;
                let Some(_) = acquired(baseline_metadata(run, baseline))? else {
                    return Ok(false);
                };
                baseline_check(&metadata, baseline)
            }
            ReplayPiece::Requests { start, end } => {
                if start >= end
                    || end > trial.requests.len()
                    || end - start > 16
                    || trial.requests[start..end] != self.trace.requests()[start..end]
                {
                    return Err(learning::Error::Evidence);
                }
                Ok(true)
            }
            ReplayPiece::Coverage { index } => {
                let value = trial.coverage.get(index).ok_or(learning::Error::Evidence)?;
                if index == 0 {
                    return if *value == self.trace.coverage() {
                        Ok(true)
                    } else {
                        Err(learning::Error::Evidence)
                    };
                }
                #[cfg(not(test))]
                if index == 1
                    && self
                        .partner
                        .is_some_and(|peer| peer.seal.coverage == *value)
                {
                    return Ok(true);
                }
                Err(learning::Error::Evidence)
            }
            ReplayPiece::Cpu { start, end } => self.cpu_piece(trial, start, end),
            ReplayPiece::Shared { .. } | ReplayPiece::Joint { .. } => {
                Err(learning::Error::Evidence)
            }
        }
    }
    fn finish(
        &self,
        trial: &Trial<'_>,
        binding: [u8; 32],
        digest: [u8; 32],
    ) -> Result<bool, learning::Error> {
        if digest == [0; 32] {
            return Err(learning::Error::Evidence);
        }
        let Some(metadata) = self.metadata(trial)? else {
            return Ok(false);
        };
        if metadata.binding != binding {
            return Err(learning::Error::Stale);
        }
        if !frozen(&metadata)? {
            return Ok(false);
        }
        #[cfg(not(test))]
        return crate::learning_workload::check_closing_bounded(&metadata.scope, trial);
        #[cfg(test)]
        (metadata.checks.closing)(&metadata.scope, trial).map(|()| true)
    }
}

fn frozen(metadata: &Metadata) -> Result<bool, learning::Error> {
    #[cfg(not(test))]
    return crate::learning_workload::check_frozen_bounded(&metadata.scope);
    #[cfg(test)]
    (metadata.checks.frozen)(&metadata.scope).map(|()| true)
}
fn issued(metadata: &Metadata, adoption: &Adoption<'_>) -> Result<bool, learning::Error> {
    #[cfg(not(test))]
    return crate::learning_workload::check_issued_bounded(&metadata.scope, adoption);
    #[cfg(test)]
    (metadata.checks.issued)(metadata.scope.key, adoption).map(|()| true)
}
fn baseline_check(
    metadata: &Metadata,
    baseline: &BaselineAdoption,
) -> Result<bool, learning::Error> {
    #[cfg(not(test))]
    return crate::learning_workload::check_baseline_bounded(&metadata.scope, baseline);
    #[cfg(test)]
    (metadata.checks.baseline)(metadata.scope.key, baseline).map(|()| true)
}

fn candidate_piece(run: RunKey, adoption: &Adoption<'_>, index: usize) -> Result<(), Error> {
    with(|owner, storage| {
        if owner.scope.map(|scope| scope.key) != Some(run) || owner.sealed.is_none() {
            return Err(Error::Stale);
        }
        let found = find_decision(owner, storage, adoption.decision_seq).ok_or(Error::Stale)?;
        let row = row(storage, found);
        let count = usize::from(u16_at(row, 204));
        if count != adoption.candidates.len() || index >= count || count > 32 {
            return fail(learning::Error::Evidence);
        }
        let word = |i| u64_at(&row[INPUT..], i * 8);
        let at = 64 + index * 10;
        if word(40) & !15 != 0 || word(at + 7) & !15 != 0 || word(at + 9) != 0 {
            return fail(learning::Error::Evidence);
        }
        let action = action(row, index)?;
        let mut target = TargetFeatures::default();
        for i in 0..4 {
            if word(at + 7) & (1 << i) != 0 {
                target.values[i] = Some(word(at + 3 + i));
            } else if word(at + 3 + i) != 0 {
                return fail(learning::Error::Evidence);
            }
        }
        let control_capacity = if matches!(action, Action::ControlSet(_)) {
            Some(word(at + 8))
        } else {
            if word(at + 8) != 0 {
                return fail(learning::Error::Evidence);
            }
            None
        };
        let expected = Candidate {
            action,
            features: RawFeatures {
                common: core::array::from_fn(|i| word(24 + i)),
                domain: core::array::from_fn(|i| word(32 + i)),
                domain_present: word(40) as u8,
                target,
                control_capacity,
            },
        };
        if adoption.candidates.get(index) != Some(expected) {
            return fail(learning::Error::Evidence);
        }
        Ok(())
    })
}
