use super::execute::{check_comparison, empty_comparison, registration_hash};
use crate::{
    learning::{
        Error,
        manifest::{ModelManifest, SealedModel},
        train::{self, TrainedModel},
        validate::ValidatedCandidate,
        worker_wire::{self as wire, Header, JobIdentity, Report, Role},
    },
    model::MODEL_BYTES,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionClaim {
    pub identity: JobIdentity,
    pub output_hash: [u8; 32],
    pub output_bytes: u32,
    pub completed_steps: u64,
}
/// Implemented by the protected runtime, never by the numerical worker.
///
/// Verification must bind the actual stopped context/image, the immutable
/// registered input allocation and current model/data generations, and this
/// exact frozen output. Setup, compute, cancellation and closing CPU must have
/// settled against the actual physical/control/extra ledgers. UNKNOWN, a lost
/// bill, an unquiesced context, or an unregistered image cannot authenticate a
/// completion. There is deliberately no permissive/default implementation.
pub trait CompletionAuthority {
    fn verify_completion(&self, claim: &CompletionClaim) -> Result<(), Error>;
    /// A scoring completion must additionally own this exact last settled
    /// receipt, with every earlier preparation/compute/release bill closed.
    /// Numerical-only adapters cannot accidentally authorize a score.
    fn verify_score_completion(
        &self,
        _claim: &CompletionClaim,
        _receipt: &crate::learning::governance::WorkReceipt,
    ) -> Result<(), Error> {
        Err(Error::Evidence)
    }
}

/// Only Encoder, which borrows FrozenData, can create this capability. A
/// decoded Header/Report alone cannot be used to create a trained model.
pub struct PreparedJob {
    header: Header,
    identity: JobIdentity,
    frozen_layers_hash: [u8; 32],
    probe_candidates: u16,
    consumed: bool,
}
impl PreparedJob {
    pub(super) fn new(
        header: Header,
        identity: JobIdentity,
        frozen_layers_hash: [u8; 32],
        probe_candidates: u16,
    ) -> Self {
        Self {
            header,
            identity,
            frozen_layers_hash,
            probe_candidates,
            consumed: false,
        }
    }
    pub fn identity(&self) -> JobIdentity {
        self.identity
    }
    pub fn header(&self) -> Header {
        self.header
    }
    pub fn input_len(&self) -> usize {
        self.header.layout().expect("prepared layout").total
    }
    pub fn consumed(&self) -> bool {
        self.consumed
    }
    fn inspect(&self, output: &[u8]) -> Result<Report, Error> {
        if self.consumed {
            return Err(Error::State);
        }
        let report = Report::decode(output)?;
        let h = self.header;
        if report.identity != self.identity
            || report.transcript_hash == [0; 32]
            || report.counts.steps == 0
            || report.counts.rows as usize != h.layout()?.row_count
            || report.counts.training != h.data.training_count
            || report.counts.golden_cases != wire::SELFTEST_CASES as u16
            || report.counts.references != h.references
            || report.counts.selections != h.selections
            || report.counts.probes != h.probes
            || report.counts.probe_candidates != self.probe_candidates
            || report.record.parent_hash != h.parent_hash
            || report.record.data != h.data
            || report.record.steps != h.data.training_count
            || report.record.shadow_parameters_hash == [0; 32]
            || report.record.result_hash != report.candidate_hash
            || <[u8; 32]>::from(Sha256::digest(report.candidate)) != report.candidate_hash
            || report.record.frozen_layers_hash != self.frozen_layers_hash
            || train::frozen_hash(&report.candidate) != self.frozen_layers_hash
        {
            return Err(Error::Evidence);
        }
        train::Parameters::from_model(&report.candidate)?;
        match h.role {
            Role::Training => {
                if report.counts.validation != 0
                    || report.manifest_hash != [0; 32]
                    || report.registration_hash != [0; 32]
                    || report.comparison != empty_comparison()
                {
                    return Err(Error::Evidence);
                }
            }
            Role::Validation => {
                if report.counts.validation != h.data.validation_count
                    || report.candidate_hash != h.candidate_hash
                    || h.record != Some(report.record)
                    || report.candidate_hash == h.parent_hash
                    || report.manifest_hash != h.model_manifest_hash
                {
                    return Err(Error::Evidence);
                }
                check_comparison(report.comparison, h.data.validation_per_family)?;
                if report.registration_hash
                    != registration_hash(
                        h.model_manifest_hash,
                        h.parent_hash,
                        h.data.hash,
                        report.comparison,
                    )
                {
                    return Err(Error::Evidence);
                }
            }
            Role::ShadowScore | Role::CanaryScore => return Err(Error::Schema),
        }
        Ok(report)
    }
    fn authenticate(
        &self,
        report: &Report,
        output: &[u8],
        authority: &impl CompletionAuthority,
    ) -> Result<(), Error> {
        authority.verify_completion(&CompletionClaim {
            identity: self.identity,
            output_hash: Sha256::digest(output).into(),
            output_bytes: output.len() as u32,
            completed_steps: report.counts.steps,
        })
    }
    pub fn accept_training(
        &mut self,
        output: &[u8],
        authority: &impl CompletionAuthority,
    ) -> Result<TrainedModel, Error> {
        if self.header.role != Role::Training {
            return Err(Error::State);
        }
        let report = self.inspect(output)?;
        self.authenticate(&report, output, authority)?;
        self.consumed = true;
        Ok(TrainedModel::from_worker(report.candidate, report.record))
    }
    /// Constant-size import after a separately scheduled Validation role has
    /// reproduced SGD, integer traces, candidate probes and all held-out MSEs.
    /// This method never calls the synchronous host registration loop.
    pub fn accept_validation<'a>(
        &mut self,
        candidate: &'a [u8; MODEL_BYTES],
        manifest: ModelManifest,
        output: &[u8],
        authority: &impl CompletionAuthority,
    ) -> Result<ValidatedCandidate<'a>, Error> {
        if self.header.role != Role::Validation {
            return Err(Error::State);
        }
        let report = self.inspect(output)?;
        if candidate != &report.candidate
            || manifest != self.header.candidate_manifest()?
            || manifest.hash() != report.manifest_hash
        {
            return Err(Error::Manifest);
        }
        // Check every caller-supplied immutable field before asking a runtime
        // that may consume its protected completion ticket.
        self.authenticate(&report, output, authority)?;
        let model = SealedModel::from_worker(candidate, manifest, report.manifest_hash);
        let validated = ValidatedCandidate::from_worker(
            model,
            report.comparison,
            self.header.parent_hash,
            report.registration_hash,
        );
        self.consumed = true;
        Ok(validated)
    }
}
