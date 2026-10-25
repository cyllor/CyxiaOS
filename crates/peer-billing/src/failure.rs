//! An actual protected root failure is distinct from an incomplete transport
//! operation. The negative fact cannot cancel START or claim work completed.
use super::{BINDING_BYTES, Binding, Error, Reader, Writer};
use cyxia_prototype::{
    domains::{Error as DomainError, ObjectKey},
    policy::{ExecutionState, PlanId, PlanReceipt, Snapshot},
};

pub const FAILURE_BYTES: usize = 160;
pub const ROOT_FAILURE_BYTES: usize = BINDING_BYTES + FAILURE_BYTES;
pub const ROOT_FAILURE_PACKET_BYTES: usize =
    super::HEADER_BYTES + ROOT_FAILURE_BYTES + super::SIGNATURE_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailedPublication {
    pub id: PlanId,
    pub snapshot: Snapshot,
    pub target: ObjectKey,
    pub plan_hash: [u8; 32],
    pub received_ns: u64,
    pub observed_ns: u64,
    pub wall_deadline_ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub root_token: u64,
    /// The original domain error's stable diagnostic value, plus one.
    pub error: u64,
    pub observed_ns: u64,
    pub publication: Option<FailedPublication>,
}
impl Failure {
    /// A later fact cannot amend the original window's CPU or coverage.
    pub fn after_closing(self, closing_ns: u64) -> bool {
        closing_ns != 0 && self.observed_ns > closing_ns
    }
    pub fn rejected(
        root_token: u64,
        receipt: PlanReceipt,
        snapshot: Snapshot,
        target: ObjectKey,
        plan_hash: [u8; 32],
        received_ns: u64,
        observed_ns: u64,
        wall_deadline_ns: u64,
    ) -> Result<Self, Error> {
        if receipt.version != 0 || receipt.published_ns != 0 || receipt.action_count != 1 {
            return Err(Error::Incomplete);
        }
        let ExecutionState::Failed(error) = receipt.state() else {
            return Err(Error::Incomplete);
        };
        let value = Self {
            root_token,
            error: error as u64 + 1,
            observed_ns,
            publication: Some(FailedPublication {
                id: receipt.id,
                snapshot,
                target,
                plan_hash,
                received_ns,
                observed_ns,
                wall_deadline_ns,
            }),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(self) -> Result<(), Error> {
        if self.root_token == 0
            || self.error == 0
            || self.error > DomainError::NotReady as u64 + 1
            || self.observed_ns == 0
        {
            return Err(Error::Identity);
        }
        if let Some(p) = self.publication {
            if p.id.boot_epoch == 0
                || p.id.controller_epoch == 0
                || p.id.plan_seq == 0
                || p.snapshot.sequence == 0
                || p.snapshot.ledger_generation == 0
                || p.snapshot.core_generation == 0
                || p.target.id == 0
                || p.target.generation == 0
                || p.plan_hash == [0; 32]
                || p.received_ns < p.snapshot.taken_ns
                || p.observed_ns < p.received_ns
                || p.observed_ns > self.observed_ns
                || p.wall_deadline_ns < p.snapshot.taken_ns
            {
                return Err(Error::Identity);
            }
        }
        Ok(())
    }
    pub(crate) fn encode_optional(value: Option<Self>, out: &mut [u8]) -> Result<(), Error> {
        if out.len() != FAILURE_BYTES {
            return Err(Error::Capacity);
        }
        out.fill(0);
        let Some(value) = value else {
            return Ok(());
        };
        value.validate()?;
        let mut w = Writer::new(out);
        w.u64(value.root_token)?;
        w.u64(value.error)?;
        w.u64(value.observed_ns)?;
        w.u64(u64::from(value.publication.is_some()))?;
        if let Some(p) = value.publication {
            for v in [
                p.id.boot_epoch,
                p.id.controller_epoch,
                p.id.plan_seq,
                p.snapshot.sequence,
                p.snapshot.taken_ns,
                p.snapshot.ledger_generation,
                p.snapshot.core_generation,
                p.target.id,
                p.target.generation,
            ] {
                w.u64(v)?;
            }
            w.bytes(&p.plan_hash)?;
            for v in [p.received_ns, p.observed_ns, p.wall_deadline_ns] {
                w.u64(v)?;
            }
        }
        Ok(())
    }
    pub(crate) fn decode_optional(bytes: &[u8]) -> Result<Option<Self>, Error> {
        if bytes.len() != FAILURE_BYTES {
            return Err(Error::Format);
        }
        if bytes == [0; FAILURE_BYTES] {
            return Ok(None);
        }
        let mut r = Reader::new(bytes);
        let root_token = r.u64()?;
        let error = r.u64()?;
        let observed_ns = r.u64()?;
        let publication = match r.u64()? {
            0 => {
                if r.take(128)?.iter().any(|v| *v != 0) {
                    return Err(Error::Format);
                }
                None
            }
            1 => Some(FailedPublication {
                id: PlanId {
                    boot_epoch: r.u64()?,
                    controller_epoch: r.u64()?,
                    plan_seq: r.u64()?,
                },
                snapshot: Snapshot {
                    sequence: r.u64()?,
                    taken_ns: r.u64()?,
                    ledger_generation: r.u64()?,
                    core_generation: r.u64()?,
                },
                target: ObjectKey {
                    id: r.u64()?,
                    generation: r.u64()?,
                },
                plan_hash: r.array()?,
                received_ns: r.u64()?,
                observed_ns: r.u64()?,
                wall_deadline_ns: r.u64()?,
            }),
            _ => return Err(Error::Format),
        };
        r.end()?;
        let value = Self {
            root_token,
            error,
            observed_ns,
            publication,
        };
        value.validate()?;
        Ok(Some(value))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootFailure {
    pub binding: Binding,
    pub failure: Failure,
}
impl RootFailure {
    pub fn validate(self) -> Result<(), Error> {
        self.binding.validate()?;
        self.failure.validate()?;
        if self
            .failure
            .publication
            .is_some_and(|p| p.id.boot_epoch != self.binding.participant.boot)
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.validate()?;
        if out.len() < ROOT_FAILURE_BYTES {
            return Err(Error::Capacity);
        }
        self.binding.encode(&mut out[..BINDING_BYTES])?;
        Failure::encode_optional(
            Some(self.failure),
            &mut out[BINDING_BYTES..ROOT_FAILURE_BYTES],
        )?;
        Ok(ROOT_FAILURE_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ROOT_FAILURE_BYTES {
            return Err(Error::Format);
        }
        let value = Self {
            binding: Binding::decode(&bytes[..BINDING_BYTES])?,
            failure: Failure::decode_optional(&bytes[BINDING_BYTES..])?.ok_or(Error::Format)?,
        };
        value.validate()?;
        Ok(value)
    }
    /// A fault is admissible only for a retained reservation/active binding.
    /// This check confers no permission to cancel an issued START.
    pub fn belongs_to(self, reserved: Binding, active: Binding) -> Result<(), Error> {
        self.validate()?;
        if self.binding != reserved && self.binding != active {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn retain(
        self,
        retained: &mut Option<Failure>,
        reserved: Binding,
        active: Binding,
    ) -> Result<(), Error> {
        self.belongs_to(reserved, active)?;
        if retained.is_some_and(|old| old != self.failure) {
            return Err(Error::Conflict);
        }
        *retained = Some(self.failure);
        Ok(())
    }
}
