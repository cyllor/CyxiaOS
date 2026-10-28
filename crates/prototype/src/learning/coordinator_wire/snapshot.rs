use super::{
    ABI, SNAPSHOT_BYTES, SNAPSHOT_MAGIC,
    codec::{decode_stage, stage_code, valid_object},
};
use crate::{
    domains::{ApplyId, ObjectKey},
    learning::{
        Error,
        governance::Stage,
        worker_wire::{
            JobBinding, array_at, decode_binding, encode_binding, put16, put32, put64, u16_at,
            u32_at, u64_at,
        },
    },
};
use sha2::{Digest, Sha256};

const FAMILY_MASK: u32 = (1u32 << 18) - 1;
const PERMIT_FLAG: u16 = 1;
const PENDING_FLAG: u16 = 2;
const BASELINE_READY_FLAG: u16 = 4;
const VERIFIED_SCORE_FLAG: u16 = 8;
const SNAPSHOT_FLAGS: u16 =
    PERMIT_FLAG | PENDING_FLAG | BASELINE_READY_FLAG | VERIFIED_SCORE_FLAG;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum LastCommandStatus {
    None = 0,
    Applied = 1,
    Rejected = 2,
    Failed = 3,
    Unknown = 4,
}
impl LastCommandStatus {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Applied),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Failed),
            4 => Ok(Self::Unknown),
            _ => Err(Error::Schema),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ObservedExecutionState {
    Pending = 1,
    Applied = 2,
    Failed = 3,
    Unknown = 4,
}
impl ObservedExecutionState {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Applied),
            3 => Ok(Self::Failed),
            4 => Ok(Self::Unknown),
            _ => Err(Error::Schema),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermitObservation {
    pub id: u64,
    pub target: ObjectKey,
    pub start_ns: u64,
    pub expires_ns: u64,
    pub quota: u16,
    pub used: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingObservation {
    pub apply: ApplyId,
    pub plan_version: u64,
    pub state: ObservedExecutionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedScore {
    pub handle: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoordinatorSnapshot {
    pub binding: JobBinding,
    pub session: ObjectKey,
    pub revision: u64,
    pub now_ns: u64,
    pub deadline_ns: u64,
    pub stage: Stage,
    pub original_hash: [u8; 32],
    pub candidate_hash: [u8; 32],
    pub registration_hash: [u8; 32],
    pub shadow_coverage: u32,
    pub closed_windows: u16,
    pub permit: Option<PermitObservation>,
    pub pending: Option<PendingObservation>,
    pub baseline_ready: bool,
    pub last_command_sequence: u64,
    pub last_command_status: LastCommandStatus,
    pub verified_score: Option<VerifiedScore>,
}
impl CoordinatorSnapshot {
    pub fn shape(self) -> Result<(), Error> {
        self.binding.validate()?;
        valid_object(self.session)?;
        if self.revision == 0
            || self.deadline_ns <= self.now_ns
            || [
                self.original_hash,
                self.candidate_hash,
                self.registration_hash,
            ]
            .contains(&[0; 32])
            || self.shadow_coverage & !FAMILY_MASK != 0
            || self.closed_windows > 300
        {
            return Err(Error::Evidence);
        }
        if (self.last_command_sequence == 0)
            != (self.last_command_status == LastCommandStatus::None)
        {
            return Err(Error::Order);
        }
        if let Some(permit) = self.permit {
            valid_object(permit.target)?;
            if permit.id == 0
                || permit.start_ns >= permit.expires_ns
                || permit.quota == 0
                || permit.quota > 300
                || permit.used > permit.quota
            {
                return Err(Error::Evidence);
            }
        }
        if let Some(pending) = self.pending {
            valid_object(pending.apply.target)?;
            if pending.apply.boot_epoch == 0
                || pending.apply.controller_epoch == 0
                || pending.apply.plan_seq == 0
                || pending.apply.action_index >= 16
                || pending.plan_version == 0
            {
                return Err(Error::Evidence);
            }
        }
        if let Some(score) = self.verified_score
            && (score.handle == 0 || score.digest == [0; 32])
        {
            return Err(Error::Evidence);
        }
        Ok(())
    }

    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        self.shape()?;
        if output.len() < SNAPSHOT_BYTES {
            return Err(Error::Capacity);
        }
        let output = &mut output[..SNAPSHOT_BYTES];
        output.fill(0);
        output[..8].copy_from_slice(SNAPSHOT_MAGIC);
        put16(output, 8, ABI);
        put16(output, 10, stage_code(self.stage));
        put32(output, 12, SNAPSHOT_BYTES as u32);
        encode_binding(&mut output[16..120], self.binding);
        put64(output, 120, self.session.id);
        put64(output, 128, self.session.generation);
        put64(output, 136, self.revision);
        put64(output, 144, self.now_ns);
        put64(output, 152, self.deadline_ns);
        output[160..192].copy_from_slice(&self.original_hash);
        output[192..224].copy_from_slice(&self.candidate_hash);
        output[224..256].copy_from_slice(&self.registration_hash);
        put32(output, 256, self.shadow_coverage);
        put16(output, 260, self.closed_windows);
        let mut flags = if self.baseline_ready {
            BASELINE_READY_FLAG
        } else {
            0
        };
        if let Some(permit) = self.permit {
            flags |= PERMIT_FLAG;
            put64(output, 264, permit.id);
            put64(output, 272, permit.target.id);
            put64(output, 280, permit.target.generation);
            put64(output, 288, permit.start_ns);
            put64(output, 296, permit.expires_ns);
            put16(output, 304, permit.quota);
            put16(output, 306, permit.used);
        }
        if let Some(pending) = self.pending {
            flags |= PENDING_FLAG;
            put64(output, 312, pending.apply.boot_epoch);
            put64(output, 320, pending.apply.controller_epoch);
            put64(output, 328, pending.apply.plan_seq);
            put16(output, 336, pending.apply.action_index);
            put16(output, 338, pending.state as u16);
            put64(output, 344, pending.apply.target.id);
            put64(output, 352, pending.apply.target.generation);
            put64(output, 360, pending.plan_version);
        }
        put64(output, 368, self.last_command_sequence);
        put16(output, 376, self.last_command_status as u16);
        if let Some(score) = self.verified_score {
            flags |= VERIFIED_SCORE_FLAG;
            put64(output, 384, score.handle);
            output[392..424].copy_from_slice(&score.digest);
        }
        put16(output, 262, flags);
        Ok(SNAPSHOT_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != SNAPSHOT_BYTES {
            return Err(Error::Capacity);
        }
        if &input[..8] != SNAPSHOT_MAGIC
            || u16_at(input, 8)? != ABI
            || u32_at(input, 12)? as usize != SNAPSHOT_BYTES
        {
            return Err(Error::Schema);
        }
        let flags = u16_at(input, 262)?;
        if flags & !SNAPSHOT_FLAGS != 0 {
            return Err(Error::Schema);
        }
        let permit = if flags & PERMIT_FLAG != 0 {
            Some(PermitObservation {
                id: u64_at(input, 264)?,
                target: ObjectKey {
                    id: u64_at(input, 272)?,
                    generation: u64_at(input, 280)?,
                },
                start_ns: u64_at(input, 288)?,
                expires_ns: u64_at(input, 296)?,
                quota: u16_at(input, 304)?,
                used: u16_at(input, 306)?,
            })
        } else {
            None
        };
        let pending = if flags & PENDING_FLAG != 0 {
            Some(PendingObservation {
                apply: ApplyId {
                    boot_epoch: u64_at(input, 312)?,
                    controller_epoch: u64_at(input, 320)?,
                    plan_seq: u64_at(input, 328)?,
                    action_index: u16_at(input, 336)?,
                    target: ObjectKey {
                        id: u64_at(input, 344)?,
                        generation: u64_at(input, 352)?,
                    },
                },
                plan_version: u64_at(input, 360)?,
                state: ObservedExecutionState::decode(u16_at(input, 338)?)?,
            })
        } else {
            None
        };
        let verified_score = if flags & VERIFIED_SCORE_FLAG != 0 {
            Some(VerifiedScore {
                handle: u64_at(input, 384)?,
                digest: array_at(input, 392)?,
            })
        } else {
            None
        };
        let snapshot = Self {
            binding: decode_binding(&input[16..120])?,
            session: ObjectKey {
                id: u64_at(input, 120)?,
                generation: u64_at(input, 128)?,
            },
            revision: u64_at(input, 136)?,
            now_ns: u64_at(input, 144)?,
            deadline_ns: u64_at(input, 152)?,
            stage: decode_stage(u16_at(input, 10)?)?,
            original_hash: array_at(input, 160)?,
            candidate_hash: array_at(input, 192)?,
            registration_hash: array_at(input, 224)?,
            shadow_coverage: u32_at(input, 256)?,
            closed_windows: u16_at(input, 260)?,
            permit,
            pending,
            baseline_ready: flags & BASELINE_READY_FLAG != 0,
            last_command_sequence: u64_at(input, 368)?,
            last_command_status: LastCommandStatus::decode(u16_at(input, 376)?)?,
            verified_score,
        };
        snapshot.shape()?;
        let mut canonical = [0; SNAPSHOT_BYTES];
        snapshot.encode(&mut canonical)?;
        if canonical.as_slice() != input {
            return Err(Error::Evidence);
        }
        Ok(snapshot)
    }

    pub fn digest(self) -> Result<[u8; 32], Error> {
        let mut bytes = [0; SNAPSHOT_BYTES];
        self.encode(&mut bytes)?;
        Ok(Sha256::digest(bytes).into())
    }
}
