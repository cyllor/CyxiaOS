use super::{
    ABI, COMMAND_BYTES, COMMAND_MAGIC,
    codec::valid_object,
    snapshot::{CoordinatorSnapshot, VerifiedScore},
};
use crate::{
    domains::ObjectKey,
    learning::{
        Error, Family,
        worker_wire::{
            JobBinding, array_at, decode_binding, encode_binding, put16, put32, put64, u16_at,
            u32_at, u64_at,
        },
    },
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ScoreMode {
    Shadow = 1,
    Canary = 2,
}
impl ScoreMode {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Shadow),
            2 => Ok(Self::Canary),
            _ => Err(Error::Schema),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RejectReason {
    Evidence = 1,
    Budget = 2,
    Deadline = 3,
    Safety = 4,
    Stale = 5,
    NoChange = 6,
}
impl RejectReason {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Evidence),
            2 => Ok(Self::Budget),
            3 => Ok(Self::Deadline),
            4 => Ok(Self::Safety),
            5 => Ok(Self::Stale),
            6 => Ok(Self::NoChange),
            _ => Err(Error::Schema),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandAction {
    Wait,
    Score { mode: ScoreMode, family: Family },
    CloseShadowWindow { window: u64 },
    PrepareBaseline { target: ObjectKey },
    BeginCanary { target: ObjectKey },
    PublishCanary { score: VerifiedScore },
    Freeze { permit_id: u64 },
    Promote { registration_hash: [u8; 32] },
    Rollback { expected_active_generation: u64 },
    Reject { reason: RejectReason },
    Release,
}
impl CommandAction {
    fn kind(self) -> u16 {
        match self {
            Self::Wait => 1,
            Self::Score { .. } => 2,
            Self::CloseShadowWindow { .. } => 3,
            Self::PrepareBaseline { .. } => 4,
            Self::BeginCanary { .. } => 5,
            Self::PublishCanary { .. } => 6,
            Self::Freeze { .. } => 7,
            Self::Promote { .. } => 8,
            Self::Rollback { .. } => 9,
            Self::Reject { .. } => 10,
            Self::Release => 11,
        }
    }

    fn shape(self) -> Result<(), Error> {
        match self {
            Self::Wait | Self::Release => Ok(()),
            Self::Score { family, .. } => family.index().map(|_| ()),
            Self::CloseShadowWindow { window } if window != 0 => Ok(()),
            Self::PrepareBaseline { target } | Self::BeginCanary { target } => valid_object(target),
            Self::PublishCanary { score } if score.handle != 0 && score.digest != [0; 32] => Ok(()),
            Self::Freeze { permit_id } if permit_id != 0 => Ok(()),
            Self::Promote { registration_hash } if registration_hash != [0; 32] => Ok(()),
            Self::Rollback {
                expected_active_generation,
            } if expected_active_generation != 0 => Ok(()),
            Self::Reject { .. } => Ok(()),
            _ => Err(Error::Evidence),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandKey {
    pub boot_epoch: u64,
    pub role_generation: u64,
    pub session_generation: u64,
    pub command_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command {
    pub binding: JobBinding,
    pub session: ObjectKey,
    pub revision: u64,
    pub sequence: u64,
    pub snapshot_digest: [u8; 32],
    pub action: CommandAction,
}
impl Command {
    pub fn shape(self) -> Result<(), Error> {
        self.binding.validate()?;
        valid_object(self.session)?;
        if self.revision == 0 || self.sequence == 0 || self.snapshot_digest == [0; 32] {
            return Err(Error::Evidence);
        }
        self.action.shape()
    }

    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        self.shape()?;
        if output.len() < COMMAND_BYTES {
            return Err(Error::Capacity);
        }
        let output = &mut output[..COMMAND_BYTES];
        output.fill(0);
        output[..8].copy_from_slice(COMMAND_MAGIC);
        put16(output, 8, ABI);
        put16(output, 10, self.action.kind());
        put32(output, 12, COMMAND_BYTES as u32);
        encode_binding(&mut output[16..120], self.binding);
        put64(output, 120, self.session.id);
        put64(output, 128, self.session.generation);
        put64(output, 136, self.revision);
        put64(output, 144, self.sequence);
        output[152..184].copy_from_slice(&self.snapshot_digest);
        match self.action {
            CommandAction::Wait | CommandAction::Release => {}
            CommandAction::Score { mode, family } => {
                put16(output, 248, family.domain);
                put16(output, 250, family.kind);
                put16(output, 252, mode as u16);
            }
            CommandAction::CloseShadowWindow { window } => put64(output, 184, window),
            CommandAction::PrepareBaseline { target } | CommandAction::BeginCanary { target } => {
                put64(output, 184, target.id);
                put64(output, 192, target.generation);
            }
            CommandAction::PublishCanary { score } => {
                put64(output, 184, score.handle);
                output[216..248].copy_from_slice(&score.digest);
            }
            CommandAction::Freeze { permit_id } => put64(output, 184, permit_id),
            CommandAction::Promote { registration_hash } => {
                output[216..248].copy_from_slice(&registration_hash);
            }
            CommandAction::Rollback {
                expected_active_generation,
            } => put64(output, 184, expected_active_generation),
            CommandAction::Reject { reason } => put16(output, 252, reason as u16),
        }
        Ok(COMMAND_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != COMMAND_BYTES {
            return Err(Error::Capacity);
        }
        if &input[..8] != COMMAND_MAGIC
            || u16_at(input, 8)? != ABI
            || u32_at(input, 12)? as usize != COMMAND_BYTES
        {
            return Err(Error::Schema);
        }
        let action = match u16_at(input, 10)? {
            1 => CommandAction::Wait,
            2 => CommandAction::Score {
                mode: ScoreMode::decode(u16_at(input, 252)?)?,
                family: Family {
                    domain: u16_at(input, 248)?,
                    kind: u16_at(input, 250)?,
                },
            },
            3 => CommandAction::CloseShadowWindow {
                window: u64_at(input, 184)?,
            },
            4 => CommandAction::PrepareBaseline {
                target: ObjectKey {
                    id: u64_at(input, 184)?,
                    generation: u64_at(input, 192)?,
                },
            },
            5 => CommandAction::BeginCanary {
                target: ObjectKey {
                    id: u64_at(input, 184)?,
                    generation: u64_at(input, 192)?,
                },
            },
            6 => CommandAction::PublishCanary {
                score: VerifiedScore {
                    handle: u64_at(input, 184)?,
                    digest: array_at(input, 216)?,
                },
            },
            7 => CommandAction::Freeze {
                permit_id: u64_at(input, 184)?,
            },
            8 => CommandAction::Promote {
                registration_hash: array_at(input, 216)?,
            },
            9 => CommandAction::Rollback {
                expected_active_generation: u64_at(input, 184)?,
            },
            10 => CommandAction::Reject {
                reason: RejectReason::decode(u16_at(input, 252)?)?,
            },
            11 => CommandAction::Release,
            _ => return Err(Error::Schema),
        };
        let command = Self {
            binding: decode_binding(&input[16..120])?,
            session: ObjectKey {
                id: u64_at(input, 120)?,
                generation: u64_at(input, 128)?,
            },
            revision: u64_at(input, 136)?,
            sequence: u64_at(input, 144)?,
            snapshot_digest: array_at(input, 152)?,
            action,
        };
        command.shape()?;
        let mut canonical = [0; COMMAND_BYTES];
        command.encode(&mut canonical)?;
        if canonical.as_slice() != input {
            return Err(Error::Evidence);
        }
        Ok(command)
    }

    pub fn digest(self) -> Result<[u8; 32], Error> {
        let mut bytes = [0; COMMAND_BYTES];
        self.encode(&mut bytes)?;
        Ok(Sha256::digest(bytes).into())
    }

    pub fn key(self) -> CommandKey {
        CommandKey {
            boot_epoch: self.binding.boot_epoch,
            role_generation: self.binding.role_context.generation,
            session_generation: self.session.generation,
            command_sequence: self.sequence,
        }
    }

    pub fn validate_for_snapshot(
        self,
        snapshot: CoordinatorSnapshot,
        now_ns: u64,
    ) -> Result<(), Error> {
        self.shape()?;
        snapshot.shape()?;
        if now_ns < snapshot.now_ns {
            return Err(Error::Stale);
        }
        if now_ns >= snapshot.deadline_ns {
            return Err(Error::Deadline);
        }
        if self.binding != snapshot.binding
            || self.session != snapshot.session
            || self.revision != snapshot.revision
        {
            return Err(Error::Stale);
        }
        if self.snapshot_digest != snapshot.digest()? {
            return Err(Error::Evidence);
        }
        let expected = snapshot
            .last_command_sequence
            .checked_add(1)
            .ok_or(Error::Numeric)?;
        if self.sequence != expected {
            return if self.sequence <= snapshot.last_command_sequence {
                Err(Error::Stale)
            } else {
                Err(Error::Order)
            };
        }
        match self.action {
            CommandAction::PublishCanary { score } if snapshot.verified_score != Some(score) => {
                Err(Error::Stale)
            }
            CommandAction::Freeze { permit_id } => match snapshot.permit {
                Some(permit) if permit.id == permit_id => Ok(()),
                _ => Err(Error::Stale),
            },
            CommandAction::Promote { registration_hash }
                if registration_hash != snapshot.registration_hash =>
            {
                Err(Error::Stale)
            }
            CommandAction::Rollback {
                expected_active_generation,
            } if expected_active_generation != snapshot.binding.model_generation => {
                Err(Error::Stale)
            }
            _ => Ok(()),
        }
    }
}
