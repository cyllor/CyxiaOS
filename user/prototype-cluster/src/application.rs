//! Copied application requests at the kernel/service boundary. No wire field
//! is a guest pointer, and a placement key retains its original BootEpoch.
use cyxia_prototype::domains::{Error, ObjectKey};

pub const MAX_INPUT: usize = 3984;
pub const SUBMISSION_HEADER: usize = 56;
pub const STATUS_BYTES: usize = 40;
pub const QUEUED: u64 = 0;
pub const PENDING: u64 = 1;
pub const LOCAL: u64 = 2;
pub const REMOTE: u64 = 3;
pub const REJECTED: u64 = 4;
pub const UNKNOWN: u64 = 5;
pub const COMPLETION_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub key: ObjectKey,
    pub outcome: u64,
    pub target: ObjectKey,
    pub value: u64,
    pub finished_ns: u64,
    pub closed: u64,
}
impl Completion {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != COMPLETION_BYTES {
            return Err(Error::Format);
        }
        let v = Self {
            key: key(bytes, 0)?,
            outcome: word(bytes, 16)?,
            target: key(bytes, 24)?,
            value: word(bytes, 40)?,
            finished_ns: word(bytes, 48)?,
            closed: word(bytes, 56)?,
        };
        if !live(v.key) || !matches!(v.outcome, 1 | 2) || v.closed != 1 {
            return Err(Error::Format);
        }
        Ok(v)
    }
    pub fn encode(self) -> [u8; COMPLETION_BYTES] {
        let mut out = [0; COMPLETION_BYTES];
        for (i, v) in [
            self.key.id,
            self.key.generation,
            self.outcome,
            self.target.id,
            self.target.generation,
            self.value,
            self.finished_ns,
            self.closed,
        ]
        .into_iter()
        .enumerate()
        {
            out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    }
}

fn word(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(Error::Format)?
            .try_into()
            .unwrap(),
    ))
}
fn key(bytes: &[u8], at: usize) -> Result<ObjectKey, Error> {
    Ok(ObjectKey {
        id: word(bytes, at)?,
        generation: word(bytes, at + 8)?,
    })
}
fn live(key: ObjectKey) -> bool {
    key.id != 0 && key.generation != 0
}

#[derive(Clone, Copy, Debug)]
pub struct Submission<'a> {
    pub actor: ObjectKey,
    pub sequence: u64,
    pub key: ObjectKey,
    pub submitted_ns: u64,
    pub input: &'a [u8],
}
impl<'a> Submission<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let length = usize::try_from(word(bytes, 48)?).map_err(|_| Error::Range)?;
        let value = Self {
            actor: key(bytes, 0)?,
            sequence: word(bytes, 16)?,
            key: key(bytes, 24)?,
            submitted_ns: word(bytes, 40)?,
            input: bytes.get(SUBMISSION_HEADER..).ok_or(Error::Format)?,
        };
        value.validate()?;
        if value.input.len() != length {
            return Err(Error::Format);
        }
        Ok(value)
    }
    fn validate(&self) -> Result<(), Error> {
        if !live(self.actor)
            || !live(self.key)
            || self.sequence == 0
            || self.input.is_empty()
            || self.input.len() > MAX_INPUT
            || !self.input.len().is_multiple_of(8)
        {
            return Err(Error::Format);
        }
        Ok(())
    }
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        self.validate()?;
        let size = SUBMISSION_HEADER + self.input.len();
        let out = output.get_mut(..size).ok_or(Error::Capacity)?;
        for (i, value) in [
            self.actor.id,
            self.actor.generation,
            self.sequence,
            self.key.id,
            self.key.generation,
            self.submitted_ns,
            self.input.len() as u64,
        ]
        .into_iter()
        .enumerate()
        {
            out[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        out[SUBMISSION_HEADER..].copy_from_slice(self.input);
        Ok(size)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub key: ObjectKey,
    pub state: u64,
    /// LOCAL: actual local task. REMOTE: durable contract with actual STARTED
    /// custody. REJECTED: nonzero error code in id, generation zero.
    pub target: ObjectKey,
}
impl Status {
    pub fn terminal(self) -> bool {
        matches!(self.state, LOCAL | REMOTE | REJECTED)
    }
    pub fn validate(self) -> Result<(), Error> {
        if !live(self.key)
            || match self.state {
                QUEUED | PENDING | UNKNOWN => self.target != ObjectKey::default(),
                LOCAL | REMOTE => !live(self.target),
                REJECTED => self.target.id == 0 || self.target.generation != 0,
                _ => true,
            }
        {
            return Err(Error::Format);
        }
        Ok(())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != STATUS_BYTES {
            return Err(Error::Format);
        }
        let value = Self {
            key: key(bytes, 0)?,
            state: word(bytes, 16)?,
            target: key(bytes, 24)?,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn encode(self) -> Result<[u8; STATUS_BYTES], Error> {
        self.validate()?;
        let mut bytes = [0; STATUS_BYTES];
        for (i, word) in [
            self.key.id,
            self.key.generation,
            self.state,
            self.target.id,
            self.target.generation,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        Ok(bytes)
    }
}
