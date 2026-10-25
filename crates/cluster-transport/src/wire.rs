//! Exact §10.3 RPC framing. Parsing bytes grants no trust or resource access.
pub const HEADER_LEN: usize = 96;
pub const MAX_BODY: usize = 65536;
pub const MAX_FRAME: usize = HEADER_LEN + MAX_BODY;
pub const MAGIC: u32 = 0x4358_4331;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Kind,
    Reserved,
    Sequence,
    Boot,
    Poisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Kind {
    Hello = 1,
    Status = 2,
    Negotiate = 3,
    Confirm = 4,
    Proof = 5,
    Ready = 6,
    Quote = 16,
    Prepare = 17,
    Commit = 18,
    Activate = 19,
    Result = 20,
    AckResult = 21,
    Close = 22,
    Leave = 32,
    LeaveProof = 33,
}
impl Kind {
    fn decode(value: u16) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::Hello,
            2 => Self::Status,
            3 => Self::Negotiate,
            4 => Self::Confirm,
            5 => Self::Proof,
            6 => Self::Ready,
            16 => Self::Quote,
            17 => Self::Prepare,
            18 => Self::Commit,
            19 => Self::Activate,
            20 => Self::Result,
            21 => Self::AckResult,
            22 => Self::Close,
            32 => Self::Leave,
            33 => Self::LeaveProof,
            _ => return Err(Error::Kind),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub response: bool,
    pub body_len: u32,
    pub session_seq: u64,
    pub request_id: [u8; 16],
    pub cluster_id: [u8; 32],
    pub config_epoch: u64,
    pub sender_boot: u64,
    pub receiver_boot: u64,
}

impl Header {
    fn validate(&self) -> Result<(), Error> {
        if self.body_len as usize > MAX_BODY {
            return Err(Error::Length);
        }
        if self.session_seq == 0 {
            return Err(Error::Sequence);
        }
        if self.sender_boot == 0
            || (self.receiver_boot == 0 && (self.kind != Kind::Hello || self.response))
        {
            return Err(Error::Boot);
        }
        Ok(())
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<(), Error> {
        self.validate()?;
        if out.len() != HEADER_LEN {
            return Err(Error::Length);
        }
        out.fill(0);
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        let kind = self.kind as u16 | if self.response { 0x8000 } else { 0 };
        out[6..8].copy_from_slice(&kind.to_le_bytes());
        out[8..10].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        out[12..16].copy_from_slice(&self.body_len.to_le_bytes());
        out[16..24].copy_from_slice(&self.session_seq.to_le_bytes());
        out[24..40].copy_from_slice(&self.request_id);
        out[40..72].copy_from_slice(&self.cluster_id);
        out[72..80].copy_from_slice(&self.config_epoch.to_le_bytes());
        out[80..88].copy_from_slice(&self.sender_boot.to_le_bytes());
        out[88..96].copy_from_slice(&self.receiver_boot.to_le_bytes());
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HEADER_LEN {
            return Err(Error::Length);
        }
        let u16_at = |i| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let u32_at = |i| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let u64_at = |i| u64::from_le_bytes(core::array::from_fn(|j| bytes[i + j]));
        if u32_at(0) != MAGIC || u16_at(4) != 1 || u16_at(8) != HEADER_LEN as u16 {
            return Err(Error::Version);
        }
        if u16_at(10) != 0 {
            return Err(Error::Reserved);
        }
        let raw_kind = u16_at(6);
        let header = Self {
            kind: Kind::decode(raw_kind & 0x7fff)?,
            response: raw_kind & 0x8000 != 0,
            body_len: u32_at(12),
            session_seq: u64_at(16),
            request_id: core::array::from_fn(|i| bytes[24 + i]),
            cluster_id: core::array::from_fn(|i| bytes[40 + i]),
            config_epoch: u64_at(72),
            sender_boot: u64_at(80),
            receiver_boot: u64_at(88),
        };
        header.validate()?;
        Ok(header)
    }
}

/// One in-flight message, caller-reserved capacity. A malformed header poisons
/// this stream rather than trying to resynchronize untrusted length fields.
pub struct Decoder<'a> {
    buffer: &'a mut [u8; MAX_FRAME],
    used: usize,
    header: Option<Header>,
    failed: bool,
}
impl<'a> Decoder<'a> {
    pub fn new(buffer: &'a mut [u8; MAX_FRAME]) -> Self {
        Self {
            buffer,
            used: 0,
            header: None,
            failed: false,
        }
    }
    /// Consumes only bytes belonging to this message; caller retains any suffix.
    pub fn feed(&mut self, input: &[u8]) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        let mut taken = 0;
        if self.used < HEADER_LEN {
            let count = input.len().min(HEADER_LEN - self.used);
            self.buffer[self.used..self.used + count].copy_from_slice(&input[..count]);
            self.used += count;
            taken += count;
            if self.used == HEADER_LEN {
                match Header::decode(&self.buffer[..HEADER_LEN]) {
                    Ok(header) => self.header = Some(header),
                    Err(e) => {
                        self.failed = true;
                        return Err(e);
                    }
                }
            }
        }
        if let Some(header) = self.header {
            let remaining = HEADER_LEN + header.body_len as usize - self.used;
            let count = (input.len() - taken).min(remaining);
            self.buffer[self.used..self.used + count].copy_from_slice(&input[taken..taken + count]);
            self.used += count;
            taken += count;
        }
        Ok(taken)
    }
    pub fn message(&self) -> Option<(Header, &[u8])> {
        let header = self.header?;
        if self.failed || self.used != HEADER_LEN + header.body_len as usize {
            return None;
        }
        Some((header, &self.buffer[HEADER_LEN..self.used]))
    }
    pub fn consume(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        if self.message().is_none() {
            return Err(Error::Length);
        }
        self.buffer[..self.used].fill(0);
        self.used = 0;
        self.header = None;
        Ok(())
    }
}

/// Only a replay/boot consistency check. Construct after TLS and HELLO bind
/// both durable BootEpochs. It is deliberately not named an admission token.
pub struct ReplayGate {
    local_boot: u64,
    peer_boot: u64,
    highwater: u64,
}
impl ReplayGate {
    pub fn new(local_boot: u64, peer_boot: u64) -> Result<Self, Error> {
        if local_boot == 0 || peer_boot == 0 {
            return Err(Error::Boot);
        }
        Ok(Self {
            local_boot,
            peer_boot,
            highwater: 0,
        })
    }
    pub fn accept(&mut self, header: &Header) -> Result<(), Error> {
        header.validate()?;
        if header.sender_boot != self.peer_boot
            || (header.receiver_boot != self.local_boot
                && !(self.highwater == 0
                    && header.kind == Kind::Hello
                    && !header.response
                    && header.receiver_boot == 0))
        {
            return Err(Error::Boot);
        }
        if header.session_seq <= self.highwater {
            return Err(Error::Sequence);
        }
        self.highwater = header.session_seq;
        Ok(())
    }
}
