//! A later root failure is a separate durable record. It cannot rewrite an
//! already sealed CPU window or authorize release before its original signed
//! packet has been fsynced, read back exactly, and closed.
use crate::{
    domain_storage as files,
    peer_replay::{self as peer, LateFailureReceipt},
};
use cyxia_prototype::domains::{
    Error, ObjectKey,
    filesystem::{Handle, OpenMode},
};
use sha2::{Digest, Sha256};

const HEADER: usize = 256;
const CHUNK: usize = super::archive_packet::CHUNK;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    Write,
    Sync,
    Read,
    Close,
    Done,
}

/// Only the completed native writer constructs this release capability.
#[derive(Clone, Copy)]
pub struct Export {
    receipt: LateFailureReceipt,
    object: ObjectKey,
    offset: u64,
    bytes: usize,
    digest: [u8; 32],
}
impl Export {
    pub fn receipt(self) -> LateFailureReceipt {
        self.receipt
    }
    pub fn object(self) -> ObjectKey {
        self.object
    }
    pub fn offset(self) -> u64 {
        self.offset
    }
    pub fn bytes(self) -> usize {
        self.bytes
    }
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
}

pub struct Archive {
    receipt: LateFailureReceipt,
    phase: Phase,
    segment: u16,
    handle: Option<Handle>,
    object: Option<ObjectKey>,
    offset: u64,
    cursor: usize,
    total: usize,
    // After fsync, reuse the completed write hasher to verify the original
    // signed packet separately from the whole archive's readback digest.
    write_hash: Sha256,
    read_hash: Sha256,
    digest: [u8; 32],
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
impl Archive {
    pub fn new(receipt: LateFailureReceipt, segment: u16) -> Result<Self, Error> {
        if peer::late_failure(receipt.key())? != Some(receipt)
            || receipt.key() != receipt.binding().run
            || receipt.sequence() == 0
            || receipt.closing_ns() == 0
            || receipt.failure().observed_ns <= receipt.closing_ns()
            || receipt.packet_bytes() != cyxia_peer_billing::ROOT_FAILURE_PACKET_BYTES
            || receipt.packet_hash() == [0; 32]
        {
            return Err(Error::Stale);
        }
        let total = HEADER + super::archive_packet::padded(receipt.packet_bytes())?;
        Ok(Self {
            receipt,
            phase: Phase::Open,
            segment,
            handle: None,
            object: None,
            offset: 0,
            cursor: 0,
            total,
            write_hash: Sha256::new(),
            read_hash: Sha256::new(),
            digest: [0; 32],
        })
    }
    pub fn done(&self) -> bool {
        self.phase == Phase::Done
    }
    pub fn segment(&self) -> u16 {
        self.segment
    }
    pub fn export(&self) -> Result<Export, Error> {
        if !self.done() || self.handle.is_some() || self.digest == [0; 32] {
            return Err(Error::Busy);
        }
        Ok(Export {
            receipt: self.receipt,
            object: self.object.ok_or(Error::NotReady)?,
            offset: self.offset,
            bytes: self.total,
            digest: self.digest,
        })
    }
    fn path(&self, bytes: &mut [u8; 32]) -> usize {
        bytes[..4].copy_from_slice(b"/lf-");
        let hex = b"0123456789abcdef";
        for i in 0..16 {
            bytes[4 + i] = hex[((self.receipt.key().boot_epoch >> (4 * (15 - i))) & 15) as usize];
        }
        bytes[20] = b'-';
        for i in 0..4 {
            bytes[21 + i] = hex[((self.segment >> (4 * (3 - i))) & 15) as usize];
        }
        25
    }
    fn encode(&self, offset: usize, out: &mut [u8; CHUNK]) -> Result<usize, Error> {
        if offset == 0 {
            out.fill(0);
            let magic = b"CYXIA_LATE_1.3\0";
            out[..magic.len()].copy_from_slice(magic);
            let run = self.receipt.key();
            let failure = self.receipt.failure();
            for (i, value) in [
                1,
                HEADER as u64,
                self.total as u64,
                run.boot_epoch,
                run.trial_id,
                run.generation,
                self.receipt.binding().participant.boot,
                self.receipt.sequence(),
                self.receipt.closing_ns(),
                failure.observed_ns,
                failure.root_token,
                failure.error,
                self.receipt.packet_bytes() as u64,
                0,
            ]
            .into_iter()
            .enumerate()
            {
                put(out, 16 + i * 8, value);
            }
            out[128..160].copy_from_slice(&self.receipt.packet_hash());
            out[160..192]
                .copy_from_slice(&self.receipt.binding().hash().map_err(|_| Error::Format)?);
            out[192..224].copy_from_slice(&self.receipt.binding().origin.node);
            out[224..256].copy_from_slice(&self.receipt.binding().participant.node);
            return Ok(HEADER);
        }
        super::archive_packet::chunk(
            self.receipt.packet_bytes(),
            offset - HEADER,
            out,
            |at, bytes| peer::copy_late_packet(self.receipt, at, bytes),
        )
    }
    /// One bounded native filesystem operation per paid service piece.
    pub fn step(&mut self, progress: &mut dyn FnMut()) -> Result<bool, Error> {
        match self.phase {
            Phase::Open => {
                let mut name = [0; 32];
                let n = self.path(&mut name);
                let path = core::str::from_utf8(&name[..n]).map_err(|_| Error::Format)?;
                let stat = match files::stat(path, progress) {
                    Ok(stat) => stat,
                    Err(Error::NotFound) => {
                        files::create(path, progress)?;
                        return Ok(true);
                    }
                    Err(error) => return Err(error),
                };
                if stat
                    .size
                    .checked_add(self.total as u64)
                    .is_none_or(|end| end > cyxia_prototype::storage::MAX_FILE_SIZE)
                {
                    self.segment = self.segment.checked_add(1).ok_or(Error::Capacity)?;
                    return Ok(true);
                }
                self.handle = Some(files::open(path, OpenMode::ReadWrite, progress)?);
                self.object = Some(stat.object);
                self.offset = stat.size;
                self.phase = Phase::Write;
            }
            Phase::Write => {
                if self.cursor == self.total {
                    self.digest = self.write_hash.clone().finalize().into();
                    self.phase = Phase::Sync;
                    return Ok(true);
                }
                let mut bytes = [0; CHUNK];
                let n = self.encode(self.cursor, &mut bytes)?;
                if files::write(
                    self.handle.ok_or(Error::NotReady)?,
                    self.offset + self.cursor as u64,
                    &bytes[..n],
                    progress,
                )? != n
                {
                    return Err(Error::Io);
                }
                self.write_hash.update(&bytes[..n]);
                self.cursor += n;
            }
            Phase::Sync => {
                let receipt = files::fsync(self.handle.ok_or(Error::NotReady)?, progress)?;
                if Some(receipt.object) != self.object || receipt.write_seq == 0 {
                    return Err(Error::Stale);
                }
                self.cursor = 0;
                self.write_hash = Sha256::new();
                self.read_hash = Sha256::new();
                self.phase = Phase::Read;
            }
            Phase::Read => {
                if self.cursor == self.total {
                    if <[u8; 32]>::from(self.read_hash.clone().finalize()) != self.digest
                        || <[u8; 32]>::from(self.write_hash.clone().finalize())
                            != self.receipt.packet_hash()
                    {
                        // A later retry rereads the same durable range. It
                        // never changes the identity or accepts a bad digest.
                        self.cursor = 0;
                        self.write_hash = Sha256::new();
                        self.read_hash = Sha256::new();
                        return Err(Error::Io);
                    }
                    self.phase = Phase::Close;
                    return Ok(true);
                }
                let mut bytes = [0; CHUNK];
                let n = (self.total - self.cursor).min(CHUNK);
                if files::read(
                    self.handle.ok_or(Error::NotReady)?,
                    self.offset + self.cursor as u64,
                    &mut bytes[..n],
                    progress,
                )? != n
                {
                    return Err(Error::Io);
                }
                self.read_hash.update(&bytes[..n]);
                if self.cursor >= HEADER {
                    let signed = self
                        .receipt
                        .packet_bytes()
                        .saturating_sub(self.cursor - HEADER)
                        .min(n);
                    self.write_hash.update(&bytes[..signed]);
                }
                self.cursor += n;
            }
            Phase::Close => {
                files::close(self.handle.ok_or(Error::NotReady)?)?;
                self.handle = None;
                self.phase = Phase::Done;
            }
            Phase::Done => return Ok(false),
        }
        Ok(true)
    }
}
