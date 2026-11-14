//! Outbound-only actual sample handoff. No decoder or label authority exists.
//! One immutable pair bank; storage I/O is drained later on paid service turns.
use crate::domain_storage as files;
use cyxia_prototype::domains::{
    Error, ObjectKey,
    filesystem::{Handle, OpenMode},
};
use sha2::{Digest, Sha256};
const BYTES: usize = super::bounded_data::SUPPLEMENT_BYTES;
const CHUNK: usize = 256;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    Write,
    Sync,
    Read,
    Close,
    Done,
}
pub struct Archive {
    bytes: [u8; BYTES],
    phase: Phase,
    boot: u64,
    handle: Option<Handle>,
    object: Option<ObjectKey>,
    cursor: usize,
    read_hash: Sha256,
    digest: [u8; 32],
}
impl Archive {
    pub fn new(bytes: [u8; BYTES], boot: u64) -> Result<Self, Error> {
        if boot == 0 {
            return Err(Error::Stale);
        }
        Ok(Self {
            digest: Sha256::digest(bytes).into(),
            bytes,
            phase: Phase::Open,
            boot,
            handle: None,
            object: None,
            cursor: 0,
            read_hash: Sha256::new(),
        })
    }
    pub fn done(&self) -> bool {
        self.phase == Phase::Done && self.handle.is_none()
    }
    pub fn bytes(&self) -> &[u8; BYTES] {
        &self.bytes
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn object(&self) -> Option<ObjectKey> {
        self.object
    }
    pub fn step(&mut self, progress: &mut dyn FnMut()) -> Result<bool, Error> {
        match self.phase {
            Phase::Open => {
                let mut name = [0; 20];
                name[..4].copy_from_slice(b"/ld-");
                for i in 0..16 {
                    name[4 + i] =
                        b"0123456789abcdef"[((self.boot >> (4 * (15 - i))) & 15) as usize];
                }
                let path = core::str::from_utf8(&name).map_err(|_| Error::Format)?;
                let stat = match files::stat(path, progress) {
                    Ok(stat) => stat,
                    Err(Error::NotFound) => {
                        files::create(path, progress)?;
                        return Ok(true);
                    }
                    Err(error) => return Err(error),
                };
                if stat.size != 0 {
                    return Err(Error::Conflict);
                }
                self.handle = Some(files::open(path, OpenMode::ReadWrite, progress)?);
                self.object = Some(stat.object);
                self.phase = Phase::Write;
            }
            Phase::Write => {
                if self.cursor == BYTES {
                    self.phase = Phase::Sync;
                    return Ok(true);
                }
                let n = (BYTES - self.cursor).min(CHUNK);
                if files::write(
                    self.handle.ok_or(Error::NotReady)?,
                    self.cursor as u64,
                    &self.bytes[self.cursor..self.cursor + n],
                    progress,
                )? != n
                {
                    return Err(Error::Io);
                }
                self.cursor += n;
            }
            Phase::Sync => {
                let receipt = files::fsync(self.handle.ok_or(Error::NotReady)?, progress)?;
                if Some(receipt.object) != self.object || receipt.write_seq == 0 {
                    return Err(Error::Stale);
                }
                self.cursor = 0;
                self.phase = Phase::Read;
            }
            Phase::Read => {
                if self.cursor == BYTES {
                    if <[u8; 32]>::from(self.read_hash.clone().finalize()) != self.digest {
                        return Err(Error::Io);
                    }
                    self.phase = Phase::Close;
                    return Ok(true);
                }
                let mut bytes = [0; CHUNK];
                let n = (BYTES - self.cursor).min(CHUNK);
                if files::read(
                    self.handle.ok_or(Error::NotReady)?,
                    self.cursor as u64,
                    &mut bytes[..n],
                    progress,
                )? != n
                {
                    return Err(Error::Io);
                }
                self.read_hash.update(&bytes[..n]);
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
