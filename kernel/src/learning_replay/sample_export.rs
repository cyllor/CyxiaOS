//! Outbound-only actual sample handoff. No decoder or label authority exists.
//! One immutable pair bank; storage I/O is drained later on paid service turns.
use super::archive::Export;
use super::sample_witness::{WITNESS_BYTES, Witness};
use crate::domain_storage as files;
use cyxia_prototype::domains::{
    Error, ObjectKey,
    filesystem::{Handle, OpenMode},
};
use sha2::{Digest, Sha256};
pub const ARCHIVE_REF_BYTES: usize = 96;
const BYTES: usize = 2048;
const CHUNK: usize = 256;
const _: () = assert!(64 + WITNESS_BYTES + 2 * ARCHIVE_REF_BYTES <= BYTES);
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
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
    pub fn new(witness: Witness, baseline: Export, candidate: Export) -> Result<Self, Error> {
        let b = baseline.key();
        let c = candidate.key();
        if b.boot_epoch != c.boot_epoch
            || b.trial_id == c.trial_id
            || witness.0[32..40] != b.trial_id.to_le_bytes()
            || witness.0[40..48] != c.trial_id.to_le_bytes()
        {
            return Err(Error::Conflict);
        }
        let mut bytes = [0; BYTES];
        bytes[..16].copy_from_slice(b"CYXIA_LABEL_16\0\0");
        put(&mut bytes, 16, 1);
        put(&mut bytes, 24, BYTES as u64);
        bytes[32..32 + WITNESS_BYTES].copy_from_slice(&witness.0);
        let digest: [u8; 32] = Sha256::digest(&witness.0).into();
        bytes[32 + WITNESS_BYTES..64 + WITNESS_BYTES].copy_from_slice(&digest);
        let mut at = 64 + WITNESS_BYTES;
        for export in [baseline, candidate] {
            let start = at;
            let key = export.key();
            let object = export.object();
            for value in [
                key.boot_epoch,
                key.trial_id,
                key.generation,
                object.id,
                object.generation,
                export.offset(),
                export.bytes() as u64,
            ] {
                put(&mut bytes, at, value);
                at += 8;
            }
            bytes[at..at + 32].copy_from_slice(&export.digest());
            at = start + ARCHIVE_REF_BYTES;
        }
        Ok(Self {
            digest: Sha256::digest(bytes).into(),
            bytes,
            phase: Phase::Open,
            boot: b.boot_epoch,
            handle: None,
            object: None,
            cursor: 0,
            read_hash: Sha256::new(),
        })
    }
    pub fn done(&self) -> bool {
        self.phase == Phase::Done && self.handle.is_none()
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
                name[..4].copy_from_slice(b"/ls-");
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
