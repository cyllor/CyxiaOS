//! Opt-in ABI v4 service for the signed scratch fixture.
//! EL1 authenticates the mounted owner and copies its private buffers before
//! calling this service. An authorized write changes the cached view for one boot.

use core::ops::Range;

use sha2::{Digest, Sha256};

use super::{
    Error,
    file::GROUP_VOLATILE_SLOTS,
    file_format_v1::{
        SCRATCH_FILE_DATA, SCRATCH_FILE_GENERATION, SCRATCH_FILE_INODE, SCRATCH_FILE_NAME,
        SCRATCH_FILE_OWNER_RIGHTS, SCRATCH_FILE_WRITE_RIGHTS, SCRATCH_WRITABLE_FILE_OWNER_RIGHTS,
    },
    file_media_v0199::crc32c_zeroed,
    file_service_v4::{REPLY_HEADER, REPLY_MAGIC, REPLY_VERSION, REQUEST_HEADER, Request},
    offline_config_v1::Principal,
};

pub const ENDPOINT: u64 = 0x4649_4c45_0000_0011;
pub const ROOT_SELECTOR: u64 = 0x4649_4c45_0000_0001;
pub const MAX_FRAME: usize = 128;
pub const MAX_REPLY: usize = 256;

const OPEN: u16 = 2;
const READ: u16 = 3;
const WRITE: u16 = 4;
const CLOSE: u16 = 6;
const READDIR: u16 = 8;
const QUERY_VOLATILE: u16 = 14;
const ACK_VOLATILE: u16 = 15;
const DIRENT_BYTES: usize = 128;
const DIRENT_CRC: usize = 124;
const CAP_OFFSET: usize = 64;
const DIGEST_OFFSET: usize = 80;
const DIGEST_END: usize = DIGEST_OFFSET + 32;
const WRITE_SEQUENCE_OFFSET: usize = 120;
const CHILD_TAG: u64 = 1 << 63;
const CHILD_MASK: u64 = CHILD_TAG - 1;
const MAX_LIVE_HANDLES: usize = 4;

const _: () = assert!(REPLY_HEADER + DIRENT_BYTES == MAX_REPLY);
const _: () = assert!(REPLY_HEADER + SCRATCH_FILE_DATA.len() <= MAX_REPLY);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedFile {
    boot_epoch: u64,
    owner: Principal,
    owner_rights: u32,
    dirent: [u8; DIRENT_BYTES],
    data: [u8; SCRATCH_FILE_DATA.len()],
    content_digest: [u8; 32],
}

impl StagedFile {
    pub fn new(
        boot_epoch: u64,
        owner: Principal,
        dirent: [u8; DIRENT_BYTES],
        data: [u8; SCRATCH_FILE_DATA.len()],
    ) -> Result<Self, Error> {
        Self::new_with_owner_rights(boot_epoch, owner, dirent, data, SCRATCH_FILE_OWNER_RIGHTS)
    }

    /// Stage the exact fixture and its validated owner ACL.
    pub fn new_with_owner_rights(
        boot_epoch: u64,
        owner: Principal,
        dirent: [u8; DIRENT_BYTES],
        data: [u8; SCRATCH_FILE_DATA.len()],
        owner_rights: u32,
    ) -> Result<Self, Error> {
        let name_end = 16 + SCRATCH_FILE_NAME.len();
        if boot_epoch == 0
            || owner.id == 0
            || owner.generation == 0
            || !matches!(
                owner_rights,
                SCRATCH_FILE_OWNER_RIGHTS | SCRATCH_WRITABLE_FILE_OWNER_RIGHTS
            )
            || u32::from_le_bytes(field(&dirent, 0)) != SCRATCH_FILE_INODE
            || usize::from(u16::from_le_bytes(field(&dirent, 4))) != SCRATCH_FILE_NAME.len()
            || dirent[6..8] != [0; 2]
            || u64::from_le_bytes(field(&dirent, 8)) != SCRATCH_FILE_GENERATION
            || &dirent[16..name_end] != SCRATCH_FILE_NAME
            || dirent[name_end..DIRENT_CRC].iter().any(|&byte| byte != 0)
            || u32::from_le_bytes(field(&dirent, DIRENT_CRC)) != crc32c_zeroed(&dirent, DIRENT_CRC)?
            || &data != SCRATCH_FILE_DATA
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            boot_epoch,
            owner,
            owner_rights,
            dirent,
            content_digest: Sha256::digest(data).into(),
            data,
        })
    }

    pub const fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    pub const fn owner(&self) -> Principal {
        self.owner
    }

    pub const fn owner_rights(&self) -> u32 {
        self.owner_rights
    }

    /// Return the digest of the originally staged fixture bytes.
    pub const fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Served {
    pub len: usize,
    pub replay: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    Unauthorized,
    Format,
    Stale,
    Conflict,
    Unsupported,
    ShortReply,
    Busy,
}

impl ReadError {
    pub const fn errno(self) -> i64 {
        match self {
            Self::Unauthorized => -1,
            Self::Format => -2,
            Self::Stale => -4,
            Self::Conflict => -5,
            Self::Unsupported => -11,
            Self::ShortReply => -12,
            Self::Busy => -13,
        }
    }
}

#[derive(Clone, Copy)]
struct Retained {
    id: u64,
    selector: u64,
    frame_len: usize,
    frame: [u8; MAX_FRAME],
    reply_len: usize,
    reply: [u8; MAX_REPLY],
}

#[derive(Clone, Copy)]
struct LiveHandle {
    generation: u64,
    rights: u32,
}

enum Effect<'a> {
    None,
    Open {
        slot: usize,
        rights: u32,
    },
    Close {
        slot: usize,
    },
    Write {
        range: Range<usize>,
        data: &'a [u8],
        sequence: u64,
    },
}

pub struct FileReadService {
    file: StagedFile,
    child_base: u64,
    open_generation: u64,
    handles: [Option<LiveHandle>; MAX_LIVE_HANDLES],
    handle_limit: usize,
    highest_id: u64,
    write_seq: u64,
    retained: [Option<Retained>; GROUP_VOLATILE_SLOTS],
}

const _: () = assert!(core::mem::size_of::<FileReadService>() <= 4096);

impl FileReadService {
    /// Give the holder one live child at a time.
    pub fn new(file: StagedFile) -> Self {
        Self::with_handle_limit(file, 1)
    }

    /// Give the holder up to four live children for the same staged file.
    pub fn with_multiple_handles(file: StagedFile) -> Self {
        Self::with_handle_limit(file, MAX_LIVE_HANDLES)
    }

    fn with_handle_limit(file: StagedFile, handle_limit: usize) -> Self {
        let mut scope = Sha256::new();
        scope.update(b"CYX/FILE-READ-SELECTOR/v1");
        scope.update(file.boot_epoch.to_le_bytes());
        scope.update(file.owner.id.to_le_bytes());
        scope.update(file.owner.generation.to_le_bytes());
        Self {
            file,
            child_base: u64::from_le_bytes(field(&scope.finalize(), 0)) & CHILD_MASK,
            open_generation: 0,
            handles: [None; MAX_LIVE_HANDLES],
            handle_limit,
            highest_id: 0,
            write_seq: 0,
            retained: [None; GROUP_VOLATILE_SLOTS],
        }
    }

    pub fn live_handles(&self) -> usize {
        self.handles.iter().flatten().count()
    }

    /// Return the current selectors by slot, with zero for each empty slot.
    pub fn live_handle_selectors(&self) -> [u64; MAX_LIVE_HANDLES] {
        self.handles
            .map(|handle| handle.map_or(0, |handle| self.child_selector(handle.generation)))
    }

    pub fn retained_count(&self) -> usize {
        self.retained.iter().flatten().count()
    }

    /// Return the latest committed volatile write sequence for this boot.
    pub const fn write_sequence(&self) -> u64 {
        self.write_seq
    }

    pub fn serve(
        &mut self,
        selector: u64,
        frame: &[u8],
        reply: &mut [u8],
    ) -> Result<Served, ReadError> {
        // The shared decoder combines a length mismatch and a selector mismatch
        // under Unauthorized. Preserve the syscall's distinct format error.
        if !(REQUEST_HEADER..=MAX_FRAME).contains(&frame.len())
            || u32::from_le_bytes(field(frame, 12)) as usize != frame.len() - REQUEST_HEADER
        {
            return Err(ReadError::Format);
        }
        let request = Request::decode(frame, selector).map_err(|error| match error {
            Error::Unauthorized => ReadError::Unauthorized,
            _ => ReadError::Format,
        })?;
        match request.op {
            QUERY_VOLATILE | ACK_VOLATILE => return self.custody(request, reply),
            OPEN | READ | CLOSE | READDIR => {}
            WRITE if self.file.owner_rights & SCRATCH_FILE_WRITE_RIGHTS != 0 => {}
            _ => return Err(ReadError::Unsupported),
        }

        if let Some(row) = self
            .retained
            .iter()
            .flatten()
            .find(|row| row.id == request.request_id)
        {
            if row.selector != selector || &row.frame[..row.frame_len] != frame {
                return Err(ReadError::Conflict);
            }
            match request.op {
                OPEN => {
                    self.live_child_slot(u64::from_le_bytes(field(&row.reply, CAP_OFFSET)), 0)?;
                }
                READ => {
                    self.live_child_slot(selector, SCRATCH_FILE_OWNER_RIGHTS)?;
                }
                WRITE => {
                    self.live_child_slot(selector, SCRATCH_FILE_WRITE_RIGHTS)?;
                }
                _ => {}
            }
            return copy_reply(reply, &row.reply[..row.reply_len], true);
        }
        if request.request_id <= self.highest_id {
            return Err(ReadError::Stale);
        }

        let (cap, output, effect) = self.prepare(request, selector)?;
        let slot = self
            .retained
            .iter()
            .position(Option::is_none)
            .ok_or(ReadError::Busy)?;
        let mut row = Retained {
            id: request.request_id,
            selector,
            frame_len: frame.len(),
            frame: [0; MAX_FRAME],
            reply_len: REPLY_HEADER + output.len(),
            reply: [0; MAX_REPLY],
        };
        row.frame[..frame.len()].copy_from_slice(frame);
        self.reply_header(&mut row.reply, request.request_id);
        row.reply[36..40].copy_from_slice(&(output.len() as u32).to_le_bytes());
        row.reply[CAP_OFFSET..CAP_OFFSET + 8].copy_from_slice(&cap.to_le_bytes());
        row.reply[72..80].copy_from_slice(&SCRATCH_FILE_GENERATION.to_le_bytes());
        if let Effect::Write { sequence, .. } = &effect {
            row.reply[WRITE_SEQUENCE_OFFSET..WRITE_SEQUENCE_OFFSET + 8]
                .copy_from_slice(&sequence.to_le_bytes());
        }
        row.reply[REPLY_HEADER..row.reply_len].copy_from_slice(output);
        // Hash the used bytes with the digest field still zeroed.
        let digest = Sha256::digest(&row.reply[..row.reply_len]);
        row.reply[DIGEST_OFFSET..DIGEST_END].copy_from_slice(&digest);

        // Capacity is the last fallible check before committing any effect.
        let served = copy_reply(reply, &row.reply[..row.reply_len], false)?;
        match effect {
            Effect::None => {}
            Effect::Open { slot, rights } => {
                self.open_generation += 1;
                self.handles[slot] = Some(LiveHandle {
                    generation: self.open_generation,
                    rights,
                });
            }
            Effect::Close { slot } => self.handles[slot] = None,
            Effect::Write {
                range,
                data,
                sequence,
            } => {
                self.file.data[range].copy_from_slice(data);
                self.write_seq = sequence;
            }
        }
        self.retained[slot] = Some(row);
        self.highest_id = request.request_id;
        Ok(served)
    }

    fn prepare<'frame>(
        &self,
        request: Request<'frame>,
        selector: u64,
    ) -> Result<(u64, &[u8], Effect<'frame>), ReadError> {
        let p = request.payload;
        match request.op {
            OPEN => {
                let name_end = 2 + usize::from(u16::from_le_bytes(field(p, 0)));
                let rights = u32::from_le_bytes(field(p, name_end));
                if selector != ROOT_SELECTOR
                    || &p[2..name_end] != SCRATCH_FILE_NAME
                    || rights == 0
                    || rights & !self.file.owner_rights != 0
                {
                    return Err(ReadError::Unauthorized);
                }
                if self.open_generation == CHILD_MASK {
                    return Err(ReadError::Busy);
                }
                let slot = self.handles[..self.handle_limit]
                    .iter()
                    .position(Option::is_none)
                    .ok_or(ReadError::Busy)?;
                Ok((
                    self.child_selector(self.open_generation + 1),
                    &[],
                    Effect::Open { slot, rights },
                ))
            }
            READ => {
                self.live_child_slot(selector, SCRATCH_FILE_OWNER_RIGHTS)?;
                let offset = u64::from_le_bytes(field(p, 0));
                let requested = u32::from_le_bytes(field(p, 8)) as usize;
                let data = &self.file.data;
                let first = offset.min(data.len() as u64) as usize;
                let end = (first + requested).min(data.len());
                Ok((0, &data[first..end], Effect::None))
            }
            WRITE => {
                self.live_child_slot(selector, SCRATCH_FILE_WRITE_RIGHTS)?;
                let data = &p[12..];
                let start = usize::try_from(u64::from_le_bytes(field(p, 0)))
                    .map_err(|_| ReadError::Format)?;
                let end = start
                    .checked_add(data.len())
                    .filter(|&end| end <= self.file.data.len())
                    .ok_or(ReadError::Format)?;
                let sequence = self.write_seq.checked_add(1).ok_or(ReadError::Busy)?;
                Ok((
                    0,
                    &[],
                    Effect::Write {
                        range: start..end,
                        data,
                        sequence,
                    },
                ))
            }
            CLOSE => {
                let slot = self.live_child_slot(selector, 0)?;
                Ok((0, &[], Effect::Close { slot }))
            }
            READDIR => {
                if selector != ROOT_SELECTOR {
                    return Err(ReadError::Unauthorized);
                }
                let entries: &[u8] = if u32::from_le_bytes(field(p, 0)) == 0 {
                    &self.file.dirent
                } else {
                    &[]
                };
                Ok((0, entries, Effect::None))
            }
            _ => Err(ReadError::Unsupported),
        }
    }

    fn child_selector(&self, generation: u64) -> u64 {
        CHILD_TAG | ((self.child_base + generation) & CHILD_MASK)
    }

    fn live_child_slot(&self, selector: u64, required_rights: u32) -> Result<usize, ReadError> {
        // The boot/owner-scoped sequence distinguishes a spent selector from
        // one this service has never issued. EL1 still authenticates the holder.
        let generation = (selector & CHILD_MASK).wrapping_sub(self.child_base) & CHILD_MASK;
        if selector & CHILD_TAG == 0 || generation == 0 || generation > self.open_generation {
            return Err(ReadError::Unauthorized);
        }
        let (slot, handle) = self
            .handles
            .iter()
            .enumerate()
            .find_map(|(slot, handle)| {
                let handle = handle.as_ref()?;
                (handle.generation == generation).then_some((slot, handle))
            })
            .ok_or(ReadError::Stale)?;
        if handle.rights & required_rights != required_rights {
            return Err(ReadError::Unauthorized);
        }
        Ok(slot)
    }

    fn custody(&mut self, request: Request<'_>, reply: &mut [u8]) -> Result<Served, ReadError> {
        let p = request.payload;
        if u64::from_le_bytes(field(p, 0)) != self.file.boot_epoch
            || u64::from_le_bytes(field(p, 8)) != self.file.boot_epoch
        {
            return Err(ReadError::Stale);
        }
        let slot = self
            .retained
            .iter()
            .position(|row| row.as_ref().is_some_and(|row| row.id == request.request_id))
            .ok_or(ReadError::Stale)?;
        let row = self.retained[slot].as_ref().unwrap();
        let digest = &row.reply[DIGEST_OFFSET..DIGEST_END];
        let ack = request.op == ACK_VOLATILE;
        if ack {
            if &p[24..] != digest {
                return Err(ReadError::Conflict);
            }
            if self
                .retained
                .iter()
                .flatten()
                .any(|older| older.id < row.id)
            {
                return Err(ReadError::Busy);
            }
        }
        let mut wire = [0; REPLY_HEADER];
        self.reply_header(&mut wire, request.request_id);
        wire[DIGEST_OFFSET..DIGEST_END].copy_from_slice(digest);
        let served = copy_reply(reply, &wire, false)?;
        if ack {
            self.retained[slot] = None;
        }
        Ok(served)
    }

    fn reply_header(&self, reply: &mut [u8], id: u64) {
        reply[..4].copy_from_slice(&REPLY_MAGIC.to_le_bytes());
        reply[4..6].copy_from_slice(&REPLY_VERSION.to_le_bytes());
        reply[6..8].copy_from_slice(&(REPLY_HEADER as u16).to_le_bytes());
        reply[8..16].copy_from_slice(&id.to_le_bytes());
        reply[16..24].copy_from_slice(&self.file.boot_epoch.to_le_bytes());
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N].try_into().unwrap()
}

fn copy_reply(reply: &mut [u8], wire: &[u8], replay: bool) -> Result<Served, ReadError> {
    let len = wire.len();
    reply
        .get_mut(..len)
        .ok_or(ReadError::ShortReply)?
        .copy_from_slice(wire);
    Ok(Served { len, replay })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::security::file_service_v4::{REPLY_HEADER, REQUEST_MAGIC, REQUEST_VERSION, Reply};
    use std::{vec, vec::Vec};

    const EPOCH: u64 = 7;
    const OWNER: Principal = Principal {
        id: 1,
        generation: 1,
    };
    const DIR_PAGE: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

    fn seal(dirent: &mut [u8; DIRENT_BYTES]) {
        let crc = crc32c_zeroed(dirent, DIRENT_CRC).unwrap();
        dirent[DIRENT_CRC..].copy_from_slice(&crc.to_le_bytes());
    }

    fn fixture_dirent() -> [u8; DIRENT_BYTES] {
        let mut dirent = [0; DIRENT_BYTES];
        dirent[..4].copy_from_slice(&1u32.to_le_bytes());
        dirent[4..6].copy_from_slice(&10u16.to_le_bytes());
        dirent[8..16].copy_from_slice(&1u64.to_le_bytes());
        dirent[16..26].copy_from_slice(b"readme.txt");
        seal(&mut dirent);
        dirent
    }

    fn fixture(epoch: u64) -> StagedFile {
        StagedFile::new(epoch, OWNER, fixture_dirent(), *SCRATCH_FILE_DATA).unwrap()
    }

    fn writable_fixture() -> StagedFile {
        StagedFile::new_with_owner_rights(
            EPOCH,
            OWNER,
            fixture_dirent(),
            *SCRATCH_FILE_DATA,
            SCRATCH_WRITABLE_FILE_OWNER_RIGHTS,
        )
        .unwrap()
    }

    fn request(op: u16, id: u64, payload: &[u8]) -> Vec<u8> {
        let mut wire = vec![0; REQUEST_HEADER + payload.len()];
        wire[..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
        wire[4..6].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
        wire[6..8].copy_from_slice(&(REQUEST_HEADER as u16).to_le_bytes());
        wire[8..10].copy_from_slice(&op.to_le_bytes());
        wire[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        wire[16..24].copy_from_slice(&id.to_le_bytes());
        wire[REQUEST_HEADER..].copy_from_slice(payload);
        wire
    }

    fn open(id: u64, name: &[u8], rights: u32) -> Vec<u8> {
        let mut payload = (name.len() as u16).to_le_bytes().to_vec();
        payload.extend_from_slice(name);
        payload.extend_from_slice(&rights.to_le_bytes());
        payload.extend_from_slice(&[0; 4]);
        request(OPEN, id, &payload)
    }

    fn read(id: u64, offset: u64, bytes: u32) -> Vec<u8> {
        let mut payload = offset.to_le_bytes().to_vec();
        payload.extend_from_slice(&bytes.to_le_bytes());
        request(READ, id, &payload)
    }

    fn write(id: u64, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut payload = offset.to_le_bytes().to_vec();
        payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
        payload.extend_from_slice(data);
        request(WRITE, id, &payload)
    }

    fn custody(op: u16, id: u64, generation: u64, digest: &[u8]) -> Vec<u8> {
        let mut payload = EPOCH.to_le_bytes().to_vec();
        payload.extend_from_slice(&generation.to_le_bytes());
        payload.extend_from_slice(&id.to_le_bytes());
        payload.extend_from_slice(digest);
        request(op, id, &payload)
    }

    fn v3_reply<'a>(wire: &'a [u8], id: u64, output: &[u8]) -> Reply<'a> {
        v3_reply_with_sequence(wire, id, output, 0)
    }

    fn v3_reply_with_sequence<'a>(
        wire: &'a [u8],
        id: u64,
        output: &[u8],
        write_seq: u64,
    ) -> Reply<'a> {
        let reply = Reply::decode(wire).unwrap();
        assert_eq!(reply.request_id, id);
        assert_eq!(reply.service_generation, EPOCH);
        assert_eq!(reply.target_generation, 1);
        assert_eq!(
            (reply.state, reply.result, reply.completed_prefix),
            (0, 0, 0)
        );
        assert_eq!((reply.commit_lsn, reply.log_epoch, reply.txid), (0, 0, 0));
        assert_eq!((reply.receipt_ref, reply.write_seq), (0, write_seq));
        assert_eq!(reply.output, output);
        let mut canonical = wire.to_vec();
        canonical[DIGEST_OFFSET..DIGEST_END].fill(0);
        let digest: [u8; 32] = Sha256::digest(canonical).into();
        assert_eq!(reply.result_digest, digest);
        reply
    }

    #[test]
    fn staged_file_requires_exact_initialized_fixture() {
        let staged = fixture(EPOCH);
        assert_eq!(staged.boot_epoch(), EPOCH);
        assert_eq!(staged.owner(), OWNER);
        assert_eq!(staged.owner_rights(), SCRATCH_FILE_OWNER_RIGHTS);
        assert_eq!(
            writable_fixture().owner_rights(),
            SCRATCH_WRITABLE_FILE_OWNER_RIGHTS
        );
        let digest: [u8; 32] = Sha256::digest(SCRATCH_FILE_DATA).into();
        assert_eq!(staged.content_digest(), digest);

        for offset in [0, 4, 6, 8, 16, 123, 124] {
            let mut dirent = fixture_dirent();
            dirent[offset] ^= 1;
            if offset != DIRENT_CRC {
                seal(&mut dirent);
            }
            assert_eq!(
                StagedFile::new(EPOCH, OWNER, dirent, *SCRATCH_FILE_DATA),
                Err(Error::Invalid),
                "dirent offset {offset}"
            );
        }
        let mut data = *SCRATCH_FILE_DATA;
        data[28] = 0;
        assert_eq!(
            StagedFile::new(EPOCH, OWNER, fixture_dirent(), data),
            Err(Error::Invalid)
        );
        assert_eq!(
            StagedFile::new(0, OWNER, fixture_dirent(), *SCRATCH_FILE_DATA),
            Err(Error::Invalid)
        );
        for rights in [
            0,
            SCRATCH_FILE_WRITE_RIGHTS,
            SCRATCH_WRITABLE_FILE_OWNER_RIGHTS | 1,
        ] {
            assert_eq!(
                StagedFile::new_with_owner_rights(
                    EPOCH,
                    OWNER,
                    fixture_dirent(),
                    *SCRATCH_FILE_DATA,
                    rights,
                ),
                Err(Error::Invalid)
            );
        }
    }

    #[test]
    fn file_read_v4_outputs_replay_and_close_fence() {
        let mut service = FileReadService::new(fixture(EPOCH));
        let mut wire = [0xa5; MAX_REPLY + 1];
        let list = request(READDIR, 1, &DIR_PAGE);
        let listed = service.serve(ROOT_SELECTOR, &list, &mut wire).unwrap();
        assert_eq!(
            listed,
            Served {
                len: MAX_REPLY,
                replay: false
            }
        );
        v3_reply(&wire[..listed.len], 1, &fixture_dirent());
        assert_eq!(wire[listed.len], 0xa5);

        let open_frame = open(2, b"readme.txt", 1 << 8);
        let opened = service
            .serve(ROOT_SELECTOR, &open_frame, &mut wire)
            .unwrap();
        let cap = v3_reply(&wire[..opened.len], 2, &[]).new_cap_selector;
        assert_ne!(cap, 0);
        assert_ne!(cap, ROOT_SELECTOR);
        assert_eq!(service.live_handles(), 1);
        assert_eq!(service.live_handle_selectors(), [cap, 0, 0, 0]);
        assert_rejected(
            &mut service,
            ROOT_SELECTOR,
            &open(6, SCRATCH_FILE_NAME, SCRATCH_FILE_OWNER_RIGHTS),
            MAX_REPLY,
            ReadError::Busy,
        );
        assert!(
            service
                .serve(ROOT_SELECTOR, &open_frame, &mut wire)
                .unwrap()
                .replay
        );

        let read_frame = read(3, 2, 65_536);
        wire.fill(0xa5);
        let read_result = service.serve(cap, &read_frame, &mut wire).unwrap();
        let original = wire;
        v3_reply(&wire[..read_result.len], 3, &SCRATCH_FILE_DATA[2..]);
        assert!(wire[read_result.len..].iter().all(|&byte| byte == 0xa5));
        assert_eq!(
            service.serve(cap, &read_frame, &mut wire),
            Ok(Served {
                replay: true,
                ..read_result
            })
        );
        assert_eq!(wire, original);
        assert_eq!(
            service.serve(ROOT_SELECTOR, &read_frame, &mut wire),
            Err(ReadError::Conflict)
        );
        assert_eq!(
            service.serve(cap, &read(3, 3, 65_536), &mut wire),
            Err(ReadError::Conflict)
        );

        let eof = service
            .serve(cap, &read(4, u64::MAX, 5), &mut wire)
            .unwrap();
        v3_reply(&wire[..eof.len], 4, &[]);
        let close = request(CLOSE, 5, &[0; 4]);
        let closed = service.serve(cap, &close, &mut wire).unwrap();
        v3_reply(&wire[..closed.len], 5, &[]);
        assert_eq!(service.live_handles(), 0);
        assert!(service.serve(cap, &close, &mut wire).unwrap().replay);
        let closed_wire = wire;
        assert_eq!(
            service.serve(cap, &read_frame, &mut wire),
            Err(ReadError::Stale)
        );
        assert_eq!(
            service.serve(ROOT_SELECTOR, &open_frame, &mut wire),
            Err(ReadError::Stale)
        );
        assert_eq!(
            service.serve(cap, &read(6, 0, 1), &mut wire),
            Err(ReadError::Stale)
        );
        assert_eq!(wire, closed_wire);

        let reopened = service
            .serve(ROOT_SELECTOR, &open(6, b"readme.txt", 1 << 8), &mut wire)
            .unwrap();
        let next_cap = v3_reply(&wire[..reopened.len], 6, &[]).new_cap_selector;
        assert_ne!(next_cap, cap);
        assert_eq!(
            service.serve(cap, &read(7, 0, 1), &mut wire),
            Err(ReadError::Stale)
        );
        assert!(service.serve(next_cap, &read(7, 0, 1), &mut wire).is_ok());

        let mut restarted = FileReadService::new(fixture(EPOCH + 1));
        assert!(
            restarted
                .serve(ROOT_SELECTOR, &open_frame, &mut wire)
                .is_ok()
        );
        assert_eq!(
            restarted.serve(cap, &read(3, 0, 1), &mut wire),
            Err(ReadError::Unauthorized)
        );
    }

    #[test]
    fn file_read_v4_failures_leave_reply_and_admission_unchanged() {
        let mut service = FileReadService::new(fixture(EPOCH));
        let mut wire = [0xa5; MAX_REPLY];
        let open_ok = open(1, b"readme.txt", 1 << 8);
        let mut invalid_len = open_ok.clone();
        invalid_len[12] ^= 1;
        for (selector, frame, error) in [
            (ROOT_SELECTOR, invalid_len, ReadError::Format),
            (
                ROOT_SELECTOR,
                open(1, b"forgot.txt", 1 << 8),
                ReadError::Unauthorized,
            ),
            (
                ROOT_SELECTOR,
                open(1, b"readme.txt", 3 << 8),
                ReadError::Unauthorized,
            ),
            (3, open_ok.clone(), ReadError::Unauthorized),
            (
                ROOT_SELECTOR,
                request(4, 1, &[0; 12]),
                ReadError::Unsupported,
            ),
            (ROOT_SELECTOR, read(1, 0, 1), ReadError::Unauthorized),
        ] {
            assert_eq!(service.serve(selector, &frame, &mut wire), Err(error));
        }
        assert_eq!(
            service.serve(ROOT_SELECTOR, &open_ok, &mut wire[..REPLY_HEADER - 1]),
            Err(ReadError::ShortReply)
        );
        assert_eq!(wire, [0xa5; MAX_REPLY]);

        let opened = service.serve(ROOT_SELECTOR, &open_ok, &mut wire).unwrap();
        assert!(!opened.replay);
        let cap = v3_reply(&wire[..opened.len], 1, &[]).new_cap_selector;
        let close_frame = request(CLOSE, 2, &[0; 4]);
        assert_eq!(
            service.serve(cap, &close_frame, &mut wire[..REPLY_HEADER - 1]),
            Err(ReadError::ShortReply)
        );
        assert!(service.serve(cap, &read(2, 0, 1), &mut wire).is_ok());
    }

    #[test]
    fn file_read_v4_acknowledgement_is_ordered_and_reuses_custody() {
        let mut service = FileReadService::new(fixture(EPOCH));
        let mut wire = [0; MAX_REPLY];
        let mut digests = [[0; 32]; GROUP_VOLATILE_SLOTS];
        for (n, digest) in digests.iter_mut().enumerate() {
            let id = (n + 1) as u64;
            let served = service
                .serve(ROOT_SELECTOR, &request(READDIR, id, &DIR_PAGE), &mut wire)
                .unwrap();
            *digest = v3_reply(&wire[..served.len], id, &fixture_dirent()).result_digest;
        }
        let queued = request(READDIR, 100, &[1, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(
            service.serve(ROOT_SELECTOR, &queued, &mut wire),
            Err(ReadError::Busy)
        );

        let query = custody(QUERY_VOLATILE, 1, EPOCH, &[]);
        let wrong_generation = custody(QUERY_VOLATILE, 1, EPOCH + 1, &[]);
        let ack = custody(ACK_VOLATILE, 1, EPOCH, &digests[0]);
        let wrong_digest = custody(ACK_VOLATILE, 1, EPOCH, &digests[1]);
        let late_ack = custody(ACK_VOLATILE, 2, EPOCH, &digests[1]);
        assert_eq!(
            service.serve(0, &wrong_generation, &mut wire),
            Err(ReadError::Stale)
        );
        assert_eq!(
            service.serve(0, &wrong_digest, &mut wire),
            Err(ReadError::Conflict)
        );
        assert_eq!(service.serve(0, &late_ack, &mut wire), Err(ReadError::Busy));
        assert_eq!(
            service.serve(0, &ack, &mut wire[..REPLY_HEADER - 1]),
            Err(ReadError::ShortReply)
        );

        for frame in [&query, &ack] {
            let result = service.serve(0, frame, &mut wire).unwrap();
            assert_eq!(
                result,
                Served {
                    len: REPLY_HEADER,
                    replay: false
                }
            );
            let reply = Reply::decode(&wire[..result.len]).unwrap();
            assert_eq!(
                (
                    reply.state,
                    reply.result,
                    reply.target_generation,
                    reply.new_cap_selector
                ),
                (0, 0, 0, 0)
            );
            assert_eq!(reply.result_digest, digests[0]);
            assert!(reply.output.is_empty());
        }
        assert_eq!(service.serve(0, &query, &mut wire), Err(ReadError::Stale));
        assert_eq!(service.serve(0, &ack, &mut wire), Err(ReadError::Stale));
        assert_eq!(
            service.serve(ROOT_SELECTOR, &request(READDIR, 1, &DIR_PAGE), &mut wire),
            Err(ReadError::Stale)
        );
        let served = service.serve(ROOT_SELECTOR, &queued, &mut wire).unwrap();
        v3_reply(&wire[..served.len], 100, &[]);
        assert!(service.serve(0, &late_ack, &mut wire).is_ok());
    }

    fn assert_rejected(
        service: &mut FileReadService,
        selector: u64,
        frame: &[u8],
        reply_capacity: usize,
        expected: ReadError,
    ) {
        let mut wire = [0xa5; MAX_REPLY];
        let live = service.live_handle_selectors();
        let retained = service.retained_count();
        let watermark = service.highest_id;
        let generation = service.open_generation;
        let file = service.file;
        let write_sequence = service.write_sequence();
        assert_eq!(
            service.serve(selector, frame, &mut wire[..reply_capacity]),
            Err(expected)
        );
        assert_eq!(wire, [0xa5; MAX_REPLY]);
        assert_eq!(service.live_handle_selectors(), live);
        assert_eq!(service.retained_count(), retained);
        assert_eq!(service.highest_id, watermark);
        assert_eq!(service.open_generation, generation);
        assert_eq!(service.file, file);
        assert_eq!(service.write_sequence(), write_sequence);
    }

    #[test]
    fn file_read_v4_multiple_handles_keep_replay_and_close_local_to_one_child() {
        let mut service = FileReadService::with_multiple_handles(fixture(EPOCH));
        let mut wire = [0xa5; MAX_REPLY];
        let mut selectors = [0; MAX_LIVE_HANDLES];
        let mut open_replies = [[0; REPLY_HEADER]; MAX_LIVE_HANDLES];
        for slot in 0..MAX_LIVE_HANDLES {
            let id = (slot + 1) as u64;
            let frame = open(id, SCRATCH_FILE_NAME, SCRATCH_FILE_OWNER_RIGHTS);
            assert_rejected(
                &mut service,
                ROOT_SELECTOR,
                &frame,
                REPLY_HEADER - 1,
                ReadError::ShortReply,
            );
            let served = service.serve(ROOT_SELECTOR, &frame, &mut wire).unwrap();
            assert!(!served.replay);
            let selector = v3_reply(&wire[..served.len], id, &[]).new_cap_selector;
            assert_ne!(selector, ROOT_SELECTOR);
            assert!(!selectors.contains(&selector));
            selectors[slot] = selector;
            open_replies[slot].copy_from_slice(&wire[..served.len]);
            assert_eq!(service.live_handle_selectors(), selectors);
            assert_eq!(service.live_handles(), slot + 1);
            assert_eq!(service.retained_count(), slot + 1);
        }

        let [first, closed, third, fourth] = selectors;
        for (slot, expected) in open_replies.iter().enumerate() {
            let id = (slot + 1) as u64;
            let frame = open(id, SCRATCH_FILE_NAME, SCRATCH_FILE_OWNER_RIGHTS);
            let served = service.serve(ROOT_SELECTOR, &frame, &mut wire).unwrap();
            assert!(served.replay);
            assert_eq!(&wire[..served.len], expected);
        }

        let read_closed = read(5, 1, 3);
        let served = service.serve(closed, &read_closed, &mut wire).unwrap();
        v3_reply(&wire[..served.len], 5, &SCRATCH_FILE_DATA[1..4]);
        let read_reply = wire;
        assert!(
            service
                .serve(closed, &read_closed, &mut wire)
                .unwrap()
                .replay
        );
        assert_eq!(wire, read_reply);

        let close = request(CLOSE, 6, &[0; 4]);
        let replacement = open(7, SCRATCH_FILE_NAME, SCRATCH_FILE_OWNER_RIGHTS);
        let never_issued = service.child_selector(5);
        let open_closed = open(2, SCRATCH_FILE_NAME, SCRATCH_FILE_OWNER_RIGHTS);
        for (selector, frame, error) in [
            (third, read_closed.clone(), ReadError::Conflict),
            (closed, read(5, 2, 3), ReadError::Conflict),
            (third, open_closed.clone(), ReadError::Conflict),
            (
                ROOT_SELECTOR,
                open(2, SCRATCH_FILE_NAME, 0),
                ReadError::Conflict,
            ),
            (closed, replacement.clone(), ReadError::Unauthorized),
            (
                ROOT_SELECTOR,
                open(6, SCRATCH_FILE_NAME, 0),
                ReadError::Unauthorized,
            ),
            (
                ROOT_SELECTOR,
                open(6, b"missing.txt", SCRATCH_FILE_OWNER_RIGHTS),
                ReadError::Unauthorized,
            ),
            (never_issued, read(6, 0, 1), ReadError::Unauthorized),
            (closed, request(CLOSE, 6, &[1, 0, 0, 0]), ReadError::Format),
            (ROOT_SELECTOR, replacement.clone(), ReadError::Busy),
        ] {
            assert_rejected(&mut service, selector, &frame, MAX_REPLY, error);
        }
        assert_rejected(
            &mut service,
            closed,
            &close,
            REPLY_HEADER - 1,
            ReadError::ShortReply,
        );
        let served = service.serve(closed, &close, &mut wire).unwrap();
        assert!(!served.replay);
        v3_reply(&wire[..served.len], 6, &[]);
        let close_reply = wire;
        assert!(service.serve(closed, &close, &mut wire).unwrap().replay);
        assert_eq!(wire, close_reply);
        assert_eq!(service.live_handles(), 3);
        assert_eq!(service.live_handle_selectors(), [first, 0, third, fourth]);

        assert_rejected(
            &mut service,
            ROOT_SELECTOR,
            &replacement,
            REPLY_HEADER - 1,
            ReadError::ShortReply,
        );
        let served = service
            .serve(ROOT_SELECTOR, &replacement, &mut wire)
            .unwrap();
        assert!(!served.replay);
        let opened = v3_reply(&wire[..served.len], 7, &[]).new_cap_selector;
        assert_eq!(opened, never_issued);
        assert!(!selectors.contains(&opened));
        assert_eq!(
            service.live_handle_selectors(),
            [first, opened, third, fourth]
        );

        for (selector, frame) in [
            (ROOT_SELECTOR, open_closed),
            (closed, read_closed),
            (closed, read(8, 0, 1)),
            (closed, request(CLOSE, 8, &[0; 4])),
        ] {
            assert_rejected(&mut service, selector, &frame, MAX_REPLY, ReadError::Stale);
        }
        let sibling = service.serve(third, &read(8, 2, 3), &mut wire).unwrap();
        v3_reply(&wire[..sibling.len], 8, &SCRATCH_FILE_DATA[2..5]);
        assert_eq!(service.live_handles(), MAX_LIVE_HANDLES);
        assert_eq!(service.retained_count(), GROUP_VOLATILE_SLOTS);
    }

    #[test]
    fn file_read_v4_full_custody_keeps_open_and_close_pending() {
        let mut service = FileReadService::with_multiple_handles(fixture(EPOCH));
        let mut wire = [0; MAX_REPLY];
        let original = open(1, SCRATCH_FILE_NAME, SCRATCH_FILE_OWNER_RIGHTS);
        let served = service.serve(ROOT_SELECTOR, &original, &mut wire).unwrap();
        let reply = v3_reply(&wire[..served.len], 1, &[]);
        let selector = reply.new_cap_selector;
        let first_ack = custody(ACK_VOLATILE, 1, EPOCH, &reply.result_digest);
        let served = service.serve(selector, &read(2, 0, 1), &mut wire).unwrap();
        let second_ack = custody(
            ACK_VOLATILE,
            2,
            EPOCH,
            &v3_reply(&wire[..served.len], 2, &SCRATCH_FILE_DATA[..1]).result_digest,
        );
        for id in 3..=GROUP_VOLATILE_SLOTS as u64 {
            service
                .serve(ROOT_SELECTOR, &request(READDIR, id, &DIR_PAGE), &mut wire)
                .unwrap();
        }
        assert_eq!(service.live_handles(), 1);
        assert_eq!(service.retained_count(), GROUP_VOLATILE_SLOTS);

        let close_id = GROUP_VOLATILE_SLOTS as u64 + 1;
        let close = request(CLOSE, close_id, &[0; 4]);
        let open_id = close_id + 1;
        let next = open(open_id, SCRATCH_FILE_NAME, SCRATCH_FILE_OWNER_RIGHTS);
        for (selector, frame) in [(selector, &close), (ROOT_SELECTOR, &next), (0, &second_ack)] {
            assert_rejected(&mut service, selector, frame, MAX_REPLY, ReadError::Busy);
        }
        assert!(
            service
                .serve(ROOT_SELECTOR, &original, &mut wire)
                .unwrap()
                .replay
        );
        service.serve(0, &first_ack, &mut wire).unwrap();
        assert_eq!(service.live_handles(), 1);
        assert_eq!(service.retained_count(), GROUP_VOLATILE_SLOTS - 1);
        let served = service.serve(selector, &close, &mut wire).unwrap();
        v3_reply(&wire[..served.len], close_id, &[]);
        assert_eq!(service.live_handles(), 0);
        assert_eq!(service.retained_count(), GROUP_VOLATILE_SLOTS);

        service.serve(0, &second_ack, &mut wire).unwrap();
        let served = service.serve(ROOT_SELECTOR, &next, &mut wire).unwrap();
        let new_selector = v3_reply(&wire[..served.len], open_id, &[]).new_cap_selector;
        assert_ne!(new_selector, selector);
        assert_eq!(new_selector, service.child_selector(2));
        assert_eq!(service.live_handle_selectors(), [new_selector, 0, 0, 0]);
        assert_eq!(service.retained_count(), GROUP_VOLATILE_SLOTS);
    }

    #[test]
    fn file_write_v4_checks_child_rights_and_replays_without_reapplying() {
        let mut service = FileReadService::with_multiple_handles(writable_fixture());
        let mut wire = [0; MAX_REPLY];
        let opened = service
            .serve(
                ROOT_SELECTOR,
                &open(1, SCRATCH_FILE_NAME, SCRATCH_FILE_WRITE_RIGHTS),
                &mut wire,
            )
            .unwrap();
        let writer = v3_reply(&wire[..opened.len], 1, &[]).new_cap_selector;
        let opened = service
            .serve(
                ROOT_SELECTOR,
                &open(2, SCRATCH_FILE_NAME, SCRATCH_FILE_OWNER_RIGHTS),
                &mut wire,
            )
            .unwrap();
        let reader = v3_reply(&wire[..opened.len], 2, &[]).new_cap_selector;

        let end = SCRATCH_FILE_DATA.len();
        let offset = (end - 3) as u64;
        let first = write(4, offset, b"xyz");
        for (selector, frame, capacity, error) in [
            (
                ROOT_SELECTOR,
                first.clone(),
                MAX_REPLY,
                ReadError::Unauthorized,
            ),
            (reader, first.clone(), MAX_REPLY, ReadError::Unauthorized),
            (writer, read(3, 0, 1), MAX_REPLY, ReadError::Unauthorized),
            (
                writer,
                write(3, end as u64, b"x"),
                MAX_REPLY,
                ReadError::Format,
            ),
            (
                writer,
                write(3, u64::MAX, b"x"),
                MAX_REPLY,
                ReadError::Format,
            ),
            (
                writer,
                first.clone(),
                REPLY_HEADER - 1,
                ReadError::ShortReply,
            ),
        ] {
            assert_rejected(&mut service, selector, &frame, capacity, error);
        }
        let served = service
            .serve(reader, &read(3, offset, 3), &mut wire)
            .unwrap();
        v3_reply(&wire[..served.len], 3, &SCRATCH_FILE_DATA[end - 3..]);
        assert_eq!(service.write_sequence(), 0);

        let served = service.serve(writer, &first, &mut wire).unwrap();
        assert!(!served.replay);
        let written = v3_reply_with_sequence(&wire[..served.len], 4, &[], 1);
        assert_eq!(written.new_cap_selector, 0);
        let original = wire[..served.len].to_vec();
        let served = service
            .serve(reader, &read(5, offset, 3), &mut wire)
            .unwrap();
        v3_reply(&wire[..served.len], 5, b"xyz");

        let served = service
            .serve(writer, &write(6, offset + 1, b"UV"), &mut wire)
            .unwrap();
        v3_reply_with_sequence(&wire[..served.len], 6, &[], 2);
        for (selector, frame, capacity, error) in [
            (reader, first.clone(), MAX_REPLY, ReadError::Conflict),
            (
                writer,
                write(4, offset, b"ABC"),
                MAX_REPLY,
                ReadError::Conflict,
            ),
            (
                writer,
                first.clone(),
                REPLY_HEADER - 1,
                ReadError::ShortReply,
            ),
        ] {
            assert_rejected(&mut service, selector, &frame, capacity, error);
        }
        let served = service.serve(writer, &first, &mut wire).unwrap();
        assert!(served.replay);
        assert_eq!(&wire[..served.len], original);
        assert_eq!(service.write_sequence(), 2);

        let served = service
            .serve(reader, &read(7, 0, end as u32), &mut wire)
            .unwrap();
        let mut expected = *SCRATCH_FILE_DATA;
        expected[end - 3..].copy_from_slice(b"xUV");
        v3_reply(&wire[..served.len], 7, &expected);

        let close = request(CLOSE, 8, &[0; 4]);
        assert!(service.serve(writer, &close, &mut wire).is_ok());
        for frame in [first, write(9, offset, b"p")] {
            assert_rejected(&mut service, writer, &frame, MAX_REPLY, ReadError::Stale);
        }
    }

    #[test]
    fn file_write_v4_full_custody_keeps_write_pending() {
        let mut service = FileReadService::new(writable_fixture());
        let mut wire = [0; MAX_REPLY];
        let opened = service
            .serve(
                ROOT_SELECTOR,
                &open(1, SCRATCH_FILE_NAME, SCRATCH_WRITABLE_FILE_OWNER_RIGHTS),
                &mut wire,
            )
            .unwrap();
        let reply = v3_reply(&wire[..opened.len], 1, &[]);
        let child = reply.new_cap_selector;
        let ack = custody(ACK_VOLATILE, 1, EPOCH, &reply.result_digest);
        for id in 2..=GROUP_VOLATILE_SLOTS as u64 {
            service.serve(child, &read(id, 0, 1), &mut wire).unwrap();
        }

        let id = GROUP_VOLATILE_SLOTS as u64 + 1;
        let frame = write(id, 0, b"X");
        assert_rejected(&mut service, child, &frame, MAX_REPLY, ReadError::Busy);
        service.serve(0, &ack, &mut wire).unwrap();
        assert_rejected(
            &mut service,
            child,
            &frame,
            REPLY_HEADER - 1,
            ReadError::ShortReply,
        );
        let served = service.serve(child, &frame, &mut wire).unwrap();
        assert!(!served.replay);
        v3_reply_with_sequence(&wire[..served.len], id, &[], 1);
        assert_eq!(service.write_sequence(), 1);
        assert_eq!(service.retained_count(), GROUP_VOLATILE_SLOTS);
    }
}
