//! Dedicated-disk two-slot snapshot wire format, independent of RAMFS layout.
//! CRC detects accidental corruption, not malicious modification. Publication
//! requires completed payload writes + FLUSH + header write + FLUSH.
use crate::block::SECTOR_BYTES;

pub const SLOT_SECTORS: u64 = 768;
pub const REQUIRED_SECTORS: u64 = 2 * SLOT_SECTORS;
pub const MAX_PAYLOAD: usize = (SLOT_SECTORS as usize - 1) * SECTOR_BYTES;
const MAGIC: &[u8; 8] = b"CYXSNAP1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Format,
    Length,
    Checksum,
    Exhausted,
    State,
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub generation: u64,
    pub length: usize,
    pub payload_crc: u32,
}
impl Header {
    pub fn new(generation: u64, payload: &[u8]) -> Result<Self, Error> {
        if generation == 0 {
            return Err(Error::Exhausted);
        }
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(Error::Length);
        }
        Ok(Self {
            generation,
            length: payload.len(),
            payload_crc: crc32(payload),
        })
    }
    pub fn encode(self) -> [u8; SECTOR_BYTES] {
        let mut bytes = [0; SECTOR_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(SECTOR_BYTES as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.generation.to_le_bytes());
        bytes[24..28].copy_from_slice(&(self.length as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&self.payload_crc.to_le_bytes());
        let checksum = crc32(&bytes[..508]);
        bytes[508..].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8; SECTOR_BYTES]) -> Result<Self, Error> {
        if &bytes[..8] != MAGIC
            || bytes[8..12] != 1u32.to_le_bytes()
            || bytes[12..16] != (SECTOR_BYTES as u32).to_le_bytes()
            || bytes[32..508].iter().any(|b| *b != 0)
        {
            return Err(Error::Format);
        }
        if crc32(&bytes[..508]) != u32::from_le_bytes(bytes[508..].try_into().unwrap()) {
            return Err(Error::Checksum);
        }
        let header = Self {
            generation: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            length: u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize,
            payload_crc: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
        };
        if header.generation == 0 || header.length == 0 || header.length > MAX_PAYLOAD {
            return Err(Error::Length);
        }
        Ok(header)
    }
    pub fn verify(self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() != self.length {
            return Err(Error::Length);
        }
        if crc32(payload) != self.payload_crc {
            return Err(Error::Checksum);
        }
        Ok(())
    }
}

/// Only fully payload-validated candidates may establish the current slot.
/// A corrupt new slot must not hide an older, intact committed snapshot.
pub fn preferred(headers: [Option<Header>; 2]) -> Option<usize> {
    match headers {
        [None, None] => None,
        [Some(_), None] => Some(0),
        [None, Some(_)] => Some(1),
        [Some(a), Some(b)] => Some(usize::from(b.generation > a.generation)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Payload { sector: u64, offset: usize },
    PayloadFlush,
    Header { sector: u64 },
    HeaderFlush,
    Done,
}

pub struct Commit {
    pub slot: usize,
    pub header: Header,
    completed: usize,
}
impl Commit {
    pub fn new(current: Option<(usize, Header)>, payload: &[u8]) -> Result<Self, Error> {
        if current.is_some_and(|(slot, _)| slot > 1) {
            return Err(Error::State);
        }
        let (slot, generation) = match current {
            None => (0, 1),
            Some((slot, header)) => (
                slot ^ 1,
                header.generation.checked_add(1).ok_or(Error::Exhausted)?,
            ),
        };
        Ok(Self {
            slot,
            header: Header::new(generation, payload)?,
            completed: 0,
        })
    }
    pub fn step(&self) -> Step {
        let count = self.header.length.div_ceil(SECTOR_BYTES);
        let base = self.slot as u64 * SLOT_SECTORS;
        match self.completed {
            n if n < count => Step::Payload {
                sector: base + 1 + n as u64,
                offset: n * SECTOR_BYTES,
            },
            n if n == count => Step::PayloadFlush,
            n if n == count + 1 => Step::Header { sector: base },
            n if n == count + 2 => Step::HeaderFlush,
            _ => Step::Done,
        }
    }
    /// Call only after the matching real device completion was checked.
    pub fn complete(&mut self, step: Step) -> Result<(), Error> {
        if self.step() != step || step == Step::Done {
            return Err(Error::State);
        }
        self.completed += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};

    fn recover(disk: &[u8]) -> Option<(usize, Header, Vec<u8>)> {
        let mut headers = [None; 2];
        for (slot, h) in headers.iter_mut().enumerate() {
            let at = slot * SLOT_SECTORS as usize * 512;
            *h = Header::decode(disk[at..at + 512].try_into().unwrap()).ok();
            if h.is_some_and(|header| {
                header
                    .verify(&disk[at + 512..at + 512 + header.length])
                    .is_err()
            }) {
                *h = None;
            }
        }
        let slot = preferred(headers)?;
        let h = headers[slot]?;
        let at = (slot * SLOT_SECTORS as usize + 1) * 512;
        Some((slot, h, disk[at..at + h.length].to_vec()))
    }
    fn apply(c: &mut Commit, data: &[u8], volatile: &mut [u8], stable: &mut [u8]) {
        let step = c.step();
        match step {
            Step::Payload { sector, offset } => {
                let n = (data.len() - offset).min(512);
                let at = sector as usize * 512;
                volatile[at..at + 512].fill(0);
                volatile[at..at + n].copy_from_slice(&data[offset..offset + n]);
            }
            Step::Header { sector } => volatile[sector as usize * 512..(sector as usize + 1) * 512]
                .copy_from_slice(&c.header.encode()),
            Step::PayloadFlush | Step::HeaderFlush => stable.copy_from_slice(volatile),
            Step::Done => panic!("completed transaction"),
        }
        c.complete(step).unwrap();
    }
    #[test]
    fn every_crash_point_retains_last_durable_snapshot() {
        let mut old = vec![0; REQUIRED_SECTORS as usize * 512];
        let mut volatile = old.clone();
        let first = vec![0x31; 777];
        let mut c = Commit::new(None, &first).unwrap();
        while c.step() != Step::Done {
            apply(&mut c, &first, &mut volatile, &mut old);
        }
        let current = (c.slot, c.header);
        let next = vec![0xab; 1301];
        for crash_after in 0..=6 {
            let mut stable = old.clone();
            let mut volatile = stable.clone();
            let mut c = Commit::new(Some(current), &next).unwrap();
            for _ in 0..crash_after {
                apply(&mut c, &next, &mut volatile, &mut stable);
            }
            let (_, h, data) = recover(&stable).unwrap();
            assert_eq!(
                data,
                if crash_after == 6 {
                    next.clone()
                } else {
                    first.clone()
                }
            );
            assert_eq!(h.generation, if crash_after == 6 { 2 } else { 1 });
        }
    }
    #[test]
    fn corrupt_new_payload_or_torn_header_falls_back_and_overflow_fails() {
        let mut stable = vec![0; REQUIRED_SECTORS as usize * 512];
        let mut volatile = stable.clone();
        let first = [0x41; 777];
        let second = [0x42; 888];
        let mut c = Commit::new(None, &first).unwrap();
        while c.step() != Step::Done {
            apply(&mut c, &first, &mut volatile, &mut stable);
        }
        let mut c = Commit::new(Some((c.slot, c.header)), &second).unwrap();
        while c.step() != Step::Done {
            apply(&mut c, &second, &mut volatile, &mut stable);
        }
        let valid = stable.clone();
        stable[(SLOT_SECTORS as usize + 1) * 512 + 12] ^= 1;
        assert_eq!(recover(&stable).unwrap().2, first);
        stable.copy_from_slice(&valid);
        stable[SLOT_SECTORS as usize * 512 + 18] ^= 1;
        assert_eq!(recover(&stable).unwrap().2, first);
        let mut h = Header::new(u64::MAX, &first).unwrap();
        assert!(matches!(
            Commit::new(Some((0, h)), &first),
            Err(Error::Exhausted)
        ));
        h.length = MAX_PAYLOAD + 1;
        assert_eq!(Header::decode(&h.encode()), Err(Error::Length));
    }
    #[test]
    fn checksum_and_completion_order_are_strict() {
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        let mut c = Commit::new(None, b"hello").unwrap();
        assert_eq!(c.complete(Step::HeaderFlush), Err(Error::State));
        assert!(matches!(c.step(), Step::Payload { .. }));
    }
}
