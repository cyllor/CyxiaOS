//! Strict bounded RX/RO ELF loader plan for the isolated control service.
//! No relocations, dynamic loader, TLS, writable ELF segments or page aliases.
//! Caller copies the approved bytes and maps per-page permissions exactly.
use super::Error;
pub const BASE: u64 = 0x80000;
pub const PAGES: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Segment {
    pub offset: usize,
    pub address: u64,
    pub file_size: usize,
    pub memory_size: usize,
    pub executable: bool,
}
pub struct Image<'a> {
    pub entry: u64,
    pub segments: [Segment; 8],
    pub count: usize,
    pub bytes: &'a [u8],
}
fn get<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    b.get(at..at.checked_add(N).ok_or(Error::Invalid)?)
        .ok_or(Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)
}
fn u16at(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(get(b, at)?))
}
fn u32at(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(get(b, at)?))
}
fn u64at(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(get(b, at)?))
}
impl<'a> Image<'a> {
    pub fn parse(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() > 512 * 1024
            || get::<7>(b, 0)? != *b"\x7fELF\x02\x01\x01"
            || u16at(b, 16)? != 2
            || u16at(b, 18)? != 183
            || u32at(b, 20)? != 1
            || u16at(b, 52)? != 64
            || u16at(b, 54)? != 56
        {
            return Err(Error::Invalid);
        }
        let entry = u64at(b, 24)?;
        let ph = usize::try_from(u64at(b, 32)?).map_err(|_| Error::Invalid)?;
        let count = u16at(b, 56)? as usize;
        if count == 0 || count > 8 {
            return Err(Error::Invalid);
        }
        let mut result = Self {
            entry,
            segments: [Segment::default(); 8],
            count: 0,
            bytes: b,
        };
        let mut seen = 0u64;
        let mut found = false;
        for i in 0..count {
            let at = ph.checked_add(i * 56).ok_or(Error::Invalid)?;
            get::<56>(b, at)?;
            match u32at(b, at)? {
                0 | 4 | 6 | 0x6474e551 => continue,
                1 => {}
                _ => return Err(Error::Denied),
            }
            let flags = u32at(b, at + 4)?;
            let address = u64at(b, at + 16)?;
            let offset = usize::try_from(u64at(b, at + 8)?).map_err(|_| Error::Invalid)?;
            let file_size = usize::try_from(u64at(b, at + 32)?).map_err(|_| Error::Invalid)?;
            let memory_size = usize::try_from(u64at(b, at + 40)?).map_err(|_| Error::Invalid)?;
            let align = u64at(b, at + 48)?;
            let end = address
                .checked_add(memory_size as u64)
                .ok_or(Error::Invalid)?;
            if !matches!(flags, 4 | 5)
                || file_size > memory_size
                || memory_size == 0
                || address < BASE
                || end > BASE + PAGES as u64 * 4096
                || !address.is_multiple_of(4096)
                || !offset.is_multiple_of(4096)
                || align != 4096
                || b.get(offset..offset.checked_add(file_size).ok_or(Error::Invalid)?)
                    .is_none()
            {
                return Err(Error::Invalid);
            }
            let first = (address - BASE) / 4096;
            let last = (end - BASE).div_ceil(4096);
            for page in first..last {
                if seen & (1 << page) != 0 {
                    return Err(Error::Denied);
                }
                seen |= 1 << page;
            }
            found |= flags == 5
                && entry >= address
                && entry < address + file_size as u64
                && entry.is_multiple_of(4);
            result.segments[result.count] = Segment {
                offset,
                address,
                file_size,
                memory_size,
                executable: flags == 5,
            };
            result.count += 1;
        }
        if !found {
            return Err(Error::Invalid);
        }
        Ok(result)
    }
}
