//! Strict static AArch64 ELF loader. No interpreter, relocations, W+X or arbitrary mapping.
use crate::{
    Errno,
    usermem::{Arena, BASE, CODE_BYTES, DATA_BYTES},
};
fn u16_at(b: &[u8], i: usize) -> Result<u16, Errno> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2)
            .ok_or(Errno::Inval)?
            .try_into()
            .map_err(|_| Errno::Inval)?,
    ))
}
fn u32_at(b: &[u8], i: usize) -> Result<u32, Errno> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4)
            .ok_or(Errno::Inval)?
            .try_into()
            .map_err(|_| Errno::Inval)?,
    ))
}
fn u64_at(b: &[u8], i: usize) -> Result<u64, Errno> {
    Ok(u64::from_le_bytes(
        b.get(i..i + 8)
            .ok_or(Errno::Inval)?
            .try_into()
            .map_err(|_| Errno::Inval)?,
    ))
}
#[derive(Clone, Copy)]
struct Segment {
    va: u64,
    offset: usize,
    files: usize,
    size: usize,
}
pub fn load(elf: &[u8], arena: &mut Arena) -> Result<u64, Errno> {
    if elf.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16_at(elf, 16)? != 2
        || u16_at(elf, 18)? != 183
        || u32_at(elf, 20)? != 1
        || u16_at(elf, 52)? != 64
        || u16_at(elf, 54)? != 56
    {
        return Err(Errno::Inval);
    }
    let entry = u64_at(elf, 24)?;
    let ph = usize::try_from(u64_at(elf, 32)?).map_err(|_| Errno::Inval)?;
    if u16_at(elf, 56)? != 2 || ph.checked_add(112).is_none_or(|end| end > elf.len()) {
        return Err(Errno::Inval);
    }
    let mut segments = [None; 2];
    for i in 0..2 {
        let p = ph + i * 56;
        if u32_at(elf, p)? != 1 {
            return Err(Errno::Inval);
        }
        let flags = u32_at(elf, p + 4)?;
        let va = u64_at(elf, p + 16)?;
        let offset = usize::try_from(u64_at(elf, p + 8)?).map_err(|_| Errno::Inval)?;
        let files = usize::try_from(u64_at(elf, p + 32)?).map_err(|_| Errno::Inval)?;
        let size = usize::try_from(u64_at(elf, p + 40)?).map_err(|_| Errno::Inval)?;
        let align = u64_at(elf, p + 48)?;
        let (slot, start, end) = match flags {
            5 => (0, BASE, BASE + CODE_BYTES as u64),
            6 => (
                1,
                BASE + CODE_BYTES as u64,
                BASE + (CODE_BYTES + DATA_BYTES) as u64,
            ),
            _ => return Err(Errno::Inval),
        };
        if segments[slot].is_some()
            || size == 0
            || files > size
            || va < start
            || va.checked_add(size as u64).is_none_or(|v| v > end)
            || offset.checked_add(files).is_none_or(|v| v > elf.len())
            || align != 4096
            || va % 4096 != offset as u64 % 4096
        {
            return Err(Errno::Inval);
        }
        segments[slot] = Some(Segment {
            va,
            offset,
            files,
            size,
        });
    }
    let code = segments[0].ok_or(Errno::Inval)?;
    if !entry.is_multiple_of(4) || entry < code.va || entry >= code.va + code.files as u64 {
        return Err(Errno::Inval);
    }
    arena.clear();
    for s in segments.into_iter().flatten() {
        debug_assert!(s.files <= s.size);
        arena.load_segment(s.va, &elf[s.offset..s.offset + s.files])?;
    }
    Ok(entry)
}
