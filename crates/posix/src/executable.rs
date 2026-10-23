//! Validated static AArch64 ELF plans and bounded AArch64 process entry stacks.
//! No memory is published here. The caller owns AI admission, physical allocation,
//! zeroing, privileged copies, final PTE permissions, TLS setup and entropy.
//! This format does not select a syscall personality or imply Linux compatibility.
//! Format references: <https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst>
//! and <https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html>.

pub const IMAGE_BASE: u64 = 0x0100_0000;
pub const IMAGE_END: u64 = 0x0200_0000;
pub const PAGE_SIZE: u64 = 4096;
pub const MAX_LOADS: usize = 16;
pub const MAX_HEADERS: usize = 64;
pub const MAX_ARGUMENTS: usize = 32;
pub const MAX_ENVIRONMENT: usize = 32;
pub const MAX_STRING_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unsupported,
    Bounds,
    Alignment,
    Permissions,
    Overlap,
    Entry,
    Headers,
    Tls,
    Limit,
    Stack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct LoadSegment<'a> {
    pub address: u64,
    pub file_offset: u64,
    pub data: &'a [u8],
    pub memory_size: u64,
    pub permissions: Permissions,
}

#[derive(Clone, Copy, Debug)]
pub struct TlsTemplate<'a> {
    pub address: u64,
    pub data: &'a [u8],
    pub memory_size: u64,
    pub alignment: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    pub address: u64,
    pub permissions: Permissions,
}

#[derive(Debug)]
pub struct Plan<'a> {
    pub entry: u64,
    pub phdr_address: u64,
    pub phnum: u16,
    pub relro: Option<Region>,
    pub stack_size_hint: u64,
    segments: [Option<LoadSegment<'a>>; MAX_LOADS],
    tls: Option<TlsTemplate<'a>>,
    headers: &'a [u8],
}

impl<'a> Plan<'a> {
    pub fn loads(&self) -> impl Iterator<Item = &LoadSegment<'a>> {
        self.segments.iter().flatten()
    }

    pub fn tls(&self) -> Option<TlsTemplate<'a>> {
        self.tls
    }

    pub fn program_headers(&self) -> &'a [u8] {
        self.headers
    }

    pub fn pages(&self) -> impl Iterator<Item = Page> + '_ {
        (IMAGE_BASE..IMAGE_END)
            .step_by(PAGE_SIZE as usize)
            .filter_map(|address| {
                self.loads()
                    .find(|load| {
                        address < load.address + load.memory_size
                            && address + PAGE_SIZE > load.address
                    })
                    .map(|load| Page {
                        address,
                        permissions: load.permissions,
                    })
            })
    }
}

fn number<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], Error> {
    bytes
        .get(at..at.checked_add(N).ok_or(Error::Bounds)?)
        .ok_or(Error::Bounds)?
        .try_into()
        .map_err(|_| Error::Bounds)
}
fn word(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(number(bytes, at)?))
}
fn wide(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(number(bytes, at)?))
}
fn file_range(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8], Error> {
    let end = offset.checked_add(size).ok_or(Error::Bounds)?;
    let start = usize::try_from(offset).map_err(|_| Error::Bounds)?;
    let end = usize::try_from(end).map_err(|_| Error::Bounds)?;
    bytes.get(start..end).ok_or(Error::Bounds)
}
#[derive(Clone, Copy)]
struct Header {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    files: u64,
    memory: u64,
    alignment: u64,
}
impl Header {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            kind: word(bytes, 0)?,
            flags: word(bytes, 4)?,
            offset: wide(bytes, 8)?,
            address: wide(bytes, 16)?,
            files: wide(bytes, 32)?,
            memory: wide(bytes, 40)?,
            alignment: wide(bytes, 48)?,
        })
    }
    fn aligned(self) -> bool {
        self.alignment <= 1
            || (self.alignment.is_power_of_two()
                && self.address % self.alignment == self.offset % self.alignment)
    }
}

fn covered(load: &LoadSegment<'_>, address: u64, size: u64) -> bool {
    address >= load.address
        && address
            .checked_add(size)
            .is_some_and(|end| end <= load.address + load.memory_size)
}

fn file_matches(load: &LoadSegment<'_>, header: Header) -> bool {
    covered(load, header.address, header.memory)
        && header.address - load.address <= load.data.len() as u64
        && header.files <= load.data.len() as u64 - (header.address - load.address)
        && load.file_offset + (header.address - load.address) == header.offset
}

fn validate_notes(bytes: &[u8]) -> Result<(), Error> {
    let mut at = 0usize;
    while at < bytes.len() {
        let names = word(bytes, at)? as usize;
        let descriptions = word(bytes, at + 4)? as usize;
        let kind = word(bytes, at + 8)?;
        let name_at = at.checked_add(12).ok_or(Error::Bounds)?;
        let name_end = name_at.checked_add(names).ok_or(Error::Bounds)?;
        let name = bytes.get(name_at..name_end).ok_or(Error::Bounds)?;
        // GNU properties can require BTI/PAC or other loader work. Reject them
        // until those semantics exist, even when carried only inside PT_NOTE.
        if kind == 5 && name == b"GNU\0" {
            return Err(Error::Unsupported);
        }
        let padded_name = name_end.checked_add(3).ok_or(Error::Bounds)? & !3;
        at = padded_name
            .checked_add(descriptions)
            .and_then(|end| end.checked_add(3))
            .ok_or(Error::Bounds)?
            & !3;
        if at > bytes.len() {
            return Err(Error::Bounds);
        }
    }
    Ok(())
}

/// Preflight the complete executable without touching caller-owned memory.
///
/// ELF headers must be file-backed by a readable LOAD for truthful AT_PHDR.
/// Different LOADs may not share a page, even with identical flags: this keeps
/// BSS zeroing and final permissions unambiguous. The caller must start each page
/// zeroed, copy `data`, then publish `pages()` permissions. RELRO is returned as
/// metadata for the caller's post-relocation protection step; parsing does not
/// claim it has already been enforced.
pub fn parse(elf: &[u8]) -> Result<Plan<'_>, Error> {
    if elf.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || !matches!(elf.get(7), Some(0 | 3))
        || elf.get(8) != Some(&0)
        || elf
            .get(9..16)
            .is_none_or(|padding| padding.iter().any(|&b| b != 0))
        || u16::from_le_bytes(number(elf, 16)?) != 2
        || u16::from_le_bytes(number(elf, 18)?) != 183
        || word(elf, 20)? != 1
        || word(elf, 48)? != 0
        || u16::from_le_bytes(number(elf, 52)?) != 64
        || u16::from_le_bytes(number(elf, 54)?) != 56
    {
        return Err(Error::Invalid);
    }
    let entry = wide(elf, 24)?;
    let offset = wide(elf, 32)?;
    let phnum = u16::from_le_bytes(number(elf, 56)?);
    if phnum == 0 || usize::from(phnum) > MAX_HEADERS || offset < 64 || offset % 8 != 0 {
        return Err(Error::Headers);
    }
    let headers = file_range(elf, offset, u64::from(phnum) * 56)?;
    let mut plan = Plan {
        entry,
        phdr_address: 0,
        phnum,
        relro: None,
        stack_size_hint: 0,
        segments: [None; MAX_LOADS],
        tls: None,
        headers,
    };
    let mut count = 0;
    let mut phdr = None;
    let mut tls = None;
    let mut relro = None;
    let mut stack_seen = false;
    let mut unwind = None;
    for raw in headers.chunks_exact(56) {
        let h = Header::parse(raw)?;
        match h.kind {
            0 => {}
            1 => {
                if count == MAX_LOADS {
                    return Err(Error::Limit);
                }
                if !matches!(h.flags, 4..=6) {
                    return Err(Error::Permissions);
                }
                if !h.aligned() || h.address % PAGE_SIZE != h.offset % PAGE_SIZE {
                    return Err(Error::Alignment);
                }
                let end = h.address.checked_add(h.memory).ok_or(Error::Bounds)?;
                if h.memory == 0 || h.files > h.memory || h.address < IMAGE_BASE || end > IMAGE_END
                {
                    return Err(Error::Bounds);
                }
                let page_start = h.address & !(PAGE_SIZE - 1);
                let page_end = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                for load in plan.loads() {
                    let old_start = load.address & !(PAGE_SIZE - 1);
                    let old_end =
                        (load.address + load.memory_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                    if page_start < old_end && old_start < page_end {
                        return Err(Error::Overlap);
                    }
                }
                plan.segments[count] = Some(LoadSegment {
                    address: h.address,
                    file_offset: h.offset,
                    data: file_range(elf, h.offset, h.files)?,
                    memory_size: h.memory,
                    permissions: Permissions {
                        read: true,
                        write: h.flags & 2 != 0,
                        execute: h.flags & 1 != 0,
                    },
                });
                count += 1;
            }
            4 => validate_notes(file_range(elf, h.offset, h.files)?)?,
            6 => {
                if phdr.replace(h).is_some() {
                    return Err(Error::Headers);
                }
            }
            7 => {
                if tls.replace(h).is_some() {
                    return Err(Error::Tls);
                }
            }
            0x6474_e550 => {
                if unwind.replace(h).is_some() {
                    return Err(Error::Headers);
                }
            }
            0x6474_e551 => {
                if stack_seen || h.flags & !6 != 0 || h.files != 0 || !h.aligned() {
                    return Err(Error::Permissions);
                }
                stack_seen = true;
                plan.stack_size_hint = h.memory;
            }
            0x6474_e552 => {
                if relro.replace(h).is_some() {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Unsupported),
        }
    }
    if !entry.is_multiple_of(4)
        || !plan.loads().any(|load| {
            load.permissions.execute
                && entry >= load.address
                && entry
                    .checked_add(4)
                    .is_some_and(|end| end <= load.address + load.data.len() as u64)
        })
    {
        return Err(Error::Entry);
    }
    let phdr_address = plan
        .loads()
        .find_map(|load| {
            let delta = offset.checked_sub(load.file_offset)?;
            (delta.checked_add(headers.len() as u64)? <= load.data.len() as u64)
                .then_some(load.address + delta)
        })
        .ok_or(Error::Headers)?;
    plan.phdr_address = phdr_address;
    if let Some(h) = phdr
        && (h.flags != 4
            || !h.aligned()
            || h.offset != offset
            || h.address != plan.phdr_address
            || h.files != headers.len() as u64
            || h.memory != h.files)
    {
        return Err(Error::Headers);
    }
    if let Some(h) = tls {
        if !matches!(h.flags, 4 | 6)
            || h.files > h.memory
            || h.memory > IMAGE_END - IMAGE_BASE
            || !h.aligned()
            || !(IMAGE_BASE..IMAGE_END).contains(&h.address)
            || h.address.checked_add(h.memory).is_none_or(|end| end > IMAGE_END)
            // A zero-file-size TLS block is entirely .tbss; LLD may describe
            // it in alignment padding outside LOAD memory. libc zeroes each
            // thread's private block and must never read these template bytes.
            || (h.files != 0 && !plan.loads().any(|load| file_matches(load, Header { memory: h.files, ..h })))
        {
            return Err(Error::Tls);
        }
        plan.tls = Some(TlsTemplate {
            address: h.address,
            data: file_range(elf, h.offset, h.files)?,
            memory_size: h.memory,
            alignment: h.alignment.max(1),
        });
    }
    if let Some(h) = unwind {
        // The static runtime consumes .eh_frame_hdr itself; the loader only
        // verifies it denotes readable, file-backed bytes in a LOAD mapping.
        if h.flags != 4
            || !h.aligned()
            || h.files == 0
            || h.files != h.memory
            || !plan.loads().any(|load| file_matches(load, h))
        {
            return Err(Error::Headers);
        }
        file_range(elf, h.offset, h.files)?;
    }
    if let Some(h) = relro {
        if h.flags & !6 != 0
            || h.files > h.memory
            || h.memory == 0
            || !plan
                .loads()
                .any(|load| load.permissions.write && covered(load, h.address, h.memory))
        {
            return Err(Error::Permissions);
        }
        file_range(elf, h.offset, h.files)?;
        plan.relro = Some(Region {
            address: h.address,
            size: h.memory,
        });
    }
    Ok(plan)
}

/// Actual process credentials and entropy are supplied by the trusted caller.
/// `phdr` must name the table mapped by Plan, and `random` must contain 16 bytes
/// from a real entropy source. This module never manufactures AT_RANDOM contents.
pub struct StackConfig {
    pub phdr: u64,
    pub phnum: u16,
    pub entry: u64,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub secure: bool,
    pub random: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialStack {
    pub sp: u64,
    pub argc: usize,
    pub argv: u64,
    pub envp: u64,
    pub auxiliary: u64,
    pub random: u64,
    pub execfn: u64,
}

/// Build a bounded argc/argv/envp/auxv stack with SP aligned to 16 bytes.
///
/// The supplied virtual base must describe the caller's actual user stack. This
/// first-stage interface uses argv[0] for AT_EXECFN, so argv[0] must be the actual
/// executable path, not a separately chosen display name. Strings are byte strings
/// without embedded NUL; the function supplies terminators. It writes only after
/// all validation and capacity checks succeed, leaving the buffer intact on error.
pub fn build_stack(
    stack: &mut [u8],
    base: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    config: &StackConfig,
) -> Result<InitialStack, Error> {
    build_stack_with_execfn(
        stack,
        base,
        argv,
        envp,
        config,
        argv.first().copied().unwrap_or(b""),
    )
}

/// Build the stack with a distinct, truthful AT_EXECFN pathname. This preserves
/// caller-chosen argv[0] (including non-UTF8 bytes) without changing executable
/// identity. The compatibility wrapper above keeps its original compact layout.
pub fn build_stack_with_execfn(
    stack: &mut [u8],
    base: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    config: &StackConfig,
    execfn: &[u8],
) -> Result<InitialStack, Error> {
    if !base.is_multiple_of(16)
        || base == 0
        || base.checked_add(stack.len() as u64).is_none()
        || argv.is_empty()
        || argv[0].is_empty()
        || execfn.is_empty()
        || execfn.contains(&0)
        || argv.len() > MAX_ARGUMENTS
        || envp.len() > MAX_ENVIRONMENT
        || config.phdr == 0
        || config.phnum == 0
        || usize::from(config.phnum) > MAX_HEADERS
        || !(IMAGE_BASE..IMAGE_END).contains(&config.entry)
        || !config.entry.is_multiple_of(4)
    {
        return Err(Error::Stack);
    }
    let mut strings = 0usize;
    for value in argv.iter().chain(envp.iter()) {
        if value.contains(&0) {
            return Err(Error::Stack);
        }
        strings = strings
            .checked_add(value.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Limit)?;
        if strings > MAX_STRING_BYTES {
            return Err(Error::Limit);
        }
    }
    let separate_execfn = execfn != argv[0];
    let argument_bytes = strings;
    if separate_execfn {
        strings = strings
            .checked_add(execfn.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Limit)?;
        if strings > MAX_STRING_BYTES {
            return Err(Error::Limit);
        }
    }
    const AUX_PAIRS: usize = 13;
    let words = 1 + argv.len() + 1 + envp.len() + 1 + 2 * AUX_PAIRS;
    let string_start = stack.len().checked_sub(strings).ok_or(Error::Stack)?;
    let random_at = string_start.checked_sub(16).ok_or(Error::Stack)? & !15;
    let table_at = random_at.checked_sub(words * 8).ok_or(Error::Stack)? & !15;
    let result = InitialStack {
        sp: base + table_at as u64,
        argc: argv.len(),
        argv: base + table_at as u64 + 8,
        envp: base + table_at as u64 + ((argv.len() + 2) * 8) as u64,
        auxiliary: base + table_at as u64 + ((argv.len() + envp.len() + 3) * 8) as u64,
        random: base + random_at as u64,
        execfn: base + (string_start + if separate_execfn { argument_bytes } else { 0 }) as u64,
    };
    // All possible failures are above this point. Only bounded, infallible writes
    // follow, so errors never leave a partially initialized caller stack behind.
    stack[table_at..].fill(0);
    let mut cursor = table_at;
    fn push(stack: &mut [u8], cursor: &mut usize, value: u64) {
        stack[*cursor..*cursor + 8].copy_from_slice(&value.to_le_bytes());
        *cursor += 8;
    }
    push(stack, &mut cursor, argv.len() as u64);
    let mut string_at = string_start;
    for group in [argv, envp] {
        for value in group {
            push(stack, &mut cursor, base + string_at as u64);
            stack[string_at..string_at + value.len()].copy_from_slice(value);
            string_at += value.len() + 1;
        }
        push(stack, &mut cursor, 0);
    }
    if separate_execfn {
        stack[string_at..string_at + execfn.len()].copy_from_slice(execfn);
    }
    for (tag, value) in [
        (3, config.phdr),
        (4, 56),
        (5, u64::from(config.phnum)),
        (6, PAGE_SIZE),
        (9, config.entry),
        (11, u64::from(config.uid)),
        (12, u64::from(config.euid)),
        (13, u64::from(config.gid)),
        (14, u64::from(config.egid)),
        (23, u64::from(config.secure)),
        (25, result.random),
        (31, result.execfn),
        (0, 0),
    ] {
        push(stack, &mut cursor, tag);
        push(stack, &mut cursor, value);
    }
    stack[random_at..random_at + 16].copy_from_slice(&config.random);
    Ok(result)
}

#[cfg(test)]
#[path = "executable_tests.rs"]
mod tests;
