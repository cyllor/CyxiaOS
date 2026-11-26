"""Read-only x86 FullOsV3 ELF admission, separate from the frozen producer.

This checks an already linked file. It neither changes a failed build receipt
nor grants guest memory, installs a program, or establishes runtime readiness.
The legacy static-ELF guards remain; only its image window is selected from the
reviewed FullOsV3 contract. The production parser's additional guards also apply.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import struct


ROOT = Path(__file__).resolve().parents[1]
PAGE = 4096
BASE = 0x01000000
LEGACY_END = 0x02000000
IMAGE_END = 0x05000000
IMAGE_BYTES = 64 * 1024 * 1024
STACK_BYTES = 2 * 1024 * 1024
U64_MAX = (1 << 64) - 1

# These exact sources were reviewed together. Recomputing arbitrary new hashes
# would not validate the hardcoded Python interpretation of a changed loader.
# 2026-11-18 reviewed update: exec_memory.rs gained the cosmic-session-gated
# on-demand executable frame arena (ContigFramePool). The change is physical
# backing only — the interpreted virtual layout (user_layout.rs), image structure
# (image.rs), executable parsing (executable.rs), per-process exec window, W^X
# permissions and page counting are unchanged, and the demo path is cfg-isolated
# (OS_NATIVE_PASS plus a 39-process session census verified). The other three
# pinned sources are byte-identical, so the hardcoded Python interpretation of
# the loader remains valid after this reviewed physical-backing change.
# 2026-11-21 reviewed e43b8e3: publish_space now synchronizes dirty executable
# and stack leaves into the retained process root. The diff changes only that
# publication method and its retirement comment; layout, parsing, page counts,
# allocation grants and W^X admission are unchanged. Native mapping/protection
# evidence is recorded in v17-cosmic-audit-hotpaths-20261121.md.
# 2026-11-22 reviewed e5d8306: init_pc takes the firmware-reserved MemoryRegion
# selected by BootPoolPlan, and both init paths pass its actual length to the
# session arena. Non-session backing still requires RESERVED_BYTES; the session
# arena checks page alignment and its existing maximum. Only physical pool
# initialization changed since e43b8e3: load_accounted, virtual bounds, stack
# budget, page counting and W^X admission are byte-identical. The other three
# pinned sources remain unchanged; this does not establish runtime readiness.
# 2026-11-26 reviewed V0.20.3 89f87ec against e5d8306: user_layout.rs changed
# only test formatting, image.rs only match formatting, and exec_memory.rs
# only import order and expression formatting. executable.rs is unchanged.
# The complete comparison and exact source identities are recorded in
# docs/implementation/v0203-loader-contract-recheck.md. Keep this byte-level
# gate: no new layout, admission, allocation or native-runtime claim is made.
_REVIEWED_LOADER_CONTRACT = (
    ('crates/contracts/src/user_layout.rs',
     '8c97945de3ce0f7f517354cfb7455d0c7affb39fe7a3c17d6691468400d244e7'),
    ('crates/contracts/src/image.rs',
     '8344a288a3af4a68105688d938d91269d1e8002623763ab2702d2d9d6ae9706a'),
    ('crates/posix/src/executable.rs',
     '0a2310be332d66a2c1e06ededc28c06fe41c4949db686b35f53e7ccd53e2b5e7'),
    ('kernel/src/desktop/memory/exec_memory.rs',
     '23c613788a9978ab07aaa124f763fc6353b19e3413268f6ff08ab19b5db3c3a4'),
)


class FullOsElfError(ValueError):
    """The file or selected resource contract is outside reviewed admission."""


def require(condition, message):
    if not condition:
        raise FullOsElfError(message)


def _read_regular(path, limit):
    """Bound the read and reject links, special files and replacement races."""
    require(isinstance(path, (str, os.PathLike)), 'ELF path must be a filesystem path')
    path = Path(path)
    require('..' not in path.parts, 'Parent traversal is outside the input contract')
    path = path.absolute()
    directory = descriptor = None
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open(path.anchor, directory_flags)
        for component in path.parts[1:-1]:
            following = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = following
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
                'Input must be a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(data) == before.st_size and len(data) <= limit
                and identity(before) == identity(os.fstat(descriptor))
                and identity(before) == identity(os.stat(path.name, dir_fd=directory,
                                                        follow_symlinks=False))
                and identity(before) == identity(path.stat(follow_symlinks=False)),
                'Input changed during the bounded read')
        return data
    except (OSError, ValueError) as error:
        if isinstance(error, FullOsElfError):
            raise
        raise FullOsElfError('Cannot read regular input: ' + str(error)) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def loader_contract():
    """Return reviewed identities only after checking the production sources."""
    result = dict(_REVIEWED_LOADER_CONTRACT)
    for name, expected in result.items():
        actual = hashlib.sha256(_read_regular(ROOT / name, 1024 * 1024)).hexdigest()
        require(actual == expected, 'Reviewed loader contract changed: ' + name)
    return result


def _profile(profile):
    require(type(profile) is dict, 'A selected notification resource profile is required')
    for name, expected in (('image_bytes', IMAGE_BYTES), ('max_elf_bytes', IMAGE_BYTES),
                           ('stack_bytes', STACK_BYTES)):
        require(type(profile.get(name)) is int and profile[name] == expected,
                'FullOsV3 requires the fixed ' + name)
    require(profile.get('target_runtime_validated') is False,
            'Static admission cannot validate target runtime')


def _range(data, offset, size):
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
            'ELF file range is out of bounds')
    return memoryview(data)[offset:offset + size]


def _aligned(header):
    alignment = header['align']
    return alignment <= 1 or (alignment & (alignment - 1) == 0
                              and header['vaddr'] % alignment == header['offset'] % alignment)


def _covered(load, address, size):
    return (load['vaddr'] <= address <= U64_MAX - size
            and address + size <= load['vaddr'] + load['memsz'])


def _file_matches(load, header, *, memory_size=None):
    size = header['memsz'] if memory_size is None else memory_size
    delta = header['vaddr'] - load['vaddr']
    return (_covered(load, header['vaddr'], size) and 0 <= delta <= load['filesz']
            and header['filesz'] <= load['filesz'] - delta
            and load['offset'] + delta == header['offset'])


def _notes(data):
    at = 0
    while at < len(data):
        require(at + 12 <= len(data), 'Truncated ELF note header')
        names, descriptions, kind = struct.unpack_from('<III', data, at)
        name_at = at + 12
        require(names <= len(data) - name_at, 'Truncated ELF note name')
        name = bytes(data[name_at:name_at + names])
        require(not (kind == 5 and name == b'GNU\0'), 'Unsupported GNU property note')
        at = (((name_at + names + 3) & ~3) + descriptions + 3) & ~3
        require(at <= len(data), 'Truncated ELF note description')


def inspect_full_os_elf(path, profile):
    """Validate one immutable x86 ELF under the fixed FullOsV3 static contract.

    The executable has the frozen inspector's field shape (``file`` is the
    basename). ``legacy_window_exceeded`` classifies only the old address-window
    rejection: all other legacy and production-loader guards have already passed.
    An installer recovering that specific failed-build case must require True.
    Resource-profile provenance remains the caller's responsibility.
    """
    _profile(profile)
    contract = loader_contract()
    data = _read_regular(path, IMAGE_BYTES)
    require(len(data) >= 64, 'Expected little-endian ELF64')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    (ident, kind, machine, version, entry, phoff, shoff, flags,
     ehsize, phsize, phnum, shsize, shnum, _) = header
    require(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3)
            and ident[8:] == bytes(8)
            and (kind, machine, version, flags, ehsize, phsize) == (2, 62, 1, 0, 64, 56),
            'Expected reviewed x86_64 ET_EXEC ELF header')
    require(1 <= phnum <= 32 and phoff >= 64 and phoff % 8 == 0,
            'Invalid program-header table')
    program_headers = _range(data, phoff, phnum * 56)
    require(shsize == 64, 'Invalid section-header table')
    _range(data, shoff, shnum * 64)
    symbol_records = 0
    for index in range(shnum):
        section = struct.unpack_from('<IIQQQQIIQQ', data, shoff + index * 64)
        if section[1] != 2:  # The legacy SHT_SYMTAB strong-undefined check.
            continue
        offset, size, entsize = section[4], section[5], section[9]
        require(entsize == 24 and size % 24 == 0, 'Invalid symbol table')
        symbols = _range(data, offset, size)
        symbol_records += size // 24
        require(symbol_records <= IMAGE_BYTES // 24, 'Symbol inspection budget exceeded')
        for position in range(0, size, 24):
            _, info, _, section_index, _, _ = struct.unpack_from('<IBBHQQ', symbols, position)
            require(not (info >> 4 == 1 and section_index == 0),
                    'Unresolved strong symbol in static ELF')

    fields = ('type', 'flags', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'align')
    headers = [dict(zip(fields, struct.unpack_from('<IIQQQQQQ', program_headers, i * 56)))
               for i in range(phnum)]
    loads, ranges, optional = [], [], {}
    note_bytes = 0
    for p in headers:
        kind = p['type']
        if kind == 0:
            continue
        if kind == 1:
            require(len(loads) < 16, 'Too many LOAD segments')
            require(p['flags'] in (4, 5, 6), 'LOAD requires readable W^X permissions')
            require(p['align'] == PAGE and _aligned(p)
                    and (p['vaddr'] - p['offset']) % PAGE == 0, 'Invalid LOAD alignment')
            require(p['memsz'] > 0 and p['filesz'] <= p['memsz']
                    and BASE <= p['vaddr'] < p['vaddr'] + p['memsz'] <= IMAGE_END,
                    'LOAD outside FullOsV3 image bounds')
            _range(data, p['offset'], p['filesz'])
            start = p['vaddr'] // PAGE
            end = (p['vaddr'] + p['memsz'] + PAGE - 1) // PAGE
            require(all(end <= old_start or old_end <= start for old_start, old_end in ranges),
                    'Overlapping LOAD pages')
            ranges.append((start, end))
            loads.append(p)
        elif kind == 4:
            note_bytes += p['filesz']
            require(note_bytes <= IMAGE_BYTES, 'Note inspection budget exceeded')
            _notes(_range(data, p['offset'], p['filesz']))
        elif kind in (6, 7, 0x6474e550, 0x6474e551, 0x6474e552):
            require(kind not in optional, 'Duplicate optional program header')
            optional[kind] = p
        else:
            require(False, 'Dynamic, INTERP or unknown program header is unsupported')

    require(any(p['flags'] & 1 and p['vaddr'] <= entry < entry + 1 <= p['vaddr'] + p['filesz']
                for p in loads), 'Entry point must be file-backed executable code')
    phdr = optional.get(6)
    require(phdr is not None, 'Program headers must be mapped for musl startup')
    phdr_address = next((p['vaddr'] + phoff - p['offset'] for p in loads
                         if 0 <= phoff - p['offset']
                         and phoff - p['offset'] + len(program_headers) <= p['filesz']), None)
    require(phdr_address is not None and phdr['flags'] == 4 and _aligned(phdr)
            and phdr['offset'] == phoff and phdr['vaddr'] == phdr_address
            and phdr['filesz'] == phdr['memsz'] == len(program_headers),
            'Invalid mapped PHDR identity')
    if 7 in optional:
        p = optional[7]
        require(p['flags'] in (4, 6) and p['filesz'] <= p['memsz'] <= IMAGE_END - BASE
                and _aligned(p) and BASE <= p['vaddr'] < IMAGE_END
                and p['vaddr'] + p['memsz'] <= IMAGE_END
                and (p['filesz'] == 0 or any(_file_matches(l, p, memory_size=p['filesz']) for l in loads)),
                'Invalid TLS template')
        _range(data, p['offset'], p['filesz'])
    if 0x6474e550 in optional:
        p = optional[0x6474e550]
        require(p['flags'] == 4 and _aligned(p) and p['filesz'] > 0
                and p['filesz'] == p['memsz'] and any(_file_matches(l, p) for l in loads),
                'Invalid file-backed unwind header')
        _range(data, p['offset'], p['filesz'])
    if 0x6474e551 in optional:
        p = optional[0x6474e551]
        require(p['flags'] & ~6 == 0 and p['filesz'] == 0 and _aligned(p)
                and p['memsz'] <= STACK_BYTES, 'Invalid non-executable stack contract')
    if 0x6474e552 in optional:
        p = optional[0x6474e552]
        require(p['flags'] & ~6 == 0 and p['filesz'] <= p['memsz'] and p['memsz'] > 0
                and any(l['flags'] & 2 and _covered(l, p['vaddr'], p['memsz']) for l in loads),
                'Invalid writable RELRO coverage')
        _range(data, p['offset'], p['filesz'])

    pages = sum(end - start for start, end in ranges)
    required_pages = pages + STACK_BYTES // PAGE
    require(required_pages <= IMAGE_BYTES // PAGE, 'LOAD pages and stack exceed private image pool')
    executable = dict(file=Path(path).name, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                      architecture='x86_64', machine=62, target='x86_64-linux-musl', entry=entry,
                      at_phdr=phdr_address, at_phent=phsize, at_phnum=phnum, program_headers=headers)
    return dict(executable=executable, image_load_pages=pages, profile='full-os-v3',
                legacy_window_exceeded=any(not (BASE <= p['vaddr'] < LEGACY_END
                                                and p['vaddr'] + p['memsz'] <= LEGACY_END) for p in loads),
                required_pages=required_pages, loader_contract=contract)
