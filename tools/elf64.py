"""Architecture-neutral, bounded ELF64 little-endian decoding.

Machine IDs, address pools, permissions and entry contracts belong to callers.
"""
import struct

LIMIT = 1 << 64


def require(ok, message):
    if not ok:
        raise ValueError(message)


def decode(raw):
    require(len(raw) >= 64, 'truncated header')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = h
    require(ident[:7] == b'\x7fELF\x02\x01\x01' and version == 1,
            'not ELF64 little-endian version 1')
    require(ehsize == 64 and phsize == 56 and 0 < phnum <= 32 and phoff >= 64
            and phoff + phnum * 56 <= len(raw), 'invalid program headers')
    segments = []
    for i in range(phnum):
        typ, fl, off, va, pa, fs, ms, al = struct.unpack_from('<IIQQQQQQ', raw, phoff + i * 56)
        if typ == 1:
            require(fs <= ms and off + fs <= len(raw) and pa + ms < LIMIT and va + ms < LIMIT,
                    'segment overflow')
        segments.append(dict(type=typ, flags=fl, offset=off, va=va, pa=pa, size=fs, mem=ms, align=al))
    return dict(kind=kind, machine=machine, entry=entry, flags=flags, segments=segments,
                section_offset=shoff, section_size=shsize, section_count=shnum, section_strings=shstr)


def symbol(raw, name, loads):
    """Resolve a symbol only inside a validated PT_LOAD, never arbitrary sections."""
    h = decode(raw)
    off, size, count = h['section_offset'], h['section_size'], h['section_count']
    require(size == 64 and count <= 1024 and (count == 0 or off >= 64)
            and off + count * size <= len(raw), 'bad sections')
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, off + i * size) for i in range(count)]
    matches = []
    for s in sections:
        if s[1] != 2:
            continue
        require(s[6] < count and s[9] == 24 and s[5] % 24 == 0 and s[4] + s[5] <= len(raw), 'bad symbol table')
        strings = sections[s[6]]
        require(strings[1] == 3 and strings[4] + strings[5] <= len(raw), 'bad symbol string table')
        table = raw[strings[4]:strings[4] + strings[5]]
        for p in range(s[4], s[4] + s[5], 24):
            n, info, other, idx, value, length = struct.unpack_from('<IBBHQQ', raw, p)
            require(n < len(table), 'symbol name outside string table')
            end = table.find(b'\0', n)
            require(end >= 0, 'unterminated symbol name')
            if table[n:end] != name.encode('utf-8') or idx == 0:
                continue
            locations = []
            for seg in loads:
                if seg['va'] <= value and value + length <= seg['va'] + seg['mem']:
                    location = dict(va=value, pa=value - seg['va'] + seg['pa'], size=length)
                    # A zero-sized linker boundary can belong to both adjacent
                    # loads. Deduplicate that mapping only within this SYMTAB
                    # entry; distinct mappings and duplicate entries still fail.
                    if location not in locations:
                        locations.append(location)
            matches.extend(locations)
    require(len(matches) == 1, ('missing symbol ' if not matches else 'ambiguous symbol ') + name)
    return matches[0]
