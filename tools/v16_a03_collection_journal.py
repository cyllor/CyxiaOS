"""Read-only committed Full journal inventory, independent of label/MLP checks.

This decodes native archive framing from learning_replay/{archive,
preparation_archive,late_archive}.rs. Signed peer packets and history rows are
preserved verbatim; this module does not authenticate or replay their contents.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct

from check_v13_disk import BLOCK, COUNT, committed_volume
from check_v13_filesystem import inspect_committed

VERSION = 'v16-a03-collection-journal-v1'
MAX_FILE = 8 * 1024**2
MAX_ROWS = 768
SCHEMAS = (
    '8b68c6f4e977aa844174a9ed4c37404faf05ce151fa67ed02106611704643854',
    'e68f5095f9cce96c0036e8765b6f303f5d7ff2a112bb5bd13b963551e5812f5b',
    '3f3642803f6cd8dcc964092ac8d2e51922eb661a185dc6e9546ae037ef1cd5ab',
    '091fa0a5ae8012692fd4e351993773077063c67fdf4303f30bfbee68d47fae7e')
KINDS = {'lr': 'regular', 'lp': 'preparation', 'lf': 'late'}
MAGIC = {'regular': b'CYXIA_REPLAY_1.3\0', 'preparation': b'CYXIA_PREP_1.3\0',
         'late': b'CYXIA_LATE_1.3\0'}
LIMITS = dict(reward_replay_verified=False, accepted_training_sample_verified=False,
    model_trained=False, model_validation_verified=False, peer_signature_verified=False,
    native_replay_authority_reconstructed=False, provenance_verified=False,
    native_acceptance_status='NOT_RUN')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _word(raw, at):
    return struct.unpack_from('<Q', raw, at)[0]


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _disk_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _family(domain, kind):
    require(1 <= domain <= 16 and (kind == 1 or (kind == 2 and domain in (1, 16))),
            'unsupported journal family')
    return [domain, kind]


def _sources(header, at, count):
    require(count <= 16, 'journal source count bound')
    for index in range(count):
        owner, generation, cls, mask = struct.unpack_from('<4Q', header, at + index * 32)
        require(owner > 0 and generation > 0 and cls <= 2 and 0 < mask <= 15,
                'invalid journal source identity/range')
    require(not any(header[at + count * 32:at + 16 * 32]), 'journal source padding')


def _packet(raw, start, size, allowed):
    require(196 <= size <= 2048, 'peer packet byte bound')
    padded = (size + 255) // 256 * 256
    require(start + padded <= len(raw), 'truncated peer packet')
    packet = raw[start:start + size]
    require(bytes(packet[:8]) == b'CXBILL1\0', 'unknown peer packet framing')
    kind, body = struct.unpack_from('<HH', packet, 8)
    require(kind in allowed and size == 132 + body + 64 and _word(packet, 12) > 0,
            'peer packet kind/length/sequence mismatch')
    require(any(packet[20:52]) and any(packet[52:84]) and packet[20:52] != packet[52:84]
            and _word(packet, 84) > 0 and _word(packet, 92) > 0 and any(packet[100:132]),
            'peer packet endpoint/session identity')
    require(not any(raw[start + size:start + padded]), 'peer packet padding')
    return padded


def _regular(raw, boot):
    require(len(raw) >= 2048, 'truncated regular journal header')
    h = raw[:2048]
    require(not any(h[17:24]) and not any(h[232:256]), 'regular journal header padding')
    epoch, trial, generation, domain, kind, target, target_generation, seed, first, warm, observation, closing = struct.unpack_from('<12Q', h, 32)
    family = _family(domain, kind)
    require(epoch == boot and min(trial, generation, target, target_generation, first) > 0
            and 1 <= seed <= 12 and warm <= observation and first <= observation
            and closing >= first, 'regular journal identity/timestamp range')
    records, cpu, requests, candidate, exclusion, error = struct.unpack_from('<6Q', h, 128)
    require(records <= 64 and cpu <= 8192 and requests <= 100 and candidate in (0, 1)
            and exclusion <= 20 and error <= 20, 'regular journal count/error bound')
    excluded = bool(exclusion or error or _word(h, 24))
    require(excluded or (requests == 100 and records > 0 and first < observation < closing),
            'successful regular journal missing observation/counts')
    require(tuple(bytes(h[448 + i * 32:480 + i * 32]).hex() for i in range(4)) == SCHEMAS
            and struct.unpack_from('<4Q', h, 576) == (13,) * 4,
            'regular journal schema mismatch')
    require(any(h[640:672]) and _word(h, 632) == 2048, 'regular journal node/header layout')
    mode, sources, peer_cpu = struct.unpack_from('<3Q', h, 608)
    peer_bytes, prewarm = _word(h, 744), _word(h, 752)
    require(mode in (0, 1, 2) and peer_cpu <= 4096 and cpu + peer_cpu <= 8192
            and prewarm <= MAX_ROWS and _word(h, 720) in (0, 1)
            and _word(h, 728) <= 100 and _word(h, 736) <= sources,
            'regular journal peer/closure count bound')
    _sources(h, 768, sources)
    if mode:
        require(domain in (10, 12, 16), 'peer packet on local journal family')
        if mode == 2:
            require(peer_cpu == 0, 'preparation packet has peer CPU rows')
        padded = _packet(raw, 2048, peer_bytes, {8, 17} if mode == 1 else {14, 19})
    else:
        require(peer_cpu == peer_bytes == 0, 'local journal contains untyped peer section')
        padded = 0
    length = 2048 + padded + records * 6144 + (cpu + peer_cpu + prewarm) * 64 + requests * 128
    return dict(length=length, trial_id=trial, family=family, boot_epoch=epoch,
        generation=generation, seed=seed, side='candidate' if candidate else 'baseline',
        excluded=excluded, records=records, local_cpu_rows=cpu, peer_cpu_rows=peer_cpu,
        prewarm_rows=prewarm, requests=requests, peer_packet_bytes=peer_bytes)


def _preparation(raw, boot):
    require(len(raw) >= 1024, 'truncated preparation journal header')
    h = raw[:1024]
    require(not any(h[15:32]) and not any(h[256:288]) and not any(h[992:1000])
            and not any(h[1008:1024]), 'preparation journal header padding')
    preparation, epoch, owner, owner_generation, trial, domain, kind, seed, candidate, started, failed, drained, error = struct.unpack_from('<13Q', h, 32)
    family = _family(domain, kind)
    require(epoch == boot and min(preparation, owner, owner_generation, trial, started) > 0
            and 1 <= seed <= 12 and candidate in (0, 1) and started <= failed <= drained
            and 1 <= error <= 20 and _word(h, 136) <= _word(h, 144) <= drained,
            'preparation journal identity/error/timestamp range')
    rows, manifest = _word(h, 200), _word(h, 208)
    require(rows <= MAX_ROWS and manifest in (0, 1) and _word(h, 248) in (0, 1)
            and all(_word(h, at) in (0, 1) for at in (160, 184, 416))
            and _word(h, 472) == 0, 'preparation journal flags/counts')
    _sources(h, 480, _word(h, 456))
    peer_bytes = _word(h, 1000)
    require(peer_bytes == 0 or domain in (10, 12, 16), 'preparation peer family mismatch')
    padded = _packet(raw, 1024, peer_bytes, {14, 19}) if peer_bytes else 0
    length = 1024 + padded + rows * 64 + manifest * 100 * 32
    require(_word(h, 464) == length, 'preparation journal encoded length mismatch')
    return dict(length=length, trial_id=trial, family=family, boot_epoch=epoch,
        preparation_id=preparation, seed=seed, excluded=True, prewarm_rows=rows,
        requests=manifest * 100, peer_packet_bytes=peer_bytes)


def _late(raw, boot):
    require(len(raw) >= 256, 'truncated late journal header')
    h = raw[:256]
    require(h[15] == 0 and _word(h, 16) == 1 and _word(h, 24) == 256
            and _word(h, 40) == boot and min(_word(h, at) for at in (48, 56, 64, 72, 80, 96)) > 0
            and _word(h, 88) > _word(h, 80) and 1 <= _word(h, 104) <= 20
            and _word(h, 120) == 0 and all(any(h[at:at + 32]) for at in (128, 160, 192, 224)),
            'late journal identity/error/timestamp/header range')
    size = _word(h, 112)
    require(size == 640, 'late journal root failure packet length')
    padded = _packet(raw, 256, size, {20})
    require(_sha(raw[256:256 + size]) == bytes(h[128:160]).hex(), 'late journal packet hash mismatch')
    length = 256 + padded
    require(_word(h, 32) == length, 'late journal encoded length mismatch')
    return dict(length=length, trial_id=_word(h, 48), boot_epoch=boot,
        generation=_word(h, 56), excluded=True, peer_packet_bytes=size)


def inspect_journals(disk_path, *, disk_uuid, boot_epoch=1, max_archives=4096,
                     max_archive_bytes=256 * 1024**2, allow_empty=False):
    """Inventory committed journal ranges and return their original byte exports.

    ``manifest`` is JSON serializable. ``exports`` maps stable flat filenames to
    exact journal bytes. An explicitly selected participant may have no own
    journal files. Header checks here grant no replay or model authority.
    """
    path = Path(disk_path)
    require(not path.is_symlink() and path.is_file(), 'missing/linked journal disk')
    require(isinstance(disk_uuid, str) and re.fullmatch('[0-9a-f]{32}', disk_uuid)
            and any(bytes.fromhex(disk_uuid)), 'invalid journal disk UUID')
    require(type(allow_empty) is bool and type(boot_epoch) is int and 0 < boot_epoch < 2**64
            and type(max_archives) is int and 1 <= max_archives <= 4096
            and type(max_archive_bytes) is int and 1 <= max_archive_bytes <= BLOCK * COUNT,
            'journal inventory limits')
    initial_identity, initial_hash = _identity(path), _disk_sha(path)
    journals, files, exports, total = [], [], {}, 0
    segments = {prefix: [] for prefix in KINDS}
    with committed_volume(path) as (current, metadata):
        volume = inspect_committed(current, metadata)
        require(volume['uuid'] == disk_uuid and volume['boot_epoch'] == boot_epoch,
                'committed journal volume identity mismatch')
        require(len(volume['files']) + len(volume['directories']) <= 256,
                'committed journal inode bound')
        for name in sorted(set(volume['files']) | set(volume['directories'])):
            if not any(part.startswith(('lr-', 'lp-', 'lf-')) for part in name.split('/')):
                continue
            match = re.fullmatch(r'/(lr|lp|lf)-([0-9a-f]{16})-([0-9a-f]{4})', name)
            require(match is not None and name in volume['files']
                    and int(match[2], 16) == boot_epoch, 'unknown journal pathname/type/boot')
            prefix, kind = match[1], KINDS[match[1]]
            segments[prefix].append(int(match[3], 16))
            node = volume['files'][name]
            require(type(node['size']) is int and 0 < node['size'] <= MAX_FILE
                    and 0 < node['inode'] < 256 and node['generation'] > 0
                    and node['durable_write_seq'] > 0, 'journal file identity/size/durability')
            total += node['size']
            require(total <= max_archive_bytes, 'journal archive byte bound')
            require(len(node['extents']) <= 16, 'journal extent count bound')
            raw = bytearray()
            logical_end = 0
            for logical, start, blocks in node['extents']:
                require(logical == logical_end and 0 < blocks <= MAX_FILE // BLOCK
                        and 0 <= start < start + blocks <= COUNT, 'journal extent range/coverage')
                logical_end += blocks
                require(logical_end <= (node['size'] + BLOCK - 1) // BLOCK, 'journal extent allocation bound')
                for index in range(start, start + blocks):
                    block = current(index)
                    require(len(block) == BLOCK, 'short journal disk block')
                    raw.extend(block[:min(BLOCK, node['size'] - len(raw))])
            require(len(raw) == node['size'] and _sha(raw) == node['sha256'],
                    'committed journal file length/hash mismatch')
            files.append(dict(path=name, inode=node['inode'], generation=node['generation'],
                bytes=node['size'], sha256=node['sha256'], durable_write_seq=node['durable_write_seq']))
            offset = 0
            while offset < len(raw):
                require(len(journals) < max_archives, 'journal archive count bound')
                remaining = memoryview(raw)[offset:]
                require(bytes(remaining[:len(MAGIC[kind])]) == MAGIC[kind],
                        'unknown/truncated journal magic or mixed journal kind')
                parsed = {'regular': _regular, 'preparation': _preparation, 'late': _late}[kind](remaining, boot_epoch)
                length = parsed['length']
                require(0 < length <= MAX_FILE and length <= len(remaining), 'truncated/unbounded journal range')
                value = bytes(remaining[:length])
                filename = f'{name[1:]}-offset-{offset:08x}.bin'
                require(filename not in exports, 'duplicate journal export name')
                row = dict(parsed, kind=kind, path=name, inode=node['inode'],
                    object_id=node['inode'], object_generation=node['generation'],
                    inode_generation=node['generation'], offset=offset,
                    durable_write_seq=node['durable_write_seq'], sha256=_sha(value), export_file=filename)
                journals.append(row)
                exports[filename] = value
                offset += length
        require(journals or allow_empty, 'missing committed learning journals')
        for prefix, values in segments.items():
            require(values == list(range(len(values))), 'missing/reordered journal segments: ' + prefix)
    require(_disk_sha(path) == initial_hash and _identity(path) == initial_identity,
            'journal disk changed during reconstruction')
    counts = dict(total=len(journals), regular=0, preparation=0, late=0, excluded=0)
    for row in journals:
        counts[row['kind']] += 1
        counts['excluded'] += int(row['excluded'])
    manifest = dict(version=VERSION, disk_uuid=disk_uuid, boot_epoch=boot_epoch,
        disk_sha256=initial_hash, disk_bytes=initial_identity[2], total_archive_bytes=total,
        counts=counts, files=files, journals=journals, **LIMITS)
    return dict(journals=journals, counts=counts, exports=exports, manifest=manifest)
