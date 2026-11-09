"""Bounded first-local-D01 committed structure; never numeric learning authority."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import struct

from check_v13_disk import BLOCK, committed_volume
from check_v13_filesystem import inspect_committed
from v16_learning_pair import sha, verify_capture
from verify_v13_boot_recovery import require

MAX_FILE = 8 * 1024 * 1024
OWNER = 0x5245504c4159
SCHEMAS = ('8b68c6f4e977aa844174a9ed4c37404faf05ce151fa67ed02106611704643854',
           'e68f5095f9cce96c0036e8765b6f303f5d7ff2a112bb5bd13b963551e5812f5b',
           '3f3642803f6cd8dcc964092ac8d2e51922eb661a185dc6e9546ae037ef1cd5ab',
           '091fa0a5ae8012692fd4e351993773077063c67fdf4303f30bfbee68d47fae7e')
EMPTY_SHARED = bytes.fromhex('32d3d5d0fec9ed1576a1889f4ce2eef857056347f0dcbfb1ae20c00765760e55')
PROOF_LIMITS = dict(reward_replay_verified=False, accepted_training_sample_verified=False,
                    model_trained=False, event_hash_recomputed=False,
                    initial_image_reexecution_verified=False, native_acceptance_status='NOT_RUN',
                    formal_acceptance={name: 'NOT_RUN' for name in ('A03', 'A08', 'A10', 'A16')})


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def word(raw, offset):
    return struct.unpack_from('<Q', raw, offset)[0]


def words(*values):
    return struct.pack('<' + 'Q' * len(values), *values)


def _hex(value, length=32):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % (length * 2), value)
            and any(bytes.fromhex(value)), 'missing/invalid trusted identity')
    return bytes.fromhex(value)


def _context(context, boot):
    require(type(boot) is int and boot == 1 == context['boot_epoch'], 'unsupported first boot')
    for name in ('build_sha256', 'model_sha256', 'schema_hash', 'node_id', 'input_sha256',
                 'config_sha256', 'disk_sha256'):
        _hex(context[name])
    _hex(context['nonce'], 16); _hex(context['disk_uuid'], 16)
    require(context['source_map'] and context['artifacts'] and context['model_generation'] == 1,
            'missing trusted source/build/model closure')
    require(context['schema_hash'] == SCHEMAS[0] and tuple(context['schema_hashes']) == SCHEMAS,
            'unsupported trusted schemas')
    require(set(context['stopped_banks']) == {'boot', 'replay', 'control', 'runtime', 'unified'},
            'missing stopped banks')
    for value in context['stopped_banks'].values():
        _hex(value)
    b = context['released_boundary']
    require(set(b) == {'publication', 'phase', 'verified', 'archived', 'paired'}
            and all(type(v) is int for v in b.values()) and b['publication'] > 0
            and not b['publication'] % 2 and b['phase'] in (0, 17)
            and b['verified'] >= 2 and b['archived'] >= 2 and b['paired'] >= 1,
            'missing released boundary')


def _action(slot, index):
    domain, kind, length, reserved, candidate, weight = struct.unpack_from('<6H', slot)
    require((domain, kind, length, reserved, candidate) == (1, 1, 4, 0, index)
            and weight in (1, 2, 4, 8) and not any(slot[12:]), 'unsupported D01 action')
    return weight


def _record(row, header, context):
    flags = word(row, 0)
    require(flags in (40, 31, 64), 'unsupported history flags')
    target = tuple(word(row, x) for x in (184, 192))
    require(target == (12, 1) and all(word(row, x) > 0 for x in (8, 152, 160, 168, 176)),
            'history snapshot/target mismatch')
    count, selected = struct.unpack_from('<HH', row, 204)
    require(1 <= count <= 4 and selected < count, 'candidate alternatives bound')
    weights = [_action(row[512 + i * 24:536 + i * 24], i) for i in range(count)]
    require(not any(row[512 + count * 24:1280]), 'unused history action slots')
    if flags == 40:
        require(header['side'] == 'Baseline' and count == 1 and selected == 0
                and row[200:204] == bytes(4) and not any(row[16:152])
                and word(row, 344) == header['boot_epoch'] and word(row, 440) == 0,
                'baseline metadata mismatch')
        _execution(row, header)
        return dict(kind='Baseline', sha256=digest(row), model_binding='trusted capture context')
    require(header['side'] == 'Candidate' and row[200:204] == b'\x01\0\x01\0'
            and word(row, 80) == context['model_generation']
            and row[88:120].hex() == context['model_sha256']
            and row[120:152].hex() == context['schema_hash'], 'history model/family mismatch')
    require(weights == sorted(set(weights)), 'unsorted/duplicate candidate alternatives')
    inp = row[2048:]
    require(digest(inp) == row[48:80].hex(), 'raw input hash mismatch')
    w = struct.unpack('<512Q', inp)
    expected_magic = int.from_bytes(b'CXPROBE1', 'little') if flags == 64 else 0x4359585254494e31
    require(w[0] == expected_magic and w[1] == 3 and w[2] == word(row, 8)
            and w[4] == word(row, 160) and (w[6], w[7]) == (word(row, 176), word(row, 168))
            and w[8:12] == (1, 1, 12, 1) and w[13:16] == (1, header['boot_epoch'], count)
            and inp[128:160] == row[88:120] and inp[160:192] == row[16:48]
            and w[40] == 15 and w[31] <= 1, 'input identity/features mismatch')
    canonical = bytearray(b'CYXIA_CANDIDATES_V1.3\0')
    canonical += words(*(word(row, i) for i in (152, 160, 168, 176, 184, 192, 80)), count)
    canonical += row[88:152]
    for i, weight in enumerate(weights):
        at = 64 + 10 * i
        payload = inp[(at + 1) * 8:(at + 3) * 8]
        require(w[at] == 4 and payload[:4] == struct.pack('<HH', i, weight)
                and not any(payload[4:]) and w[at + 7] <= 15 and w[at + 8] == w[at + 9] == 0,
                'candidate input action/target mismatch')
        canonical += struct.pack('<5H', 1, 1, 4, i, weight) + words(*w[24:36]) + bytes([w[40]])
        for j in range(4):
            present = (w[at + 7] >> j) & 1
            value = w[at + 3 + j]
            require((present or value == 0) and (j != 3 or value <= 1), 'illegal target features')
            canonical += bytes([present]) + words(value)
        canonical += bytes(9)  # absent control capacity
    require(digest(canonical) == row[16:48].hex(), 'CandidateSet integrity mismatch')
    prior = inp[405 * 8:407 * 8]
    require(w[404] == 4 and prior[:2] == bytes(2) and not any(prior[4:])
            and struct.unpack_from('<H', prior, 2)[0] in weights, 'invalid prior action')
    if flags == 64:
        require(selected == 0 and word(row, 8) == word(row, 152)
                and not any(row[208:512]) and not any(row[1280:2048])
                and all(w[i] == 0 for i in (3, 5, 12, 36, 37, 38, 39)), 'probe has publication fields')
    else:
        apply = tuple(word(row, i) for i in range(272, 320, 8))
        require(apply[0] == header['boot_epoch'] and apply[1] == w[3] > 0 and apply[2] > 0
                and apply[3:] == (0, 12, 1) and row[1280:1328] == row[272:320]
                and not any(row[1328:2048]) and word(row, 440) == 1 and word(row, 480) == 0
                and row[448:480] == EMPTY_SHARED and word(row, 496) in (0, 1)
                and not any(row[504:512]), 'unsupported publication/shared action')
        _execution(row, header)
    return dict(kind='Probe' if flags == 64 else 'Candidate', sha256=digest(row),
                candidate_set_sha256=row[16:48].hex(), input_sha256=row[48:80].hex(),
                candidate_set_integrity_verified=True)


def _execution(row, header):
    issued, accepted, started, finished = (word(row, i) for i in (352, 360, 400, 416))
    require(0 < issued <= accepted <= started <= finished <= header['closing_ns']
            and finished <= word(row, 384) and word(row, 392) > 0
            and word(row, 424) == 1 and word(row, 432) == 0, 'nonterminal/invalid execution')


def _side(raw, context):
    require(len(raw) >= 2048, 'truncated archive header')
    h = raw[:2048]
    require(h[:17] == b'CYXIA_REPLAY_1.3\0' and not any(h[17:32])
            and not any(h[232:256]) and not any(h[1280:1792]), 'unsupported archive header')
    boot, trial, generation, domain, kind, target, target_gen, seed, first, warm, observation, closing = struct.unpack_from('<12Q', h, 32)
    records, cpu, requests, candidate = struct.unpack_from('<4Q', h, 128)
    require(boot == context['boot_epoch'] and trial > 0 and generation > 0 and seed == 1
            and (domain, kind, target, target_gen) == (1, 1, 12, 1)
            and candidate in (0, 1) and 0 < first < observation < closing
            and observation == first + 6000000000 and warm == observation - 1000000000
            and closing >= observation + 10000000000, 'unsupported archive run identity/timing')
    require(1 <= records <= 64 and cpu <= 8192 and requests == 100
            and all(word(h, i) == 0 for i in (160, 168, 192, 224, 608, 624, 744, 752))
            and word(h, 632) == 2048, 'unsupported archive counts/peer/prewarm/exclusion')
    length = 2048 + records * 6144 + cpu * 64 + requests * 128
    require(length <= MAX_FILE and length <= len(raw), 'truncated/unbounded archive side')
    require(tuple(h[448 + i * 32:480 + i * 32].hex() for i in range(4)) == tuple(context['schema_hashes'])
            and struct.unpack_from('<4Q', h, 576) == (13,) * 4
            and h[640:672].hex() == context['node_id'], 'archive schema/node mismatch')
    require(h[256:288].hex() == '324fe297c7f2eeb0d2c4b2530a41adb4a657b109a211d5da291696b48071fc1a'
            and all(any(h[i:i + 32]) for i in (288, 320, 352, 384, 416)), 'archive group/hash mismatch')
    count = word(h, 616)
    require(0 < count <= 16 and not any(h[768 + count * 32:1280])
            and word(h, 728) == 100 and word(h, 736) == count, 'archive source closure mismatch')
    sources = [struct.unpack_from('<4Q', h, 768 + i * 32) for i in range(count)]
    require(sources == [(12, 1, 0, 7), (12, 1, 1, 15), (OWNER, 1, 2, 1),
                        (0x5245504c5453, 1, 2, 9)], 'unsupported D01 source manifest')
    coverage = struct.unpack_from('<7Q', h, 672)
    require(coverage == (first, observation, observation + 10000000000, closing, 3, 3, 1),
            'invalid local coverage')
    _closing(h[1792:], boot, closing)
    result = dict(boot_epoch=boot, trial_id=trial, capture_generation=generation,
                  family=[1, 1], target=[12, 1], seed=seed, side='Candidate' if candidate else 'Baseline',
                  first_ns=first, observation_ns=observation, closing_ns=closing, length=length,
                  workload_sha256=h[256:288].hex(), initial_image_sha256=h[288:320].hex(),
                  frozen_other_domains_sha256=h[320:352].hex(), frozen_scope_sha256=h[352:384].hex(),
                  event_sha256=h[384:416].hex(), producer_verification_sha256=h[416:448].hex(),
                  schema_hashes=list(context['schema_hashes']), node_id=context['node_id'])
    result['records'] = [_record(raw[2048 + i * 6144:2048 + (i + 1) * 6144], result, context) for i in range(records)]
    require(any(r['kind'] == result['side'] for r in result['records']), 'missing adopted/baseline history')
    at = 2048 + records * 6144
    for i in range(cpu):
        row = raw[at + i * 64:at + (i + 1) * 64]
        core, start, end, cls = struct.unpack_from('<4Q', row, 32)
        require(row[:32] == h[640:672] and core < 4 and cls <= 2
                and first <= start <= end <= closing
                and any(s[2] == cls and s[3] & (1 << core) for s in sources), 'invalid local CPU row')
    at += cpu * 64
    canonical = bytearray(b'CYXIA_NATIVE_WORKLOAD_SCOPE_1.3\0')
    canonical += words(boot, trial, domain, kind, target, target_gen, seed, first, observation) + h[256:352]
    for source in sources:
        canonical += words(*source)
    arrivals = []
    for i in range(requests):
        row = raw[at + i * 128:at + (i + 1) * 128]
        identity, owner, gen, relative = _request(row, i, first, observation, closing)
        canonical += words(identity, owner, gen, relative)
        arrivals.append([identity, relative])
    require(digest(canonical) == h[352:384].hex(), 'frozen scope integrity mismatch')
    result.update(relative_arrivals=arrivals, scope_hash_recomputed=True,
                  sha256=digest(raw[:length]), raw_bytes=bytes(raw[:length]))
    return result


def _request(row, index, first, observation, closing):
    """A scheduled D01 request records original queue custody before release."""
    identity, arrived, code, finished, rawcode, rawfinished, owner, gen, frozen, present, issued, scheduled = struct.unpack_from('<12Q', row)
    relative = index // 10 * 1000000000 + index % 10 * 1000
    require(identity == index + 1 and arrived == frozen == observation + relative
            and (owner, gen) == (OWNER, 1) and scheduled == 1 and present == 1
            and 0 < issued <= first <= arrived
            and code in (1, 2, 3, 4) and rawcode in (0, 1, 2, 3, 4)
            and (arrived <= finished <= closing if code == 1 else finished == 0)
            and (arrived <= rawfinished <= closing if rawcode == 1 else rawfinished == 0)
            and not any(row[96:]), 'invalid D01 request/schedule/result')
    return identity, owner, gen, relative


def _closing(row, boot, closing):
    # Restoration is a separate terminal fact. Native poll retains Applied even
    # when observation is later than its execution deadline. Adoption deadlines
    # remain enforced by _execution; a closing receipt proves no numeric result.
    require(row[:8] == b'CYCLOSE1' and tuple(word(row, i) for i in (8, 16, 24)) == (1, 1, 4)
            and struct.unpack_from('<HH', row, 32)[0] == 0
            and struct.unpack_from('<HH', row, 32)[1] in (1, 2, 4, 8)
            and not any(row[36:48]) and word(row, 48) == boot
            and all(word(row, i) > 0 for i in (56, 64, 96, 120, 128, 136, 144, 160))
            and word(row, 72) == 0 and (word(row, 80), word(row, 88)) == (12, 1)
            and word(row, 152) == 1 and word(row, 184) == 1 and word(row, 216) == 0
            and 0 < word(row, 168) <= word(row, 176) <= word(row, 192) <= word(row, 200) <= closing
            and not any(row[224:]), 'invalid closing restoration receipt')


def extract_local_pair(disk_path, *, trusted_capture_context, boot_epoch, family=(1, 1), minimum_pairs=1):
    """Read every archive side through exactly one existing committed-volume oracle."""
    require(family == (1, 1) and type(minimum_pairs) is int and minimum_pairs >= 1, 'unsupported pair scope')
    c = trusted_capture_context
    _context(c, boot_epoch)
    require(sha(disk_path) == c['disk_sha256'], 'trusted disk hash mismatch')
    sides = []; segments = []
    with committed_volume(Path(disk_path)) as (current, metadata):
        volume = inspect_committed(current, metadata)
        require(volume['uuid'] == c['disk_uuid'] and volume['boot_epoch'] == boot_epoch, 'volume identity mismatch')
        for name in sorted(set(volume['files']) | set(volume['directories'])):
            if not any(part.startswith('lr-') for part in name.split('/')):
                continue
            match = re.fullmatch(r'/lr-([0-9a-f]{16})-([0-9a-f]{4})', name)
            require(match is not None and int(match[1], 16) == boot_epoch and name in volume['files'],
                    'malformed/wrong-boot archive path')
            segments.append(int(match[2], 16))
            node = volume['files'][name]
            require(0 < node['size'] <= MAX_FILE and node['durable_write_seq'] > 0, 'empty/unbounded archive')
            raw = bytearray()
            for _, start, blocks in node['extents']:
                for block in range(start, start + blocks):
                    raw += current(block)[:min(BLOCK, node['size'] - len(raw))]
            require(len(raw) == node['size'] and digest(raw) == node['sha256'], 'committed archive hash mismatch')
            offset = 0
            while offset < len(raw):
                side = _side(memoryview(raw)[offset:], c)
                side.update(path=name, inode=node['inode'], inode_generation=node['generation'],
                            durable_write_seq=node['durable_write_seq'], offset=offset,
                            archive_sha256=node['sha256'], archive_bytes=bytes(raw))
                sides.append(side); offset += side['length']
    require(segments == list(range(len(segments))), 'missing/reordered archive segment')
    require(sha(disk_path) == c['disk_sha256'], 'disk changed during extraction')
    groups = {}
    identities = set()
    for side in sides:
        identity = (side['trial_id'], side['capture_generation'])
        require(identity not in identities, 'duplicate trial/generation')
        identities.add(identity)
        key = side['seed']
        group = groups.setdefault(key, {})
        require(side['side'] not in group, 'duplicate side')
        group[side['side']] = side
    pairs = []
    for group in groups.values():
        require(set(group) == {'Baseline', 'Candidate'}, 'missing side pair')
        b, a = group['Baseline'], group['Candidate']
        require(b['trial_id'] != a['trial_id'] and b['capture_generation'] != a['capture_generation'], 'same trial/generation pair')
        for key in ('boot_epoch', 'family', 'target', 'seed', 'workload_sha256', 'initial_image_sha256',
                    'frozen_other_domains_sha256', 'schema_hashes', 'node_id', 'relative_arrivals'):
            require(b[key] == a[key], 'contradictory pair identity: ' + key)
        pairs.append(dict(baseline=b, candidate=a, model_sha256=c['model_sha256'], **PROOF_LIMITS))
    require(len(pairs) >= minimum_pairs, 'insufficient committed pairs')
    return pairs


def _schema_context(context):
    """Bind the restricted C4 schema semantics to the already trusted source closure."""
    source = Path(context['paths']['source_root'])
    for name, expected in (('features.rs', SCHEMAS[0]), ('policy_wire.rs', SCHEMAS[1])):
        relative = 'crates/prototype/src/' + name
        require(context['source_map'][relative] == expected == sha(source / relative), 'unsupported source schema')
    relative = 'crates/prototype/src/learning.rs'
    raw = (source / relative).read_bytes()
    require(digest(raw) == context['source_map'][relative], 'learning source changed')
    for function, expected in (('reward_schema', SCHEMAS[2]), ('learning_config', SCHEMAS[3])):
        match = re.search(rb'pub fn ' + function.encode() + rb'\(\) -> SchemaBinding \{\s*binding\(b"([^"\n]*)"\)', raw)
        require(match is not None, 'unsupported learning semantic source')
        literal = match[1].replace(b'\\0', b'\0')
        require(b'\\' not in literal and digest(literal) == expected, 'unsupported learning semantic schema')
    return dict(context, schema_hashes=list(SCHEMAS))


def _exports(pairs):
    files = {}
    def visit(value):
        if isinstance(value, list):
            return [visit(v) for v in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key in ('archive_bytes', 'raw_bytes'):
                name = ('archive-' + value['path'][1:] + '.bin' if key == 'archive_bytes' else
                        'side-' + value['path'][1:] + '-%08x.bin' % value['offset'])
                require(name not in files or files[name] == item, 'conflicting raw export')
                files[name] = item
                result[key.replace('_bytes', '_export')] = dict(file=name, bytes=len(item), sha256=digest(item))
            else:
                result[key] = visit(item)
        return result
    return dict(schema=1, pairs=visit(pairs), **PROOF_LIMITS), files


def verify_pair_capture(directory, *, source_root, build_manifest, formatter, qemu_binary, qemu_source,
                        save_exports=False, producer_tools_root=None, exports_directory=None):
    """Fixed custody + committed extraction + saved-export replay, never summary authority.

    Explicit save_exports=True creates exclusive exports. Offline callers select
    a separate exports_directory and a trusted producer_tools_root; neither is
    selected by archived data. The original native capture is never rewritten.
    Independent replay compares saved exports against a fresh committed view.
    """
    require(type(save_exports) is bool, 'invalid export mode')
    require(not (save_exports and producer_tools_root is not None and exports_directory is None),
            'frozen producer replay requires separate exports directory')
    root = Path(directory)
    require(not root.is_symlink(), 'linked capture directory')
    root = root.resolve(strict=True)
    exports = root / 'learning-archives' if exports_directory is None else Path(exports_directory)
    if exports_directory is not None:
        # Reject lexical, symlink and parent aliases before creating anything.
        resolved = exports.resolve(strict=False)
        require(not exports.is_symlink() and resolved != root and root not in resolved.parents
                and resolved not in root.parents, 'explicit exports alias original capture')
        exports = resolved
    checked = verify_capture(root, source_root=source_root, build_manifest=build_manifest,
                             formatter=formatter, qemu_binary=qemu_binary, qemu_source=qemu_source,
                             producer_tools_root=producer_tools_root)
    context = _schema_context(checked['trusted_context'])
    pairs = extract_local_pair(root / 'disk.raw', trusted_capture_context=context, boot_epoch=checked['boot_epoch'])
    manifest, files = _exports(pairs)
    if save_exports:
        exports.mkdir(mode=0o700)
        for name, raw in files.items():
            with (exports / name).open('xb') as stream:
                stream.write(raw)
        with (exports / 'manifest.json').open('x') as stream:
            json.dump(manifest, stream, sort_keys=True, indent=2, allow_nan=False); stream.write('\n')
    require(exports.is_dir() and not exports.is_symlink()
            and {p.name for p in exports.iterdir()} == set(files) | {'manifest.json'}, 'missing/extra raw exports')
    require(all(not p.is_symlink() and p.is_file() for p in exports.iterdir()), 'linked/nonfile raw export')
    require((exports / 'manifest.json').stat().st_size <= MAX_FILE
            and json.loads((exports / 'manifest.json').read_text()) == manifest, 'raw archive manifest mismatch')
    for name, raw in files.items():
        path = exports / name
        require(path.stat().st_size == len(raw) and path.read_bytes() == raw, 'saved raw archive differs from committed disk')
    return dict(version=checked['version'], released_pair_observed=True, capture_complete=True,
                boot_epoch=checked['boot_epoch'], boundary=checked['boundary'],
                producer_tools_root=checked['producer_tools_root'],
                checker_identity=checked['checker_identity'], exports_directory=str(exports),
                archive_manifest_sha256=sha(exports / 'manifest.json'), pairs=manifest['pairs'], **PROOF_LIMITS)
