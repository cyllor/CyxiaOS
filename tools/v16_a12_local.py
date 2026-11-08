"""Fixed C4 Local-admission component; never a whole A12/native verdict.

Caller supplies the trusted source root, build and independently authenticated
capture inventory. This module never imports code or selects a root from a
receipt. Only fixed node-1 protected banks supply admission observations.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

COMPILED_SHA256 = '60c336577974f21545bf29f6babccc0575376cb070abb8157ba2be83f6357f93'
REVIEW_SHA256 = '2449c3ebc24bef06f50b0516ffd9869d71ab2166f89068fd6d16def516c8f3aa'
PINNED_SOURCES = {
    'kernel/src/domain_tasks.rs': '884a1681101a5c4a49cbcd09da4a0edebaf6fd89ab02f2b81601bb3d73d2f060',
    'kernel/src/domain_tasks/abi.rs': 'd9604297d61d3913c78057dbfb1fcdf8813a63a3d70557234b9f3e3cc00c00a5',
    'kernel/src/domain_tasks/execution.rs': '57c4066558ec68de56faa5acbb5994ab8cc03d65b2be67fc279d425049f42f5f',
    'kernel/src/local_placement.rs': '523e6a4628a0d8a59b8b0763841896165de7e417f4e63815209b0b17dafe42ad',
    'kernel/src/local_request_diagnostic.rs': 'b2a20f619cef15e5d8de4f0fcd042863433c71d1181a21433e3fd9b565946bb4',
    'kernel/src/domain_network/requests.rs': 'e4b98bb643995efd53873fea9a2d69120cfee392351d94c800c69626088c4ad8',
    'kernel/src/domain_network/requests_diagnostic.rs': '101aa7e0d0fc5d26480fea0f0499fcdb54372c14d60dbcc2156982459f28cc32',
    'kernel/src/domain_network/replay.rs': 'fb2bfe2dc447eb160888b56f2da3a821b85337e0e8531bd27794da43702fdaac',
    'kernel/src/unified.rs': 'd430201036395b384cd4bfb00ffb977f318a9a1af91d70814d6f05adcf17ddf0',
    'kernel/src/unified_task.rs': '3ca970e65394ee293a8029076d524f373345792575ecb681dc782e660be09724',
    'crates/prototype/src/domains/tasks/spawn.rs': '4f389a0c68f1fbd206d7e18d45c1c694eb4cca24d70aee589eaff83087604c29',
    'crates/prototype/src/domains/tasks/scheduler.rs': '558958c952e36e46443a88dc6fd86f78b1dcb94fefa37f612ffb241942e9f5ee',
    'user/prototype-cluster/src/driver/domain.rs': '89229e0258e087abbaf34cbbb7baa1e9274682b91e847d8cde5ad4ec99bbfe62',
    'user/prototype-cluster/src/driver/application.rs': '911fbcf3b2c5da6b91e303da9874cd956145452547c3c288f91be26525e7ad62',
    'user/prototype-cluster/src/application.rs': '234f5531f3ef11ece39726ba9795b9b2fcbbc204c87bdb4cfc90c5c5ae996bf7',
}
U64_MAX = 2**64 - 1


def require(condition, message):
    if not condition:
        raise ValueError('A12 Local: ' + message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def _read(root, relative, maximum=4 * 1024 * 1024):
    path = root / relative
    require(not any(p.is_symlink() for p in [path, *path.parents] if p != root.parent),
            'symlink in fixed input path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                'input is not a bounded regular file')
        chunks = []
        count = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, maximum + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            require(count <= maximum, 'input grew beyond bound')
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                and count == before.st_size, 'input changed while read')
        return b''.join(chunks)
    finally:
        os.close(fd)


def _inventoried(capture, name, inventory):
    data = _read(capture, name)
    require(inventory.get(name) == sha256(data), 'inventory SHA differs: ' + name)
    return data


def _bank(data, magic, slots, width, label):
    require(len(data) == (8 + slots * width) * 8, label + ' byte size differs')
    words = struct.unpack('<' + str(8 + slots * width) + 'Q', data)
    require(words[0] > 0 and words[0] % 2 == 0
            and words[1:5] == (magic, 1, slots, width)
            and words[0] == 2 * words[5] and words[6:8] == (0, 0),
            label + ' header/publication/replacement/reserved differs')
    rows = []
    identities = set()
    for slot in range(slots):
        row = words[8 + slot * width:8 + (slot + 1) * width]
        if not any(row):
            continue
        require(row[0] > 0 and row[1] > 0 and row[:2] not in identities,
                label + ' duplicate/empty request identity')
        identities.add(row[:2])
        rows.append((slot, row))
    return words[:8], rows


def _applications(data):
    header, rows = _bank(data, 0x4359415050513031, 32, 24, 'application')
    actor_sequences = set()
    generations = set()
    total = 0
    result = {}
    for slot, r in rows:
        require(4097 <= r[0] <= 8192 and (r[0] - 4097) % 32 == slot,
                'application request slot differs')
        require(0x1000 <= r[2] < 0x1000 + 60 and r[3] > 0 and r[4] > 0,
                'actual actor full task identity differs')
        require(r[2:5] not in actor_sequences, 'duplicate actor/sequence')
        actor_sequences.add(r[2:5])
        generations.add(r[1])
        require(r[5] <= r[6] and r[8] == 0 and 1 <= r[7] <= 8
                and r[14] & ~7 == 0, 'application timing/stage/flags differs')
        require(r[9] in range(6)
                and (r[10:12] == (0, 0) if r[9] in (0, 1, 5) else
                     r[10] > 0 and (r[11] == 0 if r[9] == 4 else r[11] > 0)),
                'application state/target differs')
        complete = bool(r[14] & 4)
        require((complete and r[12] in (1, 2) and r[5] <= r[13] <= r[6])
                or (not complete and r[12] == r[13] == 0),
                'application completion differs')
        counts = r[15:23]
        require(counts[0] + counts[5] > 0 and counts[r[7] - 1] > 0
                and 0 < sum(counts) <= header[5] and r[5] <= r[23] <= r[6],
                'application stage counters differ')
        total += sum(counts)
        result[r[:2]] = r
    require(len(generations) <= 1 and total == header[5],
            'application boot generation/publication accounting differs')
    return header, result


def _locals(data):
    header, rows = _bank(data, 0x43594c5245513031, 8, 32, 'local')
    result = {}
    spawns = set()
    total = 0
    for slot, r in rows:
        require(0 < r[2] <= 256 and (r[2] - 1) % 8 == slot
                and r[2] not in spawns and r[3] in (11, 12, 27)
                and r[4] <= 5 and r[5] <= 24 and r[6] == 0,
                'local identity/slot/return differs')
        spawns.add(r[2])
        require(r[8] in range(5) and r[7] <= 20 and r[9] <= 20
                and all(r[i] in (0, 1) for i in (12, 13, 14))
                and r[15] > 0 and r[16] <= r[17]
                and 0 < r[26] <= 3984 and r[26] % 8 == 0,
                'local state/timing/input length differs')
        require((r[8] == 1 and 0x1000 <= r[10] < 0x1000 + 56 and r[11] > 0)
                or (r[8] != 1 and r[10] == r[11] == 0),
                'local task full identity differs')
        require((r[8] == 2 and r[9] > 0) or (r[8] != 2 and r[9] == 0),
                'local failure state differs')
        require(not r[12] or r[8] == 3, 'local retry permission differs')
        counts = r[18:21]
        require(counts[{11: 0, 12: 1, 27: 2}[r[3]]] > 0
                and 0 < sum(counts) <= header[5]
                and r[21] <= counts[0] and r[22] <= sum(counts),
                'local phase/owner counters differ')
        total += sum(counts)
        require(r[23] in (0, 11, 12) and (r[24] in range(5) or r[24] == U64_MAX)
                and r[25] <= 20, 'local owner shape differs')
        require((r[23] == 0 and r[24] == U64_MAX and r[25] == r[7] == 0)
                or (r[23] != 0 and (
                    (r[25] > 0 and r[24] == U64_MAX and r[7] == r[25])
                    or (r[7] == 0 and r[24] in range(5)
                        and ((r[24] == 2 and r[25] > 0)
                             or (r[24] != 2 and r[25] == 0))))),
                'local owner result binding differs')
        require(r[27] in (0, 1, 2) and r[13] == (r[27] != 0)
                and (not r[14] or r[13] and r[8] == 1)
                and ((r[27] == 1 and r[29] == 0 and r[28] <= r[17])
                     or (r[27] == 2 and r[28] == 0 and 0 < r[29] <= 20)
                     or (r[27] == 0 and r[28] == r[29] == 0))
                and r[30:] == (0, 0), 'local completion/reserved differs')
        result[r[:2]] = r
    require(total == header[5], 'local publication accounting differs')
    return header, result


def _join_records(applications, locals_):
    local_apps = {key: row for key, row in applications.items() if row[9] == 2}
    require(bool(local_apps), 'no genuine Local application target')
    joins = []
    targets = set()
    for key, a in local_apps.items():
        require(key in locals_, 'Local application lacks same full request')
        l = locals_[key]
        require(a[12] == 1 and a[14] == 5 and a[15] > 0 and a[16] > 0
                and a[17] > 0 and a[19] > 0 and a[20:23] == (0, 0, 0),
                'Local application lacks ordinary successful completion')
        require(l[3:10] == (27, 0, 16, 0, 0, 1, 0)
                and l[12:15] == (0, 1, 1) and l[25] == 0
                and l[27] == 1 and l[29] == 0
                and l[18] > 0 and l[19] > 0 and l[20] > 0
                and l[21] > 0 and l[22] > 0,
                'Local lacks Created/no-error/actual submit-query/completion/ack')
        require(a[10:12] == l[10:12] and a[13] == l[28]
                and a[5] <= l[28] <= l[16] <= l[17],
                'request/target generation/completion timing cross-bank differs')
        require(l[10:12] not in targets and a[2:4] != l[10:12],
                'duplicate target or actor replaced by child')
        targets.add(l[10:12])
        joins.append({'request': list(key), 'actor': list(a[2:4]),
                      'sequence': a[4], 'spawn_id': l[2],
                      'target_task': list(l[10:12]), 'submitted_ns': a[5],
                      'completion_ns': l[28], 'original_deadline_ns': l[15]})
    for key, l in locals_.items():
        if l[8] == 1:
            require(key in local_apps, 'Created broker row lacks same Local application')
    return joins


def verify_local_admission(capture: Path, source_root: Path,
                           build: dict, inventory: dict) -> dict:
    """Verify a conservative existential Local component from fixed raw banks.

    Full ELF/QEMU/protected-symbol/stopped-snapshot custody and the four other
    A12 predicates remain mandatory at the caller. No final-diagnostics input.
    """
    capture, source_root = Path(capture), Path(source_root)
    require(capture.is_dir() and source_root.is_dir(), 'caller directories missing')
    code = build.get('code_source_map')
    require(isinstance(code, dict) and build.get('code_source_sha256') == COMPILED_SHA256
            and sha256(json.dumps(code, sort_keys=True, separators=(',', ':')).encode())
            == COMPILED_SHA256, 'fixed compiled source map differs')
    build_bytes = _inventoried(capture, 'build-manifest.json', inventory)
    raw_build = {k: v for k, v in build.items()
                 if k not in ('caller_paths', 'caller_manifest_path')}
    require(json.loads(build_bytes, object_pairs_hook=_unique_object) == raw_build,
            'explicit trusted build differs from capture build')
    manifest_bytes = _inventoried(capture, 'source-manifest.json', inventory)
    manifest = json.loads(manifest_bytes, object_pairs_hook=_unique_object)
    require(isinstance(manifest, dict), 'source manifest not a map')
    for relative, expected in PINNED_SOURCES.items():
        require(code.get(relative) == manifest.get(relative) == expected
                and sha256(_read(source_root, relative)) == expected,
                'reviewed fixed source differs: ' + relative)
    names = ('node-1/final-APPLICATION_REQUEST_EVIDENCE.bin',
             'node-1/final-LOCAL_REQUEST_EVIDENCE.bin')
    app_bytes, local_bytes = (_inventoried(capture, n, inventory) for n in names)
    app_header, applications = _applications(app_bytes)
    local_header, locals_ = _locals(local_bytes)
    joins = _join_records(applications, locals_)
    return {
        'local_native_admission_verified': True,
        'local_admission_component_verified': True,
        'whole_native_case_verified': False,
        'scope': 'Fixed C4 node-1 Local positive source-derived admission witness only',
        'compiled_source_sha256': COMPILED_SHA256,
        'review_sha256': REVIEW_SHA256,
        'reviewed_source_sha256': dict(PINNED_SOURCES),
        'source_assumptions_map': dict(PINNED_SOURCES),
        'source_assumptions_sha256': sha256(json.dumps(
            PINNED_SOURCES, sort_keys=True, separators=(',', ':')).encode()),
        'raw_sha256': dict(zip(names, (sha256(app_bytes), sha256(local_bytes)))),
        'rawfiles_used': dict(zip(names, (sha256(app_bytes), sha256(local_bytes)))),
        'source_manifest_sha256': sha256(manifest_bytes),
        'build_manifest_sha256': sha256(build_bytes),
        'bank_publications': {'application': app_header[5], 'local': local_header[5]},
        'verified_joins': joins,
        'joined_requests': joins,
        'joined_request_count': len(joins),
        'limitations': [
            'Caller must verify original capture/ELF/QEMU/protected-symbol/stopped custody.',
            'The other A12 boot/discovery/authentication/config predicates are not assessed here.',
            'These bounded banks are positive witnesses, not authority or complete history.',
            'Historical input/package/layout/Scheduler tuple is source-derived; not stored in these rows.',
            'No remote Authority/STARTED/result lifecycle or A13/A14 verdict is produced.',
            'Original full producer FAIL and all earlier failures remain unchanged.',
        ],
    }
