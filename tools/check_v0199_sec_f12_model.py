#!/usr/bin/env python3
"""Independent SEC-F12 state and wire checker for the bounded host trace.

The Rust producer runs the group quota ledger, ABI4 scratch file service,
and receipt/index transition verifier. This checker reconstructs the
expected outcomes, byte hashes and sequential write/ack evidence directly.
The structural image checks do not stand for a mounted durable transition.
"""

import argparse
import csv
import hashlib
import io
import itertools
import json
import platform
import struct
import subprocess
from collections import Counter
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIGN = 'docs/design/baselines/v0.19.9-implementation-spec.txt'
DESIGN_SHA = '16a53c5c4f89df55425ce6c3898e00175c05c9c1185e8926a9abd6c737782843'
HARNESS = 'crates/kernel-core/examples/v0199_sec_f12_model_check.rs'
SECURITY = 'crates/kernel-core/src/security/'
SOURCES = ('Cargo.lock', *(SECURITY + name + '.rs' for name in (
    'file', 'file_read_v4', 'file_service_v4', 'file_receipt_store_v0199', 'file_index_v0199',
    'file_media_v0199',
)))
COLUMNS = (
    'slot generation head ack_shape full stream_reuse stale recovery other_group other_pending '
    'writes readback still_full retire_ahead initial_retire retired_query retired_request replacement '
    'owner_pending media_pending media_unresolved media_straddling media_sha256 media_homes media_ack '
    'media_callback media_premature_reuse media_torn media_reopened_sha256'
).split()
SLOTS = (0, 21, 42, 85, 106)
ACKS = ('exact', 'missing_index', 'missing_home', 'wrong_principal', 'no_commit')
STATES = {2: 'Bound', 3: 'Done', 5: 'Unknown'}
UUID = b'F' * 16
BLOCK = 4096
RECORD = 192
GROUP_LIMIT = 8
WRITE_COUNT = 10
MAX_RAW_BYTES = 2 * 1024 * 1024
SCRATCH = b'CyxiaOS V0.20 signed scratch\n'


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def pack(fmt, *args):
    return struct.pack('<' + fmt, *args)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def crc_entry(byte):
    for _ in range(8):
        byte = (byte >> 1) ^ (0x82f63b78 if byte & 1 else 0)
    return byte


CRC_TABLE = tuple(map(crc_entry, range(256)))


def crc32c(raw):
    acc = 0xffffffff
    for byte in raw:
        acc = CRC_TABLE[(acc ^ byte) & 255] ^ (acc >> 8)
    return acc ^ 0xffffffff


def receipt(stream, seq, generation, state):
    done = state == 3
    id_ = (1 << 56) | (stream << 53) | seq
    wire = (
        pack('IHH16sQII7QHHiI', 0x43595243, 4, 192, UUID, generation, 0, generation,
             stream, 1 if seq == 1 else 2, seq, int(done), 11 if done else 0,
             13 if done else 0, 0, state, 0, 0, 0)
        + bytes([0 if state == 1 else 6]) * 32 + bytes([7 if done else 0]) * 32 + pack('QQ', id_, 101)
    )
    return wire + pack('I', crc32c(wire + bytes(4)))


def index_image(generation, replaced):
    wire = bytearray(BLOCK)
    wire[:40] = pack('IHH16sQQ', 0x43595349, 4, 64, UUID, 0, 12 if replaced else 10)
    for group in range(16):
        at = 64 + 24 * group
        enabled_generation = generation if group == 0 else int(group == 1)
        wire[at:at+24] = pack('IIQQ', enabled_generation, int(group < 2), enabled_generation, 101+group)
    for stream in range(9):
        at = 448 + 24 * stream
        if replaced and stream == 0:
            row = 2, 1, 2, 1
        else:
            row = 1, 1, 1, int(stream == 8)
        wire[at:at+24] = pack('IIQQ', *row)
    wire[-4:] = pack('I', crc32c(wire))
    return wire


@lru_cache(maxsize=None)
def media_hash(slot, generation, head, replaced):
    store = bytearray(6 * BLOCK)
    for stream in range(GROUP_LIMIT):
        at = RECORD * (slot if stream == 0 else 8 + stream)
        if stream == 0 and replaced:
            wire = receipt(0, 2, generation, 1)
        else:
            state = head if stream == 0 else 3 if stream == 7 else 2
            wire = receipt(stream, 1, 1, state)
        store[at:at+RECORD] = wire
    return sha(store + index_image(generation, replaced))


def expected_media(slot, generation, head, ack):
    crossing = (slot * RECORD) % BLOCK + RECORD > BLOCK
    if ack in ('missing_index', 'missing_home'):
        accepted, callback = 'err_Conflict', 0
    elif ack == 'wrong_principal':
        accepted, callback = 'err_Unauthorized', 0
    elif head != 3:
        accepted, callback = 'err_Busy', 0
    else:
        accepted, callback = ('ok_()' if ack == 'exact' else 'err_Unknown'), 1
    return (
        GROUP_LIMIT, 6 if head == 3 else 7, int(crossing), media_hash(slot, generation, head, False),
        1+int(crossing), accepted, callback, 'err_Invalid', 'err_Invalid',
        media_hash(slot, generation, head, True) if accepted == 'ok_()' else '-',
    )


@lru_cache(maxsize=None)
def writes(generation):
    expected = []
    for seq in range(1, WRITE_COUNT+1):
        # §9.6.1 Reply v3: volatile state, no durable transaction/reference,
        # target generation 1, with the digest calculated over zeroed field.
        wire = bytearray(128)
        wire[:24] = pack('IHHQQ', 0x43594652, 3, 128, seq+1, generation)
        wire[72:80] = pack('Q', 1)
        wire[120:128] = pack('Q', seq)
        digest = sha(wire)
        expected.append(','.join(map(str, (
            seq+1, seq, digest, digest, digest, 'ok_()', 'err_Stale', 'err_Conflict',
            1, 'ok_()', 'err_Stale', 'err_Stale', 1, 0, seq, GROUP_LIMIT,
        ))))
    return ';'.join(expected)


def verify(raw):
    rows = csv.reader(io.StringIO(raw.decode('ascii')), delimiter='\t', strict=True)
    require(next(rows, None) == COLUMNS, 'wrong trace header')
    missing = set(itertools.product(SLOTS, (1, 2), STATES, ACKS))
    coverage = Counter()
    crossing_slots = set()
    for row in rows:
        require(len(row) == len(COLUMNS) and all(row), f'line {rows.line_num}: wrong row shape')
        slot, generation, head = map(int, row[:3])
        ack = row[3]
        case = slot, generation, head, ack
        require(case in missing, f'line {rows.line_num}: duplicate or out-of-bounds case {case}')
        missing.remove(case)
        recovery = ','.join(['ok_' + STATES[head]] + ['ok_Bound'] * 6 + ['ok_Done'])
        expected = (
            'err_Capacity', 'err_Conflict', 'err_Stale', recovery, ','.join(['ok_()']*4), 0,
            writes(generation), (b'0123456789' + SCRATCH[10:]).hex(),
            'err_Capacity', 'err_Busy', {2:'err_Busy', 3:'ok_()', 5:'err_Unknown'}[head],
            'err_Stale', 'err_Stale', 'ok_()', GROUP_LIMIT,
            *expected_media(slot, generation, head, ack),
        )
        for field, got, wanted in zip(COLUMNS[4:], row[4:], map(str, expected), strict=True):
            # Avoid printing all ten raw per-write events in a failure log.
            require(got == wanted, f'{case}: {field} differs at row {rows.line_num}')
        data = dict(zip(COLUMNS, row, strict=True))
        coverage['cases'] += 1
        coverage['acknowledged_volatile_writes'] += len(data['writes'].split(';'))
        coverage['isolated_other_group_completions'] += 1
        coverage['protected_full_store_recovery_reads'] += len(data['recovery'].split(','))
        coverage['older_generation_rejections'] += generation == 2
        coverage['no_commit_retire_rejections'] += data['media_ack'] == 'err_Unknown'
        coverage['unknown_cannot_retire'] += data['initial_retire'] == 'err_Unknown'
        coverage['terminal_media_ack_transitions'] += data['media_ack'] == 'ok_()'
        if data['media_straddling'] == '1':
            crossing_slots.add(slot)
    require(not missing, f'missing {len(missing)} cases, first {min(missing) if missing else None}')
    require(crossing_slots == {21, 42, 85, 106}, 'missing straddling receipt positions')
    require(coverage['terminal_media_ack_transitions'] > 0
            and coverage['no_commit_retire_rejections'] > 0
            and coverage['older_generation_rejections'] > 0, 'vacuous receipt transition witness')
    coverage['distinct_straddling_slots'] = len(crossing_slots)
    return dict(sorted(coverage.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observed', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {
        'test_id': 'SEC-F12',
        'intended_proof_class': 'MODEL_CHECK',
        'formal_status': 'NOT_RUN',
        'scope': 'host quota contract, ABI4 volatile service, receipt/index structural validation',
        'checker_version': 1,
        'design_sections': ['main §9.6.1', 'security SEC-F12', 'security §7.4'],
        'baseline_sha256': DESIGN_SHA,
        'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'input_sources_sha256': {p: sha((ROOT/p).read_bytes()) for p in SOURCES},
        'checker_sha256': sha(Path(__file__).read_bytes()),
        'harness_source_sha256': sha((ROOT/HARNESS).read_bytes()),
        'harness_binary_sha256': sha(args.harness.read_bytes()),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'rustc': subprocess.check_output(['rustc', '-Vv'], cwd=ROOT, text=True).strip(),
        'cargo': subprocess.check_output(['cargo', '-V'], cwd=ROOT, text=True).strip(),
        'finite_domain': {
            'durable_tickets_in_group_a': GROUP_LIMIT,
            'successive_write_ack_pairs_per_case': WRITE_COUNT,
            'group_generations': [1, 2],
            'oldest_receipt_states': STATES,
            'receipt_slots': SLOTS,
            'ack_paths': ACKS,
        },
        'assumptions': [
            'group quota contract, scratch file service and per-stream media image are separate components',
            'synthetic authenticated principal, committed-image inputs and native-commit callback',
            'in-memory service only, no actual journal commit, redo, device FLUSH, restart or concurrent I/O',
            'recovery query observes retained records, without native recovery scheduling or new file work',
        ],
    }
    try:
        require(sha((ROOT/DESIGN).read_bytes()) == DESIGN_SHA, 'baseline content differs')
        with args.observed.open('rb') as source:
            raw = source.read(MAX_RAW_BYTES+1)
        require(len(raw) <= MAX_RAW_BYTES, 'raw trace exceeds fixed extent')
        report['raw_trace_sha256'] = sha(raw)
        report['coverage'] = verify(raw)
        report['bounded_check'] = 'MATCHED'
    except (OSError, ValueError, csv.Error) as error:
        report['bounded_check'] = 'COUNTEREXAMPLE_OR_INVALID_TRACE'
        report['detail'] = str(error)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps(report, indent=2))
    return int(report['bounded_check'] != 'MATCHED')


if __name__ == '__main__':
    raise SystemExit(main())
