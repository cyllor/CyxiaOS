"""Read-only replay of captured NBD bytes and durability events, not filesystem recovery.

V1 uses absolute mutation ordinals. V2 preserves those as raw_mutation and
independently reconstructs a second ordinal starting at an explicit arm event.
Preparation FLUSH requests retain their real persistence semantics and bytes;
they are not fault candidates. Preparation WRITE makes a v2 capture invalid.
"""
from __future__ import annotations
import hashlib
import gzip
import json
from pathlib import Path
import re
import struct
from verify_smp import require, sha
from check_prototype_evidence import _pairs, read_json


def trace_encoding(directory):
    encoding = read_json(directory/'start.json').get('trace_encoding', 'raw')
    require(encoding in ('raw', 'gzip'), 'unknown raw trace encoding')
    return encoding


def event_bytes(directory):
    compressed = trace_encoding(directory) == 'gzip'
    path = directory/('events.jsonl.gz' if compressed else 'events.jsonl')
    require(path.stat().st_size <= 128*1024*1024, 'fault trace budget')
    with (gzip.open(path, 'rb') if compressed else path.open('rb')) as stream:
        data = stream.read(128*1024*1024+1)
    require(len(data) <= 128*1024*1024, 'expanded fault trace budget')
    return data


def decode_events(raw: bytes):
    # Original bytes are separately hash-bound; strict parsing ensures that
    # two verifiers cannot disagree on the same duplicate-key/nonfinite row.
    require(raw and raw.endswith(b'\n'), 'invalid fault JSONL framing')
    def reject_constant(value):
        raise ValueError('nonfinite fault event number: ' + value)
    result = []
    # Keep independent replay within the same bounded row budget as the scope
    # verifier, even when an attacker supplies millions of tiny valid JSON rows.
    for line in raw.splitlines():
        require(len(result) < 1_000_000, 'fault event row budget exceeded')
        row = json.loads(line, object_pairs_hook=_pairs,
                         parse_constant=reject_constant)
        require(type(row) is dict, 'fault event row must be a JSON object')
        result.append(row)
    return result


def read_events(directory):
    return decode_events(event_bytes(directory))


def inspect(initial: Path, final: Path, directory: Path) -> dict:
    start = read_json(directory/'start.json')
    version = start['version']
    require(type(version) is int and version in (1, 2)
            and start['size'] == initial.stat().st_size == final.stat().st_size,
            'fault trace format/size mismatch')
    require(start['disk_initial_sha256'] == sha(initial), 'fault trace starting image mismatch')
    require(start['phase'] in ('before', 'after-ack') and start['unflushed'] in ('drop', 'reverse-half')
            and type(start['cut']) is int and start['cut'] >= 0 and start['max_pending_sectors'] == 32768,
            'invalid fault configuration')
    event_clock = start.get('event_clock')
    require(event_clock in (None, 'host-monotonic-ns-v1'), 'invalid fault event clock')
    scoped = version == 2
    if scoped:
        require(start.get('mutation_scope') == 'post-arm-v1'
                and event_clock == 'host-monotonic-ns-v1'
                and type(start.get('arm_input_sha256')) is str
                and re.fullmatch('[0-9a-f]{64}', start['arm_input_sha256']) is not None
                and start['arm_input_sha256'] != '0' * 64, 'invalid explicit arming contract')
    else:
        require('mutation_scope' not in start and 'arm_input_sha256' not in start,
                'v1 trace cannot contain a scoped arming contract')
    armed = not scoped
    compressed = trace_encoding(directory) == 'gzip'
    raw_path = directory/('requests.bin.gz' if compressed else 'requests.bin')
    require(raw_path.stat().st_size <= 128*1024*1024, 'fault trace budget')
    events = event_bytes(directory)
    rows = decode_events(events)
    wire_hash = hashlib.sha256()
    pending, stable, requests = {}, {}, {}
    pending_version, durable_version = {}, {}
    complete, acknowledged = set(), set()
    mutations = raw_mutations = flushes = acknowledged_flushes = wire_at = last_ack = 0
    cut = None
    reordered = False
    with initial.open('rb') as source, (gzip.open(raw_path, 'rb') if compressed else raw_path.open('rb')) as raw:
        def read_visible(offset, length):
            source.seek(offset)
            result = bytearray(source.read(length))
            for relative in range(0, length, 512):
                image = pending.get(offset+relative, stable.get(offset+relative))
                if image is not None:
                    result[relative:relative+512] = image
            return bytes(result)

        previous_ns = -1
        for position, row in enumerate(rows):
            require(cut is None, 'event after power cut')
            if event_clock is not None:
                require(type(row.get('monotonic_ns')) is int and row['monotonic_ns'] >= previous_ns,
                        'missing/unordered fault event clock')
                previous_ns = row['monotonic_ns']
            event = row['event']
            if event == 'option':
                require(not requests and not (scoped and armed), 'NBD option after transmission/arm')
                continue
            if event == 'arm':
                require(scoped and not armed, 'duplicate or undeclared fault arming')
                require(row.keys() == {'event', 'monotonic_ns', 'input_sha256', 'requests',
                                       'raw_mutations', 'acks', 'flushes', 'pending_sectors'}
                        and row['input_sha256'] == start['arm_input_sha256']
                        and type(row['requests']) is int and row['requests'] == len(requests)
                        and type(row['raw_mutations']) is int and row['raw_mutations'] == raw_mutations
                        and type(row['acks']) is int and row['acks'] == len(acknowledged)
                        and type(row['flushes']) is int and row['flushes'] == flushes
                        and type(row['pending_sectors']) is int and row['pending_sectors'] == 0
                        and acknowledged == set(requests) and not pending,
                        'fault arming did not follow a fully acknowledged empty preparation')
                armed = True
                continue
            if event == 'request':
                header = raw.read(28)
                require(len(header) == 28, 'truncated raw NBD request')
                magic, flags, kind, handle, offset, length = struct.unpack('>IHHQQI', header)
                require(magic == 0x25609513 and flags == 0 and kind in (0, 1, 2, 3)
                        and offset+length <= start['size'] and offset % 512 == length % 512 == 0
                        and length <= 1024*1024, 'invalid raw NBD request')
                require((kind in (0, 1) and length > 0) or (kind in (2, 3) and offset == length == 0), 'invalid raw NBD range')
                body = raw.read(length) if kind == 1 else b''
                require(len(body) == (length if kind == 1 else 0), 'truncated raw write')
                wire_hash.update(header+body)
                require(row['data_sha256'] == hashlib.sha256(body).hexdigest(), 'request payload digest mismatch')
                mutable = kind in (1, 3)
                if mutable:
                    raw_mutations += 1
                    if armed:
                        mutations += 1
                require(not scoped or armed or kind in (0, 3),
                        'preparation WRITE/DISC invalidates the fault window')
                identity = len(requests)+1
                expected = dict(id=identity, kind=kind, handle=handle, offset=offset,
                                length=length, mutation=mutations if mutable and armed else 0,
                                wire_offset=wire_at)
                if scoped:
                    expected.update(raw_mutation=raw_mutations if mutable else 0,
                                    scope='armed' if armed else 'prepare')
                else:
                    require('raw_mutation' not in row and 'scope' not in row,
                            'scoped request mislabeled as v1')
                require(all(type(row.get(key)) is type(value) and row[key] == value
                            for key, value in expected.items()), 'raw request/event mismatch')
                requests[identity] = dict(expected, body=body,
                    read_hash=hashlib.sha256(read_visible(offset, length)).hexdigest() if kind == 0 else hashlib.sha256(b'').hexdigest())
                wire_at += 28+len(body)
                require(wire_at <= 128*1024*1024, 'expanded raw request budget')
                continue
            if event == 'disconnect':
                require(position == len(rows)-1 and row['pending_sectors'] == len(pending), 'invalid disconnect')
                continue
            identity = row['id']
            require(identity in requests, 'event without request')
            request = requests[identity]
            kind, offset, length = (request[key] for key in ('kind', 'offset', 'length'))
            if event == 'complete':
                require(identity not in complete and kind in (1, 3) and identity == len(requests), 'invalid completion order')
                require(not (start['cut'] != 0 and start['cut'] == request['mutation']
                             and start['phase'] == 'before'), 'completed before-cut request')
                if kind == 1:
                    for relative in range(0, length, 512):
                        pending[offset+relative] = request['body'][relative:relative+512]
                        pending_version[offset+relative] = identity
                    require(len(pending) <= 32768, 'volatile cache exceeded bound')
                else:
                    stable.update(pending); pending.clear(); flushes += 1
                    durable_version.update(pending_version); pending_version.clear()
                complete.add(identity)
                require(row['pending_sectors'] == len(pending) and row['flushes'] == flushes, 'completion durability mismatch')
            elif event == 'ack':
                require(identity not in acknowledged and (kind == 0 or identity in complete), 'ACK without completion/duplicate')
                require(row['reply'] == struct.pack('>IIQ', 0x67446698, 0, request['handle']).hex()
                        and row['data_sha256'] == request['read_hash'], 'NBD reply mismatch')
                if kind == 3:
                    for earlier in acknowledged:
                        write = requests[earlier]
                        if write['kind'] == 1:
                            require(all(durable_version.get(at, 0) >= earlier for at in
                                        range(write['offset'], write['offset']+write['length'], 512)),
                                    'FLUSH ACK omitted an already-ACKed write')
                reordered |= identity < last_ack
                last_ack = identity
                acknowledged.add(identity)
                acknowledged_flushes += kind == 3
            elif event == 'cut':
                require(armed and start['cut'] == row['mutation'] == request['mutation'] != 0
                        and start['phase'] == row['phase'] and identity == len(requests), 'wrong fault boundary')
                if scoped:
                    require(row.get('raw_mutation') == request['raw_mutation']
                            and request['scope'] == 'armed', 'cut raw identity/scope mismatch')
                if row['phase'] == 'before':
                    require(identity not in complete and identity not in acknowledged, 'before-cut request was completed')
                else:
                    require(identity in acknowledged and rows[position-1]['event'] == 'ack'
                            and rows[position-1]['id'] == identity, 'after-ack cut has no immediate ACK')
                offsets = sorted(pending, reverse=True)
                survivors = offsets[:(len(offsets)+1)//2] if start['unflushed'] == 'reverse-half' else []
                require(row['surviving_offsets'] == survivors and row['discarded_sectors'] == len(offsets)-len(survivors)
                        and row['acks'] == len(acknowledged) and row['flushes'] == flushes, 'fault durability mismatch')
                stable.update({at: pending[at] for at in survivors})
                cut = row
            else:
                raise ValueError('unknown fault event')
        require(armed, 'explicit fault arming was not captured')
        require(not raw.read(1), 'uncaptured raw NBD suffix')
        capture = directory/'capture.json'
        require(not compressed or capture.is_file(), 'compressed capture has no raw byte binding')
        if capture.is_file():
            require(read_json(capture) == dict(version=1,
                events_raw_sha256=hashlib.sha256(events).hexdigest(), requests_raw_sha256=wire_hash.hexdigest()),
                'raw capture digest mismatch')
        require((cut is not None) == (start['cut'] != 0), 'requested power cut was not captured')
        if cut is None:
            require(acknowledged == {identity for identity, row in requests.items() if row['kind'] != 2},
                    'clean disconnect omitted outstanding replies')
        # Compare every byte, including unchanged regions; never repair the disk.
        offsets = iter(sorted(stable))
        next_offset = next(offsets, None)
        source.seek(0)
        with final.open('rb') as actual:
            for at in range(0, start['size'], 1024*1024):
                wanted = bytearray(source.read(min(1024*1024, start['size']-at)))
                while next_offset is not None and next_offset < at+len(wanted):
                    relative = next_offset-at
                    wanted[relative:relative+512] = stable[next_offset]
                    next_offset = next(offsets, None)
                require(actual.read(len(wanted)) == wanted, f'durable disk differs at chunk {at}')
    result = dict(version=version, run_id=start['run_id'], requests=len(requests), mutations=mutations,
                  flushes=flushes, acknowledged_flushes=acknowledged_flushes,
                  reordered_replies=reordered, cut=cut, disk_final_sha256=sha(final))
    if scoped:
        result.update(raw_mutations=raw_mutations, mutation_scope='post-arm-v1')
    return result
