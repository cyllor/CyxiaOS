"""Fixed read-only A12 pair components; admission and caller trust are separate.

The caller verifies the complete inventory, image/disk hashes, trusted source,
QEMU and formatter first. No summary verdict or receipt-supplied Python is used.
``build`` is that trusted build manifest plus ``caller_paths`` for the two node
ELFs, the two public keys and task.elf. No private key is read.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct

import check_elf
import check_v13_boot_disk as boot_disk
import check_v13_disk
import check_v13_filesystem
import cluster_native_journal
import decode_discovery
import discovery_capture
import transport
import verify_unified_capture
import verify_unified_disk as durable
import verify_v13_tcp
import verify_smp


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _read(path: Path, limit: int) -> bytes:
    require(path.is_file() and not path.is_symlink(), 'missing/nonregular input: ' + str(path))
    require(0 < path.stat().st_size <= limit, 'input size bound: ' + str(path))
    return path.read_bytes()


def _json(path: Path, limit=2 * 1024 * 1024):
    return json.loads(_read(path, limit))


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _serial(raw: bytes, node: int, boot: int, unified: tuple) -> dict:
    decoder = transport.FrameDecoder()
    text = b''.join(decoder.feed(raw))
    require(not decoder.buffer and not decoder.corrupt and not decoder.loss
            and decoder.frames > 0 and decoder.session == boot,
            'invalid/incomplete framed serial')
    for marker in (b'BOOT_ENTRY v1 EL1 CPU0 BOOTSTRAP\n',
                   b'PLATFORM_OK DTB RAM UART GIC TIMER BOOTSTRAP\n',
                   b'HIGH_VA_OK BOOTSTRAP\n', b'SMP_BOOT_OK a=4 b=15 c=0\n',
                   b'STORAGE_V13_BOOT_DURABLE\n', b'ENTROPY_READY VIRTIO MECHANISM\n',
                   ('UNIFIED_START node=%d boot=%d initiator=%d EL0_TLS\n' %
                    (node, boot, node - 1)).encode()):
        require(text.count(marker) == 1, 'missing/duplicate native boot marker: ' + repr(marker))
    events = [(int(a), int(b)) for a, b in
              re.findall(rb'^UNIFIED_SERVICE event=(\d+) arg1=0 arg2=0 ms=(\d+)\n',
                         text, re.MULTILINE)]
    count = unified[6]
    require(0 < count <= 200, 'invalid/truncated unified event count')
    protected = [(unified[32 + 2*i], unified[33 + 2*i]) for i in range(count)]
    require(events == protected, 'framed serial/protected event rows differ')
    require(all(event in [e for e, _ in events] for event in (1, 2, 3, 0x210, 0x211)),
            'missing native startup/authentication/CONFIRMED/BOUND event')
    require(not any(e & (1 << 63) or 0xfe <= e <= 0x108 or e >= 0xf000 for e, _ in events),
            'fatal/rejected native service event')
    return dict(decoded=text, frames=decoder.frames, loss=decoder.loss, corrupt=decoder.corrupt,
                session=decoder.session, events=events)


def _qmp(rows: list, launch: dict, folder: Path, locations: dict) -> dict:
    require(isinstance(rows, list) and 0 < len(rows) <= 40000, 'QMP transcript size bound')
    sent, responses, events = {}, {}, []
    for at, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == {'direction', 'message'}, 'QMP row shape')
        msg = row['message']
        require(isinstance(msg, dict), 'QMP message shape')
        if row['direction'] == 'send':
            key = msg.get('id')
            require(type(key) is int and key > 0 and key not in sent, 'duplicate/invalid QMP request id')
            require(msg.get('execute') in {'qmp_capabilities', 'query-cpus-fast',
                    'query-memory-size-summary', 'cont', 'ringbuf-read', 'pmemsave', 'stop', 'quit'},
                    'unreviewed QMP command')
            sent[key] = (at, msg)
        elif row['direction'] == 'receive':
            if 'id' in msg:
                key = msg['id']
                require(key in sent and key not in responses and sent[key][0] < at
                        and 'return' in msg and 'error' not in msg, 'unmatched/failed QMP response')
                responses[key] = (at, msg['return'])
            elif 'event' in msg:
                events.append((at, msg))
            else:
                require(at == 0 and 'QMP' in msg, 'unexpected QMP message')
        else:
            raise ValueError('invalid QMP direction')
    require(set(sent) == set(responses), 'incomplete QMP exchange')
    require([m['event'] for _, m in events] == ['RESUME', 'STOP', 'SHUTDOWN'],
            'missing/extra QMP RESUME/STOP/SHUTDOWN')

    def command(name):
        found = [(key, at, msg) for key, (at, msg) in sent.items() if msg['execute'] == name]
        require(len(found) == 1, 'expected one QMP ' + name)
        return found[0]

    cont, stop, quit_ = [command(name) for name in ('cont', 'stop', 'quit')]
    require(cont[1] < events[0][0] < stop[1] < events[1][0] < quit_[1] < events[2][0],
            'QMP lifecycle order differs')
    for key, _, msg in (cont, stop, quit_):
        require(responses[key][1] == {} and not msg.get('arguments'), 'QMP lifecycle result/args differ')
    require(events[2][1].get('data') == {'guest': False, 'reason': 'host-qmp-quit'},
            'not controlled QMP shutdown')
    for name, expected in (('query-cpus-fast', launch['cpus']),
                           ('query-memory-size-summary', launch['memory'])):
        key, at, _ = command(name)
        require(at < cont[1] and responses[key][1] == expected,
                'launch metadata differs from QMP ' + name)
    reads = {}
    for symbol, location in locations.items():
        path = str(folder / ('final-' + symbol + '.bin'))
        found = [(key, at, msg) for key, (at, msg) in sent.items()
                 if msg['execute'] == 'pmemsave' and msg.get('arguments', {}).get('filename') == path]
        require(len(found) == 1, 'missing/duplicate final QMP save: ' + symbol)
        key, at, msg = found[0]
        require(events[1][0] < at < responses[key][0] < quit_[1]
                and msg['arguments'] == dict(val=location['pa'], size=location['size'], filename=path)
                and responses[key][1] == {}, 'wrong/unpaused final QMP save: ' + symbol)
        reads[symbol] = dict(request_id=key, physical_address=location['pa'], bytes=location['size'])
    return dict(exchanges=len(sent), events=[m['event'] for _, m in events], stopped_bank_reads=reads)


def _same_proofs(nodes: list) -> list:
    require(len(nodes) == 2 and nodes[0]['profile_version'] == nodes[1]['profile_version'],
            'mixed/missing durable schemas')
    require(nodes[0]['local'] == nodes[1]['peer'] and nodes[1]['local'] == nodes[0]['peer'],
            'durable cross-pair identities differ')
    require(all(n['member'] == 'bound' and n['proofs'] for n in nodes), 'missing durable BOUND proof')
    require(set(nodes[0]['proofs']) == set(nodes[1]['proofs']), 'nodes hold different BOUND proofs')
    result = []
    for proof in dict.fromkeys(nodes[0]['proofs']):
        c = durable.config(proof[:252], schema_version=nodes[0]['profile_version'])
        frozen = [n['formation_locks'][c['formation']][2] for n in nodes]
        require(c['epoch'] == max(frozen) + 1, 'wrong formation epoch/frozen lower bound')
        result.append(dict(proof_sha256=_sha(proof), config_sha256=_sha(c['bytes']),
                           formation_id=c['formation'].hex(), cluster_id=c['cluster'].hex(),
                           config_epoch=c['epoch'], frozen_epochs=frozen,
                           nodes=[n.hex() for n in c['nodes']]))
    return result


def _discovery(bank_raw: bytes, pcap: bytes, pins: list, index: int, boot: int) -> tuple:
    bank = decode_discovery.decode(bank_raw, boot=boot)
    require(bank.get('local_node') == pins[index-1].hex()
            and bank.get('peer_node') == pins[2-index].hex(), 'discovery identity differs')
    wire = discovery_capture.validate_discovery_capture(pcap, {1: pins[0], 2: pins[1]}, bank)
    return bank, wire


def verify_pair_components(capture: Path, source_root: Path, build: dict,
                           qemu_source: Path, inventory: dict) -> dict:
    """Replay only boot/discovery/native mTLS/config; never return whole A12 PASS.

    Inventory is mandatory caller context, not an executable import or a verdict.
    Full inventory/source/QEMU/formatter/512MiB disk hash validation and actual
    Local owner admission belong to the caller. The result identifies used files.
    """
    capture, source_root, qemu_source = map(Path, (capture, source_root, qemu_source))
    require(capture.is_absolute() and source_root.is_absolute() and qemu_source.is_absolute(),
            'explicit absolute caller roots required')
    require(isinstance(inventory, dict) and bool(inventory), 'caller inventory required')
    require(build.get('status') == 'BUILT_NOT_RUN' and build.get('schema_version') == 1,
            'invalid caller build manifest')
    imported = (check_elf, boot_disk, check_v13_disk, check_v13_filesystem,
                cluster_native_journal, decode_discovery, discovery_capture, transport,
                verify_unified_capture, durable, verify_v13_tcp, verify_smp)
    for module in imported:
        require(Path(module.__file__).resolve() == (source_root / 'tools' / (module.__name__ + '.py')).resolve(),
                'fixed verifier dependency is outside caller trusted source')
    paths = build.get('caller_paths', {})
    names = ('node-a.elf', 'node-b.elf', 'node-a.pub', 'node-b.pub', 'task.elf')
    require(all(name in paths and Path(paths[name]).is_absolute() for name in names),
            'explicit caller_paths for five public build artifacts required')
    artifact_data = {name: _read(Path(paths[name]), 128 * 1024 * 1024) for name in names}
    for name, data in artifact_data.items():
        require(_sha(data) == build['artifacts'][name]['sha256']
                and len(data) == build['artifacts'][name]['bytes'], 'caller build artifact differs: ' + name)
    publics = [artifact_data['node-a.pub'], artifact_data['node-b.pub']]
    require(all(len(p) == 32 for p in publics), 'invalid pinned public keys')
    pins = [hashlib.sha256(p).digest() for p in publics]
    require(pins[0] != pins[1] and build.get('own_private_key_only_verified') is True,
            'cloned node identity or missing per-node key audit')
    for i, name in enumerate(('a', 'b')):
        require(build['nodes'][name]['node_id'] == pins[i].hex()
                and build['nodes'][name]['peer_node_id'] == pins[1-i].hex(), 'build identities not mutually pinned')
    source_paths = ('crates/cluster-transport/src/tls.rs',
                    'user/prototype-cluster/src/main.rs', 'user/prototype-cluster/src/runtime.rs',
                    'user/prototype-cluster/src/runtime_turn.rs', 'user/prototype-cluster/src/broker.rs',
                    'user/prototype-cluster/src/driver.rs', 'user/prototype-cluster/src/session_exit.rs',
                    'kernel/src/runtime/cluster/unified.rs')
    source_hashes = {}
    for name in source_paths:
        digest = _sha(_read(source_root / name, 1024 * 1024))
        require(build['code_source_map'].get(name) == digest, 'built authentication source differs: ' + name)
        source_hashes[name] = digest
    used, observations, disks, journals = {}, [], [], []
    for index in (1, 2):
        folder = capture / ('node-%d' % index)
        node_name = ('a', 'b')[index - 1]
        launch = _json(folder / 'launch.json')
        require(type(launch.get('exit')) is int and launch['exit'] == 0,
                'QEMU was not reaped with normal exit')
        argv = launch['argv']
        require(isinstance(argv, list) and all(type(v) is str for v in argv), 'launch argv shape')
        require(argv.count('-kernel') == 1 and argv.count('-smp') == 1 and '-S' in argv
                and '-no-reboot' in argv, 'native launch shape')
        require(Path(argv[argv.index('-kernel') + 1]).resolve() == Path(paths['node-' + node_name + '.elf']).resolve(),
                'launch uses a different caller ELF')
        require(Path(argv[0]).resolve() == (qemu_source / 'build/qemu-system-aarch64').resolve(),
                'launch uses a different caller QEMU source build')
        require(argv[argv.index('-smp') + 1] == '4' and len(launch['cpus']) == 4
                and {c['cpu-index'] for c in launch['cpus']} == {0, 1, 2, 3}
                and all(c['target'] == 'aarch64' for c in launch['cpus']), 'not four native AArch64 CPUs')
        require(launch['memory'] == {'base-memory': 1024 * 1024 * 1024, 'plugged-memory': 0},
                'native memory differs')
        elf = artifact_data['node-' + node_name + '.elf']
        check_elf.inspect_elf(elf)
        require(check_elf.boot_profile(elf)['ram_mib'] == 1024, 'ELF boot RAM profile differs')
        locations = {name: check_elf.symbol(elf, name) for name in ('UNIFIED_EVIDENCE', 'DISCOVERY_EVIDENCE', 'APPLICATION_REQUEST_EVIDENCE', 'LOCAL_REQUEST_EVIDENCE', 'DOMAIN_TASK_EVIDENCE')}
        require([locations[n]['size'] for n in locations] == [4096, 512, 6208, 2112, 256], 'capture symbol size differs')
        qmp_raw = _read(folder / 'qmp.jsonl', 8 * 1024 * 1024)
        rows = [json.loads(line) for line in qmp_raw.splitlines()]
        qmp = _qmp(rows, launch, folder, locations)
        u_raw = _read(folder / 'final-UNIFIED_EVIDENCE.bin', 4096)
        require(len(u_raw) == 4096, 'unified bank size differs')
        u = struct.unpack('<512Q', u_raw)
        require(u[0] == 0x435958554e493031 and u[1] == 1 and u[15] == 0
                and u[2] > 0 and u[4] > 0 and u[5] > 0
                and u[30] > 0 and u[30] == u[31] + 1, 'invalid native EL0/TLS/boot bank')
        serial_raw = _read(folder / 'serial.bin', 2 * 1024 * 1024)
        serial = _serial(serial_raw, index, u[1], u)
        require(serial['decoded'] == _read(folder / 'serial.txt', 2 * 1024 * 1024), 'decoded serial differs')
        require(launch['transport'] == dict(frames=serial['frames'], lost=serial['loss'], corrupt=serial['corrupt']),
                'launch transport counters differ')
        bank_raw = _read(folder / 'final-DISCOVERY_EVIDENCE.bin', 512)
        pcap = _read(folder / 'ethernet.pcap', 16 * 1024 * 1024)
        bank, discovery = _discovery(bank_raw, pcap, pins, index, u[1])
        tls = verify_unified_capture.validate_capture(pcap)
        before = _json(folder / 'disk-before.json')
        disk = boot_disk.inspect(folder / 'disk.raw')
        require(before['boot_epoch'] == 0 and disk['boot_epoch'] == 1
                and disk['uuid'] == before['uuid'], 'not same fresh native boot0 to1')
        journal = durable.verify_records(disk, dict(zip(pins, publics)), struct.pack('<4q', 1, 2, 3, 4),
                                         hashlib.sha256(artifact_data['task.elf']).digest())
        require(journal['local'] == pins[index-1] and journal['peer'] == pins[2-index],
                'durable node identity differs')
        disks.append(disk)
        journals.append(journal)
        for name in ('launch.json', 'qmp.jsonl', 'serial.bin', 'serial.txt', 'disk-before.json',
                     'final-UNIFIED_EVIDENCE.bin', 'final-DISCOVERY_EVIDENCE.bin',
                     'final-APPLICATION_REQUEST_EVIDENCE.bin', 'final-LOCAL_REQUEST_EVIDENCE.bin',
                     'final-DOMAIN_TASK_EVIDENCE.bin', 'ethernet.pcap'):
            path = folder / name
            used[str(path.relative_to(capture))] = _sha(path.read_bytes())
        observations.append(dict(node=index, uuid=disk['uuid'], boot_epoch=disk['boot_epoch'],
                                 local_node=journal['local'].hex(), peer_node=journal['peer'].hex(),
                                 qmp=qmp, serial_frames=serial['frames'],
                                 native_el0_returns=u[2], encrypted_io_bytes=[u[4], u[5]],
                                 authenticated_ms=[ms for e, ms in serial['events'] if e == 3],
                                 bound_ms=[ms for e, ms in serial['events'] if e == 0x211],
                                 ready_ms=[ms for e, ms in serial['events'] if e == 0x212],
                                 discovery=bank, controlled_wire_discovery=discovery, tls_wire_policy=tls,
                                 durable_member=journal['member']))
    require(disks[0]['uuid'] != disks[1]['uuid'], 'cloned filesystem UUID')
    proofs = _same_proofs(journals)
    return dict(scope='A12_PAIR_BOOT_DISCOVERY_NATIVE_MTLS_CONFIG_COMPONENTS_ONLY',
                components_verified=True, boot_verified=True, discovery_verified=True,
                mutual_authentication_verified=True, same_configuration_verified=True,
                uses_raw_records=True, whole_a12_verdict='NOT_ASSESSED_ADMISSION_REQUIRED',
                source_path_sha256=source_hashes, used_capture_sha256=used, nodes=observations,
                same_bound_proofs=proofs, native_mutual_tls_interpretation=
                'Both source-bound native services reached post-handshake pinned rustls traffic and '
                'guarded authenticated ingress before event3. PCAP alone does not decrypt CertificateVerify '
                'or prove peer identity. This is execution/source/identity composition, not remote attestation.',
                passive_pcap_peer_authentication=False, admission_verified=False,
                a13_a14_verified=False, runtime_failure_fixed=False)
