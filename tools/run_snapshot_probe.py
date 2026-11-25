#!/usr/bin/env python3
"""Source-bound, two-node immutable-snapshot native smoke observation.

This runs the opt-in EL0 ordinary/recovery probe and independently checks each
stopped v2 disk. It does not invoke the ordinary unified acceptance oracle and
does not certify the R01-R30 acceptance matrix or crash/fault coverage.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import time

from doctor import ROOT
from check_elf import symbol
import check_v2_filesystem as disk_v2
from run_qemu import Qmp
from transport import FrameDecoder
from verify_smp import manifest, require, sha
from verify_unified import attest_qemu, bind_build, capture, profile


PROBE_SYMBOL = 'SNAPSHOT_PROBE_EVIDENCE'
PROBE_MAGIC = 0x4359534E415031
PROBE_SCHEMA = 2
PROBE_BYTES = 128
EXTRA_DIAGNOSTICS = {'CONTROL_SETTLEMENT_EVIDENCE': 512,
                     'BASELINE_SERVICE_EVIDENCE': 1024,
                     'LEARNING_PREWARM_FIRST_FAILURE': 256}
VALUE = '/snapshot-probe/value'
KEY_FILE = '/snapshot-probe/key'
READY = '/snapshot-probe/ready'
BEFORE = b'snapshot before!'
BEFORE_SHA256 = hashlib.sha256(BEFORE).hexdigest()
SCOPE = ('Two-node immutable snapshot smoke: real EL0 ordinary/recovery actors, '
         'stopped memory, and independent v2 committed disk inspection. '
         'Not R01-R30 acceptance, a crash matrix, or real-hardware verification.')
SCOPES = ('full-unified', 'local-filesystem')


def scope_evidence(scope):
    require(scope in SCOPES, 'unknown native smoke scope')
    return dict(scope=scope, scope_description=SCOPE, full_unified_accepted=False,
                peer_network_enabled=scope == 'full-unified',
                network_isolation=('Each QEMU uses its own one-port internal hub; '
                                   'no peer socket, host network, or TCP peer is attached.'
                                   if scope == 'local-filesystem' else None))


def network_backend(scope, number, link_port=None):
    require(scope in SCOPES and number in (1, 2), 'invalid native network profile')
    if scope == 'local-filesystem':
        # Hub identifiers are local to each QEMU process. With one hub port
        # and no netdev peer, both real virtio NICs remain completely isolated.
        return 'hubport,id=net0,hubid=0'
    require(isinstance(link_port, int) and 0 < link_port < 65536,
            'full-unified scope requires a peer socket port')
    return f'socket,id=net0,{"listen" if number == 1 else "connect"}=127.0.0.1:{link_port}'


def decode_probe(data, *, final=False):
    """Read only published actor outcomes; a live read never establishes PASS."""
    require(len(data) == PROBE_BYTES, 'snapshot probe evidence size differs')
    words = struct.unpack('<16Q', data)
    if words[0] == 0 and not final:
        return None
    require(words[:2] == (PROBE_MAGIC, PROBE_SCHEMA),
            'snapshot probe evidence identity differs')
    require(not any(words[2:4]), 'snapshot probe reserved words differ')
    stage, sequence, actual, reserved = words[12:]
    if sequence:
        raise ValueError(f'CPU0 budget failure: stage={stage}, sequence={sequence}, '
                         f'actual_ns={actual}, reserved_ns={reserved}')
    if stage or actual or reserved:
        # The producer publishes sequence last. A live observation may catch
        # its first-failure record in progress; it can never establish PASS.
        require(not final, 'incomplete CPU0 budget failure publication')
        return None
    actors = []
    for role, offset in ((1, 4), (2, 8)):
        identity, generation, done, code = words[offset:offset + 4]
        require(done in (0, 1), 'invalid actor completion publication')
        if done:
            require(identity > 0 and generation > 0, 'completed actor lacks task identity')
            require(code == 0, f'EL0 snapshot role {role} exited with code {code}')
        actors.append(dict(role=role, task_id=identity, task_generation=generation,
                           completed=bool(done), exit_code=code if done else None))
    complete = all(actor['completed'] for actor in actors)
    if complete:
        require(actors[0]['task_id'] != actors[1]['task_id'], 'actor identities alias')
    if final:
        require(complete, 'both snapshot actors must complete before final capture')
    return dict(complete=complete, actors=actors)


def bind_snapshot_build(build_folder):
    build_folder = Path(build_folder).resolve(strict=True)
    path = build_folder / 'build-manifest.json'
    build = json.loads(path.read_text())
    binding = bind_build(path, build_folder / 'node-a.elf', build_folder / 'node-b.elf',
                         [build_folder / 'node-a.pub', build_folder / 'node-b.pub'],
                         build_folder / 'task.elf', 'normal')
    modes = build['profiles']
    require(modes.get('snapshot_probe') is True and modes.get('selftest') is True
            and modes.get('storage_fault') is False and modes.get('memory_probe') is False,
            'dedicated snapshot selftest build required')
    require(build.get('storage_schemas') == dict(media=2, file_service=2,
                                               snapshot_request=1, snapshot_policy=1),
            'snapshot build schemas differ')
    clients = {}
    for node in ('a', 'b'):
        client = build_folder / f'snapshot-client-{node}.elf'
        identity = dict(sha256=sha(client), bytes=client.stat().st_size)
        require(build['embedded_roles']['snapshot_probe'][node] == identity
                and build['artifacts'][client.name] == identity,
                'EL0 snapshot client differs from build manifest')
        require(client.read_bytes() in (build_folder / f'node-{node}.elf').read_bytes(),
                'kernel lacks exact source-bound EL0 snapshot client')
        clients[node] = identity
    return dict(binding, embedded_snapshot_clients=clients)


def request_receipts(path, checked):
    """Decode extra result fields only after the independent full disk checker."""
    receipts = []
    with disk_v2.committed_volume(path) as (current, metadata):
        require(metadata['uuid'] == checked['uuid'], 'disk identity changed during inspection')
        for record in checked['request_records']:
            index = record['index']
            page = current(disk_v2.REQUEST_START + 1 + index // 8)
            row = page[index % 8 * 512:(index % 8 + 1) * 512]
            result = dict(record)
            result.update(
                snapshot_key=disk_v2.snapshot_key(row[88:128], bytes.fromhex(checked['uuid']),
                                                 allow_zero=True),
                old_epoch=disk_v2.u64(row, 128), new_epoch=disk_v2.u64(row, 136),
                result_code=struct.unpack_from('<i', row, 176)[0],
                transaction=dict(uuid=row[144:160].hex(), log_epoch=disk_v2.u64(row, 160),
                                 txid=disk_v2.u64(row, 168)),
                result_digest=row[184:216].hex())
            receipts.append(result)
    return receipts


def validate_snapshot_outcome(checked, receipts, expected_uuid):
    require(checked['format_version'] == 2 and checked['uuid'] == expected_uuid
            and checked['boot_epoch'] == 1, 'fresh v2 boot identity differs')
    control = checked['control']
    require(control['live_view_epoch'] == 2 and control['business_write_gate'] == 0
            and control['restore_phase'] == 0 and control['gc_phase'] == 0,
            'restore did not advance epoch and durably reopen business writes')
    expected = ((0, 1, 0x20), (15, 2, 0x23), (15, 3, 0x29))
    selected = []
    for slot, sequence, operation in expected:
        found = [row for row in receipts if (row['client_slot'], row['client_generation'],
                 row['request_seq'], row['operation']) == (slot, 1, sequence, operation)]
        require(len(found) == 1 and found[0]['state'] == 2 and found[0]['result_code'] == 0,
                f'missing successful durable request {slot}:{sequence}:{operation:#x}')
        selected.append(found[0])
    created, restored, reopened = selected
    require(created['snapshot_key'] is not None
            and created['snapshot_key'] == restored['snapshot_key'],
            'restore did not select the ordinary client snapshot')
    require((restored['old_epoch'], restored['new_epoch'], reopened['new_epoch']) == (1, 2, 2),
            'durable restore/open receipts have inconsistent epochs')
    history = [row for row in checked['snapshots'] if row['state'] == 1
               and all(row[name] == value for name, value in created['snapshot_key'].items())]
    require(len(history) == 1 and history[0]['captured_live_view_epoch'] == 1,
            'original immutable snapshot no longer openable')
    source = history[0]
    for name, files in [('live', checked['files']), ('historical', source['files'])]:
        value = files.get(VALUE)
        require(value is not None and value['size'] == len(BEFORE)
                and value['sha256'] == BEFORE_SHA256, f'{name} original content differs')
        require(KEY_FILE in files and files[KEY_FILE]['size'] == 0 and READY not in files,
                f'{name} namespace does not match the captured point')
    active = {row['slot'] for row in checked['snapshots'] if row['state'] == 1}
    require(active.intersection(range(3)) and active.intersection(range(3, 6)),
            'recovery lost a required periodic protection layer')
    return dict(live_view_epoch=2, restored_snapshot=created['snapshot_key'],
                original_content_sha256=BEFORE_SHA256, durable_requests=selected,
                business_write_gate='OPEN', original_history_preserved=True,
                post_snapshot_names_rolled_back=True)


def reserve_ports(count):
    with ExitStack() as stack:
        listeners = [stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                     for _ in range(count)]
        for listener in listeners:
            listener.bind(('127.0.0.1', 0))
        return [listener.getsockname()[1] for listener in listeners]


def read_serial(guest):
    data = base64.b64decode(guest['qmp'].execute('ringbuf-read',
        {'device': 'cyxlog', 'size': 1048576, 'format': 'base64'}), validate=True)
    guest['raw'].extend(data)
    require(len(guest['raw']) <= 4 * 1024 * 1024, 'serial capture quota exceeded')
    for frame in guest['decoder'].feed(data):
        guest['serial'].extend(frame)
    if data:
        (guest['folder'] / 'serial-live.txt').write_bytes(guest['serial'])
    require(not any(word in guest['serial'] for word in
                    (b'PANIC', b'SMP_ERROR', b'UNIFIED_FAIL', b'UNIFIED_EL0_FAULT')),
            'guest reported a native failure')


def read_probe(guest):
    location = guest['locations'][PROBE_SYMBOL]
    path = guest['folder'] / 'probe-live.bin'
    guest['qmp'].execute('pmemsave', {'val': location['pa'], 'size': location['size'],
                                    'filename': str(path)})
    return decode_probe(path.read_bytes())


def run(build_folder, output, qemu, qemu_source, formatter, timeout=120,
        scope='full-unified'):
    require(1 <= timeout <= 180, 'native smoke timeout must be in 1..180 seconds')
    scope_fields = scope_evidence(scope)
    build_folder = Path(build_folder).resolve(strict=True)
    output = Path(output).resolve()
    require(not output.exists(), 'refuse to reuse native smoke output')
    output.mkdir(parents=True)
    report = dict(schema_version=1, status='FAIL', **scope_fields,
                  r01_r30_acceptance_verified=False, real_hardware_verified=False,
                  crash_fault_matrix_verified=False, nodes=2)
    guests, final_pages = [], None
    before = manifest()
    (output / 'source-manifest.json').write_text(json.dumps(before, indent=2) + '\n')
    report['source_manifest_sha256'] = sha(output / 'source-manifest.json')
    report['runner_sha256'] = sha(Path(__file__))
    started = time.monotonic()
    with ExitStack() as stack:
        try:
            binding = bind_snapshot_build(build_folder)
            report['build_binding'] = binding
            qemu = Path(qemu).resolve(strict=True)
            proof = attest_qemu(qemu, qemu_source)
            require(proof['qemu_pmu_patch_attested'] is True,
                    'native smoke requires the pinned per-vCPU PMU build')
            report['qemu'] = proof
            formatter = Path(formatter).resolve(strict=True)
            report['formatter_sha256'] = sha(formatter)
            if scope == 'full-unified':
                link_port, *qmp_ports = reserve_ports(3)
            else:
                link_port, qmp_ports = None, reserve_ports(2)
            for number, node in enumerate(('a', 'b'), 1):
                folder = output / f'node-{node}'
                folder.mkdir()
                image = build_folder / f'node-{node}.elf'
                image_bytes = image.read_bytes()
                locations = profile(image_bytes)
                location = symbol(image_bytes, PROBE_SYMBOL)
                require(location['size'] == PROBE_BYTES, 'snapshot actor evidence ABI differs')
                locations[PROBE_SYMBOL] = location
                for name, size in EXTRA_DIAGNOSTICS.items():
                    try:
                        diagnostic = symbol(image_bytes, name)
                    except ValueError as error:
                        if str(error) != f'missing symbol {name}':
                            raise
                        continue
                    require(diagnostic['size'] == size, f'{name} diagnostic size differs')
                    locations[name] = diagnostic
                disk = folder / 'disk.raw'
                uuid = secrets.token_hex(16)
                formatted = subprocess.run([str(formatter), str(disk), uuid],
                    check=True, capture_output=True, timeout=30)
                (folder / 'format.log').write_bytes(formatted.stdout + formatted.stderr)
                fresh = disk_v2.inspect(disk)
                require(fresh['uuid'] == uuid and fresh['format_version'] == 2
                        and fresh['boot_epoch'] == 0 and not fresh['snapshots'],
                        'formatter did not produce a fresh v2 volume')
                (folder / 'disk-before.json').write_text(json.dumps(fresh, indent=2) + '\n')
                link = network_backend(scope, number, link_port)
                args = [str(qemu), '-machine',
                    'virt-10.2,gic-version=2,secure=off,virtualization=off',
                    '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M',
                    '-accel', 'tcg,thread=multi', '-S', '-display', 'none',
                    '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
                    '-drive', f'if=none,id=disk0,format=raw,file={disk},cache=writeback',
                    '-device', 'virtio-blk-device,drive=disk0', '-netdev', link,
                    '-device', f'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:0{number}',
                    '-object', f'filter-dump,id=capture,netdev=net0,file={folder / "ethernet.pcap"}',
                    '-object', 'rng-random,id=rng0,filename=/dev/urandom',
                    '-device', 'virtio-rng-device,rng=rng0',
                    '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                    '-qmp', f'tcp:127.0.0.1:{qmp_ports[number - 1]},server=on,wait=off',
                    '-kernel', str(image), '-no-reboot']
                guest = dict(folder=folder, argv=args, disk=disk, uuid=uuid, locations=locations,
                             network_backend=link,
                             raw=bytearray(), serial=bytearray(), decoder=FrameDecoder(),
                             proc=None, sock=None, qmp=None)
                guests.append(guest)
                err = stack.enter_context((folder / 'qemu-stderr.log').open('wb'))
                guest['proc'] = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
                handshake = time.monotonic() + 15
                while True:
                    require(guest['proc'].poll() is None, f'node {node}: QEMU exited before QMP')
                    require(time.monotonic() < handshake, 'QMP startup deadline')
                    # BSD/macOS leave a socket unusable after a refused connect
                    # (the next connect fails with EINVAL), so use a fresh one.
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        sock.connect(('127.0.0.1', qmp_ports[number - 1]))
                        break
                    except ConnectionRefusedError:
                        sock.close()
                        time.sleep(.02)
                guest['sock'] = sock
                guest['qmp'] = Qmp(sock)
                require('QMP' in guest['qmp'].receive(handshake), 'invalid QMP greeting')
                guest['qmp'].execute('qmp_capabilities')
                guest['cpus'] = guest['qmp'].execute('query-cpus-fast')
                guest['memory'] = guest['qmp'].execute('query-memory-size-summary')
                require(len(guest['cpus']) == 4 and guest['memory']['base-memory'] == 1024**3,
                        'native CPU/RAM profile differs')
            for guest in guests:
                guest['qmp'].execute('cont')
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                completed = []
                for guest in guests:
                    require(guest['proc'].poll() is None, 'QEMU exited before actor completion')
                    read_serial(guest)
                    observed = read_probe(guest)
                    completed.append(observed is not None and observed['complete'])
                if all(completed):
                    final_pages = capture(guests, [g['locations'] for g in guests], 'final-')
                    actors = []
                    for guest, bundle in zip(guests, final_pages):
                        actors.append(decode_probe(bundle[PROBE_SYMBOL], final=True))
                        unified = struct.unpack('<512Q', bundle['UNIFIED_EVIDENCE'])
                        require(unified[0] == 0x435958554E493031 and unified[1] == 1
                                and unified[15] == 0 and unified[16] == 1,
                                'unified boot/probe evidence differs')
                        read_serial(guest)
                        decoder = guest['decoder']
                        require(decoder.loss == decoder.corrupt == 0 and not decoder.buffer,
                                'UART capture is incomplete or corrupt')
                        require(b'UNIFIED_START' in guest['serial'], 'missing real guest start log')
                    report['actor_observations'] = actors
                    break
                time.sleep(.05)
            else:
                raise TimeoutError('snapshot actors did not both finish before deadline')
            require(bind_snapshot_build(build_folder) == binding, 'build changed during guest run')
            require(attest_qemu(qemu, qemu_source) == proof, 'QEMU changed during guest run')
            require(sha(formatter) == report['formatter_sha256'], 'formatter changed during run')
            require(before == manifest(), 'source changed during native smoke')
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
            report['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            if final_pages is None:
                ready = [g for g in guests if g['qmp'] is not None and g['proc'].poll() is None]
                if ready:
                    try:
                        capture(ready, [g['locations'] for g in ready], 'failure-')
                    except (OSError, ValueError, RuntimeError) as error:
                        report['capture_error'] = type(error).__name__ + ': ' + str(error)
            for guest in guests:
                process, qmp = guest['proc'], guest['qmp']
                if process is not None and process.poll() is None:
                    try:
                        if qmp is not None:
                            qmp.execute('quit')
                    except (OSError, ValueError, RuntimeError):
                        pass
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
                if process is not None and process.returncode != 0:
                    report.setdefault('error', f'{guest["folder"].name}: QEMU shutdown exit '
                                      f'{process.returncode}')
                if guest['sock'] is not None:
                    guest['sock'].close()
                folder = guest['folder']
                (folder / 'serial.bin').write_bytes(guest['raw'])
                (folder / 'serial.txt').write_bytes(guest['serial'])
                if qmp is not None:
                    (folder / 'qmp.jsonl').write_text(''.join(json.dumps(row) + '\n'
                                                         for row in qmp.transcript))
                decoder = guest['decoder']
                (folder / 'launch.json').write_text(json.dumps(dict(
                    scope=scope, network_backend=guest['network_backend'],
                    argv=guest['argv'], cpus=guest.get('cpus'), memory=guest.get('memory'),
                    exit=process.returncode if process is not None else None,
                    transport=dict(frames=decoder.frames, lost=decoder.loss,
                                   corrupt=decoder.corrupt)), indent=2) + '\n')
    disks = []
    for guest in guests:
        try:
            checked = disk_v2.inspect(guest['disk'])
            receipts = request_receipts(guest['disk'], checked)
            (guest['folder'] / 'disk-after.json').write_text(json.dumps(checked, indent=2) + '\n')
            outcome = validate_snapshot_outcome(checked, receipts, guest['uuid'])
            disks.append(dict(node=guest['folder'].name, disk_sha256=sha(guest['disk']),
                              disk_bytes=guest['disk'].stat().st_size, outcome=outcome))
        except (OSError, ValueError, KeyError, TypeError) as error:
            report.setdefault('disk_errors', []).append(dict(node=guest['folder'].name,
                error=type(error).__name__ + ': ' + str(error)))
    report['disks'] = disks
    if 'error' not in report and 'disk_errors' not in report and len(disks) == 2:
        report['status'] = 'SMOKE_PASS'
        report['verified_smoke_steps'] = [
            'EL0 ordinary create and durable before bytes',
            'immutable snapshot capture and durable live overwrite',
            'historical read of before bytes before restore',
            'separate recovery actor restore and epoch advance',
            'old live handle returns ESTALE and historical handle remains readable',
            'recovery OPEN_WRITES reply and both actors exit zero',
            'independent v2 committed disk, snapshot digests and DONE request verification']
    report['elapsed_seconds'] = round(time.monotonic() - started, 6)
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--qemu-source', type=Path, required=True)
    parser.add_argument('--formatter', type=Path, default=ROOT / 'target/debug/examples/prototype-disk')
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--scope', choices=SCOPES, default='full-unified',
                        help='full-unified links the peers; local-filesystem isolates each NIC')
    return parser


def main():
    args = argument_parser().parse_args()
    report = run(args.build, args.output, args.qemu, args.qemu_source, args.formatter,
                 args.timeout, args.scope)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['status'] == 'SMOKE_PASS' else 1)


if __name__ == '__main__':
    main()
