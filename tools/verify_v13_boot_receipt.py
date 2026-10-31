#!/usr/bin/env python3
"""Replay A01 boot-regression provenance without enrolling formal A01 acceptance.

Only caller-selected source and emulator checkouts are trusted. Archive code is
never imported or executed. Producer verdicts, observations and verification
booleans are ignored. This verifies the narrow four-profile regression, not all
A01 obligations and not a signed/hardware runtime attestation.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys

from check_prototype_evidence import _pairs, read_json, safe_path, sha256
from verify_v13_boot_recovery import MODES, require, verify_samples
from verify_v13_a02 import verify_native_qemu, verify_stopped_status
from transport import FrameDecoder

VERSION = 'a01-boot-provenance-v1'
TOOL_FILES = (
    'run_v13_boot_recovery.py', 'run_v13_boot_evidence.py',
    'verify_v13_boot_recovery.py', 'verify_v13_boot_receipt.py',
    'run_qemu.py', 'run_v13_a02.py', 'verify_v13_a02.py',
    'verify_unified.py', 'build_unified.py', 'check_elf.py',
    'verify_v13_model.py', 'check_prototype_evidence.py', 'transport.py',
)
BUILD_INPUTS = ('Cargo.toml', 'Cargo.lock', '.cargo/config.toml',
                'crates/prototype/src/features.rs', 'crates/prototype/src/policy_wire.rs')
SYMBOLS = {'boot': 'A01_BOOT_EVIDENCE', 'config': 'A01_BOOT_CONFIG',
           'control': 'DOMAIN_CONTROL_EVIDENCE', 'runtime': 'RUNTIME_V13_EVIDENCE',
           'unified': 'UNIFIED_EVIDENCE'}
MANDATORY = {
    'node-a.elf', 'build-manifest.json', 'source-manifest.json', 'input.json',
    'config.bin', 'config-observed.bin', 'config-injection.json', 'platform.dtb',
    'dtb-header.bin', 'tools.json', 'launch.json', 'platform.json', 'disk.raw',
    'disk-before.json', 'format.log', 'first.bin', 'last.bin', 'control.bin',
    'runtime.bin', 'unified.bin', 'qmp-transcript.json', 'serial.bin', 'serial.txt',
    'qemu-stderr.log', 'model.bin',
} | {'tooling/' + name for name in TOOL_FILES} | {'build-inputs/' + name for name in BUILD_INPUTS}


def verify_inventory(root: Path, receipt: dict) -> None:
    require(type(receipt) is dict and receipt.get('receipt_schema') == 1
            and type(receipt.get('receipt_schema')) is int, 'unknown boot receipt schema')
    files = receipt.get('files')
    require(type(files) is dict and MANDATORY <= files.keys() and len(files) <= 128,
            'incomplete or oversized boot inventory')
    total = 0
    for name, item in files.items():
        require(name != 'summary.json' and type(item) is dict
                and item.keys() == {'bytes', 'sha256'}, 'invalid inventory entry')
        require(type(item['bytes']) is int and 0 <= item['bytes'] <= 512 * 1024 * 1024
                and type(item['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}', item['sha256']), 'invalid inventory identity')
        path = safe_path(root, name)
        require(path.stat().st_size == item['bytes'] and sha256(path) == item['sha256'],
                'changed boot artifact: ' + name)
        total += item['bytes']
        require(total <= 1024 * 1024 * 1024, 'boot inventory exceeds bound')


def _absolute(value: str) -> PurePosixPath:
    require(type(value) is str and '\\' not in value and '\x00' not in value,
            'invalid captured path')
    path = PurePosixPath(value)
    require(path.is_absolute() and '..' not in path.parts and str(path) == value,
            'noncanonical captured path')
    return path


def verify_launch(argv: list[str]) -> PurePosixPath:
    require(type(argv) is list and 1 < len(argv) < 100
            and all(type(v) is str and 0 < len(v) < 4096 and '\x00' not in v for v in argv),
            'invalid native launch')
    _absolute(argv[0])
    options = {}
    i = 1
    while i < len(argv):
        key = argv[i]
        require(key.startswith('-'), 'invalid launch option')
        if key in ('-S', '-no-reboot'):
            value = True
            i += 1
        else:
            require(i + 1 < len(argv), 'missing launch value')
            value = argv[i + 1]
            i += 2
        options.setdefault(key, []).append(value)
    fixed = {'-machine': 'virt-10.2,gic-version=2,secure=off,virtualization=off',
             '-cpu': 'cortex-a53', '-smp': '4', '-m': '1024M', '-accel': 'tcg,thread=multi',
             '-S': True, '-display': 'none', '-monitor': 'none',
             '-global': 'virtio-mmio.force-legacy=false', '-no-reboot': True,
             '-object': 'rng-random,id=rng0,filename=/dev/urandom',
             '-chardev': 'ringbuf,id=cyxlog,size=1048576', '-serial': 'chardev:cyxlog'}
    require(set(options) == set(fixed) | {'-kernel', '-drive', '-device', '-netdev', '-qmp', '-gdb'},
            'unexpected launch option')
    for key, value in fixed.items():
        require(options[key] == [value], 'wrong launch option: ' + key)
    for key in ('-kernel', '-drive', '-netdev', '-qmp', '-gdb'):
        require(len(options[key]) == 1, 'duplicate launch option: ' + key)
    kernel = _absolute(options['-kernel'][0])
    require(kernel.name == 'node-a.elf', 'wrong kernel image')
    root = kernel.parent
    require(options['-drive'] == [f'if=none,id=disk0,format=raw,file={root / "disk.raw"},cache=writeback'],
            'wrong disk attachment')
    devices = ['virtio-blk-device,drive=disk0',
               'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
               'virtio-rng-device,rng=rng0']
    require(sorted(options['-device']) == sorted(devices), 'unexpected loader/device')
    net = re.fullmatch(r'socket,id=net0,listen=127\.0\.0\.1:([0-9]+)', options['-netdev'][0])
    require(net is not None and 0 < int(net[1]) < 65536, 'nonlocal test network')
    sockets = []
    for key, name in (('-qmp', 'q.sock'), ('-gdb', 'g.sock')):
        match = re.fullmatch(r'unix:([^,]+),server=on,wait=off', options[key][0])
        require(match is not None, 'invalid local debug socket')
        path = _absolute(match[1])
        require(path.name == name, 'wrong debug socket name')
        sockets.append(path)
    require(sockets[0].parent == sockets[1].parent, 'mixed debug socket roots')
    return root


def _exchanges(rows: list[dict]) -> list[tuple[dict, object]]:
    require(type(rows) is list and 0 < len(rows) <= 100000, 'invalid QMP transcript')
    waiting = None
    exchanges = []
    next_id = 1
    greeting = False
    for row in rows:
        require(type(row) is dict and row.keys() == {'direction', 'message'}
                and row['direction'] in ('send', 'receive') and type(row['message']) is dict,
                'invalid QMP entry')
        message = row['message']
        if row['direction'] == 'send':
            require(greeting and waiting is None and message.keys() in
                    ({'execute', 'id'}, {'execute', 'id', 'arguments'})
                    and type(message['id']) is int and message['id'] == next_id
                    and type(message['execute']) is str, 'unordered/duplicate QMP request')
            waiting = message
            next_id += 1
        elif 'id' in message:
            require(waiting is not None and type(message['id']) is int
                    and message['id'] == waiting['id'] and message.keys() == {'return', 'id'},
                    'unmatched, failed or duplicate QMP response')
            exchanges.append((waiting, message['return']))
            waiting = None
        elif 'QMP' in message:
            require(not greeting and waiting is None and not exchanges and message.keys() == {'QMP'},
                    'duplicate or late QMP greeting')
            greeting = True
        else:
            require('event' in message and type(message['event']) is str
                    and message.keys() <= {'event', 'data', 'timestamp'}, 'unknown QMP message')
    require(waiting is None, 'unanswered QMP request')
    return exchanges


def verify_qmp(rows, capture_root, symbols, dtb_size, platform):
    """Validate capture ordering and addresses; never trust supplied save locations."""
    specs = {'dtb-header.bin': (0x40000000, 40), 'platform.dtb': (0x40000000, dtb_size),
             'config-observed.bin': (symbols['config']['pa'], 512),
             'pending-boot.bin': (symbols['boot']['pa'], 512),
             'first.bin': (symbols['boot']['pa'], 512), 'last.bin': (symbols['boot']['pa'], 512),
             'control.bin': (symbols['control']['pa'], 4096),
             'runtime.bin': (symbols['runtime']['pa'], 8192),
             'unified.bin': (symbols['unified']['pa'], 4096)}
    preboot = {'dtb-header.bin', 'platform.dtb', 'config-observed.bin'}
    before = set()
    queries = set()
    groups = []
    running = False
    started = False
    stopped_checked = False
    ended = False
    serial = bytearray()
    exchanges = _exchanges(rows)
    require(exchanges and exchanges[0][0]['execute'] == 'qmp_capabilities', 'missing QMP capabilities')
    for position, (request, response) in enumerate(exchanges):
        require(not ended, 'QMP command after quit')
        command = request['execute']
        args = request.get('arguments')
        if command == 'qmp_capabilities':
            require(position == 0 and args is None and response == {}, 'invalid QMP setup')
        elif command in ('query-cpus-fast', 'query-memory-size-summary'):
            require(not started and command not in queries and args is None, 'late/duplicate platform query')
            expected = platform['cpus'] if command == 'query-cpus-fast' else platform['memory']
            require(response == expected, 'platform summary differs from QMP')
            queries.add(command)
        elif command == 'cont':
            require(args is None and response == {} and not running and before == preboot
                    and len(queries) == 2, 'invalid resume/preboot capture')
            if started:
                require(groups and stopped_checked and groups[-1] in (['first.bin'], ['last.bin']),
                        'resume after authority capture or unobserved stop')
            running = started = True
            stopped_checked = False
        elif command == 'stop':
            require(args is None and response == {} and running, 'invalid capture stop')
            running = False
            stopped_checked = False
            groups.append([])
        elif command == 'query-status':
            require(args is None and started and not running and not stopped_checked,
                    'invalid capture status ordering')
            verify_stopped_status([response])
            stopped_checked = True
        elif command == 'pmemsave':
            require(type(args) is dict and args.keys() == {'val', 'size', 'filename'}
                    and type(args['val']) is int and type(args['size']) is int,
                    'invalid memory capture command')
            matches = [name for name, (address, size) in specs.items()
                       if args == {'val': address, 'size': size, 'filename': str(capture_root / name)}]
            require(len(matches) == 1 and response == {}, 'unapproved memory capture')
            name = matches[0]
            if name in preboot:
                require(not started and name not in before, 'late/duplicate preboot capture')
                before.add(name)
            elif name == 'pending-boot.bin':
                require(running, 'live probe outside running interval')
            else:
                require(started and not running and stopped_checked and name not in groups[-1],
                        'memory sample was not taken after verified stop')
                groups[-1].append(name)
        elif command == 'ringbuf-read':
            require(running and args == {'device': 'cyxlog', 'size': 1048576, 'format': 'base64'}
                    and type(response) is str, 'invalid serial capture')
            serial.extend(base64.b64decode(response, validate=True))
            require(len(serial) <= 8 * 1024 * 1024, 'serial exceeds bound')
        elif command == 'quit':
            require(args is None and response == {} and not running and stopped_checked,
                    'quit without stopped final capture')
            ended = True
        else:
            raise ValueError('forbidden QMP command: ' + command)
    require(ended and len(groups) >= 2
            and groups[-1] == ['last.bin', 'control.bin', 'runtime.bin', 'unified.bin'],
            'missing final stopped authority captures')
    first_groups = [i for i, group in enumerate(groups[:-1]) if group == ['first.bin']]
    require(first_groups and all(group == ['last.bin'] for group in groups[first_groups[-1]+1:-1]),
            'missing ordered first sample')
    require(all(group in (['first.bin'], ['last.bin']) for group in groups[:-1]),
            'extra nonfinal capture')
    return bytes(serial)


def verify_receipt(directory: Path, *, source_root: Path, qemu_source: Path) -> dict:
    from build_unified import code_source_map
    from check_elf import boot_profile, inspect_elf, symbol
    from verify_v13_model import loaded_bytes
    from check_v13_disk import inspect as inspect_disk
    root = Path(directory).resolve(strict=True)
    project = Path(source_root).resolve(strict=True)
    trusted_qemu = Path(qemu_source).resolve(strict=True)
    path = lambda name: safe_path(root, name)
    document = lambda name: read_json(path(name))
    receipt = document('summary.json')
    verify_inventory(root, receipt)
    for name in TOOL_FILES:
        require(sha256(path('tooling/' + name)) == sha256(safe_path(project, 'tools/' + name)),
                'unreviewed tooling revision: ' + name)
    for name in BUILD_INPUTS:
        require(sha256(path('build-inputs/' + name)) == sha256(safe_path(project, name)),
                'changed build input: ' + name)
    build, sources = document('build-manifest.json'), document('source-manifest.json')
    require(build.get('schema_version') == 1 and build.get('status') == 'BUILT_NOT_RUN'
            and build['profiles']['selftest'] is True and build['profiles']['fault'] == 'normal'
            and build['profiles'].get('service_fault', 'none') == 'none'
            and not build['profiles'].get('storage_fault', False)
            and build['code_source_map'] == sources == code_source_map(project), 'wrong source/build profile')
    require(build['builder_sha256'] == sha256(safe_path(project, 'tools/build_unified.py'))
            and {'cargo', 'rustc', 'clang'} <= build['tools'].keys(), 'unverified builder/toolchain')
    require(build['artifacts']['node-a.elf']['sha256'] == sha256(path('node-a.elf')), 'wrong built image')
    image = path('node-a.elf').read_bytes()
    inspect_elf(image)
    require(boot_profile(image)['ram_mib'] == 1024, 'wrong image RAM profile')
    symbols = {key: symbol(image, name) for key, name in SYMBOLS.items()}
    for key, needed in (('boot', 512), ('config', 512), ('control', 4096), ('runtime', 8192), ('unified', 4096)):
        item = symbols[key]
        require(item['size'] >= needed and 0x40000000 <= item['pa']
                and item['pa'] + needed <= 0x80000000, 'invalid capture symbol: ' + key)
    require(symbols['boot']['size'] == symbols['config']['size'] == 512, 'wrong boot wire layout')
    config = path('config.bin').read_bytes()
    require(len(config) == 512 and config == path('config-observed.bin').read_bytes(), 'unobserved boot config')
    expected = b''.join(bytes.fromhex(sha256(path(name))) for name in
                        ('node-a.elf', 'input.json', 'source-manifest.json'))
    require(config[48:144] == expected, 'wrong frozen artifact identities')
    inputs = document('input.json')
    require(type(inputs) is dict and inputs.keys() ==
            {'scope', 'mode', 'nonce', 'timeout_seconds', 'sample_gap_seconds'}
            and inputs['scope'] == 'A01-boot-recovery-regression'
            and type(inputs['mode']) is int and inputs['mode'] in MODES.values()
            and inputs['mode'] == struct.unpack_from('<Q', config, 16)[0]
            and inputs['nonce'] == config[32:48].hex()
            and type(inputs['timeout_seconds']) in (int, float) and 5 <= inputs['timeout_seconds'] <= 120
            and inputs['sample_gap_seconds'] == .5, 'wrong frozen boot scenario')
    injection = document('config-injection.json')
    payload = f'M{symbols["config"]["pa"]:x},200:{config.hex()}'.encode('ascii')
    packet = b'$' + payload + f'#{sum(payload) % 256:02x}'.encode('ascii')
    require(injection.keys() == {'request_hex', 'received_hex', 'ack_hex'}
            and injection['request_hex'] == packet.hex() and injection['ack_hex'] == '2b'
            and bytes.fromhex(injection['received_hex']).lstrip(b'+') == b'$OK#9a',
            'write outside the fixed preboot configuration')
    observed = verify_samples(*(path(name).read_bytes() for name in
                               ('first.bin', 'last.bin', 'control.bin', 'runtime.bin', 'unified.bin', 'config.bin')))
    platform = document('platform.json')
    cpus = platform['cpus']
    require(type(cpus) is list and len(cpus) == 4
            and all(type(cpu) is dict and type(cpu.get('cpu-index')) is int for cpu in cpus)
            and {cpu['cpu-index'] for cpu in cpus} == set(range(4))
            and type(platform['memory'].get('base-memory')) is int
            and platform['memory']['base-memory'] == 1024 ** 3, 'wrong captured platform')
    dtb = path('platform.dtb').read_bytes()
    require(40 <= len(dtb) <= 2 * 1024 * 1024
            and struct.unpack_from('>2I', dtb) == (0xd00dfeed, len(dtb))
            and dtb[:40] == path('dtb-header.bin').read_bytes(), 'invalid captured DTB')
    model = symbol(image, 'A02_BOOT_MODEL')
    require(model['size'] == 2772 and path('model.bin').read_bytes() == loaded_bytes(image, model['va'], model['size']),
            'model differs from built image')
    require(path('disk.raw').stat().st_size == 512 * 1024 * 1024, 'wrong disk size')
    if observed['mode'] in (0, 3):
        epoch = struct.unpack('<64Q', path('last.bin').read_bytes())[6]
        require(inspect_disk(path('disk.raw'))['boot_epoch'] == epoch, 'durable boot identity differs')
    launch = document('launch.json')
    require(launch['symbols'] == symbols, 'capture symbols differ from the ELF')
    captured_root = verify_launch(launch['argv'])
    binary = trusted_qemu / 'build/qemu-system-aarch64'
    require(launch['argv'][0] == str(binary), 'emulator was not the explicit trusted build')
    tools = document('tools.json')
    require(tools.get('qemu_pmu_patch_attested') is True, 'patched PMU emulator required')
    verify_native_qemu(tools, binary, qemu_source=trusted_qemu)
    transcript = path('qmp-transcript.json')
    require(transcript.stat().st_size <= 16 * 1024 * 1024, 'QMP transcript exceeds bound')
    rows = json.loads(transcript.read_text(), object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('invalid JSON number')))
    raw = verify_qmp(rows, captured_root, symbols, len(dtb), platform)
    require(raw == path('serial.bin').read_bytes(), 'serial bytes differ from QMP capture')
    decoder = FrameDecoder()
    text = b''.join(payload + b'\n' for payload in decoder.feed(raw))
    require(decoder.frames > 0 and decoder.loss == decoder.corrupt == 0
            and text == path('serial.txt').read_bytes()
            and not any(marker in text for marker in (b'PANIC', b'SMP_ERROR', b'UNIFIED_FAIL')),
            'serial trace incomplete or failed')
    return dict(verifier_version=VERSION, scope='A01 four-profile boot regression only',
                native_execution_verified=True, runtime_truth_attested=False,
                native_acceptance_status='NOT_RUN', full_v13_acceptance=False,
                mode=observed['mode'], run_nonce=inputs['nonce'], observations=observed,
                image_sha256=sha256(path('node-a.elf')), source_sha256=sha256(path('source-manifest.json')))


def verify_matrix(directory: Path, *, source_root: Path, qemu_source: Path) -> dict:
    root = Path(directory).resolve(strict=True)
    results = {}
    for name, mode in MODES.items():
        child = root / name
        require(child.is_dir() and not child.is_symlink(), 'missing/redirected profile: ' + name)
        result = verify_receipt(child, source_root=source_root, qemu_source=qemu_source)
        require(result['mode'] == mode, 'profile directory contains another scenario')
        results[name] = result
    require(len({r['run_nonce'] for r in results.values()}) == len(MODES), 'reused run nonce')
    for field in ('image_sha256', 'source_sha256'):
        require(len({r[field] for r in results.values()}) == 1, 'mixed matrix build/source')
    return dict(verifier_version=VERSION, status='PASS', native_execution_verified=True,
                native_acceptance_status='NOT_RUN', runtime_truth_attested=False,
                full_v13_acceptance=False, scope='A01 boot regression, not formal case enrolment', cases=results)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--receipt', type=Path)
    target.add_argument('--matrix', type=Path)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--qemu-source', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        checker = verify_matrix if args.matrix is not None else verify_receipt
        result = checker(args.matrix if args.matrix is not None else args.receipt,
                         source_root=args.source_root, qemu_source=args.qemu_source)
    except (OSError, ValueError, TypeError, KeyError, struct.error) as error:
        print(json.dumps(dict(status='FAIL', error=str(error), native_execution_verified=False,
                              native_acceptance_status='NOT_RUN', runtime_truth_attested=False)))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
