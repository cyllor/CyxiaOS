"""Independent A10 native custody; no catalogue enrollment or hardware attestation."""
from __future__ import annotations

import base64
import ast
import hashlib
import gzip
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import sys
from dataclasses import dataclass

from check_prototype_evidence import _pairs, read_json, require, safe_path, sha256
from run_v13_a10 import PENDING_DIAGNOSTICS, terminal_ready
from doctor import ROOT
from transport import FrameDecoder
from verify_unified import (PINNED_QEMU_COMMIT, PINNED_QEMU_PATCH_SHA256,
                            PATCHED_QEMU_SOURCE_SHA256)

VERSION = 'a10-native-v1'
FRAME_LIMIT = 4 * 1024 * 1024
SERIAL_LIMIT = 8 * 1024 * 1024


def finite_tree(value, *, integer_only=False):
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        require(depth <= 32, 'native JSON nesting bound')
        if type(item) is float:
            require(not integer_only and math.isfinite(item), 'nonfinite/noninteger native JSON number')
        elif type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value


def document(root, name):
    try:
        return finite_tree(read_json(safe_path(root, name)))
    except RecursionError as error:
        raise ValueError('native JSON nesting bound') from error


def validate_dtb(data):
    """Bounded FDT v17 reader for the reviewed virt-10.2 platform profile."""
    require(40 <= len(data) <= 2 * 1024**2, 'DTB size bound')
    magic, total, tree_at, strings_at, reserve_at, version, compatible, boot, strings_size, tree_size = struct.unpack_from('>10I', data)
    require(magic == 0xd00dfeed and total == len(data) and version == 17 and compatible == 16
            and boot == 0 and 40 <= reserve_at < tree_at and reserve_at % 8 == 0
            and tree_at % 4 == 0 and tree_size % 4 == 0
            and tree_at + tree_size <= strings_at and strings_at + strings_size <= total,
            'invalid DTB header/ranges')
    cursor = reserve_at
    while True:
        require(cursor + 16 <= tree_at, 'unterminated DTB reservation table')
        address, length = struct.unpack_from('>2Q', data, cursor)
        cursor += 16
        if address == length == 0:
            break
        require(0x40000000 <= address < address + length <= 0x80000000,
                'DTB reservation outside native RAM')
    strings = data[strings_at:strings_at + strings_size]
    tree_end = tree_at + tree_size
    cursor, stack, nodes, properties = tree_at, [], {}, 0
    def string(block, start, end):
        stop = block.find(b'\0', start, end)
        require(start < end and 0 <= stop - start <= 255, 'DTB string bounds')
        value = block[start:stop].decode('ascii')
        return value, stop + 1
    ended = False
    while cursor < tree_end:
        token, = struct.unpack_from('>I', data, cursor)
        cursor += 4
        if token == 1:
            name, cursor = string(data, cursor, tree_end)
            cursor = (cursor + 3) & ~3
            require('/' not in name and name not in ('.', '..') and len(stack) < 16
                    and (name != '' or not nodes), 'invalid DTB node name/depth')
            stack.append(name)
            path = '/'.join(stack) or '/'
            require(path not in nodes and len(nodes) < 1024, 'duplicate/excessive DTB node')
            nodes[path] = {}
        elif token == 2:
            require(stack, 'unmatched DTB end node')
            stack.pop()
        elif token == 3:
            require(stack and cursor + 8 <= tree_end and properties < 8192, 'DTB property bounds')
            length, name_at = struct.unpack_from('>2I', data, cursor)
            cursor += 8
            require(cursor + length <= tree_end, 'DTB property exceeds structure')
            name, _ = string(strings, name_at, len(strings))
            node = nodes['/'.join(stack) or '/']
            require(name and name not in node, 'duplicate DTB property')
            node[name] = data[cursor:cursor + length]
            cursor = (cursor + length + 3) & ~3
            properties += 1
        elif token == 4:
            continue
        elif token == 9:
            require(not stack and nodes and not any(data[cursor:tree_end]), 'invalid DTB end/trailing data')
            ended = True
            break
        else:
            raise ValueError('unknown DTB token')
    require(ended and nodes.get('/', {}).get('compatible') == b'linux,dummy-virt\0'
            and nodes['/'].get('#address-cells') == struct.pack('>I', 2)
            and nodes['/'].get('#size-cells') == struct.pack('>I', 2), 'wrong native DTB platform')
    cpus = {name: props for name, props in nodes.items() if props.get('device_type') == b'cpu\0'}
    require(set(cpus) == {'/cpus/cpu@' + str(index) for index in range(4)}
            and nodes.get('/cpus', {}).get('#address-cells') == struct.pack('>I', 1)
            and nodes['/cpus'].get('#size-cells') == bytes(4), 'wrong native DTB CPU count/address cells')
    for index in range(4):
        cpu = cpus['/cpus/cpu@' + str(index)]
        require(cpu.get('compatible') == b'arm,cortex-a53\0' and cpu.get('enable-method') == b'psci\0'
                and cpu.get('reg') == struct.pack('>I', index), 'wrong native DTB CPU identity')
    memories = [props for props in nodes.values() if props.get('device_type') == b'memory\0']
    require(len(memories) == 1 and memories[0].get('reg') == struct.pack('>2Q', 0x40000000, 1024**3),
            'wrong native DTB RAM')
    gic = nodes.get('/intc@8000000', {})
    require(gic.get('compatible') == b'arm,cortex-a15-gic\0'
            and gic.get('reg') == struct.pack('>4Q', 0x8000000, 0x10000, 0x8010000, 0x10000),
            'wrong native DTB GICv2')
    virtio = {name: props for name, props in nodes.items() if props.get('compatible') == b'virtio,mmio\0'}
    require(set(virtio) == {f'/virtio_mmio@{0xa000000 + index * 0x200:x}' for index in range(32)},
            'wrong native DTB VirtIO transport count')
    for index in range(32):
        base = 0xa000000 + index * 0x200
        require(virtio[f'/virtio_mmio@{base:x}'].get('reg') == struct.pack('>2Q', base, 0x200),
                'wrong native DTB VirtIO transport range')


def tool_closure(source_root=ROOT):
    """Hash local import closure as data; never import the archived copy."""
    pending = ['verify_v13_a10_native_receipt', 'run_v13_a10_matrix', 'v13_a10_native_capture']
    found = {}
    while pending:
        name = pending.pop()
        if name in found:
            continue
        path = safe_path(source_root, 'tools/' + name + '.py')
        found[name] = sha256(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports = ([node.module] if isinstance(node, ast.ImportFrom) else
                       [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
            for imported in imports:
                if imported and (source_root / 'tools' / (imported + '.py')).is_file():
                    pending.append(imported)
    return {name + '.py': value for name, value in sorted(found.items())}


def strict_nbd_events(root):
    """Add native strict JSON parsing without changing offline-v1's bounds."""
    path = safe_path(root, 'nbd/events.jsonl.gz')
    require(path.stat().st_size <= 128 * 1024**2, 'native NBD compressed trace bound')
    total = 0
    with gzip.open(path, 'rb') as stream:
        while True:
            line = stream.readline(FRAME_LIMIT + 1)
            if not line:
                return
            total += len(line)
            require(total <= 128 * 1024**2 and len(line) <= FRAME_LIMIT and line.endswith(b'\n'),
                    'native NBD expanded/frame bound')
            try:
                row = finite_tree(json.loads(line, object_pairs_hook=_pairs,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite NBD JSON'))),
                    integer_only=True)
            except RecursionError as error:
                raise ValueError('native JSON nesting bound') from error
            require(type(row) is dict and all(type(value) is not float for value in row.values()),
                    'invalid native NBD JSON numbers')


def qemu_identity(binary, source):
    """Only explicit caller-selected local paths reach git; never execute QEMU."""
    binary, source = Path(binary).resolve(strict=True), Path(source).resolve(strict=True)
    def git(*args):
        return subprocess.check_output(['git', '-c', 'core.fsmonitor=false', '-C', str(source),
                                        *args], text=True, timeout=10)
    head = git('rev-parse', 'HEAD')
    changed = git('status', '--short', '--untracked-files=no')
    require(head == PINNED_QEMU_COMMIT + '\n'
            and set(changed.splitlines()) == {' M ' + name for name in PATCHED_QEMU_SOURCE_SHA256}
            and len(changed.splitlines()) == len(PATCHED_QEMU_SOURCE_SHA256),
            'caller QEMU source revision/changes mismatch')
    require(all(sha256(source / name) == digest for name, digest in PATCHED_QEMU_SOURCE_SHA256.items())
            and sha256(ROOT / 'tools/qemu/cyxia-per-vcpu-pmu.patch') == PINNED_QEMU_PATCH_SHA256,
            'caller QEMU patch/source mismatch')
    digest = sha256(binary)
    require(digest == sha256(source / 'build/qemu-system-aarch64'), 'caller QEMU build/binary mismatch')
    return dict(binary_sha256=digest, source_head_output=head, source_status_output=changed,
                patched_sources=PATCHED_QEMU_SOURCE_SHA256, patch_sha256=PINNED_QEMU_PATCH_SHA256)


def validate_launch(argv, context, inputs):
    require(type(argv) is list and all(type(value) is str and len(value) <= 2048 for value in argv),
            'invalid native argv')
    private = context['private_dir']
    require(type(private) is str and Path(private).is_absolute() and len(private) <= 100
            and '..' not in Path(private).parts and Path(private).as_posix() == private
            and context['private_mode'] == 0o700, 'unsafe private endpoint root')
    require(context['endpoints'] == dict(qmp=private + '/q.sock', gdb=private + '/g.sock',
                                        nbd=private + '/disk.sock'), 'wrong private endpoint roles')
    port = context['network_port']
    require(type(port) is int and 0 < port < 65536, 'invalid loopback port')
    from run_v13_a10 import request_merging
    merging = request_merging(inputs['mode'], inputs['cut'])
    expected = [context['binary'], '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
        '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
        '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
        '-drive', f'if=none,id=disk0,file=nbd:unix:{private}/disk.sock,format=raw,cache=writeback',
        '-device', f'virtio-blk-device,drive=disk0,request-merging={merging}',
        '-netdev', f'socket,id=net0,listen=127.0.0.1:{port}',
        '-device', 'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
        '-object', 'rng-random,id=rng0,filename=/dev/urandom',
        '-device', 'virtio-rng-device,rng=rng0',
        '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
        '-qmp', f'unix:{private}/q.sock,server=on,wait=off',
        '-gdb', f'unix:{private}/g.sock,server=on,wait=off',
        '-kernel', context['capture_root'] + '/node-a.elf', '-no-reboot']
    require(argv == expected, 'native launch option/device/endpoint mismatch')


def verify_native_child(directory, *, source_root, build_manifest, qemu_binary, qemu_source):
    from build_unified import code_source_map
    from run_v13_a02 import config_write_packet
    from run_v13_a10 import profile, config_bytes, result_scope, validate_build_profile
    from verify_v13_model import loaded_bytes
    from verify_v13_a10_receipt import replay_child, replay_serial, normalized
    from v13_a10_budget import scenario_budget
    require(not Path(directory).is_symlink(), 'native receipt root is a symlink')
    root = Path(directory).resolve(strict=True)
    source_root, build_manifest = Path(source_root).resolve(strict=True), Path(build_manifest).resolve(strict=True)
    context = document(root, 'native-context.json')
    require(context.get('version') == VERSION, 'missing native context version')
    inputs, binding = document(root, 'input.json'), document(root, 'binding.json')
    budget = scenario_budget(source_root, inputs['mode'])
    require(inputs['capture_timeout_seconds'] <= budget['capture_timeout_seconds']
            and all(inputs[key] == budget[key] for key in
                    ('client_deadline_ns', 'capture_margin_ns', 'client_poll_ns')),
            'native source-bound budget mismatch')
    sources = code_source_map(source_root)
    build = document(build_manifest.parent, build_manifest.name)
    validate_build_profile(build)
    require(build['profiles'].get('service_fault') == 'none'
            and build['code_source_map'] == sources == document(root, 'source-manifest.json')
            and build['code_source_sha256'] == hashlib.sha256(json.dumps(sources,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            and build['builder_sha256'] == sha256(source_root / 'tools/build_unified.py')
            and sha256(build_manifest) == sha256(safe_path(root, 'build-manifest.json')),
            'native caller source/build mismatch')
    require({'cargo', 'rustc', 'clang', 'installed_targets', 'llvm_objdump'} <= build['tools'].keys()
            and build.get('commands'), 'missing native build provenance')
    for name in ('node-a.elf', 'service-a.elf', 'task.elf'):
        require(sha256(safe_path(root, name)) == sha256(safe_path(build_manifest.parent, name))
                == build['artifacts'][name]['sha256'], 'native caller image mismatch: ' + name)
    closure = tool_closure()
    require(document(root, 'native-tools.json') == closure == tool_closure(source_root),
            'native reviewed tool closure mismatch')
    for name, digest in closure.items():
        require(sha256(safe_path(root, 'native-tools/' + name)) == digest,
                'native archived tool changed: ' + name)
    build_inputs = ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
                    'crates/prototype/src/features.rs', 'crates/prototype/src/policy_wire.rs')
    for name in build_inputs:
        require(sha256(safe_path(root, 'build-inputs/' + name)) == sha256(safe_path(source_root, name)),
                'native build input mismatch: ' + name)
    identity = qemu_identity(qemu_binary, qemu_source)
    require(document(root, 'qemu-source.json') == identity
            and context['binary'] == str(Path(qemu_binary).resolve(strict=True))
            and context['binary_sha256'] == identity['binary_sha256'], 'native caller QEMU mismatch')
    tools = document(root, 'tools.json')
    require(safe_path(root, 'qemu-version.txt').stat().st_size <= FRAME_LIMIT,
            'native QEMU version output bound')
    require(tools['qemu_sha256'] == identity['binary_sha256']
            and tools['qemu_version'] == safe_path(root, 'qemu-version.txt').read_text()
            and tools['qemu_version'].splitlines()[0] == 'QEMU emulator version 10.2.2 (v10.2.2-dirty)'
            and tools['qemu_source_commit'] == PINNED_QEMU_COMMIT
            and tools['qemu_source_sha256'] == PATCHED_QEMU_SOURCE_SHA256
            and tools['qemu_patch_sha256'] == PINNED_QEMU_PATCH_SHA256
            and tools['qemu_pmu_patch_attested'] is True, 'native QEMU capture identity mismatch')
    image = safe_path(root, 'node-a.elf').read_bytes()
    layout = profile(image)
    for name, size in (('config.bin', 512), ('config-observed.bin', 512),
                       ('model.bin', layout['model']['size'])):
        require(safe_path(root, name).stat().st_size == size, 'native preboot file size: ' + name)
    launch = document(root, 'launch.json')
    require(launch['symbols'] == normalized(layout), 'native ELF-derived symbols mismatch')
    validate_launch(launch['argv'], context, inputs)
    config = config_bytes(binding)
    injection = document(root, 'config-injection.json')
    require(injection == dict(request_hex=config_write_packet(config, layout['config']['pa']).hex(),
                             received_hex='2b244f4b233961', ack_hex='2b')
            and safe_path(root, 'config.bin').read_bytes()
            == safe_path(root, 'config-observed.bin').read_bytes() == config,
            'native exact preboot packet/ACK/OK/readback mismatch')
    model = layout['model']
    require(safe_path(root, 'model.bin').read_bytes() == loaded_bytes(image, model['va'], model['size']),
            'native linked model mismatch')
    nbd = document(root, 'nbd/start.json')
    require(all(safe_path(root, name).stat().st_nlink == 1 for name in ('initial.raw', 'disk.raw')),
            'native mutable backing/initial disk has a shared hardlink')
    require(context['backend_run_id'] == nbd['run_id']
            and re.fullmatch('[0-9a-f]{32}', nbd['run_id']) and int(nbd['run_id'], 16)
            and context['backing_path'] == context['capture_root'] + '/disk.raw'
            and context['backing_sha256'] == nbd['disk_initial_sha256']
                == inputs['initial_disk_sha256'] == sha256(safe_path(root, 'initial.raw'))
            and context['backing_size'] == nbd['size'] == 512 * 1024**2
            and nbd['max_pending_sectors'] == 32768
            and nbd['reverse_replies'] is inputs['reverse_replies'], 'native endpoint/backing lineage mismatch')
    protocol = validate_protocol(root, context, layout, inputs,
        read_rows(safe_path(root, 'qmp.jsonl'), inputs),
        read_rows(safe_path(root, 'native-provenance.jsonl'), inputs))
    def one(event):
        require(event in protocol['lifecycle'], 'missing native lifecycle: ' + event)
        return protocol['lifecycle'][event]
    require(one('final-disk')['sha256'] == sha256(safe_path(root, 'disk.raw')),
            'native final disk hash differs after backend close')
    snapshot = document(root, 'native-identity.json')
    expected = dict(source_sha256=binding['source_sha256'], build_sha256=sha256(build_manifest),
                    input_sha256=binding['input_sha256'], initial_sha256=context['backing_sha256'],
                    image_sha256=binding['image_sha256'], qemu=identity, tools=closure)
    require(snapshot == expected and one('identity-before')['identity'] == snapshot
            == one('identity-after')['identity'] and one('identity-before')['seq'] == 1
            and one('identity-after')['seq'] == protocol['witness_count'], 'native before/after identity mismatch')
    opened, created, connected, spawned = (one(event) for event in
        ('backend-open', 'endpoint-created', 'endpoint-connected', 'spawn'))
    require(opened['run_id'] == created['run_id'] == connected['run_id'] == nbd['run_id']
            and opened['path'] == context['backing_path']
            and opened['sha256'] == context['backing_sha256'] and opened['size'] == context['backing_size']
            and created['endpoint'] == connected['endpoint'] == context['endpoints']['nbd']
            and opened['seq'] < created['seq'] < spawned['seq']
            and created['seq'] < connected['seq'] < one('kill')['seq'],
            'native backend endpoint lifecycle mismatch')
    if context['host_platform'] in ('darwin', 'linux'):
        require(type(connected['peer_pid']) is int and connected['peer_pid'] == context['pid']
                and connected['peer_identity'] == 'kernel-pid', 'native NBD peer is not the spawned QEMU')
    else:
        require(connected['peer_pid'] is None
                and connected['peer_identity'] == 'private-directory-one-connection-unsupported',
                'invalid unsupported-host peer identity boundary')
    required = {'initial.raw', 'disk.raw', 'binding.json', 'input.json', 'build-manifest.json',
                'source-manifest.json', 'node-a.elf', 'service-a.elf', 'task.elf', 'config.bin',
                'config-injection.json', 'model.bin', 'launch.json', 'platform.json', 'tools.json',
                'qmp.jsonl', 'serial.bin', 'serial.txt', 'qemu-stderr.log', 'disk-before.json',
                'disk-after.json', 'native-context.json', 'native-provenance.jsonl',
                'native-identity.json', 'native-tools.json', 'qemu-source.json', 'qemu-version.txt',
                'nbd/start.json', 'nbd/capture.json', 'nbd/events.jsonl.gz', 'nbd/requests.bin.gz'}
    from run_v13_a10 import TOOL_NAMES
    required |= protocol['capture_names'] | {'tools/' + name for name in TOOL_NAMES}
    required |= {'native-tools/' + name for name in closure}
    required |= {'build-inputs/' + name for name in build_inputs}
    summary = document(root, 'summary.json')
    actual_names = set()
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'native inventory contains a symlink')
        require(path.is_dir() or path.is_file(), 'native inventory contains a special file')
        if path.is_file():
            name = path.relative_to(root).as_posix()
            require(name in required | {'summary.json'}, 'extra native inventory file: ' + name)
            actual_names.add(name)
    require(set(summary['artifacts']) == required and actual_names == required | {'summary.json'},
            'native inventory missing/extra file')
    require(safe_path(root, 'serial.txt').stat().st_size <= SERIAL_LIMIT,
            'native decoded serial limit')
    strict_nbd_events(root)
    matrix = dict(build_manifest_sha256=sha256(build_manifest), source_manifest_sha256=binding['source_sha256'],
                  filesystem_uuid=binding['uuid'])
    replayed = replay_child(root, matrix)
    replay_serial(root, complete=not protocol['cut_observed'])
    if protocol['cut_observed']:
        actual = replayed['nbd_trace']['cut']
        require(all(one('backend-cut')[key] == actual[key] for key in ('id', 'mutation', 'phase')),
                'native cut witness differs from actual NBD stream')
    control = safe_path(root, 'control-header.bin').read_bytes()
    magic = struct.unpack_from('<Q', control)[0]
    # initialize() publishes this aligned atomic magic last, after both hashes.
    # An earlier cut can retain an unpublished diagnostic prefix.
    require(magic in (0, 0x435958444f4d3031)
            and (protocol['cut_observed'] or magic != 0), 'native control publication mismatch')
    if magic:
        require(struct.unpack_from('<Q', control, 16)[0] == binding['boot_epoch']
                and control[128:160].hex() == sha256(safe_path(root, 'model.bin'))
                and control[160:192].hex() == sources['crates/prototype/src/features.rs'],
                'native model/schema/BootEpoch capture mismatch')
    classification = dict(result_scope(protocol['cut_observed']),
        status='NOT_RUN' if protocol['cut_observed'] else 'PASS',
        cut_observed=protocol['cut_observed'], native_mode_verified=not protocol['cut_observed'],
        capture_status='FAULT_CAPTURED' if protocol['cut_observed'] else 'VERIFIED')
    require(all(type(replayed.get(key)) is type(value) and replayed[key] == value
                for key, value in classification.items()),
            'native producer summary classification/scope differs')
    derived = dict(replayed, **classification)
    return NativeChild(derived, inputs, context, binding['nonce'])


@dataclass(frozen=True)
class NativeChild:
    summary: dict
    inputs: dict
    context: dict
    nonce: str


def verify_provision(root, matrix, *, source_root, build_manifest, formatter_binary):
    from check_v13_filesystem import inspect as inspect_filesystem
    from run_v13_a10 import validate_start
    from v13_a10_native_capture import formatter_identity, formatter_artifact, formatter_environment
    require(sha256(Path(build_manifest)) == matrix['build_manifest_sha256'],
            'native matrix trusted build mismatch')
    fresh = inspect_filesystem(safe_path(root, 'formatted.raw'))
    validate_start(fresh, 1)
    require(fresh['uuid'] == matrix['filesystem_uuid']
            and safe_path(root, 'formatted.raw').stat().st_size == 512 * 1024**2
            and sha256(safe_path(root, 'formatted.raw')) == matrix['formatted_disk_sha256'],
            'native formatted UUID/disk mismatch')
    provision = document(root, 'provision.json')
    tools = formatter_identity()
    for name in ('provision-build.stdout', 'provision-build.stderr', 'provision.stdout', 'provision.stderr',
                 'provision.log'):
        require(safe_path(root, name).stat().st_size <= FRAME_LIMIT, 'formatter output exceeds bound')
    build_output = safe_path(root, 'provision-build.stdout').read_text()
    formatter = Path(formatter_binary).resolve(strict=True)
    require(sha256(safe_path(root, 'formatter.bin')) == sha256(formatter)
            == provision['formatter_sha256']
            and safe_path(root, 'formatter.bin').stat().st_mode & 0o111 == 0,
            'native caller formatter executable mismatch')
    require(provision.get('version') == VERSION and provision['returncode'] == 0
            and provision['build_returncode'] == 0
            and provision['build_argv'] == [tools['rustup']['path'], 'run', 'stable', 'cargo', 'build',
                '--locked', '--offline', '-p', 'cyxia-prototype', '--example', 'prototype-disk',
                '--message-format=json-render-diagnostics', '--target', tools['rustc']['host']]
            and provision['tools_before'] == provision['tools_after'] == tools
            and formatter_artifact(build_output) == provision['compiler_artifact']
            and Path(provision['compiler_artifact']).resolve(strict=True) == formatter
            and provision['formatter_path'] == str(formatter)
            and provision['argv'] == [provision['formatter_path'],
                                      provision['capture_root'] + '/formatted.raw', fresh['uuid']]
            and provision['source_sha256'] == matrix['source_manifest_sha256']
            and provision['build_sha256'] == matrix['build_manifest_sha256']
            and provision['disk_sha256'] == matrix['formatted_disk_sha256']
            and provision['log_sha256'] == matrix['provision_log_sha256']
            and provision['build_stdout_sha256'] == sha256(safe_path(root, 'provision-build.stdout'))
            and provision['build_stderr_sha256'] == sha256(safe_path(root, 'provision-build.stderr'))
            and safe_path(root, 'provision.log').read_bytes() == safe_path(root, 'provision.stdout').read_bytes()
                + safe_path(root, 'provision.stderr').read_bytes()
            and provision['cwd'] == str(Path(source_root).resolve(strict=True))
            and provision['environment'].keys() == {'removed', 'values'}
            and provision['environment']['values'] == formatter_environment()
            and provision['environment']['removed'] == ['RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTC_WRAPPER',
                'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTFLAGS'],
            'native fresh formatter provenance mismatch')


def verify_native_matrix_receipt(directory, *, source_root, build_manifest, qemu_binary, qemu_source,
                                 formatter_binary):
    from run_v13_a10_matrix import validate_progress
    from verify_v13_a10_receipt import verify_matrix_identity
    from verify_v13_a10_matrix import review, load_run
    root = Path(directory).resolve(strict=True)
    for name in ('matrix-input.json', 'source-manifest.json', 'build-manifest.json'):
        document(root, name)
    matrix = verify_matrix_identity(root, Path(source_root).resolve(strict=True))
    require(matrix['qemu_binary'] == str(Path(qemu_binary).resolve(strict=True))
            and matrix['qemu_source'] == str(Path(qemu_source).resolve(strict=True))
            and matrix['source_root'] == str(Path(source_root).resolve(strict=True)),
            'native matrix caller roots differ')
    verify_provision(root, matrix, source_root=source_root, build_manifest=build_manifest,
                     formatter_binary=formatter_binary)
    progress = document(root, 'progress.json')
    completed = set(validate_progress(progress))
    require(progress['status'] == 'COMPLETE', 'native matrix progress incomplete')
    abandoned = progress.get('abandoned', [])
    validate_progress(dict(schema_version=1, status='COMPLETE', completed=abandoned))
    require(all(re.fullmatch(r'_abandoned/[0-9]{6}/.+', name) for name in abandoned),
            'invalid native abandoned-attempt path')
    checked, nonces, runs, endpoints, backings = set(), set(), set(), set(), set()
    def child_loader(path, **expected):
        name = path.relative_to(root).as_posix()
        require(name in completed and name not in checked, 'native selected child/progress mismatch')
        safe_path(root, name + '/summary.json')
        child = verify_native_child(path, source_root=source_root, build_manifest=build_manifest,
                                    qemu_binary=qemu_binary, qemu_source=qemu_source)
        # Legacy loader assertions are integrity comparisons, never admission inputs.
        recorded, inputs = load_run(path, **expected)
        require(recorded == child.summary and inputs == child.inputs,
                'native independently derived child differs from matrix projection')
        context = child.context
        for value, seen in ((child.nonce, nonces), (context['backend_run_id'], runs),
                            (context['private_dir'], endpoints), (context['backing_path'], backings)):
            require(value not in seen, 'reused native child identity/endpoint/backing')
            seen.add(value)
        checked.add(name)
        return child.summary, child.inputs
    coverage = review(root, child_loader=child_loader)
    require(checked == completed, 'unselected native matrix child')
    recorded = document(root, 'summary.json')
    require(recorded['matrix_input_sha256'] == sha256(safe_path(root, 'matrix-input.json'))
            and recorded['build_manifest_sha256'] == sha256(safe_path(root, 'build-manifest.json'))
            and recorded['progress_sha256'] == sha256(safe_path(root, 'progress.json'))
            and recorded['abandoned_attempts'] == abandoned
            and recorded['child_summaries'] == {path.relative_to(root).as_posix(): sha256(path)
                for path in root.rglob('summary.json') if path != root / 'summary.json'}
            and all(recorded[key] == value for key, value in coverage.items()),
            'native matrix summary integrity mismatch')
    top_names = {'matrix-input.json', 'build-manifest.json', 'source-manifest.json', 'formatted.raw',
                 'provision.log', 'provision.json', 'progress.json', 'summary.json', 'formatter.bin',
                 'provision-build.stdout', 'provision-build.stderr', 'provision.stdout', 'provision.stderr'}
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'native matrix contains symlink')
        require(path.is_dir() or path.is_file(), 'native matrix contains special file')
        if not path.is_file():
            continue
        name = path.relative_to(root).as_posix()
        require(name in top_names or name in {'tools/' + key for key in matrix['tools']}
                or any(name.startswith(child + '/') for child in checked)
                or any(name.startswith(abandoned + '/') for abandoned in progress.get('abandoned', [])),
                'extra native matrix file: ' + name)
    complete = coverage['A10_complete']
    return dict(schema_version=1, test_id='A10', verifier_version=VERSION,
                status='PASS' if complete else 'NOT_RUN', native_acceptance_status='PASS' if complete else 'NOT_RUN',
                raw_matrix_verified=True, native_execution_verified=True,
                native_filesystem_fault_matrix_complete=complete, runtime_truth_attested=complete,
                matrix_coverage=coverage, replayed_children=len(checked),
                scope='Reviewed local launcher custody, not cryptographic QEMU/hardware attestation; no catalogue enrollment.')


def main(argv=None):
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    for name in ('source-root', 'build-manifest', 'qemu-binary', 'qemu-source', 'formatter-binary'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_native_matrix_receipt(args.evidence, source_root=args.source_root,
            build_manifest=args.build_manifest, qemu_binary=args.qemu_binary, qemu_source=args.qemu_source,
            formatter_binary=args.formatter_binary)
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'PASS' else 2
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('a10-native-receipt: ' + str(error), file=sys.stderr)
        return 1


def poll_bound(inputs):
    sample, timeout = inputs['sample_ms'], inputs['capture_timeout_seconds']
    require(type(sample) is int and 100 <= sample <= 30000
            and type(timeout) in (int, float) and math.isfinite(timeout)
            and 5 <= timeout <= 21720, 'invalid native polling bound')
    return math.ceil(timeout * 1000 / sample) + 1


def capture_limits(inputs):
    polls = poll_bound(inputs)
    commands = polls * 5 + 64
    return dict(bytes=polls * 8192 + 16 * 1024 * 1024,
                commands=commands, witness_rows=commands * 3 + 16)


def read_rows(path, inputs):
    # Five request/response pairs per poll, with <=1024-byte capture roots.
    # 8 KiB/poll covers their metadata; 16 MiB covers base64 serial and setup.
    limits = capture_limits(inputs)
    require(path.stat().st_size <= limits['bytes'], 'native transcript total bound exceeded')
    with path.open('rb') as stream:
        count = total = 0
        while True:
            line = stream.readline(FRAME_LIMIT + 1)
            if not line:
                return
            count += 1
            total += len(line)
            require(count <= limits['witness_rows'] and total <= limits['bytes'],
                    'native transcript streamed count/byte bound exceeded')
            require(len(line) <= FRAME_LIMIT and line.endswith(b'\n'),
                    'native transcript frame bound/truncation')
            try:
                value = finite_tree(json.loads(line, object_pairs_hook=_pairs,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON'))))
            except RecursionError as error:
                raise ValueError('native JSON nesting bound') from error
            require(type(value) is dict, 'native transcript row must be an object')
            yield value


def transactions(rows, limit, events):
    iterator = iter(rows)
    first = next(iterator, {})
    require(first.keys() == {'direction', 'message'} and first['direction'] == 'receive'
            and first['message'].keys() == {'QMP'}, 'missing unique QMP greeting')
    hello = first['message']['QMP']
    require(hello.keys() == {'version', 'capabilities'}
            and hello['version'].keys() == {'qemu', 'package'}
            and hello['version']['qemu'] == dict(major=10, minor=2, micro=2)
            and all(type(value) is int for value in hello['version']['qemu'].values())
            and hello['version']['package'] == 'v10.2.2-dirty'
            and hello['capabilities'] in ([], ['oob']), 'wrong QEMU greeting')
    pending = None
    count, last = 0, {}
    for row in iterator:
        require(row.keys() == {'direction', 'message'} and type(row['message']) is dict,
                'invalid QMP row')
        message = row['message']
        if row['direction'] == 'send':
            require(pending is None and message.keys() in
                    ({'execute', 'id'}, {'execute', 'id', 'arguments'})
                    and type(message['id']) is int and message['id'] == count + 1
                    and count < limit, 'unordered/duplicate QMP request')
            pending = message
        elif row['direction'] == 'receive' and 'event' in message:
            require(message.keys() == {'event', 'timestamp'}
                    and message['event'] in ('STOP', 'RESUME')
                    and type(message['timestamp']) is dict
                    and message['timestamp'].keys() == {'seconds', 'microseconds'}
                    and all(type(v) is int and v >= 0 for v in message['timestamp'].values())
                    and message['timestamp']['microseconds'] < 1000000,
                    'unaccounted QMP asynchronous event')
            transition = pending or last
            require(transition.get('execute') == {'STOP': 'stop', 'RESUME': 'cont'}[message['event']],
                    'QMP event outside transition')
            require(message['event'] not in events, 'duplicate QMP lifecycle event')
            events.append(message['event'])
        else:
            require(row['direction'] == 'receive' and pending is not None
                    and message.keys() == {'return', 'id'} and type(message['id']) is int
                    and message['id'] == pending['id'], 'unordered/missing/error QMP response')
            last = pending
            count += 1
            pending = None
            yield last, message['return']
    require(pending is None, 'unanswered QMP request')


class Forward:
    """One row of lookahead, including for large source-budgeted captures."""
    def __init__(self, rows):
        self.rows = iter(rows)
        self.current = next(self.rows, None)

    def pop(self):
        value = self.current
        self.current = next(self.rows, None)
        return value


class Lifecycle:
    FIELDS = {
        'spawn': {'pid'}, 'injection': set(), 'kill': {'pid', 'signal'},
        'wait': {'pid', 'returncode'}, 'backend-close': {'run_id'},
        'final-disk': {'sha256', 'size'},
        'backend-cut': {'run_id', 'id', 'mutation', 'phase'},
        'identity-before': {'identity'}, 'identity-after': {'identity'},
        'backend-open': {'path', 'run_id', 'sha256', 'size'},
        'endpoint-created': {'endpoint', 'run_id'},
        'endpoint-connected': {'endpoint', 'run_id', 'peer_pid', 'peer_identity'},
        'qmp-request': {'id'}, 'qmp-response': {'id'}, 'save': {'id', 'name', 'size', 'sha256'},
    }

    def __init__(self, rows):
        self.rows = iter(rows)
        self.count = self.previous = 0
        self.events = {}

    def take(self, expected):
        for row in self.rows:
            self.count += 1
            require(type(row) is dict and type(row.get('seq')) is int and row['seq'] == self.count
                    and type(row.get('monotonic_ns')) is int
                    and row['monotonic_ns'] >= self.previous, 'unordered shared native witness')
            self.previous = row['monotonic_ns']
            kind = row['event']
            require(kind in self.FIELDS and row.keys() ==
                    {'seq', 'monotonic_ns', 'event'} | self.FIELDS[kind],
                    'unknown native lifecycle field')
            if kind in ('qmp-request', 'qmp-response', 'save'):
                require(kind == expected, 'native witness/QMP/save order mismatch')
                return row
            require(kind in {'spawn', 'injection', 'kill', 'wait', 'backend-close', 'backend-cut', 'final-disk',
                    'identity-before', 'identity-after', 'backend-open', 'endpoint-created',
                    'endpoint-connected'} and kind not in self.events, 'unknown/duplicate lifecycle event')
            self.events[kind] = row
        require(expected is None, 'missing native lifecycle: ' + str(expected))

    def one(self, event):
        require(event in self.events, 'missing native lifecycle: ' + event)
        return self.events[event]


def status(value, expected):
    require(type(value) is dict and value.keys() == {'running', 'status'}
            and value['status'] == expected and value['running'] is (expected == 'running'),
            'wrong native VM status')


def validate_protocol(root, context, layout, inputs, rows, witness):
    """Validate a capture protocol; this alone never grants native admission."""
    require(context['host_platform'] == sys.platform,
            'native host platform differs from trusted local context')
    require(safe_path(root, 'serial.bin').stat().st_size <= SERIAL_LIMIT,
            'native encoded serial size bound')
    events = []
    commands = Forward(transactions(rows, poll_bound(inputs) * 5 + 64, events))
    cut = bool(inputs['cut'])
    require(type(context['capture_root']) is str and len(json.dumps(context['capture_root'])) <= 1024
            and Path(context['capture_root']).is_absolute(), 'invalid historic capture root')
    lifecycle = Lifecycle(witness)
    one = lifecycle.one
    latest = {}
    index = last_response = resume_request = 0
    injection_bounds = []
    def take(name, args=None):
        nonlocal index, last_response, resume_request
        require(commands.current is not None, 'missing QMP command: ' + name)
        command, result = commands.pop()
        index += 1
        require(command['execute'] == name and command.get('arguments') == args
                and (args is None or all(type(command['arguments'][key]) is type(value)
                                        for key, value in args.items())),
                'unexpected QMP command/arguments: ' + name)
        request, response = lifecycle.take('qmp-request'), lifecycle.take('qmp-response')
        require(request['id'] == response['id'] == index
                and one('spawn')['seq'] < request['seq'] < response['seq']
                and 'kill' not in lifecycle.events, 'QMP witness identity/order mismatch')
        if name == 'stop':
            require('backend-cut' in lifecycle.events
                    and one('backend-cut')['seq'] < request['seq'], 'cut observation must precede stop')
        if name == 'cont':
            resume_request = request['seq']
        if name == 'pmemsave' and args['filename'].endswith('/config-observed.bin'):
            injection_bounds.extend((last_response, request['seq']))
        last_response = response['seq']
        return command, result
    def empty(name):
        command, result = take(name)
        require(result == {}, 'nonempty QMP transition reply')
        return command
    def save(name, address, size):
        command, result = take('pmemsave', dict(val=address, size=size,
            filename=str(Path(context['capture_root']) / name)))
        require(result == {}, 'failed native save')
        row = lifecycle.take('save')
        require(row is not None and row.keys() ==
                {'seq', 'monotonic_ns', 'event', 'id', 'name', 'size', 'sha256'}
                and row['id'] == command['id'] and row['name'] == name and row['size'] == size
                and last_response < row['seq'] and 'kill' not in lifecycle.events,
                'save witness missing or out of order')
        latest[name] = row
        require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
                and safe_path(root, name).stat().st_size == size, 'invalid native save hash/size')
    empty('qmp_capabilities')
    status(take('query-status')[1], 'prelaunch')
    cpus = take('query-cpus-fast')[1]
    memory = take('query-memory-size-summary')[1]
    # Pinned QEMU qemu_get_thread_id() uses getpid() on Darwin. The PID is
    # also bound below to spawn/kill/wait and by the caller to the NBD peer.
    require(type(cpus) is list and len(cpus) == 4
            and [cpu.get('cpu-index') for cpu in cpus] == list(range(4))
            and all(cpu.keys() == {'cpu-index', 'thread-id', 'qom-path', 'qom-type', 'props', 'target'}
                    and cpu.get('target') == 'aarch64' and type(cpu.get('cpu-index')) is int
                    and cpu['qom-type'] == 'cortex-a53-arm-cpu'
                    and cpu['props'] == {'socket-id': 0, 'cluster-id': 0, 'core-id': index, 'thread-id': 0}
                    and all(type(value) is int for value in cpu['props'].values())
                    and type(cpu.get('thread-id')) is int and cpu['thread-id'] > 0
                    and cpu.get('qom-path') == f'/machine/unattached/device[{index}]'
                    for index, cpu in enumerate(cpus))
            and (all(cpu['thread-id'] == context['pid'] for cpu in cpus) if sys.platform == 'darwin'
                 else len({cpu['thread-id'] for cpu in cpus}) == 4)
            and type(memory) is dict and all(type(value) is int for value in memory.values())
            and memory == {'base-memory': 1024**3, 'plugged-memory': 0}, 'wrong QMP platform')
    require(read_json(safe_path(root, 'platform.json')) == dict(cpus=cpus, memory=memory),
            'captured platform differs from QMP')
    save('dtb-header.bin', 0x40000000, 40)
    header = safe_path(root, 'dtb-header.bin').read_bytes()
    require(len(header) == 40, 'short DTB header')
    magic, length = struct.unpack_from('>2I', header)
    require(magic == 0xd00dfeed and 40 <= length <= 2 * 1024 * 1024, 'invalid DTB bounds')
    save('platform.dtb', 0x40000000, length)
    require(safe_path(root, 'platform.dtb').read_bytes()[:40] == header, 'DTB header differs')
    validate_dtb(safe_path(root, 'platform.dtb').read_bytes())
    save('config-observed.bin', layout['config']['pa'], 512)
    require(injection_bounds[0] < one('injection')['seq'] < injection_bounds[1],
            'injection was not before config readback/resume')
    empty('cont')
    status(take('query-status')[1], 'running')
    serial = bytearray()
    decoder = FrameDecoder()
    def read_serial():
        encoded = take('ringbuf-read', dict(device='cyxlog', size=1048576, format='base64'))[1]
        require(type(encoded) is str and len(encoded) <= 1398104, 'oversized ringbuf reply')
        chunk = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(chunk).decode() == encoded
                and len(chunk) <= 1048576 and len(serial) + len(chunk) <= SERIAL_LIMIT,
                'native serial capture limit')
        serial.extend(chunk)
        decoder.feed(chunk)
        return not chunk and not decoder.buffer
    polls = 0
    while commands.current is not None and commands.current[0]['execute'] == 'ringbuf-read':
        polls += 1
        require(polls <= poll_bound(inputs), 'excessive native polls')
        read_serial()
        if cut and commands.current is not None and commands.current[0]['execute'] == 'stop':
            break
        save('pending-progress.bin', layout['progress']['pa'], 512)
        for name in PENDING_DIAGNOSTICS:
            location = layout['diagnostics'][name]
            save('pending-' + name + '.bin', location['pa'], location['size'])
    require(polls > 0, 'missing native polling')
    if cut:
        empty('stop')
        observed = one('backend-cut')
        require(resume_request < observed['seq']
                and observed['run_id'] == context['backend_run_id']
                and observed['mutation'] == inputs['cut'] and observed['phase'] == inputs['phase'],
                'cut observation differs from policy')
        status(take('query-status')[1], 'paused')
    else:
        require('backend-cut' not in lifecycle.events, 'clean protocol contains a cut')
        require(terminal_ready(safe_path(root, 'pending-progress.bin').read_bytes(), inputs['mode']),
                'terminal poll lacks actual selected role exits')
    for name, key in (('trace', 'capture'), ('progress', 'progress'), ('consumption', 'consumption')):
        location = layout[key]
        save(name + '.bin', location['pa'], location['size'])
    for name, location in layout['diagnostics'].items():
        save(name + '.bin', location['pa'], location['size'])
    if not cut:
        for name, key in (('trace', 'capture'), ('progress', 'progress'), ('consumption', 'consumption')):
            location = layout[key]
            save(name + '-confirm.bin', location['pa'], location['size'])
            require(safe_path(root, name + '.bin').read_bytes()
                    == safe_path(root, name + '-confirm.bin').read_bytes(),
                    'live terminal confirmation differs: ' + name)
        drains, drained = 0, False
        while commands.current is not None and commands.current[0]['execute'] == 'ringbuf-read':
            drains += 1
            require(drains <= 8 and not drained, 'excessive terminal serial drains')
            drained = read_serial()
        require(drained and decoder.loss == decoder.corrupt == 0 and not decoder.buffer,
                'terminal serial drain exhausted/nonempty or damaged/trailing frame')
        status(take('query-status')[1], 'running')
        require(safe_path(root, 'pending-progress.bin').read_bytes()
                == safe_path(root, 'progress.bin').read_bytes(), 'terminal poll differs from capture')
    require(commands.current is None, 'extra native command/save')
    lifecycle.take(None)
    require(events == (['RESUME', 'STOP'] if cut else ['RESUME']),
            'missing/duplicate QMP lifecycle event')
    require(cut == ('backend-cut' in lifecycle.events), 'wrong cut lifecycle')
    spawn, kill, wait, close = (one(name) for name in ('spawn', 'kill', 'wait', 'backend-close'))
    require(spawn['pid'] == kill['pid'] == wait['pid'] == context['pid']
            and type(context['pid']) is int and context['pid'] > 0
            and kill['signal'] == 9 and wait['returncode'] == -9
            and spawn['seq'] < kill['seq'] < wait['seq'] < close['seq']
            and close['run_id'] == context['backend_run_id'], 'wrong own-process SIGKILL/wait/close')
    require(kill['monotonic_ns'] - spawn['monotonic_ns'] <= inputs['capture_timeout_seconds'] * 1000000000,
            'native source-bound capture deadline exceeded')
    final = one('final-disk')
    require(final['seq'] > close['seq'] and final['size'] == 512*1024**2
            and type(final['sha256']) is str and re.fullmatch('[0-9a-f]{64}', final['sha256']),
            'final disk identity was not observed after backend close')
    for name, row in latest.items():
        path = safe_path(root, name)
        require(path.stat().st_size == row['size'] and sha256(path) == row['sha256'],
                'native save content mismatch: ' + name)
    require(bytes(serial) == safe_path(root, 'serial.bin').read_bytes(),
            'QMP serial reconstruction differs')
    return dict(cut_observed=cut, capture_names=set(latest), lifecycle=lifecycle.events,
                witness_count=lifecycle.count)


if __name__ == '__main__':
    raise SystemExit(main())
