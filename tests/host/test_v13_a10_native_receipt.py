"""Synthetic protocol tests only: these bytes grant no native execution evidence."""
import base64
import copy
import hashlib
import json
import os
import socket
import shutil
import shlex
import gzip
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import verify_v13_a10_native_receipt as native


# Actual query-cpus-fast shape from read-only a10nc-20261030-01/prepare,
# QMP response id 3. Embedded as data in synthetic tests, not native evidence.
DARWIN_PREPARE_CPUS = [
    {'thread-id': 31836, 'qom-type': 'cortex-a53-arm-cpu',
     'props': {'core-id': 0, 'thread-id': 0, 'socket-id': 0, 'cluster-id': 0},
     'qom-path': '/machine/unattached/device[0]', 'cpu-index': 0, 'target': 'aarch64'},
    {'thread-id': 31836, 'qom-type': 'cortex-a53-arm-cpu',
     'props': {'core-id': 1, 'thread-id': 0, 'socket-id': 0, 'cluster-id': 0},
     'qom-path': '/machine/unattached/device[1]', 'cpu-index': 1, 'target': 'aarch64'},
    {'thread-id': 31836, 'qom-type': 'cortex-a53-arm-cpu',
     'props': {'core-id': 2, 'thread-id': 0, 'socket-id': 0, 'cluster-id': 0},
     'qom-path': '/machine/unattached/device[2]', 'cpu-index': 2, 'target': 'aarch64'},
    {'thread-id': 31836, 'qom-type': 'cortex-a53-arm-cpu',
     'props': {'core-id': 3, 'thread-id': 0, 'socket-id': 0, 'cluster-id': 0},
     'qom-path': '/machine/unattached/device[3]', 'cpu-index': 3, 'target': 'aarch64'},
]


def dtb_fixture(memory_size=1024**3, cpu_count=4, controller=b'arm,cortex-a15-gic\0'):
    names, structure = bytearray(), bytearray()
    def word(value): structure.extend(struct.pack('>I', value))
    def begin(name):
        word(1); structure.extend(name.encode()+b'\0')
        while len(structure) % 4: structure.append(0)
    def prop(name, value):
        offset = len(names); names.extend(name.encode()+b'\0')
        word(3); word(len(value)); word(offset); structure.extend(value)
        while len(structure) % 4: structure.append(0)
    begin('')
    prop('compatible', b'linux,dummy-virt\0')
    prop('#address-cells', struct.pack('>I', 2)); prop('#size-cells', struct.pack('>I', 2))
    begin('cpus'); prop('#address-cells', struct.pack('>I', 1)); prop('#size-cells', bytes(4))
    for index in range(cpu_count):
        begin('cpu@'+str(index)); prop('compatible', b'arm,cortex-a53\0')
        prop('device_type', b'cpu\0'); prop('reg', struct.pack('>I', index))
        prop('enable-method', b'psci\0'); word(2)
    word(2)
    begin('memory@40000000'); prop('device_type', b'memory\0')
    prop('reg', struct.pack('>2Q', 0x40000000, memory_size)); word(2)
    begin('intc@8000000'); prop('compatible', controller)
    prop('reg', struct.pack('>4Q', 0x8000000, 0x10000, 0x8010000, 0x10000)); word(2)
    for index in range(32):
        base = 0xa000000 + index * 0x200
        begin(f'virtio_mmio@{base:x}'); prop('compatible', b'virtio,mmio\0')
        prop('reg', struct.pack('>2Q', base, 0x200)); word(2)
    word(2); word(9)
    return struct.pack('>10I', 0xd00dfeed, 56 + len(structure) + len(names),
        56, 56 + len(structure), 40, 17, 16, 0, len(names), len(structure)) + bytes(16) + structure + names


def fixture(root, cut=False, layout=None, drains=None):
    layout = layout or dict(config=dict(pa=0x40100000, size=512),
                  capture=dict(pa=0x40200000, size=299008),
                  progress=dict(pa=0x40300000, size=512),
                  consumption=dict(pa=0x40400000, size=256), diagnostics={})
    # Literal fake addresses exercise protocol validation, never ELF admission.
    from run_v13_a10 import diagnostic_specs
    for index, (_, name, size) in enumerate(diagnostic_specs()):
        layout['diagnostics'].setdefault(name, dict(pa=0x41000000 + index * 0x100000, size=size))
    context = dict(capture_root=str(root), pid=123, backend_run_id='ab' * 16,
                   host_platform=sys.platform)
    inputs = dict(mode=1, cut=int(cut), phase='before', sample_ms=30000,
                  capture_timeout_seconds=1920.0)
    rows = [dict(direction='receive', message={'QMP': {'version': {
        'qemu': {'major': 10, 'minor': 2, 'micro': 2}, 'package': 'v10.2.2-dirty'},
        'capabilities': ['oob']}})]
    witness = []
    def event(kind, **data):
        witness.append(dict(seq=len(witness) + 1, monotonic_ns=len(witness) + 1,
                            event=kind, **data))
    event('spawn', pid=123)
    def command(name, result, args=None, event_name=None):
        ident = sum(r['direction'] == 'send' for r in rows) + 1
        msg = dict(execute=name, id=ident)
        if args is not None:
            msg['arguments'] = args
        event('qmp-request', id=ident)
        rows.append(dict(direction='send', message=msg))
        if event_name:
            rows.append(dict(direction='receive', message=dict(event=event_name,
                timestamp=dict(seconds=1, microseconds=2))))
        rows.append(dict(direction='receive', message=dict(id=ident, **{'return': result})))
        event('qmp-response', id=ident)
        return ident
    def save(name, at, size, data=None):
        data = bytes(size) if data is None else data
        (root / name).write_bytes(data)
        ident = command('pmemsave', {}, dict(val=at, size=size, filename=str(root / name)))
        event('save', id=ident, name=name, size=size, sha256=hashlib.sha256(data).hexdigest())
    command('qmp_capabilities', {})
    command('query-status', dict(status='prelaunch', running=False))
    cpus = [dict(**{'cpu-index': i, 'thread-id': context['pid'] if sys.platform == 'darwin' else 100 + i,
                   'qom-path': f'/machine/unattached/device[{i}]', 'target': 'aarch64',
                   'qom-type': 'cortex-a53-arm-cpu',
                   'props': {'socket-id': 0, 'cluster-id': 0, 'core-id': i, 'thread-id': 0}})
            for i in range(4)]
    memory = {'base-memory': 1024**3, 'plugged-memory': 0}
    command('query-cpus-fast', cpus)
    command('query-memory-size-summary', memory)
    (root / 'platform.json').write_text(json.dumps(dict(cpus=cpus, memory=memory)))
    dtb = dtb_fixture()
    save('dtb-header.bin', 0x40000000, 40, dtb[:40])
    save('platform.dtb', 0x40000000, len(dtb), dtb)
    event('injection')
    save('config-observed.bin', layout['config']['pa'], 512)
    command('cont', {}, event_name='RESUME')
    command('query-status', dict(status='running', running=True))
    command('ringbuf-read', '', dict(device='cyxlog', size=1048576, format='base64'))
    if cut:
        event('backend-cut', run_id=context['backend_run_id'], id=1, mutation=1, phase='before')
        command('stop', {}, event_name='STOP')
        command('query-status', dict(status='paused', running=False))
    else:
        terminal = bytearray(512)
        for offset in (0, 256):
            struct.pack_into('<Q', terminal, offset, 0x4359584131305052)
        save('pending-progress.bin', layout['progress']['pa'], 512, terminal)
        for name in ('domain-task', 'unified-runtime', 'unified-service-stage'):
            loc = layout['diagnostics'][name]
            save('pending-' + name + '.bin', loc['pa'], loc['size'])
    for name, key in (('trace', 'capture'), ('progress', 'progress'), ('consumption', 'consumption')):
        loc = layout[key]
        data = terminal if not cut and key == 'progress' else None
        save(name + '.bin', loc['pa'], loc['size'], data)
    for name, loc in layout['diagnostics'].items():
        save(name + '.bin', loc['pa'], loc['size'])
    if not cut:
        for name, key in (('trace', 'capture'), ('progress', 'progress'), ('consumption', 'consumption')):
            loc = layout[key]
            save(name + '-confirm.bin', loc['pa'], loc['size'], (root / (name + '.bin')).read_bytes())
        for chunk in ([b''] if drains is None else drains):
            command('ringbuf-read', base64.b64encode(chunk).decode(),
                    dict(device='cyxlog', size=1048576, format='base64'))
        command('query-status', dict(status='running', running=True))
    event('kill', pid=123, signal=9)
    event('wait', pid=123, returncode=-9)
    event('backend-close', run_id=context['backend_run_id'])
    event('final-disk', sha256='11'*32, size=512*1024**2)
    (root / 'serial.bin').write_bytes(b''.join(drains or []) if not cut else b'')
    return context, layout, inputs, rows, witness


def synthetic_elf():
    """Small ELF with actual symbol tables; it is deliberately not bootable."""
    from run_v13_a10 import diagnostic_specs
    image = bytearray(8192)
    struct.pack_into('<16sHHIQQQIHHHHHH', image, 0,
        b'\x7fELF\x02\x01\x01' + bytes(9), 2, 183, 1, 0x40200000, 64, 4352,
        0, 64, 56, 1, 64, 3, 0)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, 256, 0x40200000, 0x40200000, 4096, 0x2000000, 1)
    struct.pack_into('<3Q', image, 272, 1, 1024, 2048)
    struct.pack_into('<8Q', image, 320, 1, 512, 768, 384, 295424, 299008, 512, 512)
    symbols = [('CYXIA_BOOT_PROFILE', 0x40200010, 24), ('A10_CAPTURE_LAYOUT', 0x40200040, 64),
        ('A02_BOOT_MODEL', 0x40200080, 2772), ('A10_CONFIG', 0x40300000, 512),
        ('A10_CAPTURE', 0x40400000, 299008), ('A10_PROGRESS', 0x40500000, 512),
        ('A10_CONSUMPTION', 0x40600000, 256)]
    symbols += [(name, 0x41000000 + index * 0x100000, size)
                for index, (name, _, size) in enumerate(diagnostic_specs())]
    strings = bytearray(b'\0')
    for index, (name, address, size) in enumerate(symbols):
        struct.pack_into('<IBBHQQ', image, 4608 + index * 24, len(strings), 0x11, 0, 1, address, size)
        strings.extend(name.encode() + b'\0')
    struct.pack_into('<IIQQQQIIQQ', image, 4416, 0, 2, 0, 0, 4608, len(symbols) * 24, 2, 0, 8, 24)
    struct.pack_into('<IIQQQQIIQQ', image, 4480, 0, 3, 0, 0, 6000, len(strings), 0, 0, 1, 0)
    image[6000:6000 + len(strings)] = strings
    return bytes(image)


class SyntheticChild:
    """Only QEMU attestation and offline raw replay are replaced, explicitly.

    Source/tool/build/ELF/config/argv/protocol/inventory checks remain real.
    No test result from this class is native evidence or a matrix PASS.
    """
    def __init__(self, directory, cut=False):
        from build_unified import code_source_map
        from run_v13_a10 import TOOL_NAMES, config_bytes, profile
        from run_v13_a02 import config_write_packet
        directory = directory.resolve()
        self.root, self.build_root = directory / 'receipt', directory / 'build'
        root = self.root
        root.mkdir()
        self.build_root.mkdir()
        self.image = synthetic_elf()
        layout = profile(self.image)
        context, _, inputs, rows, witness = fixture(root, layout=layout, cut=cut)
        self.qemu = dict(binary_sha256='11' * 32, source_head_output=native.PINNED_QEMU_COMMIT + '\n',
            source_status_output='synthetic external attestation', patched_sources=native.PATCHED_QEMU_SOURCE_SHA256,
            patch_sha256=native.PINNED_QEMU_PATCH_SHA256)
        sources = code_source_map(ROOT)
        self.write('source-manifest.json', sources)
        build = dict(schema_version=1, status='BUILT_NOT_RUN', profiles=dict(selftest=True,
            storage_fault=True, fault='normal', leave=False, service_fault='none'),
            code_source_map=sources, code_source_sha256=hashlib.sha256(json.dumps(sources,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            builder_sha256=native.sha256(ROOT / 'tools/build_unified.py'),
            tools={name: 'synthetic fixture' for name in ('cargo', 'rustc', 'clang', 'installed_targets', 'llvm_objdump')},
            commands=[['synthetic-fixture-not-a-build']], artifacts={})
        for name in ('node-a.elf', 'service-a.elf', 'task.elf'):
            (root / name).write_bytes(self.image)
            (self.build_root / name).write_bytes(self.image)
            build['artifacts'][name] = dict(sha256=native.sha256(root / name))
        self.write('build-manifest.json', build)
        shutil.copyfile(root / 'build-manifest.json', self.build_root / 'build-manifest.json')
        self.tools = native.tool_closure()
        self.write('native-tools.json', self.tools)
        for subdir, names in (('native-tools', self.tools), ('tools', TOOL_NAMES)):
            (root / subdir).mkdir()
            for name in names: shutil.copyfile(ROOT / 'tools' / name, root / subdir / name)
        for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
                     'crates/prototype/src/features.rs', 'crates/prototype/src/policy_wire.rs'):
            destination = root / 'build-inputs' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        for name in ('initial.raw', 'disk.raw'):
            with (root / name).open('wb') as stream: stream.truncate(512 * 1024**2)
        initial_hash = native.sha256(root / 'initial.raw')
        inputs.update(client_deadline_ns=1800000000000, capture_margin_ns=120000000000,
                      client_poll_ns=20000000000, initial_disk_sha256=initial_hash,
                      reverse_replies=True)
        self.write('input.json', inputs)
        self.binding = dict(mode=1, boot_epoch=1, uuid='22'*16, nonce='33'*16,
            image_sha256=native.sha256(root / 'node-a.elf'), input_sha256=native.sha256(root / 'input.json'),
            source_sha256=native.sha256(root / 'source-manifest.json'))
        self.write('binding.json', self.binding)
        config = config_bytes(self.binding)
        (root / 'config.bin').write_bytes(config)
        (root / 'config-observed.bin').write_bytes(config)
        self.write('config-injection.json', dict(request_hex=config_write_packet(config, 0x40300000).hex(),
                                               received_hex='2b244f4b233961', ack_hex='2b'))
        (root / 'model.bin').write_bytes(bytes(2772))
        control = bytearray(331776)
        struct.pack_into('<3Q', control, 0, 0x435958444f4d3031, 1, 1)
        control[128:160] = bytes.fromhex(native.sha256(root / 'model.bin'))
        control[160:192] = bytes.fromhex(sources['crates/prototype/src/features.rs'])
        (root / 'control-header.bin').write_bytes(control)
        for row in witness:
            if row['event'] == 'save': row['sha256'] = native.sha256(root / row['name'])
            if row['event'] == 'final-disk': row['sha256'] = initial_hash
        context.update(version=native.VERSION, binary=str(directory / 'trusted-qemu'),
            binary_sha256='11'*32, private_dir='/tmp/synthetic', private_mode=0o700,
            endpoints=dict(qmp='/tmp/synthetic/q.sock', gdb='/tmp/synthetic/g.sock', nbd='/tmp/synthetic/disk.sock'),
            backing_path=str(root / 'disk.raw'), backing_size=512*1024**2,
            backing_sha256=initial_hash, network_port=1234, initial_source='/synthetic/fresh.raw',
            host_platform=sys.platform)
        (directory / 'trusted-qemu').write_text('not executable')
        self.write('native-context.json', context)
        # Build argv independently from the validator by taking the same fixed
        # publicly documented launch grammar as the real runner.
        argv = [context['binary'], '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
            '-cpu','cortex-a53','-smp','4','-m','1024M','-accel','tcg,thread=multi','-S',
            '-display','none','-monitor','none','-global','virtio-mmio.force-legacy=false',
            '-drive','if=none,id=disk0,file=nbd:unix:/tmp/synthetic/disk.sock,format=raw,cache=writeback',
            '-device','virtio-blk-device,drive=disk0,request-merging=on',
            '-netdev','socket,id=net0,listen=127.0.0.1:1234',
            '-device','virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
            '-object','rng-random,id=rng0,filename=/dev/urandom','-device','virtio-rng-device,rng=rng0',
            '-chardev','ringbuf,id=cyxlog,size=1048576','-serial','chardev:cyxlog',
            '-qmp','unix:/tmp/synthetic/q.sock,server=on,wait=off',
            '-gdb','unix:/tmp/synthetic/g.sock,server=on,wait=off','-kernel',str(root/'node-a.elf'),'-no-reboot']
        if cut:
            argv[argv.index('virtio-blk-device,drive=disk0,request-merging=on')] = 'virtio-blk-device,drive=disk0,request-merging=off'
        self.write('launch.json', dict(argv=argv, symbols=layout))
        self.write('qemu-source.json', self.qemu)
        (root / 'qemu-version.txt').write_text('QEMU emulator version 10.2.2 (v10.2.2-dirty)\n')
        self.write('tools.json', dict(qemu_sha256='11'*32, qemu_version=(root/'qemu-version.txt').read_text(),
            qemu_source_commit=native.PINNED_QEMU_COMMIT, qemu_patch_sha256=native.PINNED_QEMU_PATCH_SHA256,
            qemu_source_sha256=native.PATCHED_QEMU_SOURCE_SHA256, qemu_pmu_patch_attested=True))
        (root / 'nbd').mkdir()
        self.write('nbd/start.json', dict(run_id=context['backend_run_id'], disk_initial_sha256=initial_hash,
            size=512*1024**2, max_pending_sectors=32768, reverse_replies=True))
        for name in ('events.jsonl', 'requests.bin'):
            with gzip.open(root / 'nbd' / (name + '.gz'), 'wb'): pass
        self.write('nbd/capture.json', {})
        for name in ('disk-before.json', 'disk-after.json'): self.write(name, {})
        for name in ('serial.txt', 'qemu-stderr.log'): (root/name).write_bytes(b'')
        identity = dict(source_sha256=self.binding['source_sha256'], build_sha256=native.sha256(root/'build-manifest.json'),
            input_sha256=self.binding['input_sha256'], initial_sha256=initial_hash,
            image_sha256=self.binding['image_sha256'], qemu=self.qemu, tools=self.tools)
        self.write('native-identity.json', identity)
        witness[:0] = [dict(event='identity-before', identity=identity),
            dict(event='backend-open', path=context['backing_path'], run_id=context['backend_run_id'],
                 sha256=initial_hash, size=512*1024**2),
            dict(event='endpoint-created', endpoint='/tmp/synthetic/disk.sock', run_id=context['backend_run_id'])]
        witness.insert(4, dict(event='endpoint-connected', endpoint='/tmp/synthetic/disk.sock',
            run_id=context['backend_run_id'], peer_pid=123, peer_identity='kernel-pid'))
        witness.append(dict(event='identity-after', identity=identity))
        for index, row in enumerate(witness): row.update(seq=index+1, monotonic_ns=index+1)
        for name, data in (('qmp.jsonl', rows), ('native-provenance.jsonl', witness)):
            (root/name).write_text(''.join(json.dumps(row)+'\n' for row in data))
        self.summary = dict(test_id='A10', native_acceptance_status='NOT_RUN', A10_complete=False,
                            native_filesystem_fault_matrix_complete=False, runtime_truth_attested=False,
                            scope=('one injected native prefix; no clean task completion inferred' if cut else
                                   'one ordinary EL0 clean mode; complete fault/replay/eviction matrix remains unrun'),
                            status='NOT_RUN' if cut else 'PASS', cut_observed=cut, native_mode_verified=not cut,
                            capture_status='FAULT_CAPTURED' if cut else 'VERIFIED', binding=self.binding)
        if cut:
            self.summary['nbd_trace'] = dict(cut=dict(id=1,mutation=1,phase='before'))
        self.rehash()

    def write(self, name, data):
        (self.root/name).write_text(json.dumps(data, sort_keys=True, separators=(',', ':'))+'\n')

    def read(self, name):
        return json.loads((self.root/name).read_text())

    def rehash(self):
        self.summary['artifacts'] = {path.relative_to(self.root).as_posix(): native.sha256(path)
            for path in self.root.rglob('*') if path.is_file() and path.name != 'summary.json'}
        self.write('summary.json', self.summary)

    def verify(self):
        with patch.object(native, 'qemu_identity', return_value=self.qemu), \
             patch('verify_v13_a10_receipt.replay_child', return_value=self.summary):
            return native.verify_native_child(self.root, source_root=ROOT,
                build_manifest=self.build_root/'build-manifest.json', qemu_binary=self.root.parent/'trusted-qemu',
                qemu_source=self.root.parent/'synthetic-qemu-source')


class NativeCpuPlatform(unittest.TestCase):
    """Controlled local-host contexts; external fixture mocks grant no native proof."""
    def capture_cpus(self, fixture, cpus, *, host_platform):
        root = fixture.root
        context = fixture.read('native-context.json')
        context.update(pid=31836, host_platform=host_platform)
        fixture.write('native-context.json', context)
        platform = fixture.read('platform.json')
        platform['cpus'] = cpus
        fixture.write('platform.json', platform)
        rows = [json.loads(line) for line in (root/'qmp.jsonl').read_text().splitlines()]
        ident = next(row['message']['id'] for row in rows
                     if row['message'].get('execute') == 'query-cpus-fast')
        next(row['message'] for row in rows if row['direction'] == 'receive'
             and row['message'].get('id') == ident)['return'] = cpus
        (root/'qmp.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
        witness = [json.loads(line) for line in (root/'native-provenance.jsonl').read_text().splitlines()]
        for row in witness:
            if 'pid' in row: row['pid'] = 31836
            if 'peer_pid' in row: row['peer_pid'] = 31836
        (root/'native-provenance.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in witness))
        fixture.rehash()

    def test_actual_darwin_cpu_shape_matches_the_owned_process(self):
        with patch.object(native.sys, 'platform', 'darwin'), tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticChild(Path(directory))
            self.capture_cpus(fixture, copy.deepcopy(DARWIN_PREPARE_CPUS), host_platform='darwin')
            try:
                child = fixture.verify()
            except ValueError as error:
                self.fail('actual Darwin CPU shape rejected in synthetic lifecycle: '+str(error))
            self.assertEqual(child.context['pid'], 31836)
            self.assertEqual(child.summary['status'], 'PASS')
            self.assertEqual(child.summary['native_acceptance_status'], 'NOT_RUN')
            self.assertIs(child.summary['A10_complete'], False)

    def test_rehashed_cpu_thread_ids_follow_local_platform_rules(self):
        for host in ('darwin', 'linux'):
            with patch.object(native.sys, 'platform', host), tempfile.TemporaryDirectory() as directory:
                fixture = SyntheticChild(Path(directory))
                valid = [31836]*4 if host == 'darwin' else [31837,31838,31839,31840]
                cpus = copy.deepcopy(DARWIN_PREPARE_CPUS)
                for cpu, tid in zip(cpus, valid): cpu['thread-id'] = tid
                self.capture_cpus(fixture, cpus, host_platform=host)
                self.assertEqual(fixture.verify().summary['status'], 'PASS')
                invalid = ([31837]*4, [31836,31836,31836,31837], [31837,31838,31839,31840]) \
                    if host == 'darwin' else ([31837]*4, [31837,31838,31839,31839])
                invalid += tuple([bad]+valid[1:] for bad in (0, -1, True, 31836.0, '31836'))
                for ids in invalid:
                    with self.subTest(host=host, ids=ids):
                        for cpu, tid in zip(cpus, ids): cpu['thread-id'] = tid
                        self.capture_cpus(fixture, cpus, host_platform=host)
                        with self.assertRaisesRegex(ValueError, 'QMP platform|thread'):
                            fixture.verify()

    def test_rehashed_host_claim_cannot_select_thread_id_semantics(self):
        for host, ids in (('darwin', [31836]*4), ('linux', [31837,31838,31839,31840])):
            with patch.object(native.sys, 'platform', host), tempfile.TemporaryDirectory() as directory:
                fixture = SyntheticChild(Path(directory))
                cpus = copy.deepcopy(DARWIN_PREPARE_CPUS)
                for cpu, tid in zip(cpus, ids): cpu['thread-id'] = tid
                for claimed in ('linux' if host == 'darwin' else 'darwin', 'unreviewed-host'):
                    with self.subTest(local=host, claimed=claimed):
                        self.capture_cpus(fixture, cpus, host_platform=claimed)
                        with self.assertRaisesRegex(ValueError, 'host platform'):
                            fixture.verify()

    def test_rehashed_darwin_cpu_pid_cannot_replace_the_owned_process_witness(self):
        with patch.object(native.sys, 'platform', 'darwin'), tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticChild(Path(directory))
            cpus = copy.deepcopy(DARWIN_PREPARE_CPUS)
            for cpu in cpus: cpu['thread-id'] = 31837
            self.capture_cpus(fixture, cpus, host_platform='darwin')
            context = fixture.read('native-context.json')
            context['pid'] = 31837
            fixture.write('native-context.json', context)
            fixture.rehash()
            with self.assertRaisesRegex(ValueError, 'own-process'):
                fixture.verify()

    def test_rehashed_darwin_pid_fallback_keeps_four_cpus_and_exact_launch(self):
        with patch.object(native.sys, 'platform', 'darwin'), tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticChild(Path(directory))
            self.capture_cpus(fixture, copy.deepcopy(DARWIN_PREPARE_CPUS[:3]), host_platform='darwin')
            with self.assertRaisesRegex(ValueError, 'QMP platform'):
                fixture.verify()
            self.capture_cpus(fixture, copy.deepcopy(DARWIN_PREPARE_CPUS), host_platform='darwin')
            original = fixture.read('launch.json')
            for option, value in (('-smp','1'), ('-accel','tcg,thread=single'), ('-m','512M')):
                with self.subTest(option=option):
                    changed = copy.deepcopy(original)
                    changed['argv'][changed['argv'].index(option)+1] = value
                    fixture.write('launch.json', changed)
                    fixture.rehash()
                    with self.assertRaisesRegex(ValueError, 'native launch'):
                        fixture.verify()


class NativeChildScope(unittest.TestCase):
    def test_valid_clean_and_cut_children_retain_fixed_incomplete_scope(self):
        for cut in (False, True):
            with self.subTest(cut=cut), tempfile.TemporaryDirectory() as directory:
                fixture = SyntheticChild(Path(directory), cut=cut)
                summary = fixture.verify().summary
                self.assertEqual(summary['test_id'], 'A10')
                self.assertEqual(summary['native_acceptance_status'], 'NOT_RUN')
                for name in ('A10_complete', 'native_filesystem_fault_matrix_complete',
                             'runtime_truth_attested'):
                    self.assertIs(summary[name], False)
                self.assertEqual(summary['status'], 'NOT_RUN' if cut else 'PASS')
                self.assertIs(summary['cut_observed'], cut)
                self.assertIs(summary['native_mode_verified'], not cut)
                self.assertEqual(summary['capture_status'], 'FAULT_CAPTURED' if cut else 'VERIFIED')
                self.assertEqual(summary['scope'],
                    'one injected native prefix; no clean task completion inferred' if cut else
                    'one ordinary EL0 clean mode; complete fault/replay/eviction matrix remains unrun')

    def test_rehashed_producer_scope_cannot_promote_clean_or_cut_children(self):
        for cut in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                fixture = SyntheticChild(Path(directory), cut=cut)
                changes = (('A10_complete', True), ('native_filesystem_fault_matrix_complete', True),
                    ('runtime_truth_attested', True), ('native_acceptance_status', 'PASS'),
                    ('test_id', 'A02'), ('scope', 'complete native A10 acceptance'),
                    ('A10_complete', 0))
                for name, value in changes:
                    with self.subTest(cut=cut, field=name, value=value):
                        original = fixture.summary[name]
                        fixture.summary[name] = value
                        fixture.rehash()
                        with self.assertRaisesRegex(ValueError, 'classification|scope'):
                            fixture.verify()
                        fixture.summary[name] = original
                del fixture.summary['native_acceptance_status']
                fixture.rehash()
                with self.subTest(cut=cut, field='missing native acceptance'):
                    with self.assertRaisesRegex(ValueError, 'classification|scope'):
                        fixture.verify()


class NativeProtocolFields(unittest.TestCase):
    def test_clean_serial_drain_requires_empty_reply_without_exhaustion_or_frame_damage(self):
        from test_transport import frame
        for chunks in ([frame(1)], [frame(index) for index in range(1,9)],
                       [frame(1)[:10], b''], [b'corrupt bytes', b'']):
            with self.subTest(chunks=len(chunks)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaisesRegex(ValueError, 'serial|frame|drain'):
                    self.check(root, fixture(root, drains=chunks))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.check(root, fixture(root, drains=[frame(1), b'']))

    def test_final_disk_hash_requires_an_observation_after_backend_close(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = fixture(root)
            values[4][:] = [row for row in values[4] if row['event'] != 'final-disk']
            with self.assertRaisesRegex(ValueError, 'final.disk'):
                self.check(root, values)

    def test_qmp_cpu_identity_cannot_be_relabelled_with_a_matching_platform_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = fixture(root)
            command = next(r['message'] for r in values[3] if r['message'].get('execute') == 'query-cpus-fast')
            response = next(r['message'] for r in values[3] if r['direction'] == 'receive'
                            and r['message'].get('id') == command['id'])
            response['return'][0]['qom-type'] = 'cortex-a57-arm-cpu'
            platform = json.loads((root/'platform.json').read_text())
            platform['cpus'] = response['return']
            (root/'platform.json').write_text(json.dumps(platform))
            with self.assertRaisesRegex(ValueError, 'platform|CPU'):
                self.check(root, values)

    def test_dtb_topology_requires_the_actual_native_cpu_memory_and_gic_profile(self):
        try:
            native.validate_dtb(dtb_fixture())
        except ValueError as error:
            self.fail('valid synthetic DTB rejected: '+str(error))
        for data in (dtb_fixture(memory_size=512*1024**2), dtb_fixture(cpu_count=3),
                     dtb_fixture(controller=b'arm,gic-v3\0'), dtb_fixture()[:-1]):
            with self.assertRaises(ValueError): native.validate_dtb(data)

    def check(self, root, values):
        return native.validate_protocol(root, *values)

    def test_unknown_lifecycle_fields_and_noninteger_sequence_cannot_hide_an_operation(self):
        for change in ('field', 'sequence', 'request-field', 'save-hash'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                values = fixture(root)
                row = values[4][0]
                if change == 'field': row['extra_memory_write'] = True
                if change == 'sequence': row['seq'] = True
                if change == 'request-field': values[4][1]['execute'] = 'blockdev-flush'
                if change == 'save-hash':
                    next(row for row in values[4] if row['event'] == 'save')['sha256'] = 'z' * 64
                with self.assertRaises(ValueError): self.check(root, values)


class NativeTrustedBoundary(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = SyntheticChild(Path(temporary.name))

    def test_real_source_elf_and_protocol_accept_only_under_explicit_synthetic_external_context(self):
        child = self.fixture.verify()
        self.assertEqual(child.summary['status'], 'PASS')
        self.assertNotIn('native_execution_verified', child.summary)

    def test_published_cut_control_identity_remains_bound_without_requiring_clean_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticChild(Path(directory), cut=True)
            self.assertEqual(fixture.verify().summary['status'], 'NOT_RUN')
            path = fixture.root/'control-header.bin'
            data = bytearray(path.read_bytes()); data[160] ^= 1; path.write_bytes(data)
            witness_path = fixture.root/'native-provenance.jsonl'
            rows = [json.loads(line) for line in witness_path.read_text().splitlines()]
            next(row for row in rows if row['event']=='save' and row['name']=='control-header.bin')['sha256'] = native.sha256(path)
            witness_path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            fixture.rehash()
            with self.assertRaisesRegex(ValueError, 'model/schema'):
                fixture.verify()

    def test_resume_cannot_resolve_qemu_from_an_archive_selected_path(self):
        import run_v13_a10_matrix as matrix
        fixture = self.fixture
        attacker = fixture.root/'attacker-qemu'
        marker = fixture.root/'executed'
        attacker.write_text('#!/bin/sh\ntouch '+str(marker)+'\n')
        attacker.chmod(0o700)
        fixture.write('matrix-input.json', dict(qemu_binary=str(attacker), qemu_source=str(fixture.root)))
        with self.assertRaisesRegex(ValueError, 'caller-selected'):
            matrix.run(fixture.build_root/'build-manifest.json', fixture.root, resume=True)
        self.assertFalse(marker.exists())

    def test_legacy_pass_summary_without_native_witness_is_not_adoptable(self):
        fixture = self.fixture
        (fixture.root/'native-context.json').unlink()
        fixture.rehash()
        with self.assertRaisesRegex(ValueError, 'missing'):
            fixture.verify()

    def test_rehashed_peer_pid_cannot_relabel_a_different_process_as_qemu(self):
        fixture = self.fixture
        path = fixture.root/'native-provenance.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        next(row for row in rows if row['event']=='endpoint-connected')['peer_pid'] += 1
        path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        fixture.rehash()
        with self.assertRaisesRegex(ValueError, 'peer'):
            fixture.verify()

    def test_extra_nested_summary_cannot_escape_the_exact_native_inventory(self):
        fixture = self.fixture
        (fixture.root/'hidden').mkdir()
        (fixture.root/'hidden/summary.json').write_text('{}')
        fixture.rehash()
        with self.assertRaisesRegex(ValueError, 'inventory|extra'):
            fixture.verify()

    def test_mutable_disks_cannot_share_an_inode_even_with_equal_hashes(self):
        fixture = self.fixture
        (fixture.root/'disk.raw').unlink()
        (fixture.root/'disk.raw').hardlink_to(fixture.root/'initial.raw')
        fixture.rehash()
        with self.assertRaisesRegex(ValueError, 'backing|shared|link'):
            fixture.verify()

    def test_oversized_preboot_bytes_fail_before_whole_file_reads(self):
        fixture = self.fixture
        path = fixture.root/'config.bin'
        with path.open('wb') as stream: stream.truncate(8*1024**2)
        fixture.rehash()
        original = Path.read_bytes
        def guarded(selected):
            if selected == path:
                self.fail('oversized preboot file reached read_bytes')
            return original(selected)
        with patch.object(Path, 'read_bytes', guarded):
            with self.assertRaisesRegex(ValueError, 'size|bound'):
                fixture.verify()

    def test_native_nbd_json_rejects_duplicate_keys_before_legacy_raw_replay(self):
        fixture = self.fixture
        with gzip.open(fixture.root/'nbd/events.jsonl.gz', 'wb') as stream:
            stream.write(b'{"event":"cut","id":1,"id":2}\n')
        fixture.rehash()
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'):
            fixture.verify()

    def test_recomputed_outer_inventory_cannot_trust_archive_selected_code_or_image(self):
        fixture = self.fixture
        original = {name: (fixture.root/name).read_bytes() for name in
            ('native-tools.json', 'native-tools/verify_v13_a10_native_receipt.py',
             'source-manifest.json', 'node-a.elf', 'model.bin', 'build-inputs/Cargo.lock')}
        changes = [('tool', 'native-tools/verify_v13_a10_native_receipt.py', 'tool'),
                   ('source', 'source-manifest.json', 'source/build'),
                   ('image', 'node-a.elf', 'image'), ('model', 'model.bin', 'model'),
                   ('lock', 'build-inputs/Cargo.lock', 'build input')]
        for kind, name, message in changes:
            with self.subTest(kind=kind):
                path = fixture.root/name
                if kind == 'source':
                    sources = fixture.read(name)
                    sources['kernel/src/smp.rs'] = '00'*32
                    fixture.write(name, sources)
                else:
                    data = bytearray(path.read_bytes()); data[-1] ^= 1; path.write_bytes(data)
                if kind == 'tool':
                    closure = fixture.read('native-tools.json')
                    closure['verify_v13_a10_native_receipt.py'] = native.sha256(path)
                    fixture.write('native-tools.json', closure)
                fixture.rehash()
                with self.assertRaisesRegex(ValueError, message): fixture.verify()
                for changed, data in original.items(): (fixture.root/changed).write_bytes(data)
                fixture.rehash()

    def test_recomputed_outer_inventory_rejects_launch_endpoint_and_preboot_injection_tampering(self):
        fixture = self.fixture
        names = ('launch.json', 'native-context.json', 'config-injection.json', 'qemu-source.json')
        original = {name: (fixture.root/name).read_bytes() for name in names}
        for kind, message in (('loader','launch'), ('endpoint','launch'), ('symbols','symbols'),
                              ('backing','backing'), ('packet','preboot'), ('qemu','QEMU')):
            with self.subTest(kind=kind):
                if kind in ('loader', 'endpoint', 'symbols'):
                    launch = fixture.read('launch.json')
                    if kind == 'loader': launch['argv'] += ['-device', 'loader,file=/attacker']
                    if kind == 'endpoint':
                        launch['argv'][launch['argv'].index('-drive')+1] = 'if=none,id=disk0,file=nbd:unix:/wrong,format=raw,cache=writeback'
                    if kind == 'symbols': launch['symbols']['config']['pa'] += 8
                    fixture.write('launch.json', launch)
                if kind == 'backing':
                    context = fixture.read('native-context.json'); context['backing_path'] += '-other'
                    fixture.write('native-context.json', context)
                if kind == 'packet':
                    packet = fixture.read('config-injection.json'); packet['request_hex'] += '00'
                    fixture.write('config-injection.json', packet)
                if kind == 'qemu':
                    proof = fixture.read('qemu-source.json'); proof['binary_sha256'] = '22'*32
                    fixture.write('qemu-source.json', proof)
                fixture.rehash()
                with self.assertRaisesRegex(ValueError, message): fixture.verify()
                for name, data in original.items(): (fixture.root/name).write_bytes(data)
                fixture.rehash()

class ProvisionProvenance(unittest.TestCase):
    def test_formatter_bytes_toolchain_and_raw_compiler_output_are_independently_bound(self):
        # External filesystem oracle/toolchain are explicit synthetic boundaries;
        # this validates metadata custody only and never creates native evidence.
        import v13_a10_native_capture as capture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            trusted = root/'trusted-formatter'
            trusted.write_bytes(b'synthetic trusted formatter bytes')
            archived = root/'formatter.bin'; archived.write_bytes(trusted.read_bytes()); archived.chmod(0o600)
            build = root/'build-manifest.json'; build.write_text('{}')
            with (root/'formatted.raw').open('wb') as stream: stream.truncate(512*1024**2)
            for name in ('provision-build.stderr','provision.stdout','provision.stderr','provision.log'):
                (root/name).write_text('')
            artifact = dict(reason='compiler-artifact', target=dict(name='prototype-disk', kind=['example']),
                            executable=str(trusted))
            (root/'provision-build.stdout').write_text(json.dumps(artifact)+'\n')
            tools = dict(rustup=dict(path='/trusted/rustup', sha256='11'*32),
                         cargo=dict(sha256='22'*32), rustc=dict(sha256='33'*32, host='aarch64-apple-darwin'))
            matrix = dict(build_manifest_sha256=native.sha256(build), filesystem_uuid='11'*16,
                source_manifest_sha256='44'*32, formatted_disk_sha256=native.sha256(root/'formatted.raw'),
                provision_log_sha256=native.sha256(root/'provision.log'))
            proof = dict(version=native.VERSION, returncode=0, build_returncode=0,
                argv=[str(trusted),str(root/'formatted.raw'),'11'*16], capture_root=str(root), cwd=str(ROOT),
                build_argv=['/trusted/rustup','run','stable','cargo','build','--locked','--offline',
                    '-p','cyxia-prototype','--example','prototype-disk','--message-format=json-render-diagnostics',
                    '--target','aarch64-apple-darwin'],
                tools_before=tools,tools_after=tools,compiler_artifact=str(trusted),formatter_path=str(trusted),
                formatter_sha256=native.sha256(trusted), source_sha256=matrix['source_manifest_sha256'],
                build_sha256=matrix['build_manifest_sha256'],disk_sha256=matrix['formatted_disk_sha256'],
                log_sha256=matrix['provision_log_sha256'],
                build_stdout_sha256=native.sha256(root/'provision-build.stdout'),
                build_stderr_sha256=native.sha256(root/'provision-build.stderr'),
                environment=dict(removed=['RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTFLAGS',
                    'CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTC_WRAPPER',
                    'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET','CARGO_BUILD_RUSTFLAGS'],
                    values=capture.formatter_environment()))
            fresh = dict(uuid='11'*16,boot_epoch=0,files={},directories={'/':{}})
            def verify(value):
                (root/'provision.json').write_text(json.dumps(value))
                with patch.object(capture,'formatter_identity',return_value=tools), \
                     patch('check_v13_filesystem.inspect',return_value=fresh):
                    native.verify_provision(root,matrix,source_root=ROOT,build_manifest=build,
                                            formatter_binary=trusted)
            verify(proof)
            for change in ('binary','toolchain','compiler-output','returncode','invoked-path','compiler-path'):
                with self.subTest(change=change):
                    altered = copy.deepcopy(proof)
                    if change == 'binary':
                        archived.write_text('#!/bin/sh\ntouch '+shlex.quote(str(root/'NEVER_EXECUTED'))+'\n')
                        altered['formatter_sha256'] = native.sha256(archived)
                    if change == 'toolchain':
                        altered['tools_before']['cargo']['sha256'] = '55'*32
                        altered['tools_after'] = copy.deepcopy(altered['tools_before'])
                    if change == 'compiler-output':
                        (root/'provision-build.stdout').write_text(json.dumps(dict(artifact,
                            target=dict(name='prototype-disk',kind=['lib'])))+'\n')
                        altered['build_stdout_sha256'] = native.sha256(root/'provision-build.stdout')
                    if change == 'returncode': altered['returncode'] = 1
                    if change in ('invoked-path', 'compiler-path'):
                        other = root/'other-formatter'; other.write_bytes(trusted.read_bytes())
                        if change == 'invoked-path':
                            altered['formatter_path'] = altered['argv'][0] = str(other)
                        else:
                            altered['compiler_artifact'] = str(other)
                            (root/'provision-build.stdout').write_text(json.dumps(dict(artifact,
                                executable=str(other)))+'\n')
                            altered['build_stdout_sha256'] = native.sha256(root/'provision-build.stdout')
                    with self.assertRaises(ValueError): verify(altered)
                    archived.write_bytes(trusted.read_bytes())
                    (root/'provision-build.stdout').write_text(json.dumps(artifact)+'\n')
            self.assertFalse((root/'NEVER_EXECUTED').exists())


class NativeProtocol(unittest.TestCase):
    def test_formatter_environment_excludes_secrets_and_arbitrary_compiler_overrides(self):
        import v13_a10_native_capture as capture
        with patch.object(capture, 'env', return_value=dict(PATH='/trusted', HOME='/local',
                CARGO_TARGET_DIR='/target', RUSTC='/attacker', CARGO_ENCODED_RUSTFLAGS='attack',
                API_SECRET='secret', LC_ALL='host-locale')):
            self.assertEqual(capture.formatter_environment(), dict(PATH='/trusted', HOME='/local',
                CARGO_TARGET_DIR='/target', LC_ALL='C', LANG='C', TZ='UTC'))

    def test_nbd_peer_platform_rules_fail_closed_on_supported_errors(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        import v13_fault_disk as fault
        for platform, response, expected in (('darwin', 123, 'kernel-pid'),
                ('linux', struct.pack('3i', 123, 456, 789), 'kernel-pid'),
                ('unsupported', None, 'private-directory-one-connection-unsupported'),
                ('darwin', PermissionError('denied'), None)):
            with self.subTest(platform=platform, expected=expected):
                events, served = [], []
                connection = MagicMock()
                if isinstance(response, Exception): connection.getsockopt.side_effect = response
                else: connection.getsockopt.return_value = response
                server = object.__new__(fault.Server)
                server.path, server.error = Path('/private/disk.sock'), None
                server.listener = SimpleNamespace(accept=lambda: (connection, None))
                server.backend = SimpleNamespace(meta=dict(run_id='11'*16),
                    witness=lambda event, **fields: events.append(dict(event=event, **fields)),
                    serve=lambda sock: served.append(sock))
                with patch.object(fault.sys, 'platform', platform), \
                     patch.object(fault.socket, 'SO_PEERCRED', 17, create=True):
                    server.run()
                if expected is None:
                    self.assertIsInstance(server.error, PermissionError)
                    self.assertEqual(events, []); self.assertEqual(served, [])
                else:
                    self.assertIsNone(server.error)
                    self.assertEqual(events[0]['peer_identity'], expected)
                    self.assertEqual(events[0]['peer_pid'], None if platform=='unsupported' else 123)
                    self.assertEqual(len(served), 1)

    def test_streaming_parser_enforces_actual_byte_and_row_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'rows'
            path.write_bytes(b'{}\n{}\n')
            with patch.object(native, 'capture_limits', return_value=dict(bytes=100, witness_rows=1)):
                with self.assertRaisesRegex(ValueError, 'count/byte'):
                    list(native.read_rows(path, {}))
            # Simulate growth after the initial stat without allocating a large file.
            with patch.object(native, 'capture_limits', return_value=dict(bytes=4, witness_rows=100)), \
                 patch.object(Path, 'stat', return_value=type('Size', (), {'st_size': 0})()):
                with self.assertRaisesRegex(ValueError, 'count/byte'):
                    list(native.read_rows(path, {}))

    def test_exhausted_witness_cannot_skip_owned_kill_wait_backend_close_and_journal_close(self):
        from types import SimpleNamespace
        from v13_a10_native_capture import Witness, close_capture
        with tempfile.TemporaryDirectory() as directory:
            witness = Witness(Path(directory)/'witness', byte_limit=0, row_limit=0)
            calls, report = [], {}
            proc = SimpleNamespace(pid=123, returncode=-9, poll=lambda: None,
                kill=lambda: calls.append('kill'), wait=lambda timeout: calls.append('wait'))
            sock = SimpleNamespace(close=lambda: calls.append('socket-close'))
            server = SimpleNamespace(close=lambda: calls.append('backend-close'), error=None)
            qmp = SimpleNamespace(close_journal=lambda: calls.append('journal-close'))
            backend = SimpleNamespace(meta=dict(run_id='11'*16))
            try:
                close_capture(proc,sock,server,qmp,backend,witness,report)
            except ValueError as error:
                self.fail('receipt limit interrupted mandatory cleanup: '+str(error))
            self.assertEqual(calls, ['kill','wait','socket-close','backend-close','journal-close'])
            self.assertIn('error', report)

    def test_streaming_qmp_journal_keeps_cut_between_actual_cont_request_and_reply(self):
        from v13_a10_native_capture import NativeQmp, Witness
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness = Witness(root/'witness.jsonl')
            client, server = socket.socketpair()
            self.addCleanup(client.close); self.addCleanup(server.close)
            def peer():
                request = json.loads(server.recv(4096))
                witness.record('backend-cut', run_id='ab'*16, id=1, mutation=1, phase='before')
                server.sendall(json.dumps(dict(event='RESUME', timestamp=dict(seconds=1,microseconds=1))).encode()+b'\n'
                    +json.dumps(dict(id=request['id'], **{'return':{}})).encode()+b'\n')
            worker = threading.Thread(target=peer); worker.start()
            qmp = NativeQmp(client,witness,journal_path=root/'qmp.jsonl',byte_limit=4096,command_limit=2)
            try:
                self.assertEqual(qmp.execute('cont'), {})
            finally:
                qmp.close_journal(); worker.join(2)
            rows = [json.loads(line) for line in (root/'qmp.jsonl').read_text().splitlines()]
            self.assertEqual([row['direction'] for row in rows], ['send','receive','receive'])
            self.assertEqual([row['message'].get('execute') for row in qmp.capture_commands], ['cont'])
            events = [json.loads(line)['event'] for line in (root/'witness.jsonl').read_text().splitlines()]
            self.assertEqual(events, ['qmp-request','backend-cut','qmp-response'])

    def test_journal_caps_fail_before_silently_dropping_or_accumulating_commands(self):
        from v13_a10_native_capture import TranscriptJournal
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for limit, count in ((1,2),(4096,0)):
                journal = TranscriptJournal(root/f'{limit}-{count}',byte_limit=limit,command_limit=count)
                try:
                    with self.assertRaises(ValueError):
                        journal.append(dict(direction='send',message=dict(execute='cont',id=1)))
                finally: journal.close()

    def test_witness_caps_preserve_complete_prefix(self):
        from v13_a10_native_capture import Witness
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'witness'
            witness = Witness(path, byte_limit=4096, row_limit=1)
            witness.record('spawn', pid=1)
            before = path.read_bytes()
            with self.assertRaises(ValueError): witness.record('kill', pid=1, signal=9)
            self.assertEqual(path.read_bytes(), before)
            limited = Witness(Path(directory)/'bounded', byte_limit=1, row_limit=2)
            with self.assertRaises(ValueError): limited.record('spawn', pid=1)

    def test_streaming_journal_retains_error_response_when_execute_raises(self):
        from v13_a10_native_capture import NativeQmp, Witness
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client, server = socket.socketpair()
            self.addCleanup(client.close); self.addCleanup(server.close)
            def peer():
                request = json.loads(server.recv(4096))
                server.sendall(json.dumps(dict(id=request['id'],error=dict(**{'class':'GenericError','desc':'synthetic'}))).encode()+b'\n')
            worker=threading.Thread(target=peer); worker.start()
            qmp=NativeQmp(client,Witness(root/'witness'),journal_path=root/'qmp',byte_limit=4096,command_limit=1)
            try:
                with self.assertRaises(RuntimeError): qmp.execute('cont')
            finally:
                qmp.close_journal(); worker.join(2)
            rows=[json.loads(line) for line in (root/'qmp').read_text().splitlines()]
            self.assertEqual(len(rows),2)
            self.assertIn('error',rows[1]['message'])

    def test_formatter_compiler_output_is_bounded_metadata_never_an_executable_request(self):
        from v13_a10_native_capture import formatter_artifact
        row = dict(reason='compiler-artifact', target=dict(name='prototype-disk', kind=['example']),
                   executable='/trusted/formatter')
        self.assertEqual(formatter_artifact(json.dumps(row)+'\n'), '/trusted/formatter')
        for output in (json.dumps(row)+'\n'+json.dumps(row)+'\n', '{}\n',
                       '{"reason":"compiler-artifact","reason":"other"}\n',
                       json.dumps(dict(row, executable='../attacker'))+'\n'):
            with self.assertRaises(ValueError): formatter_artifact(output)

    def test_private_nbd_connection_records_the_kernel_peer_process_when_supported(self):
        from v13_fault_disk import Backend, Server
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disk = root/'disk'; disk.write_bytes(bytes(4096))
            rows = []
            backend = Backend(disk, root/'nbd', witness=lambda event, **fields: rows.append(dict(event=event, **fields)))
            server = Server(backend, root/'nbd.sock')
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(root/'nbd.sock'))
                    self.assertEqual(len(client.recv(18)), 18)
                server.close()
                connected = next(row for row in rows if row['event'] == 'endpoint-connected')
                if sys.platform in ('darwin', 'linux'):
                    self.assertEqual(connected.get('peer_pid'), os.getpid())
                    self.assertEqual(connected.get('peer_identity'), 'kernel-pid')
            finally:
                server.close()

    def test_formatter_identity_resolves_only_fixed_local_toolchain_commands(self):
        from v13_a10_native_capture import formatter_identity
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for tool in ('cargo', 'rustc'):
                path = root/tool
                path.write_text('#!/bin/sh\necho "synthetic '+tool+'"\n'
                    + ('echo "host: x86_64-unknown-linux-gnu"\n' if tool == 'rustc' else ''))
                path.chmod(0o700)
            rustup = root/'rustup'
            rustup.write_text('#!/bin/sh\nif [ "$1" = which ]; then echo '+shlex.quote(str(root))+'/$4; else echo synthetic-rustup; fi\n')
            rustup.chmod(0o700)
            try:
                identity = formatter_identity(rustup)
            except ValueError as error:
                self.fail('trusted toolchain identity rejected: '+str(error))
            self.assertEqual(set(identity), {'rustup', 'cargo', 'rustc'})
            self.assertEqual(identity['cargo']['lookup_output'], str(root/'cargo')+'\n')
            self.assertEqual(identity['rustc']['sha256'], hashlib.sha256((root/'rustc').read_bytes()).hexdigest())

    def test_oversized_saved_file_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = fixture(root)
            with (root / 'platform.dtb').open('r+b') as stream: stream.truncate(2 * 1024**2 + 1)
            with self.assertRaises(ValueError): self.check(root, values)

    def test_bounded_jsonl_rejects_duplicates_nonfinite_and_truncation(self):
        for data in (b'{"event":"kill","event":"save"}\n', b'{"time":NaN}\n',
                     b'{"time":Infinity}\n', b'{"time":1e999}\n', b'{}', b'[]\n'):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'qmp.jsonl'
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    list(native.read_rows(path, dict(sample_ms=100, capture_timeout_seconds=5)))

    def test_total_and_frame_bounds_fail_without_reading_large_sparse_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'qmp.jsonl'
            with path.open('wb') as stream: stream.truncate(17 * 1024**2 + 1000000)
            with self.assertRaisesRegex(ValueError, 'total bound'):
                list(native.read_rows(path, dict(sample_ms=30000, capture_timeout_seconds=5)))
            with path.open('wb') as stream: stream.truncate(4 * 1024**2 + 1)
            with self.assertRaisesRegex(ValueError, 'frame bound'):
                list(native.read_rows(path, dict(sample_ms=30000, capture_timeout_seconds=5)))

    def test_qmp_wrapper_uses_real_protocol_and_persists_request_reply_order(self):
        from v13_a10_native_capture import NativeQmp, Witness
        with tempfile.TemporaryDirectory() as directory:
            client, server = socket.socketpair()
            self.addCleanup(client.close)
            self.addCleanup(server.close)
            def peer():
                request = json.loads(server.recv(4096))
                server.sendall(json.dumps(dict(id=request['id'], **{'return': {}})).encode() + b'\n')
            worker = threading.Thread(target=peer)
            worker.start()
            path = Path(directory) / 'witness.jsonl'
            qmp = NativeQmp(client, Witness(path))
            self.assertEqual(qmp.execute('qmp_capabilities'), {})
            worker.join(2)
            self.assertFalse(worker.is_alive())
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([(r['event'], r['id']) for r in rows], [('qmp-request', 1), ('qmp-response', 1)])
            self.assertEqual([r['direction'] for r in qmp.transcript], ['send', 'receive'])

    def test_real_backend_cut_witness_follows_survivors_and_precedes_event_publication(self):
        from test_v13_fault_disk import VolatileNbd
        fixture = VolatileNbd()
        self.addCleanup(fixture.doCleanups)
        fixture.start(cut=3, phase='after-ack', unflushed='reverse-half')
        observed = []
        def record(event, **fields):
            observed.append((event, fields, fixture.backend.cut_event.is_set(), fixture.path.read_bytes()))
        fixture.backend.witness = record
        for index in (1, 2, 3):
            fixture.request(1, index, offset=(index - 1) * 512, data=bytes([index]) * 512)
            fixture.reply(index)
        self.assertTrue(fixture.backend.cut_event.wait(2))
        fixture.finish()
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], 'backend-cut')
        self.assertFalse(observed[0][2])
        self.assertEqual(observed[0][3], bytes(512) + bytes([2])*512 + bytes([3])*512 + bytes(2560))
        self.assertEqual(fixture.inspect()['cut']['acks'], 3)

    def test_shared_witness_records_concurrent_observations_without_losing_order(self):
        from v13_a10_native_capture import Witness
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native-provenance.jsonl'
            witness = Witness(path)
            workers = [threading.Thread(target=lambda: [witness.record('observation', value=i)
                       for i in range(50)]) for _ in range(4)]
            for worker in workers: worker.start()
            for worker in workers: worker.join()
            self.assertTrue(path.exists(), 'shared lifecycle observations were not persisted')
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([r['seq'] for r in rows], list(range(1, 201)))
            self.assertEqual([r['monotonic_ns'] for r in rows], sorted(r['monotonic_ns'] for r in rows))

    def check(self, root, values):
        return native.validate_protocol(root, *values)

    def test_live_confirmed_capture_and_cut_capture_are_distinct_valid_protocols(self):
        for cut in (False, True):
            with self.subTest(cut=cut), tempfile.TemporaryDirectory() as directory:
                try:
                    result = self.check(Path(directory), fixture(Path(directory), cut))
                except ValueError as error:
                    self.fail('valid synthetic protocol rejected: ' + str(error))
                self.assertEqual(result['cut_observed'], cut)
                self.assertNotIn('native_execution_verified', result)

    def test_clean_stop_flush_and_unknown_commands_rejected(self):
        for forbidden in ('stop', 'quit', 'blockdev-flush', 'human-monitor-command'):
            with self.subTest(command=forbidden), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                values = fixture(root)
                row = next(r for r in values[3] if r.get('message', {}).get('execute') == 'ringbuf-read')
                row['message']['execute'] = forbidden
                with self.assertRaises(ValueError):
                    self.check(root, values)

    def test_reordered_duplicate_missing_response_and_wrong_save_range_rejected(self):
        for change in ('reorder', 'duplicate', 'missing', 'address', 'path', 'extra', 'status'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                values = fixture(root)
                rows = values[3]
                if change == 'reorder': rows[1], rows[2] = rows[2], rows[1]
                if change == 'duplicate': rows.insert(3, copy.deepcopy(rows[2]))
                if change == 'missing': del rows[2]
                if change in ('address', 'path'):
                    args = next(r['message']['arguments'] for r in rows if r['message'].get('execute') == 'pmemsave')
                    args['val' if change == 'address' else 'filename'] = 42 if change == 'address' else '/tmp/escape'
                if change == 'extra': rows[1]['message']['extra'] = True
                if change == 'status': rows[4]['message']['return']['running'] = True
                with self.assertRaises(ValueError): self.check(root, values)

    def test_cut_observation_must_precede_stop_on_shared_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = fixture(root, True)
            witness = values[4]
            cut = next(r for r in witness if r['event'] == 'backend-cut')
            witness.remove(cut)
            witness.insert(-4, cut)
            for index, row in enumerate(witness): row.update(seq=index + 1, monotonic_ns=index + 1)
            with self.assertRaisesRegex(ValueError, 'cut.*stop|stop.*cut'):
                self.check(root, values)

    def test_cut_observation_cannot_precede_the_actual_resume_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = fixture(root, cut=True)
            resume = next(row['message']['id'] for row in values[3]
                          if row['message'].get('execute') == 'cont')
            witness = values[4]
            cut = next(row for row in witness if row['event']=='backend-cut')
            witness.remove(cut)
            index = next(index for index,row in enumerate(witness)
                         if row['event']=='qmp-request' and row['id']==resume)
            witness.insert(index, cut)
            for position,row in enumerate(witness): row.update(seq=position+1,monotonic_ns=position+1)
            with self.assertRaisesRegex(ValueError, 'cut|resume'):
                self.check(root, values)
            witness.remove(cut)
            witness.insert(index + 1, cut)
            for position,row in enumerate(witness): row.update(seq=position+1,monotonic_ns=position+1)
            self.check(root, values)

    def test_rehashed_confirmation_serial_and_exit_tampering_rejected(self):
        for change in ('confirm', 'serial', 'exit', 'kill'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                values = fixture(root)
                if change == 'confirm':
                    path = root / 'consumption-confirm.bin'
                    path.write_bytes(b'x' + path.read_bytes()[1:])
                    next(r for r in values[4] if r.get('name') == path.name)['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                if change == 'serial': (root / 'serial.bin').write_bytes(b'fabricated')
                if change == 'exit':
                    path = root / 'pending-progress.bin'
                    path.write_bytes(bytes(512))
                    next(r for r in values[4] if r.get('name') == path.name)['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                if change == 'kill': next(r for r in values[4] if r['event'] == 'wait')['returncode'] = 0
                with self.assertRaises(ValueError): self.check(root, values)
