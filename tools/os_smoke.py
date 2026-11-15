#!/usr/bin/env python3
"""Exercise real x86 OS serial input, processes and a dedicated persistent disk."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import os_x86
import x86_64 as pc
from native_session import native_lease, idle_native_host, DEFAULT_NATIVE_LOCK
from run_qemu import Qmp
from storage import create_disk

PROMPT = rb'cyxia:/> '

def verify_boot_frame(path):
    raw = pc.bounded_bytes(path, 4 * 1024 * 1024)
    parts = raw.split(b'\n', 3)
    pc.require(len(parts) == 4 and parts[:3] == [b'P6', b'1024 768', b'255'],
               'capture is not the actual 1024x768 VirtIO scanout')
    colors = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0),
              (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0)]
    row = b''.join(bytes(color) * 128 for color in colors)
    pc.require(parts[3] == row * 768, 'actual VirtIO pixels disagree with submitted framebuffer')
    return dict(width=1024, height=768, verified_pixels=1024 * 768, sha256=pc.sha_bytes(raw))

def connect(path, process):
    sock = socket.socket(socket.AF_UNIX)
    deadline = time.monotonic() + 30
    while True:
        try:
            sock.connect(str(path)); return sock
        except (FileNotFoundError, ConnectionRefusedError):
            pc.require(process.poll() is None, 'QEMU exited before socket connection')
            pc.require(time.monotonic() < deadline, 'QEMU socket connection timeout')
            time.sleep(.01)

class Console:
    def __init__(self, sock, process, capture_path):
        self.sock = sock; self.process = process; self.raw = bytearray(); self.commands = []
        self.capture_path = capture_path
        self.capture_path.write_bytes(b'')
        self.sock.setblocking(False)

    def pump(self):
        while True:
            try:
                data = self.sock.recv(65536)
                if not data: break
                self.raw.extend(data)
                with self.capture_path.open('ab') as capture: capture.write(data)
            except BlockingIOError: break
        pc.require(len(self.raw) < 4 * 1024 * 1024, 'OS serial capture budget')
        pc.require(not any(marker in self.raw for marker in
                   (b'X86_FAIL', b'NATIVE_SERVICE_PANIC', b'NATIVE_SERVICE_CHECK_FAILED',
                    b'POSIX CHECK FAILED', b'STORAGE_ERROR', b'_PROBE FAIL', b'_PROBE RESULT FAIL', b' panicked at ',
                    b'start failed:', b'pair failed:')), 'guest failure')
        pc.require(self.process.poll() is None, 'QEMU exited unexpectedly')

    def until(self, pattern, start=0, timeout=30):
        deadline = time.monotonic() + timeout
        while True:
            self.pump()
            found = re.search(pattern, self.raw[start:], re.MULTILINE)
            if found: return found
            if time.monotonic() >= deadline: raise TimeoutError(f'guest output: {pattern!r}')
            time.sleep(.005)

    def command(self, command, expected=()):
        start = len(self.raw)
        self.commands.append(dict(command=command, serial_offset=start))
        # A socket chardev feeds UART RX. QMP ringbuf-write only changes its
        # backend buffer and must never be used as evidence of guest execution.
        self.sock.sendall(command.encode('ascii') + b'\r')
        self.until(PROMPT, start)
        for pattern in expected: self.until(pattern, start)
        pc.require(not re.search(rb'(error:|start failed:|pair failed:)', self.raw[start:]), 'command failed')
        return start

    def program(self, command, marker=None, state='Exited', code=0):
        start = self.command(command)
        pid = self.until(rb'pid=(\d+) started;', start).group(1)
        if marker: self.until(re.escape(marker), start)
        self.until(rb'pid=' + pid + rb' ' + state.encode() + rb' code=' + str(code).encode() + rb'\b', start)
        return start

def native_checks(console):
    console.program('posix run demo', b'C program: PASS')
    console.program('posix run preempt', b'REGISTERS PASS')
    at = console.command('posix status')
    console.until(rb'preemptions: [1-9]\d*', at)
    for mode in ('fault', 'readonly', 'execdata', 'kernel', 'guard'):
        console.program('posix run ' + mode, state='Fault', code=139)
    console.program('posix spawn fpu', b'NATIVE_FP_TLS_PASS')
    console.program('posix spawn heap', b'NATIVE_HEAP_PASS')
    at = console.command('posix pair', [rb'NATIVE_IPC_SERVER_PASS', rb'NATIVE_IPC_CLIENT_PASS'])
    console.until(rb'IPC pair server=(\d+) client=(\d+)', at)
    pair = re.search(rb'IPC pair server=(\d+) client=(\d+)', console.raw[at:])
    for pid in pair.groups(): console.until(rb'pid=' + pid + rb' Exited code=0\b', at)

def ported_checks(console):
    for name, marker in [('probe', b'PORTED_PROBE PASS'),
                         ('xkbcommon-probe', b'XKBCOMMON_PROBE PASS'),
                         ('wayland-probe', b'WAYLAND_PROBE PASS'),
                         ('rust-std-probe', b'RUST_STD_PROBE PASS')]:
        at = console.program('posix exec ' + name, marker)
        if name == 'rust-std-probe':
            console.until(b'RUST_STD_PROBE EPOLL_SIZE PASS', at)
            for fault in ('MAPERR', 'READONLY', 'PROT_NONE'):
                console.until(('RUST_STD_PROBE PF_' + fault + ' PASS').encode(), at)

def object_snapshot(console):
    from verify_fd_share import objects
    at = console.command('ai system')
    console.until(rb'AI_SYSTEM_END\r?\n', at)
    return objects(bytes(console.raw[at:]))

def reclaimed_probe(console, pid, before_objects, *, state="Exited", code=0):
    from verify_ported import parse_processes
    console.until(rb'pid=' + pid + b' ' + state.encode() + rb' code=' + str(code).encode() + rb'\b')
    at = console.command('posix list')
    process = parse_processes(bytes(console.raw[at:]))[int(pid)]
    for name, expected in dict(state=state, code=code, free_pages=64, heap_pages=0,
                               image_pages=0, thread_count=0, heap_free=4096,
                               image_free=16384).items():
        pc.require(process.get(name) == expected, 'probe did not reclaim ' + name)
    after_objects = object_snapshot(console)
    pc.require(after_objects == before_objects, 'probe open descriptions were not reclaimed')
    return dict(pid=int(pid), process=process, objects_before=before_objects, objects_after=after_objects)

def flock_checks(console):
    before_objects = object_snapshot(console)
    pc.require(before_objects['live'] == before_objects['references'] == 0,
               'flock capture begins with live open descriptions')
    start = console.command('posix exec flock-probe')
    pid = console.until(rb'ELF pid=(\d+) started;', start).group(1)
    for phase in ('RUNTIME_DIRECTORY', 'INDEPENDENT_DUP_RELEASE', 'SHARED_CONVERSION',
                  'INVALID_INPUT', 'INODE_IDENTITY'):
        console.until(('FLOCK_PROBE ' + phase + ' PASS').encode(), start)
    phases = []
    for phase in ('BLOCKING_UNLOCK', 'INTERRUPT', 'RETRY_REUSE'):
        console.until(('FLOCK_PROBE WAIT ' + phase).encode(), start)
        def waits():
            at = console.command('posix status')
            row = console.until(rb'UserStatus \{ pid: ' + pid + rb',[^\r\n]+', at).group(0)
            pc.require(b'state: Running' in row or b'state: Waiting' in row,
                       'flock process ended before its host gate')
            count = re.search(rb'\bwaits: (\d+)', row)
            pc.require(count is not None, 'missing real syscall wait counter')
            return int(count.group(1))
        before = waits()
        deadline = time.monotonic() + 5
        while True:
            after = waits()
            if after > before: break
            pc.require(time.monotonic() < deadline, 'flock worker did not park and retry')
            time.sleep(.01)
        console.command('touch /run/user/0/flock-' + phase)
        console.until(('FLOCK_PROBE ' + phase + ' PASS').encode(), start)
        phases.append(dict(phase=phase, waits_before=before, waits_after=after))
    console.until(rb'FLOCK_PROBE PASS', start)
    return dict(reclaimed_probe(console, pid, before_objects), phases=phases)

def nested_epoll_checks(console):
    before_objects = object_snapshot(console)
    pc.require(before_objects['live'] == before_objects['references'] == 0,
               'nested epoll capture begins with live open descriptions')
    start = console.command('posix exec nested-epoll-probe')
    pid = console.until(rb'ELF pid=(\d+) started;', start).group(1)
    for phase in ('LEVEL', 'INNER_ONESHOT', 'OUTER_EDGE', 'CYCLE_REJECTION', 'OFD_REUSE', 'SOCKET_TIMER'):
        console.until(('NESTED_EPOLL_PROBE ' + phase + ' PASS').encode(), start)
    console.until(rb'NESTED_EPOLL_PROBE PASS', start)
    result = reclaimed_probe(console, pid, before_objects)
    pc.require(result['process']['waits'] > 0, 'nested epoll timer did not enter the actual wait path')
    return result

def inotify_checks(console):
    before_objects = object_snapshot(console)
    pc.require(all(before_objects.get(key) == 0 for key in
                   ('live', 'references', 'inotify_instances', 'inotify_watches', 'inotify_events')),
               'inotify capture begins with live objects or missing accounting')
    start = console.command('posix exec inotify-probe')
    pid = console.until(rb'ELF pid=(\d+) started;', start).group(1)
    for phase in ('FLAGS_MASKS', 'FILE_EVENTS', 'RENAME', 'WATCH_LIFETIME',
                  'UNLINK_POLICY', 'RECORDS_DUP', 'VECTORED_READ', 'READINESS', 'OVERFLOW'):
        console.until(('INOTIFY_PROBE ' + phase + ' PASS').encode(), start)
    phases = []
    for phase in ('BLOCKING_READ', 'INTERRUPT', 'RETRY_REUSE'):
        console.until(('INOTIFY_PROBE WAIT ' + phase).encode(), start)
        def waits():
            at = console.command('posix status')
            row = console.until(rb'UserStatus \{ pid: ' + pid + rb',[^\r\n]+', at).group(0)
            pc.require(b'state: Running' in row or b'state: Waiting' in row,
                       'inotify process ended before its host gate')
            count = re.search(rb'\bwaits: (\d+)', row)
            pc.require(count is not None, 'missing real syscall wait counter')
            return int(count.group(1))
        before = waits()
        deadline = time.monotonic() + 5
        while True:
            after = waits()
            if after > before: break
            pc.require(time.monotonic() < deadline, 'inotify worker did not park and retry')
            time.sleep(.01)
        console.command('touch /run/user/0/inotify-' + phase)
        console.until(('INOTIFY_PROBE ' + phase + ' PASS').encode(), start)
        phases.append(dict(phase=phase, waits_before=before, waits_after=after))
    console.until(rb'INOTIFY_PROBE PASS', start)
    return dict(reclaimed_probe(console, pid, before_objects), phases=phases)

def thread_exit_checks(console, *, bad_stack=False):
    before = object_snapshot(console)
    pc.require(before['live'] == before['references'] == 0, 'thread capture begins with live objects')
    start = console.command('posix exec ' + ('thread-exit-bad-stack' if bad_stack else 'thread-exit-probe'))
    pid = console.until(rb'ELF pid=(\d+) started;', start).group(1)
    if bad_stack:
        console.until(rb'THREAD_EXIT_PROBE BAD_STACK BEGIN', start)
        result = reclaimed_probe(console, pid, before, state='Fault', code=139)
        pc.require(result['process']['esr'] == result['process']['far'] == 0,
                   'bad stack caused an actual CPU fault instead of safe entry refusal')
    else:
        first = console.until(rb'THREAD_EXIT_PROBE DETACHED_EXIT PASS|pid=' + pid +
                              rb' (?:Fault|Exited) code=\d+\b', start)
        pc.require(first.group(0) == b'THREAD_EXIT_PROBE DETACHED_EXIT PASS',
                   'detached-thread teardown ended the process before completing')
        for phase in ('DETACHED_EXIT', 'JOIN_REUSE'):
            console.until(('THREAD_EXIT_PROBE ' + phase + ' PASS').encode(), start)
        console.until(rb'THREAD_EXIT_PROBE PASS', start)
        result = reclaimed_probe(console, pid, before)
        pc.require(result['process']['thread_admissions'] == 5 and result['process']['thread_peak'] == 2,
                   'missing actual repeated detached exit and join reuse')
    return dict(result, bad_stack=bad_stack)

def syscall_probe_inputs(prefix, name):
    from build_sysroot import inspect_elf, PROBES
    prefix = Path(prefix)
    receipt_path = prefix / (name + '-layout.json')
    receipt = pc.read_json(receipt_path)
    image = prefix / (name + '.elf')
    actual = inspect_elf(image, 'x86_64')
    pc.require(all(receipt.get(key) == value for key, value in actual.items() if key != 'file'),
               name + ' layout differs from the actual target ELF')
    source = pc.ROOT / 'user/ported' / PROBES[name][0]
    sdk = pc.ROOT / 'artifacts/sysroot/x86_64-musl'
    inputs = {'source_sha256': pc.sha(source),
              'libc_sha256': pc.sha(sdk / 'sysroot/usr/lib/libc.a'),
              'driver_sha256': pc.sha(sdk / 'bin/x86_64-linux-musl-cc')}
    pc.require(all(receipt.get(key) == value for key, value in inputs.items()),
               name + ' source or SDK inputs changed since compilation')
    return dict(inputs, receipt_sha256=pc.sha(receipt_path), image_sha256=actual['sha256'])

def embedded_images(build, manifest, names):
    kernel = (build / 'kernel.elf').read_bytes()
    embedded = {}
    for name in names:
        program = (Path(manifest['sysroot']) / name).read_bytes()
        pc.require(program and kernel.count(program) == 1 and
                   any(program in kernel[load['offset']:load['offset'] + load['size']]
                       for load in manifest['elf']['loads'] if not load['flags'] & 2),
                   'exact ' + name + ' must be embedded once in a read-only load')
        embedded[name] = pc.sha_bytes(program)
    return embedded

def flock_checkpoint_proof(raw, commands):
    expected = ['write /run/user/0/boot-expired stale-session',
                'cat /run/user/0/boot-expired', 'storage checkpoint']
    tail = commands[-3:]
    pc.require([row.get('command') for row in tail] == expected,
               'runtime sentinel must be read back immediately before checkpoint')
    offsets = [row.get('serial_offset') for row in tail] + [len(raw)]
    pc.require(all(isinstance(at, int) and at >= 0 for at in offsets) and
               all(a < b for a, b in zip(offsets, offsets[1:])),
               'invalid runtime checkpoint command offsets')
    segments = [raw[a:b] for a, b in zip(offsets, offsets[1:])]
    pc.require(re.search(rb'^stale-session\r?$', segments[1], re.MULTILINE),
               'runtime sentinel was not present before checkpoint')
    durable = re.search(rb'STORAGE_DURABLE generation=(\d+) slot=\d+ bytes=(\d+) flushes=(\d+)\b', segments[2])
    pc.require(durable is not None, 'runtime checkpoint was not durable')
    generation, size, flushes = map(int, durable.groups())
    pc.require(generation > 0 and size > 0 and flushes >= 2, 'incomplete runtime checkpoint flush')
    return dict(generation=generation, bytes=size, flushes=flushes)

def flock_recovery_input(disk, current):
    """Only recover the unchanged disk of a proven sentinel-bearing capture."""
    directory = disk.parent
    previous = pc.read_json(directory / 'summary.json')
    pc.require(previous.get('status') == 'OS_FLOCK_PASS' and
               previous.get('disk') == str(disk.resolve()) and
               previous.get('disk_after_sha256') == pc.sha(disk),
               'recovery disk differs from its successful cold flock capture')
    for field in ('source_sha256', 'build_manifest_sha256', 'producer_sha256', 'producer_inputs_sha256'):
        pc.require(previous.get(field) == current[field], 'recovery predecessor changed ' + field)
    pc.require(pc.sha(directory / 'capture-producer.py') == previous['producer_sha256'],
               'recovery predecessor producer copy changed')
    hashes = {name: pc.sha(directory / name) for name in ('summary.json', 'serial.raw', 'commands.json')}
    pc.require(hashes['serial.raw'] == previous.get('serial_sha256') and
               hashes['commands.json'] == previous.get('commands_sha256'),
               'recovery predecessor serial or command capture changed')
    checkpoint = flock_checkpoint_proof(pc.bounded_bytes(directory / 'serial.raw', 4 * 1024 * 1024),
                                        pc.read_json(directory / 'commands.json'))
    pc.require(previous.get('runtime_checkpoint') == checkpoint,
               'recovery predecessor checkpoint disagrees with actual serial output')
    return dict(directory=str(directory), summary_sha256=hashes['summary.json'],
                serial_sha256=hashes['serial.raw'], commands_sha256=hashes['commands.json'],
                disk_sha256=previous['disk_after_sha256'], checkpoint=checkpoint)

def parallel_checks(console, qmp, output):
    pids = []
    for _ in range(3):
        start = console.command('posix spawn spin')
        pids.append(console.until(rb'pid=(\d+) started;', start).group(1))
    # Observe actual CPL3 state on three distinct APs at one paused machine
    # state. Online CPUs, mailbox counters or serial interleaving are insufficient.
    deadline = time.monotonic() + 5
    attempts = 0
    while True:
        attempts += 1
        qmp.execute('stop')
        try:
            registers = qmp.execute('human-monitor-command', {'command-line': 'info registers -a'})
        finally:
            qmp.execute('cont')
        blocks = re.split(r'CPU#(\d+)', registers)
        states = {int(blocks[i]): blocks[i + 1] for i in range(1, len(blocks) - 1, 2)}
        if all(re.search(r'\bCPL=3\b', states.get(cpu, '')) for cpu in (1, 2, 3)):
            (output / 'parallel-user-registers.txt').write_text(registers)
            break
        if time.monotonic() >= deadline:
            (output / 'parallel-last-registers.txt').write_text(registers)
            raise TimeoutError('three actual AP user contexts were not observed concurrently')
        console.pump(); time.sleep(.005)
    for pid in pids:
        console.command('posix kill ' + pid.decode(), [rb'pid=' + pid + rb' killed; pages reclaimed'])
    console.command('posix status', [rb'free_pages: 64\b'])
    return dict(cpus=[1, 2, 3], pids=[int(pid) for pid in pids], observations=attempts,
                method='QMP stop; hardware CPL3 on all three APs; QMP cont')

def smithay_checks(console, qmp, output):
    """Run the existing real Smithay/Wayland lifecycle on the x86 OS transport.

    The ARM runner/provenance remain separate. Only target-independent scene,
    protocol and resource validators are shared; target labels are explicit.
    """
    import verify_smithay_dynamic as dynamic
    from verify_shared_objects import snapshot, reclaimed
    from verify_ported import parse_processes
    from verify_x11 import event

    class GuestAdapter:
        text = console.raw
        def poll(self): console.pump()
        def command(self, command):
            at = console.command(command)
            return bytes(console.raw[at:])
    guest = GuestAdapter(); guest.qmp = qmp
    before = snapshot(guest); reclaimed(before)
    start = len(console.raw)
    console.command(dynamic.LAUNCH_COMMANDS[0])
    captures = []; phases = {}

    def wait_exit(pid):
        console.until(rb'^USER pid=' + str(pid).encode() +
                      rb' Exited code=0 free_pages=\d+ fault=0x0 far=0x0\r?$', start)

    def process_snapshot(phase):
        processes = parse_processes(guest.command('posix list'))
        dynamic.validate_process_phase(processes, phase, 4096)
        phases[phase] = processes

    for scene in range(12):
        dynamic.wait_marker(guest, start, dynamic.scene_ready(scene).encode())
        dynamic.wait_input_target(guest, start, scene)
        if scene in (5, 9): wait_exit({5: 3, 9: 5}[scene])
        phase = {2: 'a_alive', 4: 'full_before_probe', 5: 'b_retired',
                 8: 'c_alive', 9: 'c_retired'}.get(scene)
        if phase: process_snapshot(phase)
        witness = dynamic.capture(guest, start, output / f'scene-{scene}.ppm', scene)
        witness.update(capture_qmp_id=qmp.seq, serial_bytes_before_input=len(console.raw)-start)
        captures.append(witness)
        if scene in (0, 2, 6):
            console.command(dynamic.LAUNCH_COMMANDS[{0: 1, 2: 2, 6: 4}[scene]])
        if scene == 4:
            console.command(dynamic.LAUNCH_COMMANDS[3])
            dynamic.wait_marker(guest, start, b'DYN_CLIENT RESULT PASS id=0 eof=1')
            wait_exit(4); process_snapshot('full_after_probe')
            capacity = dynamic.capture(guest, start, output / 'scene-4-after-capacity.ppm', 4)
            pc.require(capacity['canvas_sha256'] == witness['canvas_sha256'],
                       'capacity rejection changed the actual display')
        for events in dynamic.input_events(scene): event(guest, events)
    wait_exit(2); wait_exit(1)
    observed = dynamic.validate(bytes(console.raw[start:]), architecture='x86_64')
    processes = parse_processes(guest.command('posix list'))
    after = snapshot(guest)
    dynamic.validate_resources(before, after, processes, 4096)
    return dict(observations=observed, scanouts=captures, capacity_scanout=capacity,
                process_phases=phases, processes=processes, before=before, after=after,
                scope='real Smithay dynamic clients and rendering; not cosmic-comp or a COSMIC session')

def capture(build, output, *, scenario='core', recover_disk=None, egl=False, qemu='qemu-system-x86_64'):
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        build = Path(build).resolve(strict=True)
        manifest = os_x86.validate_build(build)
        pc.require('graphics' in manifest['features'], 'smoke requires the actual display build')
        pc.require(scenario not in ('ported', 'parallel') or 'ported' in manifest['features'],
                   'ported smoke requires actual target program catalog')
        pc.require(not egl or 'mesa-probe' in manifest['features'], 'EGL smoke requires the actual Mesa image')
        pc.require(scenario != 'smithay' or 'smithay-dynamic-probe' in manifest['features'],
                   'Smithay smoke requires actual server/client target images')
        pc.require(scenario != 'cosmic-version' or 'cosmic-desktop' in manifest['features'],
                   'COSMIC execution smoke requires the actual full-OS compositor image')
        pc.require(scenario != 'flock' or (any(f in manifest['features'] for f in ('full-os', 'cosmic-desktop')) and
                   'flock-probe.elf' in manifest['external_inputs']),
                   'flock smoke requires full-OS runtime and the actual syscall probe')
        pc.require(scenario != 'nested-epoll' or ('full-os' in manifest['features'] and
                   'nested-epoll-probe.elf' in manifest['external_inputs']),
                   'nested epoll smoke requires full-OS runtime and the actual syscall probe')
        pc.require(scenario != 'inotify' or ('full-os' in manifest['features'] and
                   'inotify-probe.elf' in manifest['external_inputs']),
                   'inotify smoke requires full-OS runtime and the actual syscall probe')
        pc.require(scenario != 'thread-exit' or ('full-os' in manifest['features'] and
                   'thread-exit-probe.elf' in manifest['external_inputs']),
                   'thread-exit smoke requires full-OS runtime and actual musl probe')
        output = pc.fresh_output(output)
        producer = Path(__file__).read_bytes()
        helpers = os_x86.producer_sources(__file__)
        (output / 'capture-producer.py').write_bytes(producer)
        disk = Path(recover_disk).resolve(strict=True) if recover_disk else create_disk(output / 'data.raw')
        result = dict(status='FAIL', scenario=scenario, egl=egl, full_os_verified=False, cosmic_session_verified=False,
                      source_sha256=manifest['source_sha256'], build_manifest_sha256=pc.sha(build / 'build-manifest.json'),
                      producer_sha256=pc.sha_bytes(producer), disk=str(disk), disk_before_sha256=pc.sha(disk))
        result['producer_inputs_sha256'] = helpers
        process = None; console = None; qmp = None; started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='cyx-os-') as temporary, (output / 'qemu-stderr.log').open('wb') as err:
            path = Path(temporary); qemu = pc.executable(qemu)
            argv = os_x86.launch_argv(qemu, build / 'boot.bin', disk=disk, qmp=path / 'q.sock')
            index = argv.index('-serial')
            argv[index:index + 2] = ['-chardev', f'socket,id=osconsole,path={path / "s.sock"},server=on,wait=on',
                                    '-serial', 'chardev:osconsole']
            result.update(argv=argv, qemu_sha256=pc.sha(qemu))
            try:
                if scenario == 'smithay':
                    from os_smithay import validate_inputs
                    result['smithay_inputs'] = validate_inputs(Path(manifest['sysroot']))
                    result['smithay_embedded_sha256'] = embedded_images(build, manifest,
                        ('smithay-dynamic-probe.elf', 'smithay-dynamic-client.elf'))
                if scenario == 'cosmic-version':
                    result['cosmic_embedded_sha256'] = embedded_images(build, manifest, ('cosmic-comp.elf',))['cosmic-comp.elf']
                if scenario == 'flock':
                    result['flock_build_inputs'] = syscall_probe_inputs(manifest['sysroot'], 'flock-probe')
                    if recover_disk: result['recovery_input'] = flock_recovery_input(disk, result)
                    result['flock_embedded_sha256'] = embedded_images(build, manifest, ('flock-probe.elf',))['flock-probe.elf']
                if scenario == 'nested-epoll':
                    result['nested_epoll_build_inputs'] = syscall_probe_inputs(manifest['sysroot'], 'nested-epoll-probe')
                    result['nested_epoll_embedded_sha256'] = embedded_images(build, manifest, ('nested-epoll-probe.elf',))['nested-epoll-probe.elf']
                if scenario == 'inotify':
                    result['inotify_build_inputs'] = syscall_probe_inputs(manifest['sysroot'], 'inotify-probe')
                    result['inotify_embedded_sha256'] = embedded_images(build, manifest, ('inotify-probe.elf',))['inotify-probe.elf']
                if scenario == 'thread-exit':
                    result['thread_exit_build_inputs'] = syscall_probe_inputs(manifest['sysroot'], 'thread-exit-probe')
                    result['thread_exit_embedded_sha256'] = embedded_images(build, manifest, ('thread-exit-probe.elf',))['thread-exit-probe.elf']
                process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=err, env=pc.env())
                console = Console(connect(path / 's.sock', process), process, output / 'serial.raw')
                qmp = Qmp(connect(path / 'q.sock', process))
                qmp.receive(time.monotonic() + 10); qmp.execute('qmp_capabilities')
                console.until(PROMPT)
                result['cpus'] = qmp.execute('query-cpus-fast')
                pc.require(len(result['cpus']) == 4, 'missing CPU')
                registers = qmp.execute('human-monitor-command', {'command-line': 'info registers -a'})
                (output / 'boot-registers.txt').write_text(registers)
                cr0 = re.findall(r'CR0=([0-9a-fA-F]+)', registers)
                efer = re.findall(r'EFER=([0-9a-fA-F]+)', registers)
                pc.require(len(cr0) == 4 and all(int(v, 16) & (3 << 29) == 0 for v in cr0), 'CPU cache disabled')
                pc.require(all(int(v, 16) & (1 << 5) for v in cr0), 'native floating-point exceptions disabled')
                pc.require(len(efer) == 4 and all(int(v, 16) & (1 << 14) == 0 for v in efer), 'unsafe FFXSR mode')
                qmp.execute('screendump', {'filename': str(output / 'boot-display.ppm')})
                result['boot_display'] = verify_boot_frame(output / 'boot-display.ppm')
                if recover_disk:
                    console.until(rb'STORAGE_RECOVERED generation=')
                    if scenario == 'flock':
                        generation = result['recovery_input']['checkpoint']['generation']
                        console.until(rb'STORAGE_RECOVERED generation=' + str(generation).encode() + rb'\b')
                else:
                    console.command('mkdir /v17')
                    console.command('write /v17/hello x86-os-persistence')
                console.command('cat /v17/hello', [rb'^x86-os-persistence\r?$'])
                if scenario in ('native', 'ported', 'parallel'): native_checks(console)
                if scenario in ('ported', 'parallel'): ported_checks(console)
                if scenario == 'parallel': result['parallel_user'] = parallel_checks(console, qmp, output)
                if scenario == 'smithay': result['smithay'] = smithay_checks(console, qmp, output)
                if scenario == 'thread-exit':
                    result['thread_exit'] = [thread_exit_checks(console), thread_exit_checks(console, bad_stack=True), thread_exit_checks(console)]
                if scenario == 'inotify': result['inotify'] = [inotify_checks(console), inotify_checks(console)]
                if scenario == 'nested-epoll': result['nested_epoll'] = [nested_epoll_checks(console), nested_epoll_checks(console)]
                if scenario == 'flock':
                    console.until(rb'SESSION_RUNTIME_READY path=/run/user/0 mode=0700 uid=0')
                    at = console.command('ls /run/user/0')
                    pc.require(b'boot-expired' not in console.raw[at:], 'runtime state survived reboot')
                    result['flock'] = [flock_checks(console), flock_checks(console)]
                    # This file enters the durable snapshot. Boot must discard
                    # it after recovery, while preserving /v17/hello above.
                    if not recover_disk:
                        console.command('write /run/user/0/boot-expired stale-session')
                        console.command('cat /run/user/0/boot-expired', [rb'^stale-session\r?$'])
                if scenario == 'cosmic-version':
                    # Run the same real executable twice, proving teardown/reuse
                    # as well as entry and normal return. This does not start a session.
                    result['cosmic_executions'] = []
                    for _ in range(2):
                        at = console.program('posix exec cosmic-version', b'cosmic-comp ')
                        admitted = console.until(rb'ELF pid=(\d+) started; ABI=Linux-x86_64-subset image AI_DIRECT model=8197 pages=(\d+)', at)
                        result['cosmic_executions'].append(dict(pid=int(admitted.group(1)), pages=int(admitted.group(2))))
                    console.program('posix exec probe', b'PORTED_PROBE PASS')
                    result['scope'] = 'real cosmic-comp --version and image reuse; not compositor startup or a COSMIC session'
                if egl: console.program('posix exec egl-probe', b'EGL_PROBE RESULT PASS mode=offscreen failures=0')
                if not recover_disk:
                    console.command('storage checkpoint', [rb'STORAGE_DURABLE generation=\d+ .*flushes=[2-9]'])
                    if scenario == 'flock':
                        result['runtime_checkpoint'] = flock_checkpoint_proof(bytes(console.raw), console.commands)
                qmp.execute('screendump', {'filename': str(output / 'display.ppm')})
                if scenario == 'smithay':
                    from verify_smithay_dynamic import scanout
                    result['display'] = scanout(output / 'display.ppm', 11)
                else: result['display'] = verify_boot_frame(output / 'display.ppm')
                result['status'] = 'OS_' + ('REBOOT_' if recover_disk else '') + scenario.upper() + '_PASS'
            except Exception as error:
                result['error'] = repr(error)
                if qmp:
                    try:
                        (output / 'failure-registers.txt').write_text(qmp.execute('human-monitor-command',
                                                                   {'command-line': 'info registers -a'}))
                    except Exception as failed: result['diagnostic_error'] = repr(failed)
            finally:
                if console:
                    try: console.pump()
                    except Exception: pass
                if qmp:
                    try: qmp.execute('quit')
                    except Exception: pass
                    pc.write_json(output / 'qmp.json', qmp.transcript)
                if process:
                    try: result['returncode'] = process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill(); result['returncode'] = process.wait(); result['forced'] = True
                        result['status'] = 'FAIL'
                raw = bytes(console.raw) if console else b''
                (output / 'serial.raw').write_bytes(raw)
                (output / 'serial.txt').write_text(raw.decode(errors='replace'))
                pc.write_json(output / 'commands.json', console.commands if console else [])
                result.update(serial_sha256=pc.sha_bytes(raw), elapsed_seconds=time.monotonic() - started,
                              disk_after_sha256=pc.sha(disk), commands_sha256=pc.sha(output / 'commands.json'))
                if result['status'] != 'FAIL':
                    try:
                        os_x86.validate_build(build)
                        pc.require(Path(__file__).read_bytes() == producer, 'capture producer changed during VM')
                        pc.require(os_x86.producer_sources(__file__) == helpers,
                                   'capture validator/helper changed during VM')
                        if scenario == 'smithay':
                            pc.require(validate_inputs(Path(manifest['sysroot'])) == result['smithay_inputs'],
                                       'Smithay source/build receipt changed during VM')
                        if scenario == 'flock':
                            pc.require(syscall_probe_inputs(manifest['sysroot'], 'flock-probe') == result['flock_build_inputs'],
                                       'flock source/build inputs changed during VM')
                        if scenario == 'nested-epoll':
                            pc.require(syscall_probe_inputs(manifest['sysroot'], 'nested-epoll-probe') == result['nested_epoll_build_inputs'],
                                       'nested epoll source/build inputs changed during VM')
                        if scenario == 'inotify':
                            pc.require(syscall_probe_inputs(manifest['sysroot'], 'inotify-probe') == result['inotify_build_inputs'],
                                       'inotify source/build inputs changed during VM')
                        if scenario == 'thread-exit':
                            pc.require(syscall_probe_inputs(manifest['sysroot'], 'thread-exit-probe') == result['thread_exit_build_inputs'],
                                       'thread-exit source/build inputs changed during VM')
                        pc.require(result.get('returncode') == 0, 'QEMU did not exit normally')
                    except Exception as changed:
                        result.update(status='FAIL', error=repr(changed))
                pc.write_json(output / 'summary.json', result)
        return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scenario', choices=['core', 'native', 'ported', 'parallel', 'smithay', 'cosmic-version', 'flock', 'nested-epoll', 'inotify', 'thread-exit'], default='core')
    parser.add_argument('--recover-disk', type=Path)
    parser.add_argument('--egl', action='store_true')
    args = parser.parse_args()
    result = capture(args.build, args.output, scenario=args.scenario, recover_disk=args.recover_disk, egl=args.egl)
    print(json.dumps({k: result[k] for k in ('status', 'error') if k in result}))
    raise SystemExit(result['status'] == 'FAIL')

if __name__ == '__main__': main()
