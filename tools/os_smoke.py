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
                    kernel = (build / 'kernel.elf').read_bytes()
                    embedded = {}
                    for name in ('smithay-dynamic-probe.elf', 'smithay-dynamic-client.elf'):
                        program = (Path(manifest['sysroot']) / name).read_bytes()
                        pc.require(program and kernel.count(program) == 1,
                                   'exact Smithay target image missing or duplicated')
                        pc.require(any(program in kernel[load['offset']:load['offset']+load['size']]
                                       for load in manifest['elf']['loads'] if not load['flags'] & 2),
                                   'Smithay image must be embedded in a read-only load')
                        embedded[name] = pc.sha_bytes(program)
                    result['smithay_embedded_sha256'] = embedded
                if scenario == 'cosmic-version':
                    program = (Path(manifest['sysroot']) / 'cosmic-comp.elf').read_bytes()
                    kernel = (build / 'kernel.elf').read_bytes()
                    pc.require(program and kernel.count(program) == 1 and
                               any(program in kernel[load['offset']:load['offset']+load['size']]
                                   for load in manifest['elf']['loads'] if not load['flags'] & 2),
                               'exact COSMIC image must be embedded once in a read-only load')
                    result['cosmic_embedded_sha256'] = pc.sha_bytes(program)
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
                else:
                    console.command('mkdir /v17')
                    console.command('write /v17/hello x86-os-persistence')
                console.command('cat /v17/hello', [rb'^x86-os-persistence\r?$'])
                if scenario in ('native', 'ported', 'parallel'): native_checks(console)
                if scenario in ('ported', 'parallel'): ported_checks(console)
                if scenario == 'parallel': result['parallel_user'] = parallel_checks(console, qmp, output)
                if scenario == 'smithay': result['smithay'] = smithay_checks(console, qmp, output)
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
                              disk_after_sha256=pc.sha(disk))
                if result['status'] != 'FAIL':
                    try:
                        os_x86.validate_build(build)
                        pc.require(Path(__file__).read_bytes() == producer, 'capture producer changed during VM')
                        pc.require(os_x86.producer_sources(__file__) == helpers,
                                   'capture validator/helper changed during VM')
                        if scenario == 'smithay':
                            pc.require(validate_inputs(Path(manifest['sysroot'])) == result['smithay_inputs'],
                                       'Smithay source/build receipt changed during VM')
                        pc.require(result.get('returncode') == 0, 'QEMU did not exit normally')
                    except Exception as changed:
                        result.update(status='FAIL', error=repr(changed))
                pc.write_json(output / 'summary.json', result)
        return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scenario', choices=['core', 'native', 'ported', 'parallel', 'smithay', 'cosmic-version'], default='core')
    parser.add_argument('--recover-disk', type=Path)
    parser.add_argument('--egl', action='store_true')
    args = parser.parse_args()
    result = capture(args.build, args.output, scenario=args.scenario, recover_disk=args.recover_disk, egl=args.egl)
    print(json.dumps({k: result[k] for k in ('status', 'error') if k in result}))
    raise SystemExit(result['status'] == 'FAIL')

if __name__ == '__main__': main()
