#!/usr/bin/env python3
"""Capture a genuine COSMIC notification protocol session over QEMU FIFOs.

This consumes separately validated real builds. It never builds a guest, serves
D-Bus or Wayland, or substitutes a test compositor. A protocol PASS does not
assert that a notification's text was rendered or that a full COSMIC session is
complete. Framebuffer and Wayland observations remain separate review evidence.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

# The existing OS/QMP entry points deliberately use tools-local imports.
# Select their actual repository directory, never an ambient plugin directory.
TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import build_dbus
import build_notification_probe as probe_builder
import cosmic_notifications_dependencies as dependencies
import cosmic_notifications_elf as elf
import install_cosmic_config
import install_cosmic_fonts_v1
import install_cosmic_notifications_static_v1 as notifications
import install_cosmic_theme_defaults
import os_smoke
import os_x86
import x86_64 as pc
from native_session import idle_native_host, native_lease
from run_qemu import Qmp
from storage import create_disk
from target_profile import profile_for
from verify_ported import parse_processes

ROOT = TOOLS.parent
NATIVE_LOCK = ROOT / 'artifacts/v017-cosmic-completion-20261116/native-session.lock'
MAX_WALL_SECONDS = 240
MAX_OUTPUT_BYTES = 96 * 1024**2
MAX_FRAMES = 24
MAX_DIAGNOSTIC_LOG_BYTES = 24 * 1024**2
IMAGE_NAMES = ('probe.elf', 'dbus-daemon.elf', 'dbus-send.elf', 'cosmic-comp.elf',
               'cosmic-notifications.elf', 'notification-probe.elf')
FULL_OS = {'image_bytes': 64 * 1024**2, 'max_elf_bytes': 64 * 1024**2,
           'stack_bytes': 2 * 1024**2, 'target_runtime_validated': False}
SERVICE = b'org.freedesktop.Notifications'
SUCCESS = 'COSMIC_NOTIFICATIONS_PROTOCOL_FIFO_PASS'
FONT_COMMIT = '5a8bd9482a35ae94c1e54edf77b331c6b970f170'
FONT_FILES = {
    'res/open-sans/OpenSans-Regular.ttf': 'e64e508b2aa2880f907e470c4550980ec4c0694d103a43f36150ac3f93189bee',
    'res/open-sans/OpenSans-Light.ttf': 'cf5f5184c1441a1660aa52526328e9d5c2793e77b6d8d3a3ad654bdb07ab8424',
    'res/open-sans/OpenSans-Semibold.ttf': 'aa3b0ef53db12e3d45094030cac0e69d384e44cc5978643dd4390041cad546e2',
    'res/open-sans/OpenSans-Bold.ttf': '5894a3649b213cf5b2d673b6e7a871815fd1d120fa68a463592f27db14eae323',
    'res/open-sans/OpenSans-ExtraBold.ttf': '0fcbdb5cbeea00ae532352c7c94a7d288ebc911ba85f4d595012032dcab64ba8',
    'res/open-sans/LICENSE': '87a330d2f56cfe470431eed7996fa5423f694c79e2ad7c4c515ac75bc9a340d6',
    'res/noto/NotoSansMono-Regular.ttf': '6b692c4b6d15ccf59f1c1fe8d11cb8a92f51960f3e9f1f523781755a3af7e29f',
    'res/noto/NotoSansMono-Bold.ttf': 'b22563d5f03b345a62115e78d8789c9ed99c2cfa8059fad6e7a5c4ced288e21e',
    'res/noto/LICENSE': '6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def read_regular(path, limit=64 * 1024**2):
    return elf._read_regular(path, limit)


def identity(path, limit=64 * 1024**2):
    data = read_regular(path, limit)
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def document(path):
    value = json.loads(read_regular(path), object_pairs_hook=unique_object)
    require(type(value) is dict, 'Expected a JSON object: ' + str(path))
    return value


def write_json(path, value):
    pending = path.with_name(path.name + '.pending')
    pending.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    pending.replace(path)


def plain_directory(path):
    path = probe_builder.no_symlink_path(path)
    require(path.is_dir(), 'Missing actual directory: ' + str(path))
    return path


def fresh_output(path, inputs):
    path = probe_builder.no_symlink_path(path)
    require(not path.exists(), 'Capture output must be fresh; old evidence is preserved')
    require(not path.is_relative_to(ROOT) or path.is_relative_to(ROOT / 'artifacts'),
            'In-repository capture outputs belong only in artifacts, outside source directories')
    for source in inputs:
        require(not path.is_relative_to(source) and not source.is_relative_to(path),
                'Capture output overlaps a read-only input')
    return path


def fields(line):
    result = {}
    for token in line.decode('ascii').split():
        if '=' not in token:
            continue
        key, value = token.split('=', 1)
        require(key not in result, 'Duplicate observed field: ' + key)
        result[key] = int(value) if value.isdecimal() else value
    return result


def one_row(raw, prefix, *, optional=False):
    rows = re.findall(rb'(?m)^' + re.escape(prefix) + rb'[^\r\n]*\r?$', raw)
    require(len(rows) == 1 or (optional and not rows), 'Missing/ambiguous observed row: ' + repr(prefix))
    return fields(rows[0]) if rows else None


def system_snapshot(raw):
    require(len(re.findall(rb'(?m)^AI_SYSTEM_END\r?$', raw)) == 1,
            'Incomplete or ambiguous AI system snapshot')
    return {'display': one_row(raw, b'AI_DOMAIN name=display '),
            'display_receipt': one_row(raw, b'AI_DISPLAY_RECEIPT ', optional=True),
            'ofd': one_row(raw, b'OFD_OBJECTS '),
            'ancillary': one_row(raw, b'ANCILLARY_OBJECTS '),
            'shared': one_row(raw, b'SHARED_OBJECTS '),
            'anon': one_row(raw, b'ANON_POOL '),
            'pipe': one_row(raw, b'PIPE_POOL ')}


def completed_scanout(before, after, pid):
    """Require a real matching transfer/flush completion owned by this PID.

    observed_completed is an admission-time history count, NOT a completion
    flag. Only the driver's aggregate and current outcome establish completion.
    """
    current, previous = after['display'], before['display']
    receipt = after['display_receipt']
    require(current.get('available') == 'true' and current.get('phase') == 'Idle',
            'Display is unavailable or still in flight')
    for key in ('completed', 'submitted', 'failed', 'policy_invalid', 'clock_rejected'):
        require(type(current.get(key)) is int and type(previous.get(key)) is int,
                'Missing display counter: ' + key)
    require(current['completed'] > previous['completed']
            and current['submitted'] >= current['completed'], 'No completed native scanout')
    for key in ('failed', 'policy_invalid', 'clock_rejected'):
        require(current[key] == previous[key], 'Display failure counter increased: ' + key)
    require(receipt is not None and receipt.get('owner') == pid
            and receipt.get('phase') == 'Idle' and receipt.get('outcome') == 'Completed'
            and type(receipt.get('id')) is int and receipt['id'] > 0,
            'Latest completed display receipt does not belong to the compositor')
    return {'pid': pid, 'completed_delta': current['completed'] - previous['completed'],
            'completion_unit': 'One bounded rectangle transfer and its flush fence; not a whole semantic frame',
            'receipt': receipt, 'semantic_ui_verified': False}


def reclaimed(before, after):
    for name in ('ofd', 'ancillary', 'shared', 'pipe'):
        require(before[name] == after[name], 'Global resource did not return to baseline: ' + name)
    for key in ('capacity', 'free', 'used', 'virtual_pages'):
        require(before['anon'].get(key) == after['anon'].get(key), 'Anonymous pool not reclaimed: ' + key)
    require(after['display'].get('phase') == 'Idle', 'Display still owns an in-flight transfer')
    for key in ('failed', 'policy_invalid', 'clock_rejected'):
        require(after['display'].get(key) == before['display'].get(key), 'Display failed: ' + key)


def process_reclaimed(row, state, code):
    # free_pages projects the shared Runner arena, not this PID's ownership.
    # Each fresh process list is checked separately by global_arena().
    expected = {'state': state, 'code': code, 'heap_pages': 0,
                'image_pages': 0, 'thread_count': 0, 'heap_free': 16384,
                'heap_allocations': 0, 'heap_largest_free': 16384, 'image_free': 16384}
    require(all(row.get(key) == value for key, value in expected.items()),
            'Process memory, grant or threads remain owned: ' + repr(row))


def global_arena(rows, *, required_pids=()):
    """Check one fresh list's shared 64-page ledger, with 8 pages per Runner.

    Supervisor::poll publishes the same ledger snapshot into every row. A
    terminal row may therefore show less than 64 while another PID is active.
    Empty initial lists contain no observation of this ledger.
    """
    require(0 < len(rows) <= 8, 'Missing or oversized process arena snapshot')
    require(set(required_pids) <= set(rows), 'Missing process from final arena snapshot')
    for pid, row in rows.items():
        require(type(pid) is int and pid > 0 and row.get('pid') == pid
                and row.get('state') in ('Idle', 'Running', 'Waiting', 'Exited', 'Fault', 'Timeout', 'Killed'),
                'Invalid process arena row')
        require(type(row.get('free_pages')) is int and 0 <= row['free_pages'] <= 64,
                'Missing or invalid global arena free_pages')
    free = {row['free_pages'] for row in rows.values()}
    require(len(free) == 1, 'Contradictory global arena observations in one process list')
    free_pages = next(iter(free))
    active = sorted(pid for pid, row in rows.items() if row['state'] in ('Running', 'Waiting'))
    require(free_pages == 64 - 8 * len(active), 'Global arena grants disagree with active processes')
    return {'capacity_pages': 64, 'pages_per_active_process': 8,
            'free_pages': free_pages, 'active_pids': active}


def protocol_markers(raw, service_pid, client_pid, *, complete):
    rows = re.findall(rb'(?m)^(?:cyxia:/> )?(NOTIFICATION_PROBE[^\r\n]*)\r?$', raw)
    expected_count = 6 if complete else 4
    require(len(rows) == expected_count, 'Unexpected notification marker count/order: ' + repr(rows))
    require(rows[0] == b'NOTIFICATION_PROBE START service=org.freedesktop.Notifications render_verified=false',
            'Missing genuine client start')
    owner = re.fullmatch(rb'NOTIFICATION_PROBE OWNER PASS unique=(:[A-Za-z0-9_.-]+) service_pid=(\d+) client_pid=(\d+)', rows[1])
    require(owner is not None and int(owner[2]) == service_pid and int(owner[3]) == client_pid
            and service_pid != client_pid, 'Broker owner PID differs from the launched notification ELF')
    require(rows[2] == b'NOTIFICATION_PROBE INFO PASS name=cosmic-notifications vendor=System76 version=1.10.0 spec=1.2',
            'Wrong upstream notification server identity')
    created = re.fullmatch(rb'NOTIFICATION_PROBE CREATED id=(\d+) service_pid=(\d+) capture_ms=5000 render_verified=false', rows[3])
    require(created is not None and int(created[1]) > 0 and int(created[2]) == service_pid,
            'Invalid notification creation receipt')
    number = int(created[1])
    if complete:
        require(rows[4] == f'NOTIFICATION_PROBE CLOSED id={number} service_pid={service_pid} reason=3'.encode(),
                'NotificationClosed does not match the real Notify/Close pair')
        require(rows[5] == f'NOTIFICATION_PROBE PASS service_pid={service_pid} id={number} render_verified=false'.encode(),
                'Missing bounded genuine notification protocol result')
    return {'owner': owner[1].decode(), 'service_pid': service_pid, 'client_pid': client_pid,
            'id': number, 'capture_ms': 5000, 'markers': [row.decode() for row in rows],
            'render_verified': False}


def frame_metadata(path, baseline=None):
    raw = read_regular(path, 4 * 1024**2)
    parts = raw.split(b'\n', 3)
    require(parts[:3] == [b'P6', b'1024 768', b'255'] and len(parts) == 4
            and len(parts[3]) == 1024 * 768 * 3, 'Not an actual complete QMP 1024x768 PPM')
    pixels = parts[3]
    colors = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0),
              (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0)]
    boot = b''.join(bytes(color) * 128 for color in colors) * 768
    changed = None
    bounds = None
    if baseline is not None:
        prior = read_regular(baseline, 4 * 1024**2).split(b'\n', 3)
        require(prior[:3] == parts[:3] and len(prior) == 4 and len(prior[3]) == len(pixels),
                'Incompatible framebuffer baseline')
        differences = [i // 3 for i in range(0, len(pixels), 3) if pixels[i:i + 3] != prior[3][i:i + 3]]
        changed = len(differences)
        if differences:
            xs, ys = [i % 1024 for i in differences], [i // 1024 for i in differences]
            bounds = [min(xs), min(ys), max(xs), max(ys)]
    return {'width': 1024, 'height': 768, 'pixels': 1024 * 768, 'sha256': pc.sha_bytes(raw),
            'boot_colorbars': pixels == boot, 'changed_pixels': changed, 'changed_bounds_xyxy': bounds,
            'text_verified': False, 'notification_render_verified': False}


def wayland_observations(raw):
    rows = [line.decode('utf-8', errors='replace') for line in raw.splitlines()
            if re.search(rb'(?:wl_surface|wl_callback|zwlr_layer_(?:shell|surface)_v1)[@#]\d+\.', line)]
    require(len(rows) <= 4096, 'Wayland observation budget exceeded')
    return {'lines': rows, 'surface_attach': sum(bool(re.search(r'wl_surface[@#]\d+\.attach\(', line)) for line in rows),
            'surface_commit': sum(bool(re.search(r'wl_surface[@#]\d+\.commit\(', line)) for line in rows),
            'callback_done': sum(bool(re.search(r'wl_callback[@#]\d+\.done\(', line)) for line in rows),
            'layer_surface': sum('get_layer_surface(' in line for line in rows),
            'scope': 'Observed client protocol bytes; no inferred pixel/text success',
            'notification_render_verified': False}


class PipeChannel:
    """Separate real FIFO RX/TX; never hold a synthetic writer on guest output."""
    def __init__(self, path, deadline):
        self.path, self.deadline = path, deadline
        self.process, self.writer, self.timeout = None, None, None
        self.received_bytes = False
        for suffix in ('.in', '.out'):
            os.mkfifo(str(path) + suffix, 0o600)
        self.reader = os.open(str(path) + '.out', os.O_RDONLY | os.O_NONBLOCK)

    def connect(self, process):
        self.process = process
        until = min(self.deadline, time.monotonic() + 10)
        while True:
            require(process.poll() is None, 'QEMU exited before FIFO connection')
            try:
                self.writer = os.open(str(self.path) + '.in', os.O_WRONLY | os.O_NONBLOCK)
                return
            except OSError as error:
                if error.errno != errno.ENXIO:
                    raise
                require(time.monotonic() < until, 'FIFO connection timeout')
                time.sleep(.01)

    def setblocking(self, enabled):
        self.timeout = None if enabled else 0

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        until = self.deadline if self.timeout is None else min(self.deadline, time.monotonic() + self.timeout)
        while True:
            try:
                data = os.read(self.reader, size)
                if data:
                    self.received_bytes = True
                    return data
                if self.process.poll() is not None:
                    return data
                if self.received_bytes:
                    raise ConnectionError('Guest FIFO disconnected while QEMU is still alive')
            except BlockingIOError:
                pass
            if self.timeout == 0:
                raise BlockingIOError(errno.EAGAIN, 'No guest FIFO bytes ready')
            if time.monotonic() >= until:
                raise socket.timeout('FIFO receive timeout')
            time.sleep(.005)

    def sendall(self, data):
        until = min(self.deadline, time.monotonic() + 5)
        while data:
            require(self.process.poll() is None, 'QEMU exited before FIFO write')
            require(time.monotonic() < until, 'FIFO write deadline')
            try:
                count = os.write(self.writer, data)
                require(count > 0, 'FIFO write made no progress')
                data = data[count:]
            except BlockingIOError:
                select.select([], [self.writer], [], .01)

    def close(self):
        for name in ('reader', 'writer'):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)


class Console(os_smoke.Console):
    """Keep the formal Console checks and add a shared wall/output deadline."""
    def __init__(self, channel, process, output, deadline):
        super().__init__(channel, process, output / 'serial.raw')
        self.output, self.deadline = output, deadline

    def pump(self, *, require_running=True):
        super().pump(require_running=require_running)
        if require_running:
            require(time.monotonic() < self.deadline, 'Overall guest walltime budget exceeded')
        size = sum(path.stat().st_size for path in self.output.iterdir() if path.is_file())
        require(size <= MAX_OUTPUT_BYTES, 'Capture output budget exceeded')

    def until(self, pattern, start=0, timeout=30):
        return super().until(pattern, start, min(timeout, max(0, self.deadline - time.monotonic())))

    def command(self, command, expected=()):
        start = len(self.raw)
        self.commands.append(dict(command=command, serial_offset=start))
        encoded = command.encode('ascii')
        self.sock.sendall(encoded + b'\r')
        # Concurrent application tracing can arrive before the command echo.
        # Keep it in raw evidence, but require this command's own echo/prompt
        # and use only its response span for expected asynchronous markers.
        echo = self.until(rb'(?m)^(?:' + os_smoke.PROMPT + rb')?'
                          + re.escape(encoded) + rb'\r?\n', start)
        response = start + echo.end()
        self.until(rb'(?m)^' + os_smoke.PROMPT, response)
        # Shell errors are standalone lines. A tracing message containing the
        # word "error:" is not a shell error. Preserve kernel failure formats,
        # including asynchronous ELF launches and failed explicit kills.
        failure = (rb'(?m)^(?:' + os_smoke.PROMPT + rb')?(?:error:|'
                   rb'(?:ELF(?: [^ \r\n]+)?|USER|EL0) (?:start|pair|kill) failed:)')
        require(re.search(failure, self.raw[start:]) is None, 'command failed')
        for pattern in expected:
            self.until(pattern, response)
            require(re.search(failure, self.raw[start:]) is None, 'command failed')
        return start


def system(console):
    start = console.command('ai system')
    console.until(rb'AI_SYSTEM_END\r?\n', start)
    return system_snapshot(bytes(console.raw[start:]))


def processes(console):
    start = console.command('posix list')
    output = bytes(console.raw[start:])
    # A fresh guest has no UserStatus rows. Accept only its complete, empty
    # command response; missing, malformed or diagnostic output is not empty.
    if re.fullmatch(rb'posix list\r?\n' + os_smoke.PROMPT, output):
        return {}
    rows = parse_processes(output)
    global_arena(rows)
    return rows


def active_processes(console, allowed, required, *, allow_empty=False):
    rows = processes(console)
    require(bool(rows) or (allow_empty and not allowed and not required),
            'Missing process snapshot outside the empty initial baseline')
    active = {pid for pid, row in rows.items() if row['state'] in ('Running', 'Waiting')}
    require(set(required) <= active <= set(allowed), 'Unexpected exited or unrelated active process: ' + repr(rows))
    return rows


def launch(console, name, inspection):
    start = console.command('posix exec ' + name)
    match = console.until(rb'ELF pid=(\d+) started;[^\r\n]*image AI_DIRECT model=8197 pages=(\d+)', start)
    require(int(match[2]) == inspection['required_pages'], 'Guest executable grant differs from actual ELF/stack pages')
    return int(match[1]), start


def snapshot_frame(console, qmp, output, frames, name, baseline=None):
    console.pump()
    require(len(frames) < MAX_FRAMES, 'Framebuffer count budget exceeded')
    path = output / (name + '.ppm')
    require(not path.exists(), 'Framebuffer capture names must be unique')
    start = time.monotonic()
    offset = len(console.raw)
    qmp.execute('screendump', {'filename': str(path)})
    console.pump()
    result = {'file': path.name, 'serial_before': offset, 'serial_after': len(console.raw),
              'capture_seconds': time.monotonic() - start, **frame_metadata(path, baseline)}
    frames.append(result)
    return result


def probe_inputs(directory):
    directory = plain_directory(directory)
    report = document(directory / probe_builder.RECEIPT)
    target = profile_for('x86_64')
    target.require_report(report)
    # The preserved producer receipt is JSON: tuple-valued clang_args becomes
    # an array. Compare the complete identity in that same serialized shape.
    expected_target = json.loads(json.dumps(target.identity(), allow_nan=False))
    require(report.get('schema_version') == 1 and report.get('status') == 'BUILT_NOT_RUN'
            and report.get('source_root') == str(ROOT) and report.get('source') == str(probe_builder.SOURCE)
            and report.get('target_profile') == expected_target
            and report.get('expected_server') == probe_builder.SERVER_IDENTITY
            and report.get('capture_window_ms') == 5000
            and report.get('limits') == {'timeout_seconds': probe_builder.TIMEOUT_SECONDS,
                                        'min_free_bytes': probe_builder.MIN_FREE_BYTES,
                                        'max_output_bytes': probe_builder.MAX_OUTPUT_BYTES}
            and all(report.get(key) is False for key in ('guest_execution', 'notifications_verified',
                                                         'render_verified', 'cosmic_session_verified')),
            'Not an actual preserved notification client build')
    require('error' not in report and report['producer_inputs'] == probe_builder.producer_identity(),
            'Notification client source/producer changed')
    sdk = plain_directory(report['sdk']['path'])
    require(report['sdk'] == probe_builder.sdk_identity(sdk, target), 'Notification client SDK changed')
    require(report['dbus'] == probe_builder.dbus_identity(plain_directory(report['dbus']['path']), sdk, target),
            'Notification client D-Bus inputs changed')
    tools = {name: entry['path'] for name, entry in report['toolchain'].items()}
    require(probe_builder.tool_identity(tools) == report['toolchain'], 'Notification client compiler changed')
    program = directory / probe_builder.EXECUTABLE
    require(report['probe'] == probe_builder.inspect_elf(program, target), 'Notification client ELF changed')
    require(report['logs'] == build_dbus.file_map(directory / 'logs'), 'Notification client logs changed')
    stage, library = Path(report['dbus']['path']) / 'stage', sdk / 'sysroot/usr/lib'
    obj = directory / 'notification-probe.o'
    commands = [[tools['clang'], '--version'], [tools['rust-lld'], '-flavor', 'gnu', '--version'],
                [tools['clang'], *target.clang_args, '-nostdinc', '-isystem', sdk / 'sysroot/usr/include',
                 '-I', stage / 'usr/include/dbus-1.0', '-I', stage / 'usr/lib/dbus-1.0/include',
                 '-std=c11', '-O2', '-ffp-contract=off', '-fno-stack-protector', '-fno-pie',
                 '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror',
                 '-c', probe_builder.SOURCE, '-o', obj],
                [tools['rust-lld'], '-flavor', 'gnu', '-m', target.linker_emulation,
                 '--image-base=0x01000000', '-z', 'max-page-size=4096', '-z', 'separate-code',
                 '-static', '--no-pie', '--build-id=sha1', '--gc-sections', '-o',
                 directory / (probe_builder.EXECUTABLE + '.tmp'), library / 'crt1.o', library / 'crti.o', obj,
                 '--start-group', stage / 'usr/lib/libdbus-1.a', stage / 'usr/lib/libexpat.a',
                 library / 'libc.a', library / target.builtins_archive, '--end-group', library / 'crtn.o']]
    require(report['commands'] == [[str(arg) for arg in command] for command in commands],
            'Notification client build command mismatch')
    versions = {name: read_regular(directory / 'logs' / filename, 64 * 1024).decode()
                for name, filename in [('clang', 'clang-version.log'), ('rust-lld', 'linker-version.log')]}
    require(report['tool_versions'] == versions, 'Notification client compiler version logs changed')
    return {'receipt': identity(directory / probe_builder.RECEIPT), 'report': report,
            'image_admission': elf.inspect_full_os_elf(program, FULL_OS)}


def font_inputs(prefix):
    receipt = prefix / 'cosmic-font-assets.json'
    report = document(receipt)
    source = report.get('source', {})
    require(type(report.get('schema_version')) is int and report['schema_version'] == 1
            and report.get('status') == 'ASSETS_INSTALLED_NOT_RUN'
            and source.get('repository') == 'https://github.com/pop-os/libcosmic'
            and source.get('commit') == FONT_COMMIT, 'Unsupported genuine font source receipt')
    checkout = plain_directory(source['checkout'])
    require(dependencies.pinned_git(checkout, 'rev-parse', 'HEAD') == FONT_COMMIT
            and dependencies.pinned_git(checkout, 'rev-parse', 'HEAD^{tree}') == source.get('git_tree'),
            'Font checkout commit/tree changed')
    expected = {}
    for relative in FONT_FILES:
        if relative.endswith('.ttf'):
            guest = '/usr/share/fonts/cosmic/' + Path(relative).name
        else:
            name = 'OpenSans' if relative.startswith('res/open-sans/') else 'NotoSansMono'
            guest = '/usr/share/licenses/cosmic-fonts/' + name + '-LICENSE'
        expected[guest] = relative
    files = report.get('files')
    require(type(files) is dict and set(files) == set(expected), 'Font receipt must contain exactly seven TTFs and two full licenses')
    for guest, relative in expected.items():
        row = files[guest]
        original = checkout / relative
        require(type(row) is dict and row.get('source_relative') == relative
                and row.get('source') == str(original) and row.get('mode') == '100644',
                'Font source path/mode changed')
        raw = read_regular(original, 2 * 1024**2)
        actual = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        require(actual['sha256'] == FONT_FILES[relative]
                and type(row.get('bytes')) is int and row['bytes'] == actual['bytes']
                and row.get('sha256') == actual['sha256'], 'Font/license differs from the reviewed canonical bytes')
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        record = dependencies.pinned_git(checkout, 'ls-tree', 'HEAD', '--', relative)
        require(record == '100644 blob ' + blob + '\t' + relative and row.get('git_blob') == blob,
                'Font/license Git blob does not match the pinned source')
        installed = prefix / 'rootfs' / guest.lstrip('/')
        require(read_regular(installed, 2 * 1024**2) == raw and installed.stat().st_mode & 0o777 == 0o644,
                'Curated font/license bytes or mode changed')
    return {'receipt': identity(receipt), 'source': source, 'files': files,
            'guest_font_loading_observed': False}


def catalog_identity(build, manifest, programs):
    prefix = plain_directory(manifest['sysroot'])
    cache = plain_directory(manifest['cache']['effective'])
    catalogs = list(cache.rglob('ported_catalog.rs'))
    require(len(catalogs) == 1, 'Missing/ambiguous actual generated catalog')
    catalog = probe_builder.no_symlink_path(catalogs[0])
    raw = read_regular(catalog, 1024 * 1024)
    entries = re.findall(rb'^\("([^"\n]+)", "([^"\n]+)", include_bytes!\(concat!\(env!\("OUT_DIR"\), "/([^"\n]+)"\)\)\),$', raw, re.MULTILINE)
    bound = os_smoke.embedded_images(build, manifest, IMAGE_NAMES)
    for name, image in programs.items():
        matches = [(i, row) for i, row in enumerate(entries) if row[0] == name.removesuffix('.elf').encode()]
        expected = (name.removesuffix('.elf').encode(), ('/bin/' + name.removesuffix('.elf')).encode(), name.encode())
        require(len(matches) == 1 and matches[0][1] == expected, 'Guest catalog image/path mismatch: ' + name)
        root = f'("/bin/{name.removesuffix(".elf")}", PORTED[{matches[0][0]}].2),'.encode()
        require(raw.splitlines().count(root) == 1, 'Guest ROOT_FILES mapping mismatch: ' + name)
        require(identity(catalog.parent / name) == identity(prefix / name) == identity(image),
                'Generated/installed/original executable bytes differ: ' + name)
        require(bound[name] == identity(image)['sha256'], 'Kernel embeds a different executable: ' + name)
    assets = re.findall(rb'^\("([^"\n]+)", include_bytes!\(concat!\(env!\("OUT_DIR"\), "/(asset-\d+)"\)\)\),$',
                        raw, re.MULTILINE)
    require(len(entries) + len(assets) <= 256 and len({row[0] for row in assets}) == len(assets),
            'Generated root catalog count/uniqueness exceeds the production contract')
    copied_assets = {}
    total = sum((catalog.parent / row[2].decode()).stat().st_size for row in entries)
    for guest, filename in assets:
        name = guest.decode()
        require(name.startswith('/') and '..' not in Path(name).parts and len(guest) < 96,
                'Invalid generated root asset path')
        generated = catalog.parent / filename.decode()
        require(identity(generated) == identity(prefix / 'rootfs' / name.lstrip('/')),
                'Actual generated root asset differs from curated input: ' + name)
        copied_assets[name] = identity(generated)
        total += copied_assets[name]['bytes']
    require(total <= 96 * 1024**2, 'Generated full-OS catalog exceeds its existing byte budget')
    expected_assets = {('/' + name.removeprefix('rootfs/')) for name in manifest['external_inputs']
                       if name.startswith('rootfs/')}
    require(set(copied_assets) == expected_assets, 'Generated root asset closure differs from the actual OS inputs')
    return {'path': str(catalog), 'identity': identity(catalog), 'embedded': bound,
            'generated_assets': copied_assets, 'catalog_bytes': total}


def validate_inputs(args):
    # Separate read-only consumers are required. No status-only fallback exists.
    from cosmic_comp_inputs_v1 import validate_build as validate_comp
    build = plain_directory(args.build)
    manifest = os_x86.validate_build(build, cc=args.cc)
    require({'graphics', 'ported', 'cosmic-desktop', 'full-os'} <= set(manifest['features']),
            'Actual OS lacks the required full desktop/native graphics features')
    prefix = plain_directory(manifest['sysroot'])
    dbus_path = plain_directory(args.dbus_build)
    dbus = build_dbus.validate_build(dbus_path)
    require(dbus['output'] == dbus['validated_output'] == str(dbus_path), 'Original genuine D-Bus output is required')
    require(dbus['report']['architecture'] == 'x86_64', 'Wrong D-Bus architecture')
    comp_path = plain_directory(args.compositor_build)
    comp = validate_comp(comp_path)
    notification_path = plain_directory(args.notifications_build)
    notification = notifications.validate_build_directory(notification_path)
    installed = notifications.validate_inputs(prefix)
    require(installed['receipt']['origin']['build_output'] == str(notification_path),
            'Installed notification build differs from the selected original')
    client_path = plain_directory(args.probe_build)
    client = probe_inputs(client_path)
    require(client['report']['dbus']['path'] == str(dbus_path), 'Client uses a different broker build')
    programs = {'dbus-daemon.elf': dbus_path / 'dbus-daemon.elf', 'dbus-send.elf': dbus_path / 'dbus-send.elf',
                'cosmic-comp.elf': comp_path / 'cosmic-comp.elf',
                'cosmic-notifications.elf': notification_path / 'cosmic-notifications.elf',
                'notification-probe.elf': client_path / 'notification-probe.elf',
                'probe.elf': prefix / 'probe.elf'}
    inspections = {name.removesuffix('.elf'): elf.inspect_full_os_elf(path, FULL_OS)
                   for name, path in programs.items()}
    for guest, expected in dbus['report']['rootfs'].items():
        require(identity(prefix / 'rootfs' / guest.lstrip('/'))['sha256'] == expected,
                'Curated D-Bus runtime asset differs: ' + guest)
    assets = {'xkb': os_smoke.xkb_data_inputs(prefix), 'cosmic_config': install_cosmic_config.validate_inputs(prefix),
              'fonts': {'installer': install_cosmic_fonts_v1.validate_inputs(prefix),
                        'independent': font_inputs(prefix)}}
    if (prefix / 'cosmic-theme-assets.json').exists():
        assets['themes'] = install_cosmic_theme_defaults.validate_inputs(prefix)
    return {'os': manifest, 'build_manifest': identity(build / 'build-manifest.json'),
            'dbus': dbus, 'compositor': comp, 'notifications': notification,
            'notifications_installation': installed, 'probe': client, 'assets': assets,
            'inspections': inspections, 'catalog': catalog_identity(build, manifest, programs),
            'capture_producers': probe_builder.producer_sources(__file__)}


def qemu_inputs(args):
    program = probe_builder.no_symlink_path(args.qemu)
    require(os.access(program, os.X_OK), 'QEMU input must be executable')
    data, modules = plain_directory(args.qemu_data), plain_directory(args.qemu_module_dir)
    bios = probe_builder.no_symlink_path(args.bios)
    files = {str(path): identity(path) for path in sorted(modules.glob('*.so'))}
    require(files, 'Explicit genuine QEMU module directory is empty')
    firmware = {str(path): identity(path) for path in (bios, data / 'multiboot.bin', data / 'multiboot_dma.bin')}
    return {'program': {'path': str(program), **identity(program)}, 'modules': files,
            'firmware': firmware, 'module_directory': str(modules), 'data_directory': str(data)}


def query_bus(console, allowed, required):
    at = console.program('posix exec dbus-send')
    pid = int(console.until(rb'ELF pid=(\d+) started;', at)[1])
    row = processes(console)[pid]
    process_reclaimed(row, 'Exited', 0)
    active_processes(console, allowed, required)
    return {'pid': pid, 'process': row, 'serial_offset': at,
            'notification_name_listed': bool(re.search(rb'(?m)^\s*string "org\.freedesktop\.Notifications"\r?$', bytes(console.raw[at:])))}


def run_session(console, qmp, output, inputs, result):
    frames = result['frames']
    console.until(os_smoke.PROMPT)
    cpus = qmp.execute('query-cpus-fast')
    require(len(cpus) == 4 and len({cpu['cpu-index'] for cpu in cpus}) == 4, 'Missing actual guest CPUs')
    result['cpus'] = cpus
    registers = qmp.execute('human-monitor-command', {'command-line': 'info registers -a'})
    (output / 'boot-registers.txt').write_text(registers)
    cr0 = re.findall(r'CR0=([0-9a-fA-F]+)', registers)
    efer = re.findall(r'EFER=([0-9a-fA-F]+)', registers)
    require(len(cr0) == len(efer) == 4 and all(int(v, 16) & (3 << 29) == 0 and int(v, 16) & (1 << 5) for v in cr0)
            and all(int(v, 16) & (1 << 14) == 0 for v in efer), 'Unsafe guest CPU cache/FP state')
    boot = snapshot_frame(console, qmp, output, frames, 'boot')
    require(boot['boot_colorbars'], 'Unexpected boot framebuffer baseline')
    initial = system(console)
    result['resources_before'] = initial
    active_processes(console, set(), set(), allow_empty=True)
    require(initial['ofd'].get('live') == initial['ofd'].get('references') == 0,
            'Runtime session starts with live open descriptions')
    launched = result['launched']
    inspections = inputs['inspections']
    broker, at = launch(console, 'dbus-daemon', inspections['dbus-daemon'])
    launched['dbus-daemon'] = broker
    console.until(rb'(?m)^unix:path=/run/user/0/bus(?:,guid=[0-9a-f]+)?\r?$', at)
    result['bus_queries'].append(query_bus(console, {broker}, {broker}))
    compositor, at = launch(console, 'cosmic-comp', inspections['cosmic-comp'])
    launched['cosmic-comp'] = compositor
    deadline = min(console.deadline, time.monotonic() + 45)
    ready = None
    while time.monotonic() < deadline:
        active_processes(console, {broker, compositor}, {broker, compositor})
        observation = system(console)
        result['compositor_last_snapshot'] = observation
        for key in ('failed', 'policy_invalid', 'clock_rejected'):
            require(observation['display'].get(key) == initial['display'].get(key),
                    'Compositor display mechanism failed: ' + key)
        try:
            ready = completed_scanout(initial, observation, compositor)
        except ValueError:
            console.pump()
            time.sleep(.25)
            continue
        frame = snapshot_frame(console, qmp, output, frames, 'compositor', output / 'boot.ppm')
        require(not frame['boot_colorbars'] and frame['changed_pixels'] > 0,
                'Completed compositor transfer did not produce a non-boot scanout')
        result['compositor_scanout'] = {'completion': ready, 'frame': frame,
                                         'semantic_ui_verified': False}
        break
    require(ready is not None and 'compositor_scanout' in result, 'No genuine compositor scanout candidate')
    daemon, notification_start = launch(console, 'cosmic-notifications', inspections['cosmic-notifications'])
    launched['cosmic-notifications'] = daemon
    deadline = min(console.deadline, time.monotonic() + 30)
    listed = False
    while time.monotonic() < deadline:
        query = query_bus(console, set(launched.values()), set(launched.values()))
        result['bus_queries'].append(query)
        if query['notification_name_listed']:
            listed = True
            break
        time.sleep(.1)
    require(listed, 'Real broker did not list the notification service')
    result['notification_name_listed'] = True
    before_notification = system(console)
    snapshot_frame(console, qmp, output, frames, 'before-notify', output / 'compositor.ppm')
    client, probe_start = launch(console, 'notification-probe', inspections['notification-probe'])
    launched['notification-probe'] = client
    result['probe_serial_start'] = probe_start
    created_marker = console.until(rb'(?m)^NOTIFICATION_PROBE CREATED [^\r\n]*\r?$', probe_start, timeout=40)
    result['created_serial_end'] = probe_start + created_marker.end()
    result['protocol_created'] = protocol_markers(bytes(console.raw[probe_start:]), daemon, client, complete=False)
    result['notification_service_ready'] = True
    created_observed = time.monotonic()
    for index in range(2):
        require(time.monotonic() - created_observed < 4, 'Missed the client observation window')
        frame = snapshot_frame(console, qmp, output, frames, f'notification-{index}', output / 'before-notify.ppm')
        require(not re.search(rb'(?m)^NOTIFICATION_PROBE CLOSED ', bytes(console.raw[probe_start:])),
                'Notification already closed before the observation completed')
        frame['created_observed_elapsed_seconds'] = time.monotonic() - created_observed
        if index == 0:
            time.sleep(.25)
    during_notification = system(console)
    result['display_after_notification_frames'] = {
        'snapshot': during_notification,
        'closed_marker_observed': bool(re.search(rb'(?m)^NOTIFICATION_PROBE CLOSED ', bytes(console.raw[probe_start:])))}
    try:
        result['notification_scanout_completion'] = completed_scanout(before_notification, during_notification, compositor)
    except ValueError as error:
        result['notification_scanout_completion'] = {'observed': False, 'reason': str(error)}
    console.until(rb'(?m)^NOTIFICATION_PROBE PASS [^\r\n]*\r?$', probe_start, timeout=30)
    console.until(rb'pid=' + str(client).encode() + rb' Exited code=0\b', probe_start)
    result['protocol'] = protocol_markers(bytes(console.raw[probe_start:]), daemon, client, complete=True)
    result['wayland'] = wayland_observations(bytes(console.raw[notification_start:]))
    closed_marker = re.search(rb'(?m)^(?:cyxia:/> )?NOTIFICATION_PROBE CLOSED ', bytes(console.raw[probe_start:]))
    require(closed_marker is not None, 'Missing closed observation boundary')
    result['closed_serial_start'] = probe_start + closed_marker.start()
    result['wayland_created_to_closed'] = wayland_observations(
        bytes(console.raw[result['created_serial_end']:result['closed_serial_start']]))
    row = processes(console)[client]
    process_reclaimed(row, 'Exited', 0)
    result['processes_reclaimed']['notification-probe'] = row
    active_processes(console, set(launched.values()), {broker, compositor, daemon})
    snapshot_frame(console, qmp, output, frames, 'after-close', output / 'before-notify.ppm')
    for name in ('cosmic-notifications', 'cosmic-comp', 'dbus-daemon'):
        pid = launched[name]
        console.command('posix kill ' + str(pid), [rb'pid=' + str(pid).encode() + rb' killed; pages reclaimed'])
        row = processes(console)[pid]
        process_reclaimed(row, 'Killed', 137)
        result['processes_reclaimed'][name] = row
    # Query again after all kills: historical per-PID exit snapshots may have
    # observed other live owners. Only this nonempty list proves full recovery.
    final_rows = active_processes(console, set(), set())
    result['processes_after'] = final_rows
    result['process_arena_after'] = global_arena(final_rows, required_pids=launched.values())
    require(result['process_arena_after']['free_pages'] == 64,
            'Final global Runner arena was not fully reclaimed')
    deadline = min(console.deadline, time.monotonic() + 10)
    while True:
        after = system(console)
        if after['display'].get('phase') == 'Idle':
            break
        require(time.monotonic() < deadline, 'Pending native display transfer was not completed')
        time.sleep(.01)
    reclaimed(initial, after)
    result['resources_after'] = after
    result['service_shutdown'] = 'Explicit kernel posix kill of only the three PIDs started here; not graceful application shutdown'
    result['notification_protocol_observed'] = True


def capture(args):
    input_paths = [plain_directory(getattr(args, name)) for name in
                   ('build', 'dbus_build', 'compositor_build', 'notifications_build', 'probe_build')]
    # Discover retained SDK/catalog inputs before creating any capture path.
    # This is only path protection; full validators below still recheck facts.
    selected = document(args.build / 'build-manifest.json')
    input_paths.append(plain_directory(selected['sysroot']))
    for name, receipt_name in (('dbus_build', 'dbus-build-report.json'),
                               ('compositor_build', 'build-report.json'),
                               ('notifications_build', 'build-report.json'),
                               ('probe_build', 'build-report.json')):
        receipt = document(getattr(args, name) / receipt_name)
        for key in ('sysroot', 'source_cache', 'cache', 'cargo_cache'):
            if isinstance(receipt.get(key), str):
                input_paths.append(plain_directory(receipt[key]))
        if isinstance(receipt.get('sdk'), dict):
            input_paths.append(plain_directory(receipt['sdk']['path']))
    font_receipt = document(Path(selected['sysroot']) / 'cosmic-font-assets.json')
    input_paths.append(plain_directory(font_receipt['source']['checkout']))
    input_paths += [plain_directory(args.qemu_data), plain_directory(args.qemu_module_dir)]
    output = fresh_output(args.output, input_paths)
    lock = probe_builder.no_symlink_path(args.native_lock)
    require(all(not lock.is_relative_to(path) for path in input_paths), 'Lease file must be outside read-only inputs')
    lock.parent.mkdir(parents=True, exist_ok=True)
    with native_lease(lock):
        idle_native_host()
        output = fresh_output(output, input_paths)
        output.mkdir(parents=True)
        result = {'schema_version': 1, 'status': 'FAIL', 'scope': 'Genuine upstream notification protocol and separate scanout observations',
                  'transport': 'QEMU pipe chardev: separate real UART RX/TX and QMP FIFOs',
                  'standard_socket_capture': False, 'frames': [], 'launched': {}, 'bus_queries': [],
                  'processes_reclaimed': {}, 'notification_service_ready': False,
                  'notification_protocol_verified': False, 'notification_render_verified': False,
                  'notification_text_verified': False, 'cosmic_session_verified': False, 'full_os_verified': False,
                  'namespace_cleanup_verified': False,
                  'diagnostic_interrupt_trace': bool(getattr(args, 'trace_interrupts', False)),
                  'diagnostic_log_limit_bytes': MAX_DIAGNOSTIC_LOG_BYTES,
                  'native_lock': str(lock), 'max_wall_seconds': MAX_WALL_SECONDS,
                  'max_output_bytes': MAX_OUTPUT_BYTES, 'max_frames': MAX_FRAMES}
        process = console = qmp = watchdog = None
        channels = []
        checks_passed = False
        forced = threading.Event()
        started = time.monotonic()
        try:
            inputs = validate_inputs(args)
            machine = qemu_inputs(args)
            result['inputs'], result['qemu_inputs'] = inputs, machine
            result['qemu_version'] = pc.version(machine['program']['path'])
            producer = read_regular(__file__)
            (output / 'capture-producer.py').write_bytes(producer)
            (output / 'ported_catalog.rs').write_bytes(read_regular(inputs['catalog']['path'], 1024 * 1024))
            disk = create_disk(output / 'data.raw')
            result['disk_before'] = identity(disk)
            deadline = time.monotonic() + MAX_WALL_SECONDS
            with tempfile.TemporaryDirectory(prefix='cyx-notify-fifo-') as temporary, (output / 'qemu-stderr.log').open('wb') as error_log:
                temporary = Path(temporary)
                serial = PipeChannel(temporary / 'serial', deadline); channels.append(serial)
                management = PipeChannel(temporary / 'qmp', deadline + 8); channels.append(management)
                argv = os_x86.launch_argv(machine['program']['path'],
                                           plain_directory(args.build) / 'boot.bin', disk=disk)
                index = argv.index('-serial')
                argv[index:index + 2] = ['-chardev', f'pipe,id=serial,path={temporary / "serial"}', '-serial', 'chardev:serial']
                argv += ['-chardev', f'pipe,id=qmp,path={temporary / "qmp"}', '-mon', 'chardev=qmp,mode=control',
                         '-L', machine['data_directory'], '-bios', str(probe_builder.no_symlink_path(args.bios))]
                if result['diagnostic_interrupt_trace']:
                    # QEMU's own exception/register trace diagnoses guest faults
                    # without changing the already verified OS image. The file
                    # remains inside the same walltime/output budgets and is
                    # preserved as evidence, including on a genuine failure.
                    argv += ['-d', 'int', '-D', str(output / 'qemu-interrupts.log')]
                result['argv'] = argv
                environment = pc.env()
                environment['QEMU_MODULE_DIR'] = machine['module_directory']
                result['QEMU_MODULE_DIR'] = machine['module_directory']
                def diagnostic_limits():
                    # A kernel-enforced per-file bound also applies while QMP
                    # or UART waits. Reaching it is a failed diagnostic run,
                    # never a truncated successful trace. Guest input files
                    # are read-only; normal frame/disk outputs are much smaller.
                    resource.setrlimit(resource.RLIMIT_FSIZE,
                                       (MAX_DIAGNOSTIC_LOG_BYTES, MAX_DIAGNOSTIC_LOG_BYTES))

                process = subprocess.Popen(
                    argv, stdout=subprocess.DEVNULL, stderr=error_log, env=environment,
                    preexec_fn=diagnostic_limits if result['diagnostic_interrupt_trace'] else None)

                def expire():
                    if process.poll() is None:
                        forced.set()
                        process.kill()

                watchdog = threading.Timer(MAX_WALL_SECONDS + 8, expire)
                watchdog.daemon = True
                watchdog.start()
                serial.connect(process); management.connect(process)
                console = Console(serial, process, output, deadline)
                qmp = Qmp(management)
                require('QMP' in qmp.receive(time.monotonic() + 10), 'Missing actual QMP greeting')
                qmp.execute('qmp_capabilities')
                run_session(console, qmp, output, inputs, result)
                checks_passed = True
        except Exception as error:
            result['error'] = repr(error)
        finally:
            if console is not None:
                try:
                    console.pump()
                    result['pre_quit_uart_alive'] = True
                except Exception as error:
                    result.setdefault('error', repr(error))
            if qmp is not None:
                try:
                    qmp.execute('quit')
                    result['qmp_quit_acknowledged'] = True
                except Exception as error:
                    result.setdefault('error', repr(error))
                write_json(output / 'qmp.json', qmp.transcript)
            if process is not None:
                try:
                    result['returncode'] = process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    forced.set()
                    process.kill()
                    try:
                        result['returncode'] = process.wait(timeout=3)
                    except subprocess.TimeoutExpired as error:
                        result.setdefault('error', 'QEMU remained alive after kill: ' + repr(error))
            if watchdog is not None:
                watchdog.cancel()
                watchdog.join(timeout=1)
            result['forced'] = forced.is_set()
            if console is not None:
                try:
                    console.pump(require_running=False)
                except Exception as error:
                    result.setdefault('error', repr(error))
            raw = bytes(console.raw) if console is not None else b''
            (output / 'serial.raw').write_bytes(raw)
            (output / 'serial.txt').write_text(raw.decode('utf-8', errors='replace'))
            write_json(output / 'commands.json', console.commands if console is not None else [])
            for channel in channels:
                channel.close()
            result['elapsed_seconds'] = time.monotonic() - started
            result['serial'] = identity(output / 'serial.raw')
            diagnostic_log = output / 'qemu-interrupts.log'
            if result['diagnostic_interrupt_trace'] and diagnostic_log.exists():
                result['diagnostic_log_limit_hit'] = diagnostic_log.stat().st_size >= MAX_DIAGNOSTIC_LOG_BYTES
                if result['diagnostic_log_limit_hit']:
                    result.setdefault('error', 'QEMU diagnostic log reached its hard file limit')
            if (output / 'data.raw').exists():
                result['disk_after'] = identity(output / 'data.raw')
            if checks_passed and 'error' not in result and result.get('returncode') == 0 and not result['forced']:
                try:
                    require(result.get('qmp_quit_acknowledged') is True, 'No actual QMP quit acknowledgement')
                    require(protocol_markers(raw[result['probe_serial_start']:], result['launched']['cosmic-notifications'],
                            result['launched']['notification-probe'], complete=True) == result['protocol'],
                            'Notification protocol changed in the final UART drain')
                    require(validate_inputs(args) == inputs, 'Input/provenance changed during capture')
                    require(qemu_inputs(args) == machine and read_regular(__file__) == producer,
                            'QEMU, firmware, modules or capture producer changed')
                    for frame in result['frames']:
                        require(identity(output / frame['file'])['sha256'] == frame['sha256'], 'Captured framebuffer changed')
                    result['notification_protocol_verified'] = True
                    result['status'] = SUCCESS
                except Exception as error:
                    result['error'] = repr(error)
            result['evidence_files'] = {}
            for path in sorted(output.iterdir()):
                if path.is_file() and path.name != 'summary.json':
                    try:
                        result['evidence_files'][path.name] = identity(path, MAX_OUTPUT_BYTES)
                    except ValueError as error:
                        result['status'] = 'FAIL'
                        result['notification_protocol_verified'] = False
                        result.setdefault('error', 'Cannot finalize bounded evidence: ' + repr(error))
                        result['evidence_files'][path.name] = {'bytes': path.stat().st_size, 'hash_verified': False}
            write_json(output / 'summary.json', result)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'output', 'dbus-build', 'compositor-build', 'notifications-build', 'probe-build',
                 'qemu', 'qemu-data', 'bios', 'qemu-module-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cc', default='clang', help='Exact C compiler used by the formal OS build')
    parser.add_argument('--native-lock', type=Path, default=NATIVE_LOCK)
    parser.add_argument('--trace-interrupts', action='store_true',
                        help='Retain bounded QEMU interrupt/exception diagnostics inside this capture')
    args = parser.parse_args(argv)
    try:
        result = capture(args)
        print(json.dumps({key: result.get(key) for key in ('status', 'error', 'returncode', 'forced',
                         'elapsed_seconds', 'notification_protocol_verified', 'notification_render_verified')}, indent=2))
        return 0 if result['status'] == SUCCESS else 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('cosmic-notifications-runtime: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
