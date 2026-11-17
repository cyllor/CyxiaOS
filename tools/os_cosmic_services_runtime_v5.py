#!/usr/bin/env python3
"""Capture genuine session-version and settings-component lifecycles in QEMU.

This is an explicitly manual component integration scenario, not a normal COSMIC
session. It consumes nine independently bound real static images. Socket and
D-Bus evidence, process reclamation, and compositor scanout are separate facts.
The original first-frame 45s failure remains latched, late frame evidence ends
at launch+120s, and the guest retains its original 240s/output/owner budgets.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import threading
import time

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import os_cosmic_notifications_runtime_v2 as base
import cosmic_services_catalog_v1 as service_catalog
import install_cosmic_session_linux_v1 as session_installer
import install_cosmic_settings_linux_v3 as settings_installer
import settings_probe_inputs_v2 as settings_probe

ROOT, NATIVE_LOCK = base.ROOT, base.NATIVE_LOCK
MAX_WALL_SECONDS, MAX_OUTPUT_BYTES = base.MAX_WALL_SECONDS, base.MAX_OUTPUT_BYTES
MAX_FRAMES, MAX_DIAGNOSTIC_LOG_BYTES = base.MAX_FRAMES, base.MAX_DIAGNOSTIC_LOG_BYTES
FIRST_FRAME_SECONDS, LATE_FRAME_SECONDS = base.FIRST_FRAME_SECONDS, base.LATE_FRAME_SECONDS
FULL_OS = base.FULL_OS
IMAGE_NAMES = service_catalog.IMAGE_NAMES
SUCCESS = 'COSMIC_COMPONENT_LIFECYCLE_FIFO_PASS'
BASE_RUNTIME_SHA256 = '64aaa29ba69590731cf517c0decb8be2721f8881af37b469fc9c851b89b85d11'
ORIGINAL_RUNTIME_SHA256 = 'dfddc1f071ced0a491bfa09e6664cacde87e5ac87d15f836d2a8dcea14555058'
SERVICE = 'com.system76.CosmicSettingsDaemon'
SESSION_VERSION = '1.10.0'
THEME_ORIGINS = ('legacy-guest-v1', 'linux-host-v1', 'linux-host-v2')
require, read_regular, identity = base.require, base.read_regular, base.identity
document, write_json, plain_directory = base.document, base.write_json, base.plain_directory
fresh_output, qemu_inputs, snapshot_frame = base.fresh_output, base.qemu_inputs, base.snapshot_frame
system, processes, active_processes, launch = base.system, base.processes, base.active_processes, base.launch
process_reclaimed, reclaimed, global_arena = base.process_reclaimed, base.reclaimed, base.global_arena
catalog_identity = service_catalog.catalog_identity
PipeChannel, SessionQmp = base.PipeChannel, base.SessionQmp
probe_builder, os_smoke, os_x86, pc = base.probe_builder, base.os_smoke, base.os_x86, base.pc
native_lease, idle_native_host, create_disk = base.native_lease, base.idle_native_host, base.create_disk


def installation_binding(prefix, selected, installer, *, expected_files):
    """Validate the original installation and its exact copies in fresh catalog."""
    selected = plain_directory(selected)
    proof = installer.validate_inputs(selected)
    require(proof['status'] in ('SESSION_INSTALLATION_REVALIDATED_NOT_RUN',
                                'SETTINGS_INSTALLATION_REVALIDATED_NOT_RUN'),
            'Unrecognized independently validated component installation')
    require(type(proof['files']) is dict and set(proof['files']) == set(expected_files),
            'Installed component file closure differs from the declared upstream files')
    require(read_regular(prefix / installer.RECEIPT) == read_regular(selected / installer.RECEIPT),
            'Fresh catalog component origin receipt differs from the actual installation')
    for name, row in proof['files'].items():
        require(identity(prefix / name) == {key: row[key] for key in ('bytes', 'sha256')}
                and prefix.joinpath(name).stat().st_mode & 0o7777 == row['mode'],
                'Fresh catalog component bytes or mode differ: ' + name)
    return proof


def theme_inputs(prefix, origin):
    """A closed, source-bound consumer choice; Linux generation is not guest proof."""
    require(origin in THEME_ORIGINS, 'Select a reviewed fixed theme-generation consumer version')
    if origin == 'legacy-guest-v1':
        proof = base.install_cosmic_theme_defaults.validate_inputs(prefix)
        require(proof['status'] == 'PASS' and proof['full_os_verified'] is False
                and proof['cosmic_session_verified'] is False, 'Invalid preserved guest-export asset proof')
        receipt = 'cosmic-theme-assets.json'
        environment = 'Preserved separate CyxiaOS generator captures; not this settings lifecycle'
    elif origin == 'linux-host-v1':
        # This is deliberately a fixed module, never an arbitrary import/path.
        # The new validator binds actual Linux generator source/build/two-mode
        # outputs. It does not replace or reinterpret the old guest proof.
        import install_cosmic_theme_linux_v1
        require(not (prefix / 'cosmic-theme-assets.json').exists()
                and not (prefix / 'cosmic-theme-assets.json').is_symlink(),
                'Linux-host assets must retain their distinct receipt, not reuse the old guest receipt')
        proof = install_cosmic_theme_linux_v1.validate_inputs(prefix)
        require(proof['kind'] == 'cosmic-theme-linux-v1-assets'
                and proof['status'] == 'THEME_HOST_ASSETS_REVALIDATED_NOT_GUEST_RUN'
                and proof['host_generation'] is True and proof['guest_execution'] is False,
                'Linux theme inputs lack their genuine host-only generation identity')
        receipt = 'cosmic-theme-linux-v1-assets.json'
        environment = 'Linux host generation; CyxiaOS settings protocol remains unverified before this capture'
    else:
        # Keep the failed v1 producer and its independent interpretation intact.
        # The reviewed v2 chain has a distinct fixed module, kind and receipt.
        import install_cosmic_theme_linux_v2
        require(all(not (prefix / name).exists() and not (prefix / name).is_symlink()
                    for name in ('cosmic-theme-assets.json', 'cosmic-theme-linux-v1-assets.json')),
                'Linux-host v2 assets must retain their distinct receipt, not reuse an older origin')
        proof = install_cosmic_theme_linux_v2.validate_inputs(prefix)
        require(proof['kind'] == 'cosmic-theme-linux-v2-assets'
                and proof['status'] == 'THEME_HOST_ASSETS_REVALIDATED_NOT_GUEST_RUN'
                and proof['host_generation'] is True and proof['guest_execution'] is False,
                'Linux theme v2 inputs lack their genuine host-only generation identity')
        receipt = 'cosmic-theme-linux-v2-assets.json'
        environment = 'Linux host generation v2; CyxiaOS settings protocol remains unverified before this capture'
    require(type(proof['assets']) is list and len(proof['assets']) == 79
            and [row['path'] for row in proof['assets']] == base.install_cosmic_theme_defaults.expected_paths()
            and type(proof['bounds']['asset_files']) is int and proof['bounds']['asset_files'] == 79,
            'Settings requires all 39 light keys, 39 dark keys and the exact upstream license path')
    assets = []
    for row in proof['assets']:
        require(type(row['bytes']) is int and row['bytes'] > 0
                and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']) is not None,
                'Invalid complete theme asset identity')
        if origin in ('linux-host-v1', 'linux-host-v2'):
            require(type(row['mode']) is int and row['mode'] == 0o644, 'Linux theme file mode changed')
        path = prefix / 'rootfs' / row['path'].lstrip('/')
        require(identity(path) == {key: row[key] for key in ('bytes', 'sha256')}
                and path.stat().st_mode & 0o7777 == 0o644, 'Theme catalog bytes or mode changed: ' + row['path'])
        assets.append({**row, 'mode': 0o644})
    require(type(proof['bounds']['asset_bytes']) is int
            and sum(row['bytes'] for row in assets) == proof['bounds']['asset_bytes'],
            'Complete theme asset byte total differs from its generation proof')
    return {'origin': origin, 'generation_environment': environment, 'receipt': identity(prefix / receipt),
            'proof': proof, 'assets': assets, 'current_settings_guest_verified': False}


def protect_theme_output(output, prefix, origin):
    """Consume the real theme proof before any capture-directory mutation."""
    prefix = plain_directory(prefix)
    theme = theme_inputs(prefix, origin)
    protected = [prefix]
    if origin in ('linux-host-v1', 'linux-host-v2'):
        paths = theme['proof']['protected_paths']
        require(type(paths) is list and bool(paths),
                'Theme consumer must expose its verified generation input directories')
        for value in paths:
            require(type(value) is str and Path(value).is_absolute()
                    and str(Path(value)) == value and '..' not in Path(value).parts,
                    'Theme protected input is not a canonical absolute directory')
            protected.append(plain_directory(value))
    else:
        legacy = base.install_cosmic_theme_defaults
        legacy.validate_destination(output, legacy.MANIFEST, legacy.load_manifest(legacy.MANIFEST),
                                    theme['proof']['inputs_before'])
    return fresh_output(output, protected), theme, protected


def validate_inputs(args):
    require(identity(ROOT / 'tools/os_cosmic_notifications_runtime.py')['sha256'] == ORIGINAL_RUNTIME_SHA256
            and identity(ROOT / 'tools/os_cosmic_notifications_runtime_v2.py')['sha256'] == BASE_RUNTIME_SHA256,
            'Preserved original or reviewed v2 runtime producer changed')
    require(args.theme_origin in THEME_ORIGINS, 'Select a reviewed fixed theme-generation consumer version')
    selected_prefix = plain_directory(document(args.build / 'build-manifest.json')['sysroot'])
    if args.theme_origin in ('linux-host-v1', 'linux-host-v2'):
        require(not (selected_prefix / 'cosmic-theme-assets.json').exists()
                and not (selected_prefix / 'cosmic-theme-assets.json').is_symlink(),
                'New host generation must not impersonate a legacy guest-export receipt')
    # Retain every original broker/compositor/notification/client/asset gate.
    # Its six-image check is supplemented by the fixed nine-image helper below.
    inputs = base.validate_inputs(args)
    prefix = plain_directory(inputs['os']['sysroot'])
    inputs['assets']['themes'] = theme_inputs(prefix, args.theme_origin)
    session_path = plain_directory(args.session_installation)
    settings_path = plain_directory(args.settings_installation)
    client_path = plain_directory(args.settings_probe_build)
    session = installation_binding(prefix, session_path, session_installer,
        expected_files=(session_installer.PROGRAM, *session_installer.LICENSES.values()))
    settings = installation_binding(prefix, settings_path, settings_installer,
        expected_files=(settings_installer.PROGRAM, *settings_installer.LICENSES.values()))
    require(settings_installer.RECEIPT == 'cosmic-settings-linux-v2-installation.json'
            and settings['kind'] == 'cosmic-settings-linux-v2-installation',
            'Settings runtime requires the independently validated v2 daemon installation')
    client = settings_probe.validate_build(client_path)
    require(client['kind'] == 'cosmic-settings-probe-v2'
            and type(client['client_contract']['protocol_version']) is int
            and client['client_contract']['protocol_version'] == 2
            and client['client_contract']['changed_marker_fields']
                == ['watcher_unique', 'watcher_name', 'watcher_pid', 'service_pid', 'client_pid']
            and client['status'] == 'SETTINGS_PROBE_BUILD_REVALIDATED_NOT_RUN'
            and client['guest_execution'] is False and client['settings_verified'] is False
            and client['cosmic_session_ready'] is False and client['full_cosmic_complete'] is False
            and client['dbus_build'] == str(plain_directory(args.dbus_build)),
            'Settings client is not bound to the actual selected genuine broker')
    require(client['executable']['path'] == str(client_path / 'settings-probe.elf'),
            'Settings client executable path differs from its strict proof')
    programs = {'probe.elf': prefix / 'probe.elf',
                'dbus-daemon.elf': args.dbus_build / 'dbus-daemon.elf',
                'dbus-send.elf': args.dbus_build / 'dbus-send.elf',
                'cosmic-comp.elf': args.compositor_build / 'cosmic-comp.elf',
                'cosmic-notifications.elf': args.notifications_build / 'cosmic-notifications.elf',
                'notification-probe.elf': args.probe_build / 'notification-probe.elf',
                'cosmic-session.elf': session_path / 'cosmic-session.elf',
                'cosmic-settings-daemon.elf': settings_path / 'cosmic-settings-daemon.elf',
                'settings-probe.elf': client_path / 'settings-probe.elf'}
    for name in ('cosmic-session', 'cosmic-settings-daemon', 'settings-probe'):
        inputs['inspections'][name] = base.elf.inspect_full_os_elf(programs[name + '.elf'], FULL_OS)
    require(inputs['inspections']['settings-probe'] == client['image_admission'],
            'Settings client consumer and runtime image admission disagree')
    for name, proof in [('cosmic-session', session), ('cosmic-settings-daemon', settings)]:
        receipt = document((session_path if name == 'cosmic-session' else settings_path)
                           / (session_installer.RECEIPT if name == 'cosmic-session' else settings_installer.RECEIPT))
        require(all(inputs['inspections'][name][key] == receipt[key]
                    for key in ('required_pages', 'image_load_pages')),
                'Installed component page grant differs from actual admission: ' + name)
    inputs['session_installation'], inputs['settings_installation'] = session, settings
    inputs['settings_probe'] = client
    inputs['catalog'] = catalog_identity(plain_directory(args.build), inputs['os'], programs)
    inputs['capture_producers'] = probe_builder.producer_sources(__file__)
    return inputs


def marker_rows(raw, prefix):
    require(type(raw) is bytes, 'Protocol evidence must be actual bounded raw bytes')
    require(len(raw) < 4 * 1024**2, 'Protocol evidence exceeds the original UART budget')
    return re.findall(rb'(?m)^(?:cyxia:/> )?(' + re.escape(prefix) + rb'[^\r\n]*)\r?$', raw)


def session_version_evidence(raw, pid, required_pages):
    require(type(pid) is int and pid > 0 and type(required_pages) is int and required_pages > 0,
            'Session version evidence requires the actual positive PID and page grant')
    rows = re.findall(rb'(?m)^(?:cyxia:/> )?(cosmic-session[^\r\n]*)\r?$', raw)
    require(rows == [('cosmic-session ' + SESSION_VERSION).encode()],
            'Missing, duplicated or different genuine session version output')
    starts = re.findall(rb'ELF pid=(\d+) started;[^\r\n]*image AI_DIRECT model=8197 pages=(\d+)', raw)
    require(starts == [(str(pid).encode(), str(required_pages).encode())],
            'Session version output is not bound to its one real image launch')
    exits = re.findall(rb'(?m)^(?:cyxia:/> )?USER pid=(\d+) (Exited|Fault|Timeout|Killed) code=(\d+)\b[^\r\n]*\r?$', raw)
    require(exits == [(str(pid).encode(), b'Exited', b'0')],
            'Session version did not end with exactly one matching successful exit')
    require(raw.index(rows[0]) < raw.index(b'pid=' + str(pid).encode() + b' Exited code=0'),
            'Session version output followed its terminal event')
    return {'pid': pid, 'version': SESSION_VERSION, 'argv': ['/bin/cosmic-session', '--version'],
            'required_pages': required_pages, 'state': 'Exited', 'code': 0,
            'normal_session_executed': False}


def preparation_evidence(raw, pid, required_pages):
    require(type(pid) is int and pid > 0 and type(required_pages) is int and required_pages > 0,
            'Settings preparation requires the actual positive PID and page grant')
    require(marker_rows(raw, b'SETTINGS_PROBE') == [b'SETTINGS_PROBE PREPARED'],
            'Settings preparation evidence is missing, duplicated or unrelated')
    starts = re.findall(rb'ELF pid=(\d+) started;[^\r\n]*image AI_DIRECT model=8197 pages=(\d+)', raw)
    require(starts == [(str(pid).encode(), str(required_pages).encode())],
            'Settings preparation is not bound to its actual image grant')
    exits = re.findall(rb'(?m)^(?:cyxia:/> )?USER pid=(\d+) (Exited|Fault|Timeout|Killed) code=(\d+)\b[^\r\n]*\r?$', raw)
    require(exits == [(str(pid).encode(), b'Exited', b'0')],
            'Settings preparation did not execute and exit successfully')
    return {'pid': pid, 'argv': ['/bin/settings-probe', 'prepare'], 'prepared': True}


def settings_protocol(raw, service_pid, client_pid, *, through='complete'):
    require(through in ('readiness', 'owner', 'complete') and type(client_pid) is int and client_pid > 0,
            'Invalid settings observation stage or actual client PID')
    if through != 'readiness' or service_pid is not None:
        require(type(service_pid) is int and service_pid > 0 and service_pid != client_pid,
                'Settings owner must be the distinct actual launched service PID')
    rows = marker_rows(raw, b'SETTINGS_PROBE')
    minimum = {'readiness': 2, 'owner': 3, 'complete': 9}[through]
    require(minimum <= len(rows) <= 9, 'Unexpected settings protocol marker count')
    require(rows[0] == b'SETTINGS_PROBE START service=com.system76.CosmicSettingsDaemon render_verified=false',
            'Missing actual settings client start')
    require(rows[1] == (f'SETTINGS_PROBE WAYLAND_READY path=/run/user/0/wayland-1 client_pid={client_pid} '
                        'protocol_verified=false').encode(),
            'Wayland socket readiness is not bound to the launched real client')
    owner = None
    if len(rows) >= 3:
        require(service_pid is not None, 'Settings owner appeared before the service launch was recorded')
        match = re.fullmatch(rb'SETTINGS_PROBE OWNER PASS unique=(:[A-Za-z0-9_.-]+) service_pid=(\d+) client_pid=(\d+)', rows[2])
        require(match is not None and int(match[2]) == service_pid and int(match[3]) == client_pid
                and service_pid != client_pid, 'Broker owner/client PID differs from the launched actual images')
        owner = match[1].decode()
    watchers = {}
    for index, label in ((3, 'Config'), (4, 'State')):
        if len(rows) <= index:
            continue
        # A returned well-known name may own a separate D-Bus connection. Its
        # exact unique owner must still authenticate to the actual daemon PID.
        name = f'{SERVICE}.{label}.org.cyxia.SettingsProbe.V1'
        pattern = (f'SETTINGS_PROBE {label.upper()}_CHANGED PASS watcher_unique='.encode()
                   + rb'(:[A-Za-z0-9_.-]+) watcher_name=' + re.escape(name.encode())
                   + f' watcher_pid={service_pid} service_pid={service_pid} client_pid={client_pid}'.encode())
        match = re.fullmatch(pattern, rows[index])
        require(match is not None,
                'Changed evidence lacks its exact watcher name/unique owner and actual daemon/client PID binding')
        watchers[label.lower()] = {'name': name, 'unique': match[1].decode(), 'pid': service_pid}
    expected = [b'SETTINGS_PROBE THEME_LIGHT_DARK PASS', b'SETTINGS_PROBE UNSUPPORTED_CAPABILITIES PASS']
    for index, row in enumerate(rows[5:7]):
        require(row == expected[index], 'Settings protocol stage is missing, duplicated or reordered')
    if len(rows) >= 8:
        require(rows[7] == (f'SETTINGS_PROBE OWNER_STABLE PASS unique={owner} service_pid={service_pid} '
                           f'client_pid={client_pid}').encode(), 'Settings owner changed before completion')
    if len(rows) == 9:
        require(rows[8] == (f'SETTINGS_PROBE PASS service_pid={service_pid} client_pid={client_pid} '
                           'render_verified=false').encode(), 'Settings PASS differs from its real owner/client')
    return {'service': SERVICE, 'owner': owner, 'service_pid': service_pid, 'client_pid': client_pid,
            'watchers': watchers, 'markers': [row.decode() for row in rows], 'complete': len(rows) == 9,
            'wayland_socket_connected': True, 'wayland_protocol_verified': False,
            'render_verified': False, 'normal_session_executed': False}


def bounded_window(raw, start, end):
    require(type(raw) is bytes and type(start) is int and type(end) is int
            and 0 <= start < end <= len(raw), 'Invalid fresh UART observation window')
    return raw[start:end]


class Console(base.Console):
    """Retain exact v2 UART boundaries; only latch the independent frame clock."""
    frame_observer = None

    def pump(self, *, require_running=True):
        super().pump(require_running=require_running)
        if require_running and self.frame_observer is not None:
            self.frame_observer.tick()


class FrameObserver:
    """Cooperate with protocol progress without resetting the post-launch clock."""
    def __init__(self, console, qmp, output, initial, compositor, result):
        self.console, self.qmp, self.output = console, qmp, output
        self.initial, self.compositor, self.result = initial, compositor, result
        # Same origin as the preserved runtime: immediately after launch returns.
        self.started = time.monotonic()
        self.deadline = min(console.deadline, self.started + LATE_FRAME_SECONDS)
        self.observed = False
        self.closed = False
        result['compositor_clock_origin_seconds'] = self.started
        console.frame_observer = self

    def tick(self, *, raise_on_gate=True):
        if self.closed or self.observed:
            return
        elapsed = time.monotonic() - self.started
        if elapsed >= FIRST_FRAME_SECONDS and not self.result['first_frame_deadline_failed']:
            failure = {'schema_version': 1, 'status': 'FAIL', 'gate': 'first_compositor_frame',
                       'deadline_seconds': FIRST_FRAME_SECONDS, 'elapsed_seconds': elapsed,
                       'compositor_pid': self.compositor, 'serial_offset': len(self.console.raw),
                       'error': 'No genuine compositor scanout candidate within the original first-frame gate'}
            self.result['first_frame_deadline_failed'] = True
            self.result['first_frame_deadline_failure'] = failure
            write_json(self.output / 'first-frame-deadline-failure.json', failure)
        if self.result['first_frame_deadline_failed'] and not self.result['observe_after_frame_deadline']:
            if raise_on_gate:
                raise ValueError(self.result['first_frame_deadline_failure']['error'])
        if time.monotonic() >= self.deadline:
            self.closed = True
            self.result['late_compositor_frame_observed'] = False
            self.result['late_frame_observation_closed_at_seconds'] = elapsed

    def checkpoint(self, allowed, required):
        self.tick()
        if self.closed or self.observed:
            return
        # Existing transport deadlines apply, including a command straddling
        # a gate. Fatal/disconnect/timeout exceptions propagate unchanged.
        with base.late_frame_window(self.console, self.qmp, self.deadline):
            self.result['last_active_processes'] = active_processes(self.console, allowed, required)
            observation = system(self.console)
            self.result['compositor_last_snapshot'] = observation
            self.tick()
            for key in ('failed', 'policy_invalid', 'clock_rejected'):
                require(observation['display'].get(key) == self.initial['display'].get(key),
                        'Compositor display mechanism failed: ' + key)
            if self.closed:
                return
            try:
                ready = base.completed_scanout(self.initial, observation, self.compositor)
            except ValueError:
                return
            frame = snapshot_frame(self.console, self.qmp, self.output, self.result['frames'],
                                   'compositor', self.output / 'boot.ppm')
            require(not frame['boot_colorbars'] and frame['changed_pixels'] > 0,
                    'Completed compositor transfer did not produce a non-boot scanout')
            self.tick()
            require(not self.closed and time.monotonic() < self.deadline,
                    'Late frame observation deadline exceeded')
            self.observed = True
            self.result['compositor_scanout'] = {'completion': ready, 'frame': frame,
                'semantic_ui_verified': False, 'elapsed_seconds': time.monotonic() - self.started,
                'after_first_frame_deadline': self.result['first_frame_deadline_failed']}
            if self.result['first_frame_deadline_failed']:
                self.result['late_compositor_frame_observed'] = True

    def finish(self, allowed, required):
        while not self.observed and not self.closed:
            self.checkpoint(allowed, required)
            if not self.observed and not self.closed:
                self.console.pump()
                time.sleep(min(.25, max(0, self.deadline - time.monotonic())))


def wait_observed(console, observer, pattern, start, allowed, required, *, timeout=30):
    require(type(timeout) in (int, float) and 0 < timeout <= 30,
            'Service operation cannot extend the original 30s console bound')
    deadline = min(console.deadline, time.monotonic() + timeout)
    with base.late_frame_window(console, observer.qmp, deadline):
        while True:
            console.pump()
            found = re.search(pattern, bytes(console.raw[start:]), re.MULTILINE)
            if found is not None:
                require(time.monotonic() < deadline, 'Service observation exceeded its fixed operation deadline')
                return found
            observer.checkpoint(allowed, required)
            require(time.monotonic() < deadline, 'Service observation exceeded its fixed operation deadline')
            time.sleep(min(.25, max(0, deadline - time.monotonic())))


def final_service_arena(rows, launched):
    """Check current service slots after separately evidenced earlier phases.

    The kernel reuses a terminal Runner slot on the next launch. Its process
    list is therefore a current slot snapshot, not a history of every old PID.
    Version/preparation UART, per-PID and global resource proofs remain in their
    own completed phases; all four service-phase identities must still appear.
    """
    earlier = ('cosmic-session-version', 'settings-probe-prepare')
    services = ('dbus-daemon', 'cosmic-comp', 'settings-probe', 'cosmic-settings-daemon')
    require(type(launched) is dict and set(launched) == set(earlier + services),
            'Final service arena requires every recorded launch identity')
    pids = [launched[name] for name in earlier + services]
    require(all(type(pid) is int and pid > 0 for pid in pids)
            and len(set(pids)) == len(pids),
            'Distinct launches cannot reuse, omit or fabricate a PID')
    arena = global_arena(rows, required_pids=[launched[name] for name in services])
    require(not arena['active_pids'] and arena['free_pages'] == 64
            and all(row['state'] in ('Exited', 'Fault', 'Timeout', 'Killed') for row in rows.values()),
            'Final service process slots are not all terminal and fully reclaimed')
    for name in services:
        process_reclaimed(rows[launched[name]], 'Exited' if name == 'settings-probe' else 'Killed',
                          0 if name == 'settings-probe' else 137)
    return arena


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
    launched, inspections = result['launched'], inputs['inspections']

    version, start = launch(console, 'cosmic-session-version', inspections['cosmic-session'])
    launched['cosmic-session-version'] = version
    console.until(rb'(?m)^(?:cyxia:/> )?cosmic-session 1\.10\.0\r?$', start)
    console.until(rb'pid=' + str(version).encode() + rb' Exited code=0\b', start)
    end = len(console.raw)
    proof = session_version_evidence(bytes(console.raw[start:end]), version,
                                     inspections['cosmic-session']['required_pages'])
    row = processes(console)[version]
    process_reclaimed(row, 'Exited', 0)
    result['processes_reclaimed']['cosmic-session-version'] = row
    rows = active_processes(console, set(), set())
    after_version = system(console)
    reclaimed(initial, after_version)
    result['components']['session_version'] = {'status': 'OBSERVED_NOT_FINALIZED', 'verified': False,
        'serial_start': start, 'serial_end': end, 'evidence': proof, 'process_reclaimed': row,
        'arena': global_arena(rows, required_pids={version}), 'resources_after': after_version}

    preparation, start = launch(console, 'settings-probe-prepare', inspections['settings-probe'])
    launched['settings-probe-prepare'] = preparation
    console.until(rb'(?m)^(?:cyxia:/> )?SETTINGS_PROBE PREPARED\r?$', start)
    console.until(rb'pid=' + str(preparation).encode() + rb' Exited code=0\b', start)
    end = len(console.raw)
    result['preparation'] = {'serial_start': start, 'serial_end': end,
        'evidence': preparation_evidence(bytes(console.raw[start:end]), preparation,
                                         inspections['settings-probe']['required_pages'])}
    row = processes(console)[preparation]
    process_reclaimed(row, 'Exited', 0)
    result['processes_reclaimed']['settings-probe-prepare'] = row
    rows = active_processes(console, set(), set())
    result['preparation']['arena'] = global_arena(rows, required_pids={preparation})
    after_preparation = system(console)
    reclaimed(initial, after_preparation)
    result['preparation']['resources_after'] = after_preparation

    broker, start = launch(console, 'dbus-daemon', inspections['dbus-daemon'])
    launched['dbus-daemon'] = broker
    console.until(rb'(?m)^unix:path=/run/user/0/bus(?:,guid=[0-9a-f]+)?\r?$', start)
    result['bus_queries'].append(base.query_bus(console, {broker}, {broker}))
    compositor, start = launch(console, 'cosmic-comp', inspections['cosmic-comp'])
    launched['cosmic-comp'] = compositor
    observer = FrameObserver(console, qmp, output, initial, compositor, result)
    try:
        client, start = launch(console, 'settings-probe', inspections['settings-probe'])
        launched['settings-probe'] = client
        result['settings_probe_serial_start'] = start
        allowed, required = {broker, compositor, client}, {broker, compositor}
        wait_observed(console, observer, rb'(?m)^(?:cyxia:/> )?SETTINGS_PROBE WAYLAND_READY [^\r\n]*\r?$',
                      start, allowed, required)
        result['settings_socket_readiness'] = settings_protocol(bytes(console.raw[start:]), None, client,
                                                               through='readiness')
        # Only the real client's successful AF_UNIX connect permits this start.
        daemon, daemon_start = launch(console, 'cosmic-settings-daemon', inspections['cosmic-settings-daemon'])
        launched['cosmic-settings-daemon'] = daemon
        allowed.add(daemon); required.add(daemon)
        wait_observed(console, observer, rb'(?m)^(?:cyxia:/> )?SETTINGS_PROBE OWNER PASS [^\r\n]*\r?$',
                      start, allowed, required)
        result['settings_owner'] = settings_protocol(bytes(console.raw[start:]), daemon, client, through='owner')
        # Each real protocol stage retains a 30s host bound. Guest method/signal/
        # theme limits remain 10/15/30s in the immutable genuine client source.
        for marker in (b'CONFIG_CHANGED PASS', b'STATE_CHANGED PASS', b'THEME_LIGHT_DARK PASS',
                       b'UNSUPPORTED_CAPABILITIES PASS', b'OWNER_STABLE PASS', b'PASS service_pid='):
            wait_observed(console, observer, rb'(?m)^(?:cyxia:/> )?SETTINGS_PROBE ' + re.escape(marker) + rb'[^\r\n]*\r?$',
                          start, allowed, required)
            settings_protocol(bytes(console.raw[start:]), daemon, client, through='owner')
        wait_observed(console, observer, rb'pid=' + str(client).encode() + rb' Exited code=0\b',
                      start, allowed, required)
        end = len(console.raw)
        protocol = settings_protocol(bytes(console.raw[start:end]), daemon, client)
        row = processes(console)[client]
        process_reclaimed(row, 'Exited', 0)
        result['processes_reclaimed']['settings-probe'] = row
        active_processes(console, {broker, compositor, daemon}, {broker, compositor, daemon})
        result['components']['settings'] = {'status': 'OBSERVED_NOT_FINALIZED', 'verified': False,
            'serial_start': start, 'serial_end': end, 'daemon_serial_start': daemon_start,
            'protocol': protocol, 'client_reclaimed': row,
            'wayland': base.wayland_observations(bytes(console.raw[daemon_start:end])),
            'normal_session_executed': False}
        observer.finish({broker, compositor, daemon}, {broker, compositor, daemon})
    finally:
        observer.tick(raise_on_gate=False)

    for name in ('cosmic-settings-daemon', 'cosmic-comp', 'dbus-daemon'):
        pid = launched[name]
        console.command('posix kill ' + str(pid), [rb'pid=' + str(pid).encode() + rb' killed; pages reclaimed'])
        row = processes(console)[pid]
        process_reclaimed(row, 'Killed', 137)
        result['processes_reclaimed'][name] = row
    console.frame_observer = None
    final_rows = active_processes(console, set(), set())
    result['processes_after'] = final_rows
    result['process_arena_after'] = final_service_arena(final_rows, launched)
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
    result['resource_cleanup_observed'] = True
    result['service_shutdown'] = 'Explicit kernel posix kill of only the three service PIDs started here; not graceful application shutdown'
    result['service_lifecycle_observed'] = True


def finalize_components(raw, result, inputs):
    """Only preserved final raw bytes plus actual per-PID/global cleanup count."""
    version = result['components']['session_version']
    if version.get('status') == 'OBSERVED_NOT_FINALIZED':
        expected = session_version_evidence(bounded_window(raw, version['serial_start'], version['serial_end']),
            result['launched']['cosmic-session-version'], inputs['inspections']['cosmic-session']['required_pages'])
        require(expected == version['evidence'], 'Session version evidence changed in the final UART drain')
        require(version['process_reclaimed']['pid'] == result['launched']['cosmic-session-version'],
                'Version-only reclamation belongs to a different process')
        process_reclaimed(version['process_reclaimed'], 'Exited', 0)
        reclaimed(result['resources_before'], version['resources_after'])
        require(version['arena']['free_pages'] == 64 and not version['arena']['active_pids'],
                'Version-only process arena was not fully reclaimed')
        version['verified'], version['status'] = True, 'PASS'
    settings = result['components']['settings']
    if settings.get('status') == 'OBSERVED_NOT_FINALIZED':
        require(version.get('status') == 'PASS' and version.get('verified') is True,
                'Settings finalization requires the completed session-version phase proof')
        bounded_window(raw, settings['serial_start'], settings['serial_end'])
        require(settings_protocol(raw[settings['serial_start']:],
                result['launched']['cosmic-settings-daemon'], result['launched']['settings-probe']) == settings['protocol'],
                'Settings protocol evidence changed in the final UART drain')
        preparation = result['preparation']
        require(preparation_evidence(bounded_window(raw, preparation['serial_start'], preparation['serial_end']),
                result['launched']['settings-probe-prepare'], inputs['inspections']['settings-probe']['required_pages'])
                == preparation['evidence'], 'Settings preparation changed in the final UART drain')
        require(result['processes_reclaimed']['settings-probe-prepare']['pid']
                == result['launched']['settings-probe-prepare'], 'Preparation reclamation belongs to a different process')
        process_reclaimed(result['processes_reclaimed']['settings-probe-prepare'], 'Exited', 0)
        reclaimed(result['resources_before'], preparation['resources_after'])
        require(preparation['arena']['free_pages'] == 64 and not preparation['arena']['active_pids'],
                'Preparation process arena was not fully reclaimed')
        require(result.get('resource_cleanup_observed') is True,
                'Settings protocol lacks complete service/global reclamation evidence')
        require(settings['client_reclaimed']['pid'] == result['launched']['settings-probe'],
                'Settings client reclamation belongs to a different process')
        process_reclaimed(settings['client_reclaimed'], 'Exited', 0)
        for name in ('cosmic-settings-daemon', 'cosmic-comp', 'dbus-daemon'):
            require(result['processes_reclaimed'][name]['pid'] == result['launched'][name],
                    'Service reclamation belongs to a different process: ' + name)
            process_reclaimed(result['processes_reclaimed'][name], 'Killed', 137)
        reclaimed(result['resources_before'], result['resources_after'])
        require(final_service_arena(result['processes_after'], result['launched'])
                == result['process_arena_after'] and result['process_arena_after']['free_pages'] == 64,
                'Settings final global process arena did not fully recover')
        settings['verified'], settings['status'] = True, 'PASS'
    result['service_lifecycle_verified'] = version['verified'] and settings['verified']


def capture(args):
    input_paths = [plain_directory(getattr(args, name)) for name in
                   ('build', 'dbus_build', 'compositor_build', 'notifications_build', 'probe_build',
                    'session_installation', 'settings_installation', 'settings_probe_build')]
    # Discover retained SDK/catalog inputs before creating any capture path.
    # This is only path protection; full validators below still recheck facts.
    selected = document(args.build / 'build-manifest.json')
    input_paths.append(plain_directory(selected['sysroot']))
    for name, receipt_name in (('dbus_build', 'dbus-build-report.json'),
                               ('compositor_build', 'build-report.json'),
                               ('notifications_build', 'build-report.json'),
                               ('probe_build', 'build-report.json'), ('settings_probe_build', 'build-report.json')):
        receipt = document(getattr(args, name) / receipt_name)
        for key in ('sysroot', 'source_cache', 'cache', 'cargo_cache'):
            if isinstance(receipt.get(key), str):
                input_paths.append(plain_directory(receipt[key]))
        if isinstance(receipt.get('sdk'), dict):
            input_paths.append(plain_directory(receipt['sdk']['path']))
    for name, installer in (('session_installation', session_installer),
                            ('settings_installation', settings_installer)):
        installation = document(getattr(args, name) / installer.RECEIPT)
        original = plain_directory(installation['origin']['build_output'])
        input_paths.append(original)
        report = document(original / 'build-report.json')
        for key in ('sysroot', 'source_cache', 'cache', 'cargo_cache'):
            if isinstance(report.get(key), str):
                input_paths.append(plain_directory(report[key]))
    font_receipt = document(Path(selected['sysroot']) / 'cosmic-font-assets.json')
    input_paths.append(plain_directory(font_receipt['source']['checkout']))
    input_paths += [plain_directory(args.qemu_data), plain_directory(args.qemu_module_dir)]
    output = fresh_output(args.output, input_paths)
    lock = probe_builder.no_symlink_path(args.native_lock)
    require(lock == probe_builder.no_symlink_path(NATIVE_LOCK) and lock.is_file(),
            'Use the existing original native-session lease; preflight creates no lock path')
    require(all(not lock.is_relative_to(path) for path in input_paths), 'Lease file must be outside read-only inputs')
    with native_lease(lock):
        idle_native_host()
        output, theme_before, theme_paths = protect_theme_output(
            output, selected['sysroot'], args.theme_origin)
        input_paths += theme_paths
        require(all(not lock.is_relative_to(path) for path in input_paths),
                'Lease file must be outside verified theme-generation inputs')
        output = fresh_output(output, input_paths)
        output.mkdir(parents=True)
        result = {'schema_version': 1, 'status': 'FAIL', 'scope': 'Genuine session-version and manually launched settings-component lifecycles; separate scanout observations',
                  'transport': 'QEMU pipe chardev: separate real UART RX/TX and QMP FIFOs',
                  'standard_socket_capture': False, 'frames': [], 'launched': {}, 'bus_queries': [],
                  'processes_reclaimed': {}, 'notification_service_ready': False,
                  'notification_protocol_verified': False, 'notification_render_verified': False,
                  'notification_text_verified': False, 'cosmic_session_verified': False, 'full_os_verified': False,
                  'namespace_cleanup_verified': False,
                  'observe_after_frame_deadline': bool(getattr(args, 'observe_after_frame_deadline', False)),
                  'first_frame_deadline_failed': False, 'late_observation_evidence_verified': False,
                  'first_frame_deadline_seconds': FIRST_FRAME_SECONDS,
                  'late_frame_limit_seconds_from_compositor_launch': LATE_FRAME_SECONDS,
                  'diagnostic_interrupt_trace': bool(getattr(args, 'trace_interrupts', False)),
                  'diagnostic_log_limit_bytes': MAX_DIAGNOSTIC_LOG_BYTES,
                  'native_lock': str(lock), 'max_wall_seconds': MAX_WALL_SECONDS,
                  'max_output_bytes': MAX_OUTPUT_BYTES, 'max_frames': MAX_FRAMES}
        result.update(components={'session_version': {'status': 'NOT_RUN', 'verified': False},
                                  'settings': {'status': 'NOT_RUN', 'verified': False}},
                      service_lifecycle_observed=False, service_lifecycle_verified=False,
                      resource_cleanup_observed=False, input_identity_verified=False,
                      normal_session_executed=False, cosmic_session_ready=False,
                      full_cosmic_complete=False, late_compositor_frame_observed=False,
                      normal_session_dependencies={'executed': False,
                          'missing_required_programs': ['/bin/cosmic-panel'],
                          'scope': 'Source-level required panel dependency is absent from this exact nine-image catalog; no normal session or FD handoff execution is claimed'})
        inputs = machine = producer = None
        process = console = qmp = watchdog = None
        channels = []
        checks_passed = False
        forced = threading.Event()
        started = time.monotonic()
        try:
            inputs = validate_inputs(args)
            require(inputs['assets']['themes'] == theme_before,
                    'Theme generation identity changed after output protection')
            machine = qemu_inputs(args)
            result['inputs'], result['qemu_inputs'] = inputs, machine
            result['qemu_version'] = pc.version(machine['program']['path'])
            producer = read_regular(__file__)
            (output / 'capture-producer.py').write_bytes(producer)
            (output / 'ported_catalog.rs').write_bytes(read_regular(inputs['catalog']['path'], 1024 * 1024))
            disk = create_disk(output / 'data.raw')
            result['disk_before'] = identity(disk)
            deadline = time.monotonic() + MAX_WALL_SECONDS
            with tempfile.TemporaryDirectory(prefix='cyx-service-fifo-') as temporary, (output / 'qemu-stderr.log').open('wb') as error_log:
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
                qmp = SessionQmp(management)
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
            # Independently preserve completed component evidence even when the
            # 45s frame gate or a later component failed. An actual clean QEMU
            # exit, final raw boundaries and complete unchanged inputs are still
            # required; no component flag is promoted merely from a marker.
            if (inputs is not None and machine is not None and producer is not None
                    and result.get('returncode') == 0 and not result['forced']
                    and result.get('qmp_quit_acknowledged') is True):
                try:
                    require(validate_inputs(args) == inputs, 'Input/provenance changed during capture')
                    require(qemu_inputs(args) == machine and read_regular(__file__) == producer,
                            'QEMU, firmware, modules or capture producer changed')
                    for frame in result['frames']:
                        require(identity(output / frame['file'])['sha256'] == frame['sha256'], 'Captured framebuffer changed')
                    result['input_identity_verified'] = True
                    finalize_components(raw, result, inputs)
                    if result['first_frame_deadline_failed'] and result.get('late_compositor_frame_observed') is True:
                        result['late_observation_evidence_verified'] = True
                    if (checks_passed and 'error' not in result and result['service_lifecycle_verified']
                            and not result['first_frame_deadline_failed'] and 'compositor_scanout' in result):
                        result['status'] = SUCCESS
                except Exception as error:
                    result.setdefault('error', repr(error))
                    result['final_evidence_check_error'] = repr(error)
            result['evidence_files'] = {}
            for path in sorted(output.iterdir()):
                if path.is_file() and path.name != 'summary.json':
                    try:
                        result['evidence_files'][path.name] = identity(path, MAX_OUTPUT_BYTES)
                    except ValueError as error:
                        result['status'] = 'FAIL'
                        result['notification_protocol_verified'] = False
                        result['service_lifecycle_verified'] = False
                        for component in result['components'].values():
                            component['verified'] = False
                            if component['status'] == 'PASS':
                                component['status'] = 'OBSERVED_NOT_FINALIZED'
                        result['late_observation_evidence_verified'] = False
                        result.setdefault('error', 'Cannot finalize bounded evidence: ' + repr(error))
                        result['evidence_files'][path.name] = {'bytes': path.stat().st_size, 'hash_verified': False}
            if result['first_frame_deadline_failed']:
                result['status'] = 'FAIL'
                result['notification_protocol_verified'] = False
                result.setdefault('error', result['first_frame_deadline_failure']['error'])
            write_json(output / 'summary.json', result)
        return result



def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'output', 'dbus-build', 'compositor-build', 'notifications-build', 'probe-build',
                 'session-installation', 'settings-installation', 'settings-probe-build',
                 'qemu', 'qemu-data', 'bios', 'qemu-module-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cc', default='clang', help='Exact C compiler used by the formal OS build')
    parser.add_argument('--theme-origin', choices=THEME_ORIGINS, required=True,
                        help='Fixed complete asset consumer; Linux generation does not claim CyxiaOS guest execution')
    parser.add_argument('--native-lock', type=Path, default=NATIVE_LOCK)
    parser.add_argument('--trace-interrupts', action='store_true')
    parser.add_argument('--observe-after-frame-deadline', action='store_true',
                        help='Keep the original 45s failure and gather separate component/late scanout evidence within unchanged deadlines')
    args = parser.parse_args(argv)
    try:
        result = capture(args)
        print(json.dumps({key: result.get(key) for key in ('status', 'error', 'returncode', 'forced',
                         'elapsed_seconds', 'first_frame_deadline_failed', 'late_observation_evidence_verified',
                         'service_lifecycle_verified', 'normal_session_executed', 'full_cosmic_complete')}, indent=2))
        return 0 if result['status'] == SUCCESS else 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('cosmic-services-runtime-v1: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
