"""Pure Python acceptance boundaries for the real service-lifecycle producer.

No QEMU, compiler or target executable is run. Marker fixtures are synthetic;
kernel terminal spelling can also be checked against a deliberately selected,
full-SHA-bound retained capture via CYXIA_SERVICE_RUNTIME_V23_RAW_FIXTURE.
The integration model exercises the real driver/parser/resource functions, with
only guest transport and framebuffer acquisition replaced by explicit fixtures.
"""
import ast
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import os_cosmic_services_runtime_v4 as subject
from tools.test_os_cosmic_notifications_runtime import snapshot, process


V23_FIXTURE_ENV = 'CYXIA_SERVICE_RUNTIME_V23_RAW_FIXTURE'
V23_FIXTURE_BYTES = 2117248
V23_FIXTURE_SHA256 = '180c2800666a3db455bcc3a4135dd711eb019b8187c9cfa9c6edf1cc8f053669'


def retained_v23_fixture():
    selected = os.environ.get(V23_FIXTURE_ENV)
    if selected is None:
        return None
    subject.require(bool(selected) and Path(selected).is_absolute(),
                    'Explicit retained fixture must name an absolute regular file')
    raw = subject.read_regular(selected, 4 * 1024**2)
    subject.require(len(raw) == V23_FIXTURE_BYTES
                    and hashlib.sha256(raw).hexdigest() == V23_FIXTURE_SHA256,
                    'Explicit retained fixture must match the complete fixed v23 UART identity')
    return raw


def launch_bytes(pid, pages):
    return f'ELF pid={pid} started; ABI=Linux-x86_64-subset image AI_DIRECT model=8197 pages={pages}\r\n'.encode()


def exit_bytes(pid, *, state='Exited', code=0):
    return f'USER pid={pid} {state} code={code} free_pages=64 fault=0x0 far=0x0\r\n'.encode()


def version_trace(pid=1, pages=1512):
    return (b'posix exec cosmic-session-version\r\n' + launch_bytes(pid, pages)
            + b'cyxia:/> cosmic-session 1.10.0\r\n' + exit_bytes(pid))


def prepare_trace(pid=2, pages=570):
    return (b'posix exec settings-probe-prepare\r\n' + launch_bytes(pid, pages)
            + b'cyxia:/> SETTINGS_PROBE PREPARED\r\n' + exit_bytes(pid))


def protocol_rows(service=7, client=6, owner=':1.12'):
    return [b'SETTINGS_PROBE START service=com.system76.CosmicSettingsDaemon render_verified=false',
        f'SETTINGS_PROBE WAYLAND_READY path=/run/user/0/wayland-1 client_pid={client} protocol_verified=false'.encode(),
        f'SETTINGS_PROBE OWNER PASS unique={owner} service_pid={service} client_pid={client}'.encode(),
        (f'SETTINGS_PROBE CONFIG_CHANGED PASS watcher_unique=:1.13 '
         f'watcher_name=com.system76.CosmicSettingsDaemon.Config.org.cyxia.SettingsProbe.V1 '
         f'watcher_pid={service} service_pid={service} client_pid={client}').encode(),
        (f'SETTINGS_PROBE STATE_CHANGED PASS watcher_unique=:1.14 '
         f'watcher_name=com.system76.CosmicSettingsDaemon.State.org.cyxia.SettingsProbe.V1 '
         f'watcher_pid={service} service_pid={service} client_pid={client}').encode(),
        b'SETTINGS_PROBE THEME_LIGHT_DARK PASS', b'SETTINGS_PROBE UNSUPPORTED_CAPABILITIES PASS',
        f'SETTINGS_PROBE OWNER_STABLE PASS unique={owner} service_pid={service} client_pid={client}'.encode(),
        f'SETTINGS_PROBE PASS service_pid={service} client_pid={client} render_verified=false'.encode()]


def wire(rows):
    return b'\r\n'.join(rows) + b'\r\n'


class MarkerBoundaries(unittest.TestCase):
    def test_kernel_exit_spelling_is_backed_by_actual_v23_output(self):
        raw = retained_v23_fixture()
        if raw is None:
            self.skipTest('Select the optional full-SHA retained UART via ' + V23_FIXTURE_ENV)
        self.assertIn(b'USER pid=2 Exited code=0 free_pages=56 fault=0x0 far=0x0', raw)
        # Actual D-Bus output is deliberately NOT valid session-version proof.
        with self.assertRaises(ValueError):
            subject.session_version_evidence(raw, 2, 571)

    def test_version_requires_actual_image_grant_output_exit_and_order(self):
        proof = subject.session_version_evidence(version_trace(), 1, 1512)
        self.assertEqual(proof['argv'], ['/bin/cosmic-session', '--version'])
        self.assertIs(proof['normal_session_executed'], False)
        data = version_trace()
        mutations = [data.replace(b'1.10.0', b'1.9.0'), data.replace(b'cosmic-session 1.10.0', b'prefix cosmic-session 1.10.0'),
            data + b'cosmic-session 1.10.0\n', data.replace(b'pages=1512', b'pages=1513'),
            data.replace(b'ELF pid=1', b'ELF pid=2'), data.replace(b'Exited code=0', b'Exited code=1'),
            data.replace(b'Exited code=0', b'Fault code=139'), data.replace(b'USER pid=1', b'USER pid=2'),
            data.replace(b'USER pid=1', b'pid=1'), data + exit_bytes(1),
            launch_bytes(1, 1512) + exit_bytes(1) + b'cosmic-session 1.10.0\n']
        for changed in mutations:
            with self.subTest(changed=changed[-120:]), self.assertRaises(ValueError):
                subject.session_version_evidence(changed, 1, 1512)
        for pid, pages in [(True, 1512), (1, True), (0, 1512), (1, 0), (1.0, 1512)]:
            with self.subTest(pid=pid, pages=pages), self.assertRaises(ValueError):
                subject.session_version_evidence(data, pid, pages)

    def test_preparation_requires_its_own_launch_exit_and_single_marker(self):
        self.assertEqual(subject.preparation_evidence(prepare_trace(), 2, 570)['argv'],
                         ['/bin/settings-probe', 'prepare'])
        for changed in [b'SETTINGS_PROBE PREPARED\n', prepare_trace() + b'SETTINGS_PROBE PASS\n',
                        prepare_trace().replace(b'pages=570', b'pages=571'),
                        prepare_trace().replace(b'USER pid=2', b'USER pid=3'),
                        prepare_trace().replace(b'Exited code=0', b'Killed code=137'),
                        prepare_trace() + exit_bytes(2)]:
            with self.subTest(changed=changed[-100:]), self.assertRaises(ValueError):
                subject.preparation_evidence(changed, 2, 570)

    def test_readiness_owner_and_complete_have_distinct_exact_evidence(self):
        rows = protocol_rows()
        ready = subject.settings_protocol(wire(rows[:2]), None, 6, through='readiness')
        self.assertIs(ready['wayland_socket_connected'], True)
        self.assertIs(ready['wayland_protocol_verified'], False)
        self.assertIs(ready['complete'], False)
        for count in range(3, 10):
            proof = subject.settings_protocol(wire(rows[:count]), 7, 6, through='owner')
            self.assertEqual(proof['owner'], ':1.12')
            self.assertEqual(proof['complete'], count == 9)
        proof = subject.settings_protocol(wire(rows), 7, 6)
        self.assertIs(proof['complete'], True)
        self.assertIs(proof['render_verified'], False)
        self.assertIs(proof['normal_session_executed'], False)

    def test_wrong_actual_pids_socket_path_service_or_owner_never_pass(self):
        rows = protocol_rows()
        cases = []
        for index in (1, 2, 7, 8):
            changed = rows.copy(); changed[index] = changed[index].replace(b'client_pid=6', b'client_pid=9'); cases.append(changed)
        for index in (2, 7, 8):
            changed = rows.copy(); changed[index] = changed[index].replace(b'service_pid=7', b'service_pid=9'); cases.append(changed)
        for before, after, index in [(b'wayland-1', b'wayland-2', 1), (b'protocol_verified=false', b'protocol_verified=true', 1),
                                     (b':1.12', b':1.13', 7), (b'render_verified=false', b'render_verified=true', 8),
                                     (b'CosmicSettingsDaemon', b'FakeSettingsDaemon', 0)]:
            changed = rows.copy(); changed[index] = changed[index].replace(before, after); cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                subject.settings_protocol(wire(changed), 7, 6)
        for daemon, client in [(6, 6), (True, 6), (7, True), (0, 6), (7, 0)]:
            with self.subTest(daemon=daemon, client=client), self.assertRaises(ValueError):
                subject.settings_protocol(wire(rows), daemon, client)

    def test_missing_reordered_duplicated_unknown_or_premature_owner_rejected(self):
        rows = protocol_rows()
        cases = [rows[:count] for count in range(9)]
        cases += [rows + [rows[-1]], rows + [b'SETTINGS_PROBE FAIL hidden'],
                  rows[:3] + [b'SETTINGS_PROBE CONFIG_CHANGED SKIP'] + rows[4:]]
        for index in range(8):
            changed = rows.copy(); changed[index], changed[index + 1] = changed[index + 1], changed[index]; cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                subject.settings_protocol(wire(changed), 7, 6)
        with self.assertRaises(ValueError):
            subject.settings_protocol(wire(rows[:3]), None, 6, through='readiness')

    def test_fresh_bounded_windows_cannot_fall_back_to_stale_markers(self):
        raw = wire(protocol_rows()) + b'NEW COMMAND WITH NO REPLY\n'
        start = len(wire(protocol_rows()))
        with self.assertRaises(ValueError):
            subject.settings_protocol(subject.bounded_window(raw, start, len(raw)), 7, 6)
        for start, end in [(-1, len(raw)), (0, len(raw) + 1), (0, 0), (True, 2), (0, False), (2, 1)]:
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                subject.bounded_window(raw, start, end)


    def test_each_watcher_unique_may_differ_from_main_but_binds_exact_daemon_pid(self):
        proof = subject.settings_protocol(wire(protocol_rows()), 7, 6)
        self.assertEqual(proof['owner'], ':1.12')
        self.assertEqual(proof['watchers'], {
            'config': {'name': 'com.system76.CosmicSettingsDaemon.Config.org.cyxia.SettingsProbe.V1',
                       'unique': ':1.13', 'pid': 7},
            'state': {'name': 'com.system76.CosmicSettingsDaemon.State.org.cyxia.SettingsProbe.V1',
                      'unique': ':1.14', 'pid': 7},
        })
        for count, expected in ((2, []), (3, []), (4, ['config']), (5, ['config', 'state'])):
            mode = 'readiness' if count == 2 else 'owner'
            proof = subject.settings_protocol(wire(protocol_rows()[:count]), None if count == 2 else 7,
                                              6, through=mode)
            self.assertEqual(list(proof['watchers']), expected)

    def test_previous_bare_changed_markers_cannot_claim_v2_owner_proof(self):
        for index, label in ((3, 'CONFIG'), (4, 'STATE')):
            rows = protocol_rows(); rows[index] = f'SETTINGS_PROBE {label}_CHANGED PASS'.encode()
            with self.subTest(index=index), self.assertRaises(ValueError):
                subject.settings_protocol(wire(rows), 7, 6)

    def test_watch_pid_cannot_be_client_foreign_zero_or_noncanonical(self):
        for index in (3, 4):
            for value in (b'6', b'8', b'0', b'-7', b'07', b'7.0', b'True'):
                rows = protocol_rows(); rows[index] = rows[index].replace(b'watcher_pid=7', b'watcher_pid=' + value)
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    subject.settings_protocol(wire(rows), 7, 6)

    def test_watch_name_scope_version_identity_and_unique_are_closed(self):
        for index in (3, 4):
            original = protocol_rows()[index]
            substitutions = [(b'org.cyxia.SettingsProbe', b'org.other.Probe'), (b'.V1 ', b'.V2 '),
                             (b'watcher_unique=:1.', b'watcher_unique=1.'),
                             (b'watcher_unique=:1.', b'watcher_unique=:'),
                             (b'client_pid=6', b'client_pid=7'), (b'service_pid=7', b'service_pid=6')]
            # The empty or colon-only owner is invalid, while a different valid
            # unique is allowed because the real client authenticates its PID.
            for before, after in substitutions:
                rows = protocol_rows(); rows[index] = original.replace(before, after)
                if before == b'watcher_unique=:1.':
                    if after == b'watcher_unique=:':
                        rows[index] = re.sub(rb'watcher_unique=[^ ]+', b'watcher_unique=:', rows[index])
                with self.subTest(index=index, after=after), self.assertRaises(ValueError):
                    subject.settings_protocol(wire(rows), 7, 6)
            rows = protocol_rows(); rows[index] = original.replace(b'.Config.', b'.State.') if index == 3 else original.replace(b'.State.', b'.Config.')
            with self.assertRaises(ValueError):
                subject.settings_protocol(wire(rows), 7, 6)

    def test_watch_fields_cannot_be_missing_duplicate_reordered_or_trailing(self):
        for index in (3, 4):
            original = protocol_rows()[index]
            words = original.split(b' ')
            mutations = [b' '.join(words[:3] + words[4:]), original + b' watcher_pid=7',
                         original + b' trailing', original.replace(b'watcher_pid=7 service_pid=7',
                                                                   b'service_pid=7 watcher_pid=7')]
            for changed in mutations:
                rows = protocol_rows(); rows[index] = changed
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    subject.settings_protocol(wire(rows), 7, 6)

    def test_owner_success_followed_by_noreply_remains_failed_protocol(self):
        partial = protocol_rows()[:3]
        self.assertIs(subject.settings_protocol(wire(partial), 7, 6, through='owner')['complete'], False)
        errors = [b'SETTINGS_PROBE ERROR org.freedesktop.DBus.Error.NoReply No reply received',
                  b'SETTINGS_PROBE ERROR member=WatchConfig destination=:1.12 request_serial=9 '
                  b'elapsed_ms=10000 timeout_ms=10000 errno=11 '
                  b'name=org.freedesktop.DBus.Error.NoReply message=No reply received']
        for error in errors:
            for mode in ('owner', 'complete'):
                with self.subTest(error=error, mode=mode), self.assertRaises(ValueError):
                    subject.settings_protocol(wire(partial + [error]), 7, 6, through=mode)


class Clock:
    now = 0.0
    def monotonic(self): return self.now
    def sleep(self, amount): self.now += amount


class FrameBoundaries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.clock = Clock()
        self.timer = patch.object(subject.time, 'monotonic', side_effect=self.clock.monotonic)
        self.timer.start(); self.addCleanup(self.timer.stop)
        self.console = SimpleNamespace(deadline=240., raw=bytearray(), sock=SimpleNamespace(deadline=240.),
                                       frame_observer=None, pump=lambda **kwargs: None)
        self.qmp = SimpleNamespace(sock=SimpleNamespace(deadline=248.), observation_deadline=None)
        self.result = {'frames': [], 'first_frame_deadline_failed': False, 'observe_after_frame_deadline': True}
        self.initial = subject.base.system_snapshot(snapshot())
        self.observer = subject.FrameObserver(self.console, self.qmp, self.output, self.initial, 5, self.result)

    def capture(self, *, finish_at=None, owner=5, completed=1, boot=False):
        def frame(*args, **kwargs):
            if finish_at is not None: self.clock.now = finish_at
            entry = {'file': 'compositor.ppm', 'boot_colorbars': boot, 'changed_pixels': 10}
            self.result['frames'].append(entry)
            return entry
        with patch.object(subject, 'active_processes', return_value={}), \
                patch.object(subject, 'system', return_value=subject.base.system_snapshot(snapshot(completed, owner))), \
                patch.object(subject, 'snapshot_frame', side_effect=frame):
            self.observer.checkpoint({3, 5}, {3, 5})

    def test_45_seconds_failure_is_latched_once_and_cannot_reset(self):
        self.clock.now = 44.999; self.observer.tick()
        self.assertFalse(self.result['first_frame_deadline_failed'])
        self.clock.now = 45.; self.observer.tick()
        path = self.output / 'first-frame-deadline-failure.json'; raw = path.read_bytes()
        self.clock.now = 60.; self.observer.tick()
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(self.observer.started, 0.)
        self.assertEqual(self.observer.deadline, 120.)
        self.assertEqual(self.result['first_frame_deadline_failure']['elapsed_seconds'], 45.)

    def test_opt_out_keeps_original_fail_fast_45_gate(self):
        self.result['observe_after_frame_deadline'] = False
        self.clock.now = 45.
        with self.assertRaisesRegex(ValueError, 'original first-frame gate'):
            self.observer.tick()
        self.assertTrue(self.result['first_frame_deadline_failed'])

    def test_real_owned_completion_and_nonboot_pixels_before_45_accept_only_frame_candidate(self):
        self.clock.now = 44.9; self.capture(finish_at=44.99)
        self.assertTrue(self.observer.observed)
        self.assertFalse(self.result['first_frame_deadline_failed'])
        self.assertFalse(self.result['compositor_scanout']['semantic_ui_verified'])

    def test_capture_crossing_45_is_late_and_never_erases_first_failure(self):
        self.clock.now = 44.9; self.capture(finish_at=45.)
        self.assertTrue(self.observer.observed)
        self.assertTrue(self.result['first_frame_deadline_failed'])
        self.assertTrue(self.result['late_compositor_frame_observed'])
        self.assertTrue(self.result['compositor_scanout']['after_first_frame_deadline'])

    def test_wrong_owner_or_no_completion_cannot_accept_nonboot_frame(self):
        self.clock.now = 20.
        self.capture(owner=6)
        self.assertFalse(self.observer.observed)
        self.assertEqual(self.result['frames'], [])
        self.capture(completed=0)
        self.assertFalse(self.observer.observed)

    def test_boot_frame_cannot_be_promoted_by_a_completed_transfer(self):
        self.clock.now = 20.
        with self.assertRaisesRegex(ValueError, 'non-boot'):
            self.capture(boot=True)
        self.assertFalse(self.observer.observed)

    def test_capture_at_120_fails_without_late_success(self):
        self.clock.now = 119.9
        with self.assertRaisesRegex(ValueError, 'Late frame'):
            self.capture(finish_at=120.)
        self.assertTrue(self.result['first_frame_deadline_failed'])
        self.assertFalse(self.observer.observed)
        self.assertTrue(self.observer.closed)

    def test_no_qmp_or_uart_request_after_late_frame_cutoff(self):
        self.clock.now = 120.
        with patch.object(subject, 'system') as system, patch.object(subject, 'active_processes') as active:
            self.observer.checkpoint({3, 5}, {3, 5})
        system.assert_not_called(); active.assert_not_called()
        self.assertTrue(self.observer.closed)
        self.assertFalse(self.result['late_compositor_frame_observed'])

    def test_display_failure_is_fatal_and_cannot_be_treated_as_not_yet_ready(self):
        observed = subject.base.system_snapshot(snapshot(1, 5))
        observed['display']['failed'] = 1
        with patch.object(subject, 'active_processes', return_value={}), \
                patch.object(subject, 'system', return_value=observed), \
                self.assertRaisesRegex(ValueError, 'display mechanism failed'):
            self.observer.checkpoint({3, 5}, {3, 5})
        self.assertFalse(self.observer.observed)

    def test_stage_wait_clips_and_restores_transport_deadlines_and_never_extends_30(self):
        seen = []
        def checkpoint(allowed, required):
            seen.append((self.console.deadline, self.console.sock.deadline,
                         self.qmp.sock.deadline, self.qmp.observation_deadline))
            self.console.raw.extend(b'REAL_STAGE_DONE\n')
        observer = SimpleNamespace(qmp=self.qmp, checkpoint=checkpoint)
        with patch.object(subject.time, 'sleep', side_effect=self.clock.sleep):
            subject.wait_observed(self.console, observer, b'^REAL_STAGE_DONE$', 0, set(), set())
        self.assertEqual(seen, [(30., 30., 30., 30.)])
        self.assertEqual((self.console.deadline, self.console.sock.deadline, self.qmp.sock.deadline), (240., 240., 248.))
        self.assertIsNone(self.qmp.observation_deadline)
        for timeout in (0, -1, 31, 40, True, float('nan')):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                subject.wait_observed(self.console, observer, b'.', 0, set(), set(), timeout=timeout)

    def test_late_marker_cannot_be_accepted_after_stage_deadline(self):
        def pump(**kwargs):
            self.clock.now = 30.001; self.console.raw.extend(b'DONE\n')
        self.console.pump = pump
        observer = SimpleNamespace(qmp=self.qmp, checkpoint=lambda *args: None)
        with self.assertRaisesRegex(ValueError, 'fixed operation deadline'):
            subject.wait_observed(self.console, observer, b'^DONE$', 0, set(), set())
        self.assertEqual(self.console.deadline, 240.)


class GuestFixture:
    """Explicit scenario state; no target byte is executed and no service is emulated outside this test."""
    def __init__(self, output, *, error=None, delay=0.):
        self.output, self.error, self.delay, self.clock = output, error, delay, Clock()
        self.raw, self.commands, self.rows, self.names = bytearray(b'cyxia:/> '), [], {}, {}
        self.deadline = 240.; self.sock = SimpleNamespace(deadline=240.)
        self.frame_observer = None
        self.inspections = {name: {'required_pages': pages} for name, pages in {
            'cosmic-session': 1512, 'settings-probe': 570, 'dbus-daemon': 629,
            'dbus-send': 571, 'cosmic-comp': 8839, 'cosmic-settings-daemon': 1883}.items()}
        self.events = []

    def pump(self, **kwargs):
        if self.frame_observer is not None: self.frame_observer.tick()

    def until(self, pattern, start=0, timeout=30):
        self.pump()
        found = re.search(pattern, bytes(self.raw[start:]), re.MULTILINE)
        if found is None: raise TimeoutError('fixture has no requested guest evidence: ' + repr(pattern))
        return found

    def program(self, command, marker=None, state='Exited', code=0):
        return subject.base.os_smoke.Console.program(self, command, marker, state, code)

    def row(self, pid, state='Running', code=0):
        value = process(state, code); value['pid'] = pid
        if state in ('Running', 'Waiting'):
            value.update(heap_pages=1, image_pages=1, thread_count=1, image_free=16383)
        return value

    def terminal(self, pid, state='Exited', code=0):
        self.rows[pid] = self.row(pid, state, code)
        self.raw.extend(exit_bytes(pid, state=state, code=code))

    def current_rows(self, console=None):
        free = 64 - 8 * sum(row['state'] in ('Running', 'Waiting') for row in self.rows.values())
        result = copy.deepcopy(self.rows)
        for row in result.values(): row['free_pages'] = free
        if result: subject.global_arena(result)
        return result

    def command(self, command, expected=()):
        self.clock.now += 0. if self.error == 'no-frame' else .01
        start = len(self.raw); self.commands.append({'command': command, 'serial_offset': start})
        self.raw.extend(command.encode() + b'\r\n')
        self.events.append(command)
        if command.startswith('posix exec '):
            name = command.removeprefix('posix exec ')
            if name == 'cosmic-settings-daemon':
                assert b'SETTINGS_PROBE WAYLAND_READY ' in self.raw, 'Daemon cannot precede actual readiness evidence'
            pid = len(self.rows) + 1; self.names[name] = pid; self.rows[pid] = self.row(pid)
            image = {'cosmic-session-version': 'cosmic-session', 'settings-probe-prepare': 'settings-probe'}.get(name, name)
            self.raw.extend(launch_bytes(pid, self.inspections[image]['required_pages']))
            if name == 'cosmic-session-version':
                self.raw.extend(b'cosmic-session ' + (b'0.0.0' if self.error == 'version' else b'1.10.0') + b'\n')
                self.terminal(pid)
            elif name == 'settings-probe-prepare':
                self.raw.extend(b'SETTINGS_PROBE PREPARED\n'); self.terminal(pid)
            elif name == 'dbus-daemon': self.raw.extend(b'unix:path=/run/user/0/bus\n')
            elif name == 'dbus-send':
                self.raw.extend(b'method return\n   array [\n      string "org.freedesktop.DBus"\n   ]\n'); self.terminal(pid)
            elif name == 'settings-probe':
                self.raw.extend(wire(protocol_rows(client=pid)[:2])); self.clock.now += self.delay
            elif name == 'cosmic-settings-daemon':
                client = self.names['settings-probe']
                self.raw.extend(wire(protocol_rows(service=99 if self.error == 'owner' else pid, client=client)[2:]))
                self.terminal(client, code=1 if self.error == 'client-exit' else 0)
                if self.error == 'foreign-process': self.rows[8] = self.row(8)
        elif command == 'ai system':
            compositor = self.names.get('cosmic-comp', 0)
            raw = snapshot(completed=1 if compositor and self.error != 'no-frame' else 0, owner=compositor)
            active = any(row['state'] in ('Running', 'Waiting') for row in self.rows.values())
            if self.error == 'leak' and compositor and not active:
                raw = raw.replace(b'OFD_OBJECTS live=0 references=0', b'OFD_OBJECTS live=1 references=1')
            self.raw.extend(raw)
        elif command.startswith('posix kill '):
            pid = int(command.rsplit(' ', 1)[1])
            assert pid in [self.names.get(name) for name in ('cosmic-settings-daemon', 'cosmic-comp', 'dbus-daemon')]
            self.rows[pid] = self.row(pid, 'Killed', 137)
            self.raw.extend(f'USER pid={pid} killed; pages reclaimed\r\n'.encode())
        else:
            raise AssertionError('Unexpected command in the explicit integration fixture: ' + command)
        self.raw.extend(b'cyxia:/> ')
        for pattern in expected: self.until(pattern, start)
        return start

    def qmp(self):
        def execute(command, args=None):
            if command == 'query-cpus-fast': return [{'cpu-index': index} for index in range(4)]
            if command == 'human-monitor-command': return '\n'.join(['CR0=20 EFER=0'] * 4)
            raise AssertionError('Unspecified QMP fixture command: ' + command)
        return SimpleNamespace(execute=execute, sock=SimpleNamespace(deadline=248.), observation_deadline=None)

    def frame(self, console, qmp, output, frames, name, baseline=None):
        frame = {'file': name + '.ppm', 'boot_colorbars': name == 'boot',
                 'changed_pixels': None if name == 'boot' else 100, 'semantic_ui_verified': False}
        frames.append(frame)
        return frame


class DriverBoundaries(unittest.TestCase):
    def run_fixture(self, *, error=None, delay=0., observe=True):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)
        guest = GuestFixture(output, error=error, delay=delay)
        result = {'status': 'FAIL', 'frames': [], 'launched': {}, 'bus_queries': [], 'processes_reclaimed': {},
                  'first_frame_deadline_failed': False, 'observe_after_frame_deadline': observe,
                  'service_lifecycle_verified': False, 'normal_session_executed': False, 'full_cosmic_complete': False,
                  'components': {'session_version': {'status': 'NOT_RUN', 'verified': False},
                                 'settings': {'status': 'NOT_RUN', 'verified': False}}}
        inputs = {'inspections': guest.inspections}
        with patch.object(subject.time, 'monotonic', side_effect=guest.clock.monotonic), \
                patch.object(subject.time, 'sleep', side_effect=guest.clock.sleep), \
                patch.object(subject, 'processes', side_effect=guest.current_rows), \
                patch.object(subject.base, 'processes', side_effect=guest.current_rows), \
                patch.object(subject, 'snapshot_frame', side_effect=guest.frame):
            try:
                subject.run_session(guest, guest.qmp(), output, inputs, result)
            except Exception as caught:
                result['error'] = repr(caught)
        return guest, result, inputs

    def test_real_driver_preserves_version_prepare_readiness_owner_cleanup_order(self):
        guest, result, inputs = self.run_fixture()
        self.assertNotIn('error', result)
        launches = [command for command in guest.events if command.startswith('posix exec')]
        self.assertEqual(launches, ['posix exec cosmic-session-version', 'posix exec settings-probe-prepare',
            'posix exec dbus-daemon', 'posix exec dbus-send', 'posix exec cosmic-comp',
            'posix exec settings-probe', 'posix exec cosmic-settings-daemon'])
        self.assertEqual([command for command in guest.events if command.startswith('posix kill')],
                         ['posix kill 7', 'posix kill 5', 'posix kill 3'])
        self.assertTrue(result['resource_cleanup_observed'])
        self.assertEqual(result['process_arena_after']['free_pages'], 64)
        subject.finalize_components(bytes(guest.raw), result, inputs)
        self.assertTrue(result['service_lifecycle_verified'])
        self.assertEqual(result['components']['session_version']['status'], 'PASS')
        self.assertEqual(result['components']['settings']['status'], 'PASS')
        self.assertFalse(result['normal_session_executed'])
        self.assertFalse(result['full_cosmic_complete'])

    def test_bad_version_stops_before_bus_or_service_launch_and_is_not_promoted(self):
        guest, result, inputs = self.run_fixture(error='version')
        self.assertIn('error', result)
        self.assertEqual(set(guest.names), {'cosmic-session-version'})
        subject.finalize_components(bytes(guest.raw), result, inputs)
        self.assertFalse(result['components']['session_version']['verified'])
        self.assertFalse(result['service_lifecycle_verified'])

    def test_wrong_real_owner_or_client_exit_never_mark_settings_verified(self):
        for error in ('owner', 'client-exit', 'foreign-process'):
            guest, result, inputs = self.run_fixture(error=error)
            with self.subTest(error=error):
                self.assertIn('error', result)
                subject.finalize_components(bytes(guest.raw), result, inputs)
                self.assertTrue(result['components']['session_version']['verified'])
                self.assertFalse(result['components']['settings']['verified'])

    def test_complete_wire_markers_without_global_reclamation_cannot_pass(self):
        guest, result, inputs = self.run_fixture(error='leak')
        self.assertIn('Global resource did not return', result['error'])
        with self.assertRaisesRegex(ValueError, 'complete service/global reclamation'):
            subject.finalize_components(bytes(guest.raw), result, inputs)
        self.assertFalse(result['components']['settings']['verified'])

    def test_frame_45_failure_coexists_with_verified_components_and_late_scanout(self):
        guest, result, inputs = self.run_fixture(delay=46.)
        self.assertNotIn('error', result)
        subject.finalize_components(bytes(guest.raw), result, inputs)
        self.assertTrue(result['service_lifecycle_verified'])
        self.assertTrue(result['first_frame_deadline_failed'])
        self.assertTrue(result['late_compositor_frame_observed'])
        self.assertEqual(result['status'], 'FAIL')

    def test_missing_late_frame_does_not_relabel_component_run_as_normal_session(self):
        guest, result, inputs = self.run_fixture(error='no-frame')
        self.assertNotIn('error', result)
        subject.finalize_components(bytes(guest.raw), result, inputs)
        self.assertTrue(result['service_lifecycle_verified'])
        self.assertTrue(result['first_frame_deadline_failed'])
        self.assertFalse(result['late_compositor_frame_observed'])
        self.assertNotIn('compositor_scanout', result)
        self.assertFalse(result['normal_session_executed'])
        self.assertEqual(result['status'], 'FAIL')

    def test_final_drain_rejects_changed_version_protocol_process_or_window(self):
        for error in ('version', 'owner', 'heap', 'arena', 'offset', 'late-marker', 'client-pid', 'preparation'):
            guest, result, inputs = self.run_fixture()
            raw = bytes(guest.raw)
            if error == 'version': raw = raw.replace(b'cosmic-session 1.10.0', b'cosmic-session 1.9.00')
            elif error == 'owner': raw = raw.replace(b'unique=:1.12', b'unique=:1.13')
            elif error == 'heap': result['components']['settings']['client_reclaimed']['heap_pages'] = 1
            elif error == 'arena': result['process_arena_after']['free_pages'] = 56
            elif error == 'late-marker': raw += b'\nSETTINGS_PROBE PASS service_pid=7 client_pid=6 render_verified=false\n'
            elif error == 'client-pid': result['components']['settings']['client_reclaimed']['pid'] = 99
            elif error == 'preparation': result['preparation']['resources_after']['ofd']['live'] = 1
            else: result['components']['session_version']['serial_start'] = -1
            with self.subTest(error=error), self.assertRaises(ValueError):
                subject.finalize_components(raw, result, inputs)
            self.assertFalse(result['service_lifecycle_verified'])


class PreservationBoundaries(unittest.TestCase):
    def test_original_transport_frame_and_resource_budgets_are_exact(self):
        self.assertEqual((subject.MAX_WALL_SECONDS, subject.MAX_OUTPUT_BYTES, subject.MAX_FRAMES,
                          subject.MAX_DIAGNOSTIC_LOG_BYTES, subject.FIRST_FRAME_SECONDS, subject.LATE_FRAME_SECONDS),
                         (240, 96 * 1024**2, 24, 24 * 1024**2, 45, 120))
        self.assertIs(subject.Console.command, subject.base.Console.command)
        self.assertIs(subject.Console.until, subject.base.Console.until)
        self.assertIs(subject.PipeChannel, subject.base.PipeChannel)
        self.assertIs(subject.SessionQmp, subject.base.SessionQmp)
        self.assertIs(subject.process_reclaimed, subject.base.process_reclaimed)
        self.assertIs(subject.reclaimed, subject.base.reclaimed)
        self.assertIs(subject.global_arena, subject.base.global_arena)
        self.assertEqual(len(subject.IMAGE_NAMES), 9)
        self.assertEqual(len(subject.base.IMAGE_NAMES), 6)

    def test_actual_qemu_launch_watchdog_and_shutdown_statements_remain_identical(self):
        before = ast.parse(Path(subject.base.__file__).read_bytes())
        after = ast.parse(Path(subject.__file__).read_bytes())
        def nested(tree, name):
            found = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name]
            self.assertEqual(len(found), 1)
            return ast.dump(found[0], include_attributes=False)
        self.assertEqual(nested(before, 'diagnostic_limits'), nested(after, 'diagnostic_limits'))
        self.assertEqual(nested(before, 'expire'), nested(after, 'expire'))
        def calls(tree, selected):
            return [ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and ast.unparse(node.func) == selected]
        for selected in ('subprocess.Popen', 'threading.Timer', 'process.wait', 'watchdog.join'):
            with self.subTest(call=selected):
                self.assertEqual(calls(before, selected), calls(after, selected))


class InstallationBindings(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        original, prefix = root / 'installation', root / 'catalog'
        original.mkdir(); prefix.mkdir()
        receipt = 'component-origin.json'
        files = {}
        for name, raw, mode in [('component.elf', b'HOST STRUCTURAL IMAGE BYTES', 0o755),
                                ('rootfs/usr/share/doc/component/LICENSE', b'HOST LICENSE BYTES', 0o644)]:
            for directory in (original, prefix):
                path = directory / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw); path.chmod(mode)
            files[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode}
        for directory in (original, prefix):
            (directory / receipt).write_bytes(b'{"fixture": "preserved independent source proof"}\n')
        proof = {'status': 'SESSION_INSTALLATION_REVALIDATED_NOT_RUN', 'files': files,
                 'guest_execution': False, 'cosmic_session_ready': False, 'full_cosmic_complete': False}
        validator = SimpleNamespace(RECEIPT=receipt, validate_inputs=lambda selected: copy.deepcopy(proof))
        return original, prefix, files, proof, validator

    def test_curated_copy_must_match_original_strict_installation_and_receipt(self):
        original, prefix, files, proof, validator = self.fixture()
        self.assertEqual(subject.installation_binding(prefix, original, validator, expected_files=files), proof)

    def test_wrong_status_missing_or_extra_file_closure_cannot_pass(self):
        for mutation in ('status', 'missing', 'extra'):
            original, prefix, files, proof, validator = self.fixture()
            expected = tuple(files)
            if mutation == 'status': proof['status'] = 'PASS'
            elif mutation == 'missing': proof['files'].pop(next(iter(files)))
            else: proof['files']['extra.elf'] = next(iter(files.values()))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                subject.installation_binding(prefix, original, validator, expected_files=expected)

    def test_changed_receipt_bytes_license_executable_mode_or_symlink_rejected(self):
        for mutation in ('receipt', 'license', 'image', 'mode', 'symlink'):
            original, prefix, files, proof, validator = self.fixture()
            image = prefix / 'component.elf'
            if mutation == 'receipt': (prefix / validator.RECEIPT).write_bytes(b'{}')
            elif mutation == 'license': (prefix / 'rootfs/usr/share/doc/component/LICENSE').write_bytes(b'changed')
            elif mutation == 'image': image.write_bytes(b'changed')
            elif mutation == 'mode': image.chmod(0o644)
            else: image.unlink(); image.symlink_to(original / 'component.elf')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                subject.installation_binding(prefix, original, validator, expected_files=files)


class ThemeConsumerBindings(unittest.TestCase):
    def fixture(self, origin='linux-host-v1'):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        prefix = Path(temporary.name).resolve()
        rows = []
        for name in subject.base.install_cosmic_theme_defaults.expected_paths():
            data = ('HOST STRUCTURAL THEME FIXTURE ' + name + '\n').encode()
            path = prefix / 'rootfs' / name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); path.chmod(0o644)
            rows.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mode': 0o644})
        bounds = {'asset_files': 79, 'asset_bytes': sum(row['bytes'] for row in rows)}
        if origin in ('linux-host-v1', 'linux-host-v2'):
            generation = {'linux-host-v1': 'v1', 'linux-host-v2': 'v2'}[origin]
            receipt = 'cosmic-theme-linux-' + generation + '-assets.json'
            proof = {'kind': 'cosmic-theme-linux-' + generation + '-assets', 'status': 'THEME_HOST_ASSETS_REVALIDATED_NOT_GUEST_RUN',
                     'host_generation': True, 'guest_execution': False, 'assets': rows, 'bounds': bounds}
        else:
            receipt = 'cosmic-theme-assets.json'
            proof = {'status': 'PASS', 'full_os_verified': False, 'cosmic_session_verified': False,
                     'assets': [{key: row[key] for key in ('path', 'bytes', 'sha256')} for row in rows], 'bounds': bounds}
        (prefix / receipt).write_text('{"fixture_only": true}\n')
        calls = []
        def validate(path):
            calls.append(path)
            return copy.deepcopy(proof)
        return prefix, proof, validate, calls

    def test_linux_generation_uses_only_fixed_new_consumer_and_never_claims_guest(self):
        prefix, proof, validate, calls = self.fixture()
        module = SimpleNamespace(validate_inputs=validate)
        with patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': module}), \
                patch.object(subject.base.install_cosmic_theme_defaults, 'validate_inputs',
                             side_effect=AssertionError('Old generation consumer must not be called')):
            result = subject.theme_inputs(prefix, 'linux-host-v1')
        self.assertEqual(calls, [prefix])
        self.assertEqual(result['proof'], proof)
        self.assertIs(result['current_settings_guest_verified'], False)
        self.assertIn('Linux host generation', result['generation_environment'])
        self.assertEqual(len(result['assets']), 79)

    def test_legacy_generation_uses_unchanged_legacy_consumer_with_exact_inventory(self):
        prefix, proof, validate, calls = self.fixture('legacy-guest-v1')
        with patch.object(subject.base.install_cosmic_theme_defaults, 'validate_inputs', side_effect=validate):
            result = subject.theme_inputs(prefix, 'legacy-guest-v1')
        self.assertEqual(calls, [prefix])
        self.assertEqual(result['proof'], proof)
        self.assertIs(result['current_settings_guest_verified'], False)

    def test_arbitrary_consumer_names_and_old_guest_receipt_impersonation_rejected(self):
        prefix, proof, validate, calls = self.fixture()
        module = SimpleNamespace(validate_inputs=validate)
        for origin in ('', 'anything.py', '../legacy-guest-v1', None, True):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                subject.theme_inputs(prefix, origin)
        (prefix / 'cosmic-theme-assets.json').write_text('{"fake_old_status": "PASS"}')
        with patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': module}), self.assertRaises(ValueError):
            subject.theme_inputs(prefix, 'linux-host-v1')
        self.assertEqual(calls, [])

    def test_host_generation_or_guest_claim_identity_drift_rejected(self):
        for key, value in [('kind', 'cosmic-theme-assets'), ('status', 'PASS'), ('host_generation', 1),
                           ('host_generation', False), ('guest_execution', 0), ('guest_execution', True)]:
            prefix, proof, validate, calls = self.fixture(); proof[key] = value
            with self.subTest(key=key, value=value), \
                    patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': SimpleNamespace(validate_inputs=validate)}), \
                    self.assertRaises(ValueError):
                subject.theme_inputs(prefix, 'linux-host-v1')

    def test_missing_genuine_generation_evidence_never_falls_back_to_committed_bytes(self):
        prefix, proof, validate, calls = self.fixture()
        def reject(path): raise ValueError('Missing original source/build/two-mode generation evidence')
        with patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': SimpleNamespace(validate_inputs=reject)}), \
                patch.object(subject.base.install_cosmic_theme_defaults, 'validate_inputs') as legacy, \
                self.assertRaisesRegex(ValueError, 'Missing original'):
            subject.theme_inputs(prefix, 'linux-host-v1')
        legacy.assert_not_called()

    def test_complete_39_plus_39_plus_license_identity_mode_and_bytes_are_required(self):
        for mutation in ('missing', 'duplicate', 'wrong-path', 'mode-type', 'bytes-type', 'total', 'file', 'file-mode'):
            prefix, proof, validate, calls = self.fixture()
            if mutation == 'missing': proof['assets'].pop()
            elif mutation == 'duplicate': proof['assets'][-1] = proof['assets'][0]
            elif mutation == 'wrong-path': proof['assets'][0]['path'] = '/usr/share/cosmic/unreviewed/v2/key'
            elif mutation == 'mode-type': proof['assets'][0]['mode'] = 420.0
            elif mutation == 'bytes-type': proof['assets'][0]['bytes'] = float(proof['assets'][0]['bytes'])
            elif mutation == 'total': proof['bounds']['asset_bytes'] += 1
            elif mutation == 'file': (prefix / 'rootfs' / proof['assets'][0]['path'].lstrip('/')).write_bytes(b'changed')
            else: (prefix / 'rootfs' / proof['assets'][0]['path'].lstrip('/')).chmod(0o600)
            with self.subTest(mutation=mutation), \
                    patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': SimpleNamespace(validate_inputs=validate)}), \
                    self.assertRaises(ValueError):
                subject.theme_inputs(prefix, 'linux-host-v1')


class PortableEvidenceBoundaries(unittest.TestCase):
    def test_unselected_retained_fixture_skips_without_reading_private_artifacts(self):
        environment = {key: value for key, value in os.environ.items() if key != V23_FIXTURE_ENV}
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(subject, 'read_regular', side_effect=AssertionError('No implicit artifact read')):
            self.assertIsNone(retained_v23_fixture())

    def test_explicit_missing_relative_empty_symlink_or_changed_fixture_fails(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        changed = root / 'changed.raw'
        changed.write_bytes(b'USER pid=2 Exited code=0 free_pages=56 fault=0x0 far=0x0\n')
        same_size = root / 'same-size.raw'; same_size.write_bytes(b'X' * V23_FIXTURE_BYTES)
        linked = root / 'linked.raw'; linked.symlink_to(changed)
        for selected in ('', 'relative.raw', str(root / 'missing.raw'), str(changed), str(same_size), str(linked)):
            with self.subTest(selected=selected), patch.dict(os.environ, {V23_FIXTURE_ENV: selected}), \
                    self.assertRaises(ValueError):
                retained_v23_fixture()


class ThemeOutputProtection(unittest.TestCase):
    def linux_fixture(self, origin='linux-host-v1'):
        prefix, proof, validate, calls = ThemeConsumerBindings.fixture(self, origin)
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        outer = Path(temporary.name).resolve()
        generation = outer / 'theme-generation'; generation.mkdir()
        native, cache = generation / 'native', outer / 'rlib-cache'
        native.mkdir(); cache.mkdir()
        for directory in (generation, native, cache):
            (directory / 'preserved-input').write_bytes(b'Preserved generation input bytes\n')
        proof['protected_paths'] = [str(generation), str(native), str(cache)]
        return outer, prefix, proof, validate, calls, generation

    @staticmethod
    def tree_state(root):
        return {str(path.relative_to(root)): (path.stat().st_mode & 0o7777,
                path.read_bytes() if path.is_file() else None)
                for path in sorted(root.rglob('*'))}

    def test_verified_linux_roots_protect_children_without_creating_output(self):
        outer, prefix, proof, validate, calls, generation = self.linux_fixture()
        module = SimpleNamespace(validate_inputs=validate)
        before = self.tree_state(outer)
        with patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': module}):
            for protected in proof['protected_paths']:
                with self.subTest(protected=protected), self.assertRaisesRegex(ValueError, 'overlaps a read-only input'):
                    subject.protect_theme_output(Path(protected) / 'new-capture', prefix, 'linux-host-v1')
            output = outer / 'safe-capture'
            selected, theme, protected = subject.protect_theme_output(output, prefix, 'linux-host-v1')
        self.assertEqual(selected, output)
        self.assertEqual(theme['proof'], proof)
        self.assertEqual(protected, [prefix, *(Path(value) for value in proof['protected_paths'])])
        self.assertEqual(calls, [prefix] * 4)
        self.assertFalse(output.exists())
        self.assertEqual(self.tree_state(outer), before)

    def test_linux_protection_requires_real_canonical_absolute_directories(self):
        outer, prefix, proof, validate, calls, generation = self.linux_fixture()
        linked = outer / 'link'; linked.symlink_to(generation, target_is_directory=True)
        file_path = generation / 'preserved-input'
        cases = (None, [], (), [True], ['relative/root'], [str(generation) + '/'],
                 [str(generation) + '/../theme-generation'], [str(outer / 'missing')],
                 [str(file_path)], [str(linked)])
        for paths in cases:
            proof['protected_paths'] = paths
            with self.subTest(paths=paths), \
                    patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': SimpleNamespace(validate_inputs=validate)}), \
                    self.assertRaises(ValueError):
                subject.protect_theme_output(outer / 'capture', prefix, 'linux-host-v1')
        self.assertFalse((outer / 'capture').exists())

    def test_legacy_guard_uses_real_existing_destination_validator(self):
        prefix, proof, validate, calls = ThemeConsumerBindings.fixture(self, 'legacy-guest-v1')
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        outer = Path(temporary.name).resolve()
        generation = outer / 'generation'; generation.mkdir()
        (generation / 'build-report.json').write_text('{}\n')
        for mode in ('dark', 'light'):
            folder = outer / mode; folder.mkdir()
            (folder / 'capture.json').write_text('{"producer_inputs": ["producer"]}\n')
            (folder / 'serial.raw').write_bytes(b'preserved original capture bytes\n')
        (outer / 'producer').mkdir()
        config = {'provenance': {'build': {'prefix': 'generation', 'receipt': {'path': 'generation/build-report.json'}},
                  'captures': [{'capture': {'path': mode + '/capture.json'},
                                'serial': {'path': mode + '/serial.raw'}} for mode in ('dark', 'light')]}}
        proof['inputs_before'] = {'build': {'output': str(generation)}}
        legacy = subject.base.install_cosmic_theme_defaults
        manifest_root = outer / 'manifest-data'; manifest_root.mkdir()
        manifest = manifest_root / 'assets.json'; manifest.write_text('{}\n')
        before = self.tree_state(outer)
        actual_guard = legacy.validate_destination
        with patch.object(legacy, 'ROOT', outer), patch.object(legacy, 'MANIFEST', manifest), \
                patch.object(legacy, 'load_manifest', return_value=config) as load, \
                patch.object(legacy, 'validate_inputs', side_effect=validate), \
                patch.object(legacy, 'validate_destination', wraps=actual_guard) as guard:
            for source in (generation, outer / 'dark', outer / 'producer'):
                output = source / 'new-capture'
                with self.subTest(source=source), self.assertRaisesRegex(legacy.BuildError, 'overlaps preserved generation inputs'):
                    subject.protect_theme_output(output, prefix, 'legacy-guest-v1')
                guard.assert_called_with(output, manifest, config, proof['inputs_before'])
            selected, theme, protected = subject.protect_theme_output(outer / 'safe-capture', prefix, 'legacy-guest-v1')
            self.assertEqual(selected, outer / 'safe-capture')
            self.assertEqual(protected, [prefix])
            self.assertEqual(theme['proof'], proof)
            self.assertEqual(load.call_count, 4)
        self.assertEqual(self.tree_state(outer), before)

    def capture_fixture(self, origin='linux-host-v1'):
        outer, prefix, proof, validate, calls, generation = self.linux_fixture(origin)
        paths = {}
        for name in ('build', 'dbus_build', 'compositor_build', 'notifications_build', 'probe_build',
                     'session_installation', 'settings_installation', 'settings_probe_build',
                     'qemu_data', 'qemu_module_dir', 'font_source', 'session_build', 'settings_build'):
            paths[name] = outer / name; paths[name].mkdir()
        (paths['build'] / 'build-manifest.json').write_text(json.dumps({'sysroot': str(prefix)}))
        for name, receipt in [('dbus_build', 'dbus-build-report.json'), ('compositor_build', 'build-report.json'),
                              ('notifications_build', 'build-report.json'), ('probe_build', 'build-report.json'),
                              ('settings_probe_build', 'build-report.json'), ('session_build', 'build-report.json'),
                              ('settings_build', 'build-report.json')]:
            (paths[name] / receipt).write_text('{}\n')
        for name, source, installer in [('session_installation', 'session_build', subject.session_installer),
                                        ('settings_installation', 'settings_build', subject.settings_installer)]:
            (paths[name] / installer.RECEIPT).write_text(json.dumps({'origin': {'build_output': str(paths[source])}}))
        (prefix / 'cosmic-font-assets.json').write_text(json.dumps({'source': {'checkout': str(paths['font_source'])}}))
        lock = outer / 'native-session.lock'; lock.write_bytes(b'')
        args = SimpleNamespace(**paths, native_lock=lock, output=generation / 'new-capture', theme_origin=origin)
        return outer, prefix, proof, generation, args

    def capture_attempt(self, args, prefix, proof, *, consumer_error=None):
        events, held = [], [False]
        @contextmanager
        def lease(path):
            self.assertEqual(path, args.native_lock)
            events.append('lease-enter'); held[0] = True
            try:
                yield
            finally:
                held[0] = False; events.append('lease-exit')
        def validate(path):
            self.assertTrue(held[0], 'Full selected theme validation must run under original lease')
            self.assertEqual(path, prefix)
            events.append('strict-theme-consumer')
            if consumer_error:
                raise ValueError(consumer_error)
            return copy.deepcopy(proof)
        with patch.object(subject, 'NATIVE_LOCK', args.native_lock), patch.object(subject, 'native_lease', side_effect=lease), \
                patch.object(subject, 'idle_native_host', side_effect=lambda: events.append('idle-host-check')), \
                patch.dict(sys.modules, {{'linux-host-v1': 'install_cosmic_theme_linux_v1',
                                          'linux-host-v2': 'install_cosmic_theme_linux_v2'}[args.theme_origin]:
                                         SimpleNamespace(validate_inputs=validate)}), \
                patch.object(Path, 'mkdir', side_effect=AssertionError('No mkdir before source protection')), \
                patch.object(Path, 'write_bytes', side_effect=AssertionError('No write before source protection')), \
                patch.object(Path, 'write_text', side_effect=AssertionError('No write before source protection')), \
                patch.object(subject, 'write_json', side_effect=AssertionError('No JSON write before source protection')), \
                patch.object(subject, 'validate_inputs', side_effect=AssertionError('Must reject before full capture input phase')), \
                patch.object(subject, 'qemu_inputs', side_effect=AssertionError('Must reject before QEMU phase')):
            with self.assertRaisesRegex(ValueError, consumer_error or 'overlaps a read-only input'):
                subject.capture(args)
        self.assertEqual(events, ['lease-enter', 'idle-host-check', 'strict-theme-consumer', 'lease-exit'])
        self.assertFalse(held[0])

    def test_real_capture_rejects_theme_build_child_before_any_mkdir_or_write(self):
        outer, prefix, proof, generation, args = self.capture_fixture()
        before = self.tree_state(outer), self.tree_state(prefix)
        self.capture_attempt(args, prefix, proof)
        self.assertFalse(args.output.exists())
        self.assertEqual((self.tree_state(outer), self.tree_state(prefix)), before)

    def test_missing_strict_theme_origin_rejects_before_any_capture_mutation(self):
        outer, prefix, proof, generation, args = self.capture_fixture()
        args.output = outer / 'safe-capture'
        before = self.tree_state(outer), self.tree_state(prefix)
        self.capture_attempt(args, prefix, proof, consumer_error='Missing genuine theme generation')
        self.assertFalse(args.output.exists())
        self.assertEqual((self.tree_state(outer), self.tree_state(prefix)), before)

    def test_custom_or_missing_lease_is_rejected_before_lease_or_directory_creation(self):
        outer, prefix, proof, generation, args = self.capture_fixture()
        original = args.native_lock
        args.native_lock = generation / 'unreviewed-new-lock'
        with patch.object(subject, 'NATIVE_LOCK', original), \
                patch.object(subject, 'native_lease', side_effect=AssertionError('Do not acquire alternate lease')), \
                patch.object(Path, 'mkdir', side_effect=AssertionError('No lock parent mkdir')), \
                self.assertRaisesRegex(ValueError, 'existing original native-session lease'):
            subject.capture(args)
        self.assertFalse(args.native_lock.exists())
        args.native_lock = original; original.unlink()
        with patch.object(subject, 'NATIVE_LOCK', original), \
                patch.object(subject, 'native_lease', side_effect=AssertionError('Do not create missing original lease')), \
                patch.object(Path, 'mkdir', side_effect=AssertionError('No lock parent mkdir')), \
                self.assertRaisesRegex(ValueError, 'existing original native-session lease'):
            subject.capture(args)
        self.assertFalse(original.exists())


    def test_linux_v2_capture_rejects_generation_child_before_any_write(self):
        outer, prefix, proof, generation, args = self.capture_fixture('linux-host-v2')
        before = self.tree_state(outer), self.tree_state(prefix)
        with patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': SimpleNamespace(
                validate_inputs=lambda _: (_ for _ in ()).throw(AssertionError('Do not call old v1 consumer')))}):
            self.capture_attempt(args, prefix, proof)
        self.assertFalse(args.output.exists())
        self.assertEqual((self.tree_state(outer), self.tree_state(prefix)), before)


class LinuxThemeV2Bindings(unittest.TestCase):
    def test_fixed_v2_consumer_receipt_and_kind_without_older_consumer(self):
        prefix, proof, validate, calls = ThemeConsumerBindings.fixture(self, 'linux-host-v2')
        def old(path): raise AssertionError('An older theme consumer must not substitute for v2')
        with patch.dict(sys.modules, {'install_cosmic_theme_linux_v1': SimpleNamespace(validate_inputs=old),
                                     'install_cosmic_theme_linux_v2': SimpleNamespace(validate_inputs=validate)}), \
                patch.object(subject.base.install_cosmic_theme_defaults, 'validate_inputs', side_effect=old):
            result = subject.theme_inputs(prefix, 'linux-host-v2')
        self.assertEqual(subject.THEME_ORIGINS, ('legacy-guest-v1', 'linux-host-v1', 'linux-host-v2'))
        self.assertEqual(calls, [prefix])
        self.assertEqual(result['proof'], proof)
        self.assertEqual(result['receipt'], subject.identity(prefix / 'cosmic-theme-linux-v2-assets.json'))
        self.assertIs(result['current_settings_guest_verified'], False)
        self.assertIn('Linux host generation v2', result['generation_environment'])

    def test_v2_rejects_older_guest_or_host_receipt_before_consumer(self):
        for older in ('cosmic-theme-assets.json', 'cosmic-theme-linux-v1-assets.json'):
            prefix, proof, validate, calls = ThemeConsumerBindings.fixture(self, 'linux-host-v2')
            (prefix / older).write_text('{"older_origin_fixture": true}\n')
            with self.subTest(older=older), \
                    patch.dict(sys.modules, {'install_cosmic_theme_linux_v2': SimpleNamespace(validate_inputs=validate)}), \
                    self.assertRaisesRegex(ValueError, 'distinct receipt'):
                subject.theme_inputs(prefix, 'linux-host-v2')
            self.assertEqual(calls, [])

    def test_v2_wrong_kind_flags_status_and_missing_receipt_cannot_pass(self):
        for key, value in [('kind', 'cosmic-theme-linux-v1-assets'), ('kind', 'arbitrary-theme-assets'),
                           ('status', 'PASS'), ('host_generation', 1), ('guest_execution', 0),
                           ('guest_execution', True), ('missing_receipt', True)]:
            prefix, proof, validate, calls = ThemeConsumerBindings.fixture(self, 'linux-host-v2')
            if key == 'missing_receipt':
                (prefix / 'cosmic-theme-linux-v2-assets.json').unlink()
            else:
                proof[key] = value
            with self.subTest(key=key, value=value), \
                    patch.dict(sys.modules, {'install_cosmic_theme_linux_v2': SimpleNamespace(validate_inputs=validate)}), \
                    self.assertRaises(ValueError):
                subject.theme_inputs(prefix, 'linux-host-v2')

    def test_v2_keeps_complete_inventory_bytes_and_mode_contract(self):
        for mutation in ('missing', 'duplicate', 'mode-type', 'bytes-type', 'total', 'file-mode'):
            prefix, proof, validate, calls = ThemeConsumerBindings.fixture(self, 'linux-host-v2')
            if mutation == 'missing': proof['assets'].pop()
            elif mutation == 'duplicate': proof['assets'][-1] = proof['assets'][0]
            elif mutation == 'mode-type': proof['assets'][0]['mode'] = 420.0
            elif mutation == 'bytes-type': proof['assets'][0]['bytes'] = float(proof['assets'][0]['bytes'])
            elif mutation == 'total': proof['bounds']['asset_bytes'] += 1
            else: (prefix / 'rootfs' / proof['assets'][0]['path'].lstrip('/')).chmod(0o600)
            with self.subTest(mutation=mutation), \
                    patch.dict(sys.modules, {'install_cosmic_theme_linux_v2': SimpleNamespace(validate_inputs=validate)}), \
                    self.assertRaises(ValueError):
                subject.theme_inputs(prefix, 'linux-host-v2')


class V2ServiceInputBindings(unittest.TestCase):
    @contextmanager
    def fixture(self):
        """Exercise the real combined validator; replace only native consumers.

        Tiny explicit host files stand in for admitted images. The real
        installation copy, receipt, mode, page-grant and consumer-version
        checks run unchanged. No fixture claims a real build or guest result.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            names = ('build', 'dbus_build', 'compositor_build', 'notifications_build',
                     'probe_build', 'session_installation', 'settings_installation',
                     'settings_probe_build', 'catalog')
            paths = {name: root / name for name in names}
            for path in paths.values():
                path.mkdir()
            args = SimpleNamespace(**{key: value for key, value in paths.items() if key != 'catalog'},
                                   theme_origin='linux-host-v2', cc='fixture-compiler-never-executed')
            prefix = paths['catalog']
            (args.build / 'build-manifest.json').write_text(json.dumps({'sysroot': str(prefix)}))
            admissions = {
                'cosmic-session': {'required_pages': 1512, 'image_load_pages': 1000},
                'cosmic-settings-daemon': {'required_pages': 1883, 'image_load_pages': 1371},
                'settings-probe': {'required_pages': 571, 'image_load_pages': 59},
            }
            proofs = {}
            for label, installer, selected, status in (
                    ('session', subject.session_installer, args.session_installation,
                     'SESSION_INSTALLATION_REVALIDATED_NOT_RUN'),
                    ('settings', subject.settings_installer, args.settings_installation,
                     'SETTINGS_INSTALLATION_REVALIDATED_NOT_RUN')):
                files = {}
                for name in (installer.PROGRAM, *installer.LICENSES.values()):
                    raw = ('EXPLICIT HOST FIXTURE ' + name).encode()
                    mode = 0o755 if name == installer.PROGRAM else 0o644
                    for directory in (selected, prefix):
                        path = directory / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(raw); path.chmod(mode)
                    files[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode}
                receipt = json.dumps(admissions[Path(installer.PROGRAM).stem], sort_keys=True).encode()
                for directory in (selected, prefix):
                    (directory / installer.RECEIPT).write_bytes(receipt)
                proofs[label] = {'status': status, 'files': files, 'guest_execution': 'not performed',
                                 'settings_verified': False, 'cosmic_session_ready': False,
                                 'cosmic_session_verified': False, 'full_cosmic_complete': False}
            proofs['settings']['kind'] = 'cosmic-settings-linux-v2-installation'
            client = {'kind': 'cosmic-settings-probe-v2',
                      'client_contract': copy.deepcopy(subject.settings_probe.producer.CLIENT_CONTRACT),
                      'status': 'SETTINGS_PROBE_BUILD_REVALIDATED_NOT_RUN',
                      'guest_execution': False, 'settings_verified': False,
                      'cosmic_session_ready': False, 'full_cosmic_complete': False,
                      'dbus_build': str(args.dbus_build),
                      'executable': {'path': str(args.settings_probe_build / 'settings-probe.elf')},
                      'image_admission': copy.deepcopy(admissions['settings-probe'])}
            original = {'os': {'sysroot': str(prefix)}, 'assets': {}, 'inspections': {}}
            with patch.object(subject.base, 'validate_inputs', side_effect=lambda _: copy.deepcopy(original)) as base_check, \
                    patch.object(subject, 'theme_inputs', return_value={'explicit_host_fixture': True}), \
                    patch.object(subject.session_installer, 'validate_inputs', side_effect=lambda _: copy.deepcopy(proofs['session'])), \
                    patch.object(subject.settings_installer, 'validate_inputs', side_effect=lambda _: copy.deepcopy(proofs['settings'])), \
                    patch.object(subject.settings_probe, 'validate_build', side_effect=lambda _: copy.deepcopy(client)), \
                    patch.object(subject.base.elf, 'inspect_full_os_elf', side_effect=lambda path, _: copy.deepcopy(admissions[Path(path).stem])) as inspect, \
                    patch.object(subject, 'catalog_identity', return_value={'explicit_host_fixture': True}) as catalog, \
                    patch.object(subject.probe_builder, 'producer_sources', return_value={'explicit_host_fixture': True}):
                yield SimpleNamespace(args=args, prefix=prefix, proofs=proofs, client=client,
                                      admissions=admissions, inspect=inspect, catalog=catalog, base_check=base_check)

    def test_exact_v2_consumers_and_admissions_reach_nine_image_catalog(self):
        self.assertEqual(Path(subject.settings_installer.__file__).name, 'install_cosmic_settings_linux_v3.py')
        self.assertEqual(Path(subject.settings_probe.__file__).name, 'settings_probe_inputs_v2.py')
        with self.fixture() as fixture:
            proof = subject.validate_inputs(fixture.args)
            self.assertEqual(proof['settings_installation'], fixture.proofs['settings'])
            self.assertEqual(proof['settings_probe'], fixture.client)
            self.assertEqual(fixture.inspect.call_count, 3)
            fixture.base_check.assert_called_once_with(fixture.args)
            programs = fixture.catalog.call_args.args[2]
            self.assertEqual(set(programs), set(subject.IMAGE_NAMES))
            self.assertEqual(programs['cosmic-settings-daemon.elf'],
                             fixture.args.settings_installation / 'cosmic-settings-daemon.elf')
            self.assertEqual(programs['settings-probe.elf'],
                             fixture.args.settings_probe_build / 'settings-probe.elf')

    def test_old_or_unrecognized_settings_installation_cannot_be_reinterpreted(self):
        for kind in ('cosmic-settings-linux-v1-installation', 'PASS', None):
            with self.subTest(kind=kind), self.fixture() as fixture:
                fixture.proofs['settings']['kind'] = kind
                with self.assertRaises(ValueError):
                    subject.validate_inputs(fixture.args)
                fixture.catalog.assert_not_called()
        with self.fixture() as fixture:
            old_receipt = 'cosmic-settings-linux-v1-installation.json'
            for directory in (fixture.args.settings_installation, fixture.prefix):
                (directory / old_receipt).write_bytes((directory / subject.settings_installer.RECEIPT).read_bytes())
            with patch.object(subject.settings_installer, 'RECEIPT', old_receipt), self.assertRaises(ValueError):
                subject.validate_inputs(fixture.args)
            fixture.catalog.assert_not_called()

    def test_old_probe_kind_noninteger_version_or_changed_field_contract_rejected(self):
        mutations = [('kind', 'cosmic-settings-probe-v1'), ('kind', None),
                     ('protocol_version', 1), ('protocol_version', True), ('protocol_version', 2.0),
                     ('protocol_version', '2'), ('changed_marker_fields', ['watcher_unique']),
                     ('changed_marker_fields', ['watcher_name', 'watcher_unique', 'watcher_pid', 'service_pid', 'client_pid'])]
        for key, value in mutations:
            with self.subTest(key=key, value=value), self.fixture() as fixture:
                target = fixture.client if key == 'kind' else fixture.client['client_contract']
                target[key] = value
                with self.assertRaises(ValueError):
                    subject.validate_inputs(fixture.args)
                fixture.catalog.assert_not_called()

    def test_new_probe_still_requires_unexecuted_flags_actual_broker_and_path(self):
        for key, value in [('status', 'PASS'), ('guest_execution', True), ('settings_verified', True),
                           ('cosmic_session_ready', True), ('full_cosmic_complete', True),
                           ('dbus_build', '/unrelated/broker'), ('executable_path', '/unrelated/settings-probe.elf')]:
            with self.subTest(key=key, value=value), self.fixture() as fixture:
                if key == 'executable_path':
                    fixture.client['executable']['path'] = value
                else:
                    fixture.client[key] = value
                with self.assertRaises(ValueError):
                    subject.validate_inputs(fixture.args)
                fixture.catalog.assert_not_called()

    def test_version_change_does_not_bypass_actual_elf_page_grant_comparison(self):
        for image in ('cosmic-session', 'cosmic-settings-daemon', 'settings-probe'):
            with self.subTest(image=image), self.fixture() as fixture:
                fixture.admissions[image]['required_pages'] += 1
                with self.assertRaises(ValueError):
                    subject.validate_inputs(fixture.args)
                fixture.catalog.assert_not_called()

    def test_new_daemon_catalog_bytes_modes_and_receipt_remain_bound(self):
        for mutation in ('executable', 'license', 'mode', 'receipt'):
            with self.subTest(mutation=mutation), self.fixture() as fixture:
                target = fixture.prefix / subject.settings_installer.PROGRAM
                if mutation == 'executable':
                    target.write_bytes(b'ALTERED HOST FIXTURE')
                elif mutation == 'license':
                    (fixture.prefix / next(iter(subject.settings_installer.LICENSES.values()))).write_bytes(b'ALTERED LICENSE')
                elif mutation == 'mode':
                    target.chmod(0o644)
                else:
                    (fixture.prefix / subject.settings_installer.RECEIPT).write_text('{}')
                with self.assertRaises(ValueError):
                    subject.validate_inputs(fixture.args)
                fixture.catalog.assert_not_called()


if __name__ == '__main__':
    unittest.main()
