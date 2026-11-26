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

from tools import os_cosmic_services_runtime_v6 as subject
from tools import os_cosmic_services_runtime_v4 as previous_subject
from tools import os_cosmic_services_runtime_v5 as previous_transport_subject
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



CAPTURE2_FIXTURE_ENV = 'CYXIA_SERVICE_RUNTIME_CAPTURE2_RAW_FIXTURE'
CAPTURE2_FIXTURE_BYTES = 3780285
CAPTURE2_FIXTURE_SHA256 = 'c5bc67ae603b3f9a1df1f1a3de4fd6f1038175c0d09c3a96e61945261866bcb9'


def retained_capture2_fixture():
    selected = os.environ.get(CAPTURE2_FIXTURE_ENV)
    if selected is None:
        return None
    subject.require(bool(selected) and Path(selected).is_absolute(),
                    'Explicit capture2 fixture must name an absolute regular file')
    raw = subject.read_regular(selected, 4 * 1024**2)
    subject.require(len(raw) == CAPTURE2_FIXTURE_BYTES
                    and hashlib.sha256(raw).hexdigest() == CAPTURE2_FIXTURE_SHA256,
                    'Explicit capture2 fixture must match the complete fixed UART identity')
    return raw


class ReusableSlotGuestFixture(GuestFixture):
    """Retain protocol fixtures but expose the kernel's reusable slot inventory.

    The launch sequence and monotonically assigned PIDs are still generated by
    GuestFixture. Only its list projection follows eight reusable Runner slots;
    this deliberately does not implement or bypass the production final gate.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.slots = [None] * 8

    def command(self, command, expected=()):
        if command.startswith('posix exec '):
            name = command.removeprefix('posix exec ')
            slot = next(index for index, pid in enumerate(self.slots)
                        if pid is None or self.rows[pid]['state'] not in ('Running', 'Waiting'))
            start = super().command(command, expected)
            self.slots[slot] = self.names[name]
            return start
        return super().command(command, expected)

    def current_rows(self, console=None):
        historical = super().current_rows(console)
        rows = {pid: historical[pid] for pid in self.slots if pid is not None}
        if rows:
            subject.global_arena(rows)
        return rows


class ReusedRunnerBoundaries(unittest.TestCase):
    def launches(self):
        return {'cosmic-session-version': 1, 'settings-probe-prepare': 2, 'dbus-daemon': 3,
                'cosmic-comp': 5, 'settings-probe': 6, 'cosmic-settings-daemon': 7}

    def final_rows(self):
        rows = {}
        for pid in (3, 5, 6, 7):
            row = process('Exited' if pid == 6 else 'Killed', 0 if pid == 6 else 137)
            row.update(pid=pid, free_pages=64)
            rows[pid] = row
        return rows

    def reused_driver(self, *, previous=False, error=None):
        # Exercise each actual source driver. Only the existing explicit guest
        # transport/frame fixtures change their process-list storage model.
        selected = previous_subject if previous else subject
        with patch.dict(globals(), {'subject': selected, 'GuestFixture': ReusableSlotGuestFixture}):
            return DriverBoundaries.run_fixture(self, error=error)

    def test_all_six_launch_identities_are_closed_positive_and_distinct(self):
        good = self.launches()
        cases = []
        for name in good:
            absent = dict(good); del absent[name]; cases.append(absent)
            for invalid in (True, False, 0, -1, '7', 7.0, None):
                changed = dict(good); changed[name] = invalid; cases.append(changed)
        for name in ('dbus-daemon', 'cosmic-comp', 'settings-probe', 'cosmic-settings-daemon'):
            for old_pid in (1, 2, 3):
                if good[name] == old_pid:
                    continue
                changed = dict(good); changed[name] = old_pid; cases.append(changed)
        extra = dict(good, unrelated=99); cases.append(extra)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                subject.final_service_arena(self.final_rows(), changed)

    def test_each_current_service_pid_and_its_terminal_identity_are_required(self):
        for pid in (3, 5, 6, 7):
            changed = self.final_rows(); del changed[pid]
            with self.subTest(missing=pid), self.assertRaisesRegex(ValueError, 'Missing process'):
                subject.final_service_arena(changed, self.launches())
            changed = self.final_rows(); changed[pid]['pid'] = 99
            with self.subTest(wrong_row=pid), self.assertRaises(ValueError):
                subject.final_service_arena(changed, self.launches())
            for field, value in (('code', 1), ('state', 'Fault'), ('heap_pages', 1),
                                 ('image_pages', 1), ('thread_count', 1), ('heap_allocations', 1)):
                changed = self.final_rows(); changed[pid][field] = value
                with self.subTest(pid=pid, field=field), self.assertRaises(ValueError):
                    subject.final_service_arena(changed, self.launches())

    def test_all_fresh_rows_still_control_global_ledger_and_live_process_rejection(self):
        good = self.final_rows()
        # An un-reused earlier terminal slot may remain visible; it contributes
        # to the same complete fresh ledger, without becoming mandatory history.
        historical = process('Exited', 0); historical.update(pid=1, free_pages=64)
        good[1] = historical
        self.assertEqual(subject.final_service_arena(good, self.launches())['free_pages'], 64)
        inconsistent = self.final_rows(); inconsistent[5]['free_pages'] = 56
        with self.assertRaisesRegex(ValueError, 'Contradictory'):
            subject.final_service_arena(inconsistent, self.launches())
        live = self.final_rows()
        foreign = process('Running', 0); foreign.update(pid=8, free_pages=56)
        live[8] = foreign
        for row in live.values(): row['free_pages'] = 56
        with self.assertRaisesRegex(ValueError, 'not all terminal'):
            subject.final_service_arena(live, self.launches())
        idle = self.final_rows(); idle[8] = {**historical, 'pid': 8, 'state': 'Idle'}
        with self.assertRaisesRegex(ValueError, 'not all terminal'):
            subject.final_service_arena(idle, self.launches())

    def test_actual_old_driver_fails_reused_slots_and_new_driver_reads_final_resources(self):
        old_guest, old_result, old_inputs = self.reused_driver(previous=True)
        self.assertEqual(old_result['error'], "ValueError('Missing process from final arena snapshot')")
        self.assertNotIn('resources_after', old_result)
        self.assertEqual(old_guest.events[-1], 'posix kill 3')
        guest, result, inputs = self.reused_driver()
        self.assertNotIn('error', result)
        self.assertEqual(set(result['processes_after']), {3, 5, 6, 7})
        self.assertEqual(result['process_arena_after']['free_pages'], 64)
        self.assertEqual(guest.events[-1], 'ai system')
        self.assertTrue(result['resource_cleanup_observed'])
        subject.finalize_components(bytes(guest.raw), result, inputs)
        self.assertTrue(result['service_lifecycle_verified'])
        self.assertFalse(result['normal_session_executed'])
        self.assertFalse(result['full_cosmic_complete'])

    def test_earlier_phase_evidence_and_exact_name_pid_bindings_cannot_be_dropped(self):
        mutations = [
            ('version evidence', lambda r: r['components']['session_version'].pop('evidence')),
            ('version terminal', lambda r: r['components']['session_version'].pop('process_reclaimed')),
            ('version arena', lambda r: r['components']['session_version'].pop('arena')),
            ('version resources', lambda r: r['components']['session_version'].pop('resources_after')),
            ('version never finalized', lambda r: r['components']['session_version'].update(status='NOT_RUN')),
            ('preparation proof', lambda r: r.pop('preparation')),
            ('preparation terminal', lambda r: r['processes_reclaimed'].pop('settings-probe-prepare')),
            ('preparation arena', lambda r: r['preparation'].pop('arena')),
            ('preparation resources', lambda r: r['preparation'].pop('resources_after')),
            ('wrong service assignment', lambda r: r['launched'].update({'dbus-daemon': 5, 'cosmic-comp': 3})),
            ('missing final resources', lambda r: r.pop('resources_after')),
            ('missing final read acknowledgement', lambda r: r.update(resource_cleanup_observed=False)),
        ]
        for label, mutate in mutations:
            guest, result, inputs = self.reused_driver()
            self.assertNotIn('error', result)
            mutate(result)
            with self.subTest(case=label), self.assertRaises((ValueError, KeyError)):
                subject.finalize_components(bytes(guest.raw), result, inputs)
            self.assertFalse(result['service_lifecycle_verified'])
            self.assertFalse(result['components']['settings']['verified'])

    def test_reused_slots_do_not_hide_a_genuine_final_global_resource_leak(self):
        guest, result, inputs = self.reused_driver(error='leak')
        self.assertIn('Global resource did not return to baseline: ofd', result['error'])
        self.assertNotIn('resource_cleanup_observed', result)
        with self.assertRaisesRegex(ValueError, 'complete service/global reclamation'):
            subject.finalize_components(bytes(guest.raw), result, inputs)
        self.assertFalse(result['service_lifecycle_verified'])
        self.assertFalse(result['components']['settings']['verified'])

    def test_capture2_fixture_is_opt_in_and_invalid_selected_files_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(subject, 'read_regular') as reader:
            self.assertIsNone(retained_capture2_fixture())
            reader.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); altered = root / 'altered.raw'; altered.write_bytes(b'not the actual capture')
            link = root / 'linked.raw'; link.symlink_to(altered)
            for selected in ('', 'relative.raw', str(root / 'missing.raw'), str(altered), str(link)):
                with self.subTest(selected=selected), patch.dict(os.environ, {CAPTURE2_FIXTURE_ENV: selected}), \
                        self.assertRaises((ValueError, FileNotFoundError)):
                    retained_capture2_fixture()

    def test_actual_retained_capture2_proves_old_membership_error_without_fabricating_cleanup(self):
        raw = retained_capture2_fixture()
        if raw is None:
            self.skipTest('Select the optional full-SHA capture2 UART via ' + CAPTURE2_FIXTURE_ENV)
        launched = {}
        for name in self.launches():
            command = ('posix exec ' + name + '\r\n').encode()
            self.assertEqual(raw.count(command), 1)
            start = raw.index(command)
            match = re.search(rb'ELF pid=(\d+) started;[^\r\n]*', raw[start:start + 1024])
            self.assertIsNotNone(match)
            launched[name] = int(match[1])
        self.assertEqual(launched, self.launches())
        last_list = raw.rfind(b'posix list\r\n')
        self.assertGreater(last_list, raw.rfind(b'posix kill 3\r\n'))
        rows = subject.base.parse_processes(raw[last_list:])
        self.assertEqual(set(rows), {3, 5, 6, 7})
        with self.assertRaisesRegex(ValueError, 'Missing process from final arena snapshot'):
            previous_subject.global_arena(rows, required_pids=launched.values())
        arena = subject.final_service_arena(rows, launched)
        self.assertEqual(arena, {'capacity_pages': 64, 'pages_per_active_process': 8,
                                 'free_pages': 64, 'active_pids': []})
        protocol_start = raw.index(b'posix exec settings-probe\r\n')
        protocol = subject.settings_protocol(raw[protocol_start:], 7, 6)
        self.assertTrue(protocol['complete'])
        self.assertEqual(protocol['owner'], ':1.3')
        self.assertEqual(protocol['watchers']['config']['unique'], ':1.4')
        self.assertEqual(protocol['watchers']['state']['unique'], ':1.5')
        self.assertIn(b'USER pid=6 Exited code=0', raw)
        self.assertNotIn(b'ai system\r\n', raw[raw.rfind(b'posix kill 3\r\n'):])
        # The new helper proves only this final Runner arena. There is no final
        # OFD/shared/anonymous/pipe snapshot in the old bytes, so this regression
        # neither calls finalize_components nor changes the retained FAIL.




CAPTURE3_RAW_ENV = 'CYXIA_SERVICE_RUNTIME_CAPTURE3_RAW_FIXTURE'
CAPTURE3_COMMANDS_ENV = 'CYXIA_SERVICE_RUNTIME_CAPTURE3_COMMANDS_FIXTURE'
CAPTURE3_RAW_BYTES = 64357
CAPTURE3_RAW_SHA256 = 'caff73b9ab1689c1fc3fb371307ef95c4ced458a10dad0f806376cf600df98e4'
CAPTURE3_COMMANDS_BYTES = 1517
CAPTURE3_COMMANDS_SHA256 = 'fcb5bb1e25cee36e9471a1993ecd65f6b64534dd659726741ecd37760d8a3674'
# Exact small command-response slice from the fixed capture3 UART, independent
# of the producer's grammar/field list. Its whole raw capture remains opt-in.
CAPTURE3_LIST_BLOCK = b'posix list\r\nEL0 UserStatus { pid: 3, parent_pid: 0, exit_signal: 0, state: Waiting, code: 0, syscalls: 206, observed_tid: 3, observed_pc: 17224220, observed_sp: 169866904, observed_syscall: 281, space_rebuilds: 272, space_prepare_ns: 46590950, space_retire_ns: 17741950, preemptions: 62, ai_slices: 268, cpu_model: 12290, last_slice_ms: 1, esr: 0, far: 0, free_pages: 40, rank_model: 12289, ai_selections: 267, guard_selections: 1, thread_count: 1, thread_peak: 1, thread_memory_model: 0, thread_admissions: 0, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 267, thread_guard_selections: 1, ipc_sent: 0, ipc_received: 0, waits: 7, wakeups: 6, heap_pages: 11, heap_free: 16373, heap_model: 8199, heap_peak: 13, heap_allocations: 10, heap_peak_allocations: 11, heap_largest_free: 16371, image_pages: 629, image_free: 15755 }\r\nEL0 UserStatus { pid: 5, parent_pid: 0, exit_signal: 0, state: Running, code: 0, syscalls: 55, observed_tid: 5, observed_pc: 38537728, observed_sp: 169844648, observed_syscall: 11, space_rebuilds: 87, space_prepare_ns: 174180750, space_retire_ns: 54229740, preemptions: 31, ai_slices: 86, cpu_model: 12290, last_slice_ms: 1, esr: 0, far: 0, free_pages: 40, rank_model: 12289, ai_selections: 85, guard_selections: 1, thread_count: 1, thread_peak: 1, thread_memory_model: 0, thread_admissions: 0, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 85, thread_guard_selections: 1, ipc_sent: 0, ipc_received: 0, waits: 0, wakeups: 0, heap_pages: 29, heap_free: 16355, heap_model: 8199, heap_peak: 32, heap_allocations: 10, heap_peak_allocations: 12, heap_largest_free: 16351, image_pages: 8839, image_free: 7545 }\r\nEL0 UserStatus { pid: 6, parent_pid: 0, exit_signal: 0, state: Running, code: 0, syscalls: 25, observed_tid: 6, observed_pc: 16959602, observed_sp: 169867200, observed_syscall: 20, space_rebuilds: 37, space_prepare_ns: 7507150, space_retire_ns: 3085070, preemptions: 11, ai_slices: 36, cpu_model: 12290, last_slice_ms: 1, esr: 0, far: 0, free_pages: 40, rank_model: 12289, ai_selections: 36, guard_selections: 0, thread_count: 1, thread_peak: 1, thread_memory_model: 0, thread_admissions: 0, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 36, thread_guard_selections: 0, ipc_sent: 0, ipc_received: 0, waits: 3, wakeups: 3, heap_pages: 0, heap_free: 16384, heap_model: 0, heap_peak: 0, heap_allocations: 0, heap_peak_allocations: 0, heap_largest_free: 16384, image_pages: 571, image_free: 15813 }\r\ncyxia:/> '
CAPTURE3_LIST_BLOCK_SHA256 = '6d6a7d25888a09053507a1476380cd6cd74d4d8739fc05fa1f232bbc2dc26b23'


def current_user_status_fixture_block():
    """Synthetic current-format rows, independent of the producer grammar."""
    block = re.sub(rb'(space_rebuilds: [0-9]+, )', rb'\g<1>space_reuses: 9, ',
                   CAPTURE3_LIST_BLOCK)
    return re.sub(rb'(space_retire_ns: [0-9]+, )', rb'\g<1>space_revoke_ns: 17, ', block)


def retained_capture3_fixture():
    selected = [os.environ.get(CAPTURE3_RAW_ENV), os.environ.get(CAPTURE3_COMMANDS_ENV)]
    if selected == [None, None]:
        return None
    subject.require(all(value and Path(value).is_absolute() for value in selected),
                    'Explicit capture3 fixture requires both absolute raw and authored-command files')
    data = []
    for value, size, digest in zip(selected, (CAPTURE3_RAW_BYTES, CAPTURE3_COMMANDS_BYTES),
                                   (CAPTURE3_RAW_SHA256, CAPTURE3_COMMANDS_SHA256)):
        content = subject.read_regular(value, 4 * 1024**2)
        subject.require(len(content) == size and hashlib.sha256(content).hexdigest() == digest,
                        'Explicit capture3 fixture must match both complete fixed identities')
        data.append(content)
    return data[0], json.loads(data[1])


def interleaved_readiness(*, block=CAPTURE3_LIST_BLOCK, split=None, ready=None, lf=b'\n'):
    ready = protocol_rows()[1] if ready is None else ready
    split = ready.index(b'client_pid=') + len(b'client_p') if split is None else split
    initial = protocol_rows()[0] + b'\n'
    raw = initial + ready[:split] + block + ready[split:] + lf
    return raw, [{'command': 'posix list', 'serial_offset': len(initial)}], len(initial), split


class InterleavedListGuestFixture(ReusableSlotGuestFixture):
    def command(self, command, expected=()):
        start = super().command(command, expected)
        if command == 'posix exec settings-probe':
            marker = self.raw.index(b'SETTINGS_PROBE WAYLAND_READY ', start)
            split = self.raw.index(b'client_pid=', marker) + len(b'client_p')
            self.raw[split:split] = CAPTURE3_LIST_BLOCK
            self.commands.append({'command': 'posix list', 'serial_offset': marker})
            self.events.append('posix list')
        return start


class SettingsTransportBoundaries(unittest.TestCase):
    def fixture(self, **kwargs):
        return interleaved_readiness(**kwargs)

    def observed(self, raw, commands, *, client=6, service=None, through='readiness', expected_receipts=None):
        return subject.settings_observation(raw, commands, 0, service, client, through=through,
                                            expected_receipts=expected_receipts)

    def interleaved_driver(self, *, previous=False, error=None):
        selected = previous_transport_subject if previous else subject
        with patch.dict(globals(), {'subject': selected, 'GuestFixture': InterleavedListGuestFixture}):
            return DriverBoundaries.run_fixture(self, error=error)

    def test_exact_row_grammar_matches_actual_kernel_debug_field_order_and_types(self):
        source = (Path(subject.ROOT) / 'crates/posix/src/lib.rs').read_text()
        body = re.search(r'pub struct UserStatus \{(.*?)\n\}', source, re.S).group(1)
        fields = re.findall(r'pub (\w+): (u32|u64|UserState),', body)
        actual = tuple((name, None if kind == 'UserState' else int(kind[1:])) for name, kind in fields)
        self.assertEqual(subject.USER_STATUS_FIELDS, actual)
        self.assertEqual(hashlib.sha256(CAPTURE3_LIST_BLOCK).hexdigest(), CAPTURE3_LIST_BLOCK_SHA256)
        self.assertEqual(len(CAPTURE3_LIST_BLOCK), 2497)

    def test_current_complete_kernel_rows_keep_new_fields_bounded_and_receipted(self):
        block = current_user_status_fixture_block()
        for value in (0, 9, (1 << 64) - 1):
            current = block.replace(b'space_reuses: 9,', f'space_reuses: {value},'.encode())
            current = current.replace(b'space_revoke_ns: 17,', f'space_revoke_ns: {value},'.encode())
            raw, commands, _, _ = self.fixture(block=current)
            before = bytes(raw), copy.deepcopy(commands)
            with self.subTest(value=value):
                proof = self.observed(raw, commands)
                view, receipts = subject.settings_transport_view(raw, commands, 0)
                self.assertEqual(view, b'\n'.join(protocol_rows()[:2]) + b'\n')
                self.assertEqual(receipts[0]['bytes'], len(current))
                self.assertEqual(receipts[0]['sha256'], hashlib.sha256(current).hexdigest())
                self.assertEqual(receipts[0]['status_pids'], [3, 5, 6])
                self.assertEqual(proof['transport_command_spans'], receipts)
                self.assertEqual(self.observed(raw, commands, expected_receipts=receipts), proof)
                self.assertEqual((raw, commands), before)

    def test_current_rows_reject_missing_reordered_duplicate_unknown_and_noncanonical_fields(self):
        block = current_user_status_fixture_block()
        changes = [
            block.replace(b'space_reuses: 9, ', b'', 1),
            block.replace(b'space_revoke_ns: 17, ', b'', 1),
            block.replace(b'space_reuses: 9, ', b''),
            block.replace(b'space_revoke_ns: 17, ', b''),
            block.replace(b'space_reuses: 9, space_prepare_ns: 46590950, ',
                          b'space_prepare_ns: 46590950, space_reuses: 9, ', 1),
        ]
        for field, value in ((b'space_reuses', b'9'), (b'space_revoke_ns', b'17')):
            original = field + b': ' + value + b', '
            changes.extend((block.replace(original, original * 2, 1),
                            block.replace(original, b'unknown: ' + value + b', ', 1)))
            for invalid in (b'-1', b'00', b'18446744073709551616'):
                changes.append(block.replace(original, field + b': ' + invalid + b', ', 1))
        for changed in changes:
            raw, commands, _, _ = self.fixture(block=changed)
            with self.subTest(block=changed[:500]), self.assertRaises((ValueError, AssertionError)):
                self.observed(raw, commands)

    def test_complete_current_and_legacy_row_grammars_cannot_mix_within_one_response(self):
        current = current_user_status_fixture_block().split(b'\r\n')
        legacy = CAPTURE3_LIST_BLOCK.split(b'\r\n')
        for first, second in ((current, legacy), (legacy, current)):
            mixed = b'\r\n'.join(first[:2] + second[2:])
            raw, commands, _, _ = self.fixture(block=mixed)
            with self.subTest(block=mixed[:500]), self.assertRaisesRegex(ValueError, 'exact kernel response'):
                self.observed(raw, commands)

    def test_exact_authored_complete_block_recovers_only_unchanged_start_and_readiness(self):
        raw, commands, marker_start, split = self.fixture()
        before = bytes(raw), copy.deepcopy(commands)
        with self.assertRaisesRegex(ValueError, 'Wayland socket readiness'):
            previous_transport_subject.settings_protocol(raw, None, 6, through='readiness')
        proof = self.observed(raw, commands)
        view, receipts = subject.settings_transport_view(raw, commands, 0)
        self.assertEqual(view, b'\n'.join(protocol_rows()[:2]) + b'\n')
        self.assertEqual(proof['markers'], [row.decode() for row in protocol_rows()[:2]])
        self.assertFalse(proof['complete']); self.assertIsNone(proof['owner'])
        self.assertFalse(proof['wayland_protocol_verified']); self.assertFalse(proof['render_verified'])
        self.assertFalse(proof['normal_session_executed'])
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual((receipt['command_index'], receipt['issued_serial_offset'], receipt['serial_start'],
                          receipt['serial_end']), (0, marker_start, marker_start + split,
                                                  marker_start + split + 2497))
        self.assertEqual(receipt['sha256'], CAPTURE3_LIST_BLOCK_SHA256)
        self.assertEqual(receipt['status_pids'], [3, 5, 6])
        self.assertEqual(receipt['marker_line_start'], marker_start)
        self.assertEqual(receipt['continued_line_end'], len(raw))
        self.assertEqual(receipt['projected_line_sha256'], hashlib.sha256(protocol_rows()[1] + b'\n').hexdigest())
        self.assertEqual(proof['transport_command_spans'], receipts)
        self.assertEqual(self.observed(raw, commands, expected_receipts=receipts), proof)
        self.assertEqual((raw, commands), before)

    def test_each_interior_field_split_requires_the_same_exact_complete_marker(self):
        ready = protocol_rows()[1]
        for split in range(len(b'SETTINGS_PROBE '), len(ready)):
            raw, commands, _, _ = self.fixture(split=split)
            with self.subTest(split=split):
                proof = self.observed(raw, commands)
                self.assertEqual(proof['markers'][-1].encode(), ready)
                self.assertEqual(len(proof['transport_command_spans']), 1)

    def test_missing_wrong_or_unowned_command_ledger_never_authorizes_deletion(self):
        raw, commands, _, _ = self.fixture()
        bad = [[], [{'command': 'ai system', 'serial_offset': commands[0]['serial_offset']}],
               [{'command': 'posix list', 'serial_offset': raw.index(b'posix list') + 1}],
               [{'command': 'posix list', 'serial_offset': True}],
               [{'command': 'posix list', 'serial_offset': -1}],
               [{'command': 'posix list', 'serial_offset': len(raw) + 1}],
               [dict(commands[0], extra='unbound')], commands + commands,
               [{'command': 'posix list\r', 'serial_offset': commands[0]['serial_offset']}],
               [{'command': 'posix list\n', 'serial_offset': commands[0]['serial_offset']}],
               [{'command': 'posix listé', 'serial_offset': commands[0]['serial_offset']}]]
        for changed in bad:
            with self.subTest(commands=changed), self.assertRaises((ValueError, AssertionError)):
                self.observed(raw, changed)
        with self.assertRaises(ValueError):
            subject.settings_transport_view(raw, tuple(commands), 0)

    def test_receipt_hash_offsets_association_order_and_completeness_are_revalidated(self):
        raw, commands, _, _ = self.fixture()
        _, receipts = subject.settings_transport_view(raw, commands, 0)
        bad = [[], receipts + receipts]
        for field in ('command_index', 'issued_serial_offset', 'serial_start', 'serial_end', 'bytes',
                      'marker_line_start', 'marker_prefix_bytes', 'continued_line_end'):
            changed = copy.deepcopy(receipts); changed[0][field] += 1; bad.append(changed)
        for field in ('sha256', 'marker_prefix_sha256', 'projected_line_sha256'):
            changed = copy.deepcopy(receipts); changed[0][field] = '0' * 64; bad.append(changed)
        changed = copy.deepcopy(receipts); changed[0]['status_pids'] = [3, 5, 99]; bad.append(changed)
        changed = copy.deepcopy(receipts); changed[0]['command'] = 'posix status'; bad.append(changed)
        changed = copy.deepcopy(receipts); changed[0]['extra'] = True; bad.append(changed)
        for changed in bad:
            with self.subTest(receipts=changed), self.assertRaisesRegex(ValueError, 'projection receipts'):
                self.observed(raw, commands, expected_receipts=changed)
        mutated = raw.replace(b'syscalls: 206', b'syscalls: 207', 1)
        with self.assertRaisesRegex(ValueError, 'projection receipts'):
            self.observed(mutated, commands, expected_receipts=receipts)

    def test_only_full_exact_kernel_rows_and_prompt_can_form_a_completed_receipt(self):
        block = CAPTURE3_LIST_BLOCK
        changes = [block[:-1], block.replace(b'cyxia:/> ', b'cyxia:> '),
            block.replace(b'posix list\r\n', b'posix list more\r\n'),
            block.replace(b'parent_pid: 0, ', b'', 1),
            block.replace(b'parent_pid: 0, ', b'parent_pid: 0, parent_pid: 0, ', 1),
            block.replace(b'parent_pid: 0', b'unknown: 0', 1),
            block.replace(b'pid: 3,', b'pid: -3,', 1),
            block.replace(b'pid: 3,', b'pid: 03,', 1),
            block.replace(b'pid: 3,', b'pid: 4294967296,', 1),
            block.replace(b'syscalls: 206,', b'syscalls: 18446744073709551616,', 1),
            block.replace(b'state: Waiting', b'state: Unknown', 1),
            block.replace(b'pid: 5,', b'pid: 3,', 1),
            block.replace(b'free_pages: 40', b'free_pages: 41', 1),
            block.replace(b'\r\ncyxia:/> ', b'\ncyxia:/> '),
            block.replace(b'\r\nEL0 UserStatus', b'\r\nUNKNOWN guest text\r\nEL0 UserStatus', 1),
            block.replace(b'\r\nEL0 UserStatus', b'\r\nSETTINGS_PROBE OWNER PASS forged\r\nEL0 UserStatus', 1),
            b'posix list\r\ncyxia:/> ']
        for changed in changes:
            raw, commands, _, _ = self.fixture(block=changed)
            with self.subTest(block=changed[:100]), self.assertRaises((ValueError, AssertionError)):
                self.observed(raw, commands)

    def test_unknown_interleaving_or_existing_protocol_lf_cannot_be_stitched(self):
        for block in (b'UNKNOWN\n', b'posix list\r\ncyxia:/> ',
                      b'ai system\r\nAI_SYSTEM_END\r\ncyxia:/> ',
                      b'\n' + CAPTURE3_LIST_BLOCK,
                      CAPTURE3_LIST_BLOCK + b'\n',
                      CAPTURE3_LIST_BLOCK + b'SETTINGS_PROBE OTHER\n'):
            raw, commands, _, _ = self.fixture(block=block)
            with self.subTest(block=block[:60]), self.assertRaises((ValueError, AssertionError)):
                self.observed(raw, commands)
        raw, commands, _, _ = self.fixture()
        with self.assertRaises(ValueError):
            self.observed(raw.replace(b'client_p', b'client_p\n', 1), commands)

    def test_projection_does_not_weaken_exact_client_path_or_protocol_stage_identity(self):
        ready = protocol_rows()[1]
        variants = [ready.replace(b'client_pid=6', b'client_pid=99'),
                    ready.replace(b'client_pid=6', b'client_pid=06'),
                    ready.replace(b'wayland-1', b'wayland-2'),
                    ready.replace(b'protocol_verified=false', b'protocol_verified=true'),
                    ready + b' extra=1']
        for changed in variants:
            raw, commands, _, _ = self.fixture(ready=changed)
            with self.subTest(ready=changed), self.assertRaises(ValueError):
                self.observed(raw, commands)
        raw, commands, _, _ = self.fixture()
        for stage in ('owner', 'complete'):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                self.observed(raw, commands, service=7, through=stage)
        with self.assertRaises(ValueError):
            self.observed(raw, commands, client=99)

    def test_protocol_parser_requires_real_lf_even_when_fields_are_already_complete(self):
        for stage, count, service in (('readiness', 2, None), ('owner', 3, 7), ('complete', 9, 7)):
            raw = b'\n'.join(protocol_rows()[:count])
            with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, 'terminating LF'):
                subject.settings_protocol(raw, service, 6, through=stage)
            subject.settings_protocol(raw + b'\n', service, 6, through=stage)
        raw, commands, _, _ = self.fixture(lf=b'')
        with self.assertRaisesRegex(ValueError, 'terminating LF'):
            self.observed(raw, commands)

    def test_wait_success_is_timed_at_real_lf_not_the_earlier_marker_prefix(self):
        pattern = rb'(?m)^SETTINGS_PROBE WAYLAND_READY [^\r\n]*\r?$'
        for arrived_at, succeeds in ((29.999, True), (30., False), (30.001, False)):
            clock = Clock(); clock.now = 0.
            raw, commands, _, _ = self.fixture(lf=b'')
            console = SimpleNamespace(deadline=240., raw=bytearray(), commands=commands,
                                      sock=SimpleNamespace(deadline=240.))
            qmp = SimpleNamespace(sock=SimpleNamespace(deadline=248.), observation_deadline=None)
            pumps = []
            def pump(**kwargs):
                if not pumps:
                    clock.now = 29.5; console.raw.extend(raw)
                else:
                    clock.now = arrived_at; console.raw.extend(b'\n')
                pumps.append(clock.now)
            console.pump = pump
            checkpoints = []
            observer = SimpleNamespace(qmp=qmp, checkpoint=lambda *args: checkpoints.append(clock.now))
            with self.subTest(arrived_at=arrived_at), \
                    patch.object(subject.time, 'monotonic', side_effect=clock.monotonic), \
                    patch.object(subject.time, 'sleep', side_effect=clock.sleep):
                if succeeds:
                    found = subject.wait_observed(console, observer, pattern, 0, {3, 5, 6}, {3, 5})
                    self.assertEqual(found[0], protocol_rows()[1])
                else:
                    with self.assertRaisesRegex(ValueError, 'fixed operation deadline'):
                        subject.wait_observed(console, observer, pattern, 0, {3, 5, 6}, {3, 5})
            self.assertEqual(len(pumps), 2); self.assertEqual(checkpoints, [29.5])
            self.assertEqual((console.deadline, console.sock.deadline, qmp.sock.deadline), (240., 240., 248.))
            self.assertIsNone(qmp.observation_deadline)

    def test_actual_old_driver_rejects_split_line_and_new_driver_keeps_all_protocol_and_cleanup_gates(self):
        old_guest, old_result, _ = self.interleaved_driver(previous=True)
        self.assertIn('Wayland socket readiness', old_result['error'])
        self.assertNotIn('cosmic-settings-daemon', old_result['launched'])
        self.assertFalse(old_result['service_lifecycle_verified'])
        guest, result, inputs = self.interleaved_driver()
        self.assertNotIn('error', result)
        subject.finalize_components(bytes(guest.raw), result, inputs)
        self.assertTrue(result['service_lifecycle_verified'])
        self.assertTrue(result['resource_cleanup_observed'])
        self.assertEqual(set(result['processes_after']), {3, 5, 6, 7})
        self.assertEqual(len(result['components']['settings']['protocol']['markers']), 9)
        self.assertEqual(len(result['components']['settings']['protocol']['transport_command_spans']), 1)
        self.assertFalse(result['normal_session_executed']); self.assertFalse(result['full_cosmic_complete'])

    def test_final_raw_cannot_lose_or_change_its_authored_projection_proof(self):
        for mutation in ('missing-ledger', 'wrong-command', 'missing-span', 'wrong-sha', 'extra-span', 'changed-row'):
            guest, result, inputs = self.interleaved_driver()
            self.assertNotIn('error', result); raw = bytes(guest.raw)
            if mutation == 'missing-ledger': del result['settings_transport_commands']
            elif mutation == 'wrong-command':
                row = next(row for row in result['settings_transport_commands'] if row['command'] == 'posix list')
                row['command'] = 'posix status'
            elif mutation == 'missing-span': result['components']['settings']['protocol']['transport_command_spans'] = []
            elif mutation == 'wrong-sha':
                result['components']['settings']['protocol']['transport_command_spans'][0]['sha256'] = '0' * 64
            elif mutation == 'extra-span':
                rows = result['components']['settings']['protocol']['transport_command_spans']; rows.extend(copy.deepcopy(rows))
            else: raw = raw.replace(b'syscalls: 206', b'syscalls: 207', 1)
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, AssertionError)):
                subject.finalize_components(raw, result, inputs)
            self.assertFalse(result['service_lifecycle_verified'])

    def test_capture3_fixture_requires_explicit_complete_sha_bound_raw_and_command_files(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(retained_capture3_fixture())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'not-actual'; path.write_bytes(b'not retained UART')
            variants = [{CAPTURE3_RAW_ENV: str(path)}, {CAPTURE3_COMMANDS_ENV: str(path)},
                        {CAPTURE3_RAW_ENV: 'relative', CAPTURE3_COMMANDS_ENV: str(path)},
                        {CAPTURE3_RAW_ENV: str(path), CAPTURE3_COMMANDS_ENV: str(path)}]
            for selected in variants:
                with self.subTest(selected=selected), patch.dict(os.environ, selected, clear=True), self.assertRaises(ValueError):
                    retained_capture3_fixture()

    def test_actual_retained_capture3_proves_command_collision_without_claiming_service_success(self):
        selected = retained_capture3_fixture()
        if selected is None:
            self.skipTest('Select both full-SHA capture3 raw and authored commands via '
                          + CAPTURE3_RAW_ENV + ' and ' + CAPTURE3_COMMANDS_ENV)
        raw, commands = selected
        self.assertEqual(commands[20], {'command': 'posix list', 'serial_offset': 54102})
        self.assertEqual(commands[21], {'command': 'ai system', 'serial_offset': 56663})
        self.assertEqual(raw[54166:56663], CAPTURE3_LIST_BLOCK)
        starts = re.findall(rb'ELF pid=(\d+) started;[^\r\n]*pages=(\d+)', raw)
        self.assertIn((b'6', b'571'), starts); self.assertNotIn((b'7', b'1896'), starts)
        with self.assertRaisesRegex(ValueError, 'Wayland socket readiness'):
            previous_transport_subject.settings_protocol(raw[33439:], None, 6, through='readiness')
        proof = subject.settings_observation(raw, commands, 33439, None, 6, through='readiness')
        self.assertEqual(proof['markers'], [row.decode() for row in protocol_rows()[:2]])
        receipt = proof['transport_command_spans'][0]
        self.assertEqual((receipt['serial_start'], receipt['serial_end'], receipt['continued_line_end']),
                         (54166, 56663, 56692))
        self.assertEqual(receipt['sha256'], CAPTURE3_LIST_BLOCK_SHA256)
        self.assertFalse(proof['complete']); self.assertIsNone(proof['owner'])
        self.assertNotIn(b'posix exec cosmic-settings-daemon', raw)
        self.assertNotIn(b'SETTINGS_PROBE OWNER PASS', raw)
        self.assertNotIn(b'USER pid=6 Exited', raw)
        self.assertNotIn(b'posix kill ', raw)
        with self.assertRaises(ValueError):
            subject.settings_observation(raw, commands, 33439, 7, 6)
        # This isolated projection never invokes finalize_components or promotes
        # the preserved capture3 FAIL, incomplete lifecycle, cleanup or frame.


if __name__ == '__main__':
    unittest.main()
