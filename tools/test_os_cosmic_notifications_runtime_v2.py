"""Pure host boundary tests for v2; recorded bytes are replay, not guest runs.

All 43 original acceptance-boundary tests also execute against v2 without
editing their source. External process creation is blocked by the private test
runner. Production time/output/semantic acceptance thresholds stay unchanged.
"""
import ast
import contextlib
import hashlib
from pathlib import Path
import re
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch

try:
    from tools import os_cosmic_notifications_runtime_v2 as subject
    from tools import test_os_cosmic_notifications_runtime as legacy
except ImportError:
    import os_cosmic_notifications_runtime_v2 as subject
    import test_os_cosmic_notifications_runtime as legacy

legacy_subject = legacy.subject

# Actual v22 UART span [1935010, 1938976), ending with genuine PID8 exit.
# Original serial.raw SHA256:
# 93f287f644975c7e0b82eceff2a9c373db73003a58b3af09ca8621197257ed5a.
ACTUAL_V22 = (
    b'3", 1)\n'
    b'[1523197.824] wl_registry#2.global(33, "zwp_virtual_keyboard_manager_v1", 1)\n'
    b'[1523197.824] wl_registry#2.global(34, "wp_alpha_modifier_v1", 1)\n'
    b'[1523197.824] wl_registry#2.global(35, "wp_single_pixel_buffer_mposix exec dbus-sendanager_v1", 1)\n'
    b'\r\n'
    b'EL0 request queued\r\n'
    b'cyxia:/> \r\n'
    b'ELF pid=8 started; ABI=Linux-x86_64-subset image AI_DIRECT model=8197 pages=571\r\n'
    b'[1523197.824] wl_registry#2.global(36, "wl_fixes", 1)\n'
    b'[1524197.824]  -> wl_registry#2.bind(36, "wl_fixes", 1, new id [unknown]#4)\n'
    b'[1524197.824] wl_registry#2.global(37, "zcosmic_keyboard_layout_manager_v1", 1)\n'
    b'[1524197.824] wl_registry#2.global(38, "ext_background_effect_manager_v1", 1)\n'
    b'[1524197.824] wl_registry#2.global(39, "ext_idle_notifier_v1", 2)\n'
    b'[1524197.824] wl_registry#2.global(40, "zwp_idle_inhibit_manager_v1", 1)\n'
    b'[1524197.824] wl_registry#2.global(41, "ext_data_control_manager_v1", 1)\n'
    b'[1524197.824] wl_registry#2.global(42, "zwlr_data_control_manager_v1", 2)\n'
    b'[1524197.824] wl_registry#2.global(43, "zwlr_layer_shell_v1", 5)\n'
    b'[1524197.824] wl_registry#2.global(44, "xdg_wm_base", 7)\n'
    b'[1524197.824] wl_registry#2.global(45, "xdg_activation_v1", 1)\n'
    b'[1524197.824] wl_registry#2.global(46, "zxdg_exporter_v2", 1)\n'
    b'[1524197.824] wl_registry#2.global(47, "zxdg_importer_v2", 1)\n'
    b'[1524197.824] wl_registry#2.global(48, "zcosmic_toplevel_info_v1", 3)\n'
    b'[1524197.824] wl_registry#2.global(49, "ext_foreign_toplevel_list_v1", 1)\n'
    b'[1524197.824] wl_registry#2.global(50, "zcosmic_toplevel_manager_v1", 4)\n'
    b'[1524197.824] wl_registry#2.global(51, "ext_workspace_manager_v1", 1)\n'
    b'[1524197.824] wl_registry#2.global(52, "zcosmic_workspace_manager_v2", 2)\n'
    b'[1524197.824] wl_registry#2.global(53, "cosmic_a11y_manager_v1", 2)\n'
    b'[1524197.824] wl_registry#2.global(54, "cosmic_session_lock_layer_manager_v1", 1)\n'
    b'[1525197.824] wl_registry#2.global(55, "wl_output", 4)\n'
    b'[1525197.824] wl_registry#2.global(56, "wl_seat", 9)\n'
    b'[1525197.824] wl_callback#3.done(0)\n'
    b'UNIX_ADMISSION AI_DIRECT model=8193 committed=true\n'
    b'UNIX_ADMISSION AI_DIRECT model=8193 committed=true\n'
    b'[1525197.824]  -> wl_registry#2.bind(1, "wl_compositor", 5, new id [unknown]#3)\n'
    b'[1525197.824]  -> wl_registry#2.bind(2, "wl_subcompositor", 1, new id [unknown]#5)\n'
    b'[1525197.824]  -> wl_registry#2.bind(55, "wl_output", 4, new id [unknown]#6)\n'
    b'[1525197.824]  -> wl_registry#2.bind(7, "zxdg_output_manager_v1", 3, new id [unknown]#7)\n'
    b'[1525197.824]  -> zxdg_output_manager_v1#7.get_xdg_output(new id zxdg_output_v1#8, wl_output#6)\n'
    b'[1526197.824]  -> wl_registry#2.bind(56, "wl_seat", 9, new id [unknown]#9)\n'
    b'[1526197.824]  -> wl_registry#2.bind(5, "wp_fractional_scale_manager_v1", 1, new id [unknown]#10)\n'
    b'[1526197.824]  -> wl_registry#2.bind(20, "wp_viewporter", 1, new id [unknown]#11)\n'
    b'[1526197.824]  -> wl_registry#2.bind(18, "wl_shm", 1, new id [unknown]#12)\n'
    b'[1526197.824]  -> wl_shm#12.create_pool(new id wl_shm_pool#13, fd 8, 2)\n'
    b'[1527197.824]  -> wl_registry#2.bind(44, "xdg_wm_base", 6, new id [unknown]#14)\n'
    b'[1527197.824]  -> wl_registry#2.bind(22, "zxdg_decoration_manager_v1", 1, new id [unknown]#15)\n'
    b'[1527197.824]  -> wl_registry#2.bind(45, "xdg_activation_v1", 1, new id [unknown]#16)\n'
    b'[1527197.824]  -> wl_registry#2.bind(38, "ext_background_effect_manager_v1", 1, new id [unknown]#17)\n'
    b'[1527197.824]  -> wl_registry#2.bind(32, "zwp_text_input_manager_v3", 1, new id [unknown]#18)\n'
    b'[1527197.824]  -> wl_registry#2.bind(29, "zwp_tablet_manager_v2", 1, new id [unknown]#19)\n'
    b'[1528197.824]  -> wl_registry#2.bind(26, "zwp_pointer_constraints_v1", 1, new id [unknown]#20)\n'
    b'[1528197.824]  -> wl_registry#2.bind(28, "zwp_pointer_gestures_v1", 1, new id [unknown]#21)\n'
    b'[1528197.824]  -> wl_display#1.sync(new id wl_callback#22)\n'
    b'method return time=1794894131.000000 sender=org.freedesktop.DBus -> destination=:1.5 serial=3 reply_serial=2\n'
    b'   array [\n'
    b'      string "org.freedesktop.DBus"\n'
    b'      string ":1.5"\n'
    b'      string "com.system76.CosmicComp"\n'
    b'      string ":1.1"\n'
    b'      string "org.freedesktop.a11y.Manager"\n'
    b'   ]\n'
    b'\r\n'
    b'USER pid=8 Exited code=0 free_pages=40 fault=0x0 far=0x0\r\n'
)


class OriginalAcceptanceAgainstV2(unittest.TestSuite):
    def run(self, result, debug=False):
        # Only select the implementation under test; original cases and all
        # their explicit compiler/VM boundary fixtures remain byte-identical.
        with patch.object(legacy, 'subject', subject):
            return super().run(result, debug)


def load_tests(loader, tests, pattern):
    original = loader.loadTestsFromModule(legacy)
    assert original.countTestCases() == 43
    return unittest.TestSuite([OriginalAcceptanceAgainstV2(original), tests])


@contextlib.contextmanager
def replay(module, response, *, history=b'cyxia:/> ', chunks=None, timeout=.01):
    class Channel:
        def __init__(self):
            self.pending, self.sent = [], []
            self.gap, self.received_chunks = False, 0

        def setblocking(self, value):
            pass

        def sendall(self, value):
            self.sent.append(value)
            self.pending = list(chunks if chunks is not None else [response])

        def recv(self, size):
            # Explicit chunk boundaries force the real pump/until loop to
            # reevaluate an incomplete suffix before the next bytes arrive.
            if self.gap:
                self.gap = False
                raise BlockingIOError()
            if not self.pending:
                raise BlockingIOError()
            data = self.pending.pop(0)
            self.gap = True
            self.received_chunks += 1
            return data

    class QuickConsole(module.Console):
        def until(self, pattern, start=0, timeout=30):
            row = {'pattern': pattern, 'start': start, 'production_timeout': timeout}
            self.waits.append(row)
            found = super().until(pattern, start, min(timeout, self.host_fixture_timeout))
            row.update(end=start + found.end(), received_chunks=self.sock.received_chunks)
            return found

    with tempfile.TemporaryDirectory() as directory:
        channel = Channel()
        console = QuickConsole(channel, SimpleNamespace(poll=lambda: None),
                               Path(directory), time.monotonic() + 5)
        console.waits, console.host_fixture_timeout = [], timeout
        console.raw.extend(history)
        console.capture_path.write_bytes(console.raw)
        yield console, channel


class EchoSuffixBoundaries(unittest.TestCase):
    COMMAND = b'posix exec dbus-send'
    PROMPT = b'cyxia:/> '
    SHELL = ACTUAL_V22[:280]

    def test_actual_v22_reproduces_legacy_timeout_and_recovers_only_command_boundary(self):
        self.assertEqual(len(ACTUAL_V22), 3966)
        self.assertEqual(hashlib.sha256(ACTUAL_V22).hexdigest(),
                         '6438227a1f52020d11243ba54290a7c3f87efc7f9d493c6c95463e1a655d9b86')
        self.assertEqual(hashlib.sha256(self.SHELL).hexdigest(),
                         'c94d997ed9358ca1136885abf74e845e08a6970e44f40f8397c633563a1f7f5d')
        self.assertIn(b'buffer_mposix exec dbus-sendanager_v1", 1)\n\r\n', self.SHELL)
        with replay(legacy_subject, self.SHELL) as (console, channel):
            with self.assertRaises(TimeoutError):
                console.command(self.COMMAND.decode())
            self.assertEqual(channel.sent, [self.COMMAND + b'\r'])
        with replay(subject, self.SHELL) as (console, channel):
            self.assertEqual(console.command(self.COMMAND.decode()), 9)
            response = 9 + self.SHELL.index(b'\n\r\n', self.SHELL.index(self.COMMAND)) + 3
            self.assertEqual(console.waits[1]['start'], response)
            self.assertEqual(bytes(console.raw)[response:response + 20], b'EL0 request queued\r\n')
            self.assertEqual(channel.sent, [self.COMMAND + b'\r'])
            self.assertEqual(console.commands, [{'command': self.COMMAND.decode(), 'serial_offset': 9}])
            self.assertEqual(bytes(console.raw), b'cyxia:/> ' + self.SHELL)
            self.assertEqual(console.capture_path.read_bytes(), bytes(console.raw))
            self.assertTrue(all(row['production_timeout'] == 30 for row in console.waits))

    def test_actual_v22_program_replay_still_requires_real_recorded_launch_and_exit(self):
        with replay(subject, ACTUAL_V22) as (console, channel):
            self.assertEqual(console.program(self.COMMAND.decode()), 9)
            self.assertEqual(len(console.waits), 4) # echo, prompt, PID, matching exit.
            self.assertEqual(channel.sent, [self.COMMAND + b'\r'])
            self.assertIn(b'ELF pid=8 started;', console.raw)
            self.assertIn(b'USER pid=8 Exited code=0', console.raw)
            self.assertNotIn(b'org.freedesktop.Notifications', console.raw)
            self.assertEqual(console.capture_path.read_bytes(), b'cyxia:/> ' + ACTUAL_V22)
        # Replaying a byte span does not create a producer summary, service
        # owner proof, process-reclamation snapshot, guest run or protocol PASS.

    def test_fragmented_background_suffix_requires_the_complete_shell_crlf(self):
        head = b'async log partial ' + self.COMMAND
        chunks = [head, b'anager_v1", 1)', b'\n', b'\r', b'\n', b'EL0 request queued\r\n' + self.PROMPT]
        payload = b''.join(chunks)
        with replay(subject, payload, chunks=chunks, timeout=.2) as (console, _):
            self.assertEqual(console.command(self.COMMAND.decode()), 9)
            self.assertEqual(console.waits[0]['received_chunks'], 5)
            self.assertEqual(console.waits[0]['end'], 9 + sum(map(len, chunks[:5])))
            self.assertEqual(console.waits[1]['received_chunks'], 6)
            self.assertEqual(bytes(console.raw), b'cyxia:/> ' + payload)

    def test_longer_commands_single_terminators_and_multiline_suffixes_are_rejected(self):
        invalid = [
            self.COMMAND + b' extra\r\n' + self.PROMPT,
            self.COMMAND + b' extra\n' + self.PROMPT,
            self.COMMAND + b'suffix\r\n\r\n' + self.PROMPT,
            self.COMMAND + b'suffix\n\n' + self.PROMPT,
            self.COMMAND + b'suffix\r' + self.PROMPT,
            self.COMMAND + b'suffix\n\r' + self.PROMPT,
            self.COMMAND + b'suffix\nsecond line\n\r\n' + self.PROMPT,
            self.COMMAND + b'suffix\n\r\ntracing quotes ' + self.PROMPT,
            b'posix exec dbus-seTRACEndsuffix\n\r\n' + self.PROMPT,
        ]
        for payload in invalid:
            with self.subTest(payload=payload), replay(subject, payload) as (console, _):
                with self.assertRaises(TimeoutError):
                    console.command(self.COMMAND.decode())

    def test_stale_echo_missing_echo_and_incomplete_prompt_cannot_finish(self):
        history = self.COMMAND + b'old suffix\n\r\n' + self.PROMPT
        for payload in (self.PROMPT, b'EL0 request queued\r\n' + self.PROMPT,
                        b'posix exec cosmic-comp' + b'suffix\n\r\n' + self.PROMPT,
                        self.COMMAND + b'suffix\n\r\n',
                        self.COMMAND + b'suffix\n\r\ncyxia:/>'):
            with self.subTest(payload=payload), replay(subject, payload, history=history) as (console, _):
                with self.assertRaises(TimeoutError):
                    console.command(self.COMMAND.decode())
                self.assertEqual(console.commands[0]['serial_offset'], len(history))

    def test_expected_markers_cannot_come_from_the_background_suffix(self):
        echo = self.COMMAND + b'suffix\n\r\n'
        for payload in (self.COMMAND + b'EXPECTED_OK suffix\n\r\n' + self.PROMPT,
                        b'EXPECTED_OK\n' + echo + self.PROMPT):
            with self.subTest(payload=payload), replay(subject, payload) as (console, _):
                with self.assertRaises(TimeoutError):
                    console.command(self.COMMAND.decode(), [rb'EXPECTED_OK'])
        for payload in (echo + b'EXPECTED_OK\r\n' + self.PROMPT,
                        echo + self.PROMPT + b'\r\nEXPECTED_OK\r\n'):
            with replay(subject, payload) as (console, _):
                self.assertEqual(console.command(self.COMMAND.decode(), [rb'EXPECTED_OK']), 9)

    def test_every_original_shell_and_kernel_failure_remains_rejected_after_suffix(self):
        failures = (
            b'error: damaged input; command discarded', b'error: line too long; command discarded',
            b'error: invalid UTF-8', b'error: Capacity', b'error: NotFound',
            b'error: invalid arguments; type help', b'error: user request busy',
            b'error: storage request busy', b'error: user process busy', b'error: unknown command; type help',
            b'ELF start failed: Nomem', b'ELF cosmic-comp start failed: ported feature unavailable',
            b'USER start failed: Again', b'EL0 start failed: Again', b'USER pair failed: Again',
            b'EL0 pair failed: Again', b'USER kill failed: Noent', b'EL0 kill failed: Noent',
        )
        for failure in failures:
            for prefix in (b'', self.PROMPT):
                payload = self.COMMAND + b' background suffix\n\r\n' + prefix + failure + b'\r\n' + self.PROMPT
                with self.subTest(failure=failure, prefix=prefix), replay(subject, payload) as (console, _):
                    with self.assertRaises(ValueError):
                        console.command(self.COMMAND.decode())

    def test_recovered_echo_cannot_substitute_for_missing_or_wrong_program_exit(self):
        launch = b'\r\nELF pid=8 started; ABI=Linux-x86_64-subset image AI_DIRECT model=8197 pages=571\r\n'
        for tail in (b'', launch, launch + b'USER pid=9 Exited code=0\r\n',
                     launch + b'USER pid=8 Exited code=1\r\n', launch + b'USER pid=8 Fault code=139\r\n'):
            with self.subTest(tail=tail), replay(subject, self.SHELL + tail) as (console, _):
                with self.assertRaises(TimeoutError):
                    console.program(self.COMMAND.decode())
        with replay(subject, self.SHELL + b'\r\nELF start failed: Nomem\r\n') as (console, _):
            with self.assertRaises(ValueError):
                console.program(self.COMMAND.decode())

    def test_complete_command_is_literal_even_when_it_contains_regex_characters(self):
        command = b'cat /tmp/a[1].txt'
        with replay(subject, command + b'suffix\n\r\n' + self.PROMPT) as (console, _):
            self.assertEqual(console.command(command.decode()), 9)
        with replay(subject, b'cat /tmp/a1.txtsuffix\n\r\n' + self.PROMPT) as (console, _):
            with self.assertRaises(TimeoutError):
                console.command(command.decode())

    def test_only_console_command_changes_and_all_original_acceptance_bodies_are_preserved(self):
        original = Path(legacy_subject.__file__).read_text()
        candidate = Path(subject.__file__).read_text()
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),
                         'dfddc1f071ced0a491bfa09e6664cacde87e5ac87d15f836d2a8dcea14555058')
        self.assertEqual(hashlib.sha256(Path(legacy.__file__).read_bytes()).hexdigest(),
                         'c931cdb9496efcabbef7d543769b8bcf340823b29288236aac7fd6b3a9b3c8f3')
        def functions(source):
            found = {}
            class Collect(ast.NodeVisitor):
                def __init__(self): self.scope = []
                def visit_ClassDef(self, node):
                    self.scope.append(node.name)
                    self.generic_visit(node)
                    self.scope.pop()
                def visit_FunctionDef(self, node):
                    name = '.'.join(self.scope + [node.name])
                    assert name not in found
                    found[name] = ast.get_source_segment(source, node)
                    self.scope.append(node.name)
                    self.generic_visit(node)
                    self.scope.pop()
            Collect().visit(ast.parse(source))
            return found
        old_functions, new_functions = functions(original), functions(candidate)
        self.assertEqual(set(old_functions), set(new_functions))
        self.assertEqual(len(old_functions), 50)
        self.assertEqual([name for name in old_functions if old_functions[name] != new_functions[name]], ['Console.command'])
        self.assertEqual(original.replace(old_functions['Console.command'], '<COMMAND>', 1),
                         candidate.replace(new_functions['Console.command'], '<COMMAND>', 1))
        for name, value in [('FIRST_FRAME_SECONDS', 45), ('LATE_FRAME_SECONDS', 120),
                            ('MAX_WALL_SECONDS', 240), ('MAX_OUTPUT_BYTES', 96 * 1024**2),
                            ('MAX_FRAMES', 24), ('MAX_DIAGNOSTIC_LOG_BYTES', 24 * 1024**2)]:
            self.assertEqual(getattr(subject, name), value)
            self.assertEqual(getattr(subject, name), getattr(legacy_subject, name))


if __name__ == '__main__':
    unittest.main()
