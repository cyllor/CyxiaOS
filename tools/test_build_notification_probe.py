"""Host-only producer boundary tests; fixture outputs are never native proof."""
import contextlib
import copy
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

try:
    from tools import build_notification_probe as subject
    from tools import build_sysroot as shared
    from tools.test_build_pipe_capacity_probe import Fixture as SdkFixture, executable
except ImportError:
    import build_notification_probe as subject
    import build_sysroot as shared
    from test_build_pipe_capacity_probe import Fixture as SdkFixture, executable
from tests.host.sdk_fixtures import object_archive


class Fixture(SdkFixture):
    def __init__(self, root, architecture='x86_64'):
        super().__init__(root, architecture)
        self.source = root / 'notification_probe.c'
        self.source.write_bytes(subject.SOURCE.read_bytes())
        self.dbus = root / 'dbus-build'
        stage = self.dbus / 'stage'
        self.stage = stage
        for relative in ('usr/include/dbus-1.0/dbus/dbus.h',
                         'usr/lib/dbus-1.0/include/dbus/dbus-arch-deps.h'):
            path = stage / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('/* HOST TEST: not compiled */\n')
        (stage / 'usr/lib').mkdir(parents=True, exist_ok=True)
        for name in ('libdbus-1.a', 'libexpat.a'):
            (stage / 'usr/lib' / name).write_bytes(object_archive([self.target.machine]))
        self.dbus_report = dict(architecture=architecture, target=self.target.c_target,
            sdk={'path': str(self.sdk)},
            dbus={'archive': self.target.inspect_archive(stage / 'usr/lib/libdbus-1.a')},
            expat={'archive': self.target.inspect_archive(stage / 'usr/lib/libexpat.a')},
            stage_files=subject.build_dbus.file_map(stage),
            session={'address': 'unix:path=/run/user/0/bus', 'authentication': 'EXTERNAL'})
        (self.dbus / 'dbus-build-report.json').write_text(json.dumps(self.dbus_report))
        self.proof = dict(output=str(self.dbus), validated_output=str(self.dbus),
                          report=self.dbus_report, fixture_only=True)
        self.validation_calls = []
        self.validation_error = None

    def validate_dbus(self, path):
        self.validation_calls.append(path)
        if self.validation_error:
            raise subject.BuildError(self.validation_error)
        return copy.deepcopy(self.proof)

    def build(self, *, panel_clear=False):
        fixture = self
        def run(builder, command, log, cwd=None):
            fixture.run(builder, [str(item) for item in command], log, cwd)
        with patch.object(subject, 'SOURCE', self.source), \
                patch.object(subject, 'toolchain', return_value=self.tools), \
                patch.object(subject, 'native_lease', side_effect=lambda _: contextlib.nullcontext()), \
                patch.object(subject, 'idle_native_host'), \
                patch.object(subject.build_dbus, 'validate_build', side_effect=self.validate_dbus), \
                patch.object(subject.Builder, 'run', run):
            return subject.build(self.output, self.sdk, self.dbus, self.target.architecture,
                                 native_lock=self.root / 'native.lock', panel_clear=panel_clear)

    def failed_receipt(self):
        report = json.loads((self.output / subject.RECEIPT).read_text())
        assert report['status'] == 'FAILED'
        assert report['guest_execution'] is False
        assert report['notifications_verified'] is False
        assert report['render_verified'] is False
        assert report['cosmic_session_verified'] is False
        assert not (self.output / subject.EXECUTABLE).exists()
        return report


class NotificationProbeProducer(unittest.TestCase):
    def test_real_gates_bind_target_sdk_original_dbus_validation_and_exact_link_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            sdk_before = fixture.snapshot()
            dbus_before = subject.build_dbus.file_map(fixture.dbus)
            registry = copy.deepcopy(shared.PROBES)
            report = fixture.build()
            self.assertEqual(report['status'], 'BUILT_NOT_RUN')
            for name in ('guest_execution', 'notifications_verified', 'render_verified', 'cosmic_session_verified'):
                self.assertIs(report[name], False)
            self.assertEqual(fixture.validation_calls, [fixture.dbus, fixture.dbus])
            self.assertEqual(report['expected_server']['version'], '1.10.0')
            self.assertEqual(report['capture_window_ms'], 5000)
            self.assertEqual(report['probe']['machine'], 62)
            self.assertEqual(report['probe']['sha256'], subject.file_identity(fixture.output / subject.EXECUTABLE)['sha256'])
            self.assertEqual((fixture.output / subject.EXECUTABLE).stat().st_mode & 0o777, 0o755)
            compile_command, link_command = report['commands'][-2:]
            self.assertIn('--target=x86_64-linux-musl', compile_command)
            self.assertIn('-nostdinc', compile_command)
            self.assertIn(str(fixture.stage / 'usr/include/dbus-1.0'), compile_command)
            self.assertIn(str(fixture.stage / 'usr/lib/dbus-1.0/include'), compile_command)
            self.assertIn(str(fixture.stage / 'usr/lib/libdbus-1.a'), link_command)
            self.assertIn(str(fixture.stage / 'usr/lib/libexpat.a'), link_command)
            self.assertIn('-static', link_command)
            self.assertIn('elf_x86_64', link_command)
            self.assertEqual({c[0] for c in fixture.calls}, set(fixture.tools.values()))
            self.assertEqual(fixture.snapshot(), sdk_before)
            self.assertEqual(subject.build_dbus.file_map(fixture.dbus), dbus_before)
            self.assertEqual(shared.PROBES, registry)
            self.assertIn('tools/build_dbus.py', report['producer_inputs']['python'])
            self.assertIn('tools/build_sysroot.py', report['producer_inputs']['python'])

    def test_arm_uses_actual_arm_archive_and_elf_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory), 'aarch64')
            report = fixture.build()
            self.assertEqual(report['probe']['machine'], 183)
            self.assertIn('aarch64elf', report['commands'][-1])
            self.assertIn('--target=aarch64-linux-musl', report['commands'][-2])

    def test_panel_clear_mode_requires_the_ui_to_close_the_notification(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Fixture(Path(directory)).build(panel_clear=True)
            self.assertIs(report['panel_clear'], True)
            self.assertEqual(report['capture_window_ms'], 0)
            self.assertIn('-DNOTIFICATION_PROBE_PANEL_CLEAR=1', report['commands'][-2])

    def test_bad_dbus_provenance_target_sdk_and_development_inputs_fail_before_compiler(self):
        for mutation in ('provenance', 'arch', 'sdk', 'detached', 'foreign_archive', 'header'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                if mutation == 'provenance': fixture.validation_error = 'original source provenance rejected'
                elif mutation == 'arch': fixture.dbus_report['architecture'] = 'aarch64'
                elif mutation == 'sdk': fixture.dbus_report['sdk']['path'] = str(fixture.root / 'other-sdk')
                elif mutation == 'detached': fixture.proof['output'] = str(fixture.root / 'old-output')
                elif mutation == 'foreign_archive':
                    (fixture.stage / 'usr/lib/libdbus-1.a').write_bytes(object_archive([183]))
                else: (fixture.stage / 'usr/include/dbus-1.0/dbus/dbus.h').write_text('changed')
                with self.assertRaises((subject.BuildError, ValueError)):
                    fixture.build()
                self.assertEqual(fixture.calls, [])
                fixture.failed_receipt()

    def test_source_sdk_dbus_and_compiler_drift_after_link_never_publish(self):
        for mutation in ('source', 'sdk', 'dbus_archive', 'dbus_receipt', 'compiler'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                if mutation == 'source': changed = fixture.source
                elif mutation == 'sdk': changed = fixture.headers / 'stdio.h'
                elif mutation == 'dbus_archive': changed = fixture.stage / 'usr/lib/libdbus-1.a'
                elif mutation == 'dbus_receipt': changed = fixture.dbus / 'dbus-build-report.json'
                else: changed = Path(fixture.tools['clang'])
                fixture.mutate = lambda: changed.write_bytes(changed.read_bytes() + b'changed')
                with self.assertRaises((subject.BuildError, ValueError)):
                    fixture.build()
                fixture.failed_receipt()

    def test_compiler_failure_and_foreign_or_wx_elf_keep_failed_evidence(self):
        for mutation in ('compile', 'foreign', 'wx'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                if mutation == 'compile': fixture.failure = 'compile.log'
                elif mutation == 'foreign': fixture.program = executable(183)
                else: struct.pack_into('<I', fixture.program, 68, 7)
                before = fixture.snapshot()
                with self.assertRaises(subject.BuildError):
                    fixture.build()
                fixture.failed_receipt()
                self.assertEqual(before, fixture.snapshot())
                self.assertIn('compile.log', subject.build_dbus.file_map(fixture.output / 'logs'))

    def test_existing_nested_and_linked_output_cannot_touch_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            for path in (fixture.sdk / 'new-output', fixture.dbus / 'new-output', fixture.root):
                with self.assertRaises(subject.BuildError):
                    subject.validate_output(path, fixture.sdk, fixture.dbus)
            link = fixture.root / 'alias'
            link.symlink_to(fixture.sdk, target_is_directory=True)
            with self.assertRaises(subject.CosmicBuildError):
                subject.validate_output(link / 'new-output', fixture.sdk, fixture.dbus)
            self.assertFalse((fixture.sdk / 'new-output').exists())
            self.assertFalse((fixture.dbus / 'new-output').exists())

    def test_invalid_sdk_stops_before_dbus_validation_or_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.report['status'] = 'failed'
            fixture.save_report()
            with self.assertRaises(subject.BuildError):
                fixture.build()
            self.assertEqual(fixture.validation_calls, [])
            self.assertEqual(fixture.calls, [])
            fixture.failed_receipt()

    def test_subprocess_budget_is_total_and_no_target_execution_is_added(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            builder = subject.Builder(path, {}, subject.profile_for('x86_64'))
            with patch.object(subject, 'run_bounded') as bounded:
                builder.run(['compiler', 'compile-only'], 'compile.log')
                args = bounded.call_args.args
                self.assertEqual(args[0], ['compiler', 'compile-only'])
                self.assertGreater(args[4], 0)
                self.assertLessEqual(args[4], subject.TIMEOUT_SECONDS)
                self.assertEqual(args[5:7], (subject.MIN_FREE_BYTES, subject.MAX_OUTPUT_BYTES))
                builder.deadline = time.monotonic() - 1
                with self.assertRaisesRegex(subject.BuildError, 'deadline'):
                    builder.run(['compiler'], 'late.log')
                self.assertEqual(bounded.call_count, 1)


if __name__ == '__main__':
    unittest.main()
