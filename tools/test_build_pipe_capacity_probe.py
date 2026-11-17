"""Producer boundary tests using synthetic ELF fixtures, never native evidence."""
import contextlib
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

try:
    from tools import build_pipe_capacity_probe as subject
    from tools import build_sysroot as shared
except ImportError:
    import build_pipe_capacity_probe as subject
    import build_sysroot as shared
from tests.host.sdk_fixtures import object_archive


def executable(machine=62):
    data = bytearray(8192)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, b'\x7fELF\x02\x01\x01' + bytes(9),
                     2, machine, 1, 0x1001000, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x1000000, 0, 8192, 8192, 4096)
    struct.pack_into('<IIQQQQQQ', data, 120, 6, 4, 64, 0x1000040, 0, 112, 112, 8)
    return data


def object_file(machine):
    data = bytearray(64)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 1, machine)
    return data


class Fixture:
    def __init__(self, root, arch='x86_64'):
        self.root = root
        self.target = subject.profile_for(arch)
        self.sdk = root / 'sdk'
        self.output = root / 'new-build'
        self.lib = self.sdk / 'sysroot/usr/lib'
        self.headers = self.sdk / 'sysroot/usr/include'
        self.lib.mkdir(parents=True)
        self.headers.mkdir(parents=True)
        (self.headers / 'stdio.h').write_text('/* structural fixture header */\n')
        for name in ('crt1.o', 'crti.o', 'crtn.o'):
            (self.lib / name).write_bytes(object_file(self.target.machine))
        for name in ('libc.a', self.target.builtins_archive):
            (self.lib / name).write_bytes(object_archive([self.target.machine]))
        self.report = {'status': 'cross-built', 'target': self.target.c_target,
                       'architecture': arch, 'libc_sha256': subject.digest(self.lib / 'libc.a'),
                       'builtins_sha256': subject.digest(self.lib / self.target.builtins_archive)}
        self.save_report()
        self.source = root / 'pipe_capacity_probe.c'
        self.source.write_bytes(subject.SOURCE.read_bytes())
        self.tools = {}
        for name in ('clang', 'rust-lld'):
            tool = root / name
            tool.write_text('host-test fixture; never executed\n')
            self.tools[name] = str(tool)
        self.program = executable(self.target.machine)
        self.failure = None
        self.mutate = lambda: None
        self.calls = []

    def save_report(self):
        (self.sdk / 'build-report.json').write_text(json.dumps(self.report))

    def snapshot(self):
        return {str(path.relative_to(self.sdk)): path.read_bytes()
                for path in self.sdk.rglob('*') if path.is_file()}

    def run(self, builder, command, log, cwd=None):
        self.calls.append(command)
        builder.commands.append(command)
        (builder.output / 'logs' / log).write_text('HOST TEST STUB: ' + log + '\n')
        if log == self.failure:
            raise subject.BuildError('injected compiler failure')
        if log == 'compile.log':
            Path(command[command.index('-o') + 1]).write_bytes(object_file(self.target.machine))
        elif log == 'link.log':
            Path(command[command.index('-o') + 1]).write_bytes(self.program)
            self.mutate()

    def build(self):
        fixture = self
        def run(builder, command, log, cwd=None):
            fixture.run(builder, command, log, cwd)
        with patch.object(subject, 'SOURCE', self.source), \
                patch.object(subject, 'toolchain', return_value=self.tools), \
                patch.object(subject, 'native_lease', side_effect=lambda _: contextlib.nullcontext()), \
                patch.object(subject, 'idle_native_host'), \
                patch.object(subject.Builder, 'run', run):
            return subject.build(self.output, self.sdk, self.target.architecture,
                                 native_lock=self.root / 'native.lock')

    def failed_receipt(self):
        report = json.loads((self.output / subject.RECEIPT).read_text())
        assert report['status'] == 'FAILED'
        assert report['guest_execution'] is False
        assert report['native_acceptance'] is False
        assert not (self.output / subject.EXECUTABLE).exists()
        return report


class PipeCapacityProducer(unittest.TestCase):
    def test_real_validation_binds_sources_sdk_tools_and_elf_without_mutating_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            before = f.snapshot()
            probes = copy.deepcopy(shared.PROBES)
            report = f.build()
            self.assertEqual(report['status'], 'BUILT_NOT_RUN')
            self.assertIs(report['guest_execution'], False)
            self.assertIs(report['native_acceptance'], False)
            self.assertEqual(report['probe']['machine'], 62)
            self.assertEqual(report['probe']['sha256'], subject.digest(f.output / subject.EXECUTABLE))
            self.assertEqual(report['source_sha256'], subject.digest(f.source))
            self.assertEqual(report['sdk']['build_report']['sha256'], subject.digest(f.sdk / 'build-report.json'))
            self.assertIn(str(subject.ROOT / 'tools/build_sysroot.py'), report['producer_inputs'])
            self.assertIn(str(subject.ROOT / 'tools/target_profile.py'), report['producer_inputs'])
            self.assertEqual(report['toolchain']['clang']['sha256'], subject.digest(Path(f.tools['clang'])))
            self.assertEqual(f.snapshot(), before)
            self.assertEqual(shared.PROBES, probes)
            compile_command, link_command = report['commands'][-2:]
            self.assertIn('--target=x86_64-linux-musl', compile_command)
            self.assertIn('-nostdinc', compile_command)
            self.assertIn('elf_x86_64', link_command)
            self.assertIn('-static', link_command)
            self.assertEqual({command[0] for command in f.calls}, set(f.tools.values()))

    def test_arm_profile_keeps_its_real_target_and_machine(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory), 'aarch64')
            report = f.build()
            self.assertEqual(report['probe']['machine'], 183)
            self.assertEqual(report['target'], 'aarch64-linux-musl')
            self.assertIn('--target=aarch64-linux-musl', report['commands'][-2])
            self.assertIn('aarch64elf', report['commands'][-1])

    def test_invalid_sdk_receipt_archives_and_startup_objects_fail_before_compilation(self):
        for mutation in ('target', 'status', 'libc_digest', 'builtins_digest', 'foreign_archive', 'foreign_crt'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                if mutation == 'target': f.report['target'] = 'aarch64-linux-musl'
                elif mutation == 'status': f.report['status'] = 'FAILED'
                elif mutation == 'libc_digest': f.report['libc_sha256'] = '0' * 64
                elif mutation == 'builtins_digest': f.report['builtins_sha256'] = '0' * 64
                elif mutation == 'foreign_archive':
                    (f.lib / f.target.builtins_archive).write_bytes(object_archive([183]))
                elif mutation == 'foreign_crt':
                    (f.lib / 'crt1.o').write_bytes(object_file(183))
                f.save_report()
                with self.assertRaises((subject.BuildError, ValueError)):
                    f.build()
                self.assertEqual(f.calls, [])
                f.failed_receipt()

    def test_foreign_or_writable_executable_outputs_are_not_published(self):
        for mutation in ('foreign', 'wx'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                if mutation == 'foreign': f.program = executable(183)
                else: struct.pack_into('<I', f.program, 68, 7)
                with self.assertRaises(subject.BuildError):
                    f.build()
                f.failed_receipt()

    def test_compiler_failure_preserves_failed_logs_without_touching_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            before = f.snapshot()
            f.failure = 'compile.log'
            with self.assertRaisesRegex(subject.BuildError, 'compiler failure'):
                f.build()
            self.assertIn('compiler failure', f.failed_receipt()['error'])
            self.assertTrue((f.output / 'logs/compile.log').is_file())
            self.assertEqual(f.snapshot(), before)

    def test_post_build_source_header_tool_and_sdk_receipt_changes_are_rejected(self):
        for kind in ('source', 'header', 'tool', 'report'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                f = Fixture(Path(directory))
                path = {'source': f.source, 'header': f.headers / 'stdio.h',
                        'tool': Path(f.tools['clang']), 'report': f.sdk / 'build-report.json'}[kind]
                # Appended whitespace keeps the SDK JSON valid, but changes its identity.
                f.mutate = lambda: path.write_bytes(path.read_bytes() + b'\n')
                with self.assertRaisesRegex(subject.BuildError, 'changed during build'):
                    f.build()
                f.failed_receipt()

    def test_existing_output_and_output_inside_sdk_are_rejected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            f.output.mkdir()
            sentinel = f.output / 'receipt-to-keep'
            sentinel.write_bytes(b'original')
            with self.assertRaisesRegex(subject.BuildError, 'fresh'):
                f.build()
            self.assertEqual(sentinel.read_bytes(), b'original')
            f.output = f.sdk / 'new-build'
            with self.assertRaisesRegex(subject.BuildError, 'separate'):
                f.build()
            self.assertFalse(f.output.exists())

    def test_header_aliases_are_bound_and_cannot_escape_the_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(Path(directory))
            link = f.headers / 'alias.h'
            link.symlink_to('stdio.h')
            report = f.build()
            self.assertEqual(report['sdk']['headers']['alias.h'],
                             {'symlink': 'stdio.h', 'resolved': 'stdio.h'})
            link.unlink()
            link.symlink_to(f.source)
            f.output = f.root / 'second-build'
            with self.assertRaisesRegex(subject.BuildError, 'escapes'):
                f.build()
            f.failed_receipt()


if __name__ == '__main__':
    unittest.main()
