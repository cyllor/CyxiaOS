"""Host-only xkbcommon producer contract tests; fixture archives are not builds.

The build-state tests replace command execution and source extraction explicitly.
They exercise real validation, staging, receipts and input-preservation checks;
no compiler, native Bison, acquisition, target executable or guest is run.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import build_xkbcommon_x11_target as b
from tests.host.sdk_fixtures import object_archive


class XkbTargetContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.target = b.profile_for('x86_64')
        self.sdk = self.root / 'input'
        self.lib = self.sdk / 'sysroot/usr/lib'
        self.lib.mkdir(parents=True)
        (self.sdk / 'sysroot/usr/include').mkdir()
        (self.sdk / 'bin').mkdir()
        self.host = self.root / 'host'
        self.host.mkdir()
        self.resource = self.host / 'resource/include'
        self.resource.mkdir(parents=True)
        (self.resource / 'stddef.h').write_text('header fixture; not used to compile')
        self.tools = {}
        for name in ('clang', 'rust-lld', 'llvm-ar', 'llvm-strip', 'pkg-config', 'ninja', 'm4'):
            path = self.host / name
            path.write_text('#!/bin/sh\nexit 99\n')
            path.chmod(0o755)
            self.tools[name] = str(path)
        self.build_tools = self.root / 'build-tools'
        (self.build_tools / 'bin').mkdir(parents=True)
        meson = self.build_tools / 'bin/meson'
        meson.write_text('#!/bin/sh\nexit 99\n')
        meson.chmod(0o755)
        for name in ('libc.a', self.target.builtins_archive, 'libXau.a', 'libxcb.a', 'libxcb-xkb.a'):
            (self.lib / name).write_bytes(object_archive([62]))
        for name, command in {
            'ld.lld': [self.tools['rust-lld'], '-flavor', 'gnu'],
            'x86_64-linux-musl-ar': [self.tools['llvm-ar']],
            'x86_64-linux-musl-ranlib': [self.tools['llvm-ar'], 's'],
        }.items():
            (self.sdk / 'bin' / name).write_text('#!/bin/sh\nexec ' + shlex.join(command) + ' "$@"\n')
        self.write_driver(self.sdk)
        self.report = {'status': 'cross-built', 'target': self.target.c_target,
                       'architecture': 'x86_64', 'toolchain': self.tools,
                       'libc_sha256': b.digest(self.lib / 'libc.a'),
                       'builtins_sha256': b.digest(self.lib / self.target.builtins_archive),
                       'driver_sha256': b.digest(self.target.cc(self.sdk))}
        self.write_report()
        self.bison = self.root / 'bison'
        for relative, value in {
            'bin/bison': '#!/bin/sh\nexit 99\n',
            'share/bison/skeletons/yacc.c': 'genuine-data-contract fixture',
            'share/bison/m4sugar/m4sugar.m4': 'macro fixture',
        }.items():
            path = self.bison / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        (self.bison / 'bin/bison').chmod(0o755)
        self.bison_report = self.root / 'bison-origin.json'
        self.bison_record = {
            'status': 'cross-built', 'manifest_sha256': b.digest(b.MANIFEST),
            'native_bison': {'sha256': b.digest(self.bison / 'bin/bison'),
                             'version': 'bison (GNU Bison) 3.8.2'},
            'sources': [{'source': {'identity': {'name': 'bison'}, 'sha256': b.BISON_SHA256}}],
        }
        self.bison_report.write_text(json.dumps(self.bison_record))
        self.cache = self.root / 'cache'
        self.cache.mkdir()

    def write_driver(self, sdk):
        cc = [self.tools['clang'], *self.target.clang_args, '-nostdinc', '-isystem',
              str(sdk / 'sysroot/usr/include'), '-isystem', str(self.resource)]
        b.sdk_tools.Builder.write_cc_wrapper(SimpleNamespace(output=sdk, target=self.target),
                                             cc, sdk / 'sysroot/usr/lib', sdk / 'bin/ld.lld')

    def write_report(self):
        (self.sdk / 'build-report.json').write_text(json.dumps(self.report))

    def arguments(self, output=None):
        return SimpleNamespace(arch='x86_64', sysroot=self.sdk, cache=self.cache,
                               bison_prefix=self.bison, bison_report=self.bison_report,
                               output=output or self.root / 'fresh', jobs=1,
                               native_lock=self.root / 'unused.lock')

    def test_reviewed_source_pin_is_shared_with_original_producer(self):
        package = b.load_manifest()
        self.assertEqual(package['expected_sha256'], b.SOURCE_SHA256)
        self.assertEqual(package['host_tools'][0]['expected_sha256'], b.BISON_SHA256)
        package['expected_sha256'] = 'a' * 64
        changed = self.root / 'manifest.json'
        changed.write_text(json.dumps(package))
        with self.assertRaisesRegex(b.BuildError, 'reviewed'):
            b.load_manifest(changed)

    def test_missing_or_foreign_native_archives_fail_before_commands(self):
        for content in (None, object_archive([183]), object_archive([62, 183]), b'!<arch>\n'):
            with self.subTest(content=content):
                path = self.lib / 'libxcb-xkb.a'
                if content is None:
                    path.unlink()
                else:
                    path.write_bytes(content)
                with self.assertRaises((OSError, ValueError)):
                    b.sdk_identity(self.sdk, self.target)

    def test_core_report_and_actual_archives_must_agree(self):
        self.report['libc_sha256'] = '0' * 64
        self.write_report()
        with self.assertRaisesRegex(b.BuildError, 'core library'):
            b.sdk_identity(self.sdk, self.target)

    def test_unrecorded_driver_change_is_not_accepted_as_relocation(self):
        with self.target.cc(self.sdk).open('a') as handle:
            handle.write('# changed\n')
        with self.assertRaises(OSError):
            b.sdk_identity(self.sdk, self.target)

    def test_driver_must_match_frozen_generator_and_current_sdk_paths(self):
        path = self.target.cc(self.sdk)
        original = path.read_text()
        for changed in (original + '\n# injection\n', original.replace(str(self.sdk / 'sysroot'), '/foreign/sdk')):
            with self.subTest(changed=changed[-45:]):
                path.write_text(changed)
                with self.assertRaises(b.BuildError):
                    b.validate_driver(self.sdk, self.target, self.tools['clang'])
        path.write_text(original)
        self.assertEqual(b.validate_driver(self.sdk, self.target, self.tools['clang'])['sha256'], b.digest(path))

    def test_relocated_driver_uses_new_completed_foundation_receipt(self):
        self.report['driver_sha256'] = '0' * 64  # Preserved historical driver.
        self.write_report()
        origin = {'status': 'COPIED_NATIVE_INPUTS_NOT_RUN', 'original_files': {
            'build-report.json': {'sha256': b.digest(self.sdk / 'build-report.json')}}}
        foundation = {'status': 'NATIVE_LIBRARIES_BUILT_NOT_RUN', 'parent_preserved': True,
                      'drivers': {self.target.cc(self.sdk).name: b.digest(self.target.cc(self.sdk))},
                      'sdk_tree': b.base.tree_identity(self.sdk / 'sysroot'),
                      'tools': {name: b.executable(path) for name, path in self.tools.items()},
                      'producers': {'tools/build_sysroot.py': b.digest(b.sdk_tools.__file__)}}
        (self.sdk / 'sdk-base-origin.json').write_text(json.dumps(origin))
        xorg = {'architecture': 'x86_64', 'target_triple': self.target.rust_target,
                'target_archives': {name: self.target.inspect_archive(self.lib / name)
                                    for name in ('libXau.a', 'libxcb.a')}}
        (self.sdk / 'xorg-bootstrap-report.json').write_text(json.dumps(xorg))
        report_path = self.sdk / 'sdk-foundation-report.json'
        report_path.write_text(json.dumps(foundation))
        identity = b.sdk_identity(self.sdk, self.target)
        self.assertIn('sdk-foundation-report.json', identity['reports'])
        foundation['status'] = 'FAILED'
        report_path.write_text(json.dumps(foundation))
        with self.assertRaisesRegex(b.BuildError, 'completed foundation'):
            b.sdk_identity(self.sdk, self.target)
        foundation['steps'] = [{'name': 'xorg', 'status': 'COMPLETED'},
                               {'name': 'zlib', 'status': 'FAILED'}]
        report_path.write_text(json.dumps(foundation))
        identity = b.sdk_identity(self.sdk, self.target)
        self.assertEqual(identity['original_foundation_status'], 'FAILED')
        self.assertEqual(b.document(report_path)['status'], 'FAILED')
        xorg['target_archives']['libxcb.a']['sha256'] = '0' * 64
        (self.sdk / 'xorg-bootstrap-report.json').write_text(json.dumps(xorg))
        with self.assertRaisesRegex(b.BuildError, 'X.Org archive differs'):
            b.sdk_identity(self.sdk, self.target)

    def test_input_sdk_and_existing_outputs_cannot_be_build_destinations(self):
        for output in (self.sdk, self.sdk / 'child', self.root, self.cache / 'child'):
            with self.subTest(output=output):
                with self.assertRaises(b.BuildError):
                    b.validate_output(output, self.sdk, self.cache)
        alias = self.root / 'alias'
        alias.symlink_to(self.root / 'missing')
        with self.assertRaises(b.BuildError):
            b.validate_output(alias, self.sdk)

    def test_bison_requires_original_pin_binary_version_and_actual_data(self):
        self.assertEqual(b.bison_identity(self.bison, self.bison_report)['version'],
                         'bison (GNU Bison) 3.8.2')
        for key in ('sha256', 'version'):
            record = json.loads(json.dumps(self.bison_record))
            record['native_bison'][key] = 'changed'
            self.bison_report.write_text(json.dumps(record))
            with self.assertRaisesRegex(b.BuildError, 'provenance'):
                b.bison_identity(self.bison, self.bison_report)
        self.bison_report.write_text(json.dumps(self.bison_record))
        (self.bison / 'share/bison/skeletons/yacc.c').unlink()
        with self.assertRaises(OSError):
            b.bison_identity(self.bison, self.bison_report)

    @contextlib.contextmanager
    def fake_build(self, mutation=None, foreign_output=False):
        """Only command/extraction boundaries are replaced, never the validators."""
        def unpack(package, record, output):
            source = output / package['archive_root']
            source.mkdir()
            (source / 'LICENSE').write_text('fixture license; no upstream code compiled')
            (source / 'meson.build').write_text('source-contract fixture')
            return source

        def run(builder, command, log, extra=None):
            builder.commands.append([str(value) for value in command])
            text = 'mocked command boundary; no compiler or target was run\n'
            if log == 'bison-version.log':
                text = 'bison (GNU Bison) 3.8.2\n'
            if log == 'clang-resource.log':
                text = str(self.resource.parent) + '\n'
            (builder.output / 'logs' / log).write_text(text)
            if log == 'compile.log' and mutation:
                mutation()
            if log == 'install.log':
                self.assertEqual(extra, {'DESTDIR': str(builder.output / 'stage')})
                for name in b.LIBRARIES:
                    destination = builder.output / 'stage/usr/lib' / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    machine = 183 if foreign_output and name == 'libxkbcommon-x11.a' else 62
                    destination.write_bytes(object_archive([machine]))
                for relative in ('usr/include/xkbcommon/xkbcommon.h', 'usr/include/xkbcommon/xkbcommon-x11.h',
                                 'usr/lib/pkgconfig/xkbcommon.pc', 'usr/lib/pkgconfig/xkbcommon-x11.pc'):
                    path = builder.output / 'stage' / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('fixture header or pkgconfig')

        with patch.object(b, 'native_lease', return_value=contextlib.nullcontext()), \
             patch.object(b, 'idle_native_host'), \
             patch.object(b.desktop_ports, 'verify', return_value={'sha256': b.SOURCE_SHA256}), \
             patch.object(b.desktop_ports, 'fetch', side_effect=AssertionError('Network must not be called')), \
             patch.object(b.sdk_tools, 'unpack', side_effect=unpack), \
             patch.object(b.sdk_tools, 'BUILD_TOOLS', self.build_tools), \
             patch.object(b.shutil, 'which', side_effect=lambda name, **kwargs: self.tools[name]), \
             patch.object(b.base, 'resource_check'), \
             patch.object(b.Builder, 'run', run):
            yield

    def test_success_publishes_both_archives_and_headers_without_touching_inputs(self):
        before = b.file_map(self.sdk)
        with self.fake_build():
            report = b.build(self.arguments())
        output = self.arguments().output
        self.assertEqual(report['status'], 'cross-built')
        self.assertEqual(report['guest_execution'], 'not performed')
        self.assertEqual(report['inputs']['sysroot_files'], b.file_map(self.sdk / 'sysroot'))
        self.assertEqual(before, b.file_map(self.sdk))
        self.assertFalse((output / 'stage').exists())
        self.assertEqual(set(report['libraries']), set(b.LIBRARIES))
        self.assertTrue(all(item['machine'] == 62 for item in report['libraries'].values()))
        self.assertTrue(any(command[-2:] == ['xkbcommon', 'xkbcommon-x11'] for command in report['commands']))
        self.assertEqual(b.validate_build(output), report)
        (output / 'sdk/usr/include/xkbcommon/xkbcommon-x11.h').write_text('changed')
        with self.assertRaisesRegex(b.BuildError, 'evidence changed'):
            b.validate_build(output)

    def test_foreign_result_preserves_failed_evidence_and_never_publishes_sdk(self):
        with self.fake_build(foreign_output=True), self.assertRaises(ValueError):
            b.build(self.arguments())
        output = self.arguments().output
        self.assertFalse((output / 'sdk').exists())
        self.assertEqual(b.document(output / 'build-report.json')['status'], 'failed')
        self.assertTrue((output / 'logs/compile.log').is_file())

    def test_header_mutation_during_build_is_not_hidden_by_unchanged_library_hashes(self):
        header = self.sdk / 'sysroot/usr/include/new.h'
        with self.fake_build(mutation=lambda: header.write_text('changed')), \
             self.assertRaisesRegex(b.BuildError, 'changed during build'):
            b.build(self.arguments())
        self.assertFalse((self.arguments().output / 'sdk').exists())

    def test_bison_data_mutation_during_build_prevents_publication(self):
        skeleton = self.bison / 'share/bison/skeletons/yacc.c'
        with self.fake_build(mutation=lambda: skeleton.write_text('changed')), \
             self.assertRaisesRegex(b.BuildError, 'changed during build'):
            b.build(self.arguments())
        self.assertFalse((self.arguments().output / 'sdk').exists())

    def test_environment_uses_relocated_bison_data_and_only_input_target_pkgconfig(self):
        output = self.root / 'environment'
        for name in ('bin', 'tmp'):
            (output / name).mkdir(parents=True, exist_ok=True)
        inputs = b.sdk_identity(self.sdk, self.target)
        bison = b.bison_identity(self.bison, self.bison_report)
        poison = {'PKG_CONFIG_PATH': '/host', 'PKG_CONFIG_LIBDIR': '/host', 'CC': '/host/cc',
                  'CPATH': '/host/headers', 'DESTDIR': '/host/output', 'PYTHONPATH': '/host/python'}
        with patch.dict(os.environ, poison), patch.object(b.sdk_tools, 'BUILD_TOOLS', self.build_tools), \
             patch.object(b.shutil, 'which', side_effect=lambda name, **kwargs: self.tools[name]):
            builder = b.Builder(self.arguments(), output, self.target, inputs, bison)
        self.assertEqual(builder.env['PATH'].split(os.pathsep)[0], str(self.bison / 'bin'))
        self.assertEqual(builder.env['BISON_PKGDATADIR'], str(self.bison / 'share/bison'))
        self.assertEqual(builder.env['M4'], self.tools['m4'])
        self.assertEqual(builder.env['PKG_CONFIG_SYSROOT_DIR'], str(self.sdk / 'sysroot'))
        for name in ('CC', 'CPATH', 'DESTDIR', 'PYTHONPATH'):
            self.assertNotIn(name, builder.env)
        self.assertIn("cpu_family = 'x86_64'", builder.cross.read_text())
        self.assertIn('needs_exe_wrapper = true', builder.cross.read_text())

    def test_total_deadline_cannot_restart_for_each_subprocess(self):
        builder = object.__new__(b.Builder)
        builder.deadline = 0
        with patch.object(b.base, 'run_bounded') as run, \
             self.assertRaisesRegex(b.BuildError, 'total build deadline'):
            builder.run(['compiler'], 'not-created.log')
        run.assert_not_called()

    def test_explicit_architecture_is_required_and_existing_output_fails_without_lease(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            b.main(['--sysroot', str(self.sdk), '--output', str(self.root / 'fresh')])
        with patch.object(b, 'native_lease') as lease, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(b.main(['--arch', 'x86_64', '--sysroot', str(self.sdk),
                                     '--output', str(self.sdk)]), 1)
        lease.assert_not_called()


if __name__ == '__main__':
    unittest.main()
