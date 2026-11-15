"""Pixman source, target isolation and installation contracts; no native builds."""
import copy
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from tests.host.sdk_fixtures import object_archive

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


class PixmanBuildTests(unittest.TestCase):
    def module(self):
        return importlib.import_module('build_pixman')

    def test_inventory_is_read_only_and_cannot_fetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'absent'
            result = subprocess.run([sys.executable, str(ROOT / 'tools/build_pixman.py'),
                                     'inventory', '--arch', 'x86_64', '--output', str(output)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data['architecture'], 'x86_64')
            self.assertEqual(data['source']['name'], 'pixman')
            self.assertFalse(data['network'])
            self.assertEqual(data['guest_execution'], 'not performed')
            self.assertFalse(output.exists())
            result = subprocess.run([sys.executable, str(ROOT / 'tools/build_pixman.py'),
                                     'inventory', '--fetch'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_build_requires_explicit_sdk_destination(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/build_pixman.py'), 'build'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--output is required', result.stderr)

    def test_package_entry_point_supports_read_only_inventory(self):
        result = subprocess.run([sys.executable, '-m', 'tools.build_pixman', 'inventory'],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['guest_execution'], 'not performed')

    def test_commands_stop_on_timeout_or_growth_before_sdk_publication(self):
        build = self.module()
        for reason, script, timeout, growth in (
            ('deadline', "import time; time.sleep(.6)", .1, 4096),
            ('byte budget', "from pathlib import Path; import time; "
             "Path('growth').write_bytes(b'x' * 32768); time.sleep(.6)", 5, 4096),
            ('byte budget', "import tempfile, time; "
             "f = tempfile.NamedTemporaryFile(); f.write(b'x' * 32768); f.flush(); time.sleep(.6)",
             5, 4096),
        ):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = self.sdk(root, 'x86_64')
                (root / 'logs').mkdir()
                sentinel = root / 'sysroot/usr/lib/libpixman-1.a'
                sentinel.write_bytes(b'existing SDK sentinel')
                with patch.object(build, 'BUILD_TIMEOUT_SECONDS', timeout, create=True), \
                        patch.object(build, 'MAX_NEW_BYTES', growth):
                    builder = build.Builder(root, {}, 1, target)
                with self.assertRaisesRegex(build.BuildError, reason):
                    builder.run([sys.executable, '-c', script + "; "
                                 "from pathlib import Path; Path('continued').write_text('bad')"],
                                'bounded.log', root)
                    build.install_staged(self.stage(root), root / 'sysroot', target, budget=builder)
                self.assertEqual(sentinel.read_bytes(), b'existing SDK sentinel')
                self.assertFalse((root / 'continued').exists())

    def test_scratch_symlink_cannot_escape_counted_output(self):
        build = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / 'outside'
            outside.mkdir()
            output = root / 'output'
            output.mkdir()
            (output / 'pixman-tmp').symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(build.BuildError, 'scratch.*symlink'):
                build.Builder(output, {}, 1, 'x86_64')
            self.assertEqual(list(outside.iterdir()), [])

    def test_commands_share_one_deadline(self):
        build = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'logs').mkdir()
            with patch.object(build, 'BUILD_TIMEOUT_SECONDS', .35, create=True):
                builder = build.Builder(root, {}, 1, 'x86_64')
            builder.run([sys.executable, '-c', 'import time; time.sleep(.05)'], 'first.log', root)
            with self.assertRaisesRegex(build.BuildError, 'deadline'):
                builder.run([sys.executable, '-c', 'import time; time.sleep(.2)'], 'second.log', root)

    def test_prepublication_limits_preserve_existing_sdk(self):
        build = self.module()
        for limit in ('growth', 'deadline', 'reserve'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = self.sdk(root, 'x86_64')
                sentinel = root / 'sysroot/usr/lib/libpixman-1.a'
                sentinel.write_bytes(b'existing SDK sentinel')
                stage = self.stage(root)
                builder = build.Builder(root, {}, 1, target)
                if limit == 'growth':
                    # Current files fit; copying the validated stage would not.
                    builder.max_new_bytes = 1
                elif limit == 'deadline':
                    builder.deadline = time.monotonic() - 1
                else:
                    builder.min_free_bytes = 2 ** 63
                with self.assertRaises(build.BuildError):
                    build.install_staged(stage, root / 'sysroot', target, budget=builder)
                self.assertEqual(sentinel.read_bytes(), b'existing SDK sentinel')
                self.assertFalse((root / 'sysroot/usr/include/pixman-1/pixman.h').exists())

    def test_source_uses_existing_pin_and_rejects_unsafe_inputs(self):
        build = self.module()
        original = json.loads((ROOT / 'ports/libc/pixman-source.json').read_text())
        self.assertEqual(build.load_source(), original)
        for field, value in (('expected_sha256', ''), ('archive_root', '../outside'),
                             ('depends_on', ['host-libpng'])):
            changed = copy.deepcopy(original)
            changed[field] = value
            with tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / 'source.json'
                source.write_text(json.dumps(changed))
                with self.assertRaises((build.BuildError, build.desktop_ports.PortError)):
                    build.load_source(source)

    def sdk(self, root, arch):
        build = self.module()
        target = build.profile_for(arch)
        lib = root / 'sysroot/usr/lib'
        lib.mkdir(parents=True)
        (root / 'bin').mkdir()
        (lib / 'libc.a').write_bytes(object_archive([target.machine]))
        (lib / target.builtins_archive).write_bytes(object_archive([target.machine]))
        target.cc(root).write_text('#!/bin/sh\nexit 1\n')
        (root / 'build-report.json').write_text(json.dumps({
            'target': target.c_target, 'architecture': arch,
            'libc_sha256': build.digest(lib / 'libc.a')}))
        return target

    def test_target_environment_rejects_host_injection_and_keeps_each_isa(self):
        build = self.module()
        for arch in ('x86_64', 'aarch64'):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = self.sdk(root, arch)
                builder = build.Builder(root, {'clang': '/target/clang', 'llvm-ar': '/target/ar'},
                                        1, target)
                injected = {'PKG_CONFIG_PATH': '/host/lib', 'PKG_CONFIG_SYSROOT_DIR': '/host',
                            'PKG_CONFIG_LIBDIR': '/host/lib', 'PKG_CONFIG_ALLOW_SYSTEM_LIBS': '1',
                            'CPATH': '/host/include', 'CFLAGS': '-I/host', 'DESTDIR': '/host',
                            'LIBS': '-lhost', 'LD_PRELOAD': '/host/lib.so',
                            'DYLD_LIBRARY_PATH': '/host/lib', 'RUSTFLAGS': '-L/host'}
                with patch.dict(os.environ, injected):
                    build.target_environment(builder)
                self.assertEqual(builder.env['CC'], str(target.cc(root)))
                self.assertEqual(builder.env['PKG_CONFIG_PATH'], '')
                self.assertEqual(builder.env['PKG_CONFIG_SYSROOT_DIR'], str(root / 'sysroot'))
                for name in ('CPATH', 'CFLAGS', 'DESTDIR', 'LIBS', 'LD_PRELOAD',
                             'DYLD_LIBRARY_PATH', 'RUSTFLAGS', 'PKG_CONFIG_ALLOW_SYSTEM_LIBS'):
                    self.assertNotIn(name, builder.env)
                self.assertIn("needs_exe_wrapper = true", (root / 'pixman-cross.ini').read_text())
                self.assertIn("cpu_family = '" + arch + "'", (root / 'pixman-cross.ini').read_text())

    def test_sdk_identity_rejects_wrong_isa_or_changed_libc(self):
        build = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.sdk(root, 'aarch64')
            with self.assertRaises(ValueError):
                build.sdk_identity(root, build.profile_for('x86_64'))
            (root / 'sysroot/usr/lib/libc.a').write_bytes(object_archive([183, 183]))
            with self.assertRaisesRegex(build.BuildError, 'libc identity'):
                build.sdk_identity(root, build.profile_for('aarch64'))

    def stage(self, root, machine=62):
        stage = root / 'pixman-install'
        for relative in ('usr/lib/libpixman-1.a', 'usr/lib/pkgconfig/pixman-1.pc',
                         'usr/include/pixman-1/pixman.h', 'usr/include/pixman-1/pixman-version.h'):
            path = stage / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(object_archive([machine]) if path.suffix == '.a' else b'package file\n')
        return stage

    def test_only_pixman_files_install_and_existing_libraries_are_preserved(self):
        build = self.module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.sdk(root, 'x86_64')
            existing = root / 'sysroot/usr/lib/libwayland-server.a'
            existing.write_bytes(object_archive([62, 62]))
            before = build.protected_archives(root)
            result = build.install_staged(self.stage(root), root / 'sysroot', target,
                                          budget=build.Builder(root, {}, 1, target))
            self.assertEqual(result['archive']['machine'], 62)
            self.assertEqual(build.protected_archives(root), before)
            self.assertTrue((root / 'sysroot/usr/lib/libpixman-1.a').is_file())

    def test_staged_foreign_archive_extra_library_and_symlink_never_install(self):
        build = self.module()
        for bad in ('foreign', 'extra', 'symlink'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = self.sdk(root, 'x86_64')
                stage = self.stage(root, 183 if bad == 'foreign' else 62)
                if bad == 'extra':
                    (stage / 'usr/lib/libc.a').write_bytes(object_archive([62]))
                elif bad == 'symlink':
                    header = stage / 'usr/include/pixman-1/pixman.h'
                    header.unlink()
                    header.symlink_to(root / 'build-report.json')
                before = build.protected_archives(root)
                with self.assertRaises((ValueError, build.BuildError)):
                    build.install_staged(stage, root / 'sysroot', target,
                                         budget=build.Builder(root, {}, 1, target))
                self.assertEqual(build.protected_archives(root), before)
                self.assertFalse((root / 'sysroot/usr/lib/libpixman-1.a').exists())


if __name__ == '__main__':
    unittest.main()
