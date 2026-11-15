"""D-Bus build trust boundaries; these tests never compile or execute targets."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    from tools import build_dbus as b
except ImportError:
    import build_dbus as b
from tests.host.sdk_fixtures import object_archive


class DBusBuildContract(unittest.TestCase):
    def test_inventory_is_read_only_and_never_acquires_native_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'must-not-exist'
            with patch.object(b, 'native_lease') as lease, \
                 patch.object(b.desktop_ports, 'fetch') as fetch, \
                 patch.object(b, 'run_bounded') as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(b.main(['inventory', '--output', str(output)]), 0)
            lease.assert_not_called()
            fetch.assert_not_called()
            run.assert_not_called()
            self.assertFalse(output.exists())

    def test_inventory_rejects_fetch_and_build_requires_explicit_fresh_output(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(b, 'native_lease') as lease, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(b.main(['inventory', '--fetch']), 1)
            self.assertEqual(b.main(['build']), 1)
            self.assertEqual(b.main(['build', '--output', temporary]), 1)
        lease.assert_not_called()

    def test_sources_are_pinned_and_expat_reuses_existing_identity(self):
        manifest = b.load_manifest()
        expat, dbus = manifest['packages']
        self.assertEqual([expat['name'], dbus['name']], ['expat', 'dbus'])
        self.assertEqual(expat['version'], '2.7.5')
        self.assertEqual(dbus['version'], '1.16.4')
        self.assertEqual(dbus['expected_sha256'],
                         'd08b05526c2cb7966a5fb79210d6112b1aca3d135f315c1b302e14b4b0297dac')
        source = json.loads(b.MANIFEST.read_text())
        source['dbus']['expected_sha256'] = ''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'manifest.json'
            path.write_text(json.dumps(source))
            with self.assertRaises((b.BuildError, b.desktop_ports.PortError)):
                b.load_manifest(path)

    def test_offline_miss_and_corrupt_cache_never_fall_back_to_network(self):
        package = b.load_manifest()['packages'][-1]
        with tempfile.TemporaryDirectory() as temporary:
            cache, output = Path(temporary) / 'cache', Path(temporary) / 'out'
            output.mkdir()
            with patch.object(b.desktop_ports, 'fetch') as fetch:
                with self.assertRaises(b.desktop_ports.PortError):
                    b.source_record(package, cache, output, fetch=False)
            fetch.assert_not_called()
            directory = b.desktop_ports.destination(cache, package)
            directory.mkdir(parents=True)
            (directory / 'provenance.json').write_text('{}')
            with patch.object(b.desktop_ports, 'fetch') as fetch:
                with self.assertRaises(b.desktop_ports.PortError):
                    b.source_record(package, cache, output, fetch=True)
            fetch.assert_not_called()

    def test_sdk_rejects_foreign_objects_and_changed_producer_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            sdk = Path(temporary)
            lib = sdk / 'sysroot/usr/lib'
            lib.mkdir(parents=True)
            (sdk / 'bin').mkdir()
            (sdk / 'bin/x86_64-linux-musl-cc').write_text('compiler fixture')
            (lib / 'libc.a').write_bytes(object_archive([62]))
            (lib / 'libclang_rt.builtins-x86_64.a').write_bytes(object_archive([62]))
            report = {'target': 'x86_64-linux-musl', 'libc_sha256': b.digest(lib / 'libc.a')}
            (sdk / 'build-report.json').write_text(json.dumps(report))
            target = b.profile_for('x86_64')
            self.assertEqual(b.sdk_identity(sdk, target)['libc']['machine'], 62)
            (lib / 'libclang_rt.builtins-x86_64.a').write_bytes(object_archive([183]))
            with self.assertRaises(ValueError):
                b.sdk_identity(sdk, target)
            (lib / 'libclang_rt.builtins-x86_64.a').write_bytes(object_archive([62]))
            report['libc_sha256'] = '0' * 64
            (sdk / 'build-report.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(b.BuildError, 'libc identity'):
                b.sdk_identity(sdk, target)

    def test_output_must_not_modify_sdk_or_reuse_previous_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk = root / 'sdk'
            sdk.mkdir()
            for output in (sdk, sdk / 'new', root):
                with self.assertRaises(b.BuildError):
                    b.validate_output(output, sdk)
            fresh = root / 'fresh'
            self.assertEqual(b.validate_output(fresh, sdk), fresh.resolve())
            link = root / 'link'
            link.symlink_to(fresh)
            with self.assertRaises(b.BuildError):
                b.validate_output(link, sdk)

    def test_target_environment_discards_host_and_configure_overrides(self):
        poison = {'PKG_CONFIG_PATH': '/host', 'PKG_CONFIG_SYSROOT_DIR': '/host',
                  'LIBS': '-lhost', 'CONFIG_SITE': '/host/site', 'DESTDIR': '/host',
                  'ac_cv_func_getrandom': 'no', 'CFLAGS': '-I/host',
                  'DYLD_INSERT_LIBRARIES': '/host/inject', 'LD_PRELOAD': '/host/inject',
                  'CC_FOR_BUILD': '/host/compiler', 'PYTHONPATH': '/host/python'}
        with patch.dict(os.environ, poison):
            env = b.clean_environment()
        for name in poison:
            self.assertNotIn(name, env)

    def test_sdk_compatibility_links_are_bound_without_following_escaping_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            sdk = root / 'sdk'
            lib = sdk / 'usr/lib'
            lib.mkdir(parents=True)
            (lib / 'libc.a').write_bytes(b'archive fixture')
            (lib / 'libcompat.a').symlink_to('libc.a')
            first = b.file_map(sdk, allow_internal_links=True)
            self.assertEqual(first['usr/lib/libcompat.a'],
                             {'symlink': 'libc.a', 'resolved': 'usr/lib/libc.a', 'kind': 'file'})
            self.assertIn('usr/lib/libc.a', first)
            (lib / 'libcompat.a').unlink()
            (lib / 'libcompat.a').symlink_to('./libc.a')
            self.assertNotEqual(first, b.file_map(sdk, allow_internal_links=True))
            (lib / 'libcompat.a').unlink()
            outside = root / 'outside.a'
            outside.write_bytes(b'archive fixture')
            (lib / 'libcompat.a').symlink_to(outside)
            with self.assertRaisesRegex(b.BuildError, 'escapes'):
                b.file_map(sdk, allow_internal_links=True)

    def test_sdk_dangling_and_escaping_directory_links_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            sdk, outside = root / 'sdk', root / 'outside'
            sdk.mkdir()
            outside.mkdir()
            (outside / 'header.h').write_text('host header')
            link = sdk / 'include'
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(b.BuildError, 'escapes'):
                b.file_map(sdk, allow_internal_links=True)
            link.unlink()
            link.symlink_to('missing')
            with self.assertRaisesRegex(b.BuildError, 'Unresolvable'):
                b.file_map(sdk, allow_internal_links=True)

    def test_retained_licenses_logs_and_generated_configuration_are_revalidated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            contents = {'logs/build.log': 'compiler output', 'licenses/dbus/COPYING': 'license',
                        'dbus-cross.ini': 'target configuration', 'dbus-build/config.h': 'defines'}
            for relative, value in contents.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
            report = {'logs': b.file_map(root / 'logs'),
                      'sources': [{'source': {'identity': {'name': 'dbus'}},
                                   'licenses': b.file_map(root / 'licenses/dbus')}],
                      'dbus': {'cross_file_sha256': b.digest(root / 'dbus-cross.ini'),
                               'config_h_sha256': b.digest(root / 'dbus-build/config.h')}}
            b.validate_evidence(root, report)
            for relative, value in contents.items():
                with self.subTest(relative=relative):
                    path = root / relative
                    path.write_text(value + ' changed')
                    with self.assertRaises(b.BuildError):
                        b.validate_evidence(root, report)
                    path.write_text(value)
            # Equal bytes through a link are still not retained local evidence.
            original = root / 'logs/build.log'
            original.unlink()
            replacement = root / 'same.log'
            replacement.write_text(contents['logs/build.log'])
            original.symlink_to(replacement)
            with self.assertRaises(b.BuildError):
                b.validate_evidence(root, report)

    def test_session_config_preserves_external_authentication_and_no_activation(self):
        self.assertEqual(b.config_identity(b.SESSION_CONFIG)['address'], b.SESSION_ADDRESS)
        config = b.SESSION_CONFIG.read_text()
        for old, new in [('<auth>EXTERNAL</auth>', '<auth>ANONYMOUS</auth>'),
                         ('<type>session</type>', '<type>system</type>'),
                         ('<allow user="0"/>', '<allow user="*"/>'),
                         ('</busconfig>', '<standard_session_servicedirs/></busconfig>')]:
            self.assertIn(old, config)
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'session.conf'
                path.write_text(config.replace(old, new))
                with self.assertRaises(b.BuildError):
                    b.config_identity(path)


if __name__ == '__main__':
    unittest.main()
