import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import cosmic_ports as ports


def elf(machine=183, kind=1):
    data = bytearray(64)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, kind, machine)
    return bytes(data)


def archive(*members):
    result = bytearray(b'!<arch>\n')
    for name, data in members:
        result.extend(f'{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(data):<10}`\n'.encode())
        result.extend(data)
        if len(data) % 2:
            result.extend(b'\n')
    return bytes(result)


class CosmicPortsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manifest = ports.load_manifest()

    def tearDown(self):
        self.temporary.cleanup()

    def load(self, manifest):
        path = self.root / 'manifest.json'
        path.write_text(json.dumps(manifest))
        return ports.load_manifest(path)

    def local_source(self):
        path = self.root / 'component'
        subprocess.run(['git', 'init', '--quiet', str(path)], check=True)
        (path / 'README').write_text('upstream fixture\n')
        subprocess.run(['git', '-C', str(path), 'add', 'README'], check=True)
        subprocess.run(['git', '-C', str(path), '-c', 'user.name=Port Test',
                        '-c', 'user.email=port-test@example.invalid', 'commit', '--quiet', '-m', 'fixture'], check=True)
        url = 'https://github.com/pop-os/cosmic-comp.git'
        subprocess.run(['git', '-C', str(path), 'remote', 'add', 'origin', url], check=True)
        commit = ports.git(path, 'rev-parse', 'HEAD')
        return {'name': 'component', 'directory': 'component', 'repository': url, 'commit': commit}

    def test_real_manifest_uses_epoch_pin_not_initial_audit(self):
        comp = next(p for p in self.manifest['components'] if p['name'] == 'cosmic-comp')
        self.assertEqual(comp['commit'], '41497b42d9744d9963c4c6d17e8add49489b45ee')
        self.assertNotEqual(comp['commit'], self.manifest['initial_comp_audit']['commit'])
        self.assertEqual(len(self.manifest['components']), 30)
        self.assertEqual(len(self.manifest['compositor']['cargo_git_sources']), 14)
        self.assertEqual(self.manifest['epoch_unlinked_submodules'][0]['name'], 'simple-wrapper')

    def test_mutable_pin_and_duplicate_and_escaping_paths_rejected(self):
        for key, value in [('commit', 'master'), ('directory', '../outside'),
                           ('directory', '/absolute'), ('repository', 'file:///tmp/source'),
                           ('repository', 'https://user:pass@github.com/pop-os/cosmic-comp')]:
            manifest = copy.deepcopy(self.manifest)
            manifest['components'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ports.PortError):
                self.load(manifest)
        manifest = copy.deepcopy(self.manifest)
        manifest['components'].append(manifest['components'][0])
        with self.assertRaisesRegex(ports.PortError, 'duplicate'):
            self.load(manifest)

    def test_duplicate_json_and_mutable_cargo_source_rejected(self):
        path = self.root / 'manifest.json'
        path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ports.PortError, 'duplicate'):
            ports.load_manifest(path)
        manifest = copy.deepcopy(self.manifest)
        manifest['compositor']['cargo_git_sources'][0] = 'git+https://github.com/a/b#main'
        with self.assertRaisesRegex(ports.PortError, 'full commit'):
            self.load(manifest)

    def test_source_verifies_exact_commit_origin_and_clean_tree(self):
        source = self.local_source()
        self.assertTrue(ports.inspect_source(self.root, source)['verified'])
        wrong = dict(source, commit='0' * 40)
        self.assertFalse(ports.inspect_source(self.root, wrong)['verified'])
        wrong = dict(source, repository='https://github.com/pop-os/other')
        self.assertFalse(ports.inspect_source(self.root, wrong)['verified'])
        (self.root / 'component/README').write_text('local work preserved')
        with self.assertRaisesRegex(ports.PortError, 'existing source preserved'):
            ports.fetch_source(source, self.root)
        self.assertEqual((self.root / 'component/README').read_text(), 'local work preserved')

    def test_source_subdirectory_cannot_reuse_enclosing_repository(self):
        source = self.local_source()
        (self.root / 'component/nested').mkdir()
        nested = dict(source, directory='nested')
        result = ports.inspect_source(self.root / 'component', nested)
        self.assertFalse(result['verified'])
        self.assertIn('not its own', result['error'])

    def test_existing_verified_fetch_does_not_use_network(self):
        source = self.local_source()
        original = ports.run
        def check_command(args, **kwargs):
            self.assertNotIn('fetch', args)
            return original(args, **kwargs)
        with patch.object(ports, 'run', side_effect=check_command):
            self.assertFalse(ports.fetch_source(source, self.root)['network_used'])

    def test_invalid_fetch_fails_before_creating_cache(self):
        destination = self.root / 'not-created'
        source = dict(self.manifest['epoch'], commit='main')
        with self.assertRaises(ports.PortError):
            ports.fetch_source(source, destination)
        self.assertFalse(destination.exists())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ports.main(['fetch', '--cache', str(destination)]), 2)
        self.assertFalse(destination.exists())

    def test_complete_gitlink_set_and_stale_mapping_are_distinguished(self):
        modules = '[submodule "one"]\n path = one\n url = https://github.com/pop-os/one\n[submodule "stale"]\n\tpath = stale\n    url = https://github.com/pop-os/stale\n'
        tree = '160000 commit ' + 'a' * 40 + '\tone\n100644 blob ' + 'b' * 40 + '\tREADME'
        with patch.object(ports, 'git', side_effect=[modules, tree]):
            pins, stale = ports.epoch_pins(self.root)
        self.assertEqual(pins, {'one': ('a' * 40, 'https://github.com/pop-os/one')})
        self.assertEqual(stale, {'stale': 'https://github.com/pop-os/stale'})

    def test_cargo_hash_change_is_not_hidden_by_matching_package_count(self):
        comp_path = self.root / 'comp'
        comp_path.mkdir()
        (comp_path / 'Cargo.lock').write_text('version = 4\npackage = []\n')
        manifest = copy.deepcopy(self.manifest)
        manifest['compositor'].update(cargo_lock_package_count=0, cargo_git_sources=[])
        sources = [{'name': manifest['epoch']['name'], 'verified': False},
                   {'name': manifest['compositor']['component'], 'verified': True, 'path': str(comp_path)}]
        result = ports.inspect_locks(manifest, self.root, sources)
        self.assertFalse(result['compositor_cargo_lock'])
        self.assertTrue(any('hash/count/git pins' in s for s in result['errors']))

    def test_archive_rejects_host_mixed_empty_and_truncated_objects(self):
        path = self.root / 'libEGL.a'
        for data in [archive(('host.o/', elf(62))), archive(('a.o/', elf()), ('b.o/', elf(62))),
                     b'!<arch>\n', b'!<thin>\n', archive(('a.o/', elf()))[:-1], b'fake library']:
            path.write_bytes(data)
            with self.subTest(data=data[:15]), self.assertRaises(ports.PortError):
                ports.architecture(path)
        path.write_bytes(archive(('a.o/', elf()), ('b.o/', elf())))
        self.assertEqual(ports.architecture(path)['aarch64_objects'], 2)

    def test_rust_metadata_exception_does_not_accept_arbitrary_c_members(self):
        path = self.root / 'libstd.rlib'
        path.write_bytes(archive(('lib.rmeta/', b'rust metadata'), ('std.o/', elf())))
        self.assertEqual(ports.architecture(path, rust_archive=True)['aarch64_objects'], 1)
        with self.assertRaises(ports.PortError):
            ports.architecture(path)
        path.write_bytes(archive(('not-metadata/', b'arbitrary'), ('std.o/', elf())))
        with self.assertRaises(ports.PortError):
            ports.architecture(path, rust_archive=True)

    def test_target_inventory_does_not_accept_host_symlink_or_shared_name(self):
        libdir = self.root / 'sysroot/usr/lib'
        libdir.mkdir(parents=True)
        outside = self.root / 'host-library'
        outside.write_bytes(elf(kind=3))
        (libdir / 'libEGL.so').symlink_to(outside)
        (libdir / 'libGLESv2.so').write_bytes(elf(62, 3))
        rows = ports.inspect_libraries(self.manifest, self.root / 'sysroot')
        for name in ('EGL', 'GLESv2'):
            row = next(p for p in rows if p['name'] == name)
            self.assertFalse(row['target_library_present'])
            self.assertIn('error', row['files'][0])

    def test_rust_printed_target_directory_is_not_installed_std(self):
        with patch.object(ports, 'run', side_effect=['rustc 1.95.0 (fixture)', str(self.root)]):
            result = ports.inspect_rust('aarch64-unknown-linux-musl', '1.93', '/fixture/rustc')
        self.assertTrue(result['minimum_version_met'])
        self.assertFalse(result['std_target_present'])
        (self.root / 'libstd-fixture.rlib').write_bytes(archive(('std.o/', elf())))
        with patch.object(ports, 'run', side_effect=['rustc 1.92.0 (fixture)', str(self.root)]):
            result = ports.inspect_rust('aarch64-unknown-linux-musl', '1.93', '/fixture/rustc')
        self.assertTrue(result['std_target_present'])
        self.assertFalse(result['minimum_version_met'])
        self.assertFalse(result['guest_tested'])

    def test_all_inventory_files_cannot_claim_build_or_runtime_success(self):
        for library in self.manifest['target_libraries']:
            path = self.root / 'sysroot/usr/lib' / library['filenames'][0]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive(('fixture.o/', elf())))
        with patch.object(ports, 'inspect_source', return_value={'name': 'fixture', 'verified': True}), \
                patch.object(ports, 'inspect_locks', return_value={'epoch_components': True, 'compositor_cargo_lock': True}), \
                patch.object(ports, 'inspect_rust', return_value={'std_target_present': True, 'minimum_version_met': True}):
            result = ports.inventory(self.manifest, self.root / 'absent-cache', self.root / 'sysroot')
        self.assertTrue(result['source_pins_verified'])
        self.assertTrue(all(p['target_library_present'] for p in result['target_libraries']))
        self.assertFalse(result['compositor_build_ready'])
        self.assertFalse(result['guest_runtime_ready'])
        self.assertFalse(result['full_cosmic_session_ready'])
        self.assertFalse((self.root / 'absent-cache').exists())
        with patch.object(ports, 'inventory', return_value=result), \
                patch.object(ports, 'fetch_source', side_effect=AssertionError('network mutation')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ports.main(['inventory']), 0)
            self.assertEqual(ports.main(['check']), 1)


if __name__ == '__main__':
    unittest.main()
