"""Source/identity fixtures only: no Cargo, native compiler or guest evidence."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import build_cosmic_notifications_static_v1 as builder
from tools import cosmic_notifications_static_v1 as subject
from tools import install_cosmic_notifications as legacy_install
from tools import prepare_cosmic_notifications_static_v1 as prepare
from tools import test_install_cosmic_notifications as archive_fixture


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


class StaticSourceContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.policy = subject.load_policy()

    def test_policy_and_all_patches_are_exact_reviewed_inputs(self):
        sources = subject.support_sources(subject.PORT / 'source-policy.json', self.policy)
        self.assertEqual(len(sources), 4)
        self.assertEqual(self.policy['resolution']['package_count'], 493)
        self.assertEqual(self.policy['resolution']['workspace_package_count'], 3)
        self.assertEqual(self.policy['resolution']['local_package_count'], 5)
        self.assertIs(self.policy['runtime_verified'], False)
        self.assertEqual(self.policy['features'], ['cyxia-static'])
        copied = self.root / 'port'
        copied.mkdir()
        for path in sources:
            shutil.copyfile(path, copied / Path(path).name)
        self.assertEqual(subject.load_policy(copied / 'source-policy.json'), self.policy)
        with (copied / self.policy['patches'][0]['path']).open('ab') as stream:
            stream.write(b'\nchanged\n')
        with self.assertRaisesRegex(ValueError, 'patch identity changed'):
            subject.support_sources(copied / 'source-policy.json', self.policy)
        write(copied / 'source-policy.json', (copied / 'source-policy.json').read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'Unreviewed'):
            subject.load_policy(copied / 'source-policy.json')

    def test_recipe_retains_exact_features_native_inputs_and_sdk_identity(self):
        recipe = json.loads((subject.PORT / 'native-recipe.json').read_bytes())
        source = {'name': 'cosmic-notifications', 'commit': self.policy['commit']}
        self.assertEqual(subject.validate_recipe(recipe, source, self.policy), recipe)
        cases = []
        for key, value in (('features', []), ('default_features', True), ('target', 'aarch64-unknown-linux-musl'),
                           ('patches', []), ('effective_lock_sha256', '0' * 64), ('source_export_policy', {})):
            changed = copy.deepcopy(recipe); changed[key] = value; cases.append(changed)
        changed = copy.deepcopy(recipe); changed['native_inputs'].pop(); cases.append(changed)
        changed = copy.deepcopy(recipe); changed['static_link_inputs'].pop(); cases.append(changed)
        changed = copy.deepcopy(recipe); changed['native_sdk_origin']['path'] = '../other'; cases.append(changed)
        for changed in cases:
            with self.subTest(recipe=changed), self.assertRaises(ValueError):
                subject.validate_recipe(changed, source, self.policy)

    def test_profile_keeps_original_resource_caps_and_false_runtime(self):
        path = subject.PORT / 'resource-profile.json'
        profile = subject.select_profile(path, 2)
        self.assertEqual((profile['timeout_seconds'], profile['max_build_bytes'], profile['image_bytes'],
                          profile['stack_bytes']), (3600, 3 * 1024**3, 64 * 1024**2, 2 * 1024**2))
        self.assertIs(profile['target_runtime_validated'], False)
        with self.assertRaises(ValueError): subject.select_profile(path, 3)
        changed = json.loads(path.read_bytes())
        changed['build_profiles'][subject.PROFILE]['image_bytes'] *= 2
        alternate = write(self.root / 'resource.json', json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'Unreviewed'):
            subject.select_profile(alternate, 2)

    def test_compiler_environment_preserves_static_flags_and_is_always_offline(self):
        before = {'CARGO_ENCODED_RUSTFLAGS': '-L\x1fnative=/fixture/sdk', 'CARGO_NET_OFFLINE': 'false'}
        after = subject.cargo_environment(before)
        self.assertEqual(after['CARGO_ENCODED_RUSTFLAGS'], '-L\x1fnative=/fixture/sdk\x1f--cfg\x1ftokio_unstable')
        self.assertEqual(after['CARGO_ENCODED_RUSTDOCFLAGS'], '--cfg\x1ftokio_unstable')
        self.assertEqual(after['CARGO_NET_OFFLINE'], 'true')
        self.assertEqual(before['CARGO_NET_OFFLINE'], 'false')
        for field in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                subject.cargo_environment({**before, field: 'unreviewed'})

    def test_read_regular_rejects_alias_special_file_and_excess_bytes(self):
        original = write(self.root / 'regular', b'1234')
        self.assertEqual(subject.read_regular(original, 4), b'1234')
        with self.assertRaises(ValueError): subject.read_regular(original, 3)
        alias = self.root / 'alias'; alias.symlink_to(original)
        with self.assertRaises(ValueError): subject.read_regular(alias)
        directory = self.root / 'directory'; directory.mkdir()
        with self.assertRaises((ValueError, OSError)): subject.read_regular(directory)

    def test_complete_tree_does_not_ignore_cargo_or_target_additions(self):
        directory = self.root / 'tree'; write(directory / 'src/lib.rs', '// fixture\n')
        first = subject.read_tree(directory)
        write(directory / 'target/hidden-input', 'not ignored')
        self.assertNotEqual(subject.read_tree(directory), first)
        (directory / 'alias').symlink_to(directory / 'src/lib.rs')
        with self.assertRaises(ValueError): subject.read_tree(directory)

    def test_producer_inventory_matches_existing_transitive_format(self):
        for entry in ('prepare_cosmic_notifications_static_v1.py', 'build_cosmic_notifications_static_v1.py'):
            path = subject.ROOT / 'tools' / entry
            self.assertEqual(subject.producer_sources(path), legacy_install.producer_sources(path))

    def test_build_rejects_input_overlap_before_invoking_native_tools(self):
        sysroot = self.root / 'sdk'
        with mock.patch.object(builder.toolchain_selection, 'tools_and_sysroot',
                               side_effect=AssertionError('native calls forbidden')) as native:
            with self.assertRaisesRegex(ValueError, 'overlaps an input'):
                builder.perform_build(self.root / 'port/recipe.json', subject.PORT / 'resource-profile.json',
                    sysroot / 'bad-output', sysroot, self.root / 'cargo', self.root / 'sources', 1,
                    rust_root=self.root / 'rust', host_cc=self.root / 'clang')
            native.assert_not_called()
        self.assertFalse(sysroot.exists())

    def test_preparation_rejects_cache_overlap_without_any_export(self):
        with mock.patch.object(subject, 'export_source', side_effect=AssertionError('export forbidden')) as export:
            with self.assertRaisesRegex(ValueError, 'overlaps an input'):
                prepare.prepare(self.root / 'cargo/new', cache=self.root / 'cargo', source_cache=self.root / 'sources')
            export.assert_not_called()


class NativeArchiveSearchContracts(unittest.TestCase):
    """Real files/ar members and frozen environment; no compiler is executed."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.sdk, self.output = self.root / 'sdk', self.root / 'output'
        self.output.mkdir()
        native = []
        for name in subject.NATIVE_NAMES:
            data = archive_fixture.archive() if name.endswith('.a') else archive_fixture.object_bytes()
            path = write(self.sdk / 'sysroot/usr/lib' / name, data)
            native.append({'path': str(path.relative_to(self.sdk)), 'sha256': subject.sha(data)})
        unwind = write(self.root / 'rust/libunwind.a', archive_fixture.archive())
        self.recipe = {'native_inputs': native,
                       'static_link_inputs': ['sysroot/usr/lib/' + name for name in subject.STATIC_NAMES]}
        self.toolchain = {'target': subject.TARGET, **self.recipe,
                          'unwind': {'path': str(unwind), 'sha256': subject.build.digest(unwind)}}
        tools = {name: write(self.root / 'tools' / name, 'Fixture tool file; never executed\n')
                 for name in ('rustc', 'cargo', 'target_cc', 'target_cxx', 'target_ar',
                              'target_ranlib', 'host_cc', 'pkg_config')}
        self.control = self.root / 'control'; self.control.mkdir()
        self.environment = subject.cargo_environment(subject.build.cargo_environment(
            tools, self.toolchain, self.sdk, self.output, self.root / 'cache', self.control))

    def stage(self):
        return subject.stage_native_archives(self.output, self.sdk, self.recipe,
                                             self.toolchain, self.environment)

    def verify(self, record, environment=None):
        return subject.verify_native_archive_search(self.output, self.sdk, self.recipe,
            self.toolchain, record, self.environment if environment is None else environment)

    def test_exact_archives_become_visible_through_the_real_frozen_rustc_search_flag(self):
        flags = self.environment['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')
        search = flags[flags.index('-L') + 1]
        self.assertEqual(search, 'native=' + str(self.output / 'native'))
        directory = Path(search.removeprefix('native='))
        self.assertEqual({path.name for path in directory.iterdir()}, {'libunwind.a'})
        self.assertFalse((directory / 'libxkbcommon.a').exists())
        original_sources = {item['path']: subject.build.digest(self.sdk / item['path'])
                            for item in self.recipe['native_inputs']}
        with mock.patch.object(subprocess, 'run', side_effect=AssertionError('No native invocation')):
            record = self.stage()
            self.assertEqual(self.verify(record), record)
        self.assertEqual(set(record['files']), {'libunwind.a', *subject.STATIC_NAMES})
        for name in subject.STATIC_NAMES:
            self.assertEqual(subject.build.ports.architecture(directory / name, target='x86_64')['kind'],
                             'static-archive')
            self.assertEqual((directory / name).read_bytes(), (self.sdk / 'sysroot/usr/lib' / name).read_bytes())
        self.assertEqual(original_sources, {item['path']: subject.build.digest(self.sdk / item['path'])
                                          for item in self.recipe['native_inputs']})

    def test_missing_extra_modified_or_aliased_staged_archive_is_rejected(self):
        record = self.stage()
        path = self.output / 'native/libxkbcommon.a'; data = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'missing or extra'): self.verify(record)
        path.write_bytes(data + b'changed')
        with self.assertRaisesRegex(ValueError, 'Staged rustc native archive changed'): self.verify(record)
        path.unlink(); path.symlink_to(self.sdk / 'sysroot/usr/lib/libxkbcommon.a')
        with self.assertRaisesRegex(ValueError, 'symlink'): self.verify(record)
        path.unlink(); path.write_bytes(data)
        extra = self.output / 'native/extra'; extra.mkdir()
        with self.assertRaisesRegex(ValueError, 'missing or extra'): self.verify(record)

    def test_wrong_search_directory_duplicate_search_or_ambient_flags_are_rejected(self):
        record = self.stage()
        original = self.environment['CARGO_ENCODED_RUSTFLAGS']
        for value in ('', original.replace('native=' + str(self.output / 'native'), 'native=/wrong'),
                      original + '\x1f-L\x1fnative=/another'):
            with self.subTest(flags=value), self.assertRaises(ValueError):
                self.verify(record, {**self.environment, 'CARGO_ENCODED_RUSTFLAGS': value})
        with self.assertRaisesRegex(ValueError, 'explicit rustc native search'):
            self.verify(record, {**self.environment, 'RUSTFLAGS': '-Lnative=/ambient'})

    def test_source_tamper_or_wrong_architecture_cannot_be_staged(self):
        path = self.sdk / 'sysroot/usr/lib/libxkbcommon.a'
        path.write_bytes(archive_fixture.archive(183))
        with self.assertRaisesRegex(ValueError, 'source changed'): self.stage()
        # A changed report hash cannot turn an aarch64 archive into the target archive.
        for item in self.recipe['native_inputs']:
            if item['path'].endswith('/libxkbcommon.a'):
                item['sha256'] = subject.build.digest(path)
        with self.assertRaisesRegex(ValueError, 'x86_64 ELF'): self.stage()
        self.assertEqual({p.name for p in (self.output / 'native').iterdir()}, {'libunwind.a'})

    def test_staging_cannot_replace_existing_entries_or_rehash_a_changed_receipt(self):
        record = self.stage()
        with self.assertRaisesRegex(ValueError, 'only the frozen environment unwind'): self.stage()
        for key, value in (('schema_version', True), ('directory', str(self.sdk)), ('files', {})):
            changed = copy.deepcopy(record); changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'receipt changed'):
                self.verify(changed)


class RegistryArchiveContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cache = self.root / 'cache'
        self.stem = 'wayland-sys-0.31.11'
        self.source = self.cache / 'registry/src/fixture-index' / self.stem
        self.archive = self.cache / 'registry/cache/fixture-index' / (self.stem + '.crate')
        self.files = {'Cargo.toml': b'[package]\nname="wayland-sys"\nversion="0.31.11"\n',
                      'src/lib.rs': b'// archive identity fixture, not a binding implementation\n',
                      'LICENSE.txt': b'license fixture\n'}
        for name, data in self.files.items(): write(self.source / name, data)
        self.package = {'name': 'wayland-sys', 'version': '0.31.11', 'license_files': ['LICENSE.txt'],
                        'files': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mode': 0o644}
                                  for name, data in self.files.items()},
                        'before_tree_sha256': subject.file_tree(self.files)['sha256']}
        self.pack()

    def pack(self, extra=None):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, data in self.files.items():
                item = tarfile.TarInfo(self.stem + '/' + name); item.size = len(data); item.mode = 0o644
                archive.addfile(item, io.BytesIO(data))
            if extra is not None:
                item, data = extra
                archive.addfile(item, io.BytesIO(data) if data else None)
        packed = stream.getvalue(); write(self.archive, packed)
        self.package['archive_sha256'] = hashlib.sha256(packed).hexdigest()

    def test_complete_matching_archive_and_cache_are_exported_with_license(self):
        write(self.source / '.cargo-ok', b'')
        files, modes, record = subject.registry_snapshot(self.cache, self.package)
        self.assertEqual(files, self.files)
        self.assertEqual(set(modes.values()), {0o644})
        self.assertEqual(record['archive_sha256'], self.package['archive_sha256'])
        self.assertEqual(record['source_tree_sha256'], self.package['before_tree_sha256'])

    def test_archive_checksum_change_is_not_accepted(self):
        self.archive.write_bytes(self.archive.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'checksum changed'):
            subject.registry_snapshot(self.cache, self.package)

    def test_cached_blob_changes_and_untracked_files_are_rejected(self):
        path = self.source / 'src/lib.rs'; original = path.read_bytes()
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'differs from archive'):
            subject.registry_snapshot(self.cache, self.package)
        path.write_bytes(original); write(self.source / 'extra.rs', b'extra')
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            subject.registry_snapshot(self.cache, self.package)

    def test_alias_in_cache_or_archive_is_rejected(self):
        original = self.archive.read_bytes(); outside = write(self.root / 'outside.crate', original)
        self.archive.unlink(); self.archive.symlink_to(outside)
        with self.assertRaises(ValueError): subject.registry_snapshot(self.cache, self.package)
        self.archive.unlink(); self.archive.write_bytes(original)
        member = self.source / 'src/lib.rs'; data = member.read_bytes()
        alias = write(self.root / 'outside.rs', data); member.unlink(); member.symlink_to(alias)
        with self.assertRaises(ValueError): subject.registry_snapshot(self.cache, self.package)

    def test_checksum_valid_tar_traversal_duplicate_and_symlink_are_rejected(self):
        cases = []
        item = tarfile.TarInfo(self.stem + '/../outside'); item.size = 1; cases.append((item, b'x'))
        item = tarfile.TarInfo(self.stem + '/Cargo.toml'); item.size = 1; cases.append((item, b'x'))
        item = tarfile.TarInfo(self.stem + '/linked'); item.type = tarfile.SYMTYPE; item.linkname = '../outside'
        cases.append((item, b''))
        for extra in cases:
            self.pack(extra)
            with self.subTest(member=extra[0].name), self.assertRaises(ValueError):
                subject.registry_snapshot(self.cache, self.package)
        self.assertFalse((self.root / 'outside').exists())

    def test_optional_checksum_manifest_must_match_the_same_complete_archive(self):
        checksum = {'package': self.package['archive_sha256'],
                    'files': {name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()}}
        path = write(self.source / '.cargo-checksum.json', json.dumps(checksum))
        _, _, record = subject.registry_snapshot(self.cache, self.package)
        self.assertIsNotNone(record['checksum_manifest_sha256'])
        checksum['files']['src/lib.rs'] = '0' * 64; path.write_text(json.dumps(checksum))
        with self.assertRaisesRegex(ValueError, 'checksum manifest differs'):
            subject.registry_snapshot(self.cache, self.package)


class ResolutionContracts(unittest.TestCase):
    def setUp(self):
        names = ('cosmic-notifications', 'libcosmic', 'winit', 'wayland-sys', 'xkbcommon-dl')
        sources = (None, 'git+https://example.invalid/libcosmic#' + '1' * 40,
                   'git+https://example.invalid/winit#' + '2' * 40, None, None)
        features = (['cyxia-static'], ['a11y', 'wayland', 'winit', 'multi-window'],
                    ['x11', 'wayland', 'wayland-dlopen'], ['client', 'dlopen', 'once_cell', 'cyxia-static-client'],
                    ['x11', 'static-link'])
        packages = [{'id': name, 'name': name, 'version': 'fixture-1', 'source': source}
                    for name, source in zip(names, sources)]
        edges = ((1, 3, 4), (2,), (3, 4), (), ())
        nodes = [{'id': name, 'features': feature, 'dependencies': [names[i] for i in links],
                  'deps': [{'name': names[i].replace('-', '_'), 'pkg': names[i],
                            'dep_kinds': [{'kind': None, 'target': None}]} for i in links]}
                 for name, feature, links in zip(names, features, edges)]
        self.metadata = {'version': 1, 'packages': packages, 'resolve': {'nodes': nodes},
                         'workspace_members': ['cosmic-notifications']}
        self.policy = {'resolution': {'package_count': 5, 'local_package_count': 3, 'workspace_package_count': 1,
                       'expected_sha256': subject.canonical_hash(subject.normalized_resolution(self.metadata))}}

    def test_resolution_identity_is_independent_of_array_order(self):
        expected = subject.verify_resolution(self.metadata, self.policy)
        changed = copy.deepcopy(self.metadata)
        changed['packages'].reverse(); changed['resolve']['nodes'].reverse()
        for node in changed['resolve']['nodes']:
            node['features'].reverse(); node['deps'].reverse(); node['dependencies'].reverse()
        self.assertEqual(subject.verify_resolution(changed, self.policy), expected)

    def test_gui_accessibility_wayland_and_x11_features_cannot_disappear(self):
        for index, feature in ((1, 'a11y'), (1, 'multi-window'), (2, 'wayland'), (2, 'x11'),
                               (3, 'cyxia-static-client'), (4, 'static-link'), (4, 'x11')):
            changed = copy.deepcopy(self.metadata); changed['resolve']['nodes'][index]['features'].remove(feature)
            with self.subTest(feature=feature), self.assertRaisesRegex(ValueError, 'resolution changed'):
                subject.verify_resolution(changed, self.policy)

    def test_version_source_edge_and_workspace_changes_are_rejected(self):
        cases = []
        changed = copy.deepcopy(self.metadata); changed['packages'][1]['version'] = 'fixture-2'; cases.append(changed)
        changed = copy.deepcopy(self.metadata); changed['packages'][2]['source'] += 'changed'; cases.append(changed)
        changed = copy.deepcopy(self.metadata); changed['workspace_members'].append('wayland-sys'); cases.append(changed)
        changed = copy.deepcopy(self.metadata)
        changed['resolve']['nodes'][0]['dependencies'].remove('xkbcommon-dl')
        changed['resolve']['nodes'][0]['deps'] = [d for d in changed['resolve']['nodes'][0]['deps'] if d['pkg'] != 'xkbcommon-dl']
        cases.append(changed)
        for changed in cases:
            with self.subTest(metadata=changed), self.assertRaises(ValueError):
                subject.verify_resolution(changed, self.policy)

    def test_duplicate_packages_nodes_or_features_cannot_be_hidden_by_canonicalization(self):
        cases = []
        changed = copy.deepcopy(self.metadata); changed['packages'].append(changed['packages'][0]); cases.append(changed)
        changed = copy.deepcopy(self.metadata); changed['resolve']['nodes'].append(changed['resolve']['nodes'][0]); cases.append(changed)
        changed = copy.deepcopy(self.metadata); changed['resolve']['nodes'][0]['features'].append('cyxia-static'); cases.append(changed)
        for changed in cases:
            with self.assertRaises(ValueError): subject.verify_resolution(changed, self.policy)


class LockContracts(unittest.TestCase):
    def setUp(self):
        self.policy = subject.load_policy()
        before = 'version = 4\n\n[[package]]\nname = "cosmic-notifications"\nversion = "1.10.0"\ndependencies = ["libcosmic"]\n'
        after = before.replace('["libcosmic"]', '["libcosmic", "wayland-sys", "xkbcommon-dl"]')
        for package in self.policy['registry_inputs']:
            block = '\n[[package]]\nname = ' + json.dumps(package['name']) + '\nversion = ' + json.dumps(package['version']) + '\n'
            before += block + 'source = ' + json.dumps(package['source']) + '\nchecksum = ' + json.dumps(package['archive_sha256']) + '\n'
            after += block
        extra = '\n[[package]]\nname = "libcosmic"\nversion = "1.0.0"\nsource = "git+https://example.invalid/cosmic#' + '3' * 40 + '"\n'
        self.before, self.after = (before + extra).encode(), (after + extra).encode()

    def test_only_two_local_sources_and_two_root_dependencies_change(self):
        delta = subject.lock_delta(self.before, self.after, self.policy)
        self.assertEqual([p['name'] for p in delta['changed_packages']],
                         ['cosmic-notifications', 'wayland-sys', 'xkbcommon-dl'])
        self.assertEqual(delta['package_count'], 4)
        self.assertIs(delta['cargo_resolution_verified'], False)

    def test_other_package_versions_sources_and_root_dependencies_cannot_change(self):
        for after in (self.after.replace(b'1.0.0', b'2.0.0'), self.after.replace(b'example.invalid', b'other.invalid'),
                      self.after.replace(b', "xkbcommon-dl"', b''), self.after.replace(b'version = 4', b'version = 3')):
            with self.assertRaises(ValueError): subject.lock_delta(self.before, after, self.policy)


@unittest.skipUnless(Path('/usr/bin/git').is_file(), 'real Git required')
class CanonicalGitSourceContracts(unittest.TestCase):
    def test_replacement_tree_cannot_relabel_changed_original_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve() / 'original'; source.mkdir()
            files = {'Cargo.toml': b'[package]\nname="cosmic-notifications"\nversion="1.10.0"\n',
                     'Cargo.lock': b'version=4\n', 'src/main.rs': b'fn main() {} // original fixture\n'}
            for name, data in files.items(): write(source / name, data)
            def git(*args):
                return subprocess.check_output(['/usr/bin/git', '-C', str(source), *args],
                    env=subject.build.clean_environment('/usr/bin:/bin'), stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q'); git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'original')
            git('remote', 'add', 'origin', 'https://github.com/pop-os/cosmic-notifications')
            commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
            policy = {'commit': commit, 'git_tree': tree, 'repository': 'https://github.com/pop-os/cosmic-notifications',
                      'original_tree_sha256': subject.file_tree(files)['sha256'],
                      'source_lock_sha256': hashlib.sha256(files['Cargo.lock']).hexdigest(),
                      'root_before': {'Cargo.toml': hashlib.sha256(files['Cargo.toml']).hexdigest()}}
            self.assertEqual(subject.snapshot_source(source, policy)[0], files)
            write(source / 'src/main.rs', b'fn main() { panic!("replacement fixture"); }\n')
            git('add', '.'); git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'replacement')
            replacement = git('rev-parse', 'HEAD^{tree}')
            git('reset', '--hard', commit); git('replace', tree, replacement); git('reset', '--hard', commit)
            self.assertEqual(git('rev-parse', 'HEAD'), commit)
            with self.assertRaises(ValueError): subject.snapshot_source(source, policy)


if __name__ == '__main__':
    unittest.main()
