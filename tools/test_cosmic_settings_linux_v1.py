"""Host Git/archive/file fixtures only; no Cargo, compiler, daemon or guest."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import build_cosmic_settings_linux_v1 as builder
from tools import cosmic_settings_inputs_v1 as consumer
from tools import install_cosmic_settings_linux_v1 as installer
from tools import test_install_cosmic_notifications as binary_fixture
from tools.test_install_cosmic_notifications_static_v1 import patch_bytes

contract = builder.contract
write, save = binary_fixture.write, binary_fixture.save


class SettingsFixture(unittest.TestCase):
    """Only pin constants and native execution are replaced with explicit fixtures."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source_cache, self.cache, self.sdk = self.root / 'sources', self.root / 'cache', self.root / 'sdk'
        self.source = self.source_cache / 'cosmic-settings-daemon'
        self.comp = self.source_cache / 'cosmic-comp-epoch'
        self.port = self.root / contract.PORT
        self.old_port = self.root / 'ports/cosmic/native-settings'
        self.recipe_path, self.profile_path = self.port / 'native-recipe.json', self.port / 'resource-profile.json'
        self.build_output, self.install_output = self.root / 'build', self.root / 'installed'
        production_policy = contract.read_json(contract.ROOT / contract.PORT / 'source-policy.json')
        production_recipe = contract.read_json(contract.ROOT / contract.PORT / 'native-recipe.json')
        production_resource = (contract.ROOT / contract.PORT / 'resource-profile.json').read_bytes()
        self.registry_files = {}
        self.archive_specs = {}
        for name, version in [('wayland-sys', '0.31.11'), ('fixture-dependency', '1.0.0')]:
            stem = name + '-' + version
            content = {'Cargo.toml': f'[package]\nname="{name}"\nversion="{version}"\n'.encode(),
                       'src/lib.rs': b'// Archive identity fixture only; never compiled.\n',
                       'LICENSE.txt': b'Fixture license only.\n'}
            packed = io.BytesIO()
            with tarfile.open(fileobj=packed, mode='w:gz') as stream:
                for relative, data in content.items():
                    entry = tarfile.TarInfo(stem + '/' + relative)
                    entry.size, entry.mode = len(data), 0o644
                    stream.addfile(entry, io.BytesIO(data))
                    write(self.cache / 'registry/src/fixture' / stem / relative, data)
            archive = write(self.cache / 'registry/cache/fixture' / (stem + '.crate'), packed.getvalue())
            self.registry_files[name] = content
            self.archive_specs[name] = {'name': name, 'version': version,
                'source': 'registry+https://github.com/rust-lang/crates.io-index',
                'archive_sha256': contract.base.digest(archive), 'license_files': ['LICENSE.txt'],
                'files': {key: {'bytes': len(data), 'sha256': contract.files.sha(data), 'mode': 0o644}
                          for key, data in content.items()},
                'before_tree_sha256': contract.files.file_tree(content)['sha256']}
        comp_content = {'Cargo.toml': b'[workspace]\nmembers=["cosmic-comp-config"]\n',
            'cosmic-comp-config/Cargo.toml': b'[package]\nname="cosmic-comp-config"\nversion="1.0.0"\n',
            'cosmic-comp-config/src/lib.rs': b'// Canonical config source fixture only.\n',
            'LICENSE': b'Compositor fixture license.\n'}
        for name, data in comp_content.items(): write(self.comp / name, data)
        self.comp_id = self.git_source(self.comp, 'https://github.com/pop-os/cosmic-comp')
        prefix = ('version=4\n[[package]]\nname="cosmic-settings-daemon"\nversion="1.10.0"\n'
            'dependencies=["cosmic-comp-config","geonames","wayland-sys","fixture-dependency"]\n'
            '[[package]]\nname="cosmic-comp-config"\nversion="1.0.0"\n')
        suffix = '[[package]]\nname="geonames"\nversion="1.10.0"\n'
        registry_lock = ''
        for spec in self.archive_specs.values():
            registry_lock += (f'[[package]]\nname="{spec["name"]}"\nversion="{spec["version"]}"\n'
                              f'source="{spec["source"]}"\nchecksum="{spec["archive_sha256"]}"\n')
        original_lock = prefix + f'source="git+https://github.com/pop-os/cosmic-comp#{self.comp_id["commit"]}"\n' + suffix + registry_lock
        original = {'Cargo.toml': b'[package]\nname="cosmic-settings-daemon"\nversion="1.10.0"\n'
                    b'[workspace]\nmembers=["geonames"]\n',
                    'Cargo.lock': original_lock.encode(),
                    'src/main.rs': b'// Genuine source contract fixture; never compiled or run.\n',
                    'LICENSE': b'Settings fixture license.\n',
                    'geonames/Cargo.toml': b'[package]\nname="geonames"\nversion="1.10.0"\n',
                    'geonames/src/lib.rs': b'// Data crate fixture only.\n'}
        for name, data in original.items(): write(self.source / name, data)
        self.settings_id = self.git_source(self.source, production_policy['repository'])
        effective = dict(original)
        effective['Cargo.toml'] += b'\n[features]\ncyxia-native=[]\n'
        effective['Cargo.lock'] = (prefix + suffix + registry_lock.replace(
            'source="' + self.archive_specs['wayland-sys']['source'] + '"\nchecksum="'
            + self.archive_specs['wayland-sys']['archive_sha256'] + '"\n', '')).encode()
        effective.update({'native-deps/' + name: data for name, data in comp_content.items()
                          if name.startswith('cosmic-comp-config/')})
        effective['native-deps/cosmic-comp-config/LICENSE'] = comp_content['LICENSE']
        effective.update({'native-deps/wayland-sys/' + name: data
                          for name, data in self.registry_files['wayland-sys'].items()})
        effective['native-deps/wayland-sys/Cargo.toml'] += b'\n[features]\ncyxia-static-client=[]\n'
        patch = patch_bytes(original, effective)
        write(self.old_port / 'cosmic-settings-native.patch', patch)
        write(self.port / 'cosmic-settings-native.patch', patch)
        write(self.old_port / 'fixture-support.txt', 'Source fixture support; no native implementation.\n')
        supports = {'ports/cosmic/native-settings/fixture-support.txt': contract.base.digest(self.old_port / 'fixture-support.txt')}
        changed = {name for name in original.keys() | effective.keys() if original.get(name) != effective.get(name)}
        manifest = {'component': contract.COMPONENT, 'repository': production_policy['repository'],
            'commit': self.settings_id['commit'], 'source_lock_sha256': contract.files.sha(original['Cargo.lock']),
            'effective_lock_sha256': contract.files.sha(effective['Cargo.lock']),
            'patch_sha256': contract.files.sha(patch), 'support_inputs': supports,
            'source_inputs': {'settings': self.old_identity(self.settings_id), 'compositor': self.old_identity(self.comp_id)},
            'registry_inputs': {'wayland-sys': {'archive_sha256': self.archive_specs['wayland-sys']['archive_sha256'],
                'files': {name: contract.files.sha(data) for name, data in self.registry_files['wayland-sys'].items()}}},
            'before': {name: contract.files.sha(original[name]) if name in original else None for name in sorted(changed)},
            'after': {name: contract.files.sha(effective[name]) if name in effective else None for name in sorted(changed)}}
        manifest_path = save(self.old_port / 'native-patch.json', manifest)
        self.policy = {**production_policy, 'commit': self.settings_id['commit'], 'git_tree': self.settings_id['git_tree'],
            'source_lock_sha256': manifest['source_lock_sha256'], 'effective_lock_sha256': manifest['effective_lock_sha256'],
            'patch_manifest': {'path': str(manifest_path.relative_to(self.root)), 'sha256': contract.base.digest(manifest_path)},
            'original_patch': {'path': 'ports/cosmic/native-settings/cosmic-settings-native.patch', 'sha256': contract.files.sha(patch)},
            'support_inputs': supports,
            'compositor': {**production_policy['compositor'], 'commit': self.comp_id['commit'], 'git_tree': self.comp_id['git_tree']},
            'registry_inputs': [self.archive_specs['wayland-sys']]}
        save(self.port / 'source-policy.json', self.policy)
        self.component = {'name': contract.COMPONENT, 'directory': self.policy['directory'],
                          'repository': self.policy['repository'], 'commit': self.policy['commit']}
        self.create_sdk()
        self.recipe = {**production_recipe, 'commit': self.policy['commit'],
            'source_lock_sha256': self.policy['source_lock_sha256'], 'effective_lock_sha256': self.policy['effective_lock_sha256'],
            'patches': [{'path': 'cosmic-settings-native.patch', 'sha256': contract.files.sha(patch)}],
            'native_inputs': self.native,
            'native_sdk_origin': {'path': 'runtime-sdk-origin.json', 'sha256': contract.base.digest(self.sdk / 'runtime-sdk-origin.json')}}
        save(self.recipe_path, self.recipe)
        write(self.profile_path, production_resource)
        for owner, name, value in [(contract, 'ROOT', self.root),
            (contract, 'POLICY_SHA256', contract.base.digest(self.port / 'source-policy.json')),
            (contract, 'RECIPE_SHA256', contract.base.digest(self.recipe_path))]:
            patcher = mock.patch.object(owner, name, value); patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(contract.base.ports, 'load_manifest', return_value={'components': [self.component]})
        patcher.start(); self.addCleanup(patcher.stop)
        self.profile = contract.contract(self.recipe_path, self.profile_path, 1)[3]

    def git_source(self, path, repository):
        for args in [('init', '-q'), ('add', '.'),
            ('-c', 'user.name=Settings Test', '-c', 'user.email=settings@example.invalid', 'commit', '-qm', 'Host fixture only'),
            ('remote', 'add', 'origin', repository)]:
            subprocess.run(['/usr/bin/git', '-C', str(path), *args], check=True, capture_output=True,
                           env=contract.base.clean_environment('/usr/bin:/bin'))
        commit = contract.common.objects.pinned_git(path, 'rev-parse', 'HEAD')
        return contract.common.git_identity(path, commit)

    @staticmethod
    def old_identity(identity):
        inventory = {name: row['sha256'] for name, row in identity['files'].items()}
        return {'commit': identity['commit'], 'git_tree': identity['git_tree'], 'files': inventory,
                'tree_sha256': contract.canonical(inventory)}

    def create_sdk(self):
        self.native = []
        for name in contract.NATIVE_NAMES:
            data = binary_fixture.archive() if name.endswith('.a') else binary_fixture.object_bytes()
            path = write(self.sdk / 'sysroot/usr/lib' / name, data)
            self.native.append({'path': str(path.relative_to(self.sdk)), 'sha256': contract.files.sha(data)})
        save(self.sdk / 'runtime-sdk-origin.json', {'fixture_only': True})
        self.rust = self.root / 'rust'
        self.libdir = self.rust / 'lib/rustlib' / contract.TARGET / 'lib'
        std = write(self.libdir / 'libstd-ab12.rlib', binary_fixture.archive())
        unwind = write(self.libdir / 'self-contained/libunwind.a', binary_fixture.archive())
        write(self.libdir / 'libcore-ab12.rlib', binary_fixture.archive())
        host = 'x86_64-unknown-linux-gnu'
        self.tools = {'rustc': self.rust / 'bin/rustc', 'cargo': self.rust / 'bin/cargo',
            'target_cc': self.sdk / 'bin/x86_64-linux-musl-cc', 'target_cxx': self.sdk / 'bin/x86_64-linux-musl-cxx',
            'target_ar': self.sdk / 'bin/x86_64-linux-musl-ar', 'target_ranlib': self.sdk / 'bin/x86_64-linux-musl-ranlib',
            'host_cc': self.root / 'host/clang', 'strip': self.rust / 'lib/rustlib' / host / 'bin/llvm-strip',
            'pkg_config': self.root / 'host/pkg-config'}
        for name, path in self.tools.items():
            if name != 'target_cxx':
                write(path, 'Host identity fixture only; never executed: ' + name); path.chmod(0o755)
        self.identities = {'target': contract.TARGET, 'architecture': 'x86_64', 'host': host,
            'selection': {'schema_version': 1, 'rust_root': str(self.rust), 'host_cc': str(self.tools['host_cc'])},
            'rustc_version': 'rustc 1.95.0 fixture-only\nhost: ' + host + '\nrelease: 1.95.0\n',
            'host_cc_version': 'clang version 19.1.7 fixture-only\n',
            'std': {'path': str(std), 'sha256': contract.base.digest(std)},
            'unwind': {'path': str(unwind), 'sha256': contract.base.digest(unwind)},
            'native_inputs': self.native, 'static_link_inputs': ['sysroot/usr/lib/' + name for name in contract.STATIC_NAMES],
            'tools': {name: {'path': str(path), 'sha256': contract.base.digest(path) if path.exists() else None,
                             'available': path.exists()} for name, path in self.tools.items()}}

    def metadata(self, stage, output):
        packages = []
        for name, version, relative in [('cosmic-settings-daemon', '1.10.0', 'Cargo.toml'),
            ('cosmic-comp-config', '1.0.0', 'native-deps/cosmic-comp-config/Cargo.toml'),
            ('wayland-sys', '0.31.11', 'native-deps/wayland-sys/Cargo.toml'),
            ('geonames', '1.10.0', 'geonames/Cargo.toml')]:
            package = {'name': name, 'version': version, 'id': 'path+' + (stage / relative).parent.as_uri() + '#' + name,
                'source': None, 'manifest_path': str(stage / relative), 'targets': []}
            if name == contract.COMPONENT:
                package['targets'] = [{'name': name, 'kind': ['bin'], 'src_path': str(stage / 'src/main.rs')}]
            packages.append(package)
        spec = self.archive_specs['fixture-dependency']
        packages.append({'name': spec['name'], 'version': spec['version'], 'id': 'fixture-registry-dependency',
            'source': spec['source'], 'manifest_path': str(self.cache / 'registry/src/fixture/fixture-dependency-1.0.0/Cargo.toml'),
            'targets': []})
        edges = [{'name': row['name'].replace('-', '_'), 'pkg': row['id'], 'dep_kinds': [{'kind': None, 'target': None}]}
                 for row in packages[1:]]
        features = [['cyxia-native'], [], ['client', 'cyxia-static-client', 'dlopen'], [], []]
        return {'version': 1, 'workspace_root': str(stage), 'target_directory': str(output / 'target'),
            'workspace_members': [packages[0]['id'], packages[3]['id']], 'packages': packages,
            'resolve': {'nodes': [{'id': row['id'], 'features': feature,
                'dependencies': [edge['pkg'] for edge in edges] if index == 0 else [],
                'deps': edges if index == 0 else []} for index, (row, feature) in enumerate(zip(packages, features))]}}

    def run_builder(self, action='build', *, output=None, hook=None):
        output = output or self.build_output
        def cargo_fixture(command, control, environment, log, *args, **kwargs):
            stage = Path(command[command.index('--manifest-path') + 1]).parent
            self.assertEqual(environment['CARGO_NET_OFFLINE'], 'true')
            self.assertIn('--locked', command); self.assertIn('--offline', command)
            if command[1] == 'metadata':
                save(Path(log), self.metadata(stage, output))
                write(Path(kwargs['stderr_log']), '')
            else:
                self.assertEqual(command[1], 'build')
                write(Path(log), 'HOST FILE FIXTURE ONLY; Cargo/native programs were not executed.\n')
                write(output / 'target' / contract.TARGET / 'release' / contract.COMPONENT, binary_fixture.elf())
            if hook is not None:
                hook(command[1], stage, output)
        with mock.patch.object(contract.common.selection, 'tools_and_sysroot', return_value=(self.tools, self.identities)), \
             mock.patch.object(contract.base, 'run_bounded', side_effect=cargo_fixture):
            return builder.perform(action, self.recipe_path, self.profile_path, output, self.sdk,
                self.source_cache, self.cache, self.rust, self.tools['host_cc'], 1)


class FixedSettingsContract(unittest.TestCase):
    def test_original_patch_and_resource_caps_remain_exact(self):
        port = contract.ROOT / contract.PORT
        policy, recipe, source, profile = contract.contract(port / 'native-recipe.json', port / 'resource-profile.json', 2)
        self.assertEqual((port / 'cosmic-settings-native.patch').read_bytes(),
                         (contract.ROOT / policy['original_patch']['path']).read_bytes())
        self.assertEqual(source['commit'], '9e4ae69fc175191f15789d35423806ea0f093c9d')
        self.assertEqual((profile['timeout_seconds'], profile['max_build_bytes'], profile['jobs_max']),
                         (1200, 1536 * 1024**2, 2))
        self.assertEqual(recipe['features'], ['cyxia-native'])
        self.assertEqual(policy['boundary']['audio_mutations'], 'org.freedesktop.DBus.Error.NotSupported')
        self.assertEqual(policy['boundary']['brightness_unavailable_value'], -1)
        self.assertIs(policy['boundary']['audio_varlink_service'], False)
        self.assertIs(policy['settings_verified'], False)


@unittest.skipUnless(Path('/usr/bin/git').is_file(), 'Real Git host fixtures are required')
class SettingsProducerContracts(SettingsFixture):
    def test_genuine_source_contract_export_keeps_all_files_and_rejects_late_directories(self):
        stage = self.root / 'export'
        inputs, patches, tree = contract.export_source(self.source_cache, self.cache, self.recipe_path,
                                                       self.recipe, self.policy, stage)
        self.assertEqual(contract.verify_export(self.source_cache, self.cache, self.recipe_path,
            self.policy, stage, inputs), tree)
        self.assertEqual(patches[0]['sha256'], self.policy['original_patch']['sha256'])
        (stage / 'unreviewed-empty-directory').mkdir()
        with self.assertRaisesRegex(ValueError, 'directory inventory'):
            contract.verify_export(self.source_cache, self.cache, self.recipe_path, self.policy, stage, inputs)

    def test_git_replacement_cannot_redefine_the_reviewed_original_source(self):
        write(self.source / 'src/main.rs', '// Changed source fixture\n')
        for args in [('add', '.'), ('-c', 'user.name=Settings Test', '-c', 'user.email=settings@example.invalid',
            'commit', '-qm', 'Replacement fixture')]:
            subprocess.run(['/usr/bin/git', '-C', str(self.source), *args], check=True, capture_output=True)
        replacement = contract.common.objects.pinned_git(self.source, 'rev-parse', 'HEAD')
        subprocess.run(['/usr/bin/git', '-C', str(self.source), 'replace', self.settings_id['commit'], replacement],
                       check=True, capture_output=True)
        subprocess.run(['/usr/bin/git', '-C', str(self.source), 'update-ref', 'HEAD', self.settings_id['commit']],
                       check=True, capture_output=True)
        with self.assertRaises(ValueError):
            contract.verify_sources(self.source_cache, self.cache, self.recipe_path, self.policy)

    def test_real_archive_paths_are_staged_before_cargo_and_whole_rust_runtime_is_bound(self):
        report = self.run_builder()
        self.assertEqual(set(report['native_archive_search']['files']), {'libunwind.a', *contract.STATIC_NAMES})
        self.assertIn('libcore-ab12.rlib', report['rust_libraries_before'])
        self.assertEqual(report['generated_build_inputs'], report['generated_build_inputs_after'])
        self.assertEqual(consumer.validate_build(self.build_output)['executable'], report['executable'])
        self.assertFalse(Path(report['original_export_root']).exists())
        self.assertIs(report['settings_verified'], False)

    def test_metadata_only_never_publishes_or_installs_an_elf(self):
        report = self.run_builder('metadata')
        self.assertEqual(report['status'], 'SETTINGS_METADATA_VERIFIED_NOT_BUILT')
        self.assertIs(report['cargo_resolution_verified'], True)
        self.assertIs(report['link_completed'], False)
        self.assertIs(report['target_linked'], False)
        self.assertEqual(set(report['retained_logs']), set(contract.LOGS[:2]))
        self.assertFalse((self.build_output / builder.PROGRAM).exists())
        with self.assertRaisesRegex(ValueError, 'Not a preserved'):
            installer.install(self.build_output, self.install_output)

    def test_cargo_error_retains_failed_evidence_and_raw_target(self):
        def fail(action, stage, output):
            if action == 'build': raise ValueError('Host fixture Cargo exit 101; no compiler ran')
        with self.assertRaisesRegex(ValueError, 'exit 101'):
            self.run_builder(hook=fail)
        report = contract.read_json(self.build_output / 'build-report.json')
        self.assertEqual(report['status'], 'FAILED')
        self.assertIs(report['link_completed'], False)
        self.assertIs(report['target_linked'], False)
        self.assertIs(report['inputs_preserved'], True)
        self.assertTrue((self.build_output / 'target' / contract.TARGET / 'release' / contract.COMPONENT).is_file())
        self.assertFalse((self.build_output / builder.PROGRAM).exists())

    def test_registry_source_drift_during_build_fails_even_with_unchanged_archive(self):
        def drift(action, stage, output):
            if action == 'build':
                write(self.cache / 'registry/src/fixture/fixture-dependency-1.0.0/src/lib.rs', '// Changed registry source\n')
        with self.assertRaisesRegex(ValueError, 'postchecks failed'):
            self.run_builder(hook=drift)
        report = contract.read_json(self.build_output / 'build-report.json')
        self.assertIs(report['inputs_preserved'], False)
        self.assertIs(report['target_linked'], False)
        self.assertFalse((self.build_output / builder.PROGRAM).exists())

    def test_root_native_feature_and_vendor_path_are_required_by_actual_metadata_validator(self):
        for mode in ('audio-feature', 'wayland-feature', 'vendor-path'):
            with self.subTest(mode=mode):
                def change(action, stage, output):
                    if action != 'metadata': return
                    path = output / 'metadata.json'; data = contract.read_json(path)
                    if mode == 'audio-feature': data['resolve']['nodes'][0]['features'] = ['audio', 'cyxia-native']
                    elif mode == 'wayland-feature': data['resolve']['nodes'][2]['features'] = ['client', 'dlopen']
                    else: data['packages'][2]['manifest_path'] = str(self.comp / 'cosmic-comp-config/Cargo.toml')
                    save(path, data)
                with self.assertRaises(ValueError): self.run_builder(output=self.root / mode, hook=change)
                report = contract.read_json(self.root / mode / 'build-report.json')
                self.assertIs(report['target_linked'], False)

    def test_input_overlap_is_rejected_before_tool_selection_or_output_creation(self):
        output = self.cache / 'unwanted-output'
        with mock.patch.object(contract.common.selection, 'tools_and_sysroot', side_effect=AssertionError('No native probes')):
            with self.assertRaisesRegex(ValueError, 'overlaps a read-only input'):
                builder.perform('build', self.recipe_path, self.profile_path, output, self.sdk,
                    self.source_cache, self.cache, self.rust, self.tools['host_cc'])
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
