"""Pure synthetic file/archive/metadata fixtures; no Git/Cargo/compiler/guest.

The actual build driver, complete export verifier, native archive parser,
independent consumer and FullOs ELF admission run against explicit fixtures.
Only canonical Git observation, Git patch application, tool execution and Cargo
transport are replaced. A successful fixture is never genuine-build evidence.
"""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import build_cosmic_panel_linux_v2 as builder
from tools import cosmic_panel_inputs_v2 as consumer
from tools import test_install_cosmic_notifications as binary_fixture
from tools.test_install_cosmic_notifications_static_v1 import patch_bytes

contract = builder.contract
metadata_contract = contract.metadata_contract
write, save = binary_fixture.write, binary_fixture.save
PORT = Path(__file__).resolve().parents[1] / contract.PORT


class PanelFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source_cache, self.native_sources = self.root / 'sources', self.root / 'native-sources'
        self.cache, self.sdk, self.rust = self.root / 'cache', self.root / 'sdk', self.root / 'rust'
        self.port = self.root / contract.PORT
        self.recipe_path, self.profile_path = self.port / 'native-recipe.json', self.port / 'resource-profile.json'
        self.output = self.root / 'build'
        production = contract.read_json(PORT / 'source-policy.json')
        recipe = contract.read_json(PORT / 'native-recipe.json')
        resource = (PORT / 'resource-profile.json').read_bytes()
        self.registry_files, self.archive_specs = {}, {}
        for name, version in [('wayland-sys', '0.31.11'), ('fixture-dependency', '1.0.0')]:
            stem = name + '-' + version
            content = {'Cargo.toml': f'[package]\nname="{name}"\nversion="{version}"\n'.encode(),
                       'src/lib.rs': b'// Pure archive source fixture; never compiled.\n',
                       'LICENSE.txt': b'Pure fixture license.\n'}
            packed = io.BytesIO()
            with tarfile.open(fileobj=packed, mode='w:gz') as stream:
                for relative, data in content.items():
                    member = tarfile.TarInfo(stem + '/' + relative); member.size, member.mode = len(data), 0o644
                    stream.addfile(member, io.BytesIO(data)); write(self.cache / 'registry/src/fixture' / stem / relative, data)
            archive = write(self.cache / 'registry/cache/fixture' / (stem + '.crate'), packed.getvalue())
            self.registry_files[name] = content
            self.archive_specs[name] = {'name': name, 'version': version,
                'source': 'registry+https://github.com/rust-lang/crates.io-index',
                'archive_sha256': contract.base.digest(archive), 'license_files': ['LICENSE.txt'],
                'files': {key: {'bytes': len(data), 'sha256': contract.files.sha(data), 'mode': 0o644}
                          for key, data in content.items()}, 'before_tree_sha256': contract.files.file_tree(content)['sha256']}
        self.roots = {'panel': self.source_cache / 'cosmic-panel',
                      'launch_pad': self.source_cache / 'launch-pad-5b516ee',
                      'smithay': self.native_sources / 'smithay-0ff0098'}
        self.commits = {'panel': 'a' * 40, 'launch_pad': 'b' * 40, 'smithay': 'c' * 40}
        config_relative = 'cosmic-panel-config/src/container_config.rs'
        config = b'// Complete original configuration byte fixture; never compiled.\n'
        initial = {'Cargo.toml': ('[workspace]\nmembers=' + json.dumps(list(metadata_contract.MEMBERS)) + '\nresolver="3"\n').encode(),
            'LICENSE.md': b'Panel fixture license.\n', config_relative: config,
            'cosmic-panel-bin/src/main.rs': b'// Original main source fixture; never compiled.\n',
            'cosmic-panel-config/src/lib.rs': b'// Original member source fixture.\n',
            'xdg-shell-wrapper-config/src/lib.rs': b'// Original member source fixture.\n'}
        for name in metadata_contract.MEMBERS:
            initial[name + '/Cargo.toml'] = f'[package]\nname="{name}"\nversion="1.10.0"\n'.encode()
        local_rows = [(name, '1.10.0') for name in metadata_contract.MEMBERS] + [('launch-pad', '1.0.1'), ('smithay', '0.7.0'), ('wayland-sys', '0.31.11')]
        effective_lock = 'version=4\n' + ''.join(f'[[package]]\nname="{name}"\nversion="{version}"\n' for name, version in local_rows)
        extra = self.archive_specs['fixture-dependency']
        effective_lock += f'[[package]]\nname="fixture-dependency"\nversion="1.0.0"\nsource="{extra["source"]}"\nchecksum="{extra["archive_sha256"]}"\n'
        initial['Cargo.lock'] = (effective_lock + '# Original fixture lock marker\n').encode()
        launch = {'Cargo.toml': b'[package]\nname="launch-pad"\nversion="1.0.1"\n',
                  'src/lib.rs': b'// Original launch manager fixture.\n', 'LICENSE.md': b'Launch fixture license.\n',
                  'tests/original.rs': b'// Preserved original test source fixture.\n'}
        smithay = {'Cargo.toml': b'[package]\nname="smithay"\nversion="0.7.0"\n',
                   'src/backend/egl/ffi.rs': b'// Original EGL source fixture.\n', 'LICENSE.txt': b'Smithay fixture license.\n',
                   'smithay-drm-extras/LICENSE': b'Original extra fixture license.\n',
                   'anvil/resources/retained.bin': b'\x00\x01complete original binary fixture\xff'}
        self.source_contents = {'panel': initial, 'launch_pad': launch, 'smithay': smithay}
        for key, content in self.source_contents.items():
            for name, data in content.items():write(self.roots[key] / name, data)
        originals = {key: self.canonical_fixture(path, self.commits[key]) for key, path in self.roots.items()}
        self.effective = dict(initial)
        for key, prefix in [('launch_pad', 'native-deps/launch-pad/'), ('smithay', 'native-deps/smithay/')]:
            self.effective.update({prefix + name: data for name, data in self.source_contents[key].items()})
        self.effective.update({'native-deps/wayland-sys/' + name: data for name, data in self.registry_files['wayland-sys'].items()})
        unpatched = dict(self.effective)
        self.effective['Cargo.lock'] = effective_lock.encode()
        self.effective['cosmic-panel-bin/Cargo.toml'] += b'\n[features]\ncyxia-native=[]\n'
        child_name = 'native-deps/launch-pad/src/native_child.rs'
        self.effective[child_name] = b'// Explicit synthetic adapter fixture; never compiled or run.\n'
        self.patch = patch_bytes(unpatched, self.effective)
        write(self.port / 'cosmic-panel-native.patch', self.patch)
        changed = sorted(name for name in unpatched.keys() | self.effective.keys() if unpatched.get(name) != self.effective.get(name))
        acquisition = save(self.root / 'fixed-source-acquisition/report.json', {
            'status': 'THREE_EXACT_PANEL_SOURCES_AVAILABLE_NOT_RESOLVED_NOT_BUILT',
            'originals_preserved': True, 'protected_preserved': True, 'scope': 'Synthetic host fixture only'})
        support = write(self.root / 'ports/fixture-support.txt', b'Pure synthetic support identity.\n')
        self.policy = {**production, 'commit': self.commits['panel'], 'git_tree': originals['panel']['git_tree'],
            'source_lock_sha256': contract.files.sha(initial['Cargo.lock']), 'effective_lock_sha256': contract.files.sha(self.effective['Cargo.lock']),
            'source_acquisition': {'path': str(acquisition.relative_to(self.root)), 'sha256': contract.base.digest(acquisition)},
            'support_inputs': {str(support.relative_to(self.root)): contract.base.digest(support)},
            'registry_inputs': [{**self.archive_specs['wayland-sys'], 'prefix': 'native-deps/wayland-sys/'}],
            'git_sources': {key: {**production['git_sources'][key], 'directory': self.roots[key].name,
                'commit': row['commit'], 'git_tree': row['git_tree'], 'tree_sha256': row['sha256'],
                'file_count': len(row['files']), 'source_bytes': row['total_bytes']} for key, row in originals.items()},
            'patch': {'path': 'cosmic-panel-native.patch', 'sha256': contract.files.sha(self.patch),
                'before': {name: contract.files.sha(unpatched[name]) if name in unpatched else None for name in changed},
                'after': {name: contract.files.sha(self.effective[name]) for name in changed}},
            'native_child_postimages': {child_name: contract.files.sha(self.effective[child_name])},
            'original_panel_configuration': {**production['original_panel_configuration'], 'path': config_relative, 'sha256': contract.files.sha(config)}}
        self.create_sdk()
        self.recipe = {**recipe, 'commit': self.policy['commit'], 'source_lock_sha256': self.policy['source_lock_sha256'],
            'effective_lock_sha256': self.policy['effective_lock_sha256'],
            'patches': [{'path': 'cosmic-panel-native.patch', 'sha256': contract.files.sha(self.patch)}],
            'native_inputs': self.native, 'native_sdk_origin': self.policy['native_sdk_origin']}
        self.policy['native_inputs'] = self.native
        save(self.recipe_path, self.recipe); save(self.port / 'source-policy.json', self.policy); write(self.profile_path, resource)
        self.component = {'name': contract.COMPONENT, 'directory': 'cosmic-panel',
                          'repository': contract.REPOSITORIES['panel'], 'commit': self.policy['commit']}
        for owner, name, value in [(contract, 'ROOT', self.root),
            (contract, 'POLICY_SHA256', contract.base.digest(self.port / 'source-policy.json')),
            (contract, 'RECIPE_SHA256', contract.base.digest(self.recipe_path))]:
            patcher = mock.patch.object(owner, name, value); patcher.start(); self.addCleanup(patcher.stop)
        for owner, name, options in [
            (contract.base.ports, 'load_manifest', {'return_value': {'components': [self.component]}}),
            (contract.common, 'git_identity', {'side_effect': self.canonical_fixture}),
            (contract.common.objects, 'pinned_git', {'side_effect': self.git_observation}),
            (contract.subprocess, 'run', {'side_effect': self.patch_transport}),
            (builder, 'producer_sources', {'return_value': {'tools/build_cosmic.py': contract.base.digest(contract.base.ROOT / 'tools/build_cosmic.py')}}),
        ]:
            patcher = mock.patch.object(owner, name, **options); patcher.start(); self.addCleanup(patcher.stop)
        self.profile = contract.contract(self.recipe_path, self.profile_path, 2)[3]

    def canonical_fixture(self, root, commit):
        root = Path(root)
        files = {}
        for path in sorted(root.rglob('*')):
            if path.is_file():
                raw = path.read_bytes()
                files[str(path.relative_to(root))] = {'bytes': len(raw), 'sha256': contract.files.sha(raw),
                    'git_blob': contract.common.objects.git_blob(raw), 'mode': '100755' if path.stat().st_mode & 0o111 else '100644'}
        return {'commit': commit, 'git_tree': ('d' if root.name == 'cosmic-panel' else 'e' if root.name.startswith('launch') else 'f') * 40,
                'sha256': contract.canonical(files), 'files': files, 'submodules': {}, 'total_bytes': sum(r['bytes'] for r in files.values())}

    def git_observation(self, root, *args):
        if args == ('show', '-s', '--format=%ct'):return '1'
        self.assertEqual(args, ('remote', 'get-url', 'origin'))
        return contract.REPOSITORIES[next(k for k, v in self.roots.items() if v == Path(root))]

    def patch_transport(self, argv, **kwargs):
        self.assertEqual(argv[:2], ['/usr/bin/git', 'apply'])
        self.assertEqual(Path(argv[-1]).read_bytes(), self.patch)
        root = Path(kwargs['cwd'])
        for name, expected in self.policy['patch']['before'].items():
            self.assertEqual(contract.base.digest(root / name) if (root / name).exists() else None, expected)
        if '--check' not in argv:
            for name in self.policy['patch']['after']:write(root / name, self.effective[name])
        return None

    def create_sdk(self):
        self.native, foundation, linked = [], {}, {}
        for relative in contract.NATIVE_PATHS:
            raw = binary_fixture.archive() if relative.endswith('.a') else binary_fixture.object_bytes()
            path = write(self.sdk / relative, raw)
            row = {'bytes': len(raw), 'sha256': contract.files.sha(raw)}
            self.native.append({'path': relative, 'sha256': row['sha256']})
            if relative.startswith('sysroot/'):foundation[relative[len('sysroot/'):]] = row
            else:linked[str(path)] = row
        origin = save(self.sdk / 'runtime-sdk-origin.json', {'fixture_only': True, 'new_inputs': {'trees': {'sysroot': {'files': foundation}}}})
        completed = save(self.sdk / 'mesa-native-port/latest-report.json', {'scope': 'Synthetic retained native producer identity fixture; no compilation'})
        item = lambda p: {'path': str(p), 'bytes': p.stat().st_size, 'sha256': contract.base.digest(p)}
        mesa = save(self.root / 'fixed-mesa-proof/report.json', {
            'status': 'MESA_WAYLAND_PRODUCTION_LIBRARIES_CONSUMED_NOT_RUN', 'scope': 'Synthetic closed-input fixture only',
            'genuine_helper_embedded_in_egl': True, 'surfaceless_preserved': True, 'original_inputs_preserved': True,
            'source_and_uapi_unchanged': True, 'guest_execution': False, 'g_egl_pass': False,
            'cosmic_session_verified': False, 'full_os_verified': False,
            'sdk_assembly': item(origin), 'completed_producer': item(completed),
            'original_build_limits': {'jobs': 2, 'timeout_seconds': 3600, 'max_output_bytes': 3 * 1024**3, 'min_free_bytes': 1024**3},
            'actual_build_validation': {'actual_final_link_inputs': linked}})
        self.policy['native_mesa_validation'] = {'path': str(mesa.relative_to(self.root)), 'sha256': contract.base.digest(mesa)}
        self.policy['native_sdk_origin'] = {'path': 'runtime-sdk-origin.json', 'sha256': contract.base.digest(origin)}
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
            if name != 'target_cxx':write(path, 'Identity fixture only; never executed: ' + name); path.chmod(0o755)
        self.identities = {'target': contract.TARGET, 'architecture': 'x86_64', 'host': host,
            'selection': {'schema_version': 1, 'rust_root': str(self.rust), 'host_cc': str(self.tools['host_cc'])},
            'rustc_version': 'rustc 1.95.0 fixture-only\nhost: ' + host + '\nrelease: 1.95.0\n',
            'host_cc_version': 'clang version 19.1.7 fixture-only\n',
            'std': {'path': str(std), 'sha256': contract.base.digest(std)},
            'unwind': {'path': str(unwind), 'sha256': contract.base.digest(unwind)},
            'native_inputs': self.native, 'static_link_inputs': list(contract.STATIC_PATHS),
            'tools': {name: {'path': str(path), 'sha256': contract.base.digest(path) if path.exists() else None,
                             'available': path.exists()} for name, path in self.tools.items()}}

    def metadata(self, stage, output):
        packages, features = [], []
        selected = [(name, '1.10.0', name + '/Cargo.toml') for name in metadata_contract.MEMBERS]
        selected += [(name, version, 'native-deps/' + name + '/Cargo.toml') for name, version in
                     [('launch-pad', '1.0.1'), ('smithay', '0.7.0'), ('wayland-sys', '0.31.11')]]
        for name, version, relative in selected:
            packages.append({'name': name, 'version': version, 'id': 'path+' + (stage / relative).parent.as_uri() + '#' + name,
                'source': None, 'manifest_path': str(stage / relative), 'targets': ([{'name': 'cosmic-panel', 'kind': ['bin'],
                    'src_path': str(stage / 'cosmic-panel-bin/src/main.rs')}] if name == 'cosmic-panel-bin' else [])})
            features.append(['cyxia-native'] if name == 'cosmic-panel-bin' else sorted(metadata_contract.NATIVE_FEATURES.get(name, [])))
        spec = self.archive_specs['fixture-dependency']
        packages.append({'name': spec['name'], 'version': spec['version'], 'id': 'fixture-registry-dependency',
            'source': spec['source'], 'manifest_path': str(self.cache / 'registry/src/fixture/fixture-dependency-1.0.0/Cargo.toml'), 'targets': []})
        features.append([])
        edges = [{'name': row['name'].replace('-', '_'), 'pkg': row['id'], 'dep_kinds': [{'kind': None, 'target': None}]} for row in packages[1:]]
        return {'version': 1, 'workspace_root': str(stage), 'target_directory': str(output / 'target'),
            'workspace_members': [row['id'] for row in packages[:3]], 'workspace_default_members': [row['id'] for row in packages[:3]],
            'packages': packages, 'resolve': {'root': None, 'nodes': [{'id': row['id'], 'features': feature,
                'dependencies': [edge['pkg'] for edge in edges] if index == 0 else [], 'deps': edges if index == 0 else []}
                for index, (row, feature) in enumerate(zip(packages, features))]}}

    def run_builder(self, action='build', *, output=None, hook=None):
        output = output or self.output
        def cargo_fixture(command, control, environment, log, *args, **kwargs):
            stage = Path(command[command.index('--manifest-path') + 1]).parent
            self.assertEqual(environment['CARGO_NET_OFFLINE'], 'true')
            self.assertIn('--locked', command); self.assertIn('--offline', command)
            self.assertNotIn('--no-default-features', command)
            self.assertEqual(command[command.index('--features') + 1], 'cosmic-panel-bin/cyxia-native')
            if command[1] == 'metadata':save(Path(log), self.metadata(stage, output)); write(Path(kwargs['stderr_log']), '')
            else:
                self.assertEqual(command[1], 'build')
                self.assertEqual(command[command.index('--bin') + 1], 'cosmic-panel')
                write(Path(log), 'PURE SYNTHETIC FILE FIXTURE; no Cargo/compiler/target was executed.\n')
                write(output / 'target' / contract.TARGET / 'release/cosmic-panel', binary_fixture.elf())
            if hook is not None:hook(command[1], stage, output)
        with mock.patch.object(contract.common.selection, 'tools_and_sysroot', return_value=(self.tools, self.identities)), \
             mock.patch.object(contract.base, 'run_bounded', side_effect=cargo_fixture):
            return builder.perform(action, self.recipe_path, self.profile_path, output, self.sdk,
                self.source_cache, self.native_sources, self.cache, self.rust, self.tools['host_cc'], 2)


class FixedPanelContract(unittest.TestCase):
    def test_fixed_real_policy_preserves_members_applets_pins_and_original_bounds(self):
        policy, recipe, source, profile = contract.contract(PORT / 'native-recipe.json', PORT / 'resource-profile.json', 2)
        self.assertEqual(source['commit'], '3ce6ce1cec97669f91e809962d9446aaefe8a06e')
        self.assertEqual(policy['git_sources']['smithay']['commit'], '0ff00983b6007257a7a161a4fe8b14a778e2ac8f')
        self.assertEqual(policy['workspace_members'], ['cosmic-panel-bin', 'cosmic-panel-config', 'xdg-shell-wrapper-config'])
        self.assertEqual(policy['original_panel_configuration']['occurrences'], 18)
        self.assertEqual(policy['original_panel_configuration']['unique_ids'], 16)
        self.assertEqual(sum(row['file_count'] for row in policy['git_sources'].values())
                         + sum(len(row['files']) for row in policy['registry_inputs'])
                         + sum(v is None for v in policy['patch']['before'].values()), 516)
        self.assertEqual((profile['jobs_max'], profile['timeout_seconds'], profile['max_build_bytes'], profile['min_free_bytes']),
                         (2, 3600, 3 * 1024**3, 1024**3))
        self.assertTrue(recipe['default_features'])
        self.assertEqual(recipe['features'], ['cosmic-panel-bin/cyxia-native'])
        self.assertFalse(policy['panel_verified']); self.assertFalse(policy['full_cosmic_complete'])


class PanelAcceptance(PanelFixture):
    def export(self):
        target = self.root / 'export'
        result = contract.export_source(self.source_cache, self.native_sources, self.cache,
            self.recipe_path, self.recipe, self.policy, target)
        return target, result

    def test_complete_export_keeps_binary_originals_and_rejects_extra_dirs_files_and_modes(self):
        target, (inputs, _, tree) = self.export()
        self.assertEqual(contract.files.read_tree(target), tree)
        binary = target / 'native-deps/smithay/anvil/resources/retained.bin'
        self.assertEqual(binary.read_bytes(), self.source_contents['smithay']['anvil/resources/retained.bin'])
        for kind in ('directory', 'file', 'mode', 'config'):
            with self.subTest(kind=kind):
                changed = target / ('extra' if kind in ('directory', 'file') else
                    'cosmic-panel-config/src/container_config.rs' if kind == 'config' else 'cosmic-panel-bin/src/main.rs')
                original = changed.read_bytes() if changed.is_file() else None
                if kind == 'directory':changed.mkdir()
                elif kind in ('file', 'config'):write(changed, b'changed fixture\n')
                else:changed.chmod(0o600)
                with self.assertRaises(ValueError):
                    contract.verify_export(self.source_cache, self.native_sources, self.cache,
                        self.recipe_path, self.policy, target, inputs)
                if kind == 'directory':changed.rmdir()
                elif kind == 'file':changed.unlink()
                elif kind == 'config':changed.write_bytes(original)
                else:changed.chmod(0o644)

    def test_original_source_drift_rejected_before_export(self):
        write(self.roots['smithay'] / 'src/backend/egl/ffi.rs', b'Unreviewed changed original\n')
        with self.assertRaisesRegex(ValueError, 'Original complete panel Git source changed'):
            self.export()
        self.assertFalse((self.root / 'export').exists())

    def test_registry_extraction_must_match_the_unchanged_archive(self):
        write(self.cache / 'registry/src/fixture/wayland-sys-0.31.11/src/lib.rs', b'drift')
        with self.assertRaisesRegex(ValueError, 'extraction differs from archive'):
            self.export()

    def test_virtual_workspace_and_every_original_member_are_required(self):
        for mutation in ('root-manifest', 'missing-member', 'default-members', 'native-member', 'wrong-bin', 'root-feature'):
            with self.subTest(mutation=mutation):
                data = self.metadata(self.root / 'not-exported', self.output)
                if mutation == 'root-manifest':data['packages'][0]['manifest_path'] = str(self.root / 'not-exported/Cargo.toml')
                elif mutation == 'missing-member':data['workspace_members'].pop()
                elif mutation == 'default-members':data['workspace_default_members'].pop()
                elif mutation == 'native-member':data['workspace_members'].append(data['packages'][3]['id'])
                elif mutation == 'wrong-bin':data['packages'][0]['targets'][0]['src_path'] = str(self.root / 'not-exported/src/main.rs')
                else:data['resolve']['nodes'][0]['features'].append('default-pruned-fixture')
                with self.assertRaises(ValueError):metadata_contract.resolution(data, self.root / 'not-exported', self.recipe)

    def test_native_child_smithay_drm_and_all_three_wayland_bindings_are_required(self):
        for name, feature in [('launch-pad', 'cyxia-native'), ('smithay', 'backend_drm'), ('smithay', 'backend_egl_static'),
                              ('wayland-sys', 'cyxia-static-client'), ('wayland-sys', 'cyxia-static-server'), ('wayland-sys', 'cyxia-static-egl')]:
            with self.subTest(name=name, feature=feature):
                data = self.metadata(self.root / 'not-exported', self.output)
                index = next(i for i, row in enumerate(data['packages']) if row['name'] == name)
                data['resolve']['nodes'][index]['features'].remove(feature)
                with self.assertRaisesRegex(ValueError, 'exact real native dependency'):
                    metadata_contract.resolution(data, self.root / 'not-exported', self.recipe)

    def test_archive_closure_and_full_os_consumer_use_the_same_retained_link(self):
        report = self.run_builder()
        proof = consumer.validate_build(self.output)
        self.assertEqual(proof['executable'], report['executable'])
        self.assertEqual(set(report['native_archive_search']['files']), {'libunwind.a', *(Path(p).name for p in contract.STATIC_PATHS)})
        self.assertEqual(len(proof['licenses']), 5)
        self.assertIn('libcore-ab12.rlib', proof['rust_libraries'])
        self.assertFalse(Path(report['original_export_root']).exists())
        for key in ('panel_verified', 'panel_applet_lifecycle_verified', 'cosmic_session_ready', 'cosmic_session_verified', 'full_cosmic_complete'):
            self.assertIs(proof[key], False)

    def test_metadata_only_preserves_three_member_graph_but_never_publishes_elf(self):
        report = self.run_builder('metadata')
        self.assertEqual(report['status'], 'PANEL_METADATA_VERIFIED_NOT_BUILT')
        self.assertEqual(set(report['cargo_dependencies']['resolution']['workspace_members']), set(metadata_contract.MEMBERS))
        self.assertIs(report['cargo_resolution_verified'], True)
        self.assertFalse(report['link_completed']); self.assertFalse(report['target_linked'])
        self.assertFalse((self.output / builder.PROGRAM).exists())
        with self.assertRaisesRegex(ValueError, 'Not a preserved'):consumer.validate_build(self.output)

    def test_consumer_reconstructs_argv_without_producer_command_builder(self):
        self.run_builder()
        with mock.patch.object(contract, 'commands', side_effect=AssertionError('Consumer must build argv independently')):
            self.assertEqual(consumer.validate_build(self.output)['status'], 'VALIDATED_NOT_RUN')

    def test_cargo_failure_preserves_raw_fixture_and_rejects_publication(self):
        def fail(action, stage, output):
            if action == 'build':raise ValueError('Synthetic Cargo exit 101; no compiler executed')
        with self.assertRaisesRegex(ValueError, 'exit 101'):self.run_builder(hook=fail)
        report = contract.read_json(self.output / 'build-report.json')
        self.assertEqual(report['status'], 'FAILED'); self.assertFalse(report['target_linked'])
        self.assertTrue((self.output / 'target' / contract.TARGET / 'release/cosmic-panel').is_file())
        self.assertFalse((self.output / builder.PROGRAM).exists())

    def test_retained_source_drift_during_build_revokes_publish(self):
        def drift(action, stage, output):
            if action == 'build':write(output / 'source/xdg-shell-wrapper-config/src/lib.rs', b'drift')
        with self.assertRaisesRegex(ValueError, 'postchecks failed'):self.run_builder(hook=drift)
        report = contract.read_json(self.output / 'build-report.json')
        self.assertFalse(report['inputs_preserved']); self.assertFalse(report['target_linked'])
        self.assertFalse((self.output / builder.PROGRAM).exists())

    def test_independent_consumer_rejects_command_metadata_elf_license_and_mesa_changes(self):
        self.run_builder()
        for mutation in ('command', 'features', 'elf', 'license', 'mesa'):
            with self.subTest(mutation=mutation):
                if mutation == 'command':
                    path = self.output / 'build-report.json'; original = path.read_bytes(); value = json.loads(original)
                    value['command'].append('--no-default-features'); save(path, value)
                elif mutation == 'features':
                    path = self.output / 'metadata.json'; original = path.read_bytes(); value = json.loads(original)
                    value['resolve']['nodes'][0]['features'] = []; save(path, value)
                else:
                    path = {'elf': self.output / builder.PROGRAM, 'license': self.output / 'source/LICENSE.md',
                            'mesa': self.root / self.policy['native_mesa_validation']['path']}[mutation]
                    original = path.read_bytes(); path.write_bytes(original + b'changed')
                with self.assertRaises(ValueError):consumer.validate_build(self.output)
                path.write_bytes(original)

    def test_generation_receipt_output_overlap_is_rejected_before_mkdir_or_native_probe(self):
        for key in ('native_mesa_validation', 'source_acquisition'):
            output = (self.root / self.policy[key]['path']).parent / 'bad-output'
            with self.subTest(key=key), \
                    mock.patch.object(contract.common.selection, 'tools_and_sysroot', side_effect=AssertionError('No native probe')):
                with self.assertRaisesRegex(ValueError, 'overlaps a read-only input'):
                    builder.perform('build', self.recipe_path, self.profile_path, output, self.sdk,
                        self.source_cache, self.native_sources, self.cache, self.rust, self.tools['host_cc'], 2)
            self.assertFalse(output.exists())

    def test_missing_static_archive_and_registry_source_drift_never_survive_postchecks(self):
        for mode in ('native', 'registry'):
            output = self.root / ('build-' + mode)
            changed = self.sdk / 'sysroot/usr/lib/libwayland-egl.a' if mode == 'native' else self.cache / 'registry/src/fixture/fixture-dependency-1.0.0/src/lib.rs'
            original = changed.read_bytes()
            def drift(action, stage, output):
                if action == 'build':changed.write_bytes(b'drift')
            with self.subTest(mode=mode), self.assertRaises(ValueError):self.run_builder(output=output, hook=drift)
            self.assertFalse((output / builder.PROGRAM).exists())
            changed.write_bytes(original)


    def test_host_compiler_directory_overlap_is_rejected_before_output_or_probe(self):
        for suffix in ('panel-build', 'nested/panel-build'):
            output = self.tools['host_cc'].parent / suffix
            with self.subTest(suffix=suffix), \
                    mock.patch.object(contract.common.selection, 'tools_and_sysroot', side_effect=AssertionError('No native probe')):
                with self.assertRaisesRegex(ValueError, 'overlaps a read-only input'):
                    builder.perform('build', self.recipe_path, self.profile_path, output, self.sdk,
                        self.source_cache, self.native_sources, self.cache, self.rust, self.tools['host_cc'], 2)
            self.assertFalse(output.exists())
            self.assertFalse((self.tools['host_cc'].parent / 'nested').exists())

    def test_pkg_config_link_and_real_directories_are_protected_before_output(self):
        real = write(self.root / 'real-pkg/bin/pkgconf', 'Pure executable identity fixture; never executed')
        real.chmod(0o755)
        link = self.root / 'link-pkg/bin/pkg-config'
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        for parent in (link.parent, real.parent):
            output = parent / 'panel-build'
            with self.subTest(parent=parent), \
                    mock.patch.object(builder.shutil, 'which', return_value=str(link)), \
                    mock.patch.object(contract.common.selection, 'tools_and_sysroot', side_effect=AssertionError('No native probe')):
                with self.assertRaisesRegex(ValueError, 'overlaps a read-only input'):
                    builder.perform('build', self.recipe_path, self.profile_path, output, self.sdk,
                        self.source_cache, self.native_sources, self.cache, self.rust, self.tools['host_cc'], 2)
            self.assertFalse(output.exists())

    def test_consumer_protects_tool_link_and_real_parents_without_requiring_absent_cxx(self):
        real = write(self.root / 'consumer-pkg-real/bin/pkgconf', 'Pure executable identity fixture; never executed')
        real.chmod(0o755)
        link = self.root / 'consumer-pkg-link/bin/pkg-config'
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        self.tools['pkg_config'] = link
        self.identities['tools']['pkg_config'] = {'path': str(link), 'sha256': contract.base.digest(real), 'available': True}
        self.run_builder()
        proof = consumer.validate_build(self.output)
        protected = set(proof['input_directories'])
        self.assertIn(str(self.tools['host_cc'].parent), protected)
        self.assertIn(str(link.parent), protected)
        self.assertIn(str(real.parent), protected)
        for record in self.identities['tools'].values():
            if record['available']:
                path = Path(record['path'])
                self.assertIn(str(path.parent.resolve(strict=True)), protected)
                self.assertIn(str(path.resolve(strict=True).parent), protected)
        self.assertFalse(self.identities['tools']['target_cxx']['available'])
        self.assertFalse(self.tools['target_cxx'].exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
