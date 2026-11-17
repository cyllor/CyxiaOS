"""Pure source/filesystem boundary fixtures for Linux-v3 settings.

Every external process entry is blocked. Canonical Git/native execution and
the small builder's target bytes are explicitly mocked. No successful fixture
report is usable as a genuine build, source acquisition, or guest proof.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


def forbidden_process(*args, **kwargs):
    raise AssertionError('External process forbidden in pure settings v3 fixtures')


def process_guards(stack):
    for module, names in (
        (subprocess, ('Popen', 'run', 'call', 'check_call', 'check_output')),
        (os, ('system', 'popen', 'fork', 'posix_spawn', 'posix_spawnp',
              'execv', 'execve', 'execl', 'execle', 'execvp', 'execvpe')),
    ):
        for name in names:
            if hasattr(module, name):
                stack.enter_context(mock.patch.object(module, name, side_effect=forbidden_process))


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
with contextlib.ExitStack() as guards:
    process_guards(guards)
    builder = importlib.import_module('build_cosmic_settings_linux_v3')
    consumer = importlib.import_module('cosmic_settings_inputs_v3')

contract = builder.contract
PORT = HERE.parent / contract.PORT


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


def save(path, value):
    return write(path, json.dumps(value, indent=2, allow_nan=False) + '\n')


class PureCase(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        process_guards(self.stack)
        self.temporary = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='settings-v3-pure-'))
        self.root = Path(self.temporary).resolve()

    def patch(self, module, name, **kwargs):
        return self.stack.enter_context(mock.patch.object(module, name, **kwargs))


class ContractBoundaries(PureCase):
    def setUp(self):
        super().setUp()
        self.port = self.root / 'new-port'
        self.port.mkdir()
        for name in ('source-policy.json', 'native-recipe.json', 'resource-profile.json'):
            write(self.port / name, (PORT / name).read_bytes())
        self.policy = json.loads((self.port / 'source-policy.json').read_bytes())
        self.recipe = json.loads((self.port / 'native-recipe.json').read_bytes())
        self.resource = json.loads((self.port / 'resource-profile.json').read_bytes())

    def selected(self):
        return contract.contract(self.port / 'native-recipe.json', self.port / 'resource-profile.json', 2)

    def mutated(self, name, document, pin):
        path = save(self.port / name, document)
        return mock.patch.object(contract, pin, contract.files.sha(path.read_bytes()))

    def test_actual_contract_retains_original_features_native_archives_and_bounds(self):
        policy, recipe, source, profile = self.selected()
        old_policy, old_recipe, old_source, old_profile = contract.previous.contract(
            contract.ROOT / contract.previous.PORT / 'native-recipe.json',
            contract.ROOT / contract.previous.PORT / 'resource-profile.json', 2)
        self.assertEqual(source, old_source)
        self.assertEqual(recipe['patches'][:-1], old_recipe['patches'])
        self.assertEqual(recipe['features'], ['cyxia-native'])
        self.assertIs(recipe['default_features'], False)
        self.assertEqual(recipe['native_inputs'], old_recipe['native_inputs'])
        self.assertEqual({k: v for k, v in profile.items() if k != 'purpose'},
                         {k: v for k, v in old_profile.items() if k != 'purpose'})
        self.assertEqual(policy['preserved_resolution']['package_count'], 502)
        self.assertEqual(len(policy['preserved_resolution']['workspace']), 11)
        self.assertIs(policy['preserved_resolution']['reference_is_new_build_proof'], False)

    def test_even_repinned_recipe_cannot_change_feature_lock_native_or_patch_order(self):
        for key, value in [('features', ['cyxia-native', 'audio']), ('default_features', True),
                           ('effective_lock_sha256', 'a' * 64), ('native_inputs', []),
                           ('static_link_inputs', []), ('patches', list(reversed(self.recipe['patches'])))]:
            changed = {**self.recipe, key: value}
            with self.subTest(key=key), self.mutated('native-recipe.json', changed, 'RECIPE_SHA256'):
                with self.assertRaises(contract.BuildError): self.selected()
        save(self.port / 'native-recipe.json', self.recipe)

    def test_even_repinned_policy_cannot_modify_historical_boundary_or_upstream(self):
        for key, value in [('kind', contract.previous.KIND), ('commit', 'a' * 40),
                           ('features', []), ('source_lock_sha256', 'b' * 64),
                           ('boundary', {**self.policy['boundary'], 'system_services_emulated': True}),
                           ('prior_linux', {})]:
            changed = {**self.policy, key: value}
            with self.subTest(key=key), self.mutated('source-policy.json', changed, 'POLICY_SHA256'):
                with self.assertRaises(contract.BuildError): self.selected()
        save(self.port / 'source-policy.json', self.policy)

    def test_delta_cannot_expand_changed_paths_or_claim_runtime_success(self):
        for mutation in ('second-file', 'executable-mode', 'guest', 'fixed'):
            changed = copy.deepcopy(self.policy)
            delta = changed['theme_dispatch']
            if mutation == 'second-file': delta['files']['src/main.rs'] = delta['files']['src/theme.rs']
            elif mutation == 'executable-mode': delta['files']['src/theme.rs']['mode'] = '100755'
            elif mutation == 'guest': delta['guest_execution'] = True
            else: delta['no_reply_fixed'] = True
            with self.subTest(mutation=mutation), self.mutated('source-policy.json', changed, 'POLICY_SHA256'):
                with self.assertRaises(contract.BuildError): self.selected()
        save(self.port / 'source-policy.json', self.policy)

    def test_original_budgets_cannot_be_raised_even_with_a_new_pin(self):
        for name in ('timeout_seconds', 'jobs_max', 'max_build_bytes', 'image_bytes', 'stack_bytes'):
            changed = copy.deepcopy(self.resource)
            changed['build_profiles'][contract.PROFILE][name] += 1
            with self.subTest(name=name), self.mutated('resource-profile.json', changed, 'RESOURCE_SHA256'):
                with self.assertRaises(contract.BuildError): self.selected()
        save(self.port / 'resource-profile.json', self.resource)

    def test_original_11_members_502_graph_and_reference_not_proof_are_required(self):
        for field, value in [('package_count', 501), ('workspace', []),
                             ('default_members', []), ('reference_is_new_build_proof', True)]:
            changed = copy.deepcopy(self.policy)
            changed['preserved_resolution'][field] = value
            with self.subTest(field=field), self.mutated('source-policy.json', changed, 'POLICY_SHA256'):
                with self.assertRaises(contract.BuildError): self.selected()
        save(self.port / 'source-policy.json', self.policy)

    def test_commands_stay_locked_offline_selected_and_bound_to_exact_package(self):
        metadata, compile_command = contract.commands('/fixture/cargo', self.root / 'source', self.recipe, 2, 'exact-id')
        for command in (metadata, compile_command):
            self.assertIn('--locked', command)
            self.assertIn('--offline', command)
            self.assertIn('--no-default-features', command)
            self.assertEqual(command[command.index('--features') + 1], 'cyxia-native')
            self.assertNotIn('--all-features', command)
            self.assertNotIn('--exclude', command)
        self.assertEqual(compile_command[compile_command.index('--package') + 1], 'exact-id')
        self.assertEqual(compile_command[compile_command.index('--jobs') + 1], '2')


    def test_guard_delta_cannot_expand_paths_change_mode_or_claim_runtime_success(self):
        for mutation in ('second-file', 'executable-mode', 'guest', 'fixed', 'cause', 'patch-path'):
            changed = copy.deepcopy(self.policy)
            delta = changed['interface_guard']
            if mutation == 'second-file': delta['files']['src/theme.rs'] = delta['files']['src/main.rs']
            elif mutation == 'executable-mode': delta['files']['src/main.rs']['mode'] = '100755'
            elif mutation == 'guest': delta['guest_execution'] = True
            elif mutation == 'fixed': delta['no_reply_fixed'] = True
            elif mutation == 'cause': delta['no_reply_cause_proven'] = True
            else: delta['patch']['path'] = 'different.patch'
            with self.subTest(mutation=mutation), self.mutated('source-policy.json', changed, 'POLICY_SHA256'):
                with self.assertRaises(contract.BuildError): self.selected()
        save(self.port / 'source-policy.json', self.policy)

    def test_immediate_v2_parent_and_complete_theme_contract_remain_exact(self):
        for mutation in ('parent', 'theme', 'graph'):
            changed = copy.deepcopy(self.policy)
            if mutation == 'parent': changed['prior_linux_v2'] = changed['prior_linux']
            elif mutation == 'theme': changed['theme_dispatch']['files']['src/theme.rs']['after_sha256'] = 'a' * 64
            else: changed['preserved_resolution']['normalized_graph_sha256'] = 'b' * 64
            with self.subTest(mutation=mutation), self.mutated('source-policy.json', changed, 'POLICY_SHA256'):
                with self.assertRaises(contract.BuildError): self.selected()
        save(self.port / 'source-policy.json', self.policy)


class SourceClosure(PureCase):
    def setUp(self):
        super().setUp()
        self.tree = self.root / 'retained'
        self.original = {'Cargo.lock': b'fixture original lock\n', 'Cargo.toml': b'fixture unchanged workspace\n',
                         'src/main.rs': b'fixture canonical upstream main\n',
                         'src/theme.rs': b'fixture upstream theme\n', 'LICENSE': b'fixture complete license\n'}
        self.historical = {**self.original, 'src/main.rs': b'fixture native current_thread + LocalSet main\n',
                           'src/theme.rs': b'fixture original reviewed native theme\n'}
        self.themed = {**self.historical, 'src/theme.rs': b'fixture serial v2 dispatch theme\n'}
        self.final = {**self.themed, 'src/main.rs': b'fixture same Arc handles with bounded v3 guard scope\n'}
        for name, raw in self.final.items(): write(self.tree / name, raw)
        self.manifest = {'before': {name: contract.files.sha(self.original[name])
                                    for name in ('src/main.rs', 'src/theme.rs')},
                         'after': {name: contract.files.sha(self.historical[name])
                                   for name in ('src/main.rs', 'src/theme.rs')}}
        self.policy = {'patch_manifest': {'path': 'fixture-manifest.json', 'sha256': 'd' * 64},
                       'effective_lock_sha256': contract.files.sha(self.final['Cargo.lock']),
                       'theme_dispatch': {'files': {'src/theme.rs': {
                           'before_sha256': contract.files.sha(self.historical['src/theme.rs']),
                           'after_sha256': contract.files.sha(self.themed['src/theme.rs']), 'mode': '100644'}}},
                       'interface_guard': {'files': {'src/main.rs': {
                           'before_sha256': contract.files.sha(self.themed['src/main.rs']),
                           'after_sha256': contract.files.sha(self.final['src/main.rs']), 'mode': '100644'}}}}
        self.inputs = {'explicit_host_source_fixture': True, 'originals': {'settings': {
            'files': {name: {'sha256': contract.files.sha(raw), 'mode': '100644'}
                      for name, raw in self.original.items()}}}}
        self.patch(contract, 'verify_sources', return_value=self.inputs)
        self.patch(contract, 'read_json', return_value=self.manifest)

    def verify(self):
        return contract.verify_export(self.root / 'sources', self.root / 'cache', self.root / 'recipe.json',
                                      self.policy, self.tree, self.inputs)

    def test_only_exact_historical_then_new_postimage_is_accepted(self):
        self.assertEqual(self.verify(), contract.files.file_tree(self.final))
        write(self.tree / 'src/theme.rs', self.historical['src/theme.rs'])
        with self.assertRaises(contract.BuildError): self.verify()

    def test_new_delta_cannot_start_at_upstream_before_the_original_native_patch(self):
        self.policy['theme_dispatch']['files']['src/theme.rs']['before_sha256'] = contract.files.sha(
            self.original['src/theme.rs'])
        with self.assertRaisesRegex(contract.BuildError, 'delta preimage'): self.verify()

    def test_manifest_lock_main_license_and_theme_changes_all_fail_closed(self):
        for name, raw in self.final.items():
            write(self.tree / name, raw + b'unreviewed change')
            with self.subTest(name=name), self.assertRaises(contract.BuildError): self.verify()
            write(self.tree / name, raw)

    def test_added_file_empty_directory_symlink_and_executable_bit_are_rejected(self):
        for mutation in ('extra-file', 'extra-directory', 'symlink', 'executable'):
            path = self.tree / ('unexpected' if mutation.startswith('extra') else 'src/theme.rs')
            if mutation == 'extra-file': path.write_bytes(b'extra')
            elif mutation == 'extra-directory': path.mkdir()
            elif mutation == 'symlink':
                path.unlink(); path.symlink_to(self.tree / 'src/main.rs')
            else: path.chmod(0o755)
            with self.subTest(mutation=mutation), self.assertRaises(contract.BuildError): self.verify()
            if mutation == 'extra-directory': path.rmdir()
            elif mutation.startswith('extra'): path.unlink()
            elif mutation == 'symlink': path.unlink(); path.write_bytes(self.final['src/theme.rs'])
            else: path.chmod(0o644)

    def test_missing_original_source_or_changed_binding_is_rejected(self):
        (self.tree / 'LICENSE').unlink()
        with self.assertRaises(contract.BuildError): self.verify()
        write(self.tree / 'LICENSE', self.final['LICENSE'])
        with mock.patch.object(contract, 'verify_sources', return_value={'different': True}):
            with self.assertRaisesRegex(contract.BuildError, 'source inputs changed'): self.verify()


    def test_guard_requires_exact_v2_main_preimage_and_a_new_postimage(self):
        self.assertEqual(self.verify(), contract.files.file_tree(self.final))
        row = self.policy['interface_guard']['files']['src/main.rs']
        original = row['before_sha256']
        row['before_sha256'] = contract.files.sha(self.original['src/main.rs'])
        with self.assertRaisesRegex(contract.BuildError, 'guard preimage'): self.verify()
        row['before_sha256'] = original
        write(self.tree / 'src/main.rs', self.themed['src/main.rs'])
        with self.assertRaises(contract.BuildError): self.verify()


class GraphBoundaries(PureCase):
    def setUp(self):
        super().setUp()
        production = json.loads((PORT / 'source-policy.json').read_bytes())
        self.stage = self.root / 'fixture-source'
        packages = []
        for row in production['preserved_resolution']['workspace']:
            packages.append({'id': 'fixture:' + row['name'], 'name': row['name'], 'version': row['version'],
                             'source': None, 'manifest_path': str(self.stage / row['manifest']),
                             'targets': [{'name': row['name'], 'kind': ['bin'],
                                          'src_path': str(self.stage / 'src/main.rs')}] if row['name'] == contract.COMPONENT else []})
        root_id = next(row['id'] for row in packages if row['name'] == contract.COMPONENT)
        direct = {row['name']: row['id'] for row in packages
                  if row['name'] in ('cosmic-comp-config', 'wayland-sys', 'geonames')}
        nodes = []
        for row in packages:
            features = ['cyxia-native'] if row['id'] == root_id else (
                ['client', 'cyxia-static-client', 'dlopen'] if row['name'] == 'wayland-sys' else [])
            edges = [{'name': name.replace('-', '_'), 'pkg': identifier,
                      'dep_kinds': [{'kind': None, 'target': None}]} for name, identifier in direct.items()]
            nodes.append({'id': row['id'], 'features': features,
                          'dependencies': list(direct.values()) if row['id'] == root_id else [],
                          'deps': edges if row['id'] == root_id else []})
        self.metadata = {'version': 1, 'packages': packages, 'resolve': {'nodes': nodes},
                         'workspace_members': [row['id'] for row in packages],
                         'workspace_default_members': [root_id]}
        self.policy = copy.deepcopy(production)
        graph = contract.files.normalized_resolution(self.metadata)
        # The pure graph deliberately has 11 fixture packages, not a real 502-package build.
        self.policy['preserved_resolution'].update(package_count=len(graph),
            normalized_graph_sha256=contract.canonical(graph))
        self.recipe = {'package': contract.COMPONENT, 'binary': contract.COMPONENT}
        self.patch(contract.packages, 'local_package', return_value=root_id)

    def selected(self):
        return contract.resolution(self.metadata, self.stage, self.recipe, self.policy)

    def test_full_fixture_workspace_and_default_member_survive_selection(self):
        self.assertEqual(self.selected()['features'], ['cyxia-native'])
        self.assertEqual(self.selected()['package_count'], 11)
        self.assertEqual(len(self.metadata['workspace_members']), 11)

    def test_pruning_workspace_altering_features_or_edges_changes_graph(self):
        original = copy.deepcopy(self.metadata)
        for mutation in ('workspace-pruned', 'feature', 'edge'):
            self.metadata = copy.deepcopy(original)
            if mutation == 'workspace-pruned': self.metadata['workspace_members'].pop()
            elif mutation == 'feature': self.metadata['resolve']['nodes'][0]['features'].append('unreviewed')
            else:
                node = next(row for row in self.metadata['resolve']['nodes'] if row['dependencies'])
                node['deps'].pop(); node['dependencies'].pop()
            with self.subTest(mutation=mutation), self.assertRaises(contract.BuildError): self.selected()

    def test_same_normalized_graph_cannot_relocate_workspace_or_change_default(self):
        original = copy.deepcopy(self.metadata)
        for mutation in ('manifest', 'escape', 'default', 'duplicate'):
            self.metadata = copy.deepcopy(original)
            if mutation == 'manifest': self.metadata['packages'][0]['manifest_path'] = str(self.stage / 'other/Cargo.toml')
            elif mutation == 'escape': self.metadata['packages'][0]['manifest_path'] = str(self.root / 'elsewhere/Cargo.toml')
            elif mutation == 'default':
                self.metadata['workspace_default_members'] = [next(row['id'] for row in self.metadata['packages']
                    if row['name'] != contract.COMPONENT)]
            else: self.metadata['workspace_members'].append(self.metadata['workspace_members'][0])
            with self.subTest(mutation=mutation), self.assertRaises(contract.BuildError): self.selected()


class BuilderBoundaries(PureCase):
    def setUp(self):
        super().setUp()
        self.output = self.root / 'build'
        self.recipe_path = write(self.root / 'contracts/native-recipe.json', '{}\n')
        self.profile_path = write(self.root / 'contracts/resource-profile.json', '{}\n')
        self.sdk, self.sources, self.cache, self.rust = [self.root / name for name in ('sdk', 'sources', 'cache', 'rust')]
        for directory in (self.sdk / 'sysroot', self.sources, self.cache, self.rust): directory.mkdir(parents=True)
        self.host_cc = write(self.root / 'host/bin/clang', 'EXPLICIT NONEXECUTABLE TOOL FIXTURE')
        self.profile = {'timeout_seconds': 1200, 'min_free_bytes': 1, 'max_build_bytes': 1536 * 1024**2,
                        'max_elf_bytes': 64 * 1024**2, 'image_bytes': 64 * 1024**2, 'stack_bytes': 2 * 1024**2}
        self.policy, self.recipe, self.source = ({'boundary': {'fixture': True}, 'commit': 'a' * 40},
            {'target': contract.TARGET, 'binary': contract.COMPONENT}, {'name': contract.COMPONENT})
        self.toolchain = {'selection': {'schema_version': 1}, 'host': 'x86_64-unknown-linux-gnu',
                         'rustc_version': 'release: 1.95.0\n', 'host_cc_version': 'clang version 19.1.7'}
        self.producer_identity = {'EXPLICIT-PURE-FIXTURE': 'b' * 64}
        self.patch(contract, 'contract', side_effect=lambda *_: (self.policy, self.recipe, self.source, self.profile))
        self.patch(builder, 'producer_sources', side_effect=lambda: dict(self.producer_identity))
        self.patch(contract.base, 'validate_cache', return_value=None)
        self.patch(contract.common, 'check_control', return_value=None)
        self.patch(contract, 'export_source', side_effect=self.export)
        self.patch(contract, 'verify_export', side_effect=lambda _s, _c, _r, _p, stage, _i: contract.files.read_tree(stage))
        self.patch(contract.common.selection, 'tools_and_sysroot', return_value=({'cargo': '/fixture/cargo'}, self.toolchain))
        self.patch(contract.files, 'sdk_origin', return_value={'fixture': 'sdk'})
        self.patch(contract, 'rust_libraries', return_value={'fixture': {'bytes': 1, 'sha256': 'c' * 64}})
        self.patch(contract.base, 'cargo_environment', return_value={})
        self.patch(contract, 'stage_native_archives', return_value={'fixture': 'archives'})
        self.patch(contract, 'generated_inputs', return_value={'fixture': 'generated'})
        self.patch(contract.common.objects, 'pinned_git', return_value='0')
        self.patch(contract, 'metadata_identity', return_value={'resolution': {'package_id': 'fixture-package'}})
        self.patch(contract.base, 'run_bounded', side_effect=self.run_bounded)
        self.patch(contract.elf, 'inspect_full_os_elf', side_effect=self.fixture_admission)

    def export(self, _s, _c, _r, _recipe, _policy, stage):
        write(stage / 'src/main.rs', 'EXPLICIT PURE SOURCE FIXTURE; NEVER COMPILED\n')
        return ({'originals': {'settings': {'path': str(self.sources)}}}, [], contract.files.read_tree(stage))

    def run_bounded(self, command, _cwd, _env, log, *_bounds, **_budget):
        if command[1] == 'metadata':
            save(log, {'target_directory': str(self.output / 'target'), 'pure_fixture_only': True})
            write(self.output / 'metadata.stderr.log', '')
        else:
            write(log, 'EXPLICIT PURE CARGO LOG FIXTURE; NO COMPILER RAN\n')
            write(self.output / 'target' / contract.TARGET / 'release' / contract.COMPONENT,
                  b'EXPLICIT PURE TARGET BYTE FIXTURE; NOT ELF\n')

    @staticmethod
    def fixture_admission(path, _profile):
        raw = Path(path).read_bytes()
        return {'executable': {'file': Path(path).name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
                'image_load_pages': 1, 'required_pages': 513, 'pure_fixture_only': True}

    def perform(self, action='build', output=None):
        return builder.perform(action, self.recipe_path, self.profile_path, output or self.output,
            self.sdk, self.sources, self.cache, self.rust, self.host_cc, jobs=2)

    def report(self):
        return json.loads((self.output / 'build-report.json').read_bytes())

    def test_mocked_success_is_not_guest_and_source_identity_is_rechecked(self):
        report = self.perform()
        self.assertEqual(report['status'], 'cross-built')
        self.assertIs(report['image_admission']['pure_fixture_only'], True)
        self.assertEqual(report['producer_sources'], report['producer_sources_after'])
        self.assertIs(report['settings_verified'], False)
        self.assertEqual(report['guest_execution'], 'not performed')

    def test_metadata_only_has_no_installable_elf(self):
        report = self.perform('metadata')
        self.assertEqual(report['status'], 'SETTINGS_METADATA_VERIFIED_NOT_BUILT')
        self.assertFalse((self.output / builder.PROGRAM).exists())
        with self.assertRaisesRegex(consumer.BuildError, 'Not a preserved'):
            consumer.validate_build(self.output)

    def test_tool_parent_and_legal_pkgconfig_link_targets_are_protected_before_output(self):
        tool = write(self.root / 'real-tools/pkgconf', 'EXPLICIT PURE TOOL FIXTURE')
        alias = self.root / 'lookup-tools/pkg-config'
        alias.parent.mkdir()
        alias.symlink_to(tool)
        for directory in (self.host_cc.parent, alias.parent, tool.parent, self.cache):
            output = directory / 'new-output'
            with mock.patch.object(builder.shutil, 'which', return_value=str(alias)):
                with self.subTest(directory=directory), self.assertRaisesRegex(contract.BuildError, 'overlaps'):
                    self.perform(output=output)
            self.assertFalse(output.exists())

    def test_failed_export_is_retained_failed_never_published(self):
        with mock.patch.object(contract, 'export_source', side_effect=contract.BuildError('fixture source changed')):
            with self.assertRaisesRegex(contract.BuildError, 'fixture source changed'): self.perform()
        self.assertEqual(self.report()['status'], 'FAILED')
        self.assertFalse(self.report()['target_linked'])
        self.assertFalse((self.output / builder.PROGRAM).exists())

    def test_failed_compile_retains_raw_evidence_but_revokes_publication(self):
        original = self.run_bounded
        def fail(command, *args, **kwargs):
            original(command, *args, **kwargs)
            if command[1] == 'build': raise contract.BuildError('fixture cargo exit 101')
        with mock.patch.object(contract.base, 'run_bounded', side_effect=fail):
            with self.assertRaisesRegex(contract.BuildError, 'exit 101'): self.perform()
        self.assertEqual(self.report()['status'], 'FAILED')
        self.assertFalse((self.output / builder.PROGRAM).exists())
        self.assertTrue((self.output / 'target' / contract.TARGET / 'release' / contract.COMPONENT).exists())
        self.assertIn('cargo.log', self.report()['retained_logs'])

    def test_input_drift_after_publication_revokes_final_elf_and_claims(self):
        original = builder.publish
        def drift(*args):
            result = original(*args)
            write(self.output / 'source/src/main.rs', 'CHANGED AFTER MOCK PUBLICATION\n')
            return result
        with mock.patch.object(builder, 'publish', side_effect=drift):
            with self.assertRaisesRegex(contract.BuildError, 'input changed during publication'): self.perform()
        self.assertEqual(self.report()['status'], 'FAILED')
        self.assertFalse(self.report()['target_linked'])
        self.assertFalse(self.report()['inputs_preserved'])
        self.assertFalse((self.output / builder.PROGRAM).exists())
        self.assertFalse((self.output / ('.' + builder.PROGRAM + '.pending')).exists())

    def test_expired_original_deadline_cannot_publish_even_after_successful_link(self):
        original = self.run_bounded
        def expire(command, *args, **kwargs):
            original(command, *args, **kwargs)
            if command[1] == 'build':
                self.patch(contract.common, 'remaining_bounds', side_effect=contract.BuildError('fixture deadline exceeded'))
        with mock.patch.object(contract.base, 'run_bounded', side_effect=expire):
            with self.assertRaisesRegex(contract.BuildError, 'deadline exceeded'): self.perform()
        self.assertEqual(self.report()['status'], 'FAILED')
        self.assertFalse((self.output / builder.PROGRAM).exists())

    def test_existing_output_is_never_revoked_by_failed_attempt(self):
        write(self.output / builder.PROGRAM, 'PREEXISTING USER DATA\n')
        with self.assertRaises(contract.BuildError): self.perform()
        self.assertEqual((self.output / builder.PROGRAM).read_text(), 'PREEXISTING USER DATA\n')


    def test_previous_v2_build_is_rejected_before_contract_or_source_revalidation(self):
        self.perform()
        report = self.report()
        report['kind'] = contract.previous.KIND
        save(self.output / 'build-report.json', report)
        with mock.patch.object(contract, 'contract', side_effect=AssertionError('heavy old-receipt validation forbidden')):
            with self.assertRaisesRegex(consumer.BuildError, 'Not a preserved'):
                consumer.validate_build(self.output)


class RetainedMetadataBoundaries(PureCase):
    def setUp(self):
        super().setUp()
        self.output, self.retained, self.cache = [self.root / name for name in ('output', 'retained', 'cache')]
        self.original = self.root / 'deleted-stage'
        self.retained.mkdir()
        write(self.retained / 'Cargo.toml', 'fixture manifest')
        write(self.retained / 'src/main.rs', 'fixture source')
        self.data = {'workspace_root': str(self.original), 'target_directory': str(self.output / 'target'),
                     'packages': [{'source': None, 'manifest_path': str(self.original / 'Cargo.toml'),
                                   'targets': [{'src_path': str(self.original / 'src/main.rs')}]}]}
        self.expected = {'resolution': {'package_id': 'fixture-id'},
                         'packages': [{'source': None, 'manifest': str(self.original / 'Cargo.toml')}]}
        self.report = {'original_export_root': str(self.original), 'package_id': 'fixture-id',
                       'cargo_dependencies': copy.deepcopy(self.expected)}
        self.patch(contract, 'read_json', side_effect=lambda *_: copy.deepcopy(self.data))
        self.actual = copy.deepcopy(self.expected)
        self.actual['packages'][0]['manifest'] = str(self.retained / 'Cargo.toml')
        self.patch(contract, 'metadata_identity', side_effect=lambda *_: copy.deepcopy(self.actual))

    def verify(self):
        return consumer.metadata_identity(self.report, self.output, self.retained, self.cache, {}, {})

    def test_only_deleted_stage_is_relocated_to_retained_source(self):
        self.assertEqual(self.verify()['resolution'], {'package_id': 'fixture-id'})
        self.assertEqual(self.report['cargo_dependencies'], self.expected)

    def test_external_local_manifest_target_and_changed_proof_are_rejected(self):
        for mutation in ('manifest', 'target', 'proof'):
            data, actual = copy.deepcopy(self.data), copy.deepcopy(self.actual)
            if mutation == 'manifest': self.data['packages'][0]['manifest_path'] = str(self.root / 'other/Cargo.toml')
            elif mutation == 'target': self.data['packages'][0]['targets'][0]['src_path'] = str(self.root / 'other/main.rs')
            else: self.actual['resolution']['package_id'] = 'changed'
            with self.subTest(mutation=mutation), self.assertRaises(contract.BuildError): self.verify()
            self.data, self.actual = data, actual


if __name__ == '__main__':
    unittest.main()
