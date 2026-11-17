"""Portable phase contract tests and optional exact pinned-source replay.

Run all portable cases with:
    python3 -m unittest discover -s tools -p test_cosmic_comp_phase_v1.py

Select the original unpatched cosmic-comp 41497b42 source directory for all
six additional source-replay cases with CYXIA_COMP_PHASE_CANONICAL=/absolute/path.
Only the 24 exact canonical preimages touched by the original three patches
are read; their hashes come from the pinned repository patch manifests. This
is a source fixture, not a complete upstream-tree or native-build proof.
No compiler, Cargo, full consumer, network or guest process is invoked.
"""
from __future__ import annotations

import ast
import copy
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import stat
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SUBJECT = HERE
sys.path.insert(0, str(SUBJECT))
import build_cosmic_comp_linux_v2 as producer
import cosmic_comp_inputs_v2 as consumer

PORT = REPO / 'ports/cosmic/native-comp-phase-v1'
CANONICAL_ENV = 'CYXIA_COMP_PHASE_CANONICAL'
MAX_FIXTURE_FILE_BYTES = 1024 * 1024
MAX_FIXTURE_BYTES = 2 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def apply_exact_patch(files, raw):
    """Strict in-memory unified-diff replay, without Git or offset/fuzz search."""
    lines = raw.decode().splitlines(keepends=True)
    before = dict(files)
    output = dict(files)
    index = 0
    changed = set()
    while index < len(lines):
        if not lines[index].startswith('--- '):
            if lines[index].startswith(('diff --git ', 'index ', 'new file mode ', 'deleted file mode ')):
                index += 1
                continue
            raise ValueError('Unexpected patch header: ' + lines[index])
        old_name = lines[index][4:].strip().split('\t')[0]
        index += 1
        if index == len(lines) or not lines[index].startswith('+++ '):
            raise ValueError('Missing postimage header')
        new_name = lines[index][4:].strip().split('\t')[0]
        index += 1
        selected = old_name if new_name == '/dev/null' else new_name
        if selected.startswith(('a/', 'b/')):
            selected = selected[2:]
        if Path(selected).is_absolute() or '..' in Path(selected).parts or selected in changed:
            raise ValueError('Unsafe or repeated patch file')
        if old_name == '/dev/null':
            if selected in output:
                raise ValueError('New file already exists')
            old = []
        else:
            if old_name.removeprefix('a/') != selected:
                raise ValueError('Unexpected rename')
            old = output[selected].decode().splitlines(keepends=True)
        result, cursor, hunks = [], 0, 0
        while index < len(lines) and lines[index].startswith('@@ '):
            header = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', lines[index])
            if header is None:
                raise ValueError('Invalid exact hunk header')
            old_start, old_count, new_start, new_count = [int(value) if value is not None else 1
                                                         for value in header.groups()]
            offset = old_start - 1 if old_count else old_start
            if offset < cursor or offset > len(old):
                raise ValueError('Hunk offset overlaps or escapes source')
            result.extend(old[cursor:offset])
            cursor = offset
            if len(result) != (new_start - 1 if new_count else new_start):
                raise ValueError('Hunk postimage offset mismatch')
            index += 1
            removed = inserted = 0
            while index < len(lines) and (removed < old_count or inserted < new_count):
                line = lines[index]
                if not line or line[0] not in ' +-':
                    raise ValueError('Invalid hunk line')
                marker, payload = line[0], line[1:]
                if marker in ' -':
                    if cursor >= len(old) or old[cursor] != payload:
                        raise ValueError('Exact preimage line changed')
                    cursor += 1
                    removed += 1
                if marker in ' +':
                    result.append(payload)
                    inserted += 1
                index += 1
            if (removed, inserted) != (old_count, new_count):
                raise ValueError('Hunk count mismatch')
            hunks += 1
        if hunks == 0:
            raise ValueError('No patch hunks')
        result.extend(old[cursor:])
        if new_name == '/dev/null':
            if result:
                raise ValueError('Deleted file left bytes')
            del output[selected]
        else:
            output[selected] = ''.join(result).encode()
        changed.add(selected)
    if {name for name in before.keys() | output.keys() if before.get(name) != output.get(name)} != changed:
        raise ValueError('Patch includes unmodified or unbound files')
    return output, changed


def functions(source):
    tree = ast.parse(source)
    return {node.name: ast.get_source_segment(source, node)
            for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def checked_source_file(root, name, checksum):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Unsafe fixture source path')
    path = root / relative
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('Linked fixture source path')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FIXTURE_FILE_BYTES:
            raise ValueError('Unbounded fixture source file')
        raw = stream.read(MAX_FIXTURE_FILE_BYTES + 1)
        stamp = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        if (len(raw) != before.st_size or stamp(before) != stamp(os.fstat(stream.fileno()))
                or stamp(before) != stamp(path.stat(follow_symlinks=False)) or sha(raw) != checksum):
            raise ValueError('Pinned fixture source preimage changed: ' + name)
    return raw


@functools.lru_cache(maxsize=1)
def replayed_sources():
    selected = os.environ.get(CANONICAL_ENV)
    if selected is None:
        raise unittest.SkipTest(CANONICAL_ENV + ' not selected; pinned canonical source fixture required')
    root = Path(selected)
    if (not root.is_absolute() or '..' in root.parts or not root.is_dir()
            or any(part.is_symlink() for part in (root, *root.parents))):
        raise ValueError('Selected canonical source must be an existing absolute unlinked directory')
    policy = producer.phase_policy()
    base = policy['base_series']
    raw = (REPO / base['path']).read_bytes()
    if sha(raw) != base['sha256']:
        raise ValueError('Original series identity changed')
    entries = json.loads(raw)['patches']
    if len(entries) != 3:
        raise ValueError('Exactly the three original patch entries are required')
    initial_hashes, steps = {}, []
    for entry in entries:
        manifest_raw = (REPO / entry['manifest']).read_bytes()
        if sha(manifest_raw) != entry['manifest_sha256']:
            raise ValueError('Original patch manifest changed')
        manifest = json.loads(manifest_raw)
        patch = (REPO / entry['patch']).read_bytes()
        if sha(patch) != manifest['patch_sha256']:
            raise ValueError('Original patch bytes changed')
        for name, checksum in manifest['before'].items():
            initial_hashes.setdefault(name, checksum)
        steps.append((manifest, patch))
    initial = {}
    for name, checksum in initial_hashes.items():
        if checksum is None:
            path = root / name
            if path.exists() or path.is_symlink():
                raise ValueError('Original newly-created path is already present: ' + name)
        else:
            initial[name] = checked_source_file(root, name, checksum)
    if len(initial) != 24 or len(initial_hashes) != 37 or sum(map(len, initial.values())) > MAX_FIXTURE_BYTES:
        raise ValueError('Selected fixture is not the bounded original 24-preimage window')
    current = initial
    for manifest, patch in steps:
        for name, checksum in manifest['before'].items():
            if (sha(current[name]) if name in current else None) != checksum:
                raise ValueError('Original series preimage association changed')
        current, modified = apply_exact_patch(current, patch)
        if modified != {name for name in manifest['before']
                        if manifest['before'][name] != manifest['after'][name]}:
            raise ValueError('Original series changed unexpected paths')
        for name, checksum in manifest['after'].items():
            if (sha(current[name]) if name in current else None) != checksum:
                raise ValueError('Original series postimage association changed')
    before = current
    phase = load(PORT / 'phase-patch.json')
    for name, checksum in phase['before'].items():
        if (sha(before[name]) if name in before else None) != checksum:
            raise ValueError('Phase patch preimage changed')
    after, modified = apply_exact_patch(before, (PORT / 'cosmic-comp-phase-observation.patch').read_bytes())
    if modified != set(phase['before']) or len(modified) != 4:
        raise ValueError('Phase patch changed unexpected paths')
    for name, checksum in phase['after'].items():
        if sha(after[name]) != checksum:
            raise ValueError('Phase patch postimage changed')
    return before, after


def phase_source(name, *, before=False):
    old, new = replayed_sources()
    return (old if before else new)[name]


class SeriesAndSourceTests(unittest.TestCase):
    def test_exact_original_three_plus_fourth_patch_replay(self):
        before, after = replayed_sources()
        phase = load(PORT / 'phase-patch.json')
        self.assertEqual(len(before), 37)
        self.assertEqual(len(after), 38)
        for name in before.keys() - set(phase['before']):
            self.assertEqual(after[name], before[name])
        for name, checksum in phase['after'].items():
            self.assertEqual(sha(after[name]), checksum)

    def test_exact_patch_rejects_changed_preimage_without_fuzz(self):
        phase = load(PORT / 'phase-patch.json')
        initial = {name: phase_source(name, before=True)
                   for name, checksum in phase['before'].items() if checksum is not None}
        initial['src/lib.rs'] = initial['src/lib.rs'].replace(b'    // init state\n', b'    // drift state\n')
        with self.assertRaisesRegex(ValueError, 'preimage'):
            apply_exact_patch(initial, (PORT / 'cosmic-comp-phase-observation.patch').read_bytes())

    def test_series_keeps_original_entries_and_binds_all_new_bytes(self):
        previous = load(REPO / 'ports/cosmic/native-comp/native-series.json')
        current = load(PORT / 'native-series.json')
        self.assertEqual(current['patches'][:-1], previous['patches'])
        self.assertEqual({k: v for k, v in current.items() if k != 'patches'},
                         {k: v for k, v in previous.items() if k != 'patches'})
        phase = load(PORT / 'phase-patch.json')
        self.assertEqual(sha((PORT / 'phase-patch.json').read_bytes()), current['patches'][-1]['manifest_sha256'])
        self.assertEqual(sha((PORT / 'cosmic-comp-phase-observation.patch').read_bytes()), phase['patch_sha256'])
        self.assertEqual(sha((PORT / 'native-series.json').read_bytes()), producer.SERIES_SHA256)

    def test_original_rust_operations_are_preserved_in_order(self):
        phase = load(PORT / 'phase-patch.json')
        for name, checksum in phase['before'].items():
            if checksum is None:
                continue
            old = phase_source(name, before=True).decode().splitlines()
            new = phase_source(name).decode().splitlines()
            new = [line.replace('let mut presentation = PendingPresentation::new(',
                                'let presentation = PendingPresentation::new(') for line in new]
            cursor = iter(new)
            for line in old:
                self.assertTrue(any(candidate == line for candidate in cursor), (name, line))
        patch = (PORT / 'cosmic-comp-phase-observation.patch').read_text()
        removed = [line[1:] for line in patch.splitlines()
                   if line.startswith('-') and not line.startswith('---')]
        self.assertEqual(removed, [
            '            let presentation = PendingPresentation::new(self.native.info(), mapping.flipped())?;'])

    def test_phase_has_closed_once_only_and_fixed_stack_bound(self):
        source = phase_source('src/backend/cyxia/phase.rs').decode()
        policy = load(PORT / 'source-policy.json')['observation']
        body = source.split('pub(crate) enum Phase {\n', 1)[1].split('\n}', 1)[0]
        variants = re.findall(r'^    ([A-Za-z]+),$', body, re.M)
        mappings = re.findall(r'Self::([A-Za-z]+) => "([a-z_]+)"', source)
        self.assertEqual(len(variants), 19)
        self.assertEqual([name for name, _ in mappings], variants)
        self.assertEqual([value for _, value in mappings], policy['events'])
        self.assertLess(len(variants), 32)
        maximum = max(len(f'CYXIA_COMP_PHASE_V1 pid={2**32-1} phase={name} elapsed_ns={2**128-1}\n'.encode())
                      for name in policy['events'])
        self.assertLessEqual(maximum, policy['max_record_bytes'])
        self.assertEqual(policy['max_record_bytes'] * len(variants), policy['max_output_bytes'])
        self.assertEqual(source.count('.write_all('), 1)
        self.assertIn('let _ = std::io::stderr().lock().write_all', source)
        once = source.index('SEEN.fetch_or(bit, Ordering::Relaxed)')
        early = source.index('return false;', once)
        self.assertLess(early, source.index('ORIGIN.get_or_init'))
        self.assertLess(early, source.index('.write_all'))
        self.assertNotRegex(source, r'\b(?:Vec|String|sleep|loop|panic|unwrap|expect)\b')
        self.assertNotIn('PASS', source)

    def test_first_cursor_success_and_black_exclusion(self):
        source = phase_source('src/backend/cyxia/native/presentation.rs').decode()
        self.assertIn('observe_first_frame: false,', source)
        begin = source.index('phase::mark_once(Phase::FirstTileSubmitBegin)')
        match = source.index('match submit(rect, &self.tile[..length])')
        ok = source.index('Ok(0) => {', match)
        end = source.index('phase::mark_once(Phase::FirstTileSubmitEnd)', ok)
        full = source.index('phase::mark_once(Phase::FirstFullScanoutComplete)', end)
        failure = source.index('Err(err)', full)
        self.assertLess(begin, match)
        self.assertLess(ok, end)
        self.assertLess(full, failure)
        self.assertIn('self.deadline = now() + STALL_TIMEOUT;', source[ok:end])
        self.assertIn('if self.observe_first_frame && rgba.is_some() {', source[ok:end])
        self.assertIn('if self.left == self.info.width {', source[end:full])
        self.assertEqual(source.count('Phase::FirstFullScanoutComplete'), 1)
        backend = phase_source('src/backend/cyxia/mod.rs').decode()
        self.assertEqual(backend.count('Phase::FirstRenderBegin'), 1)
        self.assertEqual(backend.count('observe_first_frame(first_frame)'), 1)
        self.assertIn('let first_frame = phase::mark_once(Phase::FirstRenderBegin);', backend)
        self.assertLess(backend.index('sync.wait().context'), backend.index('Phase::FirstRenderEnd'))
        self.assertIn('if first_frame && mapping.is_some()', backend)

    def test_state_and_success_boundaries_wrap_original_calls(self):
        source = phase_source('src/lib.rs').decode()
        self.assertLess(source.index('Phase::StateBegin'), source.index('state::State::new('))
        self.assertLess(source.index('state::State::new('), source.index('Phase::StateEnd'))
        self.assertLess(source.index('Phase::StateEnd'), source.index('libei::setup_ei('))
        backend = phase_source('src/backend/cyxia/mod.rs').decode()
        for name, call in [('EglDisplay', 'EGLDisplay::new('), ('EglContext', 'EGLContext::new('),
                           ('Renderer', 'GlowRenderer::new('), ('Shaders', 'init_shaders(renderer.borrow_mut())')]:
            begin, end = backend.index('Phase::' + name + 'Begin'), backend.index('Phase::' + name + 'End')
            self.assertLess(begin, backend.index(call))
            self.assertLess(backend.index(call), end)
            self.assertIn('?;', backend[begin:end])


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.root = mock.patch.object(producer, 'ROOT', REPO)
        self.root.start()
        self.addCleanup(self.root.stop)
        self.policy = load(PORT / 'source-policy.json')
        self.recipe = load(PORT / 'native-linux-recipe.json')

    def test_actual_repository_policy_and_recipe_are_bound(self):
        self.assertEqual(producer.phase_policy(), self.policy)
        producer.contract(self.recipe)
        self.assertEqual(sha((PORT / 'source-policy.json').read_bytes()), producer.POLICY_SHA256)
        self.assertFalse(self.policy['guest_execution'])

    def test_legacy_recipe_is_rejected(self):
        recipe = copy.deepcopy(self.recipe)
        recipe.pop('phase_observation_policy')
        recipe['source_series'] = self.policy['base_series']
        with self.assertRaises(producer.base.CosmicBuildError):
            producer.contract(recipe)

    def test_feature_native_lock_profile_mutations_are_rejected(self):
        mutations = []
        for key, value in [('features', []), ('default_features', True), ('resource_profile', 'other'),
                           ('effective_lock_sha256', '0' * 64), ('source_lock_sha256', '0' * 64),
                           ('static_link_inputs', [])]:
            recipe = copy.deepcopy(self.recipe)
            recipe[key] = value
            mutations.append(recipe)
        for index in range(len(self.recipe['native_inputs'])):
            recipe = copy.deepcopy(self.recipe)
            recipe['native_inputs'][index]['sha256'] = '0' * 64
            mutations.append(recipe)
        for recipe in mutations:
            with self.subTest(recipe=recipe), self.assertRaises(producer.base.CosmicBuildError):
                producer.contract(recipe)

    def test_all_original_resource_bounds_and_jobs_are_kept(self):
        original = load(REPO / self.policy['resource_profile']['path'])
        producer.full_os_profile(original, self.recipe, 2)
        for key in ('max_elf_bytes', 'image_bytes', 'stack_bytes', 'jobs_max', 'min_free_bytes',
                    'max_build_bytes', 'timeout_seconds'):
            altered = copy.deepcopy(original)
            altered['build_profiles'][producer.PROFILE][key] += 1
            with self.subTest(key=key), self.assertRaises(producer.base.CosmicBuildError):
                producer.full_os_profile(altered, self.recipe, 2)
        with self.assertRaises(producer.base.CosmicBuildError):
            producer.full_os_profile(original, self.recipe, 3)

    def test_old_critical_producer_functions_are_byte_preserved(self):
        previous = functions((REPO / 'tools/build_cosmic_comp_linux.py').read_text())
        current = functions((SUBJECT / 'build_cosmic_comp_linux_v2.py').read_text())
        changed = {'contract', 'metadata_identity', 'perform', 'compile_selected'}
        self.assertEqual(set(current) - set(previous), {'phase_policy', 'resolution'})
        for name in previous.keys() - changed:
            with self.subTest(name=name):
                self.assertEqual(current[name], previous[name])
        self.assertEqual(current['compile_selected'].replace(
            "    report['preserved_resolution'] = resolution(metadata, stage)\n", ''), previous['compile_selected'])
        self.assertEqual(current['metadata_identity'].replace('    resolution(metadata, stage)\n', ''),
                         previous['metadata_identity'])

    def test_original_consumer_source_commands_and_identity_helpers_are_preserved(self):
        previous = functions((REPO / 'tools/cosmic_comp_inputs_v1.py').read_text())
        current = functions((SUBJECT / 'cosmic_comp_inputs_v2.py').read_text())
        self.assertEqual(set(previous), set(current))
        for name in previous.keys() - {'metadata_identity', 'validate_build'}:
            with self.subTest(name=name):
                self.assertEqual(current[name], previous[name])
        self.assertEqual(Path(consumer.producer.__file__).resolve(), SUBJECT / 'build_cosmic_comp_linux_v2.py')


class GraphTests(unittest.TestCase):
    def setUp(self):
        stage = Path('/synthetic/compositor/source')
        root, config = 'root-id', 'config-id'
        self.stage = stage
        self.metadata = {
            'version': 1, 'workspace_members': [root, config], 'workspace_default_members': [root],
            'packages': [
                {'id': root, 'name': 'cosmic-comp', 'version': '1.0.0', 'source': None,
                 'manifest_path': str(stage / 'Cargo.toml')},
                {'id': config, 'name': 'cosmic-comp-config', 'version': '1.0.0', 'source': None,
                 'manifest_path': str(stage / 'cosmic-comp-config/Cargo.toml')},
            ],
            'resolve': {'nodes': [
                {'id': root, 'features': ['backend-cyxia'], 'dependencies': [config],
                 'deps': [{'name': 'cosmic_comp_config', 'pkg': config,
                           'dep_kinds': [{'kind': None, 'target': None}]}]},
                {'id': config, 'features': [], 'dependencies': [], 'deps': []},
            ]},
        }
        expected = copy.deepcopy(load(PORT / 'source-policy.json')['preserved_resolution'])
        expected.update(package_count=2,
                        normalized_graph_sha256=producer.files.canonical_hash(
                            producer.files.normalized_resolution(self.metadata)))
        self.expected = expected
        self.patch = mock.patch.object(producer, 'phase_policy', return_value={'preserved_resolution': expected})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_synthetic_graph_accepts_only_expected_graph(self):
        self.assertEqual(producer.resolution(self.metadata, self.stage), self.expected)

    def test_feature_and_version_drift_are_rejected(self):
        for section, field, value in [('node', 'features', []), ('package', 'version', '1.0.1'),
                                       ('package', 'source', 'registry+https://invalid.example')]:
            metadata = copy.deepcopy(self.metadata)
            target = metadata['resolve']['nodes'][0] if section == 'node' else metadata['packages'][0]
            target[field] = value
            with self.subTest(field=field), self.assertRaises(producer.base.CosmicBuildError):
                producer.resolution(metadata, self.stage)

    def test_edge_kind_and_target_drift_are_rejected(self):
        for kind in [{'kind': 'build', 'target': None}, {'kind': None, 'target': 'cfg(windows)'}]:
            metadata = copy.deepcopy(self.metadata)
            metadata['resolve']['nodes'][0]['deps'][0]['dep_kinds'] = [kind]
            with self.subTest(kind=kind), self.assertRaises(producer.base.CosmicBuildError):
                producer.resolution(metadata, self.stage)

    def test_missing_and_duplicate_nodes_are_rejected(self):
        for duplicate in (False, True):
            metadata = copy.deepcopy(self.metadata)
            if duplicate:
                metadata['resolve']['nodes'].append(copy.deepcopy(metadata['resolve']['nodes'][0]))
            else:
                metadata['resolve']['nodes'].pop()
            with self.subTest(duplicate=duplicate), self.assertRaises(producer.base.CosmicBuildError):
                producer.resolution(metadata, self.stage)

    def test_duplicate_workspace_members_are_rejected(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['workspace_members'].append('root-id')
        with self.assertRaises(producer.base.CosmicBuildError):
            producer.resolution(metadata, self.stage)

    def test_other_default_member_is_rejected(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['workspace_default_members'] = ['config-id']
        with self.assertRaises(producer.base.CosmicBuildError):
            producer.resolution(metadata, self.stage)

    def test_external_manifest_and_renamed_local_manifest_are_rejected(self):
        for manifest in ['/external/Cargo.toml', str(self.stage / 'renamed/Cargo.toml')]:
            metadata = copy.deepcopy(self.metadata)
            metadata['packages'][1]['manifest_path'] = manifest
            with self.subTest(manifest=manifest), self.assertRaises(producer.base.CosmicBuildError):
                producer.resolution(metadata, self.stage)

    def test_legitimate_export_relocation_preserves_graph(self):
        relocated = copy.deepcopy(self.metadata)
        stage = Path('/another/private/source')
        for package in relocated['packages']:
            package['manifest_path'] = str(stage / Path(package['manifest_path']).relative_to(self.stage))
        self.assertEqual(producer.resolution(relocated, stage), self.expected)


class ConsumerBoundaryTests(unittest.TestCase):
    def report(self):
        return {'schema_version': 1, 'kind': producer.KIND, 'phase_policy_sha256': producer.POLICY_SHA256,
                'status': 'cross-built', 'operation': 'build', 'target': 'x86_64-unknown-linux-musl',
                'architecture': 'x86_64', 'link_completed': True, 'target_linked': True,
                'source_preserved': True, 'producer_sources_preserved': True, 'cargo_offline': True,
                'build_script_network_sandbox': False, 'guest_execution': 'not performed',
                'cosmic_session_ready': False, 'output': '/synthetic/output'}

    def test_old_build_cannot_be_promoted_by_new_consumer(self):
        report = self.report()
        report.pop('kind')
        report.pop('phase_policy_sha256')
        with mock.patch.object(consumer, 'path', side_effect=lambda value, **kwargs: Path(value)), \
             mock.patch.object(consumer, 'read_json', return_value=(report, '0' * 64)), \
             mock.patch.object(producer, 'phase_policy', side_effect=AssertionError('Past first version gate')):
            with self.assertRaisesRegex(consumer.BuildError, 'successful native'):
                consumer.validate_build(Path('/synthetic/output'))

    def test_wrong_version_type_or_policy_is_rejected_before_heavy_inputs(self):
        for key, value in [('kind', 'cosmic-comp'), ('phase_policy_sha256', '0' * 64),
                           ('schema_version', True), ('guest_execution', False)]:
            report = self.report()
            report[key] = value
            with self.subTest(key=key), \
                 mock.patch.object(consumer, 'path', side_effect=lambda value, **kwargs: Path(value)), \
                 mock.patch.object(consumer, 'read_json', return_value=(report, '0' * 64)), \
                 mock.patch.object(producer, 'phase_policy', side_effect=AssertionError('Past first version gate')):
                with self.assertRaises(consumer.BuildError):
                    consumer.validate_build(Path('/synthetic/output'))

    def test_observation_contract_drift_is_not_accepted(self):
        report = self.report()
        policy = load(PORT / 'source-policy.json')
        report['phase_observation_contract'] = copy.deepcopy(policy['observation'])
        report['phase_observation_contract']['timing_gate_input'] = True
        with mock.patch.object(consumer, 'path', side_effect=lambda value, **kwargs: Path(value)), \
             mock.patch.object(consumer, 'read_json', return_value=(report, '0' * 64)), \
             mock.patch.object(producer, 'phase_policy', return_value=policy), \
             mock.patch.object(consumer, 'bind', side_effect=AssertionError('Past observation gate')):
            with self.assertRaisesRegex(consumer.BuildError, 'observation contract'):
                consumer.validate_build(Path('/synthetic/output'))


if __name__ == '__main__':
    unittest.main()
