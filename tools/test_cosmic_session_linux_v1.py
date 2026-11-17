"""Session v1 host contracts with real local Git trees and parser byte fixtures.

Cargo/compiler calls are replaced at their boundary. Nothing in this suite is
native build, service execution or guest evidence. Source export, patches,
metadata relocation, tool/SDK hashing and FullOs parsing are production code.
"""
from contextlib import ExitStack
import copy
import difflib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch

from tools import build_cosmic_session_linux_v1 as builder
from tools import cosmic_session_inputs_v1 as consumer
from tools.test_install_cosmic_notifications import archive, object_bytes, full_os_fixture

contract, base = builder.contract, builder.base


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


def save(path, value):
    return write(path, json.dumps(value, indent=2) + '\n')


def git(directory, *arguments):
    return subprocess.run(['/usr/bin/git', '-c', 'user.name=Session Fixture',
                           '-c', 'user.email=fixture@example.invalid', '-C', str(directory), *arguments],
                          env=base.clean_environment('/usr/bin:/bin'), check=True,
                          capture_output=True, text=True).stdout.strip()


def commit(directory):
    git(directory, 'init', '--quiet')
    git(directory, 'add', '--all')
    git(directory, 'commit', '--quiet', '-m', 'Pinned source contract fixture')
    return git(directory, 'rev-parse', 'HEAD')


class Fixture:
    def __init__(self, root, stack):
        self.root, self.repo = root, root / 'repository'
        self.output, self.source_cache, self.cache = root / 'build', root / 'sources', root / 'cache'
        self.original, self.launch = self.source_cache / 'cosmic-session', self.source_cache / 'launch-pad-pin'
        self.sdk, self.rust = root / 'sdk', root / 'rust'
        self.git_dependency = self.cache / 'git/checkouts/dependency-fixture/pinned'
        self.registry = self.cache / 'registry/src/fixture/registry-dep-1.0.0'
        write(self.git_dependency / 'Cargo.toml', '[package]\nname="git-dep"\nversion="1.0.0"\n')
        write(self.git_dependency / 'src/lib.rs', '// canonical transitive Git source\n')
        dependency_commit = commit(self.git_dependency)
        self.spec = 'git+https://example.invalid/dependency?branch=feature/test#' + dependency_commit
        self.registry_spec = 'registry+https://example.invalid/index'
        write(self.registry / 'Cargo.toml', '[package]\nname="registry-dep"\nversion="1.0.0"\n')
        write(self.registry / 'src/lib.rs', '// retained registry fixture\n')
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode='w:gz') as stream:
            for selected in sorted(self.registry.rglob('*')):
                if selected.is_file():
                    raw = selected.read_bytes()
                    entry = tarfile.TarInfo(self.registry.name + '/' + str(selected.relative_to(self.registry)))
                    entry.size, entry.mode = len(raw), 0o644
                    stream.addfile(entry, io.BytesIO(raw))
        self.registry_archive = write(self.cache / 'registry/cache/fixture' / (self.registry.name + '.crate'), packed.getvalue())
        launch_files = {'Cargo.toml': '[package]\nname="launch-pad"\nversion="1.0.1"\n',
                        'src/lib.rs': '// original genuine-source contract sample\n',
                        'LICENSE': 'License fixture, not an upstream artifact\n'}
        for name, raw in launch_files.items():
            write(self.launch / name, raw)
        launch_commit = commit(self.launch)
        git(self.launch, 'remote', 'add', 'origin', 'https://github.com/pop-os/launch-pad')
        source_files = {'Cargo.toml': '[package]\nname="cosmic-session"\nversion="1.10.0"\n',
                        'Cargo.lock': 'version=4\n[[package]]\nname="cosmic-session"\nversion="1.10.0"\n',
                        'src/main.rs': 'fn main() {} // source contract fixture\n',
                        'LICENSE': 'Fixture source license\n'}
        for name, raw in source_files.items():
            write(self.original / name, raw)
        source_commit = commit(self.original)
        git(self.original, 'remote', 'add', 'origin', 'https://github.com/pop-os/cosmic-session')
        self.source = {'name': 'cosmic-session', 'directory': self.original.name,
                       'repository': 'https://github.com/pop-os/cosmic-session', 'commit': source_commit}
        self.port = self.repo / contract.PORT
        old_port = self.repo / 'ports/cosmic/native-session'
        after = {'Cargo.toml': source_files['Cargo.toml'] + '\n[features]\ncyxia-native=["launch-pad/cyxia-native"]\n'
                 '[dependencies]\nlaunch-pad={path="native-deps/launch-pad"}\n',
                 'Cargo.lock': source_files['Cargo.lock'] + '[[package]]\nname="launch-pad"\nversion="1.0.1"\n'
                 '[[package]]\nname="git-dep"\nversion="1.0.0"\nsource=' + json.dumps(
                     self.spec.replace('feature/test', 'feature%2Ftest')) + '\n'
                 '[[package]]\nname="registry-dep"\nversion="1.0.0"\nsource=' + json.dumps(self.registry_spec)
                 + '\nchecksum="' + base.digest(self.registry_archive) + '"\n',
                 **{'native-deps/launch-pad/' + name: raw for name, raw in launch_files.items()}}
        after['native-deps/launch-pad/Cargo.toml'] += '[features]\ncyxia-native=[]\n'
        patch_bytes = ''.join(''.join(difflib.unified_diff(source_files.get(name, '').splitlines(keepends=True),
                                raw.splitlines(keepends=True), fromfile='a/' + name if name in source_files else '/dev/null',
                                tofile='b/' + name)) for name, raw in sorted(after.items())).encode()
        self.patch = write(self.port / 'cosmic-session-native.patch', patch_bytes)
        original_patch = write(old_port / 'cosmic-session-native.patch', patch_bytes)
        support = write(old_port / 'native_child.rs', '// reviewed child fixture, NEVER COMPILED\n')
        manifest_path = old_port / 'native-patch.json'
        originals = {}
        for key, source_path, pin in [('session', self.original, source_commit), ('launch_pad', self.launch, launch_commit)]:
            identity = contract.common.git_identity(source_path, pin)
            files = {name: item['sha256'] for name, item in identity['files'].items()}
            originals[key] = {'commit': pin, 'git_tree': identity['git_tree'],
                              'files': files, 'tree_sha256': contract.canonical(files)}
        source_lock = base.digest(self.original / 'Cargo.lock')
        effective_lock = hashlib.sha256(after['Cargo.lock'].encode()).hexdigest()
        save(manifest_path, {'component': 'cosmic-session', 'commit': source_commit,
            'source_lock_sha256': source_lock, 'effective_lock_sha256': effective_lock,
            'patch_sha256': base.digest(self.patch), 'source_inputs': originals,
            'support_inputs': {str(support.relative_to(self.repo)): base.digest(support)},
            'before': {name: hashlib.sha256(source_files[name].encode()).hexdigest() if name in source_files else None
                       for name in after},
            'after': {name: hashlib.sha256(raw.encode()).hexdigest() for name, raw in after.items()}})
        self.policy = {'schema_version': 1, 'kind': contract.KIND, 'component': 'cosmic-session',
            'version': '1.10.0', 'repository': self.source['repository'], 'commit': source_commit,
            'directory': self.original.name, 'git_tree': originals['session']['git_tree'],
            'source_lock_sha256': source_lock, 'effective_lock_sha256': effective_lock,
            'patch_manifest': {'path': str(manifest_path.relative_to(self.repo)), 'sha256': base.digest(manifest_path)},
            'original_patch': {'path': str(original_patch.relative_to(self.repo)), 'sha256': base.digest(original_patch)},
            'support_inputs': {str(support.relative_to(self.repo)): base.digest(support)},
            'launch_pad': {'repository': 'https://github.com/pop-os/launch-pad', 'commit': launch_commit,
                'directory': self.launch.name, 'git_tree': originals['launch_pad']['git_tree'], 'version': '1.0.1'},
            'default_features': False, 'features': ['cyxia-native'], 'launch_pad_features': ['cyxia-native'],
            'guest_execution': False, 'cosmic_session_ready': False}
        policy_path = save(self.port / 'source-policy.json', self.policy)
        native_inputs = []
        for name in contract.NATIVE_NAMES:
            selected = write(self.sdk / 'sysroot/usr/lib' / name, archive() if name.endswith('.a') else object_bytes())
            native_inputs.append({'path': str(selected.relative_to(self.sdk)), 'sha256': base.digest(selected)})
        write(self.sdk / 'sysroot/usr/include/fixture.h', '// reviewed SDK fixture\n')
        self.recipe = {'schema_version': 1, 'component': 'cosmic-session', 'package': 'cosmic-session',
            'binary': 'cosmic-session', 'commit': source_commit, 'target': contract.TARGET,
            'purpose': 'bounded-build-experiment', 'resource_profile': contract.PROFILE,
            'default_features': False, 'features': ['cyxia-native'], 'source_lock_sha256': source_lock,
            'effective_lock_sha256': effective_lock,
            'patches': [{'path': self.patch.name, 'sha256': base.digest(self.patch)}], 'native_inputs': native_inputs}
        self.recipe_path = save(self.port / 'native-recipe.json', self.recipe)
        self.profile = {'target_runtime_validated': False, 'jobs_max': 1, 'min_free_bytes': 1024**3,
            'max_build_bytes': 512*1024**2, 'timeout_seconds': 900, 'image_bytes': 64*1024**2,
            'max_elf_bytes': 64*1024**2, 'stack_bytes': 2*1024**2}
        self.profile_path = save(self.port / 'resource-profile.json', {'schema_version': 1,
                'target': contract.TARGET, 'build_profiles': {contract.PROFILE: self.profile}})
        real_root = builder.ROOT
        for name in builder.producer_sources():
            write(self.repo / name, (real_root / name).read_bytes())
        for target, name, value in [
            (builder, 'ROOT', self.repo), (builder, 'BUILDER', self.repo / 'tools/build_cosmic_session_linux_v1.py'),
            (consumer, 'ROOT', self.repo), (contract, 'ROOT', self.repo),
            (contract.common.os_x86, 'ROOT', self.repo),
            (contract, 'POLICY_SHA256', base.digest(policy_path)),
            (contract, 'RECIPE_SHA256', base.digest(self.recipe_path)),
            (contract, 'RESOURCE_SHA256', base.digest(self.profile_path)),
        ]:
            stack.enter_context(patch.object(target, name, value))
        stack.enter_context(patch.object(base.ports, 'load_manifest', return_value={'components': [self.source]}))
        self.host = 'x86_64-unknown-linux-gnu'
        library = self.rust / 'lib/rustlib' / contract.TARGET / 'lib'
        std = write(library / 'libstd-abc123.rlib', archive())
        unwind = write(library / 'self-contained/libunwind.a', archive())
        write(library / 'libcore-abc123.rlib', archive())
        self.tool_paths = {'rustc': self.rust / 'bin/rustc', 'cargo': self.rust / 'bin/cargo',
            'target_cc': self.sdk / 'bin/x86_64-linux-musl-cc',
            'target_cxx': self.sdk / 'bin/x86_64-linux-musl-cxx',
            'target_ar': self.sdk / 'bin/x86_64-linux-musl-ar',
            'target_ranlib': self.sdk / 'bin/x86_64-linux-musl-ranlib',
            'host_cc': root / 'host/clang', 'strip': self.rust / 'lib/rustlib' / self.host / 'bin/llvm-strip',
            'pkg_config': root / 'host/pkg-config'}
        for name, selected in self.tool_paths.items():
            write(selected, 'Contract tool fixture, NEVER EXECUTED: ' + name).chmod(0o755)
        self.toolchain = {'target': contract.TARGET, 'architecture': 'x86_64', 'host': self.host,
            'selection': {'schema_version': 1, 'rust_root': str(self.rust), 'host_cc': str(self.tool_paths['host_cc'])},
            'rustc_version': 'rustc 1.95.0\nrelease: 1.95.0\nhost: ' + self.host + '\n',
            'host_cc_version': 'clang fixture, never executed\n', 'native_inputs': native_inputs,
            'static_link_inputs': [], 'std': {'path': str(std), 'sha256': base.digest(std)},
            'unwind': {'path': str(unwind), 'sha256': base.digest(unwind)}}
        self.commands = []
        self.hook = None
        self.link_bytes = full_os_fixture()
        stack.enter_context(patch.object(contract.common.selection, 'tools_and_sysroot', side_effect=self.select_tools))
        stack.enter_context(patch.object(base, 'run_bounded', side_effect=self.run_bounded))

    def select_tools(self, *args, **kwargs):
        result = copy.deepcopy(self.toolchain)
        result['tools'] = {name: {'path': str(selected), 'sha256': base.digest(selected), 'available': True}
                           for name, selected in self.tool_paths.items()}
        for item in result['native_inputs']:
            contract.require(base.digest(self.sdk / item['path']) == item['sha256'], 'SDK fixture input changed')
        for field in ('std', 'unwind'):
            result[field]['sha256'] = base.digest(result[field]['path'])
        return dict(self.tool_paths), result

    def run_bounded(self, command, control, env, log, timeout, min_free, max_bytes, **kwargs):
        self.commands.append((command, timeout))
        contract.require(command[0] == str(self.tool_paths['cargo']) and '--offline' in command
                         and '--locked' in command and env['CARGO_NET_OFFLINE'] == 'true',
                         'Unexpected fixture Cargo boundary')
        stage = Path(command[command.index('--manifest-path') + 1]).parent
        if command[1] == 'metadata':
            root_id = 'path+' + stage.as_uri() + '#cosmic-session@1.10.0'
            launch_path = stage / 'native-deps/launch-pad'
            launch_id = 'path+' + launch_path.as_uri() + '#launch-pad@1.0.1'
            metadata = {'version': 1, 'workspace_root': str(stage), 'target_directory': str(self.output / 'target'),
                'packages': [
                    {'id': root_id, 'name': 'cosmic-session', 'version': '1.10.0', 'source': None,
                     'manifest_path': str(stage / 'Cargo.toml'), 'targets': [{'name': 'cosmic-session', 'kind': ['bin']}]},
                    {'id': launch_id, 'name': 'launch-pad', 'version': '1.0.1', 'source': None,
                     'manifest_path': str(launch_path / 'Cargo.toml'), 'targets': [{'name': 'launch_pad', 'kind': ['lib']}]},
                    {'id': 'git', 'name': 'git-dep', 'version': '1.0.0', 'source': self.spec,
                     'manifest_path': str(self.git_dependency / 'Cargo.toml'), 'targets': []},
                    {'id': 'registry', 'name': 'registry-dep', 'version': '1.0.0', 'source': self.registry_spec,
                     'manifest_path': str(self.registry / 'Cargo.toml'), 'targets': []}],
                'resolve': {'nodes': [
                    {'id': root_id, 'dependencies': [launch_id, 'git', 'registry'], 'features': ['cyxia-native']},
                    {'id': launch_id, 'dependencies': [], 'features': ['cyxia-native']},
                    {'id': 'git', 'dependencies': [], 'features': []},
                    {'id': 'registry', 'dependencies': [], 'features': []}]}}
            save(log, metadata)
            write(kwargs['stderr_log'], 'HOST METADATA FIXTURE; NO CARGO EXECUTION\n')
        elif command[1] == 'build':
            write(log, 'HOST BUILD CONTRACT FIXTURE; NO NATIVE COMPILATION\n')
            write(self.output / 'target' / contract.TARGET / 'release/cosmic-session', self.link_bytes)
        else:
            raise AssertionError('Unexpected native/acquisition operation')
        if self.hook is not None:
            self.hook(command, stage)

    def build(self, action='build'):
        return builder.perform(action, self.recipe_path, self.profile_path, self.output,
                               self.sdk, self.source_cache, self.cache, self.rust, self.tool_paths['host_cc'])

    def report(self):
        return json.loads((self.output / 'build-report.json').read_text())

    def save_report(self, report):
        save(self.output / 'build-report.json', report)

    def metadata(self):
        return json.loads((self.output / 'metadata.json').read_text())

    def save_metadata(self, metadata):
        save(self.output / 'metadata.json', metadata)
        report = self.report()
        report['retained_logs']['metadata.json'] = base.digest(self.output / 'metadata.json')
        self.save_report(report)


class SessionContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.fixture = Fixture(Path(temporary.name).resolve(), self.stack)

    def reject(self, message='.'):
        with self.assertRaisesRegex(base.CosmicBuildError, message):
            consumer.validate_build(self.fixture.output)

    def test_build_fixture_round_trip_relocates_deleted_export_without_native_execution(self):
        fixture = self.fixture
        report = fixture.build()
        self.assertEqual(report['status'], 'cross-built')
        self.assertFalse(Path(report['original_export_root']).exists())
        self.assertEqual(len(fixture.commands), 2)
        self.assertLess(fixture.commands[1][1], fixture.commands[0][1])
        before = base.tree_identity(fixture.root)
        original_run = subprocess.run

        def readonly_git(command, *args, **kwargs):
            self.assertEqual(command[0], '/usr/bin/git')
            self.assertTrue(any(token in command for token in ('rev-parse', 'ls-tree', 'remote')))
            return original_run(command, *args, **kwargs)

        with patch.object(subprocess, 'run', side_effect=readonly_git):
            actual = consumer.validate_build(fixture.output)
            self.assertEqual(actual, consumer.validate_build(fixture.output))
        self.assertEqual(before, base.tree_identity(fixture.root))
        self.assertEqual(actual['status'], 'SESSION_BUILD_REVALIDATED_NOT_RUN')
        self.assertEqual(actual['identity']['dependencies']['package_count'], 4)
        self.assertEqual(actual['required_pages'], 514)
        self.assertFalse(actual['guest_execution'])
        self.assertFalse(actual['cosmic_session_ready'])

    def test_metadata_only_never_publishes_or_passes_consumer(self):
        report = self.fixture.build('metadata')
        self.assertEqual(report['status'], 'SESSION_METADATA_VERIFIED_NOT_BUILT')
        self.assertFalse(report['target_linked'])
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())
        self.assertEqual(len(self.fixture.commands), 1)
        self.reject('successful native session')

    def test_real_source_patch_and_new_fixed_policy_drift_are_rejected_before_cargo(self):
        for selected in (self.fixture.original / 'src/main.rs', self.fixture.launch / 'src/lib.rs',
                         self.fixture.patch, self.fixture.port / 'source-policy.json'):
            original = selected.read_bytes()
            selected.write_bytes(original + b'changed\n')
            with self.subTest(path=selected), self.assertRaises(base.CosmicBuildError):
                self.fixture.build()
            self.assertFalse(self.fixture.commands)
            selected.write_bytes(original)
            if self.fixture.output.exists():
                shutil.rmtree(self.fixture.output)

    def test_success_refuses_changed_inputs_on_every_postcheck_path(self):
        targets = [self.fixture.original / 'src/main.rs', self.fixture.launch / 'src/lib.rs',
                   self.fixture.sdk / 'sysroot/usr/include/fixture.h',
                   self.fixture.rust / 'lib/rustlib' / contract.TARGET / 'lib/libcore-abc123.rlib',
                   self.fixture.tool_paths['host_cc'], self.fixture.repo / 'tools/cosmic_session_linux_v1.py']
        for selected in targets:
            original = selected.read_bytes()
            self.fixture.hook = lambda command, stage, selected=selected: (
                selected.write_bytes(original + b'changed\n') if command[1] == 'build' else None)
            with self.subTest(path=selected), self.assertRaises(base.CosmicBuildError):
                self.fixture.build()
            report = self.fixture.report()
            self.assertEqual(report['status'], 'FAILED')
            self.assertFalse(report['target_linked'])
            self.assertFalse(report['inputs_preserved'])
            self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())
            self.assertTrue((self.fixture.output / 'target' / contract.TARGET / 'release/cosmic-session').exists())
            selected.write_bytes(original)
            shutil.rmtree(self.fixture.output)

    def test_build_failure_preserves_raw_logs_and_detects_concurrent_mutation(self):
        def fail(command, stage):
            if command[1] == 'build':
                write(self.fixture.output / 'native/libunwind.a', b'changed runtime\n')
                raise RuntimeError('simulated compiler exit 1')
        self.fixture.hook = fail
        with self.assertRaisesRegex(base.CosmicBuildError, 'simulated compiler exit 1'):
            self.fixture.build()
        report = self.fixture.report()
        self.assertFalse(report['inputs_preserved'])
        self.assertTrue(any(item.startswith('generated inputs:') for item in report['postcheck_errors']))
        self.assertIn('cargo.log', report['retained_logs'])
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())

    def test_metadata_observation_cannot_change_between_resolution_and_publication(self):
        def changed(command, stage):
            if command[1] == 'build':
                metadata = self.fixture.metadata()
                metadata['workspace_root'] = str(self.fixture.original)
                save(self.fixture.output / 'metadata.json', metadata)
        self.fixture.hook = changed
        with self.assertRaisesRegex(base.CosmicBuildError, 'Cargo metadata'):
            self.fixture.build()
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())

    def test_full_os_rejection_cannot_publish_a_successful_link(self):
        self.fixture.link_bytes = b'not a target ELF\n'
        with self.assertRaises(base.CosmicBuildError):
            self.fixture.build()
        report = self.fixture.report()
        self.assertTrue(report['link_completed'])
        self.assertFalse(report['target_linked'])
        self.assertEqual(report['status'], 'FAILED')
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())

    def test_publication_failure_has_no_installable_result(self):
        actual_inspect = contract.elf.inspect_full_os_elf
        def inspector(path, profile):
            if Path(path).parent.name.startswith('.publication-'):
                raise ValueError('simulated candidate inspection failure')
            return actual_inspect(path, profile)
        with patch.object(contract.elf, 'inspect_full_os_elf', side_effect=inspector):
            with self.assertRaisesRegex(base.CosmicBuildError, 'candidate inspection'):
                self.fixture.build()
        self.assertEqual(self.fixture.report()['status'], 'FAILED')
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())

    def test_missing_required_log_cannot_publish(self):
        def remove_log(command, stage):
            if command[1] == 'build':
                (self.fixture.output / 'cargo.log').unlink()
        self.fixture.hook = remove_log
        with self.assertRaises(base.CosmicBuildError):
            self.fixture.build()
        self.assertEqual(self.fixture.report()['status'], 'FAILED')
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())

    def test_receipt_write_failure_revokes_publication_and_is_propagated(self):
        original_write = Path.write_text
        def fail_receipt(path, *args, **kwargs):
            if path.name == '.build-report.json.tmp':
                raise OSError('simulated receipt write failure')
            return original_write(path, *args, **kwargs)
        with patch.object(Path, 'write_text', new=fail_receipt):
            with self.assertRaisesRegex(OSError, 'receipt write failure'):
                self.fixture.build()
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())
        self.assertEqual(self.fixture.report()['status'], 'FAILED')
        self.assertFalse(self.fixture.report()['target_linked'])

    def test_keyboard_interrupt_revokes_candidate_and_propagates(self):
        original_replace = Path.replace
        def interrupt(path, destination):
            if Path(destination).name == 'cosmic-session.elf':
                original_replace(path, destination)
                raise KeyboardInterrupt('fixture publication interrupt')
            return original_replace(path, destination)
        with patch.object(Path, 'replace', new=interrupt):
            with self.assertRaisesRegex(KeyboardInterrupt, 'publication interrupt'):
                self.fixture.build()
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())
        self.assertEqual(self.fixture.report()['status'], 'FAILED')

    def test_one_shared_deadline_covers_metadata_and_build(self):
        actual_remaining = contract.common.remaining_bounds
        calls = []
        def remaining(deadline, bounds):
            calls.append(deadline)
            if len(calls) == 2:
                raise base.CosmicBuildError('shared deadline expired after metadata')
            return actual_remaining(deadline, bounds)
        with patch.object(contract.common, 'remaining_bounds', side_effect=remaining):
            with self.assertRaisesRegex(base.CosmicBuildError, 'shared deadline expired'):
                self.fixture.build()
        self.assertEqual(len(set(calls)), 1)
        self.assertEqual(len(self.fixture.commands), 1)
        self.assertFalse((self.fixture.output / 'cosmic-session.elf').exists())

    def test_native_launch_pad_features_and_dependency_edge_are_required_before_compile(self):
        def wrong_features(command, stage):
            if command[1] == 'metadata':
                metadata = self.fixture.metadata()
                metadata['resolve']['nodes'][1]['features'] = []
                save(self.fixture.output / 'metadata.json', metadata)
        self.fixture.hook = wrong_features
        with self.assertRaisesRegex(base.CosmicBuildError, 'feature selection'):
            self.fixture.build()
        self.assertEqual(len(self.fixture.commands), 1)

    def test_input_overlap_and_existing_output_are_never_overwritten(self):
        original = self.fixture.output
        self.fixture.output = self.fixture.sdk / 'new-output'
        with self.assertRaisesRegex(base.CosmicBuildError, 'overlaps'):
            self.fixture.build()
        self.assertFalse(self.fixture.output.exists())
        self.fixture.output = original
        write(original / 'keep', 'preserve me')
        with self.assertRaisesRegex(base.CosmicBuildError, 'output already exists'):
            self.fixture.build()
        self.assertEqual((original / 'keep').read_text(), 'preserve me')

    def test_consumer_rejects_failed_partial_and_runtime_claiming_reports(self):
        original = self.fixture.build()
        for field, value in [('status', 'FAILED'), ('operation', 'metadata'), ('target_linked', False),
                ('inputs_preserved', False), ('cosmic_session_ready', True), ('guest_execution', 'passed'),
                ('schema_version', True), ('error', 'previous failure'), ('postcheck_errors', ['SDK changed'])]:
            self.fixture.save_report({**original, field: value})
            with self.subTest(field=field):
                self.reject('successful native session')

    def test_consumer_checks_both_genuine_originals_not_only_retained_source(self):
        self.fixture.build()
        for selected in (self.fixture.original / 'src/main.rs', self.fixture.launch / 'src/lib.rs'):
            original = selected.read_bytes()
            selected.write_bytes(original + b'changed\n')
            with self.subTest(path=selected):
                self.reject('blob bytes changed')
            selected.write_bytes(original)
        git(self.fixture.launch, 'remote', 'set-url', 'origin', 'https://example.invalid/other')
        self.reject('repository changed')

    def test_consumer_retained_postimage_and_modes_derive_from_bound_patch(self):
        self.fixture.build()
        selected = self.fixture.output / 'source/native-deps/launch-pad/src/lib.rs'
        original = selected.read_bytes()
        selected.write_bytes(original + b'forged retained source\n')
        report = self.fixture.report()
        report['source_tree'] = base.tree_identity(self.fixture.output / 'source')
        self.fixture.save_report(report)
        self.reject('fixed patch postimage')
        selected.write_bytes(original)
        selected.chmod(0o755)
        self.reject('fixed patch postimage')

    def test_consumer_rejects_producer_patch_policy_and_support_drift(self):
        self.fixture.build()
        for selected in (self.fixture.repo / 'tools/cosmic_session_linux_v1.py',
                         self.fixture.repo / self.fixture.policy['patch_manifest']['path'],
                         self.fixture.repo / 'ports/cosmic/native-session/native_child.rs', self.fixture.patch,
                         self.fixture.recipe_path, self.fixture.profile_path):
            original = selected.read_bytes()
            selected.write_bytes(original + b'\n')
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)

    def test_consumer_rechecks_real_git_and_registry_dependencies(self):
        self.fixture.build()
        for selected in (self.fixture.git_dependency / 'src/lib.rs', self.fixture.registry / 'src/lib.rs'):
            original = selected.read_bytes()
            selected.write_bytes(original + b'changed dependency\n')
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)

    def test_forged_registry_tree_receipt_does_not_bypass_locked_archive(self):
        report = self.fixture.build()
        write(self.fixture.registry / 'src/lib.rs', '// forged cached registry source\n')
        record = next(item for item in report['cargo_dependencies'] if item['name'] == 'registry-dep')
        record['source_tree_sha256'] = base.tree_identity(self.fixture.registry)['sha256']
        self.fixture.save_report(report)
        self.reject('differs from pinned archive')

    def test_consumer_requires_actual_launch_pad_features_edge_and_local_path(self):
        self.fixture.build()
        original = self.fixture.metadata()
        for mutation in ('features', 'edge', 'manifest'):
            metadata = copy.deepcopy(original)
            if mutation == 'features':
                metadata['resolve']['nodes'][1]['features'] = ['systemd']
            elif mutation == 'edge':
                metadata['resolve']['nodes'][0]['dependencies'].remove(metadata['packages'][1]['id'])
            else:
                metadata['packages'][1]['manifest_path'] = str(self.fixture.launch / 'Cargo.toml')
            self.fixture.save_metadata(metadata)
            with self.subTest(mutation=mutation):
                self.reject()

    def test_consumer_checks_exact_offline_package_id_and_command(self):
        original = self.fixture.build()
        for previous, replacement in [('--offline', '--frozen'), ('--package', '--workspace'),
                                      ('cyxia-native', 'systemd'), (original['package_id'], 'cosmic-session')]:
            report = copy.deepcopy(original)
            report['command'][report['command'].index(previous)] = replacement
            self.fixture.save_report(report)
            with self.subTest(previous=previous):
                self.reject('exact locked offline')

    def test_consumer_rechecks_sdk_tools_extra_rust_archives_generated_inputs_and_logs(self):
        self.fixture.build()
        for selected in (self.fixture.sdk / 'sysroot/usr/include/fixture.h', self.fixture.tool_paths['host_cc'],
                         self.fixture.rust / 'lib/rustlib' / contract.TARGET / 'lib/libcore-abc123.rlib',
                         self.fixture.output / 'bin/target-pkg-config', self.fixture.output / 'cargo.log'):
            original = selected.read_bytes()
            selected.write_bytes(original + b'changed bytes\n')
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)

    def test_consumer_rechecks_raw_and_published_full_os_bytes(self):
        self.fixture.build()
        for selected in (self.fixture.output / 'cosmic-session.elf',
                         self.fixture.output / 'target' / contract.TARGET / 'release/cosmic-session'):
            original = selected.read_bytes()
            selected.write_bytes(original + b'changed link\n')
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)

    def test_consumer_rejects_detached_or_symlinked_output(self):
        report = self.fixture.build()
        report['output'] = str(self.fixture.root)
        self.fixture.save_report(report)
        self.reject('Detached')
        alias = self.fixture.root / 'alias'
        alias.symlink_to(self.fixture.output, target_is_directory=True)
        with self.assertRaises(base.CosmicBuildError):
            consumer.validate_build(alias)


if __name__ == '__main__':
    unittest.main()
