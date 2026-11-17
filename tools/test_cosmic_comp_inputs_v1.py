"""Retained-input consumer tests using real local Git/files and parser bytes.

No compiler, Cargo, service or guest runs. Reports, tools and ELF in these
fixtures are contract samples, never genuine compositor build evidence.
"""
from contextlib import ExitStack
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import cosmic_comp_inputs_v1 as subject
from tools.test_install_cosmic_notifications import archive, object_bytes, full_os_fixture


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


def save(path, value):
    return write(path, json.dumps(value, indent=2) + '\n')


def git(directory, *arguments):
    return subprocess.run(['/usr/bin/git', '-c', 'user.name=Consumer Fixture',
                           '-c', 'user.email=fixture@example.invalid', '-C', str(directory), *arguments],
                          env=subject.base.clean_environment('/usr/bin:/bin'),
                          capture_output=True, text=True, check=True).stdout.strip()


def commit(directory):
    git(directory, 'init', '--quiet')
    git(directory, 'add', '--all')
    git(directory, 'commit', '--quiet', '-m', 'Source identity fixture')
    return git(directory, 'rev-parse', 'HEAD')


class Fixture:
    def __init__(self, root, stack):
        self.root, self.repo = root, root / 'repository'
        self.output = root / 'build'
        self.source_cache, self.cache = root / 'sources', root / 'cache'
        self.original = self.source_cache / 'cosmic-comp-epoch'
        self.stage = root / 'deleted-temporary/source'
        self.retained = self.output / 'source'
        self.sdk, self.rust = root / 'sdk', root / 'rust'
        self.registry = self.cache / 'registry/src/fixture/registry-dep-1.0.0'
        self.dependency = self.cache / 'git/checkouts/dep-fixture/pinned'
        write(self.dependency / 'Cargo.toml', '[package]\nname="git-dep"\nversion="1.0.0"\n')
        write(self.dependency / 'src/lib.rs', '// canonical Git dependency fixture\n')
        dependency_commit = commit(self.dependency)
        self.spec = 'git+https://example.invalid/dep?branch=feature/test#' + dependency_commit
        locked_spec = self.spec.replace('feature/test', 'feature%2Ftest')
        self.registry_spec = 'registry+https://example.invalid/index'
        write(self.registry / 'Cargo.toml', '[package]\nname="registry-dep"\nversion="1.0.0"\n')
        write(self.registry / 'src/lib.rs', '// retained registry contract sample\n')
        write(self.original / 'Cargo.toml', '[package]\nname="cosmic-comp"\nversion="1.0.0"\n'
              '[features]\nbackend-cyxia=[]\n')
        write(self.original / 'Cargo.lock', 'version=4\n[[package]]\nname="cosmic-comp"\nversion="1.0.0"\n'
              '[[package]]\nname="git-dep"\nversion="1.0.0"\nsource=' + json.dumps(locked_spec) + '\n'
              '[[package]]\nname="registry-dep"\nversion="1.0.0"\nsource=' + json.dumps(self.registry_spec) + '\n')
        before = b'fn main() {} // original fixture\n'
        after = b'fn main() {} // reviewed fixture port\n'
        write(self.original / 'src/main.rs', before)
        write(self.original / 'LICENSE', 'upstream source fixture license\n')
        source_commit = commit(self.original)
        git(self.original, 'remote', 'add', 'origin', 'https://github.com/pop-os/cosmic-comp')
        self.source = {'name': 'cosmic-comp', 'directory': 'cosmic-comp-epoch',
                       'repository': 'https://github.com/pop-os/cosmic-comp', 'commit': source_commit}
        lock_sha = subject.base.digest(self.original / 'Cargo.lock')
        self.patch_path = self.repo / 'ports/fixture.patch'
        self.manifest_path = self.repo / 'ports/fixture.json'
        write(self.patch_path, '--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n'
              '-fn main() {} // original fixture\n+fn main() {} // reviewed fixture port\n')
        patch_sha = subject.base.digest(self.patch_path)
        save(self.manifest_path, {'schema_version': 1, 'repository': self.source['repository'],
            'commit': source_commit, 'patch_sha256': patch_sha,
            'before': {'src/main.rs': hashlib.sha256(before).hexdigest()},
            'after': {'src/main.rs': hashlib.sha256(after).hexdigest()}})
        manifest_sha = subject.base.digest(self.manifest_path)
        self.series_path = self.repo / subject.producer.SERIES
        save(self.series_path, {'schema_version': 1, 'component': 'cosmic-comp',
            'repository': self.source['repository'], 'commit': source_commit, 'source_lock_sha256': lock_sha,
            'patches': [{'manifest': 'ports/fixture.json', 'patch': 'ports/fixture.patch',
                         'manifest_sha256': manifest_sha}]})
        series_sha = subject.base.digest(self.series_path)
        # Copy the real transitive producer source closure into this fixture.
        # Contract pins are overridden solely for the real temporary Git source.
        for name in subject.contracts.producer_sources(subject.BUILDER):
            write(self.repo / name, (subject.ROOT / name).read_bytes())
        for target, name, value in (
            (subject, 'ROOT', self.repo), (subject, 'BUILDER', self.repo / 'tools/build_cosmic_comp_linux.py'),
            (subject.contracts, 'ROOT', self.repo), (subject.producer, 'ROOT', self.repo),
            (subject.producer, 'COMMIT', source_commit), (subject.producer, 'LOCK_SHA256', lock_sha),
            (subject.producer, 'SERIES_SHA256', series_sha)):
            stack.enter_context(patch.object(target, name, value))
        stack.enter_context(patch.object(subject.base.ports, 'load_manifest',
                                        return_value={'components': [self.source]}))
        shutil.copytree(self.original, self.stage, ignore=shutil.ignore_patterns('.git'))
        write(self.stage / 'src/main.rs', after)
        shutil.copytree(self.stage, self.retained)
        native = []
        for name in ('libc.a', 'libclang_rt.builtins-x86_64.a', 'crt1.o', 'crti.o', 'crtn.o'):
            selected = write(self.sdk / 'sysroot/usr/lib' / name,
                             archive() if name.endswith('.a') else object_bytes())
            native.append({'path': str(selected.relative_to(self.sdk)), 'sha256': subject.base.digest(selected)})
        write(self.sdk / 'sysroot/usr/include/fixture.h', '/* target header fixture */\n')
        self.recipe_path = root / 'recipe.json'
        self.recipe = {'schema_version': 1, 'component': 'cosmic-comp', 'package': 'cosmic-comp',
            'binary': 'cosmic-comp', 'commit': source_commit, 'target': 'x86_64-unknown-linux-musl',
            'purpose': 'bounded-build-experiment', 'resource_profile': subject.producer.PROFILE,
            'default_features': False, 'features': ['backend-cyxia'],
            'source_lock_sha256': lock_sha, 'effective_lock_sha256': lock_sha, 'patches': [],
            'source_series': {'path': subject.producer.SERIES, 'sha256': series_sha},
            'native_inputs': native, 'static_link_inputs': []}
        save(self.recipe_path, self.recipe)
        self.profile_path = root / 'profile.json'
        self.profile = {'target_runtime_validated': False, 'jobs_max': 2, 'min_free_bytes': 1024**3,
            'max_build_bytes': 3*1024**3, 'timeout_seconds': 3600, 'max_elf_bytes': 64*1024**2,
            'image_bytes': 64*1024**2, 'stack_bytes': 2*1024**2}
        save(self.profile_path, {'schema_version': 1, 'target': self.recipe['target'],
                                 'build_profiles': {subject.producer.PROFILE: self.profile}})
        library = self.rust / 'lib/rustlib' / self.recipe['target'] / 'lib'
        std = write(library / 'libstd-abc123.rlib', archive())
        unwind = write(library / 'self-contained/libunwind.a', archive())
        tool_paths = {'rustc': self.rust / 'bin/rustc', 'cargo': self.rust / 'bin/cargo',
            'target_cc': self.sdk / 'bin/x86_64-linux-musl-cc',
            'target_cxx': self.sdk / 'bin/x86_64-linux-musl-cxx',
            'target_ar': self.sdk / 'bin/x86_64-linux-musl-ar',
            'target_ranlib': self.sdk / 'bin/x86_64-linux-musl-ranlib',
            'host_cc': root / 'host/clang', 'strip': self.rust / 'lib/rustlib/fixture-host/bin/llvm-strip',
            'pkg_config': root / 'host/pkg-config'}
        tools = {}
        for name, selected in tool_paths.items():
            write(selected, 'Contract tool bytes, NEVER EXECUTED: ' + name)
            selected.chmod(0o755)
            tools[name] = {'path': str(selected), 'sha256': subject.base.digest(selected), 'available': True}
        self.tools = tools
        write(self.output / 'native/libunwind.a', unwind.read_bytes())
        for name in ('target-pkg-config', 'host-pkg-config'):
            write(self.output / 'bin' / name, '# fixture generated wrapper, NEVER EXECUTED\n')
        metadata = {'version': 1, 'workspace_root': str(self.stage), 'target_directory': str(self.output / 'target'),
            'packages': [
                {'id': 'root', 'name': 'cosmic-comp', 'version': '1.0.0', 'source': None,
                 'manifest_path': str(self.stage / 'Cargo.toml'), 'targets': [{'name': 'cosmic-comp', 'kind': ['bin']}]},
                {'id': 'git', 'name': 'git-dep', 'version': '1.0.0', 'source': self.spec,
                 'manifest_path': str(self.dependency / 'Cargo.toml'), 'targets': []},
                {'id': 'registry', 'name': 'registry-dep', 'version': '1.0.0', 'source': self.registry_spec,
                 'manifest_path': str(self.registry / 'Cargo.toml'), 'targets': []}],
            'resolve': {'nodes': [{'id': 'root', 'dependencies': ['git', 'registry'], 'features': ['backend-cyxia']},
                                 {'id': 'git', 'dependencies': [], 'features': []},
                                 {'id': 'registry', 'dependencies': [], 'features': []}]}}
        self.metadata = metadata
        records = subject.producer.metadata_identity(metadata, self.stage, self.cache, self.recipe)
        save(self.output / 'metadata.json', metadata)
        write(self.output / 'metadata.stderr.log', '')
        write(self.output / 'cargo.log', 'HOST CONTRACT FIXTURE: NO COMPOSITOR WAS COMPILED\n')
        self.linked = write(self.output / 'target' / self.recipe['target'] / 'release/cosmic-comp', full_os_fixture())
        self.binary = write(self.output / 'cosmic-comp.elf', full_os_fixture())
        linked = subject.elf.inspect_full_os_elf(self.linked, self.profile)
        published = subject.elf.inspect_full_os_elf(self.binary, self.profile)
        producers = subject.contracts.producer_sources(subject.BUILDER)
        common = ['--manifest-path', str(self.stage / 'Cargo.toml'), '--locked', '--offline',
                  '--no-default-features', '--features', 'backend-cyxia']
        self.report = {'schema_version': 1, 'status': 'cross-built', 'operation': 'build',
            'target': self.recipe['target'], 'architecture': 'x86_64', 'output': str(self.output),
            'component': self.source, 'recipe_path': str(self.recipe_path), 'recipe': self.recipe,
            'recipe_sha256': subject.base.digest(self.recipe_path), 'producer_sources': producers,
            'producer_sources_after': producers, 'builder_sha256': subject.base.digest(subject.BUILDER),
            'link_completed': True, 'target_linked': True, 'source_preserved': True,
            'producer_sources_preserved': True, 'cargo_offline': True, 'build_script_network_sandbox': False,
            'guest_execution': 'not performed', 'cosmic_session_ready': False, 'jobs': 1,
            'source_cache': str(self.source_cache), 'cargo_cache': str(self.cache),
            'canonical_source': subject.producer.git_identity(self.original, source_commit),
            'series_sha256': series_sha, 'patches': [{'patch': 'ports/fixture.patch', 'patch_sha256': patch_sha,
                'manifest': 'ports/fixture.json', 'manifest_sha256': manifest_sha, 'changed_paths': ['src/main.rs']}],
            'source_tree': subject.base.tree_identity(self.retained), 'original_export_root': str(self.stage),
            'cargo_dependencies': records, 'profile_file': str(self.profile_path),
            'profile_file_sha256': subject.base.digest(self.profile_path), 'resource_profile': self.profile,
            'operation_timeout_seconds': 3600, 'elapsed_seconds': 1.0,
            'timeout_scope': 'Shared across export, Cargo commands and validation; publication refuses an expired deadline',
            'sysroot': str(self.sdk), 'sysroot_before': subject.base.tree_identity(self.sdk / 'sysroot'),
            'toolchain': {'target': self.recipe['target'], 'architecture': 'x86_64', 'host': 'fixture-host',
                'selection': {'schema_version': 1, 'rust_root': str(self.rust), 'host_cc': tools['host_cc']['path']},
                'rustc_version': 'rustc fixture\nhost: fixture-host\n', 'host_cc_version': 'clang fixture\n',
                'tools': tools, 'std': {'path': str(std), 'sha256': subject.base.digest(std)},
                'unwind': {'path': str(unwind), 'sha256': subject.base.digest(unwind)},
                'native_inputs': native, 'static_link_inputs': []},
            'generated_build_inputs': {key: subject.base.tree_identity(self.output / key) for key in ('bin', 'native')},
            'metadata_command': [tools['cargo']['path'], 'metadata', '--format-version', '1',
                '--filter-platform', self.recipe['target'], *common],
            'command': [tools['cargo']['path'], 'build', '--release', '--target', self.recipe['target'],
                '--jobs', '1', '--package', 'cosmic-comp', '--bin', 'cosmic-comp', *common],
            'retained_logs': {name: subject.base.digest(self.output / name) for name in subject.LOGS},
            'linked_binary': {'path': str(self.linked), 'bytes': self.linked.stat().st_size,
                              'sha256': linked['executable']['sha256']},
            'full_os_inspection': linked, 'executable': {**published['executable'], 'path': str(self.binary)},
            'image_load_pages': published['image_load_pages']}
        self.save()
        shutil.rmtree(self.stage.parent)

    def save(self):
        save(self.output / 'build-report.json', self.report)

    def save_metadata(self):
        save(self.output / 'metadata.json', self.metadata)
        self.report['retained_logs']['metadata.json'] = subject.base.digest(self.output / 'metadata.json')
        self.save()

    def validate(self):
        return subject.validate_build(self.output)


class CompositorConsumer(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.fixture = Fixture(Path(temporary.name).resolve(), self.stack)

    def reject(self, message=None):
        with self.assertRaisesRegex(subject.BuildError, message or '.'):
            self.fixture.validate()

    def test_removed_export_is_relocated_and_identity_is_stable_without_native_execution(self):
        fixture = self.fixture
        original_run = subprocess.run

        def read_only_git(command, *args, **kwargs):
            self.assertEqual(command[0], '/usr/bin/git')
            self.assertTrue(any(token in command for token in ('rev-parse', 'ls-tree', 'remote')))
            return original_run(command, *args, **kwargs)

        before = subject.base.tree_identity(fixture.root)
        with patch.object(subprocess, 'run', side_effect=read_only_git):
            result = fixture.validate()
            self.assertEqual(result, fixture.validate())
        self.assertFalse(fixture.stage.exists())
        self.assertEqual(before, subject.base.tree_identity(fixture.root))
        self.assertEqual(result['executable']['path'], str(fixture.binary))
        self.assertEqual(result['executable']['file'], str(fixture.binary))
        self.assertEqual(result['image_load_pages'], 2)
        self.assertEqual(result['required_pages'], 514)
        self.assertFalse(result['guest_execution'])
        self.assertFalse(result['cosmic_session_ready'])
        self.assertEqual(result['identity']['dependencies']['package_count'], 3)
        self.assertEqual(result['identity_sha256'], subject.canonical(result['identity']))

    def test_failed_metadata_only_incomplete_and_runtime_claiming_receipts_are_rejected(self):
        original = copy.deepcopy(self.fixture.report)
        for field, value in [('status', 'FAILED'), ('status', 'CARGO_SOURCES_AVAILABLE'),
                             ('operation', 'prepare'), ('link_completed', False), ('target_linked', False),
                             ('source_preserved', False), ('producer_sources_preserved', False),
                             ('cargo_offline', False), ('guest_execution', 'passed'),
                             ('cosmic_session_ready', True), ('schema_version', True), ('error', 'previous failure')]:
            with self.subTest(field=field, value=value):
                self.fixture.report = {**original, field: value}
                self.fixture.save()
                self.reject('successful native compositor')

    def test_detached_or_symlinked_output_is_rejected(self):
        self.fixture.report['output'] = str(self.fixture.root)
        self.fixture.save()
        self.reject('Detached')
        alias = self.fixture.root / 'alias'
        alias.symlink_to(self.fixture.output, target_is_directory=True)
        with self.assertRaises(subject.BuildError):
            subject.validate_build(alias)

    def test_transitive_producer_bytes_must_still_match(self):
        producer_file = self.fixture.repo / 'tools/cosmic_comp_git.py'
        producer_file.write_bytes(producer_file.read_bytes() + b'\n# changed after build\n')
        self.reject('producer closure changed')

    def test_top_git_bytes_and_head_are_revalidated(self):
        selected = self.fixture.original / 'src/main.rs'
        selected.write_text('changed original source\n')
        self.reject('blob bytes changed')
        git(self.fixture.original, 'add', '--all')
        git(self.fixture.original, 'commit', '--quiet', '-m', 'Changed source')
        self.reject('HEAD differs')

    def test_retained_postimage_cannot_be_forged_by_updating_only_tree_receipt(self):
        write(self.fixture.retained / 'src/main.rs', 'unreviewed postimage\n')
        self.fixture.report['source_tree'] = subject.base.tree_identity(self.fixture.retained)
        self.fixture.save()
        self.reject('canonical patch result')

    def test_unbound_retained_files_and_mode_changes_are_rejected(self):
        extra = write(self.fixture.retained / 'extra.rs', '// unbound\n')
        self.reject('missing or unbound')
        extra.unlink()
        (self.fixture.retained / 'src/main.rs').chmod(0o755)
        self.reject('mode differs')

    def test_current_patch_and_series_are_hash_bound(self):
        for selected in (self.fixture.patch_path, self.fixture.manifest_path, self.fixture.series_path):
            original = selected.read_bytes()
            selected.write_bytes(original + b'\n')
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)

    def test_real_git_and_registry_dependency_mutations_are_rejected(self):
        for selected in (self.fixture.dependency / 'src/lib.rs', self.fixture.registry / 'src/lib.rs'):
            original = selected.read_bytes()
            selected.write_bytes(original + b'changed dependency\n')
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)

    def test_local_manifest_can_only_relocate_under_exact_recorded_root(self):
        self.fixture.metadata['packages'][0]['manifest_path'] = str(self.fixture.original / 'Cargo.toml')
        self.fixture.save_metadata()
        self.reject('exact local compositor')

    def test_resolved_features_and_metadata_workspace_are_checked(self):
        self.fixture.metadata['resolve']['nodes'][0]['features'] = ['backend-winit']
        self.fixture.save_metadata()
        self.reject('backend/features')
        self.fixture.metadata['resolve']['nodes'][0]['features'] = ['backend-cyxia']
        self.fixture.metadata['workspace_root'] = str(self.fixture.original)
        self.fixture.save_metadata()
        self.reject('workspace/target')

    def test_commands_cannot_change_target_offline_package_or_backend(self):
        original = copy.deepcopy(self.fixture.report)
        for field, previous, replacement in (('command', '--offline', '--frozen'),
                ('command', '--package', '--workspace'), ('command', 'backend-cyxia', 'backend-winit'),
                ('metadata_command', '--locked', '--no-deps')):
            self.fixture.report = copy.deepcopy(original)
            command = self.fixture.report[field]
            command[command.index(previous)] = replacement
            self.fixture.save()
            with self.subTest(previous=previous):
                self.reject('Cargo commands')

    def test_recipe_resource_profile_and_deadline_evidence_are_checked(self):
        for selected in (self.fixture.recipe_path, self.fixture.profile_path):
            original = selected.read_bytes()
            selected.write_bytes(original + b'\n')
            with self.subTest(path=selected):
                self.reject('identity changed')
            selected.write_bytes(original)
        self.fixture.report['operation_timeout_seconds'] = 7200
        self.fixture.save()
        self.reject('deadline evidence')

    def test_sdk_library_header_driver_and_explicit_toolchain_drift_are_rejected(self):
        for selected in (self.fixture.sdk / 'sysroot/usr/lib/libc.a',
                         self.fixture.sdk / 'sysroot/usr/include/fixture.h',
                         Path(self.fixture.tools['target_cc']['path']),
                         Path(self.fixture.tools['rustc']['path'])):
            original = selected.read_bytes()
            selected.write_bytes(original + b'changed\n')
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)
        del self.fixture.report['toolchain']['selection']
        self.fixture.save()
        self.reject('Explicit compositor')

    def test_generated_wrapper_native_and_log_bytes_are_revalidated(self):
        for selected in (self.fixture.output / 'bin/target-pkg-config',
                         self.fixture.output / 'native/libunwind.a', self.fixture.output / 'cargo.log'):
            original = selected.read_bytes()
            selected.write_bytes(original + b'changed\n')
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)
        del self.fixture.report['retained_logs']['metadata.stderr.log']
        self.fixture.save()
        self.reject('log closure')

    def test_raw_and_published_elf_are_both_bound(self):
        for selected in (self.fixture.linked, self.fixture.binary):
            original = selected.read_bytes()
            changed = bytearray(original)
            changed[-1] ^= 1
            selected.write_bytes(changed)
            with self.subTest(path=selected):
                self.reject()
            selected.write_bytes(original)

    def test_omitting_generated_wrapper_from_both_disk_and_receipt_is_rejected(self):
        (self.fixture.output / 'bin/target-pkg-config').unlink()
        self.fixture.report['generated_build_inputs']['bin'] = subject.base.tree_identity(self.fixture.output / 'bin')
        self.fixture.save()
        self.reject('input closure is incomplete')

    def test_full_os_parser_rejects_foreign_elf_even_if_hash_receipt_is_updated(self):
        data = bytearray(self.fixture.linked.read_bytes())
        struct.pack_into('<H', data, 18, 183)
        self.fixture.linked.write_bytes(data)
        self.fixture.binary.write_bytes(data)
        self.fixture.report['linked_binary']['sha256'] = subject.base.digest(self.fixture.linked)
        self.fixture.save()
        self.reject('x86|machine|ELF')

    def test_tampered_admission_pages_and_published_path_are_rejected(self):
        original = copy.deepcopy(self.fixture.report)
        self.fixture.report['image_load_pages'] += 1
        self.fixture.save()
        self.reject('Published compositor')
        self.fixture.report = original
        self.fixture.report['executable']['path'] = str(self.fixture.linked)
        self.fixture.save()
        self.reject('Published compositor')


if __name__ == '__main__':
    unittest.main()
