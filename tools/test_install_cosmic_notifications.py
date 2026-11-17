"""Real-file/Git installer contracts; fixtures are never build or guest evidence."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import install_cosmic_notifications as subject


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


def save(path, data):
    return write(path, json.dumps(data, indent=2) + '\n')


def elf():
    """Static ELF parser bytes only; no compiler or notification implementation."""
    data = bytearray(4096)
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 2, 62, 1,
                     0x1000100, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 6, 4, 64, 0x1000040, 0x1000040, 112, 112, 8)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 5, 0, 0x1000000, 0x1000000, 4096, 4096, 4096)
    return bytes(data)


def full_os_fixture():
    """Parser fixture with a second LOAD outside the legacy 16 MiB window."""
    data = bytearray(8192)
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 2, 62, 1,
                     0x1000100, 64, 0, 0, 64, 56, 3, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 6, 4, 64, 0x1000040, 0x1000040, 168, 168, 8)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 5, 0, 0x1000000, 0x1000000, 4096, 4096, 4096)
    struct.pack_into('<IIQQQQQQ', data, 176, 1, 6, 4096, 0x2000000, 0x2000000, 4096, 4096, 4096)
    return bytes(data)


def object_bytes(machine=62):
    data = bytearray(64)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 1, machine)
    return bytes(data)


def archive(machine=62):
    data = object_bytes(machine)
    header = ('object.o/'.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6)
              + '644'.ljust(8) + str(len(data)).ljust(10) + '`\n').encode()
    return b'!<arch>\n' + header + data


@unittest.skipUnless(Path('/usr/bin/git').is_file(), 'real Git is required')
class NotificationInstallation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.build_output = self.root / 'build'
        self.output = self.root / 'installed'
        self.source_cache = self.root / 'sources'
        self.source = self.source_cache / 'cosmic-notifications'
        self.cache = self.root / 'cargo-cache'
        self.dependency = self.cache / 'registry/src/fixture/dependency-1.0.0'
        self.sysroot = self.root / 'sdk'
        self.recipe_path = self.root / 'ports/native-recipe.json'
        self.resource = self.root / 'ports/resource.json'
        self.policy_path = self.root / 'ports/source-policy.json'
        self.exported = self.build_output / 'source'
        self.stage = self.root / 'removed-temporary-build/source'
        self.addCleanup(mock.patch.stopall)
        write(self.source / 'Cargo.toml', '[package]\nname="cosmic-notifications"\nversion="1.10.0"\n')
        write(self.source / 'Cargo.lock', 'version=4\n[[package]]\nname="cosmic-notifications"\nversion="1.10.0"\n'
              '[[package]]\nname="dependency"\nversion="1.0.0"\nsource="registry+https://example.invalid/index"\n')
        write(self.source / 'src/main.rs', 'fn main() {} // contract fixture only\n')
        write(self.source / 'LICENSE.md', 'upstream license fixture\n')
        write(self.source / '.cargo/config.toml', subject.reviewed.CONFIG)
        write(self.source / '.cargo/config.default', subject.reviewed.CONFIG)
        for args in (('init', '-q'), ('add', '.'),
                     ('-c', 'user.name=Install Test', '-c', 'user.email=install@example.invalid', 'commit', '-qm', 'Source fixture'),
                     ('remote', 'add', 'origin', 'https://github.com/pop-os/cosmic-notifications')):
            subprocess.run(['/usr/bin/git', '-C', str(self.source), *args], check=True, capture_output=True,
                           env=subject.build.clean_environment('/usr/bin:/bin'))
        commit = subject.dependencies.pinned_git(self.source, 'rev-parse', 'HEAD')
        self.component = {'name': 'cosmic-notifications', 'directory': 'cosmic-notifications',
                          'repository': 'https://github.com/pop-os/cosmic-notifications', 'commit': commit}
        mock.patch.object(subject.build.ports, 'load_manifest', return_value={'components': [self.component]}).start()
        shutil.copytree(self.source, self.stage, ignore=shutil.ignore_patterns('.git'))
        before = subject.build.tree_identity(self.stage)
        removed = before['files']['.cargo/config.toml']
        (self.stage / '.cargo/config.toml').unlink()
        shutil.copytree(self.stage, self.exported)
        write(self.dependency / 'Cargo.toml', '[package]\nname="dependency"\nversion="1.0.0"\n')
        write(self.dependency / 'src/lib.rs', '// cache fixture\n')
        native = []
        for name in ('libc.a', 'libclang_rt.builtins-x86_64.a', 'crt1.o', 'crti.o', 'crtn.o',
                     'libwayland-client.a', 'libffi.a', 'libxkbcommon.a'):
            path = write(self.sysroot / 'sysroot/usr/lib' / name,
                         archive() if name.endswith('.a') else object_bytes())
            native.append({'path': str(path.relative_to(self.sysroot)), 'sha256': subject.build.digest(path)})
        rust = self.root / 'rust-toolchain'
        self.libdir = rust / 'lib/rustlib/x86_64-unknown-linux-musl/lib'
        std = write(self.libdir / 'libstd-ab12.rlib', archive())
        unwind = write(self.libdir / 'self-contained/libunwind.a', archive())
        write(self.libdir / 'libcore-ab12.rlib', archive())
        tool_paths = {'rustc': rust / 'bin/rustc', 'cargo': rust / 'bin/cargo',
                      'target_cc': self.sysroot / 'bin/x86_64-linux-musl-cc',
                      'target_cxx': self.sysroot / 'bin/x86_64-linux-musl-cxx',
                      'target_ar': self.sysroot / 'bin/x86_64-linux-musl-ar',
                      'target_ranlib': self.sysroot / 'bin/x86_64-linux-musl-ranlib',
                      'host_cc': self.root / 'host/clang', 'strip': rust / 'lib/rustlib/fixture-host/bin/llvm-strip',
                      'pkg_config': self.root / 'host/pkg-config'}
        tools = {}
        for name, path in tool_paths.items():
            if name == 'target_cxx':
                tools[name] = {'path': str(path), 'sha256': None, 'available': False}
            else:
                write(path, 'Tool file-hash fixture, never executed: ' + name)
                path.chmod(0o755)
                tools[name] = {'path': str(path), 'sha256': subject.build.digest(path), 'available': True}
        lock = subject.build.digest(self.source / 'Cargo.lock')
        self.policy = {'schema_version': 1, 'component': 'cosmic-notifications',
                       'repository': self.component['repository'], 'commit': commit, 'source_lock_sha256': lock,
                       'before': {'.cargo/config.toml': subject.reviewed.CONFIG_SHA256},
                       'after': {'.cargo/config.toml': None},
                       'rust_flags': list(subject.reviewed.FLAGS), 'rustdoc_flags': list(subject.reviewed.FLAGS)}
        save(self.policy_path, self.policy)
        self.recipe = {'schema_version': 1, 'component': 'cosmic-notifications', 'commit': commit,
                       'target': subject.TARGET.rust_target, 'purpose': 'bounded-build-experiment',
                       'package': 'cosmic-notifications', 'binary': 'cosmic-notifications',
                       'resource_profile': 'notifications-fixture', 'default_features': False, 'features': [],
                       'source_lock_sha256': lock, 'effective_lock_sha256': lock,
                       'native_inputs': native, 'patches': [],
                       'static_link_inputs': ['sysroot/usr/lib/libwayland-client.a', 'sysroot/usr/lib/libffi.a',
                                              'sysroot/usr/lib/libxkbcommon.a'],
                       'source_export_policy': {'path': 'source-policy.json', 'sha256': subject.build.digest(self.policy_path)},
                       'reviewed_rust_flags': list(subject.reviewed.FLAGS), 'reviewed_rustdoc_flags': list(subject.reviewed.FLAGS)}
        save(self.recipe_path, self.recipe)
        self.profile = {'target_runtime_validated': False, 'jobs_max': 2, 'min_free_bytes': 1024,
                        'max_build_bytes': 1024, 'timeout_seconds': 60, 'max_elf_bytes': 67108864,
                        'image_bytes': 67108864, 'stack_bytes': 2097152}
        save(self.resource, {'schema_version': 1, 'target': subject.TARGET.rust_target,
                             'build_profiles': {'notifications-fixture': self.profile}})
        package_id = 'path+' + self.stage.as_uri() + '#cosmic-notifications@1.10.0'
        self.metadata = {'version': 1, 'workspace_root': str(self.stage), 'packages': [
            {'name': 'cosmic-notifications', 'version': '1.10.0', 'id': package_id, 'source': None,
             'manifest_path': str(self.stage / 'Cargo.toml'),
             'targets': [{'name': 'cosmic-notifications', 'kind': ['bin']}]},
            {'name': 'dependency', 'version': '1.0.0', 'id': 'dependency-id',
             'source': 'registry+https://example.invalid/index',
             'manifest_path': str(self.dependency / 'Cargo.toml'), 'targets': []}],
            'resolve': {'nodes': [{'id': package_id, 'dependencies': ['dependency-id']},
                                  {'id': 'dependency-id', 'dependencies': []}]}}
        records = subject.dependencies.verify_metadata(self.metadata, self.stage, self.cache, self.recipe)
        save(self.build_output / 'metadata.json', self.metadata)
        write(self.build_output / 'metadata.stderr.log', '')
        write(self.build_output / 'cargo.log', 'Contract fixture only; no compiler ran\n')
        write(self.build_output / 'native/libunwind.a', unwind.read_bytes())
        binary = write(self.build_output / subject.PROGRAM, elf())
        linked = write(self.build_output / 'target/x86_64-unknown-linux-musl/release/cosmic-notifications', elf())
        common = ['--manifest-path', str(self.stage / 'Cargo.toml'), '--locked', '--offline', '--no-default-features']
        producers = subject.producer_sources(subject.ROOT / 'tools/build_cosmic_notifications.py')
        self.report = {'status': 'cross-built', 'component': self.component, 'recipe': self.recipe,
                       'recipe_sha256': subject.build.digest(self.recipe_path), 'resource_profile': self.profile,
                       'profile_sha256': hashlib.sha256(json.dumps(self.profile, sort_keys=True).encode()).hexdigest(),
                       'target': subject.TARGET.rust_target, 'architecture': 'x86_64',
                       'operation': 'build', 'cargo_offline': True, 'build_script_network_sandbox': False,
                       'guest_execution': 'not performed', 'cosmic_session_ready': False,
                       'link_completed': True, 'target_linked': True, 'source_preserved': True,
                       'producer_sources': producers, 'producer_sources_after': producers,
                       'producer_sources_preserved': True, 'source_export_policy': self.policy,
                       'reviewed_rust_flags': list(subject.reviewed.FLAGS), 'reviewed_rustdoc_flags': list(subject.reviewed.FLAGS),
                       'source_normalization': {'policy': self.policy, 'exporter_sha256': subject.build.digest(subject.reviewed.__file__),
                           'original_tree': before, 'source_tree': subject.build.tree_identity(self.stage),
                           'removed': {'.cargo/config.toml': removed}, 'source_preserved': True},
                       'patches': [], 'source_tree': subject.build.tree_identity(self.stage),
                       'toolchain': {'target': subject.TARGET.rust_target, 'architecture': 'x86_64', 'host': 'fixture-host',
                                     'std': {'path': str(std), 'sha256': subject.build.digest(std)},
                                     'unwind': {'path': str(unwind), 'sha256': subject.build.digest(unwind)},
                                     'native_inputs': native, 'static_link_inputs': self.recipe['static_link_inputs'], 'tools': tools},
                       'metadata_command': [str(tool_paths['cargo']), 'metadata', '--format-version', '1', '--filter-platform',
                                            subject.TARGET.rust_target, *common],
                       'command': [str(tool_paths['cargo']), 'build', '--release', '--target', subject.TARGET.rust_target,
                                   '--jobs', '1', '--package', package_id, '--bin', 'cosmic-notifications', *common],
                       'package_id': package_id, 'cargo_dependencies': records,
                       'sysroot_before': subject.build.tree_identity(self.sysroot / 'sysroot'),
                       'linked_binary': {'path': str(linked), 'bytes': linked.stat().st_size, 'sha256': subject.build.digest(linked)},
                       'executable': subject.build.inspect_elf(binary, subject.TARGET), 'image_load_pages': 1}
        for key, filename in {'builder_sha256': 'build_cosmic_notifications.py', 'common_builder_sha256': 'build_cosmic.py',
                              'source_exporter_sha256': 'cosmic_notifications_source.py',
                              'package_selector_sha256': 'build_cosmic_component.py',
                              'dependency_validator_sha256': 'cosmic_notifications_dependencies.py'}.items():
            self.report[key] = subject.build.digest(subject.ROOT / 'tools' / filename)
        save(self.build_output / 'build-report.json', self.report)
        # Mirror perform_build's actual lifetime: only output/source survives.
        shutil.rmtree(self.stage.parent)

    def install(self, **kwargs):
        return subject.install(self.build_output, self.output, recipe=self.recipe_path,
                               resource_profile=self.resource, sysroot=self.sysroot,
                               source_cache=self.source_cache, cache=self.cache, **kwargs)

    def legacy_window_failure(self, data=None):
        """Mirror the real post-link failure, including its absent published ELF."""
        data = full_os_fixture() if data is None else data
        linked = Path(self.report['linked_binary']['path'])
        linked.write_bytes(data)
        (self.build_output / subject.PROGRAM).unlink()
        self.report.update(status='failed', error=subject.LEGACY_LOAD_ERROR, target_linked=False,
                           linked_binary={'path': str(linked), 'bytes': len(data),
                                          'sha256': subject.build.digest(linked)})
        del self.report['executable']
        del self.report['image_load_pages']
        save(self.build_output / 'build-report.json', self.report)

    def test_build_producer_inventory_matches_actual_recording_format(self):
        with mock.patch.object(sys, 'path', [str(subject.ROOT / 'tools'), *sys.path]):
            import os_x86
        entry = subject.ROOT / 'tools/build_cosmic_notifications.py'
        self.assertEqual(subject.producer_sources(entry), os_x86.producer_sources(entry))

    def test_explicit_toolchain_selection_binds_actual_paths_and_version_observations(self):
        tools = self.report['toolchain']['tools']
        selection = {'schema_version': 1, 'rust_root': str(Path(tools['rustc']['path']).parent.parent),
                     'host_cc': tools['host_cc']['path']}
        self.report['toolchain'].update(selection=selection,
            host_cc_version='clang version 19.1.7 (fixture; never executed)\n',
            rustc_version='rustc 1.95.0 (fixture)\nhost: fixture-host\nrelease: 1.95.0\n')
        save(self.build_output / 'build-report.json', self.report)
        receipt = self.install()
        self.assertEqual(receipt['status'], 'INSTALLED_NOT_RUN')
        base = copy.deepcopy(self.report)
        cases = []
        changed = copy.deepcopy(base); changed['toolchain']['selection']['rust_root'] = str(self.root); cases.append(changed)
        changed = copy.deepcopy(base); changed['toolchain']['selection']['host_cc'] = tools['cargo']['path']; cases.append(changed)
        changed = copy.deepcopy(base); changed['toolchain']['selection']['schema_version'] = True; cases.append(changed)
        changed = copy.deepcopy(base); changed['toolchain']['host_cc_version'] = ''; cases.append(changed)
        changed = copy.deepcopy(base); changed['toolchain']['rustc_version'] = 'host: wrong-host\n'; cases.append(changed)
        changed = copy.deepcopy(base); del changed['toolchain']['selection']; cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed):
                save(self.build_output / 'build-report.json', changed)
                with self.assertRaises((subject.BuildError, ValueError)):
                    subject.validate_build(receipt['origin'])
        save(self.build_output / 'build-report.json', base)
        compiler = Path(tools['host_cc']['path'])
        compiler.chmod(0o644)
        with self.assertRaisesRegex(subject.BuildError, 'not executable: host_cc'):
            subject.validate_build(receipt['origin'])

    def test_removed_temporary_source_installs_real_files_atomically_without_native_execution(self):
        self.assertFalse(self.stage.exists())
        original_run = subject.build.subprocess.run
        original_rename = Path.rename
        observed = []
        def only_git(command, *args, **kwargs):
            self.assertEqual(Path(command[0]).name, 'git')
            return original_run(command, *args, **kwargs)
        def publish(source, target):
            self.assertEqual(target, self.output)
            self.assertFalse(target.exists())
            self.assertTrue((source / subject.PROGRAM).is_file())
            self.assertTrue((source / subject.RECEIPT).is_file())
            self.assertTrue((source / subject.LICENSE).is_file())
            observed.append(str(source))
            return original_rename(source, target)
        with mock.patch.object(subject.build.subprocess, 'run', side_effect=only_git), \
             mock.patch.object(subject.build.subprocess, 'check_output', side_effect=AssertionError('native probe forbidden')), \
             mock.patch.object(Path, 'rename', publish):
            receipt = self.install()
            result = subject.validate_inputs(self.output)
        self.assertEqual(len(observed), 1)
        self.assertEqual(receipt['status'], 'INSTALLED_NOT_RUN')
        self.assertEqual(result['status'], 'VALIDATED_NOT_RUN')
        self.assertFalse(result['notifications_verified'])
        self.assertFalse(result['cosmic_session_verified'])
        self.assertEqual((self.output / subject.PROGRAM).read_bytes(), elf())
        self.assertFalse(self.stage.exists())

    def test_failed_unlinked_wrong_target_or_false_runtime_report_cannot_install(self):
        for key, value in (('status', 'failed'), ('target_linked', False), ('link_completed', 1),
                           ('architecture', 'aarch64'), ('target', 'aarch64-unknown-linux-musl'),
                           ('source_preserved', False), ('producer_sources_preserved', False),
                           ('guest_execution', 'performed'), ('cosmic_session_ready', True)):
            with self.subTest(field=key):
                save(self.build_output / 'build-report.json', {**self.report, key: value})
                with self.assertRaises((subject.BuildError, ValueError)): self.install()
                self.assertFalse(self.output.exists())

    def test_postinstallation_source_dependency_tool_library_and_log_tamper_fails(self):
        self.install()
        paths = [self.output / subject.PROGRAM, self.output / subject.LICENSE,
                 self.build_output / subject.PROGRAM, Path(self.report['linked_binary']['path']),
                 self.source / 'src/main.rs', self.exported / 'src/main.rs', self.dependency / 'src/lib.rs',
                 self.recipe_path, self.policy_path, self.resource, self.build_output / 'cargo.log',
                 self.build_output / 'metadata.stderr.log', self.sysroot / 'sysroot/usr/lib/libc.a',
                 Path(self.report['toolchain']['tools']['rustc']['path']), self.build_output / 'native/libunwind.a']
        for path in paths:
            original = path.read_bytes()
            with self.subTest(path=path):
                path.write_bytes(original + b' altered')
                with self.assertRaises((subject.BuildError, ValueError, OSError)):
                    subject.validate_inputs(self.output)
                path.write_bytes(original)
        write(self.libdir / 'new.rlib', archive())
        with self.assertRaises((subject.BuildError, ValueError)): subject.validate_inputs(self.output)

    def test_local_metadata_cannot_escape_removed_stage_or_select_another_package(self):
        changed = copy.deepcopy(self.metadata)
        changed['packages'][1]['source'] = None
        save(self.build_output / 'metadata.json', changed)
        with self.assertRaisesRegex(subject.BuildError, 'Local dependency escapes'):
            self.install()
        save(self.build_output / 'metadata.json', self.metadata)
        changed = copy.deepcopy(self.report); changed['package_id'] = 'path+file:///wrong#cosmic-notifications@1.10.0'
        save(self.build_output / 'build-report.json', changed)
        with self.assertRaisesRegex(subject.BuildError, 'different local Cargo package'):
            self.install()
        self.assertFalse(self.output.exists())

    def test_resealed_export_producer_or_link_path_changes_are_rejected(self):
        cases = []
        changed = copy.deepcopy(self.report); changed['builder_sha256'] = '0' * 64; cases.append(changed)
        changed = copy.deepcopy(self.report); changed['producer_sources_after'] = {}; cases.append(changed)
        changed = copy.deepcopy(self.report); changed['linked_binary']['path'] = str(self.root / subject.PROGRAM); cases.append(changed)
        changed = copy.deepcopy(self.report); changed['command'] = changed['command'][:-1]; cases.append(changed)
        changed = copy.deepcopy(self.report); changed['image_load_pages'] = 2; cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed):
                save(self.build_output / 'build-report.json', changed)
                with self.assertRaises((subject.BuildError, ValueError)): self.install()
        write(self.exported / 'src/main.rs', '// arbitrary replacement source\n')
        changed = copy.deepcopy(self.report); changed['source_tree'] = subject.build.tree_identity(self.exported)
        save(self.build_output / 'build-report.json', changed)
        with self.assertRaisesRegex(subject.BuildError, 'canonical source'): self.install()

    def test_foreign_architecture_native_input_is_not_saved_by_matching_hashes(self):
        native = self.sysroot / 'sysroot/usr/lib/libc.a'
        native.write_bytes(archive(183))
        self.recipe['native_inputs'][0]['sha256'] = subject.build.digest(native)
        save(self.recipe_path, self.recipe)
        self.report['recipe_sha256'] = subject.build.digest(self.recipe_path)
        self.report['sysroot_before'] = subject.build.tree_identity(self.sysroot / 'sysroot')
        save(self.build_output / 'build-report.json', self.report)
        with self.assertRaisesRegex(ValueError, 'not a x86_64 ELF'):
            self.install()
        self.assertFalse(self.output.exists())

    def test_symlinks_existing_output_and_overlapping_output_are_rejected(self):
        self.output.mkdir(); write(self.output / 'keep', 'existing data')
        with self.assertRaisesRegex(subject.BuildError, 'Preserving existing'): self.install()
        self.assertEqual((self.output / 'keep').read_text(), 'existing data')
        shutil.rmtree(self.output)
        for path in (self.build_output / subject.PROGRAM, self.dependency / 'Cargo.toml'):
            data = path.read_bytes()
            outside = write(self.root / 'alias-target', data)
            path.unlink(); path.symlink_to(outside)
            with self.subTest(path=path), self.assertRaises((subject.BuildError, ValueError)):
                self.install()
            path.unlink(); path.write_bytes(data)
        self.output.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(subject.BuildError, 'Symlink'): self.install()
        self.output.unlink()
        self.output = self.cache / 'new-output'
        with self.assertRaisesRegex(subject.BuildError, 'overlaps'): self.install()

    def test_staging_recheck_failure_never_publishes_partial_installation(self):
        validate = subject.validate_inputs
        def mutate_before_recheck(prefix):
            self.assertFalse(self.output.exists())
            write(self.exported / 'src/main.rs', '// concurrent input change\n')
            return validate(prefix)
        with mock.patch.object(subject, 'validate_inputs', side_effect=mutate_before_recheck), \
             self.assertRaises((subject.BuildError, ValueError)):
            self.install()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.output.parent.glob('.' + self.output.name + '-*')), [])

    def test_receipt_paths_and_runtime_claims_cannot_be_changed(self):
        receipt = self.install()
        path = self.output / subject.RECEIPT
        for key, value in (('notifications_verified', True), ('cosmic_session_verified', True),
                           ('status', 'PASS'), ('guest_execution', 'performed')):
            save(path, {**receipt, key: value})
            with self.subTest(field=key), self.assertRaises(subject.BuildError):
                subject.validate_inputs(self.output)
        changed = copy.deepcopy(receipt); changed['artifacts'][0]['path'] = '../elsewhere'
        save(path, changed)
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        save(path, receipt)
        path.write_text(path.read_text().replace('"schema_version": 1,', '"schema_version": 1, "schema_version": 1,', 1))
        with self.assertRaisesRegex(subject.BuildError, 'Duplicate JSON key'):
            subject.validate_inputs(self.output)

    def test_full_os_opt_in_installs_exact_link_output_without_rewriting_failed_build(self):
        self.legacy_window_failure()
        before = subject.build.tree_identity(self.build_output)
        with self.assertRaisesRegex(subject.BuildError, 'Not a preserved notifications cross-build'):
            self.install()
        self.assertFalse(self.output.exists())
        original_run = subject.build.subprocess.run
        def only_git(command, *args, **kwargs):
            self.assertEqual(Path(command[0]).name, 'git')
            return original_run(command, *args, **kwargs)
        with mock.patch.object(subject.build.subprocess, 'run', side_effect=only_git), \
             mock.patch.object(subject.build.subprocess, 'check_output', side_effect=AssertionError('native probe forbidden')):
            receipt = self.install(full_os_linked_elf=True)
            result = subject.validate_inputs(self.output)
        self.assertEqual(subject.build.tree_identity(self.build_output), before)
        self.assertEqual(receipt['origin']['admission'], subject.FULL_OS_ADMISSION)
        self.assertEqual(receipt['inputs']['admission']['original_status'], 'failed')
        self.assertEqual(receipt['inputs']['admission']['inspection']['profile'], 'full-os-v3')
        self.assertIs(receipt['inputs']['admission']['inspection']['legacy_window_exceeded'], True)
        self.assertEqual(receipt['inputs']['admission']['inspection']['image_load_pages'], 2)
        self.assertEqual(receipt['inputs']['admission']['inspection']['required_pages'], 514)
        self.assertEqual(receipt['inputs']['admission']['original_report']['sha256'],
                         subject.build.digest(self.build_output / 'build-report.json'))
        self.assertEqual(receipt['status'], 'INSTALLED_NOT_RUN')
        self.assertEqual(result['status'], 'VALIDATED_NOT_RUN')
        self.assertIs(result['notifications_verified'], False)
        self.assertIs(result['cosmic_session_verified'], False)
        self.assertEqual((self.output / subject.PROGRAM).read_bytes(), full_os_fixture())
        self.assertFalse((self.build_output / subject.PROGRAM).exists())
        self.assertFalse(self.stage.exists())

    def test_full_os_mode_requires_exact_completed_legacy_failure_and_no_published_results(self):
        self.legacy_window_failure()
        cases = [(key, value) for key, value in (
            ('status', 'cross-built'), ('error', 'build deadline exceeded'), ('target_linked', True),
            ('link_completed', False), ('link_completed', 1), ('source_preserved', False),
            ('producer_sources_preserved', False), ('operation', 'prepare'), ('cargo_offline', False),
            ('target', 'aarch64-unknown-linux-musl'), ('architecture', 'aarch64'),
            ('guest_execution', 'performed'), ('cosmic_session_ready', True),
            ('executable', {}), ('image_load_pages', 2), ('producer_check_error', 'changed'))]
        for key, value in cases:
            save(self.build_output / 'build-report.json', {**self.report, key: value})
            with self.subTest(field=key, value=value), self.assertRaises((subject.BuildError, ValueError)):
                self.install(full_os_linked_elf=True)
            self.assertFalse(self.output.exists())
        save(self.build_output / 'build-report.json', self.report)
        published = self.build_output / subject.PROGRAM
        write(published, full_os_fixture())
        with self.assertRaisesRegex(subject.BuildError, 'already contains published'):
            self.install(full_os_linked_elf=True)
        published.unlink()
        published.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(subject.BuildError, 'already contains published'):
            self.install(full_os_linked_elf=True)

    def test_full_os_mode_rejects_matching_hash_invalid_elf_and_unneeded_exception(self):
        self.legacy_window_failure()
        bad_permissions = bytearray(full_os_fixture())
        struct.pack_into('<I', bad_permissions, 180, 7)
        for data in (elf(), bytes(bad_permissions), full_os_fixture()[:-1]):
            linked = Path(self.report['linked_binary']['path'])
            linked.write_bytes(data)
            report = copy.deepcopy(self.report)
            report['linked_binary'].update(bytes=len(data), sha256=subject.build.digest(linked))
            save(self.build_output / 'build-report.json', report)
            with self.subTest(bytes=len(data)), self.assertRaises((subject.BuildError, ValueError)):
                self.install(full_os_linked_elf=True)
            self.assertFalse(self.output.exists())

    def test_full_os_admission_still_checks_source_dependency_sdk_and_original_link_identity(self):
        self.legacy_window_failure()
        paths = [self.exported / 'src/main.rs', self.source / 'src/main.rs', self.dependency / 'src/lib.rs',
                 self.sysroot / 'sysroot/usr/lib/libc.a', Path(self.report['linked_binary']['path'])]
        for path in paths:
            data = path.read_bytes()
            path.write_bytes(data + b' after-link change')
            with self.subTest(path=path), self.assertRaises((subject.BuildError, ValueError, OSError)):
                self.install(full_os_linked_elf=True)
            self.assertFalse(self.output.exists())
            path.write_bytes(data)
        changed = copy.deepcopy(self.report)
        changed['producer_sources_after'] = {}
        save(self.build_output / 'build-report.json', changed)
        with self.assertRaisesRegex(subject.BuildError, 'producers changed'):
            self.install(full_os_linked_elf=True)
        changed = copy.deepcopy(self.report)
        changed['linked_binary']['path'] = str(self.root / 'outside-link')
        save(self.build_output / 'build-report.json', changed)
        with self.assertRaisesRegex(subject.BuildError, 'differs from real link output'):
            self.install(full_os_linked_elf=True)
        save(self.build_output / 'build-report.json', self.report)
        linked = Path(self.report['linked_binary']['path'])
        outside = write(self.root / 'alias-elf', linked.read_bytes())
        linked.unlink(); linked.symlink_to(outside)
        with self.assertRaisesRegex(subject.BuildError, 'Symlink'):
            self.install(full_os_linked_elf=True)

    def test_full_os_mode_cannot_expand_fixed_admission_budget(self):
        self.legacy_window_failure()
        for field, value in (('image_bytes', 134217728), ('max_elf_bytes', 134217728), ('stack_bytes', 1048576)):
            profile = {**self.profile, field: value}
            save(self.resource, {'schema_version': 1, 'target': subject.TARGET.rust_target,
                                 'build_profiles': {'notifications-fixture': profile}})
            changed = {**self.report, 'resource_profile': profile,
                       'profile_sha256': hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()}
            save(self.build_output / 'build-report.json', changed)
            with self.subTest(field=field), self.assertRaises((subject.BuildError, ValueError)):
                self.install(full_os_linked_elf=True)
            self.assertFalse(self.output.exists())

    def test_full_os_receipt_binds_explicit_mode_inspection_and_failed_report(self):
        self.legacy_window_failure()
        receipt = self.install(full_os_linked_elf=True)
        receipt_path = self.output / subject.RECEIPT
        cases = []
        changed = copy.deepcopy(receipt); changed['origin'].pop('admission'); cases.append(changed)
        for key, value in (('schema_version', True), ('mode', 'cross-built'), ('original_status', 'cross-built'),
                           ('image_profile', 'legacy')):
            changed = copy.deepcopy(receipt); changed['origin']['admission'][key] = value; cases.append(changed)
        changed = copy.deepcopy(receipt)
        changed['inputs']['admission']['inspection']['required_pages'] -= 1
        cases.append(changed)
        for changed in cases:
            save(receipt_path, changed)
            with self.subTest(origin=changed['origin']), self.assertRaises((subject.BuildError, ValueError)):
                subject.validate_inputs(self.output)
        save(receipt_path, receipt)
        report_path = self.build_output / 'build-report.json'
        report_path.write_text(report_path.read_text() + '\n')
        with self.assertRaisesRegex(subject.BuildError, 'inputs or paths changed'):
            subject.validate_inputs(self.output)

    def test_full_os_staging_rechecks_link_identity_before_atomic_publication(self):
        self.legacy_window_failure()
        validate = subject.validate_inputs
        def mutate_before_recheck(prefix):
            self.assertFalse(self.output.exists())
            linked = Path(self.report['linked_binary']['path'])
            linked.write_bytes(linked.read_bytes() + b' concurrent link replacement')
            return validate(prefix)
        with mock.patch.object(subject, 'validate_inputs', side_effect=mutate_before_recheck), \
             self.assertRaisesRegex(subject.BuildError, 'differs from real link output'):
            self.install(full_os_linked_elf=True)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.output.parent.glob('.' + self.output.name + '-*')), [])


if __name__ == '__main__':
    unittest.main()
