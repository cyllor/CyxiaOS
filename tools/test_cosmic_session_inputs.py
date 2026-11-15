"""Receipt and filesystem contracts; test data is never compiler/guest evidence."""
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

from tools import cosmic_session_inputs as subject


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


def save(path, data):
    write(path, json.dumps(data, indent=2) + '\n')


def elf():
    """A parser fixture, never advertised as compiled code or guest evidence."""
    data = bytearray(4096)
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 2, 62, 1,
                     0x1000100, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 6, 4, 64, 0x1000040, 0x1000040, 112, 112, 8)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 5, 0, 0x1000000, 0x1000000, 4096, 4096, 4096)
    return bytes(data)


class SessionInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.addCleanup(patch.stopall)
        patch.object(subject, 'ROOT', self.root).start()
        patch.object(subject, 'HOST_CC', self.root / 'host/clang').start()
        self.output = self.root / 'artifacts/build'
        self.curated = self.root / 'artifacts/curated'
        self.curated.mkdir(parents=True)
        self.source = self.root / 'artifacts/cosmic-sources/cosmic-session'
        self.exported = self.root / 'artifacts/source-export'
        write(self.source / 'Cargo.toml', '[package]\nname="cosmic-session"\nversion="1.0.0"\n')
        write(self.source / 'Cargo.lock', 'version = 4\n')
        write(self.source / 'src/main.rs', 'fn main() {}\n')
        for args in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Receipt Test', '-c', 'user.email=receipt@example.invalid',
                      'commit', '-qm', 'source fixture'],
                     ['remote', 'add', 'origin', 'https://github.com/pop-os/cosmic-session']):
            subprocess.run(['git', '-C', str(self.source), *args], check=True, capture_output=True)
        commit = subject.build.git(self.source, 'rev-parse', 'HEAD')
        self.component = {'name': 'cosmic-session', 'directory': 'cosmic-session',
                          'repository': 'https://github.com/pop-os/cosmic-session', 'commit': commit}
        patch.object(subject.ports, 'load_manifest', return_value={'components': [self.component]}).start()
        shutil.copytree(self.source, self.exported, ignore=shutil.ignore_patterns('.git'))
        self.cache = self.root / 'artifacts/cosmic-cargo-cache'
        self.dependency = self.cache / 'registry/src/example/dependency-1.0.0'
        write(self.dependency / 'Cargo.toml', '[package]\nname="dependency"\nversion="1.0.0"\n')
        write(self.dependency / 'src/lib.rs', '// dependency bytes\n')
        (self.cache / 'git').mkdir()
        sdk = self.root / 'artifacts/sysroot/x86_64-musl'
        self.native = []
        for name in ('libc.a', 'libclang_rt.builtins-x86_64.a', 'crt1.o', 'crti.o', 'crtn.o'):
            selected = write(sdk / 'sysroot/usr/lib' / name, 'native file-hash seam: ' + name)
            self.native.append({'path': str(selected.relative_to(sdk)), 'sha256': subject.build.digest(selected)})
        rust = self.root / 'rust-toolchain'
        libdir = rust / 'lib/rustlib/x86_64-unknown-linux-musl/lib'
        std = write(libdir / 'libstd-ab12.rlib', 'target std file-hash seam')
        unwind = write(libdir / 'self-contained/libunwind.a', 'target unwind file-hash seam')
        write(libdir / 'libcore-ab12.rlib', 'target core file-hash seam')
        tool_paths = {'rustc': rust / 'bin/rustc', 'cargo': rust / 'bin/cargo',
                      'target_cc': sdk / 'bin/x86_64-linux-musl-cc',
                      'target_cxx': sdk / 'bin/x86_64-linux-musl-cxx',
                      'target_ar': sdk / 'bin/x86_64-linux-musl-ar',
                      'target_ranlib': sdk / 'bin/x86_64-linux-musl-ranlib',
                      'host_cc': subject.HOST_CC,
                      'strip': rust / 'lib/rustlib/test-host/bin/llvm-strip',
                      'pkg_config': self.root / 'host/pkg-config'}
        tools = {}
        for name, selected in tool_paths.items():
            if name == 'target_cxx':
                tools[name] = {'path': str(selected), 'sha256': None, 'available': False}
            else:
                write(selected, 'tool bytes never executed: ' + name)
                tools[name] = {'path': str(selected), 'sha256': subject.build.digest(selected), 'available': True}
        self.recipe_path = self.root / 'ports/recipe.json'
        self.resource_path = self.root / 'ports/resource.json'
        lock = subject.build.digest(self.source / 'Cargo.lock')
        self.recipe = {'schema_version': 1, 'component': 'cosmic-session', 'commit': commit,
                       'target': subject.TARGET.rust_target, 'purpose': 'bounded-build-experiment',
                       'package': 'cosmic-session', 'binary': 'cosmic-session',
                       'resource_profile': 'session-test-v1', 'default_features': False, 'features': [],
                       'source_lock_sha256': lock, 'effective_lock_sha256': lock,
                       'native_inputs': self.native, 'patches': []}
        self.profile = {'target_runtime_validated': False, 'jobs_max': 1, 'min_free_bytes': 1024,
                        'max_build_bytes': 1024, 'timeout_seconds': 900, 'max_elf_bytes': 67108864,
                        'image_bytes': 67108864, 'stack_bytes': 2097152}
        save(self.recipe_path, self.recipe)
        save(self.resource_path, {'schema_version': 1, 'target': subject.TARGET.rust_target,
                                 'build_profiles': {'session-test-v1': self.profile}})
        builder = write(self.root / 'tools/build_cosmic.py', Path(subject.build.__file__).read_bytes())
        self.old_source = self.root / 'removed-temporary-build/source'
        self.metadata = {'packages': [
            {'name': 'cosmic-session', 'version': '1.0.0', 'source': None,
             'manifest_path': str(self.old_source / 'Cargo.toml'),
             'targets': [{'name': 'cosmic-session', 'kind': ['bin']}]},
            {'name': 'dependency', 'version': '1.0.0', 'source': 'registry+https://example.invalid/index',
             'manifest_path': str(self.dependency / 'Cargo.toml'), 'targets': []}]}
        relocated = copy.deepcopy(self.metadata)
        relocated['packages'][0]['manifest_path'] = str(self.exported / 'Cargo.toml')
        records = subject.build.verify_metadata(relocated, self.exported, self.cache, self.recipe)
        records[0]['manifest'] = str(self.old_source / 'Cargo.toml')
        save(self.output / 'metadata.json', self.metadata)
        write(self.output / 'metadata.stderr.log', '')
        write(self.output / 'cargo.log', 'file fixture; no compiler invoked\n')
        write(self.output / 'native/libunwind.a', unwind.read_bytes())
        binary = write(self.output / subject.PROGRAM, elf())
        linked = write(self.output / 'target/x86_64-unknown-linux-musl/release/cosmic-session', elf())
        write(self.curated / subject.PROGRAM, elf())
        common = ['--manifest-path', str(self.old_source / 'Cargo.toml'), '--locked', '--offline', '--no-default-features']
        self.report = {'status': 'cross-built', 'component': self.component,
                       'recipe_sha256': subject.build.digest(self.recipe_path), 'recipe': self.recipe,
                       'resource_profile': self.profile, 'target': subject.TARGET.rust_target,
                       'architecture': 'x86_64', 'builder_sha256': subject.build.digest(builder),
                       'profile_sha256': subject.canonical_hash(self.profile), 'guest_execution': 'not performed',
                       'cosmic_session_ready': False, 'operation': 'build', 'link_completed': True,
                       'target_linked': True, 'cargo_offline': True, 'build_script_network_sandbox': False,
                       'source_preserved': True, 'patches': [], 'source_tree': subject.build.tree_identity(self.exported),
                       'toolchain': {'target': subject.TARGET.rust_target, 'architecture': 'x86_64', 'host': 'test-host',
                                     'std': {'path': str(std), 'sha256': subject.build.digest(std)},
                                     'unwind': {'path': str(unwind), 'sha256': subject.build.digest(unwind)},
                                     'native_inputs': self.native, 'static_link_inputs': [], 'tools': tools},
                       'metadata_command': [str(tool_paths['cargo']), 'metadata', '--format-version', '1',
                                            '--filter-platform', subject.TARGET.rust_target, *common],
                       'command': [str(tool_paths['cargo']), 'build', '--release', '--target', subject.TARGET.rust_target,
                                   '--jobs', '1', '--package', 'cosmic-session', '--bin', 'cosmic-session', *common],
                       'cargo_dependencies': records, 'sysroot_before': subject.build.tree_identity(sdk / 'sysroot'),
                       'linked_binary': {'path': str(linked), 'bytes': linked.stat().st_size, 'sha256': subject.build.digest(linked)},
                       'executable': subject.inspect_elf(binary, subject.TARGET), 'image_load_pages': 1}
        save(self.output / 'build-report.json', self.report)

    def publish(self, **kwargs):
        return subject.record_origin(self.output, self.recipe_path, self.resource_path,
                                     self.exported, self.curated, **kwargs)

    def rewrite_origin(self, origin):
        save(self.curated / subject.RECEIPT, origin)

    def test_real_files_and_git_validate_without_running_compiler_or_cargo(self):
        original_run = subject.build.subprocess.run
        def only_git(command, *args, **kwargs):
            self.assertEqual(Path(command[0]).name, 'git')
            return original_run(command, *args, **kwargs)
        with patch.object(subject.build.subprocess, 'run', side_effect=only_git), \
             patch.object(subject.build.subprocess, 'check_output', side_effect=AssertionError('native probe')):
            self.publish()

            result = subject.validate_inputs(self.curated)
        self.assertEqual(result['status'], 'VALIDATED_NOT_RUN')
        self.assertFalse(result['cosmic_session_ready'])
        self.assertEqual(result['dependency_count'], 2)
        with self.assertRaisesRegex(ValueError, 'Preserving existing'):
            self.publish()

    def test_component_selection_cannot_relabel_a_session_receipt(self):
        with self.assertRaises(ValueError):
            self.publish(component='cosmic-settings-daemon')
        self.assertFalse((self.curated / 'cosmic-settings-daemon-origin.json').exists())
        with self.assertRaisesRegex(ValueError, 'Unsupported COSMIC service'):
            self.publish(component='../cosmic-session')

    def test_changed_copied_or_original_elf_is_rejected(self):
        self.publish()
        for selected in (self.curated / subject.PROGRAM, self.output / subject.PROGRAM,
                         Path(self.report['linked_binary']['path'])):
            original = selected.read_bytes()
            with self.subTest(path=selected):
                selected.write_bytes(original + b'changed')
                with self.assertRaises(ValueError): subject.validate_inputs(self.curated)
                selected.write_bytes(original)

    def test_failed_wrong_target_guest_or_unpreserved_receipt_cannot_publish(self):
        for key, value in [('status', 'failed'), ('architecture', 'aarch64'), ('target_linked', False),
                           ('guest_execution', 'performed'), ('cosmic_session_ready', True),
                           ('source_preserved', False), ('link_completed', 1)]:
            with self.subTest(key=key):
                save(self.output / 'build-report.json', {**self.report, key: value})
                with self.assertRaisesRegex(ValueError, 'real session cross-build'): self.publish()
        self.assertFalse((self.curated / subject.RECEIPT).exists())

    def test_source_dirty_export_change_and_log_change_fail(self):
        self.publish()
        for selected in (self.source / 'src/main.rs', self.exported / 'src/main.rs', self.output / 'cargo.log',
                         self.dependency / 'src/lib.rs', self.recipe_path, self.resource_path):
            original = selected.read_bytes()
            with self.subTest(path=selected):
                selected.write_bytes(original + b' changed')
                with self.assertRaises(ValueError): subject.validate_inputs(self.curated)
                selected.write_bytes(original)

    def test_sdk_tool_and_new_rust_library_are_bound(self):
        self.publish()
        for selected in (self.root / 'artifacts/sysroot/x86_64-musl/sysroot/usr/lib/libc.a',
                         Path(self.report['toolchain']['tools']['rustc']['path']),
                         self.output / 'native/libunwind.a'):
            original = selected.read_bytes()
            with self.subTest(path=selected):
                selected.write_bytes(b'changed')
                with self.assertRaises(ValueError): subject.validate_inputs(self.curated)
                selected.write_bytes(original)
        write(Path(self.report['toolchain']['std']['path']).parent / 'extra.rlib', 'unexpected runtime')
        with self.assertRaisesRegex(ValueError, 'library set changed'): subject.validate_inputs(self.curated)

    def test_missing_metadata_package_and_source_escape_fail_even_with_rebound_log(self):
        origin = self.publish()
        for change in ('missing', 'local-escape', 'registry-escape'):
            metadata = copy.deepcopy(self.metadata)
            if change == 'missing': metadata['packages'].pop()
            elif change == 'local-escape': metadata['packages'][0]['manifest_path'] = str(self.dependency / 'Cargo.toml')
            else: metadata['packages'][1]['manifest_path'] = str(self.source / 'Cargo.toml')
            with self.subTest(change=change):
                save(self.output / 'metadata.json', metadata)
                origin['logs_sha256']['metadata.json'] = subject.build.digest(self.output / 'metadata.json')
                self.rewrite_origin(origin)
                with self.assertRaises(ValueError): subject.validate_inputs(self.curated)

    def test_aliases_and_traversal_are_rejected(self):
        origin = self.publish()
        alias = self.root / 'artifacts/alias'
        alias.symlink_to(self.curated, target_is_directory=True)
        with self.assertRaises(ValueError): subject.validate_inputs(alias)
        with self.assertRaises(ValueError): subject.validate_inputs(self.curated / '../curated')
        original = self.curated / subject.PROGRAM
        original.unlink()
        original.symlink_to(self.output / subject.PROGRAM)
        with self.assertRaises(ValueError): subject.validate_inputs(self.curated)
        original.unlink()
        write(original, elf())
        origin['source_export'] = str(alias)
        self.rewrite_origin(origin)
        with self.assertRaises(ValueError): subject.validate_inputs(self.curated)

    def test_duplicate_json_keys_and_unknown_origin_fields_fail(self):
        origin = self.publish()
        receipt = self.curated / subject.RECEIPT
        receipt.write_text(receipt.read_text().replace('"schema_version": 1,', '"schema_version": 1, "schema_version": 1,'))
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'): subject.validate_inputs(self.curated)
        self.rewrite_origin({**origin, 'unchecked_input': 'extra'})
        with self.assertRaisesRegex(ValueError, 'Unsupported'): subject.validate_inputs(self.curated)

    def test_changed_profile_bounds_or_cargo_features_do_not_publish(self):
        for key, value in [('image_load_pages', 2), ('profile_sha256', 'a' * 64),
                           ('command', self.report['command'][:-1])]:
            with self.subTest(key=key):
                save(self.output / 'build-report.json', {**self.report, key: value})
                with self.assertRaises(ValueError): self.publish()

    def prepare_patch(self):
        patch_path = write(self.recipe_path.parent / 'native.patch',
                           '--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-fn main() {}\n+fn main() { /* adapter */ }\n')
        support = write(self.root / 'ports/native_child.rs', '// reviewed adapter source\n')
        before = subject.build.digest(self.source / 'src/main.rs')
        write(self.exported / 'src/main.rs', 'fn main() { /* adapter */ }\n')
        after = subject.build.digest(self.exported / 'src/main.rs')
        files = subject.tracked_files(self.source)
        manifest = {'schema_version': 1, 'component': 'cosmic-session',
                    'repository': self.component['repository'], 'commit': self.component['commit'],
                    'source_lock_sha256': self.recipe['source_lock_sha256'],
                    'effective_lock_sha256': self.recipe['effective_lock_sha256'],
                    'patch_sha256': subject.build.digest(patch_path),
                    'before': {'src/main.rs': before}, 'after': {'src/main.rs': after},
                    'source_inputs': {'session': {'path': str(self.source.relative_to(self.root)),
                                                  'commit': self.component['commit'],
                                                  'git_tree': subject.build.git(self.source, 'rev-parse', 'HEAD^{tree}'),
                                                  'files': files,
                                                  'tree_sha256': hashlib.sha256(json.dumps(files, sort_keys=True,
                                                                                           separators=(',', ':')).encode()).hexdigest()}},
                    'support_inputs': {str(support.relative_to(self.root)): subject.build.digest(support)}}
        manifest_path = self.recipe_path.parent / 'native-patch.json'
        save(manifest_path, manifest)
        self.recipe['patches'] = [{'path': patch_path.name, 'sha256': manifest['patch_sha256']}]
        save(self.recipe_path, self.recipe)
        self.report['recipe_sha256'] = subject.build.digest(self.recipe_path)
        self.report['patches'] = [{'path': str(patch_path), 'sha256': manifest['patch_sha256']}]
        self.report['source_tree'] = subject.build.tree_identity(self.exported)
        self.report['cargo_dependencies'][0]['source_tree_sha256'] = self.report['source_tree']['sha256']
        save(self.output / 'build-report.json', self.report)
        return manifest_path, manifest, patch_path, support

    def test_patch_manifest_binds_original_postimage_support_and_patch_bytes(self):
        manifest_path, _, patch_path, support = self.prepare_patch()
        self.publish(patch_manifests=[manifest_path])
        self.assertEqual(subject.validate_inputs(self.curated)['status'], 'VALIDATED_NOT_RUN')
        for selected in (manifest_path, patch_path, support):
            original = selected.read_bytes()
            with self.subTest(path=selected):
                selected.write_bytes(original + b'changed')
                with self.assertRaises(ValueError): subject.validate_inputs(self.curated)
                selected.write_bytes(original)

    def test_incomplete_or_false_patch_manifest_cannot_publish(self):
        manifest_path, manifest, _, _ = self.prepare_patch()
        with self.assertRaisesRegex(ValueError, 'exactly one bound manifest'): self.publish()
        variants = []
        for field in ('before', 'after'):
            invalid = copy.deepcopy(manifest)
            invalid[field]['src/main.rs'] = 'a' * 64
            variants.append(invalid)
        invalid = copy.deepcopy(manifest)
        invalid['source_inputs']['session']['git_tree'] = 'a' * 40
        variants.append(invalid)
        invalid = copy.deepcopy(manifest)
        invalid['source_inputs']['session']['files']['src/main.rs'] = 'a' * 64
        variants.append(invalid)
        for invalid in variants:
            with self.subTest(manifest=invalid):
                save(manifest_path, invalid)
                with self.assertRaises(ValueError): self.publish(patch_manifests=[manifest_path])

    def test_dependency_manifest_alias_is_rejected(self):
        self.publish()
        selected = self.dependency / 'Cargo.toml'
        original = selected.read_bytes()
        outside = write(self.root / 'outside.toml', original)
        selected.unlink()
        selected.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink'): subject.validate_inputs(self.curated)


if __name__ == '__main__':
    unittest.main()
