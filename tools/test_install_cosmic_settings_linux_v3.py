"""Pure filesystem tests with mocked original consumer and ELF admission.

The bytes are explicit host fixtures, not a settings executable. Every process
creation entry point used by repository tools is blocked. No real build input
validation, compiler, Cargo, Git, guest, or settings service is exercised.
Actual installation must separately replay the independent genuine Linux-v2 consumer.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def forbidden_process(*args, **kwargs):
    raise AssertionError('External process is forbidden in pure settings installer fixtures')


def process_guards(stack):
    for module, names in (
            (subprocess, ('Popen', 'run', 'call', 'check_call', 'check_output')),
            (os, ('system', 'popen', 'fork', 'posix_spawn', 'posix_spawnp',
                  'execv', 'execve', 'execl', 'execle', 'execvp', 'execvpe'))):
        for name in names:
            if hasattr(module, name):
                stack.enter_context(patch.object(module, name, side_effect=forbidden_process))


# Load the candidate next to this test, even if an older repository installer
# is importable. The caller supplies the unchanged tools directory in PYTHONPATH.
candidate = Path(__file__).resolve().with_name('install_cosmic_settings_linux_v3.py')
sys.path.insert(0, str(candidate.parent))
with contextlib.ExitStack() as guards:
    process_guards(guards)
    specification = importlib.util.spec_from_file_location('settings_installer_v3_candidate', candidate)
    subject = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(subject)


class InstallationBoundaries(unittest.TestCase):
    def setUp(self):
        self.guards = contextlib.ExitStack()
        process_guards(self.guards)
        self.addCleanup(self.guards.close)
        temporary = tempfile.TemporaryDirectory(prefix='settings-install-boundary-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build = self.root / 'explicit-host-consumer-fixture'
        self.build.mkdir()
        self.output = self.root / 'installed'
        self.data = {subject.PROGRAM: b'EXPLICIT HOST ELF-BYTE FIXTURE; NOT A REAL ELF\n'}
        for relative in subject.LICENSES:
            self.data['source/' + relative] = ('COMPLETE HOST LICENSE FIXTURE ' + relative + '\n').encode()
        for relative, raw in self.data.items():
            path = self.build / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.report = {}
        for name in ('sysroot', 'source_cache', 'cargo_cache'):
            path = self.root / name
            path.mkdir()
            self.report[name] = str(path)
        self.rust_root = self.root / 'rust-toolchain'
        self.host_tools = self.root / 'host-tools'
        self.real_tools = self.root / 'real-host-tools'
        self.recipe = self.root / 'recipe-and-profile'
        for path in (self.rust_root / 'bin', self.host_tools, self.real_tools, self.recipe):
            path.mkdir(parents=True)
        self.report['toolchain'] = {'selection': {'rust_root': str(self.rust_root)},
            'tools': {'rustc': {'path': str(self.rust_root / 'bin/rustc'), 'available': True},
                      'host_cc': {'path': str(self.host_tools / 'clang'), 'available': True}}}
        for row in self.report['toolchain']['tools'].values():
            Path(row['path']).write_bytes(b'EXPLICIT HOST TOOL-BYTE FIXTURE')
        executable = {'file': subject.PROGRAM, **subject.identify(self.data[subject.PROGRAM])}
        self.validated = {'status': 'VALIDATED_NOT_RUN', 'kind': subject.contract.KIND,
            'build_output': str(self.build), 'program': str(self.build / subject.PROGRAM),
            'executable': executable,
            'image_admission': {'executable': copy.deepcopy(executable),
                                'required_pages': 1883, 'image_load_pages': 1371},
            'resource_profile': {'max_elf_bytes': 64 * 1024**2},
            'source_tree_sha256': 'a' * 64, 'metadata': {'host_fixture_only': True},
            'generated_inputs': {}, 'rust_libraries': {}, 'hashes': {},
            'licenses': [{'source_relative': source, 'path': destination,
                          **subject.identify(self.data['source/' + source])}
                         for source, destination in subject.LICENSES.items()],
            'input_directories': [str(self.build), *[self.report[name] for name in
                ('sysroot', 'source_cache', 'cargo_cache')], str(self.rust_root), str(self.recipe)],
            'boundary': {'audio_mutations': 'org.freedesktop.DBus.Error.NotSupported',
                         'brightness_mutations': 'org.freedesktop.DBus.Error.NotSupported',
                         'brightness_unavailable_value': -1, 'audio_varlink_service': False,
                         'system_services_emulated': False,
                         'accessibility_behavior': 'upstream; system service failures remain explicit'},
            'guest_execution': 'not performed', 'settings_verified': False,
            'cosmic_session_ready': False, 'cosmic_session_verified': False}
        self.save_report()
        self.consumer = self.guards.enter_context(patch.object(subject.consumer, 'validate_build',
            side_effect=self.consume_fixture))
        self.producers = self.guards.enter_context(patch.object(subject, 'producers',
            return_value={'HOST-FIXTURE-PRODUCER': 'c' * 64}))
        self.admission = self.guards.enter_context(patch.object(subject.contract.elf, 'inspect_full_os_elf',
            side_effect=lambda _path, _profile: copy.deepcopy(self.validated['image_admission'])))

    def save_report(self):
        path = self.build / 'build-report.json'
        raw = (json.dumps(self.report, indent=2) + '\n').encode()
        path.write_bytes(raw)
        self.validated['hashes'][str(path)] = subject.identify(raw)['sha256']

    def consume_fixture(self, path):
        self.assertEqual(Path(path), self.build)
        return copy.deepcopy(self.validated)

    def receipt_json(self):
        return json.loads((self.output / subject.RECEIPT).read_bytes())

    def assert_no_publication(self):
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('.installed-*')), [])

    def test_exact_elf_three_licenses_modes_boundary_and_unrun_claims(self):
        receipt = subject.install(self.build, self.output)
        self.assertEqual(set(receipt['files']), {subject.PROGRAM, *subject.LICENSES.values()})
        for source, destination in {subject.PROGRAM: subject.PROGRAM,
                **{'source/' + key: value for key, value in subject.LICENSES.items()}}.items():
            path = self.output / destination
            self.assertEqual(path.read_bytes(), self.data[source])
            self.assertEqual(path.stat().st_mode & 0o7777, 0o755 if source == subject.PROGRAM else 0o644)
        result = subject.validate_inputs(self.output)
        self.assertEqual(result['status'], 'SETTINGS_INSTALLATION_REVALIDATED_NOT_RUN')
        self.assertEqual(receipt['consumer_identity_sha256'], subject.contract.canonical(self.validated))
        self.assertEqual(receipt['boundary'], self.validated['boundary'])
        self.assertEqual(receipt['guest_execution'], 'not performed')
        self.assertEqual(result['guest_execution'], 'not performed')
        for key in ('settings_verified', 'cosmic_session_ready', 'cosmic_session_verified', 'full_cosmic_complete'):
            self.assertIs(receipt[key], False)
            self.assertIs(result[key], False)
        self.assertGreaterEqual(self.consumer.call_count, 3)
        self.assertGreaterEqual(self.admission.call_count, 2)

    def test_copied_catalog_prefix_revalidates_without_binding_install_prefix(self):
        subject.install(self.build, self.output)
        combined = self.root / 'combined-catalog'
        shutil.copytree(self.output, combined)
        (combined / 'other-component.elf').write_bytes(b'UNRELATED HOST CATALOG FIXTURE')
        result = subject.validate_inputs(combined)
        self.assertEqual(result['status'], 'SETTINGS_INSTALLATION_REVALIDATED_NOT_RUN')
        self.assertEqual((combined / subject.RECEIPT).read_bytes(), (self.output / subject.RECEIPT).read_bytes())
        self.assertEqual(self.receipt_json()['origin'], {'build_output': str(self.build)})

    def test_existing_output_and_all_protected_input_roots_are_preserved(self):
        self.output.mkdir()
        keep = self.output / 'keep'
        keep.write_bytes(b'prior content')
        with self.assertRaises(subject.BuildError): subject.install(self.build, self.output)
        self.assertEqual(keep.read_bytes(), b'prior content')
        for parent in (self.build, self.rust_root, self.host_tools, self.recipe,
                       *[Path(self.report[key]) for key in ('sysroot', 'source_cache', 'cargo_cache')]):
            output = parent / 'new-output'
            with self.subTest(parent=parent), self.assertRaises(subject.BuildError):
                subject.install(self.build, output)
            self.assertFalse(output.exists())

    def test_atomic_publication_preserves_a_concurrent_empty_directory(self):
        original = subject.publish_directory
        created = []
        def concurrent(pending, output):
            output.mkdir()
            created.append(output.stat().st_ino)
            return original(pending, output)
        with patch.object(subject, 'publish_directory', side_effect=concurrent):
            with self.assertRaises(FileExistsError): subject.install(self.build, self.output)
        self.assertEqual(self.output.stat().st_ino, created[0])
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(list(self.root.glob('.installed-*')), [])

    def test_missing_atomic_primitive_fails_closed(self):
        with patch.object(subject.ctypes, 'CDLL', return_value=object()):
            with self.assertRaises(OSError): subject.install(self.build, self.output)
        self.assert_no_publication()

    def test_symlink_build_installed_file_and_traversal_are_rejected(self):
        link = self.root / 'build-link'
        link.symlink_to(self.build, target_is_directory=True)
        with self.assertRaises(subject.BuildError): subject.install(link, self.output)
        with self.assertRaises(subject.BuildError):
            subject.install(self.build, self.root / 'prefix' / '..' / 'other-output')
        subject.install(self.build, self.output)
        target = self.output / subject.PROGRAM
        target.unlink()
        target.symlink_to(self.build / subject.PROGRAM)
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)

    def test_available_tool_symlink_accepts_and_protects_both_directories(self):
        real = self.real_tools / 'pkgconf'
        real.write_bytes(b'EXPLICIT HOST PKG-CONFIG FIXTURE')
        link = self.host_tools / 'pkg-config'
        link.symlink_to(real)
        self.report['toolchain']['tools']['pkg_config'] = {'path': str(link), 'available': True}
        self.validated['hashes'][str(link)] = subject.identify(real.read_bytes())['sha256']
        self.save_report()
        subject.install(self.build, self.output)
        self.assertEqual(subject.validate_inputs(self.output)['status'], 'SETTINGS_INSTALLATION_REVALIDATED_NOT_RUN')
        self.assertTrue(link.is_symlink())
        for parent in (self.host_tools, self.real_tools):
            with self.assertRaises(subject.BuildError): subject.install(self.build, parent / 'new-output')
            self.assertFalse((parent / 'new-output').exists())

    def test_missing_optional_tool_stays_unavailable_and_parent_stays_protected(self):
        missing = self.host_tools / 'optional-target-cxx'
        self.report['toolchain']['tools']['target_cxx'] = {'path': str(missing), 'available': False, 'sha256': None}
        self.save_report()
        subject.install(self.build, self.output)
        self.assertEqual(subject.validate_inputs(self.output)['status'], 'SETTINGS_INSTALLATION_REVALIDATED_NOT_RUN')
        self.assertFalse(missing.exists())
        with self.assertRaises(subject.BuildError): subject.install(self.build, self.host_tools / 'new-output')

    def test_second_consumer_failure_cleans_pending_and_never_publishes(self):
        self.consumer.side_effect = [copy.deepcopy(self.validated), subject.BuildError('fixture changed')]
        with self.assertRaisesRegex(subject.BuildError, 'fixture changed'):
            subject.install(self.build, self.output)
        self.assert_no_publication()

    def test_original_consumer_claims_and_output_identity_are_required(self):
        original = copy.deepcopy(self.validated)
        for key, value in [('status', 'METADATA_ONLY'), ('kind', 'generic-settings'),
                ('guest_execution', False), ('settings_verified', True), ('cosmic_session_ready', True),
                ('cosmic_session_verified', True), ('build_output', str(self.root)),
                ('program', str(self.root / subject.PROGRAM))]:
            self.validated = {**copy.deepcopy(original), key: value}
            with self.subTest(key=key), self.assertRaises(subject.BuildError):
                subject.install(self.build, self.output)
            self.assert_no_publication()

    def test_license_inventory_and_post_consumer_source_report_changes_fail_closed(self):
        original = copy.deepcopy(self.validated)
        for mutation in ('missing-license', 'wrong-license-digest', 'changed-license', 'changed-report'):
            self.validated = copy.deepcopy(original)
            source = self.build / 'source' / next(iter(subject.LICENSES))
            raw = source.read_bytes()
            report = (self.build / 'build-report.json').read_bytes()
            if mutation == 'missing-license': self.validated['licenses'].pop()
            elif mutation == 'wrong-license-digest': self.validated['licenses'][0]['sha256'] = 'd' * 64
            elif mutation == 'changed-license': source.write_bytes(raw[:-1])
            else: (self.build / 'build-report.json').write_bytes(report + b' ')
            with self.subTest(mutation=mutation), self.assertRaises(subject.BuildError):
                subject.install(self.build, self.output)
            self.assert_no_publication()
            source.write_bytes(raw)
            (self.build / 'build-report.json').write_bytes(report)

    def test_source_changes_during_copy_and_installed_admission_failure_never_publish(self):
        original_read = subject.read
        source = self.build / subject.PROGRAM
        seen = []
        def drift(path, *args):
            data = original_read(path, *args)
            if Path(path) == source:
                seen.append(True)
                if len(seen) == 1: source.write_bytes(data + b' changed after admission')
            return data
        with patch.object(subject, 'read', side_effect=drift):
            with self.assertRaises(subject.BuildError): subject.install(self.build, self.output)
        self.assert_no_publication()
        source.write_bytes(self.data[subject.PROGRAM])
        self.admission.side_effect = lambda *_: {'host_fixture_only': 'different admission'}
        with self.assertRaises(subject.BuildError): subject.install(self.build, self.output)
        self.assert_no_publication()

    def test_installed_bytes_and_modes_for_all_four_artifacts_fail_closed(self):
        subject.install(self.build, self.output)
        for name, row in self.receipt_json()['files'].items():
            path = self.output / name
            original = path.read_bytes()
            path.write_bytes(original + b'changed')
            with self.subTest(name=name, kind='bytes'), self.assertRaises(subject.BuildError):
                subject.validate_inputs(self.output)
            path.write_bytes(original)
            path.chmod(row['mode'] | 0o4000)
            with self.subTest(name=name, kind='mode'), self.assertRaises(subject.BuildError):
                subject.validate_inputs(self.output)
            path.chmod(row['mode'])

    def test_receipt_types_old_format_and_runtime_claims_are_rejected(self):
        subject.install(self.build, self.output)
        path = self.output / subject.RECEIPT
        original = self.receipt_json()
        for key, value in [('schema_version', True), ('kind', subject.contract.KIND),
                ('guest_execution', True), ('settings_verified', True), ('cosmic_session_ready', True),
                ('cosmic_session_verified', True), ('full_cosmic_complete', True),
                ('required_pages', True), ('image_load_pages', True), ('producer_sources', {}),
                ('consumer_identity_sha256', 'd' * 64), ('build_report_sha256', 'e' * 64),
                ('origin', {'build_output': str(self.build), 'install_prefix': str(self.output)}),
                ('boundary', {**original['boundary'], 'system_services_emulated': True}),
                ('files', {**original['files'], subject.PROGRAM: {**original['files'][subject.PROGRAM], 'mode': 493.0}})]:
            path.write_text(json.dumps({**original, key: value}))
            with self.subTest(key=key), self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        raw = json.dumps(original)
        path.write_text(raw[:-1] + ', "settings_verified": false}')
        with self.assertRaises((subject.BuildError, ValueError)): subject.validate_inputs(self.output)

    def test_linux_v1_receipt_cannot_be_reinterpreted_as_v2(self):
        subject.install(self.build, self.output)
        path = self.output / subject.RECEIPT
        original = self.receipt_json()
        path.write_text(json.dumps({**original, 'kind': 'cosmic-settings-linux-v1-installation'}))
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        path.write_text(json.dumps(original))
        old = self.output / 'cosmic-settings-linux-v1-installation.json'
        path.rename(old)
        with self.assertRaises((subject.BuildError, FileNotFoundError)): subject.validate_inputs(self.output)

    def test_new_api_carries_kind_and_complete_protected_roots_after_catalog_move(self):
        subject.install(self.build, self.output)
        proof = subject.validate_inputs(self.output)
        self.assertEqual(proof['kind'], 'cosmic-settings-linux-v2-installation')
        expected = {str(self.build), str(self.rust_root), str(self.host_tools), str(self.recipe),
                    *[self.report[name] for name in ('sysroot', 'source_cache', 'cargo_cache')]}
        self.assertTrue(expected <= set(proof['protected_paths']))
        moved = self.root / 'combined-catalog'
        shutil.copytree(self.output, moved)
        self.assertEqual(proof, subject.validate_inputs(moved))

    def test_complete_consumer_identity_and_installer_closure_are_rechecked(self):
        subject.install(self.build, self.output)
        self.validated['source_tree_sha256'] = 'd' * 64
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        self.validated['source_tree_sha256'] = 'a' * 64
        self.producers.side_effect = [{'HOST-FIXTURE-PRODUCER': 'c' * 64}, {'HOST-FIXTURE-PRODUCER': 'e' * 64}]
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)

    def test_receipt_changed_during_validation_is_rejected(self):
        subject.install(self.build, self.output)
        path = self.output / subject.RECEIPT
        original_read = subject.read
        seen = []
        def drift(selected, *args):
            raw = original_read(selected, *args)
            if Path(selected) == path:
                seen.append(True)
                if len(seen) == 1: path.write_bytes(raw + b' ')
            return raw
        with patch.object(subject, 'read', side_effect=drift):
            with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)

    def test_cli_holds_shared_lease_across_each_operation_without_real_processes(self):
        held, operations = [], []
        lock = self.root / 'native-fixture.lock'
        @contextlib.contextmanager
        def lease(path):
            self.assertEqual(path, lock)
            held.append(True)
            try: yield
            finally: held.pop()
        def idle(): self.assertEqual(held, [True])
        def operation(*args):
            self.assertEqual(held, [True])
            operations.append(args)
            return {'explicit_host_fixture_only': True}
        with patch.object(subject.native_session, 'native_lease', side_effect=lease), \
             patch.object(subject.native_session, 'idle_native_host', side_effect=idle), \
             patch.object(subject, 'install', side_effect=operation), \
             patch.object(subject, 'validate_inputs', side_effect=operation), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(subject.main(['--native-lock', str(lock), 'install',
                '--build', str(self.build), '--output', str(self.output)]), 0)
            self.assertEqual(subject.main(['--native-lock', str(lock), 'validate',
                '--prefix', str(self.output)]), 0)
        self.assertEqual(len(operations), 2)
        self.assertEqual(held, [])


if __name__ == '__main__':
    unittest.main()
