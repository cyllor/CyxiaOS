"""Pure filesystem fixtures; compiler/exporter/old provenance are all blocked.

Synthetic ELF admission and exporter execution are MOCKS. These tests establish
boundary enforcement only and are never genuine theme generation evidence.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import build_cosmic_theme_linux_v1 as producer
import cosmic_theme_inputs_v1 as consumer
import install_cosmic_theme_linux_v1 as installer


class ThemeBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cyxia-theme-pure-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'artifacts/generated'
        self.installation = self.root / 'installed'
        self.original_root = producer.ROOT
        self.comparison = producer.reference_assets()
        self.assets = self.comparison['assets']
        self.payloads = {row['path']: producer.read(producer.MANIFEST.parent / 'rootfs' / row['path'][1:])
                         for row in self.assets}
        self.license = self.root / 'upstream/LICENSE'
        self.license.parent.mkdir()
        self.license.write_bytes(self.payloads[producer.reference.LICENSE_PATH])
        self.input = {'settings_build': str(self.root / 'supplier'),
            'settings_proof': {'status': 'MOCK_ONLY', 'input_directories': [str(self.root / 'supplier')]},
            'settings_report': {'path': str(self.root / 'supplier/build-report.json'), 'bytes': 1, 'sha256': '1' * 64},
            'sdk': str(self.root / 'sdk'), 'rust_root': str(self.root / 'rust'),
            'rustc': str(self.root / 'rust/bin/rustc'), 'python': '/usr/local/bin/python3',
            'host_runtime': {'library_paths': [str(self.root / 'lib')], 'elf_closure': {}},
            'tools': {}, 'declared_tools': {},
            'externs': {name: {'path': str(self.root / ('lib' + name + '.rlib'))} for name in producer.EXTERNS},
            'comparison': self.comparison, 'producer_sources': {'mock-producer.py': '2' * 64},
            'upstream_license': {'path': str(self.license), **producer.identity(self.license)},
            'rlib_snapshot_is_new_input': True, 'old_settings_receipt_bound_each_rlib': False}
        self.events = []
        patches = [mock.patch.object(producer, 'ROOT', self.root), mock.patch.object(consumer, 'ROOT', self.root),
            mock.patch.object(installer, 'ROOT', self.root),
            mock.patch.object(producer, 'capture_inputs', side_effect=lambda _: copy.deepcopy(self.input)),
            mock.patch.object(producer, 'producer_sources', return_value=self.input['producer_sources']),
            mock.patch.object(consumer, 'consumer_sources', return_value={'mock-consumer.py': '3' * 64}),
            mock.patch.object(installer, 'sources', return_value={'mock-installer.py': '4' * 64}),
            mock.patch.object(producer.native_session, 'idle_native_host'),
            mock.patch.object(producer.processes, 'resource_check'),
            mock.patch.object(producer.processes, 'run_bounded', side_effect=self.fake_runner),
            mock.patch.object(producer.build_sysroot, 'inspect_elf', side_effect=self.fake_admission),
            mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('External process forbidden')),
            mock.patch.object(subprocess, 'run', side_effect=AssertionError('External process forbidden')),
            mock.patch.object(producer.reference, 'verify_inputs', side_effect=AssertionError('Old missing provenance forbidden')),
            mock.patch.object(producer.reference, 'validate_inputs', side_effect=AssertionError('Old missing provenance forbidden'))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.build()

    def fake_admission(self, path, target):
        self.assertEqual(target, 'x86_64')
        return {'fixture_only': True, 'file': str(path), **producer.identity(path)}

    def fake_runner(self, command, cwd, env, log, timeout, min_free, max_bytes, **kwargs):
        self.assertEqual(timeout <= 120 and timeout > 0, True)
        self.assertEqual(min_free, 1024 ** 3)
        self.assertEqual(max_bytes, 256 * 1024 ** 2)
        self.assertFalse({'RUSTFLAGS', 'CARGO_HOME', 'FLATPAK_ID', 'LD_PRELOAD'} & env.keys())
        output = Path(kwargs['budget_root'])
        if command[0] == self.input['rustc']:
            self.events.append('link-mocked')
            (output / (producer.EXECUTABLE + '.pending')).write_bytes(b'PURE-FIXTURE-NOT-AN-ELF')
            raw = b''
        else:
            mode = command[1]
            self.events.append(mode + '-mocked')
            self.assertEqual(command, [str(output / producer.EXECUTABLE), mode])
            home = Path(env['HOME'])
            self.assertEqual(list(home.iterdir()), [])
            base = home / '.config/cosmic' / producer.reference.IDS[mode] / 'v2'
            base.mkdir(parents=True)
            rows = [f'THEME_DEFAULTS BEGIN mode={mode} id={producer.reference.IDS[mode]} version=2 keys=39 source=libcosmic@{producer.COMMIT}']
            for key in producer.reference.KEYS:
                payload = self.payloads[producer.reference.destination(mode, key)]
                (base / key).write_bytes(payload)
                (base / key).chmod(0o644)
                rows.append(f'THEME_DEFAULTS KEY name={key} bytes={len(payload)} hex={payload.hex()}')
            rows.append(f'THEME_DEFAULTS PASS mode={mode} keys=39')
            raw = ('\n'.join(rows) + '\n').encode()
        Path(log).write_bytes(raw)
        Path(kwargs['stderr_log']).write_bytes(b'')

    def build(self):
        return producer.build(self.input['settings_build'], self.output)

    def report(self):
        return producer.decode((self.output / producer.RECEIPT).read_bytes())

    def save(self, report):
        producer.write_report(self.output, report)

    def reject(self):
        with self.assertRaises((producer.BuildError, OSError, ValueError)):
            consumer.validate_build(self.output)

    def test_complete_mock_workflow_and_distinct_api(self):
        self.assertEqual(self.events, ['link-mocked', 'dark-mocked', 'light-mocked'])
        proof = consumer.validate_build(self.output)
        self.assertEqual(proof['bounds']['asset_files'], 79)
        self.assertEqual(proof['bounds']['asset_bytes'], 34654)
        self.assertEqual(proof['bounds']['max_guest_path_bytes'], 76)
        self.assertTrue(proof['host_generation'])
        self.assertIs(proof['guest_execution'], False)
        installer.install(self.output, self.installation)
        installed = installer.validate_inputs(self.installation)
        self.assertEqual(installed['kind'], 'cosmic-theme-linux-v1-assets')
        self.assertEqual(installed['status'], 'THEME_HOST_ASSETS_REVALIDATED_NOT_GUEST_RUN')
        self.assertEqual(installed['assets'], self.assets)
        self.assertIn(str(self.output), installed['protected_paths'])
        self.assertIn(self.input['rust_root'], installed['protected_paths'])
        self.assertFalse((self.installation / 'cosmic-theme-assets.json').exists())

    def test_false_or_promoted_claims_and_budget_are_rejected(self):
        original = self.report()
        changes = [('guest_execution', True), ('host_generation', False), ('host_generation', 1),
                   ('full_cosmic_complete', True), ('reference_is_generation_proof', True),
                   ('status', 'PASS'), ('kind', 'cosmic-theme-defaults'), ('native_elapsed_seconds', 121)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(original)
                changed[key] = value
                self.save(changed)
                self.reject()
        changed = copy.deepcopy(original)
        changed['limits']['jobs'] = 2
        self.save(changed)
        self.reject()

    def test_missing_second_real_run_is_rejected(self):
        report = self.report()
        report['steps'].pop()
        self.save(report)
        self.reject()

    def test_exit_boolean_is_not_exit_zero(self):
        report = self.report()
        report['steps'][1]['returncode'] = False
        self.save(report)
        self.reject()

    def test_switched_mode_command_is_rejected(self):
        report = self.report()
        report['steps'][2]['argv'][1] = 'dark'
        self.save(report)
        self.reject()

    def test_ambient_compiler_environment_is_rejected(self):
        report = self.report()
        report['steps'][0]['environment']['RUSTFLAGS'] = '--cfg injected'
        self.save(report)
        self.reject()

    def test_parallel_native_steps_are_rejected(self):
        report = self.report()
        report['steps'][2]['started_seconds'] = 0
        self.save(report)
        self.reject()

    def test_renewing_deadline_for_each_run_is_rejected(self):
        report = self.report()
        report['steps'][2]['started_seconds'] = 10
        report['steps'][2]['ended_seconds'] = 11
        report['steps'][2]['timeout_seconds'] = 120
        report['native_elapsed_seconds'] = 11
        self.save(report)
        self.reject()

    def test_current_supplier_mutation_is_rejected(self):
        self.input['old_settings_receipt_bound_each_rlib'] = True
        self.reject()

    def test_input_boolean_integer_equivalence_is_rejected(self):
        report = self.report()
        report['inputs_after']['rlib_snapshot_is_new_input'] = 1
        self.save(report)
        self.reject()

    def test_extra_stdout_even_with_new_inventory_is_rejected(self):
        path = self.output / 'run-dark.stdout.log'
        path.write_bytes(path.read_bytes() + b'unexplained output\n')
        report = self.report()
        report['files'] = producer.inventory(self.output)
        self.save(report)
        self.reject()

    def test_nonempty_stderr_is_rejected(self):
        (self.output / 'run-light.stderr.log').write_text('export failed\n')
        self.reject()

    def test_missing_generated_key_is_rejected(self):
        path = self.output / 'homes/light/.config/cosmic/com.system76.CosmicTheme.Light/v2/name'
        path.unlink()
        self.reject()

    def test_extra_generated_key_is_rejected(self):
        path = self.output / 'homes/dark/.config/cosmic/com.system76.CosmicTheme.Dark/v2/extra'
        path.write_bytes(b'true')
        self.reject()

    def test_generated_key_source_symlink_is_rejected(self):
        path = self.output / 'homes/dark/.config/cosmic/com.system76.CosmicTheme.Dark/v2/name'
        raw = path.read_bytes()
        path.unlink()
        external = self.root / 'external-name'
        external.write_bytes(raw)
        path.symlink_to(external)
        self.reject()

    def test_rootfs_license_or_key_must_come_from_actual_sources(self):
        (self.output / 'rootfs/usr/share/doc/libcosmic/LICENSE').write_bytes(b'truncated')
        self.reject()

    def test_retained_generator_source_mutation_is_rejected(self):
        (self.output / 'client.rs').write_text('// substituted generator\n')
        self.reject()

    def test_extra_retained_artifact_is_rejected(self):
        (self.output / 'unexplained').write_bytes(b'asset')
        report = self.report()
        report['files'] = producer.inventory(self.output)
        self.save(report)
        self.reject()

    def test_generated_file_mode_is_enforced(self):
        (self.output / 'rootfs/usr/share/doc/libcosmic/LICENSE').chmod(0o600)
        self.reject()

    def test_retained_exporter_identity_is_enforced(self):
        (self.output / producer.EXECUTABLE).write_bytes(b'changed')
        self.reject()

    def test_installed_prefix_can_move_into_combined_catalog(self):
        installer.install(self.output, self.installation)
        before = installer.validate_inputs(self.installation)
        combined = self.root / 'combined'
        shutil.copytree(self.installation, combined)
        (combined / 'other-origin.json').write_text('{"unrelated":true}\n')
        other = combined / 'rootfs/usr/share/other/file'
        other.parent.mkdir(parents=True)
        other.write_text('other catalog asset')
        self.assertEqual(before, installer.validate_inputs(combined))

    def test_no_replace_race_preserves_concurrent_empty_directory(self):
        publish = installer.atomic.publish_directory
        def race(pending, output):
            output.mkdir()
            self.inode = output.stat().st_ino
            publish(pending, output)
        with mock.patch.object(installer.atomic, 'publish_directory', side_effect=race):
            with self.assertRaises(FileExistsError):
                installer.install(self.output, self.installation)
        self.assertEqual(self.installation.stat().st_ino, self.inode)
        self.assertEqual(list(self.installation.iterdir()), [])

    def test_existing_prefix_preserved(self):
        self.installation.mkdir()
        (self.installation / 'original').write_text('keep')
        with self.assertRaises(producer.BuildError):
            installer.install(self.output, self.installation)
        self.assertEqual((self.installation / 'original').read_text(), 'keep')

    def test_protected_toolchain_subdirectory_rejected(self):
        with self.assertRaises(producer.BuildError):
            installer.install(self.output, self.root / 'rust/new-installation')

    def test_installed_receipt_mode_and_claims_enforced(self):
        installer.install(self.output, self.installation)
        path = self.installation / installer.RECEIPT
        raw = path.read_bytes()
        path.chmod(0o600)
        with self.assertRaises(producer.BuildError):
            installer.validate_inputs(self.installation)
        path.chmod(0o644)
        data = producer.decode(raw)
        data['guest_execution'] = True
        path.write_text(json.dumps(data))
        with self.assertRaises(producer.BuildError):
            installer.validate_inputs(self.installation)

    def test_old_receipt_name_cannot_masquerade_as_new_origin(self):
        installer.install(self.output, self.installation)
        (self.installation / installer.RECEIPT).rename(self.installation / 'cosmic-theme-assets.json')
        with self.assertRaises((producer.BuildError, FileNotFoundError)):
            installer.validate_inputs(self.installation)

    def test_failed_input_postcheck_never_publishes_success(self):
        self.output = self.root / 'artifacts/changed-during-build'
        after = copy.deepcopy(self.input)
        after['rlib_snapshot_is_new_input'] = False
        with mock.patch.object(producer, 'capture_inputs', side_effect=[copy.deepcopy(self.input), after]):
            with self.assertRaises(producer.BuildError):
                self.build()
        report = self.report()
        self.assertEqual(report['status'], 'failed')
        self.assertIs(report['host_generation'], False)
        self.assertIs(report['inputs_preserved'], False)

    def test_native_failure_retained_without_false_success(self):
        self.output = self.root / 'artifacts/native-failed'
        def fail(*args, **kwargs):
            raise producer.processes.CosmicBuildError('mocked command exit 17; no real process')
        with mock.patch.object(producer.processes, 'run_bounded', side_effect=fail):
            with self.assertRaises(producer.processes.CosmicBuildError):
                self.build()
        report = self.report()
        self.assertEqual(report['steps'][0]['status'], 'failed')
        self.assertNotIn('returncode', report['steps'][0])
        self.assertIs(report['host_generation'], False)

    def test_available_symlink_and_unavailable_tool_protection(self):
        target = self.root / 'real-tools/real'
        target.parent.mkdir()
        target.write_bytes(b'fixture')
        declared = self.root / 'tool-links/tool'
        declared.parent.mkdir()
        declared.symlink_to(target)
        absent = self.root / 'optional/unavailable'
        self.input['tools'][str(declared)] = producer.tool_identity(declared)
        self.input['declared_tools'] = {'real': {'path': str(declared), 'available': True},
                                       'optional': {'path': str(absent), 'available': False}}
        protected = producer.protected_paths(self.input)
        self.assertIn(declared.parent, protected)
        self.assertIn(target.parent, protected)
        self.assertIn(absent.parent, protected)


class ElfReadOnlyBoundaries(unittest.TestCase):
    def test_dynamic_graph_parser_without_execution(self):
        with tempfile.TemporaryDirectory(prefix='cyxia-host-elf-fixture-') as temporary:
            root = Path(temporary)
            path = root / 'host-tool'
            strings = b'\0libfixture.so\0$ORIGIN\0'
            raw = bytearray(1024)
            struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, b'\x7fELF\x02\x01\x01' + bytes(9),
                             2, 62, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
            struct.pack_into('<IIQQQQQQ', raw, 64, 1, 4, 0, 0x1000, 0, 1024, 1024, 4096)
            struct.pack_into('<IIQQQQQQ', raw, 120, 2, 4, 512, 0x1200, 0, 80, 80, 8)
            for index, entry in enumerate(((1, 1), (5, 0x1300), (10, len(strings)), (29, 15), (0, 0))):
                struct.pack_into('<qQ', raw, 512 + index * 16, *entry)
            raw[768:768 + len(strings)] = strings
            path.write_bytes(raw)
            (root / 'libfixture.so').write_bytes(b'fixture-only-not-executable')
            with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('No tools')):
                graph = producer.host_runtime([str(path)], [str(root)])
            parsed = graph['elf_closure'][str(path)]['dynamic']
            self.assertEqual(parsed['needed'], ['libfixture.so'])
            self.assertEqual(parsed['runpath'], ['$ORIGIN'])
            self.assertEqual(graph['elf_closure'][str(path)]['selected']['libfixture.so'], str(root / 'libfixture.so'))

    def test_truncated_elf_rejected(self):
        with tempfile.TemporaryDirectory(prefix='cyxia-host-elf-fixture-') as temporary:
            path = Path(temporary) / 'truncated'
            path.write_bytes(b'\x7fELFbad')
            with self.assertRaises(producer.BuildError):
                producer.elf_dependencies(path)


if __name__ == '__main__':
    unittest.main()
