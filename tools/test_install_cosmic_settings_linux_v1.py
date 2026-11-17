"""Publication/consumer host fixtures; never compile or run settings services."""
import copy
import contextlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.test_cosmic_settings_linux_v1 import SettingsFixture, binary_fixture, save, write
from tools import build_cosmic_settings_linux_v1 as builder
from tools import cosmic_settings_inputs_v1 as consumer
from tools import install_cosmic_settings_linux_v1 as subject

contract = builder.contract


@unittest.skipUnless(Path('/usr/bin/git').is_file(), 'Real Git host fixtures are required')
class SettingsPublicationContracts(SettingsFixture):
    def test_complete_fixture_installs_atomically_after_original_stage_is_deleted(self):
        report = self.run_builder()
        self.assertFalse(Path(report['original_export_root']).exists())
        real_run, rename = subprocess.run, Path.rename
        published = []
        def only_git(command, *args, **kwargs):
            self.assertEqual(command[0], '/usr/bin/git')
            return real_run(command, *args, **kwargs)
        def atomic(pending, output):
            self.assertEqual(output, self.install_output)
            self.assertFalse(output.exists())
            self.assertEqual(subject.validate_inputs(pending)['status'], 'VALIDATED_NOT_RUN')
            published.append(True)
            return rename(pending, output)
        with mock.patch.object(subprocess, 'run', side_effect=only_git), \
             mock.patch.object(subprocess, 'check_output', side_effect=AssertionError('No native probes')), \
             mock.patch.object(Path, 'rename', atomic):
            receipt = subject.install(self.build_output, self.install_output)
            checked = subject.validate_inputs(self.install_output)
        self.assertEqual(published, [True])
        self.assertEqual(receipt['status'], 'INSTALLED_NOT_RUN')
        self.assertEqual(len(receipt['artifacts']), 4)
        self.assertIs(checked['settings_verified'], False)
        self.assertIs(checked['cosmic_session_ready'], False)
        self.assertEqual(receipt['inputs']['boundary'], self.policy['boundary'])

    def check_revoked(self, output):
        report = contract.read_json(output / 'build-report.json')
        self.assertEqual(report['status'], 'FAILED')
        self.assertIs(report['target_linked'], False)
        self.assertIs(report['settings_verified'], False)
        self.assertFalse((output / builder.PROGRAM).exists())
        self.assertFalse((output / ('.' + builder.PROGRAM + '.pending')).exists())
        self.assertEqual((output / 'target' / contract.TARGET / 'release' / contract.COMPONENT).read_bytes(), binary_fixture.elf())
        self.assertTrue((output / 'source/Cargo.toml').is_file())
        self.assertTrue((output / 'cargo.log').is_file())
        with self.assertRaisesRegex(ValueError, 'Not a preserved'):
            consumer.validate_build(output)

    def test_partial_copy_late_input_change_report_io_interrupt_and_cleanup_revoke_publication(self):
        for failure in ('partial-copy', 'late-source', 'report-io', 'interrupt', 'cleanup'):
            with self.subTest(failure=failure), contextlib.ExitStack() as mocks:
                output = self.root / failure
                triggered = []
                if failure == 'partial-copy':
                    original = builder.shutil.copyfileobj
                    def partial(source, destination, *args, **kwargs):
                        if Path(destination.name).name == '.' + builder.PROGRAM + '.pending':
                            destination.write(source.read(31)); triggered.append(True)
                            raise OSError('Fixture partial ELF copy')
                        return original(source, destination, *args, **kwargs)
                    mocks.enter_context(mock.patch.object(builder.shutil, 'copyfileobj', side_effect=partial))
                elif failure in ('late-source', 'interrupt'):
                    original = builder.publish
                    def late(*args, **kwargs):
                        result = original(*args, **kwargs); triggered.append(True)
                        if failure == 'interrupt': raise KeyboardInterrupt('Fixture finalization interrupt')
                        write(output / 'source/src/main.rs', '// Changed after publication fixture\n')
                        return result
                    mocks.enter_context(mock.patch.object(builder, 'publish', side_effect=late))
                elif failure == 'report-io':
                    original = builder.write_report
                    def failed_report(directory, report):
                        if report['status'] == 'cross-built' and not triggered:
                            triggered.append(True)
                            write(directory / 'build-report.json', '{"partial":')
                            raise OSError('Fixture report I/O failure')
                        return original(directory, report)
                    mocks.enter_context(mock.patch.object(builder, 'write_report', side_effect=failed_report))
                else:
                    original = tempfile.TemporaryDirectory.__exit__
                    def failed_cleanup(directory, *args):
                        result = original(directory, *args)
                        if Path(directory.name).name.startswith('cyxia-settings-linux-v1-'):
                            triggered.append(True)
                            raise OSError('Fixture control-directory cleanup failure')
                        return result
                    mocks.enter_context(mock.patch.object(tempfile.TemporaryDirectory, '__exit__', failed_cleanup))
                with self.assertRaises((ValueError, OSError, KeyboardInterrupt)):
                    self.run_builder(output=output)
                self.assertTrue(triggered)
                self.check_revoked(output)

    def test_success_cannot_omit_any_build_log(self):
        for name in contract.LOGS:
            with self.subTest(name=name):
                output = self.root / ('missing-' + name)
                def remove(action, stage, directory):
                    if action == 'build': (directory / name).unlink()
                with self.assertRaises((ValueError, OSError)):
                    self.run_builder(output=output, hook=remove)
                report = contract.read_json(output / 'build-report.json')
                self.assertEqual(report['status'], 'FAILED')
                self.assertIs(report['target_linked'], False)
                self.assertFalse((output / builder.PROGRAM).exists())

    def test_failed_runtime_claimed_or_altered_provenance_report_is_rejected(self):
        original = self.run_builder()
        path = self.build_output / 'build-report.json'
        for field, value in [('status', 'FAILED'), ('schema_version', True), ('settings_verified', True),
            ('cosmic_session_ready', True), ('cosmic_session_verified', True), ('source_preserved', False),
            ('inputs_preserved', False), ('target_linked', False), ('link_completed', 1),
            ('cargo_offline', False), ('operation', 'metadata'), ('postcheck_errors', ['changed']),
            ('producer_sources_after', {}), ('generated_build_inputs_after', {}), ('rust_libraries_after', {})]:
            changed = copy.deepcopy(original); changed[field] = value; save(path, changed)
            with self.subTest(field=field), self.assertRaises(ValueError): consumer.validate_build(self.build_output)
        save(path, original)
        self.assertEqual(consumer.validate_build(self.build_output)['status'], 'VALIDATED_NOT_RUN')

    def test_mutated_sources_archives_tools_rust_libraries_and_wrappers_are_rejected(self):
        self.run_builder()
        for path in [self.build_output / 'source/src/main.rs', self.build_output / 'native/libwayland-client.a',
                     self.sdk / 'sysroot/usr/lib/libffi.a', self.libdir / 'libcore-ab12.rlib',
                     self.tools['host_cc'], self.build_output / 'bin/target-pkg-config']:
            original = path.read_bytes(); path.write_bytes(original + b'changed')
            with self.subTest(path=path), self.assertRaises(ValueError): consumer.validate_build(self.build_output)
            path.write_bytes(original)
        extra = write(self.build_output / 'native/unreviewed.a', binary_fixture.archive())
        with self.assertRaisesRegex(ValueError, 'missing or extra'): consumer.validate_build(self.build_output)
        extra.unlink()

    def test_local_metadata_escape_and_rehashed_feature_change_are_rejected(self):
        original = self.run_builder()
        report_path, metadata_path = self.build_output / 'build-report.json', self.build_output / 'metadata.json'
        metadata = contract.read_json(metadata_path)
        for mutation in ('local-escape', 'feature'):
            altered = copy.deepcopy(metadata)
            if mutation == 'local-escape':
                altered['packages'][0]['manifest_path'] = str(self.source / 'Cargo.toml')
            else:
                altered['resolve']['nodes'][0]['features'] = ['audio', 'cyxia-native']
            save(metadata_path, altered)
            report = copy.deepcopy(original)
            report['metadata_sha256'] = contract.base.digest(metadata_path)
            report['retained_logs']['metadata.json'] = {'bytes': metadata_path.stat().st_size,
                                                       'sha256': report['metadata_sha256']}
            save(report_path, report)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): consumer.validate_build(self.build_output)
        save(metadata_path, metadata); save(report_path, original)

    def test_installation_rechecks_source_after_copy_and_preserves_existing_outputs(self):
        self.run_builder()
        self.install_output.mkdir()
        marker = write(self.install_output / 'keep', 'Preserve existing output.\n')
        with self.assertRaisesRegex(ValueError, 'Preserving existing'):
            subject.install(self.build_output, self.install_output)
        self.assertEqual(marker.read_text(), 'Preserve existing output.\n')
        marker.unlink(); self.install_output.rmdir()
        with self.assertRaisesRegex(ValueError, 'overlaps a read-only input'):
            subject.install(self.build_output, self.cache / 'forbidden-install')
        self.assertFalse((self.cache / 'forbidden-install').exists())
        original_read = contract.read_regular
        changed, observations = [], []
        def drift(path, *args, **kwargs):
            data = original_read(path, *args, **kwargs)
            if Path(path) == self.build_output / builder.PROGRAM:
                observations.append(True)
                if len(observations) == 2:
                    changed.append(True)
                    write(self.build_output / 'source/src/main.rs', '// Changed input during install\n')
            return data
        with mock.patch.object(contract, 'read_regular', side_effect=drift):
            with self.assertRaises(ValueError): subject.install(self.build_output, self.install_output)
        self.assertTrue(changed)
        self.assertFalse(self.install_output.exists())
        self.assertFalse(list(self.root.glob('.installed-*')))

    def test_installed_bytes_modes_and_receipt_cannot_claim_guest_verification(self):
        self.run_builder()
        receipt = subject.install(self.build_output, self.install_output)
        receipt_path = self.install_output / subject.RECEIPT
        changed = copy.deepcopy(receipt); changed['settings_verified'] = True; save(receipt_path, changed)
        with self.assertRaises(ValueError): subject.validate_inputs(self.install_output)
        save(receipt_path, receipt)
        for row in receipt['artifacts']:
            path = self.install_output / row['path']; original = path.read_bytes(); path.write_bytes(original + b'changed')
            with self.subTest(path=path), self.assertRaises(ValueError): subject.validate_inputs(self.install_output)
            path.write_bytes(original)
        (self.install_output / builder.PROGRAM).chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'file mode'): subject.validate_inputs(self.install_output)


if __name__ == '__main__':
    unittest.main()
