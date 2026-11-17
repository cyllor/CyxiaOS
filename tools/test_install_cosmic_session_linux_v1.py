"""Pure filesystem boundary tests; the independent build consumer is a fixture.

No real ELF admission, compiler, Cargo, native tool or guest is exercised here.
Actual installation must separately replay the original genuine build consumer.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    from tools import install_cosmic_session_linux_v1 as subject
except ImportError:
    import install_cosmic_session_linux_v1 as subject


class InstallationBoundaries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='session-install-boundary-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build = self.root / 'genuine-consumer-fixture'
        self.build.mkdir()
        self.output = self.root / 'installed'
        self.data = {subject.PROGRAM: b'EXPLICIT HOST ELF-BYTE FIXTURE\n'}
        for relative, destination in subject.LICENSES.items():
            self.data['source/' + relative] = ('COMPLETE HOST LICENSE FIXTURE ' + relative + '\n').encode()
        for relative, raw in self.data.items():
            p = self.build / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)
        report = {}
        for name in ('sysroot', 'source_cache', 'cargo_cache'):
            p = self.root / name
            p.mkdir()
            report[name] = str(p)
        self.rust_root = self.root / 'rust-toolchain'
        self.host_tools = self.root / 'host-tools'
        for p in (self.rust_root / 'bin', self.host_tools): p.mkdir(parents=True)
        report['toolchain'] = {'selection': {'rust_root': str(self.rust_root)},
            'tools': {'rustc': {'path': str(self.rust_root / 'bin/rustc'), 'available': True},
                      'host_cc': {'path': str(self.host_tools / 'clang'), 'available': True}}}
        for row in report['toolchain']['tools'].values():
            Path(row['path']).write_bytes(b'EXPLICIT HOST TOOL-BYTE FIXTURE')
        (self.build / 'build-report.json').write_text(json.dumps(report))
        self.validated = {'status': 'SESSION_BUILD_REVALIDATED_NOT_RUN', 'output': str(self.build),
            'guest_execution': False, 'cosmic_session_ready': False,
            'executable': subject.identify(self.data[subject.PROGRAM]),
            'identity_sha256': 'a' * 64, 'receipt_sha256': 'b' * 64,
            'required_pages': 1512, 'image_load_pages': 1000}
        consumer = patch.object(subject.consumer, 'validate_build', side_effect=lambda _path: copy.deepcopy(self.validated))
        self.consumer = consumer.start()
        self.addCleanup(consumer.stop)
        producers = patch.object(subject, 'producers', return_value={'HOST-FIXTURE-PRODUCER': 'c' * 64})
        producers.start()
        self.addCleanup(producers.stop)

    def test_copies_exact_bytes_modes_and_two_licenses_without_claiming_execution(self):
        receipt = subject.install(self.build, self.output)
        self.assertEqual(set(receipt['files']), {subject.PROGRAM, *subject.LICENSES.values()})
        self.assertEqual((self.output / subject.PROGRAM).read_bytes(), self.data[subject.PROGRAM])
        self.assertEqual((self.output / subject.PROGRAM).stat().st_mode & 0o7777, 0o755)
        for source, target in subject.LICENSES.items():
            self.assertEqual((self.output / target).read_bytes(), self.data['source/' + source])
            self.assertEqual((self.output / target).stat().st_mode & 0o7777, 0o644)
        result = subject.validate_inputs(self.output)
        self.assertEqual(result['status'], 'SESSION_INSTALLATION_REVALIDATED_NOT_RUN')
        for key in ('guest_execution', 'cosmic_session_ready', 'full_cosmic_complete'):
            self.assertIs(receipt[key], False)
            self.assertIs(result[key], False)
        self.assertGreaterEqual(self.consumer.call_count, 3)

    def test_existing_output_and_source_overlap_preserve_original_bytes(self):
        self.output.mkdir()
        keep = self.output / 'keep'
        keep.write_bytes(b'prior content')
        with self.assertRaises(subject.BuildError):
            subject.install(self.build, self.output)
        self.assertEqual(keep.read_bytes(), b'prior content')
        with self.assertRaises(subject.BuildError):
            subject.install(self.build, self.build / 'nested-output')
        self.assertFalse((self.build / 'nested-output').exists())
        for output in (self.rust_root / 'unrelated-new-directory', self.host_tools / 'unrelated-new-directory'):
            with self.assertRaises(subject.BuildError): subject.install(self.build, output)
            self.assertFalse(output.exists())

    def test_atomic_publication_does_not_replace_a_concurrent_empty_directory(self):
        original = subject.publish_directory
        created = []
        def concurrently_created(pending, output):
            output.mkdir()
            created.append(output.stat().st_ino)
            return original(pending, output)
        with patch.object(subject, 'publish_directory', side_effect=concurrently_created):
            with self.assertRaises(FileExistsError): subject.install(self.build, self.output)
        self.assertEqual(self.output.stat().st_ino, created[0])
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(list(self.root.glob('.installed-*')), [])

    def test_symlink_input_or_installed_file_is_rejected(self):
        link = self.root / 'build-link'
        link.symlink_to(self.build, target_is_directory=True)
        with self.assertRaises(subject.BuildError):
            subject.install(link, self.output)
        subject.install(self.build, self.output)
        target = self.output / subject.PROGRAM
        target.unlink()
        target.symlink_to(self.build / subject.PROGRAM)
        with self.assertRaises(subject.BuildError):
            subject.validate_inputs(self.output)

    def test_original_consumer_tool_symlink_remains_compatible(self):
        real_tool = self.host_tools / 'pkgconf'
        real_tool.write_bytes(b'EXPLICIT HOST PKG-CONFIG TOOL FIXTURE')
        tool_link = self.host_tools / 'pkg-config'
        tool_link.symlink_to(real_tool)
        path = self.build / 'build-report.json'
        report = json.loads(path.read_text())
        report['toolchain']['tools']['pkg_config'] = {'path': str(tool_link), 'available': True}
        path.write_text(json.dumps(report))
        subject.install(self.build, self.output)
        self.assertEqual(subject.validate_inputs(self.output)['status'], 'SESSION_INSTALLATION_REVALIDATED_NOT_RUN')
        self.assertTrue(tool_link.is_symlink())
        self.assertEqual(real_tool.read_bytes(), b'EXPLICIT HOST PKG-CONFIG TOOL FIXTURE')

    def test_original_consumer_missing_optional_tool_remains_unavailable(self):
        missing = self.host_tools / 'optional-target-cxx'
        path = self.build / 'build-report.json'
        report = json.loads(path.read_text())
        report['toolchain']['tools']['target_cxx'] = {'path': str(missing), 'available': False, 'sha256': None}
        path.write_text(json.dumps(report))
        subject.install(self.build, self.output)
        self.assertEqual(subject.validate_inputs(self.output)['status'], 'SESSION_INSTALLATION_REVALIDATED_NOT_RUN')
        self.assertFalse(missing.exists())
        with self.assertRaises(subject.BuildError):
            subject.install(self.build, self.host_tools / 'new-output')

    def test_failed_second_consumer_validation_never_publishes_partial_output(self):
        self.consumer.side_effect = [copy.deepcopy(self.validated), subject.BuildError('fixture source changed')]
        with self.assertRaisesRegex(subject.BuildError, 'fixture source changed'):
            subject.install(self.build, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('.installed-*')), [])
        self.assertEqual((self.build / subject.PROGRAM).read_bytes(), self.data[subject.PROGRAM])

    def test_installed_byte_mode_license_and_origin_tampering_fail_closed(self):
        subject.install(self.build, self.output)
        selected = self.output / subject.PROGRAM
        original = selected.read_bytes()
        selected.write_bytes(original + b'changed')
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        selected.write_bytes(original)
        selected.chmod(0o4755)
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        selected.chmod(0o755)
        license_path = self.output / next(iter(subject.LICENSES.values()))
        license_raw = license_path.read_bytes()
        license_path.write_bytes(license_raw[:-1])
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        license_path.write_bytes(license_raw)
        self.validated['identity_sha256'] = 'd' * 64
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)

    def test_receipt_cannot_claim_runtime_success_or_boolean_page_counts(self):
        subject.install(self.build, self.output)
        path = self.output / subject.RECEIPT
        original = json.loads(path.read_text())
        for key, value in [('guest_execution', True), ('cosmic_session_ready', True),
                           ('full_cosmic_complete', True), ('required_pages', True),
                           ('image_load_pages', True), ('producer_sources', {})]:
            with self.subTest(key=key):
                path.write_text(json.dumps({**original, key: value}))
                with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        raw = json.dumps(original)
        path.write_text(raw[:-1] + ', "guest_execution": false}')
        with self.assertRaises((subject.BuildError, ValueError)): subject.validate_inputs(self.output)


if __name__ == '__main__':
    unittest.main()
