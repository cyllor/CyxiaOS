"""Config client link contracts. Fixtures never invoke a compiler or a guest."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import build_cosmic_config as b


def elf_bytes():
    data = bytearray(4096)
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 2, 62, 1,
                     0x1000100, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 6, 4, 64, 0x1000040, 0x1000040, 112, 112, 8)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 5, 0, 0x1000000, 0x1000000, 4096, 4096, 4096)
    return bytes(data)


class ConfigBuildContract(unittest.TestCase):
    def fixture(self, root):
        artifacts = root / 'artifacts'
        artifacts.mkdir()
        cosmic, sdk = artifacts / 'cosmic', artifacts / 'sdk'
        cosmic.mkdir()
        sdk.mkdir()
        manifest = root / 'manifest.json'
        manifest.write_text('{}')
        inputs = {'cosmic_build': str(cosmic), 'sdk': str(sdk),
                  'manifest': {'path': str(manifest), 'sha256': b.file_hash(manifest)},
                  'rustc': str(root / 'rustc'), 'toolchain_root': str(root / 'toolchain'),
                  'source': str(root / 'client.rs'), 'externs': {
                      name: str(cosmic / (name + '.rlib')) for name in b.EXTERN_NAMES}}
        return artifacts, cosmic, sdk, manifest, inputs

    def fake_run(self, command, cwd, env, log, *args, **kwargs):
        Path(log).write_text('fixture compiler log\n')
        Path(command[command.index('-o') + 1]).write_bytes(elf_bytes())

    def test_fresh_output_is_confined_to_artifacts_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts, cosmic, sdk, _, _ = self.fixture(root)
            with patch.object(b, 'ARTIFACTS', artifacts):
                self.assertEqual(b.validate_output(artifacts / 'new', cosmic, sdk), artifacts / 'new')
                for path in (root / 'outside', cosmic, sdk / 'new', artifacts / '../escape'):
                    with self.assertRaises(b.BuildError): b.validate_output(path, cosmic, sdk)
                (artifacts / 'alias').symlink_to(root, target_is_directory=True)
                with self.assertRaises(b.BuildError): b.validate_output(artifacts / 'alias/new', cosmic, sdk)

    def test_search_root_rejects_modified_missing_extra_and_symlinked_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'one.rlib').write_bytes(b'actual library fixture')
            expected = b.file_map(root)
            self.assertEqual(b.verify_tree(root, expected), expected)
            for change in ('modified', 'missing', 'extra', 'symlink'):
                path = root / 'one.rlib'
                if path.exists() or path.is_symlink(): path.unlink()
                path.write_bytes(b'actual library fixture')
                if change == 'modified': path.write_bytes(b'changed')
                elif change == 'missing': path.unlink()
                elif change == 'extra': (root / 'two.rmeta').write_bytes(b'extra')
                else:
                    path.unlink()
                    path.symlink_to(root / 'two.rmeta')
                with self.assertRaises(b.BuildError): b.verify_tree(root, expected)
                if (root / 'two.rmeta').exists(): (root / 'two.rmeta').unlink()

    def test_extern_resolution_requires_one_exact_rlib_per_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / b.SEARCH_ROOTS[0]
            target.mkdir(parents=True)
            expected = {}
            for name in b.EXTERN_NAMES:
                path = target / ('lib' + name + '-123.rlib')
                path.write_bytes(b'library')
                expected[name] = str(path.relative_to(root))
            self.assertEqual(set(b.resolve_externs(root, expected)), set(b.EXTERN_NAMES))
            (target / 'libcosmic_config-other.rlib').write_bytes(b'ambiguous')
            with self.assertRaisesRegex(b.BuildError, 'Ambiguous'):
                b.resolve_externs(root, expected)
            (target / 'libcosmic_config-other.rlib').unlink()
            expected['cosmic_config'] = '../escape.rlib'
            with self.assertRaises(b.BuildError): b.resolve_externs(root, expected)

    def test_original_failed_build_status_is_not_promoted(self):
        report = {'status': 'failed', 'link_completed': True, 'target_linked': False,
                  'target': b.TARGET, 'architecture': 'x86_64',
                  'error': 'Invalid LOAD bounds, alignment or W^X permissions',
                  'resource_profile': {'max_elf_bytes': 16777216, 'image_bytes': 16777216}}
        self.assertEqual(b.original_outcome(report)['status'], 'failed')
        for key, value in [('status', 'cross-built'), ('link_completed', False),
                           ('target_linked', True), ('target', 'aarch64-unknown-linux-musl')]:
            bad = {**report, key: value}
            with self.assertRaises(b.BuildError): b.original_outcome(bad)

    def test_build_and_curated_copy_require_exact_receipt_and_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts, cosmic, sdk, manifest, inputs = self.fixture(root)
            output = artifacts / 'out'
            with patch.object(b, 'ARTIFACTS', artifacts), \
                 patch.object(b, 'capture_inputs', return_value=inputs), \
                 patch.object(b, 'native_lease', return_value=contextlib.nullcontext()), \
                 patch.object(b, 'idle_native_host'), \
                 patch.object(b, 'run_bounded', side_effect=self.fake_run):
                report = b.build(output, cosmic, sdk, manifest=manifest)
                self.assertEqual(report['status'], 'cross-built')
                self.assertFalse(report['cosmic_session_ready'])
                self.assertEqual(b.validate_inputs(output)['report'], report)
                curated = artifacts / 'curated'
                curated.mkdir()
                for name in (b.RECEIPT, b.EXECUTABLE): shutil.copyfile(output / name, curated / name)
                self.assertEqual(b.validate_inputs(curated)['report'], report)
                receipt = curated / b.RECEIPT
                receipt.write_text(receipt.read_text() + ' ')
                with self.assertRaisesRegex(b.BuildError, 'exact original receipt'):
                    b.validate_inputs(curated)
                shutil.copyfile(output / b.RECEIPT, receipt)
                (curated / b.EXECUTABLE).write_bytes(elf_bytes() + b'changed')
                with self.assertRaises(b.BuildError): b.validate_inputs(curated)
                (curated / b.EXECUTABLE).unlink()
                (curated / b.EXECUTABLE).symlink_to(output / b.EXECUTABLE)
                with self.assertRaises(b.BuildError): b.validate_inputs(curated)

    def test_before_after_change_cannot_publish_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts, cosmic, sdk, manifest, inputs = self.fixture(root)
            with patch.object(b, 'ARTIFACTS', artifacts), \
                 patch.object(b, 'capture_inputs', side_effect=[inputs, {**inputs, 'changed': True}]), \
                 patch.object(b, 'native_lease', return_value=contextlib.nullcontext()), \
                 patch.object(b, 'idle_native_host'), \
                 patch.object(b, 'run_bounded', side_effect=self.fake_run):
                with self.assertRaisesRegex(b.BuildError, 'changed during'):
                    b.build(artifacts / 'out', cosmic, sdk, manifest=manifest)
            report = json.loads((artifacts / 'out' / b.RECEIPT).read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertFalse((artifacts / 'out' / b.EXECUTABLE).exists())

    def test_receipt_mutations_and_duplicate_json_keys_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts, cosmic, sdk, manifest, inputs = self.fixture(root)
            output = artifacts / 'out'
            with patch.object(b, 'ARTIFACTS', artifacts), \
                 patch.object(b, 'capture_inputs', return_value=inputs), \
                 patch.object(b, 'native_lease', return_value=contextlib.nullcontext()), \
                 patch.object(b, 'idle_native_host'), \
                 patch.object(b, 'run_bounded', side_effect=self.fake_run):
                report = b.build(output, cosmic, sdk, manifest=manifest)
                for key, value in [('command', []), ('environment', {'RUSTFLAGS': 'injected'}),
                                   ('limits', {}), ('input_preserved', False),
                                   ('cosmic_session_ready', True), ('inputs_after', {})]:
                    bad = {**report, key: value}
                    (output / b.RECEIPT).write_text(json.dumps(bad))
                    with self.subTest(key=key), self.assertRaises(b.BuildError): b.validate_inputs(output)
            manifest.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(b.BuildError, 'Duplicate JSON key'): b.read_json(manifest)

    def test_dependency_closure_checks_current_sources_and_original_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            packages, nodes, records = [], [], []
            for name in ('cosmic-config', 'cosmic-settings-config', 'transitive-fixture'):
                directory = root / 'artifacts/cosmic-cargo-cache' / name
                directory.mkdir(parents=True)
                manifest = directory / 'Cargo.toml'
                manifest.write_text('pinned ' + name)
                packages.append({'id': name, 'name': name, 'version': '1.0', 'source': 'pinned',
                                 'manifest_path': str(manifest)})
                nodes.append({'id': name, 'dependencies': ['transitive-fixture'] if name != 'transitive-fixture' else []})
                records.append({'name': name, 'version': '1.0', 'source': 'pinned', 'manifest': str(manifest),
                                'source_tree_sha256': b.map_hash(b.file_map(directory))})
            metadata = {'packages': packages, 'resolve': {'nodes': nodes}}
            original = {'cargo_dependencies': records}
            with patch.object(b, 'ROOT', root):
                self.assertEqual(len(b.dependency_records(metadata, original)), 3)
                for mutation in ('source-bytes', 'record', 'duplicate'):
                    changed = copy.deepcopy(original)
                    if mutation == 'source-bytes': manifest.write_text('changed')
                    elif mutation == 'record': changed['cargo_dependencies'][2]['version'] = '2.0'
                    else: changed['cargo_dependencies'].append(copy.deepcopy(records[2]))
                    with self.subTest(mutation=mutation), self.assertRaises(b.BuildError):
                        b.dependency_records(metadata, changed)
                    manifest.write_text('pinned transitive-fixture')

    def test_pinned_manifest_rejects_unsafe_and_missing_closure_entries(self):
        pinned = b.load_manifest()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'manifest.json'
            for mutation in ('search-root', 'file-path', 'extern-path', 'lock', 'native', 'tools'):
                changed = copy.deepcopy(pinned)
                if mutation == 'search-root': changed['search_roots']['../outside'] = {}
                elif mutation == 'file-path': changed['search_roots'][b.SEARCH_ROOTS[0]]['../outside'] = {'bytes': 1, 'sha256': 'a' * 64}
                elif mutation == 'extern-path': changed['externs']['cosmic_config'] = '/outside'
                elif mutation == 'lock': changed['lock']['path'] = '../outside'
                elif mutation == 'native': changed['sdk']['native_inputs'].pop('sysroot/usr/lib/libxkbcommon.a')
                else: changed['toolchain']['files'].pop('/usr/bin/clang')
                path.write_text(json.dumps(changed))
                with self.subTest(mutation=mutation), self.assertRaises(b.BuildError): b.load_manifest(path)

    def test_inventory_has_no_writes_or_native_calls_and_build_needs_output(self):
        with patch.object(b, 'native_lease') as lease, patch.object(b, 'run_bounded') as run, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(b.main(['inventory']), 0)
            self.assertEqual(b.main(['build']), 1)
        lease.assert_not_called()
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
