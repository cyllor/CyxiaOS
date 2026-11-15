"""COSMIC default asset integrity checks; no native build or target execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import install_cosmic_config as installer


class CosmicConfigAssets(unittest.TestCase):
    def fixture(self, root):
        manifest = installer.load_manifest()
        sources, blobs = {}, {}
        for package in manifest['packages']:
            source = root / package['name']
            source.mkdir()
            sources[package['name']] = source
            for entry in package['files']:
                data = (package['name'] + ':' + entry['source']).encode()
                path = source / entry['source']
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                entry['bytes'] = len(data)
                entry['sha256'] = hashlib.sha256(data).hexdigest()
                blobs[(str(source), entry['source'])] = data
        manifest_path = root / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest))

        def git_output(source, *args):
            if args == ('rev-parse', '--show-toplevel'):
                return str(source).encode() + b'\n'
            package = next(p for p in manifest['packages'] if sources[p['name']] == source)
            if args == ('rev-parse', 'HEAD'):
                return package['commit'].encode() + b'\n'
            if args[0] == 'cat-file':
                return blobs[(str(source), args[-1].split(':', 1)[1])]
            raise AssertionError(args)

        return manifest_path, sources, git_output

    def test_exact_defaults_and_licenses_are_pinned(self):
        manifest = installer.load_manifest()
        assets = [f['destination'] for p in manifest['packages'] for f in p['files']
                  if 'destination' in f]
        self.assertEqual(len(assets), 5)
        self.assertEqual(sum('/cosmic/' in p for p in assets), 3)
        self.assertNotIn('/usr/share/cosmic/com.system76.CosmicSettings.Shortcuts/v1/custom', assets)
        self.assertEqual(manifest['packages'][0]['commit'],
                         '41497b42d9744d9963c4c6d17e8add49489b45ee')
        self.assertEqual(manifest['packages'][1]['commit'],
                         'e37160f14d1e7ee428f973cd2848b4e95f83dfe1')

    def test_copy_and_curated_receipt_preserve_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest, sources, git_output = self.fixture(root)
            with patch.object(installer, 'git_output', side_effect=git_output):
                report = installer.install(root / 'out', sources, manifest)
                self.assertTrue(report['source_preserved'])
                self.assertEqual(report['sources_before'], report['sources_after'])
                self.assertEqual(report['bounds']['asset_files'], 5)
                self.assertFalse(report['cosmic_session_verified'])
                for asset in report['assets']:
                    path = root / 'out/rootfs' / asset['path'].lstrip('/')
                    self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                self.assertEqual(installer.validate_inputs(root / 'out', manifest,
                                 receipt='report.json')['assets'], report['assets'])
                curated = root / 'curated'
                curated.mkdir()
                import shutil
                shutil.copytree(root / 'out/rootfs', curated / 'rootfs')
                shutil.copyfile(root / 'out/report.json', curated / 'cosmic-config-assets.json')
                (curated / 'rootfs/unrelated').write_text('another package')
                self.assertEqual(installer.validate_inputs(curated, manifest)['assets'], report['assets'])

    def test_bad_manifest_paths_duplicates_and_identity_fail_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest, sources, git_output = self.fixture(root)
            original = json.loads(manifest.read_text())
            for mutation in ('duplicate', 'escape', 'absolute', 'noncanonical', 'hash', 'commit', 'recipe'):
                with self.subTest(mutation=mutation):
                    bad = copy.deepcopy(original)
                    entry = bad['packages'][0]['files'][0]
                    if mutation == 'duplicate': bad['packages'][0]['files'].append(copy.deepcopy(entry))
                    elif mutation == 'escape': entry['source'] = '../escape'
                    elif mutation == 'absolute': entry['source'] = '/escape'
                    elif mutation == 'noncanonical': entry['destination'] = '/usr/share/../escape'
                    elif mutation == 'hash': entry['sha256'] = '0' * 64
                    elif mutation == 'commit': bad['packages'][0]['commit'] = '0' * 40
                    else: bad['packages'][0]['files'][-1]['sha256'] = '0' * 64
                    manifest.write_text(json.dumps(bad))
                    with patch.object(installer, 'git_output', side_effect=git_output):
                        with self.assertRaises(installer.BuildError):
                            installer.install(root / 'out', sources, manifest)
                    self.assertFalse((root / 'out').exists())

    def test_source_mutation_symlink_and_output_reuse_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest, sources, git_output = self.fixture(root)
            package = installer.load_manifest(manifest)['packages'][0]
            selected = sources[package['name']] / package['files'][0]['source']
            data = selected.read_bytes()
            with patch.object(installer, 'git_output', side_effect=git_output):
                selected.write_bytes(data + b'changed')
                with self.assertRaises(installer.BuildError): installer.install(root / 'out', sources, manifest)
                selected.unlink()
                alternate = root / 'same-bytes'
                alternate.write_bytes(data)
                selected.symlink_to(alternate)
                with self.assertRaises(installer.BuildError): installer.install(root / 'out', sources, manifest)
                selected.unlink()
                selected.write_bytes(data)
                for output in (root, sources[package['name']] / 'out'):
                    with self.assertRaises(installer.BuildError): installer.install(output, sources, manifest)
                link = root / 'alias'
                link.symlink_to(root, target_is_directory=True)
                with self.assertRaises(installer.BuildError): installer.install(link / 'out', sources, manifest)
                installer.install(root / 'out', sources, manifest)
                with self.assertRaises(installer.BuildError): installer.install(root / 'out', sources, manifest)

    def test_receipt_tampering_missing_bytes_and_symlinks_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest, sources, git_output = self.fixture(root)
            output = root / 'out'
            with patch.object(installer, 'git_output', side_effect=git_output):
                original = installer.install(output, sources, manifest)
            receipt = output / 'report.json'
            for mutation in ('duplicate', 'foreign', 'hash', 'manifest', 'preservation', 'bounds', 'source'):
                with self.subTest(mutation=mutation):
                    bad = copy.deepcopy(original)
                    if mutation == 'duplicate': bad['assets'].append(copy.deepcopy(bad['assets'][0]))
                    elif mutation == 'foreign': bad['assets'][0]['path'] = '/../escape'
                    elif mutation == 'hash': bad['assets'][0]['sha256'] = '0' * 64
                    elif mutation == 'manifest': bad['manifest']['sha256'] = '0' * 64
                    elif mutation == 'preservation': bad['source_preserved'] = False
                    elif mutation == 'bounds': bad['bounds']['asset_files'] = 99
                    else: bad['sources_before'][0]['commit'] = '0' * 40
                    receipt.write_text(json.dumps(bad))
                    with self.assertRaises(installer.BuildError):
                        installer.validate_inputs(output, manifest, receipt='report.json')
            receipt.write_text(json.dumps(original))
            selected = output / 'rootfs' / original['assets'][0]['path'].lstrip('/')
            data = selected.read_bytes()
            selected.write_bytes(data + b'changed')
            with self.assertRaises(installer.BuildError): installer.validate_inputs(output, manifest, receipt='report.json')
            selected.unlink()
            with self.assertRaises(installer.BuildError): installer.validate_inputs(output, manifest, receipt='report.json')
            alternate = root / 'same'
            alternate.write_bytes(data)
            selected.symlink_to(alternate)
            with self.assertRaises(installer.BuildError): installer.validate_inputs(output, manifest, receipt='report.json')

    def test_changed_git_blob_and_mutation_during_copy_cannot_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest, sources, git_output = self.fixture(root)

            def changed_blob(source, *args):
                data = git_output(source, *args)
                return data + b'changed Git object' if args[0] == 'cat-file' else data

            with patch.object(installer, 'git_output', side_effect=changed_blob):
                with self.assertRaisesRegex(installer.BuildError, 'pinned Git blob'):
                    installer.install(root / 'bad-blob', sources, manifest)
            self.assertFalse((root / 'bad-blob').exists())
            verify_sources = installer.verify_sources
            calls = 0

            def mutate_before_second_check(config, source_paths):
                nonlocal calls
                calls += 1
                if calls == 2:
                    selected = sources['cosmic-comp'] / 'data/keybindings.ron'
                    selected.write_bytes(b'changed while staging')
                return verify_sources(config, source_paths)

            with patch.object(installer, 'git_output', side_effect=git_output), \
                 patch.object(installer, 'verify_sources', side_effect=mutate_before_second_check):
                with self.assertRaisesRegex(installer.BuildError, 'source identity changed'):
                    installer.install(root / 'changing', sources, manifest)
            self.assertFalse((root / 'changing/report.json').exists())
            self.assertFalse((root / 'changing/rootfs').exists())

    def test_duplicate_json_keys_and_symlinked_receipts_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bad = root / 'bad.json'
            bad.write_text('{"schema_version": 1, "schema_version": 1}')
            with self.assertRaisesRegex(installer.BuildError, 'Duplicate JSON key'):
                installer.load_manifest(bad)
            manifest, sources, git_output = self.fixture(root)
            with patch.object(installer, 'git_output', side_effect=git_output):
                installer.install(root / 'out', sources, manifest)
            receipt = root / 'out/report.json'
            saved = root / 'saved.json'
            receipt.rename(saved)
            receipt.symlink_to(saved)
            with self.assertRaisesRegex(installer.BuildError, 'Symlink'):
                installer.validate_inputs(root / 'out', manifest, receipt='report.json')


if __name__ == '__main__':
    unittest.main()
