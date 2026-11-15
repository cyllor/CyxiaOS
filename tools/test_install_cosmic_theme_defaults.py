"""Pure fixture coverage of generated-theme provenance and publication."""
import contextlib
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools import install_cosmic_theme_defaults as b


class ThemeAssetsTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()

            def write(path, data):
                selected = root / path
                selected.parent.mkdir(parents=True, exist_ok=True)
                selected.write_bytes(data)
                return {'path': path, **b.common.identity(data)}

            source = write(b.SOURCE_FILE, b'pinned upstream theme source fixture')
            generator = write(b.GENERATOR_FILE, b'generator fixture')
            license_data = b'Mozilla Public License Version 2.0 fixture'
            producer = write('tools/capture-fixture.py', b'capture fixture')
            receipt = write('artifacts/helper/' + b.builder.RECEIPT, b'{}')
            proof = {'status': 'VALIDATED_NOT_RUN', 'receipt_sha256': receipt['sha256'],
                     'executable': {'sha256': 'f' * 64}}
            files, captures = [], []
            for mode in b.IDS:
                rows = [(f'THEME_DEFAULTS BEGIN mode={mode} id={b.IDS[mode]} version=2 keys=39 '
                         f'source=libcosmic@{b.COMMIT}').encode()]
                keys = []
                for key in b.KEYS:
                    data = (b'true' if mode == 'dark' else b'false') if key == 'is_dark' else b'(fixture: 1)'
                    identity = b.common.identity(data)
                    path = b.destination(mode, key)
                    write('assets/rootfs' + path, data)
                    files.append({'path': path, **identity})
                    keys.append({'name': key, **identity})
                    rows.append(f'THEME_DEFAULTS KEY name={key} bytes={len(data)} hex={data.hex()}'.encode())
                rows.append(f'THEME_DEFAULTS PASS mode={mode} keys=39'.encode())
                serial = write('artifacts/' + mode + '/serial.raw', b'guest output\n' + b'\r\n'.join(rows) + b'\r\n')
                capture = {'status': 'PASS', 'mode': mode, 'exit_code': 0, 'returncode': 0,
                           'before': {'objects': 1}, 'after': {'objects': 1}, 'inputs': proof,
                           'images': {b.builder.EXECUTABLE: 'f' * 64}, 'full_os_verified': False,
                           'cosmic_session_verified': False, 'source_sha256': 'a' * 64,
                           'build_manifest_sha256': 'b' * 64, 'serial_sha256': serial['sha256'],
                           'generator_sha256': generator['sha256'], 'producer_sha256': producer['sha256'],
                           'producer_inputs': {producer['path']: producer['sha256']}, 'keys': keys}
                summary = write('artifacts/' + mode + '/summary.json', json.dumps(capture).encode())
                captures.append({'mode': mode, 'capture': summary, 'serial': serial})
            write('assets/rootfs' + b.LICENSE_PATH, license_data)
            files.append({'path': b.LICENSE_PATH, **b.common.identity(license_data)})
            manifest = {'schema_version': 1, 'repository': b.REPOSITORY, 'commit': b.COMMIT,
                        'license': 'MPL-2.0', 'theme_version': 2,
                        'files': sorted(files, key=lambda row: row['path']),
                        'provenance': {'source': source, 'generator': generator,
                                       'build': {'prefix': 'artifacts/helper', 'receipt': receipt},
                                       'captures': captures}}
            path = root / 'assets/assets.json'
            path.write_text(json.dumps(manifest))

            def git_output(checkout, *args):
                return license_data if args[-1].endswith(':LICENSE') else (root / b.SOURCE_FILE).read_bytes()

            with patch.object(b, 'ROOT', root), patch.object(b, 'producer_identity', return_value={'fixture': 'pinned'}), \
                 patch.object(b.builder, 'validate_inputs', return_value=proof), \
                 patch.object(b.common, 'git_output', side_effect=git_output):
                yield root, path, manifest, proof

    def rewrite_capture(self, root, manifest, mutate):
        selected = manifest['provenance']['captures'][0]['capture']
        path = root / selected['path']
        summary = json.loads(path.read_text())
        mutate(summary)
        data = json.dumps(summary).encode()
        path.write_bytes(data)
        selected.update(b.common.identity(data))

    def test_install_and_curated_prefix_preserve_all_79_exact_assets(self):
        with self.fixture() as (root, path, _, _):
            output = root / 'out'
            report = b.install(output, path)
            self.assertEqual(report['bounds']['asset_files'], 79)
            self.assertEqual(report['inputs_before'], report['inputs_after'])
            self.assertEqual(b.validate_inputs(output, path, receipt='report.json'), report)
            curated = root / 'curated'
            curated.mkdir()
            shutil.copytree(output / 'rootfs', curated / 'rootfs')
            shutil.copyfile(output / 'report.json', curated / 'cosmic-theme-assets.json')
            (curated / 'rootfs/other-package').write_text('preserve')
            self.assertEqual(b.validate_inputs(curated, path)['assets'], report['assets'])
            self.assertEqual((curated / 'rootfs/other-package').read_text(), 'preserve')
            with self.assertRaises(b.BuildError):
                b.install(output, path)

    def test_manifest_destination_count_order_and_pins_reject_before_output(self):
        for mutation in ('extra', 'missing', 'duplicate', 'unsorted', 'escape', 'commit', 'version'):
            with self.subTest(mutation=mutation), self.fixture() as (root, path, manifest, _):
                if mutation == 'extra': manifest['files'].append(copy.deepcopy(manifest['files'][0]))
                elif mutation == 'missing': manifest['files'].pop()
                elif mutation == 'duplicate': manifest['files'][1] = copy.deepcopy(manifest['files'][0])
                elif mutation == 'unsorted': manifest['files'].reverse()
                elif mutation == 'escape': manifest['files'][0]['path'] = '/../escape'
                elif mutation == 'commit': manifest['commit'] = '0' * 40
                else: manifest['theme_version'] = 1
                path.write_text(json.dumps(manifest))
                with self.assertRaises(b.BuildError): b.install(root / 'out', path)
                self.assertFalse((root / 'out').exists())

    def test_failed_abnormal_or_inconsistent_capture_cannot_admit_valid_pass_serial(self):
        changes = {'status': 'FAIL', 'exit_code': 1, 'returncode': -9, 'forced': True,
                   'after': {'objects': 2}, 'inputs': {}, 'images': {}, 'serial_sha256': '0' * 64,
                   'generator_sha256': '0' * 64, 'keys': [], 'producer_inputs': {},
                   'full_os_verified': True, 'cosmic_session_verified': True}
        for key, value in changes.items():
            with self.subTest(key=key), self.fixture() as (root, path, manifest, _):
                self.rewrite_capture(root, manifest, lambda summary: summary.update({key: value}))
                path.write_text(json.dumps(manifest))
                with self.assertRaises(b.BuildError): b.install(root / 'out', path)
                self.assertFalse((root / 'out').exists())

    def test_serial_requires_one_complete_sorted_exact_generation(self):
        with self.fixture() as (root, _, manifest, _):
            data = (root / manifest['provenance']['captures'][0]['serial']['path']).read_bytes()
            self.assertEqual(tuple(b.parse_serial(data, 'dark')), b.KEYS)
            rows = data.splitlines()
            for bad in (data + b'THEME_DEFAULTS FAIL: late error\n', data + data,
                        b'\n'.join(rows[:-1]), data.replace(b'bytes=12 ', b'bytes=11 ', 1)):
                with self.assertRaises(b.BuildError): b.parse_serial(bad, 'dark')
            with self.assertRaises(b.BuildError): b.parse_serial(data, 'light')

    def test_changed_bytes_extra_files_symlinks_and_curated_tampering_fail(self):
        for mutation in ('changed', 'extra', 'symlink'):
            with self.subTest(mutation=mutation), self.fixture() as (root, path, manifest, _):
                selected = root / 'assets/rootfs' / manifest['files'][0]['path'].lstrip('/')
                if mutation == 'changed': selected.write_bytes(b'changed')
                elif mutation == 'extra': (root / 'assets/rootfs/extra').write_bytes(b'extra')
                else:
                    alternate = root / 'alias-source'
                    alternate.write_bytes(selected.read_bytes())
                    selected.unlink()
                    selected.symlink_to(alternate)
                with self.assertRaises(b.BuildError): b.install(root / 'out', path)
                self.assertFalse((root / 'out').exists())
        with self.fixture() as (root, path, manifest, _):
            b.install(root / 'out', path)
            selected = root / 'out/rootfs' / manifest['files'][0]['path'].lstrip('/')
            selected.write_bytes(b'changed')
            with self.assertRaises(b.BuildError):
                b.validate_inputs(root / 'out', path, receipt='report.json')

    def test_failed_destination_validation_never_modifies_preserved_input_trees(self):
        with self.fixture() as (root, path, manifest, _):
            for destination in (root / b.CHECKOUT / 'new-output',
                                root / 'artifacts/helper/new-output',
                                root / 'artifacts/dark/new-output',
                                root / 'artifacts/cosmic-cargo-cache/new-output'):
                with self.subTest(destination=destination), self.assertRaises(b.BuildError):
                    b.install(destination, path)
                self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
