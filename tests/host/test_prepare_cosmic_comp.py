"""Public source preparation boundary: real Git export and ordered patches."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import prepare_cosmic_comp as prep


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PrepareCompTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / 'upstream'
        self.source.mkdir()
        self.git('init', '-q')
        self.git('remote', 'add', 'origin', 'https://example.invalid/cosmic-comp')
        (self.source / 'Cargo.lock').write_text('version = 4\n')
        (self.source / 'render.rs').write_text('old\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'source')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.series = dict(schema_version=1, component='cosmic-comp',
                           repository='https://example.invalid/cosmic-comp', commit=self.commit,
                           source_lock_sha256=digest(b'version = 4\n'), patches=[])
        self.add_patch('one', b'old\n', b'middle\n')
        self.add_patch('two', b'middle\n', b'new\n')
        self.series_path = self.root / 'series.json'
        self.write_series()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.source), *args], text=True)

    def write_series(self):
        self.series_path.write_text(json.dumps(self.series))

    def add_patch(self, name, before, after):
        patch = ('diff --git a/render.rs b/render.rs\n--- a/render.rs\n+++ b/render.rs\n'
                 '@@ -1 +1 @@\n-' + before.decode() + '+' + after.decode()).encode()
        (self.root / (name + '.patch')).write_bytes(patch)
        manifest = dict(schema_version=1, repository=self.series['repository'], commit=self.commit,
                        patch_sha256=digest(patch), before={'render.rs': digest(before)},
                        after={'render.rs': digest(after)})
        manifest_path = self.root / (name + '.json')
        manifest_path.write_text(json.dumps(manifest))
        self.series['patches'].append(dict(patch=name + '.patch', manifest=name + '.json',
                                          manifest_sha256=digest(manifest_path.read_bytes())))

    def prepare(self):
        return prep.prepare(self.source, self.root / 'output', series_path=self.series_path,
                            root=self.root)

    def test_ordered_patch_stack_exports_real_source_without_mutating_pin(self):
        result = self.prepare()
        self.assertEqual((self.root / 'output/source/render.rs').read_text(), 'new\n')
        self.assertEqual((self.source / 'render.rs').read_text(), 'old\n')
        self.assertEqual(self.git('status', '--porcelain'), '')
        self.assertEqual(result['status'], 'PATCHED_NOT_COMPOSITOR_BUILT')
        self.assertFalse(result['compositor_built'])
        self.assertFalse(result['guest_tested'])
        self.assertEqual(len(result['patches']), 2)
        self.assertTrue(result['source_preserved'])

    def test_wrong_order_does_not_apply_with_fuzz_or_claim_success(self):
        self.series['patches'].reverse()
        self.write_series()
        with self.assertRaisesRegex(ValueError, 'preimage'):
            self.prepare()
        report = json.loads((self.root / 'output/preparation.json').read_text())
        self.assertEqual(report['status'], 'FAILED')
        self.assertFalse(report['compositor_built'])
        self.assertFalse((self.root / 'output/source').exists())

    def test_unbound_change_in_patch_is_rejected(self):
        path = self.root / 'one.patch'
        path.write_text(path.read_text() + 'diff --git a/extra b/extra\nnew file mode 100644\n'
                        '--- /dev/null\n+++ b/extra\n@@ -0,0 +1 @@\n+unlisted\n')
        manifest = json.loads((self.root / 'one.json').read_text())
        manifest['patch_sha256'] = digest(path.read_bytes())
        (self.root / 'one.json').write_text(json.dumps(manifest))
        self.series['patches'][0]['manifest_sha256'] = digest((self.root / 'one.json').read_bytes())
        self.write_series()
        with self.assertRaisesRegex(ValueError, 'unbound'):
            self.prepare()

    def test_modified_original_is_preserved_and_rejected(self):
        (self.source / 'render.rs').write_text('user edit\n')
        with self.assertRaisesRegex(ValueError, 'modified'):
            self.prepare()
        self.assertEqual((self.source / 'render.rs').read_text(), 'user edit\n')

    def test_coordinated_patch_and_manifest_edit_cannot_keep_series_identity(self):
        path = self.root / 'two.patch'
        path.write_text(path.read_text().replace('+new', '+different'))
        manifest_path = self.root / 'two.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['patch_sha256'] = digest(path.read_bytes())
        manifest['after']['render.rs'] = digest(b'different\n')
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'manifest identity'):
            self.prepare()

    def test_copy_failure_never_publishes_partial_source(self):
        def fail_copy(source, destination, **kwargs):
            destination.mkdir()
            (destination / 'render.rs').write_text('partial')
            raise OSError('disk full')
        with patch.object(prep.shutil, 'copytree', side_effect=fail_copy):
            with self.assertRaisesRegex(OSError, 'disk full'):
                self.prepare()
        self.assertFalse((self.root / 'output/source').exists())
        report = json.loads((self.root / 'output/preparation.json').read_text())
        self.assertEqual(report['status'], 'FAILED')

    def test_patch_checksum_is_enforced(self):
        (self.root / 'one.patch').write_text('tampered')
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.prepare()

    def test_existing_destination_is_preserved(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.prepare()
        self.assertEqual((self.root / 'output/source/render.rs').read_text(), 'new\n')


if __name__ == '__main__':
    unittest.main()
