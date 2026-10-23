"""Pinned desktop resources must not escape or partially install bad manifests."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import build_pcmanfm as build


class DesktopAssetsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.write_bytes(b'pinned')
        self.rootfs = self.root / 'rootfs'
        self.manifest_path = self.root / 'assets.json'
        self.report_path = self.root / 'report.json'
        self.entry = {'source': 'source', 'target': '/etc/panel', 'bytes': 6,
                      'sha256': hashlib.sha256(b'pinned').hexdigest()}

    def install(self, entries):
        self.manifest_path.write_text(json.dumps({'files': entries, 'file_count': len(entries),
            'total_bytes': sum(x['bytes'] for x in entries)}))
        with patch.object(build, 'ROOT', self.root):
            return build.install_assets(self.manifest_path, self.rootfs, self.report_path)

    def test_pinned_resource_install_and_idempotence(self):
        for _ in range(2):
            self.install([self.entry])
            self.assertEqual((self.rootfs / 'etc/panel').read_bytes(), b'pinned')
            self.assertEqual(json.loads(self.report_path.read_text())['status'], 'assets-installed')

    def test_invalid_later_hash_does_not_install_earlier_file(self):
        invalid = dict(self.entry, target='/etc/bad', sha256='0' * 64)
        with self.assertRaises(build.BuildError):
            self.install([self.entry, invalid])
        self.assertFalse(self.rootfs.exists())

    def test_escaping_and_duplicate_paths_rejected(self):
        entries = [dict(self.entry, target='/etc/../escape'),
                   dict(self.entry, target='/../../escape'),
                   dict(self.entry, target='etc/panel'),
                   dict(self.entry, source='../outside')]
        for entry in entries:
            with self.subTest(entry=entry), self.assertRaises(build.BuildError):
                self.install([entry])
        with self.assertRaises(build.BuildError):
            self.install([self.entry, self.entry])

    def test_existing_directory_symlink_cannot_escape_rootfs(self):
        self.rootfs.mkdir()
        (self.rootfs / 'etc').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(build.BuildError):
            self.install([self.entry])
        self.assertFalse((self.root / 'panel').exists())


if __name__ == '__main__':
    unittest.main()
