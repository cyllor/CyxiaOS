"""Trusted local decoder/tool-custody boundaries; no native PASS fixtures."""
import hashlib
import inspect as reflection
from pathlib import Path
import shutil
import tempfile
import unittest

import check_v13_boot_disk as boot
import check_v13_disk as reserved
import verify_v13_a02 as a02
import verify_v13_boot_receipt as a01


class BootDiskConsumers(unittest.TestCase):
    def test_current_normal_runners_choose_the_ordinary_aware_decoder(self):
        import run_v13_a02
        import verify_unified
        import verify_unified_disk
        import verify_v13_boot_reboots
        for function in (run_v13_a02.inspect_disk, verify_unified.inspect_disk,
                         verify_unified_disk.inspect, verify_v13_boot_reboots.inspect_disk):
            self.assertIs(function, boot.inspect)
        self.assertTrue(set(boot.TOOL_FILES) <= set(a01.TOOL_FILES))

    def test_a02_current_and_historical_revisions_remain_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'tools').mkdir()
            paths = (Path(reflection.getfile(__import__('run_v13_a02'))),
                     Path(reflection.getfile(a02)))
            for path in paths:
                shutil.copyfile(path, root / 'tools' / path.name)
            current = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths)
            self.assertEqual(a02.verify_capture_revision(*current, source_root=root), 'current')
            historic = ('55ad61d89cc3abbcafcbb77ed49768e37dcfe7ba7560928325860f4a0b9a1db3',
                        'b59af78493b056a8ece7911584d7dc91cb55af3e17309aea81c3bb4b000631ef')
            self.assertEqual(a02.verify_capture_revision(*historic, source_root=root), 'reviewed-v4')
            self.assertIs(a02.disk_decoder(root, root, {}, 'reviewed-v4'), reserved.inspect)
            with self.assertRaises(ValueError):
                a02.verify_capture_revision(current[0], historic[1], source_root=root)
            with self.assertRaises(ValueError):
                a02.disk_decoder(root, root, {}, 'unreviewed')

    def test_a02_new_decoder_requires_exact_archived_and_trusted_dependency_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted, archive = root / 'trusted', root / 'archive'
            (trusted / 'tools').mkdir(parents=True)
            archive.mkdir()
            directory = Path(reflection.getfile(boot)).parent
            artifacts = {}
            for name in boot.TOOL_FILES:
                data = (directory / name).read_bytes()
                (trusted / 'tools' / name).write_bytes(data)
                (archive / name).write_bytes(data)
                artifacts[name] = hashlib.sha256(data).hexdigest()
            self.assertIs(a02.disk_decoder(archive, trusted, artifacts, 'current'), boot.inspect)
            for name in boot.TOOL_FILES:
                with self.subTest(name=name):
                    data = (archive / name).read_bytes()
                    (archive / name).write_bytes(data + b'\n# changed archived dependency\n')
                    with self.assertRaises(ValueError):
                        a02.disk_decoder(archive, trusted, artifacts, 'current')
                    (archive / name).write_bytes(data)
                    missing = dict(artifacts)
                    del missing[name]
                    with self.assertRaises(ValueError):
                        a02.disk_decoder(archive, trusted, missing, 'current')
                    changed = dict(artifacts)
                    changed[name] = '0' * 64
                    with self.assertRaises(ValueError):
                        a02.disk_decoder(archive, trusted, changed, 'current')

    def test_caller_source_cannot_define_a_new_current_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'tools').mkdir()
            names = ('run_v13_a02.py', 'verify_v13_a02.py')
            data = (b'caller-selected runner', b'caller-selected verifier')
            for name, value in zip(names, data):
                (root / 'tools' / name).write_bytes(value)
            forged = tuple(hashlib.sha256(value).hexdigest() for value in data)
            with self.assertRaisesRegex(ValueError, 'unreviewed runner/verifier revision'):
                a02.verify_capture_revision(*forged, source_root=root)
            local = Path(reflection.getfile(a02)).parent
            current = tuple(hashlib.sha256((local / name).read_bytes()).hexdigest() for name in names)
            with self.assertRaisesRegex(ValueError, 'explicit source has a different current'):
                a02.verify_capture_revision(*current, source_root=root)

    def test_archive_and_caller_source_agreement_cannot_replace_local_decoder_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted, archive = root / 'trusted', root / 'archive'
            (trusted / 'tools').mkdir(parents=True)
            archive.mkdir()
            local = Path(reflection.getfile(boot)).parent
            for name in boot.TOOL_FILES:
                (trusted / 'tools' / name).write_bytes((local / name).read_bytes())
                (archive / name).write_bytes((local / name).read_bytes())
            for name in boot.TOOL_FILES:
                with self.subTest(name=name):
                    original = (local / name).read_bytes()
                    changed = original + b'\n# caller and archive agree on unreviewed code\n'
                    (trusted / 'tools' / name).write_bytes(changed)
                    (archive / name).write_bytes(changed)
                    artifacts = {item: hashlib.sha256((archive / item).read_bytes()).hexdigest()
                                 for item in boot.TOOL_FILES}
                    with self.assertRaisesRegex(ValueError, 'unreviewed boot disk decoder revision'):
                        a02.disk_decoder(archive, trusted, artifacts, 'current')
                    (trusted / 'tools' / name).write_bytes(original)
                    (archive / name).write_bytes(original)


if __name__ == '__main__':
    unittest.main()
