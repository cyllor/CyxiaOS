"""Real host handoff/allocation seam; synthetic disks never native evidence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import boot_reboot_contract as custody
from check_prototype_evidence import sha256


class SparseDiskHandoff(unittest.TestCase):
    def parent(self, root, *, zero_tail):
        previous = root / 'previous'
        previous.mkdir()
        disk = previous / 'disk.raw'
        size = custody.DISK_BYTES
        pieces = [(0, b'HEAD-at-zero'),
                  (size // 2 + 1024 * 1024 - 3, b'MIDDLE-crosses-chunk-boundary'),
                  (size - 2 * 1024 * 1024 + 17, b'TAIL-before-zero-suffix')
                  if zero_tail else (size - 4, b'EOF!')]
        with disk.open('xb') as stream:
            stream.truncate(size)
            for offset, data in pieces:
                stream.seek(offset)
                stream.write(data)
        (previous / 'process-exit.json').write_text(json.dumps(dict(
            schema=1, started_ns=10, exited_ns=20, returncode=0, forced=False)))
        (previous / 'input.json').write_text(json.dumps({'nonce': '01' * 16}))
        files = {path.name: dict(bytes=path.stat().st_size, sha256=sha256(path))
                 for path in previous.iterdir()}
        (previous / 'summary.json').write_text(json.dumps({'files': files}))
        return previous, pieces

    def test_sparse_nonzero_regions_and_zero_eof_preserve_bytes_without_dense_allocation(self):
        for zero_tail in (False, True):
            with self.subTest(zero_tail=zero_tail), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                previous, pieces = self.parent(root, zero_tail=zero_tail)
                source = previous / 'disk.raw'
                output = root / 'next'
                output.mkdir()
                frozen = {p.name: sha256(p) for p in previous.iterdir()}
                size = source.stat().st_size
                # Refuse a vacuous sparse fixture on filesystems that do not
                # expose allocation. This environment's real st_blocks is used.
                self.assertTrue(hasattr(source.stat(), 'st_blocks'))
                source_allocated = source.stat().st_blocks * 512
                self.assertLess(source_allocated, size // 8)
                sync = os.fsync
                synchronizations = []
                def synchronized(fd):
                    self.assertEqual(os.fstat(fd).st_size, size,
                                     'trailing hole must reach exact EOF before setup fsync')
                    synchronizations.append(True)
                    return sync(fd)
                with patch.object(custody.os, 'fsync', side_effect=synchronized), \
                     patch.object(custody.subprocess, 'run') as formatter:
                    origin = custody.prepare_disk(output, Path('/unused'), 'unused', previous)
                    formatter.assert_not_called()
                target = output / 'disk.raw'
                allocated = target.stat().st_blocks * 512
                print(json.dumps(dict(zero_tail=zero_tail, logical_bytes=size,
                    parent_allocated_bytes=source_allocated, output_allocated_bytes=allocated,
                    expected_sha256=frozen['disk.raw'], actual_sha256=sha256(target))), flush=True)
                self.assertEqual(target.stat().st_size, size)
                self.assertEqual(sha256(target), frozen['disk.raw'])
                self.assertEqual({p.name: sha256(p) for p in previous.iterdir()}, frozen,
                                 'stopped predecessor disk or custody metadata changed')
                self.assertEqual(origin, custody.handoff_origin(previous))
                self.assertEqual(synchronizations, [True])
                self.assertEqual((output / 'format.log').read_bytes(), custody.HANDOFF_LOG)
                with target.open('rb') as stream:
                    for offset, data in pieces:
                        stream.seek(offset)
                        self.assertEqual(stream.read(len(data)), data)
                    stream.seek(size - 64)
                    self.assertEqual(stream.read(64), bytes(64) if zero_tail else bytes(60) + b'EOF!')
                    self.assertEqual(stream.read(1), b'', 'copy gained an extra EOF byte')
                self.assertLess(allocated, size // 8,
                                'host handoff expanded a sparse predecessor into a dense disk')

    def test_existing_target_is_never_overwritten_or_formatted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous, _ = self.parent(root, zero_tail=True)
            output = root / 'next'
            output.mkdir()
            target = output / 'disk.raw'
            target.write_bytes(b'exclusive-target-sentinel')
            before = target.read_bytes()
            with patch.object(custody.subprocess, 'run') as formatter:
                with self.assertRaisesRegex(ValueError, 'overwrite'):
                    custody.prepare_disk(output, Path('/unused'), 'unused', previous)
                formatter.assert_not_called()
            self.assertEqual(target.read_bytes(), before)
            self.assertFalse((output / 'format.log').exists())

    def test_parent_mutation_at_sync_is_rejected_and_failed_copy_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous, _ = self.parent(root, zero_tail=True)
            output = root / 'next'
            output.mkdir()
            sync = os.fsync
            def altered_parent(fd):
                sync(fd)
                with (previous / 'disk.raw').open('r+b') as parent:
                    parent.seek(32)
                    parent.write(b'changed-during-stopped-copy')
            with patch.object(custody.os, 'fsync', side_effect=altered_parent), \
                 patch.object(custody.subprocess, 'run') as formatter:
                with self.assertRaisesRegex(ValueError, 'predecessor disk changed'):
                    custody.prepare_disk(output, Path('/unused'), 'unused', previous)
                self.assertTrue((output / 'disk.raw').exists())
                self.assertFalse((output / 'format.log').exists())
                with self.assertRaisesRegex(ValueError, 'overwrite'):
                    custody.prepare_disk(output, Path('/unused'), 'unused')
                formatter.assert_not_called()


if __name__ == '__main__':
    unittest.main()
