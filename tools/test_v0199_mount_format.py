"""Host-only format/extent regressions. No native persistence proof."""
import tempfile
import unittest
from pathlib import Path
import verify_v0199_epoch_disk as fmt


class MountFormat(unittest.TestCase):
    def test_new_image_and_exact_one_byte_padding(self):
        with tempfile.TemporaryDirectory() as directory:
            disk = Path(directory) / "new.img"
            fmt.create_disk(disk)
            self.assertEqual(disk.stat().st_size, fmt.CAPACITY)
            with disk.open("rb") as f:
                self.assertEqual(f.read(2 * fmt.BLOCK), fmt.superblock() * 2)
                f.seek(fmt.BLOCK * (fmt.HOME + 1))
                self.assertEqual(f.read(fmt.BLOCK),
                                 fmt.MARKER + bytes(fmt.BLOCK - len(fmt.MARKER)))
                for block, data in fmt.fixed_metadata().items():
                    self.assertEqual(len(data) % fmt.BLOCK, 0)
                    f.seek(block * fmt.BLOCK)
                    self.assertEqual(f.read(len(data)), data)
                f.seek(2 * fmt.BLOCK)
                self.assertEqual(f.read(4096), bytes(4096))
            with self.assertRaises(FileExistsError):
                fmt.create_disk(disk)

    def test_independent_expected_log_extents(self):
        for epoch in (1, 2):
            # Reference bytes only: do not write simulated guest evidence.
            self.assertEqual(len(fmt.transaction(2 * epoch - 1)), 6 * fmt.BLOCK)
            self.assertEqual(len(fmt.transaction(2 * epoch)), 4 * fmt.BLOCK)
            self.assertEqual(len(fmt.state(2 * epoch)), fmt.BLOCK)
            self.assertEqual(len(fmt.boot_store(epoch)), fmt.BLOCK)


if __name__ == "__main__":
    unittest.main()
