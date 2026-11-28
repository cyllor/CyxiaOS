"""Verify the independent 512 MiB G1 image and the zero-payload boundary."""

from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest

if __package__:
    from . import v020_g1_genesis as genesis
    from .v020_snapshot_envelopes import crc32c_zeroed, verify_envelopes
else:
    import v020_g1_genesis as genesis
    from v020_snapshot_envelopes import crc32c_zeroed, verify_envelopes


class GenesisTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "genesis.raw"

    def test_sparse_image_matches_pinned_vector_and_independent_structure_reader(self):
        produced = genesis.generate_image(self.path)
        self.assertEqual(genesis.verify_image(self.path), produced)
        self.assertFalse(produced["golden_vector_pending"])
        self.assertEqual(produced["nonzero_blocks"], 31)
        stat = self.path.stat()
        self.assertEqual(stat.st_size, 512 * 1024 * 1024)
        if hasattr(stat, "st_blocks"):
            self.assertLess(stat.st_blocks * 512, stat.st_size)
        envelope = verify_envelopes(self.path, unified=True, snapshot_read=True)
        self.assertEqual(envelope["superblock_generation"], 1)
        self.assertEqual(envelope["system_inodes"], 8)
        self.assertEqual((envelope["system_blocks"], envelope["data_blocks"]), (151, 152))

    def test_zero_fill_must_cover_redo_object_tails_and_free_data(self):
        genesis.generate_image(self.path)
        for block in (4097, 4267, 131071):
            with self.subTest(block=block):
                with self.path.open("r+b") as image:
                    image.seek(block * genesis.BLOCK_BYTES)
                    image.write(b"\x01")
                with self.assertRaisesRegex(ValueError, f"differs at block {block}"):
                    genesis.verify_image(self.path)
                with self.path.open("r+b") as image:
                    image.seek(block * genesis.BLOCK_BYTES)
                    image.write(b"\x00")

    def test_crc_cannot_admit_an_unfrozen_payload(self):
        genesis.generate_image(self.path)
        with self.path.open("r+b") as image:
            offset = 4131 * genesis.BLOCK_BYTES
            image.seek(offset)
            catalog = bytearray(image.read(genesis.BLOCK_BYTES))
            catalog[40] = 1
            struct.pack_into("<I", catalog, 32, crc32c_zeroed(catalog, 32))
            image.seek(offset)
            image.write(catalog)
        with self.assertRaisesRegex(ValueError, "differs at block 4131"):
            genesis.verify_image(self.path)
        with self.assertRaisesRegex(ValueError, "nonzero candidate payload"):
            verify_envelopes(self.path, unified=True)

    def test_existing_destination_is_preserved_and_short_image_rejected(self):
        self.path.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            genesis.generate_image(self.path)
        self.assertEqual(self.path.read_bytes(), b"existing")
        with self.assertRaisesRegex(ValueError, "exactly 512 MiB"):
            genesis.verify_image(self.path)


if __name__ == "__main__":
    unittest.main()
