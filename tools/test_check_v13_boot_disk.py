"""Synthetic sparse raw-volume checks; never native or training evidence."""
from pathlib import Path
import struct
import tempfile
import unittest

from check_v13_disk import BLOCK, COUNT, crc32c, inspect as reserved_only
from check_v13_filesystem import inspect as ordinary_filesystem
from check_v13_boot_disk import inspect


def checksum(block, offset):
    block[offset:offset + 4] = bytes(4)
    struct.pack_into('<I', block, offset, crc32c(block))
    return block


def inode(kind=0, *, generation=1, size=0, sequence=0, parent=0,
          parent_generation=1, extents=()):
    result = bytearray(256)
    struct.pack_into('<IH', result, 0, 0x4359494e, kind)
    struct.pack_into('<Q', result, 8, generation)
    if kind:
        struct.pack_into('<QQH', result, 16, size, sequence, len(extents))
        struct.pack_into('<IQ', result, 36, parent, parent_generation)
        for index, extent in enumerate(extents):
            struct.pack_into('<III', result, 48 + index * 12, *extent)
    return checksum(result, 252)


def entry(identity=None, name='', generation=0):
    result = bytearray(128)
    if identity is None:
        struct.pack_into('<I', result, 0, 0xffffffff)
    else:
        encoded = name.encode()
        struct.pack_into('<IH', result, 0, identity, len(encoded))
        struct.pack_into('<Q', result, 8, generation)
        result[16:16 + len(encoded)] = encoded
    return checksum(result, 124)


class Volume:
    def __init__(self, directory, *, ordinary=True):
        self.path = Path(directory) / 'disk.raw'
        self.blocks = {}
        identity = bytes(range(1, 17))
        superblock = bytearray(BLOCK)
        struct.pack_into('<IHHII', superblock, 0, 0x43594653, 1, 80, BLOCK, COUNT)
        superblock[16:32] = identity
        struct.pack_into('<3Q', superblock, 32, 2, 8, 2)
        struct.pack_into('<5I', superblock, 56, 4098, 4102, 4118, 256, 0)
        self.blocks[0] = checksum(superblock, 76)
        self.blocks[1] = bytearray(self.blocks[0])
        table = bytearray().join(inode() for _ in range(256))
        body = b'CXID1' + identity + bytes([17]) * 32 + bytes([34]) * 32
        header = bytearray(struct.pack('<4sIII', b'CXV1', len(body), crc32c(body), 0))
        struct.pack_into('<I', header, 12, crc32c(header[:12]))
        record = header + body
        definitions = {
            0: inode(2, size=512 if ordinary else 256, sequence=3 if ordinary else 2,
                     extents=[(0, 4118, 1)]),
            1: inode(1, size=64, sequence=1, extents=[(0, 4119, 1)]),
            2: inode(1, size=len(record), sequence=1, extents=[(0, 4120, 1)]),
        }
        if ordinary:
            definitions[4] = inode(2, generation=2)
        for index, value in definitions.items():
            table[index * 256:(index + 1) * 256] = value
        for index in range(16):
            self.blocks[4102 + index] = table[index * BLOCK:(index + 1) * BLOCK]
        directory_data = bytearray(BLOCK)
        directory_data[:128] = entry(1, '.cyxia-boot', 1)
        directory_data[128:256] = entry(2, '.cyxia-cluster-a', 1)
        if ordinary:
            directory_data[256:384] = entry()
            directory_data[384:512] = entry(4, 'domain-probe', 2)
        self.blocks[4118] = directory_data
        boot = bytearray(BLOCK)
        boot[:8] = b'CYXBOOT1'
        boot[8:24] = identity
        struct.pack_into('<Q', boot, 24, 1)
        struct.pack_into('<I', boot, 32, crc32c(boot[:32]))
        self.blocks[4119] = boot
        self.blocks[4120] = bytearray(record) + bytearray(BLOCK - len(record))
        bitmap = bytearray(4 * BLOCK)
        for block in range(4121):
            bitmap[block // 8] |= 1 << (block % 8)
        for index in range(4):
            self.blocks[4098 + index] = bitmap[index * BLOCK:(index + 1) * BLOCK]
        with self.path.open('wb') as disk:
            disk.truncate(BLOCK * COUNT)
        self.flush()

    def flush(self):
        with self.path.open('r+b') as disk:
            for index, block in self.blocks.items():
                disk.seek(index * BLOCK)
                disk.write(block)

    def edit_inode(self, identity, edit):
        block, offset = 4102 + identity // 16, identity % 16 * 256
        value = bytearray(self.blocks[block][offset:offset + 256])
        edit(value)
        self.blocks[block][offset:offset + 256] = checksum(value, 252)

    def nested_reserved_basename(self, *, start=8216):
        self.edit_inode(4, lambda value: value.__setitem__(slice(None),
            inode(2, generation=2, size=128, sequence=1, extents=[(0, start, 1)])))
        self.edit_inode(5, lambda value: value.__setitem__(slice(None),
            inode(1, parent=4, parent_generation=2)))
        self.blocks[start] = entry(5, '.cyxia-cluster-b', 1) + bytearray(BLOCK - 128)
        bitmap_block = 4098 + start // (BLOCK * 8)
        self.blocks[bitmap_block][start % (BLOCK * 8) // 8] |= 1 << (start % 8)
        self.flush()


class BootDiskAdapter(unittest.TestCase):
    def test_actual_ordinary_shape_keeps_tombstone_and_reused_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            volume = Volume(directory)
            with self.assertRaisesRegex(ValueError, 'root size/sequence'):
                reserved_only(volume.path)
            raw = ordinary_filesystem(volume.path)
            self.assertEqual(raw['directories']['/']['size'], 512)
            self.assertEqual(raw['directories']['/']['durable_write_seq'], 3)
            self.assertEqual(raw['directories']['/domain-probe']['generation'], 2)
            decoded = inspect(volume.path)
            self.assertEqual(decoded['boot_epoch'], 1)
            self.assertEqual(decoded['cluster_files'], 1)
            self.assertEqual(decoded['cluster_file_sizes'], [101])
            self.assertEqual(len(decoded['cluster_records']), 1)

    def test_reserved_only_outputs_remain_byte_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            volume = Volume(directory, ordinary=False)
            self.assertEqual(inspect(volume.path), reserved_only(volume.path))

    def test_reserved_root_name_cannot_be_impersonated_by_ordinary_directory(self):
        for name in ('.cyxia-boot', '.cyxia-cluster-a', '.cyxia-cluster-b'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                volume = Volume(directory)
                volume.blocks[4118][384:512] = entry(4, name, 2)
                volume.flush()
                if name == '.cyxia-cluster-b':
                    ordinary_filesystem(volume.path)
                with self.assertRaises(ValueError):
                    inspect(volume.path)

    def test_nonroot_reserved_basename_is_not_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            volume = Volume(directory)
            volume.nested_reserved_basename()
            self.assertIn('/domain-probe/.cyxia-cluster-b', ordinary_filesystem(volume.path)['files'])
            self.assertEqual(inspect(volume.path)['boot_epoch'], 1)

    def test_legacy_root_keeps_exact_sequence_and_free_generation_guards(self):
        for field, value in (('sequence', 1), ('sequence', 3), ('free-generation', 2)):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                volume = Volume(directory, ordinary=False)
                if field == 'sequence':
                    volume.edit_inode(0, lambda data: struct.pack_into('<Q', data, 24, value))
                else:
                    volume.edit_inode(4, lambda data: struct.pack_into('<Q', data, 8, value))
                volume.flush()
                ordinary_filesystem(volume.path)
                with self.assertRaises(ValueError):
                    reserved_only(volume.path)
                with self.assertRaises(ValueError):
                    inspect(volume.path)

    def test_expanded_root_sequence_cannot_undercount_live_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            volume = Volume(directory)
            volume.edit_inode(0, lambda data: struct.pack_into('<Q', data, 24, 2))
            volume.flush()
            ordinary_filesystem(volume.path)
            with self.assertRaisesRegex(ValueError, 'sequence below live entries'):
                inspect(volume.path)

    def test_rehashed_reserved_generation_sequence_and_identity_are_rejected(self):
        def generation(volume):
            volume.edit_inode(2, lambda value: struct.pack_into('<Q', value, 8, 2))
            volume.blocks[4118][128:256] = entry(2, '.cyxia-cluster-a', 2)
        def sequence(volume):
            volume.edit_inode(2, lambda value: struct.pack_into('<Q', value, 24, 2))
        def boot_epoch(volume):
            struct.pack_into('<Q', volume.blocks[4119], 24, 2)
            struct.pack_into('<I', volume.blocks[4119], 32, crc32c(volume.blocks[4119][:32]))
        def boot_uuid(volume):
            volume.blocks[4119][8] ^= 1
            struct.pack_into('<I', volume.blocks[4119], 32, crc32c(volume.blocks[4119][:32]))
        for mutation in (generation, sequence, boot_epoch, boot_uuid):
            with self.subTest(mutation=mutation.__name__), tempfile.TemporaryDirectory() as directory:
                volume = Volume(directory)
                mutation(volume)
                volume.flush()
                with self.assertRaises(ValueError):
                    inspect(volume.path)

    def test_reserved_padding_and_cluster_crc_remain_strict(self):
        for block, offset in ((4118, 800), (4120, 200), (6168, 0),
                              (4120, 12), (4120, 40), (4119, 32)):
            with self.subTest(block=block, offset=offset), tempfile.TemporaryDirectory() as directory:
                volume = Volume(directory)
                volume.blocks.setdefault(block, bytearray(BLOCK))[offset] ^= 1
                volume.flush()
                with self.assertRaises(ValueError):
                    inspect(volume.path)

    def test_ordinary_reserved_ownership_bitmap_and_crc_are_not_ignored(self):
        for mutation in ('reserved-extent', 'bitmap', 'inode-crc'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                volume = Volume(directory)
                if mutation == 'reserved-extent':
                    volume.nested_reserved_basename(start=4121)
                elif mutation == 'bitmap':
                    volume.blocks[4099][0] ^= 1
                else:
                    volume.blocks[4102][4 * 256 + 252] ^= 1
                volume.flush()
                with self.assertRaises(ValueError):
                    inspect(volume.path)


if __name__ == '__main__':
    unittest.main()
