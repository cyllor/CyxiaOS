"""Check the recovery carrier signing message against raw v1 metadata."""

from hashlib import sha256
import struct
from tempfile import TemporaryFile
import unittest

if __package__:
    from .package_v020_recovery_store import prepare
    from .v020_g1_genesis import ACL, BUILTIN_CONFIG, CAPACITY, ROOT, _inode, _seal, _superblock
    from .v020_snapshot_envelopes import BLOCK_BYTES, INODE_BYTES, INODE_START
else:
    from package_v020_recovery_store import prepare
    from v020_g1_genesis import ACL, BUILTIN_CONFIG, CAPACITY, ROOT, _inode, _seal, _superblock
    from v020_snapshot_envelopes import BLOCK_BYTES, INODE_BYTES, INODE_START


class RecoveryStorePackageTest(unittest.TestCase):
    def test_locator_binds_denied_file_metadata_and_complete_config(self):
        config = BUILTIN_CONFIG.read_bytes()
        inode_id, home = 1, ROOT + 1
        inode = _inode(1, 2 * BLOCK_BYTES, home, 2)
        acl = _seal(struct.pack("<II3QIIQ", inode_id, 1, 1, 1, 1, 0, 0, 1), 64, 60)
        acl_offset = ACL * BLOCK_BYTES + inode_id * 64
        with TemporaryFile() as disk:
            disk.truncate(CAPACITY)
            disk.write(_superblock() * 2)
            disk.seek(INODE_START * BLOCK_BYTES + inode_id * INODE_BYTES)
            disk.write(inode)
            disk.seek(acl_offset)
            disk.write(acl)
            wire, message = prepare(config, disk, inode_id)
            self.assertEqual(wire, struct.pack("<8s16s32sIIQ32s", b"CYXRPF01",
                                               config[16:32], sha256(config).digest(), inode_id,
                                               home, 1, sha256(inode + acl).digest()))
            self.assertEqual(message, b"CYX/RECOVERY-STORE/v1" + wire)

            wrong_uuid = config[:16] + bytes(16) + config[32:]
            with self.assertRaisesRegex(ValueError, "identity differ"):
                prepare(wrong_uuid, disk, inode_id)

            writable_acl = bytearray(acl[:60])
            struct.pack_into("<I", writable_acl, 32, 1 << 9)
            disk.seek(acl_offset)
            disk.write(_seal(writable_acl, 64, 60))
            with self.assertRaisesRegex(ValueError, "without EL0 rights"):
                prepare(config, disk, inode_id)


if __name__ == "__main__":
    unittest.main()
