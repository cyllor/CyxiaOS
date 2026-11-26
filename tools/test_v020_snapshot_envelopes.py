"""D1.5 scratch envelope candidates checked against independent wire bytes."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

if __package__:
    from . import v020_snapshot_envelopes as codec
else:
    import v020_snapshot_envelopes as codec


BLOCK_BYTES = 4096
STAGING_UUID = b"CYX-W11-STAGING!"

# D1.5 header bytes, CRC32C, and full-block SHA-256 from Go's hash/crc32
# (Castagnoli) and crypto/sha256. Each block is zero beyond its header.
VECTORS = {
    "catalog": (
        4131, 1, 224, 0x28A3F5EA,
        "43415943010028004359582d5731312d53544147494e4721"
        "0100000000000000eaf5a32800000000",
        "90c1293b5876b4689c25da6e2af3c69ac3bb54ef679451e2c98cc74555e2a94d",
    ),
    "slot": (
        4132, 120, 226, 0xCCAEB7CA,
        "534c5943010028004359582d5731312d53544147494e4721"
        "0100000000000000cab7aecc00000000",
        "c403669b48dbb0fb880eb3588e046364e39aec4e45cfce0ac5934e02b9e36a4d",
    ),
    "request": (
        4252, 16, 228, 0x249964EA,
        "52515943010028004359582d5731312d53544147494e4721"
        "0100000000000000ea64992400000000",
        "414e2f3f07975f86f7e9423fb77bcd430cf01a5b7e62cae012645d49250184f4",
    ),
    "protection": (
        4268, 1, 227, 0xE0A70CA0,
        "50445943010028004359582d5731312d53544147494e4721"
        "0100000000000000a00ca7e000000000",
        "82ab76b7941bc52bc890c85adcb5009c995f8691180f2ebfc84eb5ab84e32dc8",
    ),
}
GENESIS_SUPERBLOCK = bytes.fromhex(
    "534659430100500000100000000002004359582d5731312d53544147494e4721"
    "010000000000000000000000000000000100000000000000"
    "02100000061000001610000000010000000000003637ec3c"
).ljust(BLOCK_BYTES, b"\0")
CHECKPOINT_SUPERBLOCK = bytes.fromhex(
    "534659430100500000100000000002004359582d5731312d53544147494e4721"
    "020000000000000004000000000000000200000000000000"
    "0210000006100000161000000001000000000000f7873d07"
).ljust(BLOCK_BYTES, b"\0")
FREE_INODE = b"NIYC" + bytes(248) + bytes.fromhex("e6e098ba")
STALE_FREE_INODE = bytes.fromhex("4e495943000000000100000000000000") + bytes(236) + bytes.fromhex("60cb7803")
EMPTY_ROOT_SLOT = b"\xff" * 4 + bytes(120) + b"\xff" * 4


def block_for(kind):
    return bytes.fromhex(VECTORS[kind][4]).ljust(BLOCK_BYTES, b"\0")


def changed_catalog(offset, value, crc32c):
    block = bytearray(block_for("catalog"))
    block[offset] = value
    block[32:36] = crc32c.to_bytes(4, "little")
    return bytes(block)


def seal_fixture(prefix, record_bytes):
    # Use the normal Castagnoli polynomial on reflected input bytes.
    raw = prefix.ljust(record_bytes, b"\0")
    crc = 0xFFFFFFFF
    for byte in raw:
        crc ^= int(f"{byte:08b}"[::-1], 2) << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1EDC6F41 if crc >> 31 else 0)) & 0xFFFFFFFF
    crc = int(f"{crc:032b}"[::-1], 2) ^ 0xFFFFFFFF
    return raw[:-4] + crc.to_bytes(4, "little")


def live_inode(kind, size, physical, blocks):
    fields = struct.pack("<4sHHQQQHHIQIII", b"NIYC", kind, 0, 1, size, 0, 1, 0, 0, 1, 0, physical, blocks)
    return seal_fixture(fields, 256)


def acl_entry(inode, live, owner, system):
    fields = struct.pack("<IIQQQIIQ", inode, live, live, live, live, owner, system, live)
    return seal_fixture(fields, 64)


class SnapshotEnvelopeTests(unittest.TestCase):
    def scratch_image(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "scratch.raw"
        with path.open("xb") as disk:
            disk.truncate(512 * 1024 * 1024)
            disk.write(GENESIS_SUPERBLOCK * 2)
            for kind, (head, _, inode, _, _, _) in VECTORS.items():
                disk.seek(4102 * BLOCK_BYTES + inode * 256)
                disk.write(FREE_INODE)
                disk.seek(head * BLOCK_BYTES)
                disk.write(block_for(kind))
        return path

    def unified_scratch_image(self):
        path = self.scratch_image()
        hidden = {225: (4118, 1), 229: (4119, 7), 230: (4126, 4), 231: (4130, 1)}
        hidden.update({inode: (head, count) for head, count, inode, *_ in VECTORS.values()})
        inodes = [FREE_INODE] * 256
        inodes[0] = live_inode(2, 128, 4269, 1)
        for inode, (head, blocks) in hidden.items():
            inodes[inode] = live_inode(1, blocks * BLOCK_BYTES, head, blocks)
        acls = b"".join(
            acl_entry(inode, int(inode == 0 or inode in hidden),
                      0x4000 if inode == 0 else 0, 0x2300 if inode in hidden else 0)
            for inode in range(256)
        )
        self.write_at(path, 4098 * BLOCK_BYTES, b"\xff" * 533 + b"\x3f")
        self.write_at(path, 4102 * BLOCK_BYTES, b"".join(inodes))
        self.write_at(path, 4126 * BLOCK_BYTES, acls)
        self.write_at(path, 4269 * BLOCK_BYTES, EMPTY_ROOT_SLOT * 32)
        return path

    def write_at(self, path, address, data):
        with path.open("r+b") as disk:
            disk.seek(address)
            disk.write(data)

    def test_unified_staged_file_binds_allocation_acl_entry_and_data(self):
        path = self.unified_scratch_image()
        root_offset = 4269 * BLOCK_BYTES
        data_offset = 4270 * BLOCK_BYTES
        acl_offset = 4126 * BLOCK_BYTES
        payload = b"CyxiaOS V0.20 signed scratch\n"
        entry = seal_fixture(struct.pack("<IHHQ", 1, 10, 0, 1) + b"readme.txt", 128)
        self.write_at(path, 4098 * BLOCK_BYTES + 533, b"\x7f")
        self.write_at(path, 4102 * BLOCK_BYTES + 256, live_inode(1, 29, 4270, 1))
        self.write_at(path, acl_offset, acl_entry(0, 1, 0x5000, 0) + acl_entry(1, 1, 0x100, 0))
        self.write_at(path, root_offset, entry)
        self.write_at(path, data_offset, payload)
        evidence = codec.verify_envelopes(path, unified=True, file_read=True)
        self.assertEqual((evidence["system_blocks"], evidence["data_blocks"]), (151, 153))
        self.assertEqual(evidence["file_owner_rights"], 0x100)
        self.assertEqual(evidence["file_read_bytes"], 29)
        self.assertEqual(evidence["file_read_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(evidence["file_read_dirent_sha256"], hashlib.sha256(entry).hexdigest())
        with self.assertRaises(codec.EnvelopeVerificationError):
            codec.verify_envelopes(path, unified=True)
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "v1 ACL 1"):
            codec.verify_envelopes(path, unified=True, file_volatile_write=True)
        self.write_at(path, data_offset + len(payload), b"\x01")
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "payload or zero padding"):
            codec.verify_envelopes(path, unified=True, file_read=True)
        self.write_at(path, data_offset + len(payload), b"\0")
        self.write_at(path, acl_offset + 64, acl_entry(1, 1, 0x300, 0))
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "v1 ACL 1"):
            codec.verify_envelopes(path, unified=True, file_read=True)
        writable = codec.verify_envelopes(path, unified=True, file_volatile_write=True)
        self.assertEqual(writable, {**evidence, "file_owner_rights": 0x300})
        self.write_at(path, acl_offset + 64, acl_entry(1, 1, 0x2300, 0))
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "v1 ACL 1"):
            codec.verify_envelopes(path, unified=True, file_volatile_write=True)

    def test_encode_and_decode_match_four_fixed_wire_vectors(self):
        for kind, (_, _, _, crc, _, _) in VECTORS.items():
            with self.subTest(kind=kind):
                block = block_for(kind)
                self.assertEqual(codec.encode_envelope(kind, STAGING_UUID), block)
                decoded = codec.decode_envelope(kind, block)
                self.assertEqual((decoded.kind, decoded.fs_uuid, decoded.generation, decoded.crc32c),
                                 (kind, STAGING_UUID, 1, crc))

    def test_crc32c_ignores_the_stored_acl_checksum(self):
        raw = bytearray(acl_entry(224, 1, 0, 0x2300))
        self.assertEqual(codec.crc32c_zeroed(raw, 60), 0x85492987)

    def test_verify_reports_envelopes_from_raw_image(self):
        path = self.scratch_image()
        proof = codec.verify_envelopes(path)
        self.assertTrue(proof["golden_vector_pending"])
        self.assertEqual(proof["fs_uuid"], STAGING_UUID.hex())
        self.assertEqual(proof["superblock_generation"], 1)
        self.assertEqual(proof["snapshot_blocks"], 138)
        self.assertEqual(set(proof["objects"]), set(VECTORS))
        for kind, (head, count, inode, crc, _, digest) in VECTORS.items():
            with self.subTest(kind=kind):
                self.assertEqual(proof["objects"][kind], {
                    "first_block": head, "blocks": count, "inode": inode, "generation": 1,
                    "crc32c": crc, "envelope_sha256": digest, "zero_tail_blocks": count - 1,
                })

    def test_verify_selects_next_superblock_after_alternating_checkpoint(self):
        path = self.scratch_image()
        self.write_at(path, BLOCK_BYTES, CHECKPOINT_SUPERBLOCK)
        proof = codec.verify_envelopes(path)
        self.assertEqual(proof["superblock_generation"], 2)
        self.assertTrue(all(envelope["generation"] == 1 for envelope in proof["objects"].values()))

    def test_verify_rejects_v2_data_start_even_with_a_valid_superblock_crc(self):
        path = self.scratch_image()
        bad_geometry = bytearray(GENESIS_SUPERBLOCK)
        bad_geometry[64:68] = bytes.fromhex("90100000")
        bad_geometry[76:80] = bytes.fromhex("feca9f39")
        self.write_at(path, BLOCK_BYTES, bad_geometry)
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "superblock 1.*geometry"):
            codec.verify_envelopes(path)

    def test_verify_rejects_superblock_generation_jump(self):
        path = self.scratch_image()
        bad_checkpoint = bytearray(CHECKPOINT_SUPERBLOCK)
        bad_checkpoint[32] = 3
        bad_checkpoint[76:80] = bytes.fromhex("f2f92f65")
        self.write_at(path, BLOCK_BYTES, bad_checkpoint)
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "checkpoint pair"):
            codec.verify_envelopes(path)

    def test_decode_rejects_wrong_kind_or_header_version_or_size(self):
        invalid = {
            "kind": block_for("slot"),
            "version": changed_catalog(4, 2, 0x945168A6),
            "header size": changed_catalog(6, 39, 0xBA40D4F1),
        }
        for reason, block in invalid.items():
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(codec.EnvelopeVerificationError, "header"):
                    codec.decode_envelope("catalog", block)

    def test_decode_rejects_short_block_and_zero_generation(self):
        invalid = (block_for("catalog")[:-1], changed_catalog(24, 0, 0xE7A5858F))
        for block in invalid:
            with self.subTest(length=len(block)):
                with self.assertRaises(codec.EnvelopeVerificationError):
                    codec.decode_envelope("catalog", block)

    def test_verify_rejects_bad_crc(self):
        path = self.scratch_image()
        self.write_at(path, 4131 * BLOCK_BYTES + 32, b"\xeb")
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "catalog.*CRC32C"):
            codec.verify_envelopes(path)

    def test_verify_rejects_wrong_uuid_or_generation_with_valid_crc(self):
        path = self.scratch_image()
        for field, raw in (
            ("UUID", changed_catalog(23, ord("?"), 0x2695DD78)),
            ("generation", changed_catalog(24, 2, 0x7C4513B4)),
        ):
            with self.subTest(field=field):
                self.write_at(path, 4131 * BLOCK_BYTES, raw)
                with self.assertRaisesRegex(codec.EnvelopeVerificationError, f"catalog.*{field}"):
                    codec.verify_envelopes(path)

    def test_verify_rejects_nonzero_reserved_or_payload_bytes_with_valid_crc(self):
        path = self.scratch_image()
        for field, raw in (
            ("reserved", changed_catalog(36, 1, 0x34BCFC95)),
            ("payload", changed_catalog(4095, 1, 0xDAC876E9)),
        ):
            with self.subTest(field=field):
                self.write_at(path, 4131 * BLOCK_BYTES, raw)
                with self.assertRaisesRegex(codec.EnvelopeVerificationError, f"catalog.*{field}"):
                    codec.verify_envelopes(path)

    def test_verify_rejects_nonzero_blocks_at_both_range_ends(self):
        path = self.scratch_image()
        for kind, tail in (("slot", 4251), ("request", 4267)):
            with self.subTest(kind=kind):
                address = (tail + 1) * BLOCK_BYTES - 1
                self.write_at(path, address, b"\x01")
                with self.assertRaisesRegex(codec.EnvelopeVerificationError, f"{kind}.*tail.*{tail}"):
                    codec.verify_envelopes(path)
                self.write_at(path, address, b"\0")

    def test_snapshot_read_hashes_the_entire_slot_extent(self):
        path = self.unified_scratch_image()
        slot = codec.verify_envelopes(path, unified=True, snapshot_read=True)["objects"]["slot"]
        expected = hashlib.sha256(block_for("slot") + bytes(119 * BLOCK_BYTES)).hexdigest()
        self.assertEqual(slot["extent_sha256"], expected)
        self.assertNotEqual(slot["extent_sha256"], slot["envelope_sha256"])
        self.assertNotIn("extent_sha256", codec.verify_envelopes(path, unified=True)["objects"]["slot"])
        self.write_at(path, 4252 * BLOCK_BYTES - 1, b"\x01")
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "slot tail block 4251 is nonzero"):
            codec.verify_envelopes(path, unified=True, snapshot_read=True)

    def test_verify_rejects_snapshot_allocation_in_v1_bitmap(self):
        path = self.scratch_image()
        self.write_at(path, 4098 * BLOCK_BYTES + 4267 // 8, b"\x08")
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "block 4267.*bitmap"):
            codec.verify_envelopes(path)

    def test_verify_rejects_snapshot_inode_with_stale_generation(self):
        path = self.scratch_image()
        self.write_at(path, 4102 * BLOCK_BYTES + 227 * 256, STALE_FREE_INODE)
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "inode 227.*free"):
            codec.verify_envelopes(path)

    def test_verify_unified_reports_all_hidden_allocations(self):
        path = self.unified_scratch_image()
        for generation in (1, 2):
            with self.subTest(generation=generation):
                proof = codec.verify_envelopes(path, unified=True)
                self.assertTrue(proof["golden_vector_pending"])
                self.assertEqual(proof["superblock_generation"], generation)
                self.assertEqual(proof["system_inodes"], 8)
                self.assertEqual(proof["system_blocks"], 151)
                self.assertEqual(proof["data_blocks"], 152)
                self.assertEqual(proof["snapshot_blocks"], 138)
                self.assertEqual(set(proof["objects"]), set(VECTORS))
                if generation == 1:
                    self.write_at(path, BLOCK_BYTES, CHECKPOINT_SUPERBLOCK)
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "inode 224.*free"):
            codec.verify_envelopes(path)

    def test_verify_unified_rejects_missing_or_unexplained_bitmap_allocations(self):
        path = self.unified_scratch_image()
        for block, changed, original in (
            (0, b"\xfe", b"\xff"),
            (4126, b"\xbf", b"\xff"),
            (4251, b"\xf7", b"\xff"),
            (4269, b"\x1f", b"\x3f"),
            (4270, b"\x7f", b"\x3f"),
            (131071, b"\x80", b"\0"),
        ):
            with self.subTest(block=block):
                offset = 4098 * BLOCK_BYTES + block // 8
                self.write_at(path, offset, changed)
                with self.assertRaisesRegex(codec.EnvelopeVerificationError, f"bitmap.*block {block}"):
                    codec.verify_envelopes(path, unified=True)
                self.write_at(path, offset, original)

    def test_verify_unified_rejects_hidden_inode_with_wrong_extent_even_with_valid_crc(self):
        path = self.unified_scratch_image()
        # Go's Castagnoli CRC32C for the catalog inode moved to the boot-epoch block.
        raw = live_inode(1, BLOCK_BYTES, 4118, 1)
        self.assertEqual(raw[252:], bytes.fromhex("79508a65"))
        self.write_at(path, 4102 * BLOCK_BYTES + 224 * 256, raw)
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "inode 224.*extent"):
            codec.verify_envelopes(path, unified=True)

    def test_verify_unified_checks_inode_crc(self):
        path = self.unified_scratch_image()
        self.write_at(path, 4102 * BLOCK_BYTES + 224 * 256 + 252, b"\x1c")
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "inode 224.*CRC32C"):
            codec.verify_envelopes(path, unified=True)

    def test_verify_unified_checks_acl_crc(self):
        path = self.unified_scratch_image()
        self.write_at(path, 4126 * BLOCK_BYTES + 224 * 64 + 60, b"\x86")
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "ACL 224.*CRC32C"):
            codec.verify_envelopes(path, unified=True)

    def test_verify_unified_rejects_hidden_acl_owner_rights_even_with_valid_crc(self):
        path = self.unified_scratch_image()
        raw = acl_entry(224, 1, 0x100, 0x2300)
        self.assertEqual(raw[60:], bytes.fromhex("0a49eefd"))
        self.write_at(path, 4126 * BLOCK_BYTES + 224 * 64, raw)
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "ACL 224.*rights"):
            codec.verify_envelopes(path, unified=True)

    def test_verify_unified_rejects_a_root_reference_to_a_hidden_object(self):
        path = self.unified_scratch_image()
        raw = seal_fixture(struct.pack("<IHHQ", 224, 7, 0, 1) + b"catalog", 128)
        self.assertEqual(raw[124:], bytes.fromhex("2055294e"))
        for slot in (0, 31):
            with self.subTest(slot=slot):
                offset = 4269 * BLOCK_BYTES + slot * 128
                self.write_at(path, offset, raw)
                with self.assertRaisesRegex(codec.EnvelopeVerificationError, f"root.*slot {slot}.*empty"):
                    codec.verify_envelopes(path, unified=True)
                self.write_at(path, offset, EMPTY_ROOT_SLOT)

    def test_verify_unified_rejects_a_live_business_inode_without_a_root_reference(self):
        path = self.unified_scratch_image()
        fields = struct.pack("<4sHHQQQHHIQ", b"NIYC", 1, 0, 1, 0, 0, 0, 0, 0, 1)
        self.write_at(path, 4102 * BLOCK_BYTES + 256, seal_fixture(fields, 256))
        with self.assertRaisesRegex(codec.EnvelopeVerificationError, "inode 1.*free"):
            codec.verify_envelopes(path, unified=True)

    def test_verify_unified_rejects_reserved_inodes_with_retained_generation(self):
        path = self.unified_scratch_image()
        for inode in (232, 255):
            with self.subTest(inode=inode):
                offset = 4102 * BLOCK_BYTES + inode * 256
                self.write_at(path, offset, STALE_FREE_INODE)
                with self.assertRaisesRegex(codec.EnvelopeVerificationError, f"inode {inode}.*free"):
                    codec.verify_envelopes(path, unified=True)
                self.write_at(path, offset, FREE_INODE)


if __name__ == "__main__":
    unittest.main()
