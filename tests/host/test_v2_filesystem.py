"""Independent disk fixtures exercise the v2 checker without the Rust encoder."""
from pathlib import Path
import hashlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from check_v2_filesystem import inspect, crc32c, BLOCK, FIRST_BUSINESS_BLOCK as BUSINESS

UUID = bytes([7]) * 16


def seal(data, offset):
    data[offset:offset + 4] = bytes(4)
    struct.pack_into('<I', data, offset, crc32c(data))
    return data


def node(identity, kind=0, size=0, parent=0, physical=0, sequence=0, generation=1):
    data = bytearray(256)
    struct.pack_into('<IH', data, 0, 0x4359494e, kind)
    struct.pack_into('<QQQH', data, 8, generation, size, sequence, int(size > 0))
    if kind:
        struct.pack_into('<IQ', data, 36, parent, 1)
    if size:
        struct.pack_into('<III', data, 48, 0, physical, (size + 4095) // 4096)
    return seal(data, 252)


def directory_entry(identity, name, generation=1):
    data = bytearray(128)
    name = name.encode()
    struct.pack_into('<IH', data, 0, identity, len(name))
    struct.pack_into('<Q', data, 8, generation)
    data[16:16 + len(name)] = name
    return seal(data, 124)


class SnapshotVolume(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'v2.raw'
        with self.path.open('wb') as stream:
            stream.truncate(512 * 1024 * 1024)
        sb = bytearray(BLOCK)
        struct.pack_into('<IHHII', sb, 0, 0x43594653, 2, 112, BLOCK, 131072)
        sb[16:32] = UUID
        struct.pack_into('<3Q13I', sb, 32, 1, 0, 1, 4098, 4102, 4240, 256, 0, 4118, 4119, 4120, 8, 15, 224, 224, 0)
        self.write(0, seal(sb, 108)); self.write(1, sb)
        bitmap = bytearray(16384)
        for block in range(BUSINESS + 2):
            bitmap[block // 8] |= 1 << (block % 8)
        for index in range(4):
            self.write(4098 + index, bitmap[index * BLOCK:(index + 1) * BLOCK])
        table = bytearray().join(node(identity) for identity in range(256))
        table[:256] = node(0, 2, 128, 0, BUSINESS)
        table[256:512] = node(1, 1, BLOCK, 0, BUSINESS + 1, sequence=1)
        table[224 * 256:225 * 256] = node(224, 2, 512, 224, 4240)
        table[225 * 256:226 * 256] = node(225, 1, 64, 224, 4241)
        table[226 * 256:227 * 256] = node(226, 1, parent=224)
        table[227 * 256:228 * 256] = node(227, 1, parent=224)
        table[228 * 256:229 * 256] = node(228, 1, 65536, 224, 8338)
        for index in range(16):
            self.write(4102 + index, table[index * BLOCK:(index + 1) * BLOCK])
        root = bytearray(BLOCK)
        for index, name in enumerate(('.cyxia-boot', '.cyxia-cluster-a', '.cyxia-cluster-b', '.cyxia-snapshot-requests')):
            root[index * 128:(index + 1) * 128] = directory_entry(225 + index, name)
        self.write(4240, root)
        boot = bytearray(BLOCK); boot[:8] = b'CYXBOOT1'; boot[8:24] = UUID
        struct.pack_into('<I', boot, 32, crc32c(boot[:32])); self.write(4241, boot)
        self.write(BUSINESS, directory_entry(1, 'value') + bytes(BLOCK - 128))
        self.write(BUSINESS + 1, b'A' * BLOCK)
        control = bytearray(BLOCK)
        struct.pack_into('<IHH', control, 0, 0x43594643, 2, 256); control[8:24] = UUID
        for offset, value in ((24, 1), (32, 1), (40, 1), (72, 86400 * 10**9), (80, 3600 * 10**9), (88, 21600 * 10**9), (128, 1)):
            struct.pack_into('<Q', control, offset, value)
        struct.pack_into('<I', control, 100, 1); struct.pack_into('<I', control, 228, 1)
        self.write(4118, seal(control, 240))
        catalog = bytearray(BLOCK)
        struct.pack_into('<IHHHHI', catalog, 0, 0x43595343, 2, 512, 448, 8, 0)
        catalog[16:32] = UUID; struct.pack_into('<Q', catalog, 32, 1)
        for slot in range(8):
            struct.pack_into('<I', catalog, 512 + slot * 448 + 4, 1 if slot < 6 else 2)
        self.write(4119, seal(catalog, 40))
        requests = bytearray(BLOCK)
        struct.pack_into('<IHH', requests, 0, 0x43595251, 1, 512); requests[8:24] = UUID
        struct.pack_into('<6I', requests, 24, 64, 512, 16, 128, 1, 512)
        for slot in range(16):
            mark = bytearray(128); struct.pack_into('<IHHI', mark, 0, 0x4359574d, 1, 128, slot)
            struct.pack_into('<Q', mark, 16, 1)
            requests[512 + slot * 128:640 + slot * 128] = seal(mark, 124)
        self.write(8338, seal(requests, 508))
        record = bytearray(512); struct.pack_into('<IHH', record, 0, 0x43594652, 1, 512)
        record = seal(record, 508)
        for index in range(1, 9):
            self.write(8338 + index, record * 8)

    def read(self, block):
        with self.path.open('rb') as stream:
            stream.seek(block * BLOCK); return stream.read(BLOCK)

    def write(self, block, data):
        with self.path.open('r+b') as stream:
            stream.seek(block * BLOCK); stream.write(data)

    def allocate(self, block):
        index = block // (BLOCK * 8)
        data = bytearray(self.read(4098 + index)); offset = block % (BLOCK * 8)
        data[offset // 8] |= 1 << (offset % 8); self.write(4098 + index, data)

    def capture(self, slot=6, snapshot_id=1):
        first = 4120 + slot * 15
        image = b''.join(self.read(4102 + index) for index in range(14))
        for index in range(14):
            self.write(first + 1 + index, image[index * BLOCK:(index + 1) * BLOCK])
        descriptor = bytearray(BLOCK)
        struct.pack_into('<IHH', descriptor, 0, 0x43595352, 2, 128); descriptor[8:24] = UUID
        struct.pack_into('<QI', descriptor, 24, snapshot_id, slot)
        struct.pack_into('<3Q4I', descriptor, 40, 1, 1, 0, 224, 14, first + 1, 0)
        descriptor[80:112] = hashlib.sha256(image).digest(); seal(descriptor, 120)
        self.write(first, descriptor)
        catalog = bytearray(self.read(4119)); at = 512 + slot * 448
        struct.pack_into('<II6QIII', catalog, at, 1, 1 if slot < 6 else 2, snapshot_id, 1, 1, 0, 0, 3600 * 10**9, 1, 1, 0)
        struct.pack_into('<QQII', catalog, at + 72, 1, 1, first, first + 1)
        catalog[at + 96:at + 128] = hashlib.sha256(descriptor).digest()
        struct.pack_into('<Q', catalog, at + 128, 1); self.write(4119, seal(catalog, 40))
        control = bytearray(self.read(4118)); struct.pack_into('<Q', control, 40, snapshot_id + 1)
        self.write(4118, seal(control, 240))

    def record(self, kind, lsn, payload, home=0, index=0, count=0, txid=1):
        length = 64 + len(payload); data = bytearray((length + 4095) // 4096 * 4096)
        struct.pack_into('<IHHIIQQQQII', data, 0, 0x43594c47, 1, kind, length, crc32c(payload), txid, lsn, 1, home, index, count)
        struct.pack_into('<I', data, 56, crc32c(data[:64])); data[64:64 + len(payload)] = payload
        return data

    def transaction(self, at, begin, txid, changes, commit=True):
        count = len(changes)
        self.write(at, self.record(1, begin, struct.pack('<IIQ', count, 0, count * BLOCK), txid=txid))
        digest = hashlib.sha256()
        for index, (home, image) in enumerate(changes):
            self.write(at + 1 + index * 2, self.record(2, begin + 1 + index, image, home, index, count, txid))
            digest.update(struct.pack('<Q', home) + image)
        if commit:
            payload = struct.pack('<QQQII', txid, begin, begin + count, count, 0) + digest.digest()
            self.write(at + 1 + count * 2, self.record(3, begin + count + 1, payload, txid=txid))

    def test_fixed_system_capacity_and_pending_garbage_are_distinct(self):
        result = inspect(self.path)
        self.assertEqual(result['format_version'], 2)
        self.assertEqual(result['boot_epoch'], 0)
        self.assertEqual(result['allocated_business_blocks'], 2)
        self.assertEqual(result['garbage_blocks'], 0)
        self.assertNotIn('/.cyxia-boot', result['files'])
        self.allocate(BUSINESS + 20)
        self.assertEqual(inspect(self.path)['garbage_blocks'], 1)

    def test_cow_snapshot_retains_old_content_while_live_inode_changes(self):
        self.capture()
        self.allocate(BUSINESS + 2); self.write(BUSINESS + 2, b'B' * BLOCK)
        table = bytearray(self.read(4102)); table[256:512] = node(1, 1, BLOCK, 0, BUSINESS + 2, sequence=2)
        self.write(4102, table)
        result = inspect(self.path)
        self.assertEqual(result['files']['/value']['sha256'], hashlib.sha256(b'B' * BLOCK).hexdigest())
        self.assertEqual(result['snapshots'][0]['files']['/value']['sha256'], hashlib.sha256(b'A' * BLOCK).hexdigest())
        self.assertEqual(result['reachable_business_blocks'], 3)
        self.assertEqual(result['garbage_blocks'], 0)

    def test_snapshot_digest_and_required_old_allocation_fail_closed(self):
        self.capture()
        old = self.read(4211); corrupt = bytearray(old); corrupt[300] ^= 1; self.write(4211, corrupt)
        with self.assertRaisesRegex(ValueError, 'inode image digest'): inspect(self.path)
        self.write(4211, old)
        table = bytearray(self.read(4102)); table[256:512] = node(1, 1, 0, 0); self.write(4102, table)
        bitmap = bytearray(self.read(4098)); block = BUSINESS + 1; bitmap[block // 8] &= ~(1 << (block % 8)); self.write(4098, bitmap)
        with self.assertRaisesRegex(ValueError, 'allocation'): inspect(self.path)

    def test_metadata_prefix_publishes_cow_bytes_and_discards_incomplete_tail(self):
        table = bytearray(self.read(4102)); table[256:512] = node(1, 1, BLOCK, 0, BUSINESS + 2, sequence=2)
        bitmap = bytearray(self.read(4098)); bitmap[(BUSINESS + 2) // 8] |= 1 << ((BUSINESS + 2) % 8)
        self.write(BUSINESS + 2, b'B' * BLOCK)
        self.transaction(2, 1, 1, [(4102, table), (4098, bitmap)])
        later = bytearray(table); later[256:512] = node(1, 1, BLOCK, 0, BUSINESS + 3, sequence=3)
        self.transaction(8, 5, 2, [(4102, later)], commit=False)
        result = inspect(self.path)
        self.assertEqual((result['last_commit_lsn'], result['committed_transactions'], result['replayed_blocks']), (4, 1, 2))
        self.assertTrue(result['discarded_tail'])
        self.assertEqual(result['files']['/value']['durable_write_seq'], 2)
        self.assertEqual(result['files']['/value']['sha256'], hashlib.sha256(b'B' * BLOCK).hexdigest())

    def test_business_redo_cannot_overwrite_live_or_historical_blocks(self):
        self.capture()
        self.transaction(2, 1, 1, [(BUSINESS + 1, b'B' * BLOCK)])
        with self.assertRaisesRegex(ValueError, 'REDO.*COMMIT'): inspect(self.path)
        self.assertEqual(self.read(BUSINESS + 1), b'A' * BLOCK)

    def test_cross_namespace_extent_and_directory_references_are_rejected(self):
        table = bytearray(self.read(4102)); original = bytes(table)
        table[256:512] = node(1, 1, BLOCK, 0, 4242); self.write(4102, table)
        with self.assertRaisesRegex(ValueError, 'namespace'): inspect(self.path)
        self.write(4102, original)
        self.write(BUSINESS, directory_entry(225, 'boot') + bytes(BLOCK - 128))
        with self.assertRaisesRegex(ValueError, 'namespace'): inspect(self.path)

    def test_legacy_or_conflicting_superblocks_are_not_v2_mounts(self):
        sb = bytearray(self.read(0)); original = bytes(sb)
        struct.pack_into('<H', sb, 4, 1); seal(sb, 108); self.write(0, sb); self.write(1, sb)
        with self.assertRaisesRegex(ValueError, 'superblock'): inspect(self.path)
        self.write(0, original); sb = bytearray(original); struct.pack_into('<Q', sb, 40, 1)
        self.write(1, seal(sb, 108))
        with self.assertRaisesRegex(ValueError, 'disagreement'): inspect(self.path)

    def test_catalog_width_and_request_header_reserved_fields_are_checked(self):
        catalog = bytearray(self.read(4119)); original = bytes(catalog)
        struct.pack_into('<II', catalog, 8, 448, 8); self.write(4119, seal(catalog, 40))
        with self.assertRaisesRegex(ValueError, 'catalog'): inspect(self.path)
        self.write(4119, original)
        requests = bytearray(self.read(8338)); requests[48] = 1; self.write(8338, seal(requests, 508))
        with self.assertRaisesRegex(ValueError, 'request object'): inspect(self.path)

    def test_indirect_extent_identity_and_complete_mapping_are_verified(self):
        table = bytearray(self.read(4102))
        child = node(1, 1, 17 * BLOCK, 0, BUSINESS + 1, sequence=1)
        struct.pack_into('<H', child, 32, 16)
        child[48:240] = bytes(192)
        expected = bytearray()
        for index in range(17):
            block = BUSINESS + 1 + index * 2
            self.allocate(block); payload = bytes([index + 1]) * BLOCK
            self.write(block, payload); expected.extend(payload)
            if index < 16:
                struct.pack_into('<III', child, 48 + index * 12, index, block, 1)
        indirect_block = BUSINESS + 40
        self.allocate(indirect_block)
        struct.pack_into('<IH', child, 240, indirect_block, 1)
        table[256:512] = seal(child, 252); self.write(4102, table)
        indirect = bytearray(BLOCK)
        struct.pack_into('<IHHIH', indirect, 0, 0x43594558, 2, 32, 1, 1)
        struct.pack_into('<Q', indirect, 16, 1)
        struct.pack_into('<III', indirect, 32, 16, BUSINESS + 33, 1)
        self.write(indirect_block, seal(indirect, 4092))
        result = inspect(self.path)
        self.assertEqual(result['files']['/value']['sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(result['files']['/value']['ext_count'], 1)
        struct.pack_into('<Q', indirect, 16, 2); self.write(indirect_block, seal(indirect, 4092))
        with self.assertRaisesRegex(ValueError, 'indirect extent identity'): inspect(self.path)
        struct.pack_into('<Q', indirect, 16, 1)
        struct.pack_into('<I', indirect, 36, indirect_block); self.write(indirect_block, seal(indirect, 4092))
        with self.assertRaisesRegex(ValueError, 'ownership'): inspect(self.path)

    def test_deleting_identity_survives_durable_gc_without_reopening_old_data(self):
        self.capture()
        table = bytearray(self.read(4102)); table[256:512] = node(1, 1, parent=0)
        self.write(4102, table)
        bitmap = bytearray(self.read(4098)); block = BUSINESS + 1
        bitmap[block // 8] &= ~(1 << (block % 8)); self.write(4098, bitmap)
        catalog = bytearray(self.read(4119)); at = 512 + 6 * 448
        struct.pack_into('<I', catalog, at, 2); struct.pack_into('<Q', catalog, at + 136, 1)
        self.write(4119, seal(catalog, 40))
        ctl = bytearray(self.read(4118)); struct.pack_into('<QQI', ctl, 104, 1, 1, 2)
        self.write(4118, seal(ctl, 240))
        sb = bytearray(self.read(0)); struct.pack_into('<3Q', sb, 32, 2, 1, 2)
        self.write(0, seal(sb, 108)); self.write(1, sb)
        result = inspect(self.path)
        self.assertEqual(result['control']['gc_phase'], 2)
        self.assertEqual(result['snapshots'][0]['state'], 2)
        self.assertEqual(result['snapshots'][0]['files'], {})

    def test_directory_bytes_beyond_published_size_must_be_zero(self):
        page = bytearray(self.read(BUSINESS)); page[256] = 1; self.write(BUSINESS, page)
        with self.assertRaisesRegex(ValueError, 'beyond inode size'): inspect(self.path)


if __name__ == '__main__':
    unittest.main()
