"""Structural host fixtures only; never native learning or signature evidence."""
from contextlib import contextmanager
import hashlib
import importlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


SCHEMAS = (
    '8b68c6f4e977aa844174a9ed4c37404faf05ce151fa67ed02106611704643854',
    'e68f5095f9cce96c0036e8765b6f303f5d7ff2a112bb5bd13b963551e5812f5b',
    '3f3642803f6cd8dcc964092ac8d2e51922eb661a185dc6e9546ae037ef1cd5ab',
    '091fa0a5ae8012692fd4e351993773077063c67fdf4303f30bfbee68d47fae7e')
UUID = 'ab' * 16


def put(raw, at, *values):
    struct.pack_into('<' + 'Q' * len(values), raw, at, *values)


def packet(kind=8, body=224):
    raw = bytearray(132 + body + 64)
    raw[:8] = b'CXBILL1\0'
    struct.pack_into('<HHQ', raw, 8, kind, body, 1)
    raw[20:52] = b'P' * 32
    raw[52:84] = b'N' * 32
    put(raw, 84, 1, 1)
    raw[100:132] = b'S' * 32
    raw[132:] = b'B' * (body + 64)
    return bytes(raw)


def regular(family=(16, 2), trial=4, peer=True, excluded=False):
    peer_bytes = packet() if peer else b''
    padded = (len(peer_bytes) + 255) // 256 * 256
    raw = bytearray(2048 + padded + 6144 + (1 + int(peer) + 1) * 64 + 100 * 128)
    raw[:17] = b'CYXIA_REPLAY_1.3\0'
    put(raw, 32, 1, trial, trial, *family, 12, 1, 12, 100, 100, 200, 300,
        1, 1, 100, 1, 7 if excluded else 0, 7 if excluded else 0)
    raw[256:416] = b'H' * 160
    if not excluded:
        raw[416:448] = b'V' * 32
    for index, schema in enumerate(SCHEMAS):
        raw[448 + index * 32:480 + index * 32] = bytes.fromhex(schema)
    put(raw, 576, 13, 13, 13, 13, int(peer), 1, int(peer), 2048)
    raw[640:672] = b'N' * 32
    put(raw, 728, 100, 1, len(peer_bytes), 1)
    put(raw, 768, 12, 1, 0, 15)
    raw[2048:2048 + len(peer_bytes)] = peer_bytes
    return bytes(raw)


def preparation(trial=3, peer=True):
    peer_bytes = packet(19, 516) if peer else b''
    padded = (len(peer_bytes) + 255) // 256 * 256
    raw = bytearray(1024 + padded + 64 + 100 * 32)
    raw[:15] = b'CYXIA_PREP_1.3\0'
    put(raw, 32, 7, 1, 0x5245504c4159, 1, trial, 12, 1, 12, 0, 100, 110, 120,
        8, 100, 120, 0, 1, 12, 1, 1, 12, 1, 1, 1, 100, 110, 1, 0)
    raw[288:416] = b'H' * 128
    put(raw, 456, 1, len(raw), 0)
    put(raw, 480, 12, 1, 0, 15)
    put(raw, 1000, len(peer_bytes))
    raw[1024:1024 + len(peer_bytes)] = peer_bytes
    return bytes(raw)


def late(trial=4):
    peer_bytes = packet(20, 444)
    raw = bytearray(256 + (len(peer_bytes) + 255) // 256 * 256)
    raw[:15] = b'CYXIA_LATE_1.3\0'
    put(raw, 16, 1, 256, len(raw), 1, trial, trial, 1, 8, 300, 400, 7, 8,
        len(peer_bytes), 0)
    raw[128:160] = hashlib.sha256(peer_bytes).digest()
    raw[160:192] = b'H' * 32
    raw[192:224] = b'N' * 32
    raw[224:256] = b'P' * 32
    raw[256:256 + len(peer_bytes)] = peer_bytes
    return bytes(raw)


class Journals(unittest.TestCase):
    def setUp(self):
        self.parser = importlib.import_module('v16_a03_collection_journal')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.disk = Path(self.temp.name) / 'disk.raw'
        self.disk.write_bytes(b'bounded disk fixture')

    def inspect(self, files, *, directories=None, uuid=UUID, boot=1, mutate=None,
                during_read=None, **limits):
        nodes, blocks = {}, {}
        block = 9000
        for index, (name, raw) in enumerate(files.items()):
            count = (len(raw) + 4095) // 4096
            nodes[name] = dict(inode=index + 4, generation=2, size=len(raw),
                durable_write_seq=3, sha256=hashlib.sha256(raw).hexdigest(),
                extents=[(0, block, count)])
            for offset in range(count):
                blocks[block + offset] = raw[offset * 4096:(offset + 1) * 4096].ljust(4096, b'\0')
            block += count
        if mutate:
            mutate(nodes, blocks)
        @contextmanager
        def volume(path):
            if during_read:
                during_read()
            yield blocks.__getitem__, {}
        with patch.object(self.parser, 'committed_volume', side_effect=volume), \
             patch.object(self.parser, 'inspect_committed', return_value=dict(
                 uuid=uuid, boot_epoch=boot, files=nodes, directories=directories or {})):
            return self.parser.inspect_journals(self.disk, disk_uuid=UUID, **limits)

    def test_later_peer_and_concatenated_journals_preserve_every_byte(self):
        first, second, prep, failure = regular(), regular(trial=5, excluded=True), preparation(), late()
        result = self.inspect({'/lr-0000000000000001-0000': first + second,
            '/lp-0000000000000001-0000': prep, '/lf-0000000000000001-0000': failure})
        self.assertEqual(result['counts'], dict(total=4, regular=2, preparation=1, late=1, excluded=3))
        sides = [row for row in result['journals'] if row['kind'] == 'regular']
        self.assertEqual([row['offset'] for row in sides], [0, len(first)])
        self.assertEqual(sides[0]['family'], [16, 2])
        self.assertEqual(set(result['exports'].values()), {first, second, prep, failure})
        self.assertEqual(result['manifest']['total_archive_bytes'], len(first + second + prep + failure))
        self.assertFalse(result['manifest']['reward_replay_verified'])
        self.assertFalse(result['manifest']['native_replay_authority_reconstructed'])
        self.assertEqual(result['manifest']['disk_sha256'], hashlib.sha256(self.disk.read_bytes()).hexdigest())
        for row in result['journals']:
            self.assertEqual(row['sha256'], hashlib.sha256(result['exports'][row['export_file']]).hexdigest())

    def test_local_all_eighteen_families_and_empty_peer_sections(self):
        families = [(1, 1), (1, 2)] + [(d, 1) for d in range(2, 17)] + [(16, 2)]
        for family in families:
            with self.subTest(family=family):
                result = self.inspect({'/lr-0000000000000001-0000': regular(family, peer=family[0] in (10, 12, 16))})
                self.assertEqual(result['journals'][0]['family'], list(family))

    def test_preparation_and_late_lengths_and_peer_padding_fail_closed(self):
        changes = [(regular(), 744, 2049), (regular(), 632, 1024),
                   (regular(), 136, 8193), (regular(), 752, 769),
                   (preparation(), 464, 1024), (late(), 32, 256), (late(), 112, 641)]
        for original, at, value in changes:
            raw = bytearray(original); put(raw, at, value)
            prefix = 'lr' if raw.startswith(b'CYXIA_REPLAY') else 'lp' if raw.startswith(b'CYXIA_PREP') else 'lf'
            with self.subTest(at=at, prefix=prefix), self.assertRaises(ValueError):
                self.inspect({f'/{prefix}-0000000000000001-0000': bytes(raw)})
        for prefix, original, start, size in [('lr', regular(), 2048, 420),
                ('lp', preparation(), 1024, 712), ('lf', late(), 256, 640)]:
            raw = bytearray(original); raw[start + size] = 1
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                self.inspect({f'/{prefix}-0000000000000001-0000': bytes(raw)})

    def test_schema_identity_and_unknown_trailing_journal_fail_closed(self):
        for at in (0, 32, 56, 64, 448, 576):
            raw = bytearray(regular()); raw[at] ^= 255
            with self.subTest(at=at), self.assertRaises(ValueError):
                self.inspect({'/lr-0000000000000001-0000': bytes(raw)})
        for suffix in (b'x', regular()[:-1], preparation()):
            with self.subTest(suffix=len(suffix)), self.assertRaises(ValueError):
                self.inspect({'/lr-0000000000000001-0000': regular() + suffix})

    def test_missing_wrong_boot_nested_unknown_segment_and_directory_fail(self):
        for files in ({}, {'/lr-0000000000000002-0000': regular()},
                {'/nested/lr-0000000000000001-0000': regular()},
                {'/lr-0000000000000001-0000.extra': regular()},
                {'/lr-0000000000000001-0001': regular()}):
            with self.subTest(files=list(files)), self.assertRaises(ValueError):
                self.inspect(files)
        with self.assertRaises(ValueError):
            self.inspect({'/lr-0000000000000001-0000': regular()},
                directories={'/lp-0000000000000001-0000': {}})

    def test_empty_participant_inventory_requires_explicit_boolean_opt_in(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.inspect({})
        result = self.inspect({}, allow_empty=True)
        self.assertEqual(result['counts'], dict(total=0, regular=0, preparation=0, late=0, excluded=0))
        self.assertEqual(result['journals'], [])
        self.assertEqual(result['exports'], {})
        self.assertEqual(result['manifest']['total_archive_bytes'], 0)
        for value in (1, None, 'true'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.inspect({}, allow_empty=value)

    def test_volume_custody_limits_hash_and_durable_sequence_are_checked(self):
        files = {'/lr-0000000000000001-0000': regular() + regular(trial=5)}
        for options in ({'uuid': 'cd' * 16}, {'boot': 2}, {'max_archives': 1},
                        {'max_archive_bytes': len(regular())}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.inspect(files, **options)
        for field, value in [('sha256', '00' * 32), ('durable_write_seq', 0), ('generation', 0)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.inspect(files, mutate=lambda nodes, blocks: nodes[next(iter(nodes))].update({field: value}))
        def change_disk():
            self.disk.write_bytes(b'changed during committed reconstruction')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.inspect(files, during_read=change_disk)

    def test_late_packet_hash_and_framing_are_checked_without_signature_claim(self):
        for at in (128, 256, 256 + 10, 256 + 132):
            raw = bytearray(late()); raw[at] ^= 1
            with self.subTest(at=at), self.assertRaises(ValueError):
                self.inspect({'/lf-0000000000000001-0000': bytes(raw)})
        result = self.inspect({'/lf-0000000000000001-0000': late()})
        self.assertFalse(result['manifest']['peer_signature_verified'])
        self.assertFalse(result['manifest']['provenance_verified'])

    def test_optional_original_r7_and_r8_committed_journals(self):
        root = Path(__file__).resolve().parent.parent
        cases = (
            ('artifacts/v016-progress-20261109-r7/learning-pair-01', 2, 0, 109248),
            ('artifacts/v016-focus-a03-a10-20261109-r8/a03-coreset-canonical-reuse-01', 1, 1, 36096))
        found = False
        for relative, count, excluded, size in cases:
            directory = root / relative
            if not (directory / 'disk.raw').is_file() or not (directory / 'input.json').is_file():
                continue
            found = True
            with self.subTest(capture=relative):
                uuid = json.loads((directory / 'input.json').read_text())['disk_uuid']
                result = self.parser.inspect_journals(directory / 'disk.raw', disk_uuid=uuid)
                self.assertEqual(result['counts']['regular'], count)
                self.assertEqual(result['counts']['excluded'], excluded)
                self.assertEqual(result['manifest']['total_archive_bytes'], size)
                self.assertEqual(sum(map(len, result['exports'].values())), size)
        if not found:
            self.skipTest('original local R7/R8 capture artifacts are unavailable')


if __name__ == '__main__':
    unittest.main()
