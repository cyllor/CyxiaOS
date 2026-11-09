"""Independent writer-layout fixtures: synthetic raw structure, never native proof."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from test_check_v13_boot_disk import Volume, inode, entry, BLOCK

FEATURE = '8b68c6f4e977aa844174a9ed4c37404faf05ce151fa67ed02106611704643854'
SCHEMAS = [FEATURE, 'e68f5095f9cce96c0036e8765b6f303f5d7ff2a112bb5bd13b963551e5812f5b', '3f3642803f6cd8dcc964092ac8d2e51922eb661a185dc6e9546ae037ef1cd5ab', '091fa0a5ae8012692fd4e351993773077063c67fdf4303f30bfbee68d47fae7e']
OWNER = 0x5245504c4159
# Pinned below from an independent, byte-by-byte writer transcription.
SET_HASH = 'a812e965bf2c0ff3cc048e0968caf936fcff49d779d90eb253d0541768294664'
INPUT_HASH = 'bebf98702c8d990dec5b880eb731dc92f76b86676e6a99b98cb8d7e340c8e4fb'
PROBE_HASH = 'ffa3414985a6d7d87410d7626fdf3c2796357072e80a0f0a7a2090b14734d0ea'
SCOPE_HASHES = ['ea44b5ce0e55db6a31d01f8756daafc3a550ea00f0221737f55fb6287ab9d2a5', '9794d710003780b28584199c35cdb2d1666e6c10aa337367232642a9b44fed75']


def put(data, offset, *values):
    struct.pack_into('<' + 'Q' * len(values), data, offset, *values)


def context():
    return dict(source_map={'crates/prototype/src/features.rs': FEATURE}, build_sha256='aa' * 32,
                artifacts={'node-a.elf': 'bb' * 32}, model_sha256='11' * 32, model_generation=1,
                schema_hash=FEATURE, schema_hashes=SCHEMAS, node_id='33' * 32,
                input_sha256='44' * 32, config_sha256='55' * 32, nonce='66' * 16,
                disk_uuid=bytes(range(1, 17)).hex(), boot_epoch=1,
                released_boundary=dict(publication=2, phase=0, verified=2, archived=2, paired=1),
                stopped_banks={k: '77' * 32 for k in ('boot', 'replay', 'control', 'runtime', 'unified')})


def history(probe=False, baseline=False):
    row = bytearray(6144)
    put(row, 0, 40 if baseline else 64 if probe else 31, 7)
    put(row, 152, 7, 120, 2, 3, 12, 1)
    struct.pack_into('<4H', row, 200, 0 if baseline else 1, 0 if baseline else 1, 1 if baseline else 2, 0)
    for i, weight in enumerate((1,) if baseline else (1, 2)):
        struct.pack_into('<4H2H', row, 512 + 24 * i, 1, 1, 4, 0, i, weight)
    if baseline:
        put(row, 344, 1, 120, 121, 0, 200, 200, 1, 122, 0, 130, 1, 0, 0)
        row[2048:] = b'R' * 4096  # reused-slot residue is legal
        return row
    row[16:48] = bytes.fromhex(SET_HASH)
    row[48:80] = bytes.fromhex(PROBE_HASH if probe else INPUT_HASH)
    put(row, 80, 1)
    row[88:120] = bytes.fromhex('11' * 32)
    row[120:152] = bytes.fromhex(FEATURE)
    inp = bytearray(4096)
    put(inp, 0, int.from_bytes(b'CXPROBE1', 'little') if probe else 0x4359585254494e31,
        3, 7, 0 if probe else 9, 120, 0 if probe else 1000000000, 3, 2, 1, 1, 12, 1, 0 if probe else 1, 1, 1, 2)
    inp[128:160] = bytes.fromhex('11' * 32)
    inp[160:192] = bytes.fromhex(SET_HASH)
    put(inp, 320, 15)
    for i, weight in enumerate((1, 2)):
        put(inp, (64 + i * 10) * 8, 4, i | weight << 16, 0, 0, 0, 0, 0, 0, 0, 0)
    put(inp, 404 * 8, 4, 1 << 16, 0)
    row[2048:] = inp
    if not probe:
        put(row, 272, 1, 9, 10, 0, 12, 1)
        put(row, 320, 1, 120, 200, 1, 120, 121, 200, 200, 200, 1, 122, 130, 130, 1, 0, 1)
        row[448:480] = bytes.fromhex('32d3d5d0fec9ed1576a1889f4ce2eef857056347f0dcbfb1ae20c00765760e55')
        row[1280:1328] = row[272:320]
    return row


def side(candidate=False, probe=False):
    header = bytearray(2048)
    header[:17] = b'CYXIA_REPLAY_1.3\0'
    first = 20 if candidate else 10
    observation = first + 6000000000
    closing = observation + 10000000000
    put(header, 32, 1, 2 if candidate else 1, 2 if candidate else 1, 1, 1, 12, 1, 1,
        first, observation - 1000000000, observation, closing, 2 if probe else 1, 1, 100, int(candidate))
    for offset, value in ((256, '324fe297c7f2eeb0d2c4b2530a41adb4a657b109a211d5da291696b48071fc1a'), (288, '22' * 32), (320, '23' * 32), (352, SCOPE_HASHES[int(candidate)]), (384, '24' * 32), (416, '25' * 32)):
        header[offset:offset + 32] = bytes.fromhex(value)
    for i, value in enumerate(SCHEMAS):
        header[448 + i * 32:480 + i * 32] = bytes.fromhex(value)
    put(header, 576, 13, 13, 13, 13, 0, 4, 0, 2048)
    header[640:672] = bytes.fromhex('33' * 32)
    put(header, 672, first, observation, closing, closing, 3, 3, 1, 100, 4, 0, 0, 1)
    put(header, 768, 12, 1, 0, 7, 12, 1, 1, 15, OWNER, 1, 2, 1, 0x5245504c5453, 1, 2, 9)
    header[1792:1800] = b'CYCLOSE1'
    put(header, 1800, 1, 1, 4)
    struct.pack_into('<HH', header, 1824, 0, 1)
    put(header, 1840, 1, 9, 99, 0, 12, 1, 1, 120, closing, 8, 120, 2, 3, 1, 1, 120, 121, 1, 122, 130, closing, 0)
    rows = history(baseline=not candidate)
    if probe:
        rows = history(probe=True) + rows
    cpu = bytes.fromhex('33' * 32) + struct.pack('<4Q', 0, observation, observation + 5, 2)
    requests = bytearray()
    for i in range(100):
        arrived = observation + i // 10 * 1000000000 + i % 10 * 1000
        requests += struct.pack('<12Q', i + 1, arrived, 1, arrived + 1, 1, arrived + 1,
                                OWNER, 1, arrived, 1, 2 if candidate else 1, 1) + bytes(32)
    return header + rows + cpu + requests


def archive_volume(directory, data, name='lr-0000000000000001-0000'):
    volume = Volume(directory)
    volume.blocks[4118][384:512] = entry(4, name, 2)
    blocks = (len(data) + BLOCK - 1) // BLOCK
    volume.edit_inode(4, lambda value: value.__setitem__(slice(None), inode(1, generation=2, size=len(data), sequence=1,
        extents=[(0, 8216, blocks)])))
    for i in range(blocks):
        volume.blocks[8216 + i] = data[i * BLOCK:(i + 1) * BLOCK].ljust(BLOCK, b'\0')
        index = 8216 + i
        volume.blocks[4098 + index // (BLOCK * 8)][index % (BLOCK * 8) // 8] |= 1 << (index % 8)
    volume.flush()
    return volume.path


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('v16_learning_archive'),
                             'strict committed archive extractor is missing')
        import v16_learning_archive
        self.archive = v16_learning_archive

    def extract(self, data, *, ctx=None, name='lr-0000000000000001-0000'):
        with tempfile.TemporaryDirectory() as directory:
            path = archive_volume(directory, data, name)
            trusted = context() if ctx is None else copy.deepcopy(ctx)
            with path.open('rb') as stream:
                trusted['disk_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            return self.archive.extract_local_pair(path, trusted_capture_context=trusted, boot_epoch=1)

    def test_concatenated_baseline_residue_and_two_alternative_candidate_are_raw_structure_only(self):
        data = side() + side(True, True)
        pairs = self.extract(data)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0]['baseline']['offset'], 0)
        self.assertEqual(pairs[0]['candidate']['offset'], 21056)
        self.assertEqual(pairs[0]['candidate']['records'][0]['kind'], 'Probe')
        self.assertEqual(pairs[0]['candidate']['records'][1]['candidate_set_sha256'], SET_HASH)
        self.assertEqual(pairs[0]['baseline']['archive_bytes'], data)
        for flag in ('reward_replay_verified', 'accepted_training_sample_verified', 'model_trained', 'event_hash_recomputed', 'initial_image_reexecution_verified'):
            self.assertIs(pairs[0][flag], False)

    def test_every_partial_final_header_history_cpu_and_request_tail_is_rejected(self):
        raw = side(True)
        for size in (1, 2047, 2048, 8191, 8192, 8255, len(raw) - 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.extract(side() + raw[:size])

    def test_unsupported_and_identity_mutations_cannot_manufacture_complete_pair(self):
        for offset, value in ((24, 1), (32, 2), (56, 2), (88, 2), (128, 65), (136, 8193),
                              (144, 4097), (152, 2), (160, 1), (168, 1), (192, 1), (576, 12),
                              (608, 1), (624, 1), (632, 1024), (744, 1), (752, 1),
                              (2048, 128), (2048 + 80, 2), (2048 + 440, 2),
                              (2048 + 2048 + 112, 2), (8192 + 32, 4), (8256 + 8, 201)):
            with self.subTest(offset=offset):
                raw = side(True)
                put(raw, offset, value)
                with self.assertRaises(ValueError):
                    self.extract(side() + raw)
        for offset in (256, 288, 320, 352, 448, 480, 640, 1280, 1792, 2048 + 16, 2048 + 48,
                       2048 + 88, 2048 + 120, 2048 + 2048 + 512):
            with self.subTest(byte=offset):
                raw = side(True)
                raw[offset] ^= 1
                with self.assertRaises(ValueError):
                    self.extract(side() + raw)

    def test_wrong_warmup_coverage_and_missing_initial_segment_are_rejected(self):
        for offset, value in ((104, 20), (688, 6000000020), (704, 7)):
            raw = side(True)
            put(raw, offset, value)
            if offset == 704:
                put(raw, 712, 7)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.extract(side() + raw)
        with self.assertRaises(ValueError):
            self.extract(side() + side(True), name='lr-0000000000000001-0001')

    def test_rehashed_incomplete_source_manifest_is_rejected(self):
        sides = []
        for candidate, scope in ((False, 'a3da7977cecd500c66a0be383933363bc8203e759cd38f9caf898fe91c41273a'),
                                 (True, '35d99c04159b9fbd11c29cd7c8a0c7964c74977ab3a22591a0e40ee92e52a33f')):
            raw = side(candidate)
            put(raw, 616, 1)
            put(raw, 736, 1)
            raw[768:1280] = bytes(512)
            put(raw, 768, OWNER, 1, 2, 15)
            raw[352:384] = bytes.fromhex(scope)
            sides.append(raw)
        with self.assertRaises(ValueError):
            self.extract(sides[0] + sides[1])

    def test_saved_exports_are_exclusive_and_independent_replay_rejects_rehashed_tampering(self):
        # Custody is tested by Task2; this seam retains real disk extraction and export validation.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disk = archive_volume(directory, side() + side(True))
            trusted = context()
            with disk.open('rb') as stream:
                trusted['disk_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            source = Path(__file__).resolve().parents[1]
            trusted['paths'] = {'source_root': str(source)}
            for name in ('features.rs', 'policy_wire.rs', 'learning.rs'):
                rel = 'crates/prototype/src/' + name
                trusted['source_map'][rel] = hashlib.sha256((source / rel).read_bytes()).hexdigest()
            checked = dict(version='synthetic-only', trusted_context=trusted, boot_epoch=1,
                           boundary=trusted['released_boundary'], checker_identity={'version': 'test-only'},
                           producer_tools_root=str(source))
            args = dict(source_root=source, build_manifest='unused', formatter='unused',
                        qemu_binary='unused', qemu_source='unused')
            with patch.object(self.archive, 'verify_capture', return_value=checked):
                with self.assertRaises(ValueError):
                    self.archive.verify_pair_capture(root, **args)
                result = self.archive.verify_pair_capture(root, save_exports=True, **args)
                self.assertTrue(result['capture_complete'])
                (root / 'summary.json').write_text('{"capture_complete": false}')
                self.assertEqual(self.archive.verify_pair_capture(root, **args), result)
                with self.assertRaises(FileExistsError):
                    self.archive.verify_pair_capture(root, save_exports=True, **args)
                export = next((root / 'learning-archives').glob('side-*.bin'))
                export.write_bytes(b'forged')
                manifest_path = root / 'learning-archives' / 'manifest.json'
                manifest = json.loads(manifest_path.read_text())
                for pair in manifest['pairs']:
                    for key in ('baseline', 'candidate'):
                        record = pair[key]['raw_export']
                        if record['file'] == export.name:
                            record.update(bytes=6, sha256=hashlib.sha256(b'forged').hexdigest())
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    self.archive.verify_pair_capture(root, **args)

    def test_missing_duplicate_wrong_boot_and_malformed_paths_are_rejected(self):
        for data, name in ((side(), 'lr-0000000000000001-0000'),
                           (side() + side(), 'lr-0000000000000001-0000'),
                           (side() + side(True), 'lr-0000000000000002-0000'),
                           (side() + side(True), 'lr-0000000000000001-000A')):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.extract(data, name=name)

    def test_applied_closing_restoration_retains_literal_late_observation(self):
        # Actual retained bytes; this unit proves structure only, never native acceptance.
        row = bytes.fromhex("""
        4359434c4f534531010000000000000001000000000000000400000000000000
        0000010000000000000000000000000001000000000000000100000000000000
        4f0200000000000000000000000000000c000000000000000100000000000000
        1e02000000000000c0eb9c7818000000c0cfa8cc1a0000004f02000000000000
        c0eb9c78180000007d0400000000000004000000000000000100000000000000
        0100000000000000c0eb9c781800000050ed9f78180000000100000000000000
        70d4c57818000000c039b38718000000d0dd9a7b180000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        """)
        self.assertEqual(hashlib.sha256(row).hexdigest(),
                         'b419818d0cd5dfe983ea1ca17d71a61a6c485437aea5529e6985daf420546451')
        try:
            self.archive._closing(row, 1, 107408062992)
        except ValueError as error:
            self.fail('lawful retained Applied closing receipt rejected: ' + str(error))
        for offset, value in ((48, 2), (80, 13), (152, 0), (184, 0), (192, 105355884993),
                              (200, 107408062993), (216, 1)):
            bad = bytearray(row); put(bad, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.archive._closing(bad, 1, 107408062992)

    def test_native_literal_scheduled_request_is_queued_before_scope_and_release(self):
        row = bytes.fromhex("""
        01000000000000007060011d16000000010000000000000030db1a5a16000000
        010000000000000030db1a5a1600000059414c50455200000100000000000000
        7060011d1600000001000000000000008035986f0d0000000100000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        """)
        self.assertEqual(hashlib.sha256(row).hexdigest(),
                         'f3d14a6b306c3cf2f966bdb7c3b9cd90b8580ca06c3da308fcdd4416ab1eef42')
        self.assertTrue(hasattr(self.archive, '_request'), 'missing source-correct queued admission decoder')
        self.assertEqual(self.archive._request(row, 0, 88975910000, 94975910000, 107408062992),
                         (1, OWNER, 1, 0))
        for offset, value in ((72, 0), (72, 2), (80, 0), (80, 88975910001),
                              (80, 94975910001), (88, 0)):
            bad = bytearray(row); put(bad, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.archive._request(bad, 0, 88975910000, 94975910000, 107408062992)

    def test_candidate_runtime_abi_magic_matches_native_prefix_and_fixture_abi_is_rejected(self):
        row = history()
        self.assertEqual(row[2048:2056], bytes.fromhex('314e495452585943'))
        try:
            self.archive._record(row, dict(side='Candidate', boot_epoch=1, closing_ns=1000), context())
        except ValueError as error:
            self.fail('native-derived continuous runtime ABI input rejected: ' + str(error))
        # Rehashing an engineering-fixture ABI transport must not admit it.
        row[2048:2056] = bytes.fromhex('3331504e49585943')
        row[48:80] = bytes.fromhex('d00a10c7e059aabbcbaf61e936626c0f294f40ab16e7269876c0354838c22809')
        with self.assertRaises(ValueError):
            self.archive._record(row, dict(side='Candidate', boot_epoch=1, closing_ns=1000), context())

    def test_ordinary_history_execution_and_start_deadlines_remain_strict(self):
        for baseline in (False, True):
            for started, finished in ((122, 201), (201, 201)):
                row = history(baseline=baseline)
                put(row, 400, started); put(row, 416, finished)
                with self.subTest(baseline=baseline, started=started), self.assertRaises(ValueError):
                    self.archive._execution(row, dict(closing_ns=1000))

    def test_separate_offline_exports_roundtrip_tamper_and_capture_alias_refusal(self):
        self.assertIn('exports_directory', __import__('inspect').signature(self.archive.verify_pair_capture).parameters,
                      'missing caller-selected separate export directory')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); root = base / 'original'; root.mkdir()
            disk = archive_volume(root, side() + side(True))
            trusted = context()
            with disk.open('rb') as stream:
                trusted['disk_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            source = Path(__file__).resolve().parents[1]
            trusted['paths'] = {'source_root': str(source)}
            for name in ('features.rs', 'policy_wire.rs', 'learning.rs'):
                rel = 'crates/prototype/src/' + name
                trusted['source_map'][rel] = hashlib.sha256((source / rel).read_bytes()).hexdigest()
            checked = dict(version='synthetic-only', trusted_context=trusted, boot_epoch=1,
                           boundary=trusted['released_boundary'], checker_identity={'version': 'test-only'},
                           producer_tools_root=str(source))
            args = dict(source_root=source, build_manifest='unused', formatter='unused',
                        qemu_binary='unused', qemu_source='unused', producer_tools_root=source)
            exports = base / 'derived'
            before = {}
            for path in root.iterdir():
                if path.is_file():
                    with path.open('rb') as stream:
                        before[path.name] = (path.stat().st_size, hashlib.file_digest(stream, 'sha256').hexdigest())
            with patch.object(self.archive, 'verify_capture', return_value=checked):
                with self.assertRaisesRegex(ValueError, 'separate exports'):
                    self.archive.verify_pair_capture(root, save_exports=True, **args)
                result = self.archive.verify_pair_capture(root, exports_directory=exports, save_exports=True, **args)
                self.assertTrue(result['capture_complete'])
                self.assertEqual(result['exports_directory'], str(exports.resolve()))
                self.assertEqual(result['checker_identity'], {'version': 'test-only'})
                self.assertEqual(self.archive.verify_pair_capture(root, exports_directory=exports, **args), result)
                with self.assertRaises(FileExistsError):
                    self.archive.verify_pair_capture(root, exports_directory=exports, save_exports=True, **args)
                aliases = (root, root / 'new-inside', base / 'alias')
                aliases[-1].symlink_to(root, target_is_directory=True)
                for alias in aliases:
                    with self.subTest(alias=alias), self.assertRaises(ValueError):
                        self.archive.verify_pair_capture(root, exports_directory=alias, save_exports=True, **args)
                target = next(exports.glob('archive-*.bin')); target.write_bytes(b'forged')
                with self.assertRaises(ValueError):
                    self.archive.verify_pair_capture(root, exports_directory=exports, **args)
            self.assertFalse((root / 'learning-archives').exists())
            after = {}
            for path in root.iterdir():
                if path.is_file():
                    with path.open('rb') as stream:
                        after[path.name] = (path.stat().st_size, hashlib.file_digest(stream, 'sha256').hexdigest())
            self.assertEqual(before, after)

    def test_changed_trusted_node_model_schema_or_released_boundary_is_rejected(self):
        for key, value in (('node_id', '99' * 32), ('model_sha256', '99' * 32),
                           ('schema_hash', '99' * 32), ('released_boundary', {}), ('nonce', '00' * 16)):
            ctx = context(); ctx[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.extract(side() + side(True), ctx=ctx)


if __name__ == '__main__':
    unittest.main()
