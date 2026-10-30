"""Offline A10 contract fixtures; none are native execution receipts."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


class A10OfflineReceipt(unittest.TestCase):
    def setUp(self):
        self.adapter = importlib.import_module('verify_v13_a10_receipt')

    def file_fixture(self, root):
        import test_v13_a10
        fixture = test_v13_a10.ProtectedFileReplies()
        fixture.setUp()
        raw, terminal, oracle = fixture.complete_prepare()
        consumption = fixture.consumption(raw, terminal, fixture.binding)
        for name, data in (('trace.bin', raw), ('progress.bin', terminal),
                           ('consumption.bin', consumption)):
            (root / name).write_bytes(data)
        before = dict(uuid=fixture.binding['uuid'], boot_epoch=0, files={},
                      directories={'/': {}}, committed_transactions=0,
                      replayed_blocks=0, discarded_tail=False, last_commit_lsn=23,
                      generation=1, log_epoch=1)
        boot = [0] * 512
        boot[:3] = [0x43595853544f3133, 1, 1]
        boot[3:5] = struct.unpack('<2Q', bytes.fromhex(before['uuid']))
        boot[8:15] = [29, 2, 2, 4096, 11, 4, 1]
        (root / 'storage-boot.bin').write_bytes(struct.pack('<512Q', *boot))
        serial = [b'STORAGE_V13_BOOT_DURABLE', b'SMP_BOOT_OK a=4 b=15 c=0']
        serial += [f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode() for cpu in (1, 2, 3)]
        wire = bytearray()
        for sequence, line in enumerate(serial, 1):
            frame = struct.pack('<4sBBHQQ', b'CYX1', 1, 0, len(line), 1, sequence) + line
            wire.extend(frame + struct.pack('<I', zlib.crc32(frame)))
        (root / 'serial.bin').write_bytes(wire)
        (root / 'serial.txt').write_bytes(b''.join(line + b'\n' for line in serial))
        return fixture.binding, before, oracle

    def test_clean_raw_file_replay_reconstructs_consumed_ack_without_native_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding, before, after = self.file_fixture(root)
            observed = self.adapter.replay_file_observation(root, binding, before, after, cut=False)
            self.assertEqual(observed['observation']['durable_write_seq'], 2)
            self.assertTrue(observed['observation']['consumption_boundary']['present'])
            self.assertEqual(observed['storage_boot']['epoch'], 1)
            self.assertNotIn('native_execution_verified', observed)

    def test_changed_protected_fsync_cannot_be_hidden_by_a_pass_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding, before, after = self.file_fixture(root)
            (root / 'summary.json').write_text(json.dumps(dict(status='PASS',
                native_mode_verified=True, observation={'durable_write_seq': 2})))
            raw = bytearray((root / 'trace.bin').read_bytes())
            struct.pack_into('<Q', raw, 512 + 4 * 768 + 128 + 120, 1)
            (root / 'trace.bin').write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'fsync receipt'):
                self.adapter.replay_file_observation(root, binding, before, after, cut=False)

    def test_disk_oracle_or_consumption_tampering_fails_raw_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding, before, after = self.file_fixture(root)
            bad = copy.deepcopy(after)
            bad['files']['/a10/value']['sha256'] = '00' * 32
            with self.assertRaises(ValueError):
                self.adapter.replay_file_observation(root, binding, before, bad, cut=False)
            raw = bytearray((root / 'consumption.bin').read_bytes())
            raw[32] ^= 1
            (root / 'consumption.bin').write_bytes(raw)
            with self.assertRaises(ValueError):
                self.adapter.replay_file_observation(root, binding, before, after, cut=False)

    def test_plaintext_success_and_corrupt_serial_cannot_replace_framed_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding, before, after = self.file_fixture(root)
            original = (root / 'serial.bin').read_bytes()
            for wire in ((root / 'serial.txt').read_bytes(), original[:-1] + b'\x00'):
                (root / 'serial.bin').write_bytes(wire)
                with self.subTest(wire=wire[:8]), self.assertRaises(ValueError):
                    self.adapter.replay_file_observation(root, binding, before, after, cut=False)

    def test_complete_serial_rejects_truncated_trailing_frame_after_valid_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.file_fixture(root)
            original = (root / 'serial.bin').read_bytes()
            half_header = struct.pack('<4sBBHQQ', b'CYX1', 1, 0, 4, 1, 6)[:13]
            for tail in (b'C', b'CY', b'CYX', half_header):
                (root / 'serial.bin').write_bytes(original + tail)
                with self.subTest(tail=tail), self.assertRaisesRegex(ValueError, 'incomplete.*serial'):
                    self.adapter.replay_serial(root, complete=True)

    def test_cut_consumption_is_reconstructed_not_taken_from_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding, before, after = self.file_fixture(root)
            before = dict(before, boot_epoch=1, files=copy.deepcopy(after['files']))
            (root / 'summary.json').write_text(json.dumps(dict(
                consumption_boundary={'present': True})))
            (root / 'consumption.bin').write_bytes(bytes(256))
            result = self.adapter.replay_file_observation(root, binding, before, after, cut=True)
            self.assertNotIn('consumption_boundary', result)
            self.assertIn('consumption_boundary_error', result)

    def test_child_replay_requires_exact_derived_observation_even_with_rehashed_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding, before, after = self.file_fixture(root)
            actual = self.adapter.replay_file_observation(root, binding, before, after, cut=False)
            fake = dict(actual, status='PASS', cut_observed=False, binding=binding,
                        nbd_trace={'cut': None})
            fake['observation'] = dict(fake['observation'], durable_write_seq=99)
            (root / 'summary.json').write_text(json.dumps(fake))
            for name in ('initial.raw', 'disk.raw'):
                (root / name).write_bytes(b'controlled independent disk-oracle boundary')
            for name, oracle in (('disk-before.json', before), ('disk-after.json', after)):
                (root / name).write_text(json.dumps(oracle))
            with patch.object(self.adapter, 'replay_transport', return_value=fake['nbd_trace']), \
                 patch.object(self.adapter, 'inspect_filesystem', side_effect=[before, after]), \
                 patch.object(self.adapter, 'verify_child_identity'):
                with self.assertRaisesRegex(ValueError, 'derived.*observation'):
                    self.adapter.replay_child(root, {'unused': 'controlled identity boundary'})

    def transport_fixture(self, root, *, cut=False):
        (root / 'nbd').mkdir()
        (root / 'initial.raw').write_bytes(bytes(512))
        (root / 'disk.raw').write_bytes(bytes(512) if cut else b'A' * 512)
        start = dict(version=1, size=512, disk_initial_sha256=hashlib.sha256(bytes(512)).hexdigest(),
                     phase='before', unflushed='drop', cut=2 if cut else 0, max_pending_sectors=32768,
                     run_id='host-fixture')
        (root / 'nbd/start.json').write_text(json.dumps(start))
        wire = struct.pack('>IHHQQI', 0x25609513, 0, 1, 1, 0, 512) + b'A' * 512
        wire += struct.pack('>IHHQQI', 0x25609513, 0, 3, 2, 0, 0)
        (root / 'nbd/requests.bin').write_bytes(wire)
        rows = []
        for identity, kind, offset, length, wire_offset, body in (
                (1, 1, 0, 512, 0, b'A' * 512), (2, 3, 0, 0, 540, b'')):
            rows += [dict(event='request', id=identity, kind=kind, handle=identity,
                          offset=offset, length=length, mutation=identity,
                          wire_offset=wire_offset, data_sha256=hashlib.sha256(body).hexdigest())]
            if cut and kind == 3:
                rows += [dict(event='cut', id=identity, mutation=2, phase='before',
                              surviving_offsets=[], discarded_sectors=1, acks=1, flushes=0)]
                continue
            rows += [dict(event='complete', id=identity, pending_sectors=1 if kind == 1 else 0,
                          flushes=0 if kind == 1 else 1),
                     dict(event='ack', id=identity, reply=struct.pack('>IIQ',
                          0x67446698, 0, identity).hex(),
                          data_sha256=hashlib.sha256(b'').hexdigest())]
        (root / 'nbd/events.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        (root / 'input.json').write_text(json.dumps(
            {key: start[key] for key in ('cut', 'phase', 'unflushed')}))

    def test_raw_cut_policy_cannot_be_relabelled_by_rehashing_frozen_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.transport_fixture(root, cut=True)
            actual = self.adapter.replay_transport(root)
            self.assertEqual((actual['cut']['mutation'], actual['cut']['phase']), (2, 'before'))
            inputs = json.loads((root / 'input.json').read_text())
            for key, value in (('unflushed', 'reverse-half'), ('phase', 'after-ack'), ('cut', 1)):
                forged = dict(inputs, **{key: value})
                (root / 'input.json').write_text(json.dumps(forged))
                (root / 'binding.json').write_text(json.dumps(dict(
                    input_sha256=self.adapter.sha256(root / 'input.json'))))
                artifacts = {path.relative_to(root).as_posix(): self.adapter.sha256(path)
                             for path in root.rglob('*')
                             if path.is_file() and path.name != 'summary.json'}
                (root / 'summary.json').write_text(json.dumps(dict(
                    status='NOT_RUN', nbd_trace=actual, artifacts=artifacts)))
                self.assertEqual(artifacts['input.json'], self.adapter.sha256(root / 'input.json'))
                with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'raw NBD fault policy'):
                    self.adapter.replay_transport(root)

    def test_raw_nbd_replay_checks_bytes_even_when_summary_is_forged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.transport_fixture(root)
            result = self.adapter.replay_transport(root)
            self.assertEqual(result['acknowledged_flushes'], 1)
            (root / 'summary.json').write_text(json.dumps(dict(nbd_trace=result, status='PASS')))
            (root / 'disk.raw').write_bytes(bytes(512))
            with self.assertRaisesRegex(ValueError, 'durable disk differs'):
                self.adapter.replay_transport(root)

    def test_archived_verifier_code_and_missing_inventory_cannot_select_a_checker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'summary.json').write_text(json.dumps(dict(status='PASS',
                native_filesystem_fault_matrix_complete=True, A10_complete=True)))
            with self.assertRaisesRegex(ValueError, 'matrix-input'):
                self.adapter.verify_matrix_receipt(root, source_root=ROOT)

    def identity_fixture(self, root):
        sources = self.adapter.code_source_map(ROOT)
        source_path = root / 'source-manifest.json'
        source_path.write_text(json.dumps(sources))
        build = dict(schema_version=1, status='BUILT_NOT_RUN', profiles=dict(
            selftest=True, storage_fault=True, fault='normal', leave=False),
            code_source_map=sources,
            code_source_sha256=hashlib.sha256(json.dumps(sources, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
            builder_sha256=self.adapter.sha256(ROOT / 'tools/build_unified.py'))
        build_path = root / 'build-manifest.json'
        build_path.write_text(json.dumps(build))
        tools = {}
        (root / 'tools').mkdir()
        for name in self.adapter.TOOL_NAMES:
            (root / 'tools' / name).write_bytes((ROOT / 'tools' / name).read_bytes())
            tools[name] = self.adapter.sha256(root / 'tools' / name)
        request = dict(build_manifest_sha256=self.adapter.sha256(build_path),
            source_manifest_sha256=self.adapter.sha256(source_path), tools=tools,
            qemu_attestation=dict(qemu_pmu_patch_attested=True, qemu_sha256='12'*32,
                qemu_source_commit=self.adapter.PINNED_QEMU_COMMIT,
                qemu_patch_sha256=self.adapter.PINNED_QEMU_PATCH_SHA256,
                qemu_source_sha256=self.adapter.PATCHED_QEMU_SOURCE_SHA256))
        (root / 'matrix-input.json').write_text(json.dumps(request))
        return request, build

    def test_fixed_tool_and_caller_source_binding_is_verified_without_running_archive_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, _ = self.identity_fixture(root)
            self.assertEqual(self.adapter.verify_matrix_identity(root, ROOT), request)
            request['qemu_attestation']['qemu_source_commit'] = '0' * 40
            (root / 'matrix-input.json').write_text(json.dumps(request))
            with self.assertRaisesRegex(ValueError, 'QEMU source/patch'):
                self.adapter.verify_matrix_identity(root, ROOT)

    def test_self_consistent_forged_source_and_archived_tool_hashes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, build = self.identity_fixture(root)
            build['code_source_map']['kernel/src/smp.rs'] = '0' * 64
            (root / 'source-manifest.json').write_text(json.dumps(build['code_source_map']))
            (root / 'build-manifest.json').write_text(json.dumps(build))
            for key, name in (('source_manifest_sha256', 'source-manifest.json'),
                              ('build_manifest_sha256', 'build-manifest.json')):
                request[key] = self.adapter.sha256(root / name)
            (root / 'matrix-input.json').write_text(json.dumps(request))
            with self.assertRaisesRegex(ValueError, 'build/source identity'):
                self.adapter.verify_matrix_identity(root, ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, _ = self.identity_fixture(root)
            name = 'verify_v13_a10.py'
            (root / 'tools' / name).write_text('raise RuntimeError("archive code must never run")')
            request['tools'][name] = self.adapter.sha256(root / 'tools' / name)
            (root / 'matrix-input.json').write_text(json.dumps(request))
            with self.assertRaisesRegex(ValueError, 'fixed reviewed local tools'):
                self.adapter.verify_matrix_identity(root, ROOT)

    def test_missing_tool_and_symlinked_archived_tool_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, _ = self.identity_fixture(root)
            name = 'verify_v13_a10.py'
            del request['tools'][name]
            (root / 'matrix-input.json').write_text(json.dumps(request))
            with self.assertRaisesRegex(ValueError, 'tool revisions'):
                self.adapter.verify_matrix_identity(root, ROOT)
            request['tools'][name] = self.adapter.sha256(ROOT / 'tools' / name)
            (root / 'matrix-input.json').write_text(json.dumps(request))
            (root / 'tools' / name).unlink()
            (root / 'tools' / name).symlink_to(ROOT / 'tools' / name)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                self.adapter.verify_matrix_identity(root, ROOT)

    def test_complete_coverage_still_cannot_promote_unreviewed_native_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix = dict(overwrite_points='all', recovery_points='all')
            names = ['prepare', 'overwrite-probe', 'cache-eviction']
            for phase in self.adapter.PHASES:
                for loss in self.adapter.LOSSES:
                    prefix = f'overwrite/p0001-{phase}-{loss}'
                    names += [prefix + '/cut', prefix + '/recovery-probe']
                    for recovery_phase in self.adapter.PHASES:
                        for recovery_loss in self.adapter.LOSSES:
                            nested = prefix + f'/recovery/r0001-{recovery_phase}-{recovery_loss}'
                            names += [nested + '/cut', nested + '/final']
            for name in names:
                (root / name).mkdir(parents=True)
                (root / name / 'summary.json').write_text('{}')
            coverage = dict(status='PASS', A10_complete=True,
                            native_filesystem_fault_matrix_complete=True)
            with patch.object(self.adapter, 'verify_matrix_identity', return_value=matrix), \
                 patch.object(self.adapter, 'mutation_schedule', return_value=[{'mutation': 1}]), \
                 patch.object(self.adapter, 'replay_child') as replay, \
                 patch.object(self.adapter, 'review', return_value=coverage):
                result = self.adapter.verify_matrix_receipt(root, source_root=ROOT)
            self.assertEqual(replay.call_count, 43)
            self.assertEqual(result['replayed_children'], 43)
            self.assertTrue(result['raw_matrix_verified'])
            self.assertEqual(result['native_acceptance_status'], 'NOT_RUN')
            self.assertFalse(result['native_execution_verified'])
            self.assertFalse(result['native_filesystem_fault_matrix_complete'])
            self.assertFalse(result['runtime_truth_attested'])
            self.assertTrue(result['native_admission_blockers'])


if __name__ == '__main__':
    unittest.main()
