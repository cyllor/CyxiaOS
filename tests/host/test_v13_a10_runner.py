"""Runner boundaries only; synthetic inputs never establish native A10 PASS."""
import hashlib
import importlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))


class A10Runner(unittest.TestCase):
    def setUp(self):
        try:
            self.runner = importlib.import_module('run_v13_a10')
        except ModuleNotFoundError as error:
            if error.name != 'run_v13_a10':
                raise
            self.fail('native single-mode A10 runner missing')

    def binding(self):
        return dict(mode=2, boot_epoch=8, nonce='11' * 16, uuid='22' * 16,
                    image_sha256='33' * 32, input_sha256='44' * 32, source_sha256='55' * 32)

    def test_config_binds_only_exact_preboot_identity_range(self):
        binding = self.binding()
        raw = self.runner.config_bytes(binding)
        self.assertEqual(len(raw), 512)
        self.assertEqual(struct.unpack_from('<4Q', raw), (0x4359584131304346, 1, 2, 8))
        for at, width, key in ((32,16,'nonce'), (48,32,'image_sha256'), (80,32,'input_sha256'),
                               (112,32,'source_sha256'), (144,16,'uuid')):
            self.assertEqual(raw[at:at+width].hex(), binding[key])
        self.assertEqual(raw[160:], bytes(352))
        for key, value in (('mode', 4), ('mode', True), ('boot_epoch', 0), ('nonce', '00'*16),
                           ('uuid', '22'*15), ('image_sha256', '33'*31)):
            bad = dict(binding, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.runner.config_bytes(bad)

    def test_completion_probe_requires_actual_exit_tags_not_user_stage(self):
        raw = bytearray(512)
        struct.pack_into('<Q', raw, 88, 8)  # forged user completion is insufficient
        self.assertFalse(self.runner.terminal_ready(raw, 1))
        struct.pack_into('<Q', raw, 256, 0x4359584131305052)
        self.assertFalse(self.runner.terminal_ready(raw, 2))
        self.assertTrue(self.runner.terminal_ready(raw, 3))
        struct.pack_into('<Q', raw, 0, 0x4359584131305052)
        # Failed exits are captured promptly; the independent verifier rejects
        # their exit codes rather than treating them as successful consumption.
        struct.pack_into('<Q', raw, 24, 211)
        self.assertTrue(self.runner.terminal_ready(raw, 1))

    def test_clean_capture_forbids_stop_and_graceful_quit_flushes(self):
        rows = [dict(direction='send', message=dict(execute='cont', id=1))]
        self.runner.validate_capture_commands(rows, cut_observed=False)
        for command in ('stop', 'quit'):
            bad = rows + [dict(direction='send', message=dict(execute=command, id=2))]
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.runner.validate_capture_commands(bad, cut_observed=False)
        stopped = rows + [dict(direction='send', message=dict(execute='stop', id=2))]
        self.runner.validate_capture_commands(stopped, cut_observed=True)
        with self.assertRaises(ValueError):
            self.runner.validate_capture_commands(stopped + stopped[1:], cut_observed=True)

    def oracle(self, sequence=2):
        from verify_v13_a10 import payload
        return dict(uuid='22'*16, boot_epoch=7, files={'/a10/value': dict(
            inode=5, generation=2, size=4096, durable_write_seq=sequence,
            sha256=hashlib.sha256(payload(sequence)).hexdigest())}, directories={'/': {}, '/a10': {}})

    def test_starting_image_must_match_the_selected_mode(self):
        fresh = dict(uuid='22'*16, boot_epoch=0, files={}, directories={'/': {}})
        self.assertEqual(self.runner.validate_start(fresh, 1)['boot_epoch'], 1)
        self.assertEqual(self.runner.validate_start(self.oracle(), 2)['prior_object'], (5, 2))
        self.assertEqual(self.runner.validate_start(self.oracle(3), 3)['boot_epoch'], 8)
        for oracle, mode in ((self.oracle(), 1), (fresh, 2), (self.oracle(3), 2)):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.runner.validate_start(oracle, mode)
        bad = self.oracle(); bad['files']['/a10/value']['sha256'] = '00'*32
        with self.assertRaises(ValueError): self.runner.validate_start(bad, 3)

    def test_default_unified_image_cannot_impersonate_storage_fault_profile(self):
        profile = dict(schema_version=1, status='BUILT_NOT_RUN', profiles=dict(
            fault='normal', leave=False, selftest=True, storage_fault=False))
        with self.assertRaisesRegex(ValueError, 'storage-fault'):
            self.runner.validate_build_profile(profile)
        profile['profiles']['storage_fault'] = True
        self.runner.validate_build_profile(profile)
        profile['profiles']['fault'] = 'controller-panic'
        with self.assertRaises(ValueError): self.runner.validate_build_profile(profile)

    def test_single_mode_or_cut_never_claims_complete_a10_acceptance(self):
        for cut in (False, True):
            result = self.runner.result_scope(cut)
            self.assertFalse(result['A10_complete'])
            self.assertFalse(result['native_filesystem_fault_matrix_complete'])
            self.assertFalse(result['runtime_truth_attested'])
            self.assertEqual(result['native_acceptance_status'], 'NOT_RUN')

    def test_executed_image_manifest_and_binary_changes_are_rejected(self):
        self.assertTrue(hasattr(self.runner, 'verify_unchanged'), 'frozen execution file guard missing')
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ('node-a.elf', 'build-manifest.json', 'qemu')]
            expected = {}
            for path in paths:
                path.write_bytes(path.name.encode())
                expected[path] = hashlib.sha256(path.read_bytes()).hexdigest()
            self.runner.verify_unchanged(expected)
            for path in paths:
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, 'changed frozen execution file'):
                    self.runner.verify_unchanged(expected)
                path.write_bytes(original)

    def test_fault_prefix_cannot_lose_or_replace_previously_acknowledged_file(self):
        self.assertTrue(hasattr(self.runner, 'validate_cut_oracle'), 'fault durable prefix guard missing')
        import copy
        before = self.oracle()
        after = self.oracle(3); after['boot_epoch'] += 1
        self.runner.validate_cut_oracle(before, after, 2)
        for key, value in (('inode', 6), ('generation', 3), ('durable_write_seq', 1), ('sha256', '00'*32)):
            bad = copy.deepcopy(after); bad['files']['/a10/value'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.runner.validate_cut_oracle(before, bad, 2)
        with self.assertRaises(ValueError):
            self.runner.validate_cut_oracle(self.oracle(3), self.oracle(2), 3)


if __name__ == '__main__':
    unittest.main()
