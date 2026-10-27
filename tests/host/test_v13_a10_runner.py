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
        for key, value in (('mode', 5), ('mode', True), ('boot_epoch', 0), ('nonce', '00'*16),
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
        self.assertTrue(self.runner.terminal_ready(raw, 4))
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
        self.assertEqual(self.runner.validate_start(self.oracle(3), 4)['boot_epoch'], 8)
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

    def test_runner_uses_the_complete_current_control_evidence_bank(self):
        self.assertEqual(self.runner.CONTROL_EVIDENCE_BYTES, (512 + 64 * 640) * 8)
        self.assertEqual(self.runner.LAYOUT, (1, 512, 768, 384, 295424, 299008, 512, 512))

    def test_timeout_diagnostics_include_unified_startup_stage(self):
        self.assertIn(('UNIFIED_EVIDENCE', 'unified-runtime', 4096),
                      self.runner.diagnostic_specs())
        self.assertIn(('DOMAIN_TASK_EVIDENCE', 'domain-task', 256),
                      self.runner.diagnostic_specs())
        self.assertIn(('RUNTIME_V13_EVIDENCE', 'runtime-v13', 8192),
                      self.runner.diagnostic_specs())
        self.assertIn(('DYNAMIC_V13_EVIDENCE', 'dynamic-v13', 4096),
                      self.runner.diagnostic_specs())
        self.assertIn(('UNIFIED_SERVICE_STAGE', 'unified-service-stage', 8),
                      self.runner.diagnostic_specs())

    def test_slow_run_samples_minimal_startup_diagnostics_without_control_bank(self):
        self.assertEqual(self.runner.PENDING_DIAGNOSTICS,
                         ('domain-task', 'unified-runtime', 'unified-service-stage'))
        self.assertNotIn('control-header', self.runner.PENDING_DIAGNOSTICS)

    def test_progress_sampling_is_bounded_and_converted_to_seconds(self):
        self.assertEqual(self.runner.sample_interval(100), 0.1)
        self.assertEqual(self.runner.sample_interval(2000), 2.0)
        self.assertEqual(self.runner.sample_interval(30000), 30.0)
        for value in (99, 30001, 100.0, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.runner.sample_interval(value)

    def test_scenario_budget_is_mode_specific_and_source_bound(self):
        expected = {
            1: (1_800_000_000_000, 20_000_000_000, 1920.0),
            2: (1_800_000_000_000, 20_000_000_000, 1920.0),
            3: (1_800_000_000_000, 20_000_000_000, 1920.0),
            4: (21_600_000_000_000, 240_000_000_000, 21_720.0),
        }
        for mode, (client_ns, poll_ns, capture_seconds) in expected.items():
            with self.subTest(mode=mode):
                budget = self.runner.scenario_budget(self.runner.ROOT, mode)
                self.assertEqual(budget['client_deadline_ns'], client_ns)
                self.assertEqual(budget['client_poll_ns'], poll_ns)
                self.assertEqual(budget['capture_timeout_seconds'], capture_seconds)
        for mode in (0, 5, True):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.runner.scenario_budget(self.runner.ROOT, mode)

    def test_only_non_schedule_clean_modes_allow_qemu_request_merging(self):
        self.assertEqual(self.runner.request_merging(1, 0), 'on')
        self.assertEqual(self.runner.request_merging(4, 0), 'on')
        for mode in (2, 3):
            self.assertEqual(self.runner.request_merging(mode, 0), 'off')
        for mode in range(1, 5):
            self.assertEqual(self.runner.request_merging(mode, 1), 'off')
            self.assertEqual(self.runner.request_merging(mode, 4096), 'off')

    def test_explicit_qemu_path_is_attested_and_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'qemu-system-aarch64'
            binary.write_text('#!/bin/sh\necho "QEMU emulator version 10.2.2"\n')
            binary.chmod(0o700)
            selected, proof = self.runner.resolve_qemu(binary, None)
            self.assertEqual(selected, binary.resolve())
            self.assertEqual(proof['qemu_version'].splitlines()[0],
                             'QEMU emulator version 10.2.2')
            self.assertFalse(proof['qemu_pmu_patch_attested'])

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
