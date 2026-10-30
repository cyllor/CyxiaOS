"""Capture producer tests; host executions never count as native acceptance."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


class A02NativeProducer(unittest.TestCase):
    def test_unreviewed_capture_tool_pair_is_rejected(self):
        import verify_v13_a02
        self.assertTrue(hasattr(verify_v13_a02, 'verify_capture_revision'), 'capture revision guard missing')
        for pair in (('0' * 64, '1' * 64),
                     ('0' * 64, 'b59af78493b056a8ece7911584d7dc91cb55af3e17309aea81c3bb4b000631ef')):
            with self.subTest(pair=pair), self.assertRaisesRegex(ValueError, 'unreviewed runner/verifier revision'):
                verify_v13_a02.verify_capture_revision(*pair)

    def test_recorded_native_capture_replays_only_against_matching_explicit_source(self):
        import inspect
        import verify_v13_a02
        self.assertIn('source_root', inspect.signature(verify_v13_a02.verify_native_receipt).parameters,
                      'explicit frozen source checkout is missing')
        capture = ROOT / 'artifacts/a02-native-20261026-paused-status-v4'
        frozen = ROOT / 'artifacts/v13-batched-source-20261026'
        if not capture.is_dir() or not frozen.is_dir():
            self.skipTest('historical native capture is not present; synthetic PASS fixtures are prohibited')
        result = verify_v13_a02.verify_native_receipt(capture, source_root=frozen)
        self.assertEqual(result['native_acceptance_status'], 'PASS')
        self.assertTrue(result['native_execution_verified'])
        self.assertFalse(result['runtime_truth_attested'])
        with tempfile.TemporaryDirectory() as directory:
            # An explicit unrelated checkout must not inherit the receipt's source.
            subprocess.run(['git', 'init', '-q', directory], check=True)
            with self.assertRaisesRegex(ValueError, 'incomplete native source checkout'):
                verify_v13_a02.verify_native_receipt(capture, source_root=Path(directory))

    def test_stopped_qmp_status_accepts_current_and_legacy_paused_reply(self):
        import verify_v13_a02
        self.assertTrue(hasattr(verify_v13_a02, 'verify_stopped_status'), 'stopped status validator missing')
        for status in ({'status': 'paused', 'running': False},
                       {'status': 'paused', 'running': False, 'singlestep': False}):
            with self.subTest(status=status):
                verify_v13_a02.verify_stopped_status([status])

    def test_stopped_qmp_status_rejects_running_unpaused_and_duplicate_reply(self):
        import verify_v13_a02
        self.assertTrue(hasattr(verify_v13_a02, 'verify_stopped_status'), 'stopped status validator missing')
        paused = {'status': 'paused', 'running': False}
        for statuses in ([], [paused, paused], [{'status': 'paused', 'running': True}],
                         [{'status': 'running', 'running': False}],
                         [{'status': 'paused', 'running': False, 'singlestep': True}],
                         [{'status': 'paused', 'running': 0}], [{'status': 'paused'}]):
            with self.subTest(statuses=statuses):
                with self.assertRaisesRegex(ValueError, 'stopped VM status'):
                    verify_v13_a02.verify_stopped_status(statuses)

    def test_duplicate_receipt_keys_and_nonfinite_json_are_rejected(self):
        import verify_v13_a02
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for text, error in (( '{"artifacts":{},"artifacts":{}}', 'Duplicate JSON key'),
                                ('{"artifacts":NaN}', 'Invalid number')):
                with self.subTest(text=text):
                    (root / 'summary.json').write_text(text)
                    with self.assertRaisesRegex(ValueError, error):
                        verify_v13_a02.verify_native_receipt(root)

    def test_native_artifact_reader_rejects_symlink_ancestors_inside_root(self):
        import verify_v13_a02
        self.assertTrue(hasattr(verify_v13_a02, 'native_document'), 'strict native artifact reader missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'real').mkdir()
            (root / 'real/input.json').write_text('{}')
            (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                verify_v13_a02.native_document(root, 'alias/input.json')

    def test_qmp_jsonl_rejects_duplicate_keys_and_nonfinite_values(self):
        import verify_v13_a02
        self.assertTrue(hasattr(verify_v13_a02, 'read_native_qmp'), 'strict QMP JSONL reader missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for text, error in (('{"message":{"id":1,"id":2}}\n', 'Duplicate JSON key'),
                                ('{"message":{"timestamp":Infinity}}\n', 'Invalid number')):
                (root / 'qmp.jsonl').write_text(text)
                with self.assertRaisesRegex(ValueError, error):
                    verify_v13_a02.read_native_qmp(root)

    def test_local_native_verification_is_not_runtime_attestation(self):
        import verify_v13_a02
        self.assertTrue(hasattr(verify_v13_a02, 'execution_flags'), 'local verification flags missing')
        self.assertEqual(verify_v13_a02.execution_flags(True),
                         {'native_execution_verified': True, 'runtime_truth_attested': False})
        self.assertEqual(verify_v13_a02.execution_flags(False),
                         {'native_execution_verified': False, 'runtime_truth_attested': False})

    def test_preboot_debugger_write_is_exactly_the_config_range(self):
        import run_v13_a02
        self.assertTrue(hasattr(run_v13_a02, 'config_write_packet'), 'preboot config injection is missing')
        config = run_v13_a02.config_bytes('11' * 32, '22' * 32, '33' * 32, bytes.fromhex('44' * 16))
        payload = f'M40800000,200:{config.hex()}'.encode()
        self.assertEqual(run_v13_a02.config_write_packet(config, 0x40800000),
                         b'$' + payload + f'#{sum(payload) % 256:02x}'.encode())

    def test_native_receipt_rejects_a_producer_pass_boolean(self):
        import verify_v13_a02
        self.assertTrue(hasattr(verify_v13_a02, 'verify_native_receipt'),
                        'independent native receipt adapter is missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'summary.json').write_text('{"status":"PASS","runtime_truth_attested":true}')
            with self.assertRaises((ValueError, OSError)):
                verify_v13_a02.verify_native_receipt(root)

    def test_preboot_config_binds_exact_artifacts_and_run_nonce_only(self):
        self.assertTrue((ROOT / 'tools/run_v13_a02.py').is_file(), 'native A02 runner is missing')
        import run_v13_a02
        import struct
        raw = run_v13_a02.config_bytes('11' * 32, '22' * 32, '33' * 32, bytes.fromhex('44' * 16))
        self.assertEqual(len(raw), 512)
        self.assertEqual(struct.unpack_from('<2Q', raw), (0x4359584130324346, 2))
        self.assertEqual(raw[16:32], bytes.fromhex('44' * 16))
        self.assertEqual(raw[32:128], bytes.fromhex('11' * 32 + '22' * 32 + '33' * 32))
        self.assertEqual(raw[128:], bytes(384))
        for nonce in (bytes(16), bytes(15)):
            with self.assertRaises(ValueError):
                run_v13_a02.config_bytes('11' * 32, '22' * 32, '33' * 32, nonce)

    def test_protected_capture_records_actual_boundaries_and_fails_closed(self):
        source = ROOT / 'kernel/src/a02_capture/state.rs'
        self.assertTrue(source.is_file(), 'native A02 capture state is missing')
        rustc = shutil.which('rustc') or str(Path.home() / '.cargo/bin/rustc')
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'capture-tests')
            result = subprocess.run([rustc, '--edition=2024', '--test', str(source), '-o', binary],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('0 failed', result.stdout)

    def test_control_capture_preparation_is_bound_to_current_identity(self):
        source = (ROOT / 'kernel/src/prototype_runtime/native.rs').read_text()
        run = source[source.index('fn run_turn('):source.index('fn charge_turn(')]
        self.assertIn('let task = capture_task(slot);', run)
        compact = ''.join(run.split())
        self.assertIn('.capture.prepare(task,crate::a02_capture::prepare)', compact)
        self.assertIn('worker.native.capture.index(task)', compact)
        self.assertNotIn('worker.native.capture_index', source)

    def test_capture_contention_sleeps_until_a_published_unlock_event(self):
        source = (ROOT / 'kernel/src/a02_capture.rs').read_text()
        lock = source[source.index('fn locked<R>'):source.index('/// CPU0, before')]
        self.assertIn('.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)', lock)
        self.assertNotIn('compare_exchange_weak', lock)
        self.assertIn('WAITERS.store(true, Ordering::Release)', lock)
        self.assertIn('if LOCK.load(Ordering::Acquire)', lock)
        self.assertIn('core::arch::asm!("wfe"', lock)
        self.assertIn('LOCK.store(false, Ordering::Release)', lock)
        self.assertIn('WAITERS.load(Ordering::Acquire)', lock)
        self.assertIn('WAITERS.swap(false, Ordering::AcqRel)', lock)
        self.assertIn('core::arch::asm!("dsb ishst", "sev"', lock)


if __name__ == '__main__':
    unittest.main()
