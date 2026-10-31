"""Host-only A01 failure diagnostics; these fixtures never establish native PASS."""
import base64
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from run_v13_boot_evidence import preserve_and_verify
from run_v13_boot_recovery import capture_failure, stopped_boot_state
from test_verify_v13_boot_recovery import fixture, packed


class BootFailureDiagnostics(unittest.TestCase):
    def setUp(self):
        self.sample, _, self.config = fixture(0)
        self.sample[3:8] = [2, 3, 0, 0, 0]
        self.sample[14:25] = [0] * 11
        self.symbols = {key: {'pa': 0x40200000 + index * 0x4000}
                        for index, key in enumerate(('boot', 'control', 'runtime', 'unified'))}

    def test_mount_failure_is_distinct_from_selftest_and_no_epoch_is_invented(self):
        result = stopped_boot_state(packed(self.sample), packed(self.config))
        self.assertEqual((result['state'], result['reason_name'], result['epoch']), (2, 'mount', 0))
        self.assertEqual(result['model_turns'], 0)
        self.assertNotIn('native_acceptance_status', result)
        self.assertNotIn('status', result)

    def test_torn_wrong_version_and_mixed_identity_records_are_rejected(self):
        for index, value in ((2, 1), (0, 0), (1, 2), (5, 3), (32, self.sample[32] ^ 1)):
            with self.subTest(index=index):
                changed = self.sample.copy()
                changed[index] = value
                with self.assertRaises(ValueError):
                    stopped_boot_state(packed(changed), packed(self.config))
        with self.assertRaises(ValueError):
            stopped_boot_state(packed(self.sample)[:-1], packed(self.config))

    def capture(self, *, odd=False, fail_key=None, paused=True, overflow=False):
        events, saved = [], {}
        sample = self.sample.copy()
        if odd:
            sample[2] |= 1
        payload = b'raw-serial'

        def execute(command, args=None):
            events.append(command)
            if command == 'stop':
                return {}
            if command == 'query-status':
                return {'status': 'paused' if paused else 'running'}
            if command == 'ringbuf-read':
                return base64.b64encode(payload).decode()
            raise AssertionError('unexpected command: ' + command)

        def save(name, address, size):
            self.assertEqual(events[:2], ['stop', 'query-status'])
            key = name.removeprefix('failure-').removesuffix('.bin')
            self.assertEqual(address, self.symbols[key]['pa'])
            self.assertIn(size, (512, 4096, 8192))
            events.append(name)
            if key == fail_key:
                raise OSError('simulated capture failure')
            data = packed(sample) if key == 'boot' else bytes(size)
            saved[name] = data
            return data

        decoder = Mock()
        decoder.feed.return_value = [b'decoded-serial']
        raw = bytearray(8 * 1024 * 1024) if overflow else bytearray()
        text = bytearray()
        result = capture_failure(Mock(execute=execute), save, self.symbols,
                                 packed(self.config), decoder, raw, text)
        return result, events, saved, raw, text, decoder

    def test_stopped_capture_keeps_all_authority_buffers_and_raw_serial(self):
        result, events, saved, raw, text, _ = self.capture()
        self.assertEqual(result['failure_capture']['reason_name'], 'mount')
        self.assertNotIn('failure_capture_errors', result)
        self.assertEqual(len(saved), 4)
        self.assertEqual(raw, b'raw-serial')
        self.assertEqual(text, b'decoded-serial\n')
        self.assertEqual(events[-1], 'ringbuf-read')
        self.assertNotIn('cont', events)

    def test_torn_snapshot_is_retained_without_suppressing_other_evidence(self):
        result, _, saved, raw, _, _ = self.capture(odd=True)
        self.assertNotIn('failure_capture', result)
        self.assertIn('boot', result['failure_capture_errors'])
        self.assertEqual(len(saved), 4)
        self.assertEqual(raw, b'raw-serial')

    def test_one_capture_error_does_not_discard_independent_captures(self):
        result, _, saved, raw, _, _ = self.capture(fail_key='control')
        self.assertEqual(set(result['failure_capture_errors']), {'control'})
        self.assertIn('failure-runtime.bin', saved)
        self.assertIn('failure-unified.bin', saved)
        self.assertEqual(raw, b'raw-serial')

    def test_no_memory_capture_without_stopped_confirmation(self):
        result, events, saved, raw, _, _ = self.capture(paused=False)
        self.assertEqual(events, ['stop', 'query-status'])
        self.assertEqual(saved, {})
        self.assertEqual(raw, b'')
        self.assertIn('stop', result['failure_capture_errors'])

    def test_serial_limit_is_not_relaxed_during_failure_cleanup(self):
        result, _, saved, raw, text, decoder = self.capture(overflow=True)
        self.assertEqual(len(saved), 4)
        self.assertEqual(len(raw), 8 * 1024 * 1024)
        self.assertEqual(text, b'')
        self.assertIn('serial', result['failure_capture_errors'])
        decoder.feed.assert_not_called()

    def test_failed_producer_is_preserved_but_never_sent_to_pass_verifier(self):
        with patch('run_v13_boot_evidence.preserve_evidence',
                   return_value={'status': 'FAIL', 'error': 'mount'}) as preserve, \
             patch('run_v13_boot_evidence.verify_receipt') as verify:
            with self.assertRaisesRegex(ValueError, '^mount$'):
                preserve_and_verify(Path('/unused'), Path('/unused'), Path('/unused'), {})
            preserve.assert_called_once()
            verify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
