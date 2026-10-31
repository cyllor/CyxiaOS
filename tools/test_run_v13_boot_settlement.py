"""Diagnostic-only captures never authorize A01 PASS or suppress raw failures."""
import struct
import unittest
from unittest.mock import Mock

from run_v13_boot_recovery import capture_failure
from test_run_v13_boot_diagnostics import BootFailureDiagnostics


class BootSettlementCapture(unittest.TestCase):
    def fixture(self):
        base = BootFailureDiagnostics()
        base.setUp()
        base.symbols['model-debug'] = {'pa': 0x41000000, 'size': 512}
        base.symbols['control-settlement'] = {'pa': 0x41001000, 'size': 512}
        return base

    def test_extra_buffers_are_independent_stopped_diagnostics(self):
        base = self.fixture()
        result, events, saved, raw, _, _ = base.capture()
        self.assertEqual(len(saved), 6)
        self.assertEqual(result['failure_diagnostics']['model-debug']['fields']['actual_ns'], 0)
        self.assertNotIn('status', result['failure_diagnostics']['model-debug'])
        self.assertNotIn('native_acceptance_status', result)
        self.assertEqual(events[:2], ['stop', 'query-status'])
        self.assertNotIn('cont', events)
        self.assertEqual(raw, b'raw-serial')

    def test_missing_one_debug_buffer_keeps_other_debug_and_authority_bytes(self):
        result, _, saved, _, _, _ = self.fixture().capture(fail_key='model-debug')
        self.assertEqual(set(result['failure_capture_errors']), {'model-debug'})
        self.assertIn('failure-control-settlement.bin', saved)
        self.assertIn('failure-boot.bin', saved)
        self.assertIn('failure-runtime.bin', saved)

    def test_unbounded_debug_size_is_rejected_without_losing_core_captures(self):
        base = self.fixture()
        base.symbols['model-debug']['size'] = 8193
        result, _, saved, _, _, _ = base.capture()
        self.assertIn('model-debug', result['failure_capture_errors'])
        self.assertNotIn('failure-model-debug.bin', saved)
        self.assertEqual(len(saved), 5)

    def test_final_bill_fields_do_not_alias_checkpoint_or_model_verdict(self):
        base = self.fixture()
        words = [0] * 64
        words[16:19] = [8_100_000, 8_100_123, 400_000_000]
        words[19] = 9
        words[22:24] = [0, 5]
        words[27:29] = [2, 0]
        words[48:51] = [100_000_000, 1_100_000_000, 1]
        payload = struct.pack('<64Q', *words)
        qmp = Mock()
        qmp.execute.side_effect = [{}, {'status': 'paused'}, '']
        decoder = Mock()
        decoder.feed.return_value = []

        def save(name, address, size):
            if name == 'failure-model-debug.bin':
                return payload
            if name == 'failure-boot.bin':
                return struct.pack('<64Q', *base.sample)
            return bytes(size)

        result = capture_failure(qmp, save, base.symbols,
                                 struct.pack('<64Q', *base.config), decoder,
                                 bytearray(), bytearray())
        fields = result['failure_diagnostics']['model-debug']['fields']
        self.assertEqual(fields['actual_ns'], 8_100_000)
        self.assertEqual(fields['total_cpu_ns'], 8_100_123)
        self.assertEqual(fields['model_result'], 0)
        self.assertEqual(fields['terminal_cause'], 5)
        self.assertEqual(fields['cancel_won'], 1)
        self.assertEqual(result['failure_capture']['model_checkpoint_cpu_ns'], 0)


if __name__ == '__main__':
    unittest.main()
