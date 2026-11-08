import struct
import unittest
from pathlib import Path

from decode_runtime_loop import decode_runtime_loop


class RuntimeLoopDecoder(unittest.TestCase):
    def snapshot(self):
        words = [0] * 64
        words[:8] = [16, 0x4359_5254_4c4f_4f31, 1, 8, 7, 3, 9, 0]
        record = [
            1, 9, 42, 100, 900, 1200, 300, 600, 900,
            40, 910, 950, 80, 960, 1040, 50, 970, 1020,
            30, 1020, 1050, 20, 1060, 1080, 90, 1090, 1180,
            875, 1200, 12, 0, 0,
        ]
        words[8:40] = record
        return struct.pack('<64Q', *words)

    def test_decodes_bounded_stopped_snapshot(self):
        result = decode_runtime_loop(self.snapshot())
        self.assertEqual(result['boot_epoch'], 7)
        self.assertEqual(result['service_generation'], 3)
        self.assertEqual(result['connection_epoch'], 9)
        self.assertEqual(result['reports'], 8)
        self.assertEqual(result['loops'], 42)
        self.assertEqual(result['max_loop_gap'],
                         {'duration_ns': 300, 'started_ns': 600, 'finished_ns': 900})
        self.assertEqual(result['segments']['ingest']['duration_ns'], 80)
        self.assertEqual(result['segments']['handle']['finished_ns'], 1020)
        self.assertEqual(result['segments']['post_admission']['started_ns'], 1020)
        self.assertEqual(result['segments']['egress']['duration_ns'], 90)
        self.assertEqual(result['last_liveness_attempt_ns'], 875)
        self.assertEqual(result['exit'], {'at_ns': 1200, 'reason': 12, 'result': 0})
        self.assertIn('zero does not exclude', result['scope'])
        self.assertIn('never the current active session', result['scope'])

    def test_rejects_in_progress_or_non_monotonic_snapshot(self):
        data = bytearray(self.snapshot())
        struct.pack_into('<Q', data, 0, 3)
        with self.assertRaisesRegex(ValueError, 'publication'):
            decode_runtime_loop(bytes(data))
        data = bytearray(self.snapshot())
        struct.pack_into('<Q', data, (8 + 20) * 8, 900)
        with self.assertRaisesRegex(ValueError, 'post_admission'):
            decode_runtime_loop(bytes(data))
        data = bytearray(self.snapshot())
        struct.pack_into('<Q', data, (8 + 6) * 8, 299)
        with self.assertRaisesRegex(ValueError, 'loop_gap'):
            decode_runtime_loop(bytes(data))
        data = bytearray(self.snapshot())
        struct.pack_into('<Q', data, (8 + 10) * 8, 99)
        with self.assertRaisesRegex(ValueError, 'receive'):
            decode_runtime_loop(bytes(data))
        data = bytearray(self.snapshot())
        struct.pack_into('<Q', data, (8 + 27) * 8, 99)
        with self.assertRaisesRegex(ValueError, 'liveness attempt'):
            decode_runtime_loop(bytes(data))

    def test_rejects_invalid_exit_reason_report_count_and_reserved_tail(self):
        for word, value, message in (
            (8 + 29, 17, 'exit reason'),
            (0, 18, 'publication/report count'),
            (40, 1, 'reserved tail'),
        ):
            with self.subTest(word=word):
                data = bytearray(self.snapshot())
                struct.pack_into('<Q', data, word * 8, value)
                with self.assertRaisesRegex(ValueError, message):
                    decode_runtime_loop(bytes(data))

    def test_terminal_publication_follows_authority_and_socket_teardown(self):
        source = (Path(__file__).parents[1] /
                  'user/prototype-cluster/src/runtime.rs').read_text()
        self.assertIn('let mut state = SessionState::new(epoch, ticket);', source)
        self.assertIn('if let Err(exit) = session_turn(', source)
        tail = source[source.index('let unauthenticated_exit = state.authenticated.is_none();'):]
        self.assertLess(tail.index('driver.disconnect();'), tail.index('state.timing.report('))
        self.assertLess(tail.index('broker::close();'), tail.index('state.timing.report('))
        self.assertLess(tail.index('ingress.leave_authenticated_at('),
                        tail.index('state.timing.report('))


if __name__ == '__main__':
    unittest.main()
