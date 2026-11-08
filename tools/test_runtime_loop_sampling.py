"""Exercise the actual native snapshot seam before a session has terminated."""
import struct
import unittest

from decode_runtime_loop import decode_runtime_loop
import test_decode_runtime_loop as runtime_fixture
import test_verify_domains as domain_fixture
from verify_domains import refresh_snapshot


class RuntimeLoopSampling(unittest.TestCase):
    def snapshot(self, runtime):
        bundle = domain_fixture.EvidenceParserTests().snapshot()
        bundle['RUNTIME_LOOP_EVIDENCE'] = runtime
        return bundle

    def test_unpublished_terminal_diagnostic_does_not_abort_native_startup(self):
        raw = bytes(512)
        guest = {'runtime_loop': {'old': 'previous stopped snapshot'}}
        refresh_snapshot(guest, self.snapshot(raw))
        self.assertEqual(guest['runtime_loop_evidence'], [0] * 64)
        self.assertIsNone(guest['runtime_loop'])
        self.assertEqual(guest['progress_diagnostic_status']['runtime_loop'],
                         'not_published')
        with self.assertRaisesRegex(ValueError, 'publication is incomplete'):
            decode_runtime_loop(raw)

    def test_in_progress_terminal_diagnostic_remains_strict_and_raw(self):
        data = bytearray(runtime_fixture.RuntimeLoopDecoder().snapshot())
        struct.pack_into('<Q', data, 0, 17)
        guest = {'runtime_loop': {'old': 'previous completed record'}}
        with self.assertRaisesRegex(ValueError, 'publication is incomplete'):
            refresh_snapshot(guest, self.snapshot(data))
        self.assertEqual(guest['runtime_loop_evidence'],
                         list(struct.unpack('<64Q', data)))
        self.assertIsNone(guest['runtime_loop'])
        with self.assertRaisesRegex(ValueError, 'publication is incomplete'):
            decode_runtime_loop(data)

    def test_completed_terminal_diagnostic_uses_the_strict_decoder(self):
        data = runtime_fixture.RuntimeLoopDecoder().snapshot()
        guest = {}
        refresh_snapshot(guest, self.snapshot(data))
        self.assertEqual(guest['runtime_loop'], decode_runtime_loop(data))

    def test_unpublished_but_nonzero_or_truncated_bank_is_not_silently_ignored(self):
        nonzero = [0] * 64
        nonzero[1] = 1
        for raw in (domain_fixture.encode(nonzero), bytes(511)):
            with self.subTest(bytes=len(raw)), self.assertRaises(ValueError):
                refresh_snapshot({}, self.snapshot(raw))

    def test_malformed_completed_terminal_diagnostic_still_fails(self):
        data = bytearray(runtime_fixture.RuntimeLoopDecoder().snapshot())
        struct.pack_into('<Q', data, 40 * 8, 1)
        guest = {}
        with self.assertRaisesRegex(ValueError, 'reserved tail'):
            refresh_snapshot(guest, self.snapshot(data))
        self.assertEqual(guest['runtime_loop_evidence'],
                         list(struct.unpack('<64Q', data)))
        self.assertIsNone(guest['runtime_loop'])

    def test_optional_startup_bank_cannot_mask_an_authoritative_task_failure(self):
        bundle = self.snapshot(bytes(512))
        bundle['DOMAIN_TASK_EVIDENCE'] = domain_fixture.EvidenceParserTests().snapshot(
            overrun=True)['DOMAIN_TASK_EVIDENCE']
        guest = {}
        with self.assertRaisesRegex(ValueError, 'overrun/quarantine'):
            refresh_snapshot(guest, bundle)
        self.assertEqual(guest['runtime_loop_evidence'], [0] * 64)
        self.assertIsNone(guest['runtime_loop'])


if __name__ == '__main__':
    unittest.main()
