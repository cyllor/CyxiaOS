"""Diagnostic-vector integrity only; vectors are not native executions."""
import struct
import unittest

import decode_application_requests as decoder
import test_verify_domains as fixtures
from verify_domains import refresh_snapshot


class ApplicationQueueDiagnostic(unittest.TestCase):
    def bank(self):
        words = [0] * decoder.WORDS
        words[:8] = [8, decoder.MAGIC, 1, 32, 24, 4, 0, 0]
        words[8:32] = [4097, 7, 44, 8, 1, 100, 300, 4, 0, 5, 0, 0,
                       0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 200]
        return words

    def packed(self, words):
        return struct.pack(f'<{len(words)}Q', *words)

    def test_distinguishes_queued_handoff_unknown_without_claiming_completion(self):
        result = decoder.decode(self.packed(self.bank()))
        row = result['rows'][0]
        self.assertEqual(row['request'], [4097, 7])
        self.assertEqual(row['stage_counts']['next'], 1)
        self.assertEqual(row['state'], 5)
        self.assertIsNone(row['completion_outcome'])
        self.assertFalse(result['native_acceptance_verified'])
        self.assertFalse(result['complete_history'])

    def test_rejects_torn_truncated_mismatched_identity_and_fabricated_completion(self):
        for index, value in ((0, 7), (5, 5), (8, 4098), (16, 1),
                             (8 + 12, 1), (8 + 15, 0), (8 + 6, 99)):
            with self.subTest(index=index, value=value):
                bank = self.bank()
                bank[index] = value
                with self.assertRaises(ValueError):
                    decoder.decode(self.packed(bank))
        with self.assertRaises(ValueError):
            decoder.decode(self.packed(self.bank())[:-1])

    def test_snapshot_keeps_interrupted_bank_raw_and_clears_previous_decode(self):
        bundle = fixtures.EvidenceParserTests().snapshot()
        raw = self.bank()
        raw[0] |= 1
        bundle['APPLICATION_REQUEST_EVIDENCE'] = self.packed(raw)
        guest = {'application_requests': {'old': 'prior stopped bank'}}
        refresh_snapshot(guest, bundle)
        self.assertEqual(guest['application_request_evidence'], raw)
        self.assertIsNone(guest['application_requests'])
        self.assertEqual(guest['progress_diagnostic_status']['application_requests'],
                         'in_progress')
        bundle['APPLICATION_REQUEST_EVIDENCE'] = self.packed(self.bank())
        refresh_snapshot(guest, bundle)
        self.assertEqual(guest['application_requests']['rows'][0]['state'], 5)
        bundle.pop('APPLICATION_REQUEST_EVIDENCE')
        refresh_snapshot(guest, bundle)
        self.assertIsNone(guest['application_request_evidence'])
        self.assertIsNone(guest['application_requests'])


if __name__ == '__main__':
    unittest.main()
