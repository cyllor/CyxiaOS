"""Local diagnostic integrity vectors, never synthetic native PASS receipts."""
import struct
import unittest

import decode_local_requests as decoder
import test_verify_domains as fixtures
from verify_domains import refresh_snapshot


class LocalRequestDiagnostic(unittest.TestCase):
    def bank(self):
        words = [0] * decoder.WORDS
        words[:8] = [6, decoder.MAGIC, 1, 8, 32, 3, 0, 0]
        words[8:40] = [4097, 1, 1, 12, 0, 24, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 1_000_000_000, 100, 200,
                        1, 2, 0, 1, 2, 12, 0, 0, 32, 0, 0, 0, 0, 0]
        return words

    def packed(self, words):
        return struct.pack(f'<{len(words)}Q', *words)

    def test_actual_queued_query_and_explicit_no_custody_retry_are_distinct(self):
        row = decoder.decode(self.packed(self.bank()))['rows'][0]
        self.assertEqual(row['spawn_state'], 'Queued')
        self.assertEqual(row['owner_spawn_state'], 'Queued')
        self.assertEqual(row['submit_calls'], 1)
        self.assertEqual(row['query_calls'], 2)
        self.assertFalse(row['retryable'])
        bank = self.bank()
        bank[:8] = [2, decoder.MAGIC, 1, 8, 32, 1, 0, 0]
        r = bank[8:40]
        r[3:9] = [11, 1, 0, 0, 10, 3]
        r[12] = 1
        r[18:26] = [1, 0, 0, 1, 0, 11, 2**64 - 1, 10]
        bank[8:40] = r
        row = decoder.decode(self.packed(bank))['rows'][0]
        self.assertEqual(row['spawn_state'], 'Unknown')
        self.assertTrue(row['retryable'])
        self.assertEqual(row['owner_error'], 10)

    def test_unknown_after_deadline_does_not_become_a_completion(self):
        bank = self.bank()
        bank[8 + 8] = bank[8 + 24] = 3
        bank[8 + 17] = 2_000_000_000
        result = decoder.decode(self.packed(bank))
        row = result['rows'][0]
        self.assertEqual(row['spawn_state'], 'Unknown')
        self.assertFalse(row['completion_retained'])
        self.assertFalse(result['native_acceptance_verified'])
        self.assertFalse(result['complete_history'])

    def test_successful_query_can_retain_a_real_failed_spawn(self):
        bank = self.bank()
        bank[8 + 8] = bank[8 + 24] = 2
        bank[8 + 9] = bank[8 + 25] = 11
        row = decoder.decode(self.packed(bank))['rows'][0]
        self.assertEqual(row['spawn_state'], 'Failed')
        self.assertEqual(row['spawn_error'], 11)
        self.assertIsNone(row['owner_error'])

    def test_rejects_torn_truncated_wrong_identity_and_fake_created_completion(self):
        for index, value in ((0, 5), (5, 4), (8 + 2, 2), (8 + 8, 1),
                             (8 + 13, 1), (8 + 16, 300), (8 + 30, 1),
                             (8 + 23, 27), (8 + 18, 0)):
            with self.subTest(index=index, value=value):
                bank = self.bank()
                bank[index] = value
                with self.assertRaises(ValueError):
                    decoder.decode(self.packed(bank))
        with self.assertRaises(ValueError):
            decoder.decode(self.packed(self.bank())[:-1])

    def test_snapshot_preserves_raw_in_progress_and_clears_stale_decode(self):
        bundle = fixtures.EvidenceParserTests().snapshot()
        raw = self.bank()
        raw[0] |= 1
        bundle['LOCAL_REQUEST_EVIDENCE'] = self.packed(raw)
        guest = {'local_requests': {'old': 'prior stopped sample'}}
        refresh_snapshot(guest, bundle)
        self.assertEqual(guest['local_request_evidence'], raw)
        self.assertIsNone(guest['local_requests'])
        self.assertEqual(guest['progress_diagnostic_status']['local_requests'], 'in_progress')
        bundle['LOCAL_REQUEST_EVIDENCE'] = self.packed(self.bank())
        refresh_snapshot(guest, bundle)
        self.assertEqual(guest['local_requests']['rows'][0]['spawn_state'], 'Queued')
        bundle.pop('LOCAL_REQUEST_EVIDENCE')
        refresh_snapshot(guest, bundle)
        self.assertIsNone(guest['local_request_evidence'])
        self.assertIsNone(guest['local_requests'])


if __name__ == '__main__':
    unittest.main()
