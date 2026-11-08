"""Engineering vectors for the exact phase-9 observation producer layout."""
import struct
import unittest

import decode_session_activity as decoder
import test_verify_domains as fixtures
from verify_domains import refresh_snapshot


class SessionActivityDecoder(unittest.TestCase):
    def bank(self):
        # Mirrors the actual Authority/phase-9 sequence tested in
        # tests/host/test_session_activity_observation.py, with snapshot boot7.
        words = [0] * decoder.WORDS
        words[:8] = [decoder.MAGIC, 1, 104, 24, 5, 3, 2, 1]
        rows = [
            [2, 1, 7, 1, 7, 7, 1, 100, 0, 0, 0, 1, 0, 0, 7, 1, 100, 1],
            [2, 3, 7, 3, 7, 7, 1, 3099, 7, 1, 1599, 1, 3, 3, 7, 0, 1599, 2],
            [6, 4, 7, 3, 7, 7, 0, 3200, 7, 0, 1599, 2, 3, 1, 7, 0, 1599, 2],
            [10, 5, 7, 1, 8, 7, 1, 4000, 7, 0, 1599, 2, 3, 1, 7, 0, 1599, 2],
        ]
        for slot, row in enumerate(rows):
            words[8 + slot * 24:8 + slot * 24 + 18] = row
        return words

    def packed(self, words):
        return struct.pack(f'<{len(words)}Q', *words)

    def test_actual_clock_expiry_transport_and_first_failure_are_distinct(self):
        result = decoder.decode(self.packed(self.bank()), boot=7)
        self.assertEqual(result['status'], 'sampled')
        self.assertEqual(result['counts'], {'total': 5, 'activity': 3,
            'rejected_activity': 2, 'accepted_activity': 1})
        records = result['records']
        self.assertEqual(records['first_registered']['fresh_ms'], 100)
        self.assertEqual(records['first_activity_failure']['fresh_ms'], 3099)
        self.assertEqual(records['first_activity_failure']['reason'], 'not_ready')
        self.assertEqual(records['first_activity_failure']['before']['last_rx_ms'], 1599)
        self.assertEqual(records['first_activity_failure']['after']['last_rx_ms'], 1599)
        self.assertEqual(records['latest_activity']['reason'], 'transport_or_epoch')
        self.assertFalse(result['native_acceptance_verified'])
        self.assertFalse(result['complete_history'])

    def test_unpublished_and_partially_written_rows_never_become_completed(self):
        absent = decoder.decode(bytes(832))
        self.assertFalse(absent['present'])
        self.assertEqual(absent['status'], 'not_published')
        initial = [decoder.MAGIC, 1, 104, 24] + [0] * 100
        self.assertEqual(decoder.decode(self.packed(initial))['status'], 'not_published')
        words = self.bank()
        words[8 + 2 * 24] |= 1
        result = decoder.decode(self.packed(words))
        self.assertEqual(result['status'], 'in_progress')
        self.assertEqual(result['in_progress_rows'], ['latest_activity'])
        self.assertNotIn('latest_activity', result['records'])
        self.assertIn('first_activity_failure', result['records'])

    def test_header_counter_updates_before_rows_are_marked_in_progress(self):
        words = self.bank()
        words[4] += 1
        words[5] += 1
        result = decoder.decode(self.packed(words))
        self.assertEqual(result['status'], 'in_progress')
        self.assertTrue(result['counters_in_progress'])
        self.assertEqual(result['records']['latest']['ordinal'], 5)

    def test_v2_actual_broker_stage_times_are_ordered_and_v1_stays_strict(self):
        words = self.bank()
        words[1] = 2
        for slot in range(4):
            row = 8 + slot * 24
            fresh = words[row + 7]
            words[row + 18:row + 21] = [fresh - 600, fresh - 500, fresh - 1] if fresh >= 600 else [0, 1, 2]
        result = decoder.decode(self.packed(words), boot=7)
        self.assertEqual(result['records']['first_activity_failure']['broker_timing'],
            {'request_entry_ms': 2499, 'network_finished_ms': 2599, 'credit_acquired_ms': 3098})
        words[8 + 24 + 19] = 2498
        with self.assertRaisesRegex(ValueError, 'broker time ordering'):
            decoder.decode(self.packed(words))
        words = self.bank()
        words[8 + 18] = 1
        with self.assertRaisesRegex(ValueError, 'invalid session-activity record'):
            decoder.decode(self.packed(words))

    def test_rejects_bad_header_truncation_and_completed_record_corruption(self):
        cases = [(0, 0), (2, 103), (3, 23), (6, 4),
                 (8 + 1, 6), (8 + 6, 2), (8 + 12, 3),
                 (8 + 18, 1), (8 + 24 + 15, 1),
                 (8 + 2 * 24 + 13, 0), (8 + 3 * 24 + 5, 8)]
        for at, value in cases:
            with self.subTest(at=at, value=value):
                words = self.bank()
                words[at] = value
                with self.assertRaises(ValueError):
                    decoder.decode(self.packed(words))
        with self.assertRaises(ValueError):
            decoder.decode(self.packed(self.bank())[:-1])
        with self.assertRaisesRegex(ValueError, 'BootEpoch'):
            decoder.decode(self.packed(self.bank()), boot=8)

    def test_expired_activity_cannot_be_relabelled_as_successful_renewal(self):
        words = self.bank()
        row = 8 + 2 * 24
        words[row:row + 18] = [8, 5, 7, 3, 7, 7, 1, 3099,
                              7, 1, 1599, 1, 0, 0, 7, 1, 3099, 1]
        with self.assertRaisesRegex(ValueError, 'expired or foreign'):
            decoder.decode(self.packed(words))

    def test_snapshot_preserves_raw_rows_clears_stale_results_and_binds_boot(self):
        bundle = fixtures.EvidenceParserTests().snapshot()
        words = self.bank()
        words[8 + 2 * 24] |= 1
        bundle['SESSION_ACTIVITY_EVIDENCE'] = self.packed(words)
        guest = {'session_activity': {'old': 'different stopped snapshot'}}
        refresh_snapshot(guest, bundle)
        self.assertEqual(guest['session_activity_evidence'], words)
        self.assertEqual(guest['progress_diagnostic_status']['session_activity'], 'in_progress')
        self.assertNotIn('latest_activity', guest['session_activity']['records'])
        words[8 + 2] = 8
        bundle['SESSION_ACTIVITY_EVIDENCE'] = self.packed(words)
        with self.assertRaisesRegex(ValueError, 'snapshot BootEpoch mismatch'):
            refresh_snapshot(guest, bundle)
        self.assertIsNone(guest['session_activity'])
        bundle.pop('SESSION_ACTIVITY_EVIDENCE')
        refresh_snapshot(guest, bundle)
        self.assertIsNone(guest['session_activity'])
        self.assertIsNone(guest['session_activity_evidence'])


if __name__ == '__main__':
    unittest.main()
