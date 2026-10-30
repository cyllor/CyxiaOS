"""Retained sampled raw banks are diagnostics, never complete run attribution."""
import base64
import hashlib
import struct
import unittest

import test_verify_domains as fixtures
from verify_domains import refresh_snapshot


class CaptureSourceHistory(unittest.TestCase):
    def snapshot(self, trial=1, generation=1, sequence=2, count=1):
        bundle = fixtures.EvidenceParserTests().snapshot()
        bank = [0] * 128
        bank[:14] = [0x4359535243450001, 2, sequence, 7, trial, generation,
                     count, count, 0, count, 0, 1, 0, 0]
        bank[16:40] = [13, 2, 13, 2, 2, 0, 5, count, 100, 100 + count,
                       1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        bundle['TRACE_SOURCE_EVIDENCE'] = fixtures.encode(bank)
        return bundle, bank

    def history(self, guest):
        self.assertTrue('capture_source_history' in guest,
                        'replacing a live source bank must retain sampled prior RunKeys')
        return guest['capture_source_history']

    def test_replaced_runs_keep_exact_raw_identity_and_only_same_run_is_updated(self):
        guest = {}
        first, _ = self.snapshot()
        refresh_snapshot(guest, first)
        second, _ = self.snapshot(2, 2, 4, 2)
        refresh_snapshot(guest, second)
        latest, _ = self.snapshot(1, 1, 6, 3)
        refresh_snapshot(guest, latest)
        history = self.history(guest)
        self.assertFalse(history['complete'])
        self.assertEqual(history['run_limit'], 64)
        self.assertFalse(history['overflow'])
        self.assertEqual([r['run'] for r in history['entries']], [[7, 1, 1], [7, 2, 2]])
        for entry, snapshot, sequence in zip(history['entries'], [latest, second], [6, 4]):
            raw = base64.b64decode(entry['raw_base64'], validate=True)
            self.assertEqual(raw, snapshot['TRACE_SOURCE_EVIDENCE'])
            self.assertEqual(entry['sequence'], sequence)
            self.assertEqual(entry['bytes'], 1024)
            self.assertEqual(entry['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(guest['capture_source']['run'], [7, 1, 1])

    def test_ordinary_fatal_snapshot_still_retains_its_stable_raw_source(self):
        snapshot, _ = self.snapshot()
        u = list(struct.unpack('<512Q', snapshot['UNIFIED_EVIDENCE']))
        u[6] = 201
        snapshot['UNIFIED_EVIDENCE'] = fixtures.encode(u)
        guest = {}
        with self.assertRaisesRegex(ValueError, 'unified event trace overflow'):
            refresh_snapshot(guest, snapshot)
        self.assertEqual(self.history(guest)['entries'][0]['run'], [7, 1, 1])

    def test_absent_odd_invalid_and_foreign_samples_do_not_replace_history(self):
        guest = {}
        first, _ = self.snapshot()
        refresh_snapshot(guest, first)
        retained = self.history(guest)['entries'][0].copy()
        for mutation in ('absent', 'odd', 'reserved', 'foreign', 'zero_sequence'):
            with self.subTest(mutation=mutation):
                snapshot, bank = self.snapshot(2, 2)
                if mutation == 'absent':
                    bank = [0] * 128
                elif mutation == 'odd':
                    bank[2] = 3
                elif mutation == 'reserved':
                    bank[13] = 1
                elif mutation == 'foreign':
                    bank[3] = 8
                else:
                    bank[2] = 0
                snapshot['TRACE_SOURCE_EVIDENCE'] = fixtures.encode(bank)
                if mutation in ('reserved', 'foreign'):
                    with self.assertRaises(ValueError):
                        refresh_snapshot(guest, snapshot)
                else:
                    refresh_snapshot(guest, snapshot)
                self.assertEqual(self.history(guest)['entries'], [retained])
        refresh_snapshot(guest, fixtures.EvidenceParserTests().snapshot())
        self.assertIsNone(guest['capture_source'])
        self.assertEqual(self.history(guest)['entries'], [retained])

    def test_run_limit_reports_first_omission_without_evicting_or_blocking_updates(self):
        guest = {}
        for run in range(1, 66):
            snapshot, _ = self.snapshot(run, run, 2 * run)
            refresh_snapshot(guest, snapshot)
        history = self.history(guest)
        self.assertEqual(len(history['entries']), 64)
        self.assertTrue(history['overflow'])
        self.assertEqual(history['first_unretained_run'], [7, 65, 65])
        self.assertEqual([r['run'][1] for r in history['entries']], list(range(1, 65)))
        snapshot, _ = self.snapshot(1, 1, 132, 2)
        refresh_snapshot(guest, snapshot)
        self.assertEqual(history['entries'][0]['sequence'], 132)
        self.assertEqual(len(history['entries']), 64)
        self.assertFalse(history['complete'])


if __name__ == '__main__':
    unittest.main()
