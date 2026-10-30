"""Native diagnostic integration contracts; host snapshots are not native PASS."""
import unittest
import struct

import test_verify_domains as fixtures
import test_decode_session_exits as session_fixture
from verify_domains import refresh_snapshot


class ProgressDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        session_fixture.SessionExitDecoderTests.setUpClass()

    def with_session_bank(self):
        snapshot = fixtures.EvidenceParserTests().snapshot()
        u = list(struct.unpack('<512Q', snapshot['UNIFIED_EVIDENCE']))
        original = struct.unpack('<512Q', session_fixture.SessionExitDecoderTests.snapshot)
        u[30] = original[30]
        u[432:] = original[432:]
        snapshot['UNIFIED_EVIDENCE'] = fixtures.encode(u)
        return snapshot, u

    def with_source_banks(self):
        snapshot, _ = self.with_session_bank()
        p = [0] * 128
        p[:16] = [0x4359505542430002, 0, 1, 7, 9, 11, 99, 2, 3, 8, 1,
                  0, 100, 10, 2, 0]
        p[18:28] = [110, 15, 3, 23, 0, 112, 17, 115, 20, 10]
        p[29] = 23
        p[43:46] = [7, 9, 11]
        p[63] = 11
        # CPU2 is physically stopped before its row is release-published.
        p[64:70] = [0x4359505542430002, 0, 2, 7, 9, 12]
        c = [0] * 128
        c[:14] = [0x4359535243450001, 1, 2, 7, 1, 2, 1, 1, 0, 0, 0, 1, 0, 1]
        c[16:40] = [99, 8, 13, 2, 2, 0, 1, 37, 100, 137, 100, 137,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        snapshot['DOMAIN_PUBLICATION_COST'] = fixtures.encode(p)
        snapshot['TRACE_SOURCE_EVIDENCE'] = fixtures.encode(c)
        return snapshot, p, c

    def test_new_raw_banks_survive_an_independent_fatal_snapshot(self):
        snapshot = fixtures.EvidenceParserTests().snapshot(overrun=True)
        rows = {
            'DOMAIN_PUBLICATION_COST': ('publication_cost_evidence', list(range(128))),
            'TRACE_SOURCE_EVIDENCE': ('capture_source_evidence', list(range(128))),
        }
        for symbol, (_, values) in rows.items():
            snapshot[symbol] = fixtures.encode(values)
        guest = {}
        with self.assertRaisesRegex(ValueError, 'overrun/quarantine'):
            refresh_snapshot(guest, snapshot)
        for field, values in rows.values():
            self.assertEqual(guest.get(field), values,
                             'fresh raw diagnostics must survive another parser failure')

    def test_legacy_snapshot_clears_prior_new_diagnostics(self):
        fields = ('publication_cost_evidence', 'publication_cost',
                  'capture_source_evidence', 'capture_source',
                  'session_exit_evidence', 'session_exits')
        guest = {name: {'old': 'different stopped snapshot'} for name in fields}
        refresh_snapshot(guest, fixtures.EvidenceParserTests().snapshot())
        for name in fields:
            self.assertIsNone(guest.get(name),
                              'an absent bank cannot retain an older diagnostic result')

    def test_actual_session_retention_decodes_after_unified_overflow(self):
        snapshot, u = self.with_session_bank()
        u[6] = 201
        snapshot['UNIFIED_EVIDENCE'] = fixtures.encode(u)
        guest = {}
        with self.assertRaisesRegex(ValueError, 'unified event trace overflow'):
            refresh_snapshot(guest, snapshot)
        self.assertEqual(guest['session_exit_evidence'], u[432:])
        result = guest['session_exits']
        self.assertEqual(result['counts']['authenticated'], 2)
        self.assertEqual(result['first_authenticated']['service_generation'], 1)
        self.assertEqual(result['latest_authenticated']['service_generation'], 2)
        self.assertFalse(result['ordinary_events_complete'])
        self.assertFalse(result['complete_session_history'])
        self.assertFalse(result['native_pass'])

    def test_interrupted_session_retention_is_raw_only(self):
        snapshot, u = self.with_session_bank()
        u[432] |= 1
        snapshot['UNIFIED_EVIDENCE'] = fixtures.encode(u)
        guest = {}
        refresh_snapshot(guest, snapshot)
        self.assertEqual(guest['session_exit_evidence'], u[432:])
        self.assertIsNone(guest['session_exits'])
        self.assertEqual(guest['progress_diagnostic_status']['session_exits'], 'in_progress')

    def test_malformed_session_identity_cannot_hide_task_fault(self):
        snapshot, u = self.with_session_bank()
        u[441] = 8  # original slot BootEpoch differs from current snapshot7
        snapshot['UNIFIED_EVIDENCE'] = fixtures.encode(u)
        snapshot['DOMAIN_TASK_EVIDENCE'] = fixtures.EvidenceParserTests().snapshot(overrun=True)['DOMAIN_TASK_EVIDENCE']
        guest = {}
        with self.assertRaisesRegex(ValueError, 'overrun/quarantine'):
            refresh_snapshot(guest, snapshot)
        self.assertEqual(guest['session_exit_evidence'], u[432:])
        self.assertIsNone(guest['session_exits'])
        self.assertTrue(any(e['field'] == 'session_exits' for e in guest['diagnostic_errors']))
        snapshot['DOMAIN_TASK_EVIDENCE'] = fixtures.EvidenceParserTests().snapshot()['DOMAIN_TASK_EVIDENCE']
        with self.assertRaisesRegex(ValueError, 'record boot/service/session identity mismatch'):
            refresh_snapshot({}, snapshot)

    def test_completed_cost_and_capture_rows_decode_alongside_partial_cpu(self):
        snapshot, p, c = self.with_source_banks()
        snapshot.pop('REPLAY_V13_EVIDENCE')
        guest = {}
        refresh_snapshot(guest, snapshot)
        self.assertEqual(guest['publication_cost_evidence'], p)
        self.assertEqual(guest['capture_source_evidence'], c)
        self.assertEqual(len(guest['publication_cost']), 1)
        self.assertEqual(guest['publication_cost'][0]['job'], 11)
        self.assertEqual(guest['publication_cost'][0]['checkpoint_cumulative_ns'], 10)
        self.assertEqual(guest['progress_diagnostic_status']['publication_cost']['in_progress_cpus'], [2])
        source = guest['capture_source']
        self.assertEqual(source['run'], [7, 1, 2])
        self.assertEqual(source['sources'][0]['original_owner'], [99, 8])
        self.assertEqual(source['sources'][0]['resolved_source'], [13, 2])
        self.assertFalse(source['attribution_complete'])
        self.assertIsNone(source['current_run_match'])

    def test_capture_last_recorded_run_is_not_joined_to_newer_replay_run(self):
        snapshot, _, _ = self.with_source_banks()
        replay = [0] * 64
        replay[:10] = [2, 0x435952504c593133, 3, 8, 1, 0, 2, 4, 7, 5]
        snapshot['REPLAY_V13_EVIDENCE'] = fixtures.encode(replay)
        guest = {}
        refresh_snapshot(guest, snapshot)
        self.assertEqual(guest['capture_source']['run'], [7, 1, 2])
        self.assertFalse(guest['capture_source']['current_run_match'])
        self.assertEqual(guest['capture_source']['current_replay_run'], [7, 4, 5])

    def test_foreign_completed_cost_and_source_banks_fail_independently(self):
        snapshot, p, c = self.with_source_banks()
        p[3] = c[3] = 8
        p[43] = 8  # internally consistent foreign receipt still fails snapshot binding
        snapshot['DOMAIN_PUBLICATION_COST'] = fixtures.encode(p)
        snapshot['TRACE_SOURCE_EVIDENCE'] = fixtures.encode(c)
        guest = {}
        with self.assertRaisesRegex(ValueError, 'expected identity mismatch: boot'):
            refresh_snapshot(guest, snapshot)
        self.assertIsNone(guest['publication_cost'])
        self.assertIsNone(guest['capture_source'])
        self.assertIsNotNone(guest['session_exits'])
        fields = {e['field'] for e in guest['diagnostic_errors']}
        self.assertTrue({'publication_cost', 'capture_source'} <= fields)

    def test_interrupted_capture_stays_raw_without_reusing_prior_decode(self):
        snapshot, _, c = self.with_source_banks()
        c[2] = 3
        snapshot['TRACE_SOURCE_EVIDENCE'] = fixtures.encode(c)
        guest = {'capture_source': {'old': 'prior-run'}}
        refresh_snapshot(guest, snapshot)
        self.assertEqual(guest['capture_source_evidence'], c)
        self.assertIsNone(guest['capture_source'])
        self.assertEqual(guest['progress_diagnostic_status']['capture_source'], 'in_progress')

    def test_checkpoint_binds_only_matching_original_charged_stop(self):
        snapshot, _, _ = self.with_source_banks()
        ctl = list(struct.unpack(f'<{fixtures.CONTROL_WORDS}Q', snapshot['DOMAIN_CONTROL_EVIDENCE']))
        ctl[160:163] = [0x43594f5053540001, 1, 1]
        ctl[164:184] = [2, 100, 7, 9, 11, 99, 2, 23, 0, 0,
                        2, 500001, 500003, 0, 0, 1, 3, 11, 1, 10]
        ctl[191] = 2
        snapshot['DOMAIN_CONTROL_EVIDENCE'] = fixtures.encode(ctl)
        guest = {}
        refresh_snapshot(guest, snapshot)
        self.assertIn('charged_stop', guest['publication_cost'][0],
                      'checkpoint cannot stand in for the final original charged stop')
        stop = guest['publication_cost'][0]['charged_stop']
        self.assertIsNotNone(stop)
        self.assertEqual(stop['charged_cumulative_ns'], 500003)
        self.assertEqual(guest['publication_cost'][0]['checkpoint_cumulative_ns'], 10)
        ctl[191] = 3
        snapshot['DOMAIN_CONTROL_EVIDENCE'] = fixtures.encode(ctl)
        guest = {}
        refresh_snapshot(guest, snapshot)
        self.assertIsNone(guest['publication_cost'][0]['charged_stop'])
        self.assertEqual(guest['progress_diagnostic_status']['publication_cost']['stop_receipt'], 'in_progress')
        ctl[191] = 2
        ctl[164 + 5] = 100  # same Job/CPU but foreign target cannot bind
        snapshot['DOMAIN_CONTROL_EVIDENCE'] = fixtures.encode(ctl)
        with self.assertRaisesRegex(ValueError, 'identity'):
            refresh_snapshot({}, snapshot)
        ctl[164 + 4] = 12  # a genuinely different original Job remains unbound
        snapshot['DOMAIN_CONTROL_EVIDENCE'] = fixtures.encode(ctl)
        guest = {}
        refresh_snapshot(guest, snapshot)
        self.assertIsNone(guest['publication_cost'][0]['charged_stop'])


if __name__ == '__main__':
    unittest.main()
