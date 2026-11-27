"""Independent checker regressions for measured diagnostic CPU0 evidence."""

import struct
import unittest

from v0199_budget_trace import HEADER, MAGIC, ROW, TRACE_BYTES, WINDOW, verify_sustained, verify_trace


class BudgetTraceTests(unittest.TestCase):
    def setUp(self):
        self.start = WINDOW - 400_000
        controller = 3 | (3 << 8) | (1 << 16) | (1 << 32)
        self.rows = [
            (WINDOW - 300_000, 1_100, 0, 0, 0, WINDOW - 300_016),
            (WINDOW - 1, 1_600, 250_000, WINDOW, controller, WINDOW - 16),
            (2 * WINDOW + 20, 2_100, 0, 0, 0, 2 * WINDOW + 4),
            (2 * WINDOW + 400, 2_200, 2_000_000, 2 * WINDOW + 50_000_020, 5, 2 * WINDOW + 384),
        ]
        self.summary = [1_200, 1_200, 1_100, 1, self.start, self.rows[-1][0], 0, 0, 500, 600, 100, 0]

    def evidence(self, version=3):
        raw = bytearray(TRACE_BYTES)
        HEADER.pack_into(raw, 0, MAGIC, version, len(self.rows), self.start, 1_000, self.start - 16)
        for index, row in enumerate(self.rows):
            ROW.pack_into(raw, HEADER.size + index * ROW.size, *row)
        return raw

    def test_boundary_stop_and_gap_crossing_debit_once(self):
        result = verify_trace(self.evidence(), self.summary, recovery_slices=(1, 100))
        self.assertEqual(result["budget_intervals_replayed"], 4)
        self.assertEqual(result["budget_grants_replayed"], 2)
        self.assertEqual(result["budget_max_window_upper_ns"], 1_100)

    def test_boot_coordination_matches_the_sealed_trace_prefix(self):
        boundary = (1, self.rows[0][0], 100)
        result = verify_trace(self.evidence(version=4), self.summary, boot_accounting=boundary)
        self.assertEqual(result["early_boot_coordination_intervals"], 1)
        self.assertEqual(result["early_boot_coordination_cpu_ns"], 100)
        with self.assertRaisesRegex(ValueError, "early boot accounting"):
            verify_trace(self.evidence(version=4), self.summary)
        with self.assertRaisesRegex(ValueError, "early boot accounting"):
            verify_trace(self.evidence(), self.summary, boot_accounting=boundary)
        with self.assertRaisesRegex(ValueError, "early boot debit differs"):
            verify_trace(self.evidence(version=4), self.summary,
                         boot_accounting=(1, self.rows[0][0], 99))
        with self.assertRaisesRegex(ValueError, "role grant during early boot"):
            verify_trace(self.evidence(version=4), self.summary,
                         boot_accounting=(2, self.rows[1][0], 600))

    def test_grant_must_precede_deadline_and_have_enough_credit(self):
        end, counter, _, deadline, scope, lower = self.rows[1]
        self.rows[1] = end, counter, 310_000, deadline, scope, lower
        with self.assertRaisesRegex(ValueError, "grant expiry, window, or measured quota"):
            verify_trace(self.evidence(), self.summary)

    def test_credit_of_both_gap_endpoint_windows_is_checked(self):
        self.start = WINDOW - 50_000_000
        self.rows = [(WINDOW - 600_010, 1_601_000, 0, 0, 0, WINDOW - 600_026),
                     (WINDOW + 20, 2_101_000, 0, 0, 0, WINDOW + 4)]
        with self.assertRaisesRegex(ValueError, "EL1 coordination sublimit"):
            verify_trace(self.evidence(), self.summary)

    def test_balanced_but_forged_summary_cannot_reclassify_cpu_time(self):
        self.summary[-2] -= 50
        self.summary[-3] += 50
        with self.assertRaisesRegex(ValueError, "does not conserve"):
            verify_trace(self.evidence(), self.summary)

    def test_balanced_trace_cannot_charge_more_cpu_than_wall_brackets_allow(self):
        end, _, quota, deadline, scope, lower = self.rows[-1]
        self.rows[-1] = end, 2_600, quota, deadline, scope, lower
        self.summary[0:2] = [1_600, 1_600]
        self.summary[-2] = 500
        with self.assertRaisesRegex(ValueError, "CPU0 execution exceeds wall-clock bounds"):
            verify_trace(self.evidence(), self.summary, recovery_slices=(1, 500))

    def test_counter_rollback_and_wrong_role_class_are_rejected(self):
        end, counter, quota, deadline, scope, lower = self.rows[1]
        self.rows[1] = end, counter, quota, deadline, scope ^ (2 << 8), lower
        with self.assertRaisesRegex(ValueError, "incorrect role grant class"):
            verify_trace(self.evidence(), self.summary)
        self.rows[1] = end, 999, quota, deadline, scope, lower
        with self.assertRaisesRegex(ValueError, "regressed CPU0"):
            verify_trace(self.evidence(), self.summary)

    def test_boundary_ambiguous_sample_and_wrong_recovery_grant_are_rejected(self):
        crossing = self.rows[2]
        self.rows[2] = (*crossing[:5], 2 * WINDOW - 1)
        with self.assertRaisesRegex(ValueError, "sample straddles a window"):
            verify_trace(self.evidence(), self.summary)
        self.rows[2] = crossing
        with self.assertRaisesRegex(ValueError, "recovery slices differ"):
            verify_trace(self.evidence(), self.summary, recovery_slices=(1, 99))
        end, tick, _, deadline, scope, lower = self.rows[-1]
        self.rows[-1] = (end, tick, 8_000_000, deadline, scope, lower)
        with self.assertRaisesRegex(ValueError, "incorrect EL1 prepayment"):
            verify_trace(self.evidence(), self.summary)

    def test_sustained_window_claim_requires_all_native_role_admissions(self):
        raw = bytearray(TRACE_BYTES)
        trace = []
        windows = []
        tick = 10_000
        for window in range(2, 10):
            start = window * WINDOW + 32
            trace.append((start, tick, 0, 0, 0, start - 16))
            begin = len(trace)
            for actor in (1, 2, 2, 2, 2, 3, 4, 5, 6, 7, 8):
                start += 1_000
                tick += 100
                trace.append((start, tick, 0, 0, (2 << 32) | (actor << 8) | 4, start - 16))
            windows.append((window, begin, len(trace), 255, 3, 4))
        trace.append((10 * WINDOW + 32, tick, 0, 0, 0, 10 * WINDOW + 16))
        HEADER.pack_into(raw, 0, MAGIC, 4, len(trace), WINDOW + 32, 10_000, WINDOW + 16)
        for index, row in enumerate(trace):
            ROW.pack_into(raw, HEADER.size + index * ROW.size, *row)
        result = verify_sustained(raw, windows)
        self.assertEqual(result["sustained_windows"], 8)
        self.assertEqual(result["sustained_slot_refusals"], 16)
        self.assertEqual(result["sustained_role_grants"], [8, 32, 8, 8, 8, 8, 8, 8])
        last = windows[0][2] - 1
        struct.pack_into("<Q", raw, HEADER.size + last * ROW.size + 32, (2 << 32) | (7 << 8) | 4)
        with self.assertRaisesRegex(ValueError, "missing sustained role grant"):
            verify_sustained(raw, windows)


if __name__ == "__main__":
    unittest.main()
