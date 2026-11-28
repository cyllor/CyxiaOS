"""Independent checker regressions for measured diagnostic CPU0 evidence."""

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from verify_v0199_eight_packages import Bringup

from v0199_budget_trace import (FAILURE_MAGIC, HEADER, MAGIC, ROW, TRACE_BYTES, WINDOW,
                                inspect_failure_trace, verify_sustained, verify_trace)


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

    def failure_evidence(self):
        raw = self.evidence(version=4)
        struct.pack_into("<Q", raw, 0, FAILURE_MAGIC)
        return raw

    def test_failed_prefix_is_not_a_successful_trace(self):
        raw = self.failure_evidence()
        detail = inspect_failure_trace(raw)
        self.assertEqual(detail["scope"], "terminal_failure_prefix_only")
        self.assertEqual(detail["intervals"], 4)
        self.assertEqual(detail["sampled_cpu_ns"], 1_200)
        self.assertEqual(detail["last_debit_ns"], 100)
        with self.assertRaisesRegex(ValueError, "unsealed CPU0 trace"):
            verify_trace(raw, self.summary, boot_accounting=(1, self.rows[0][0], 100))

    def test_failed_prefix_rejects_incomplete_and_wrong_identity(self):
        for raw in (self.evidence(version=4), self.failure_evidence()[:-1], bytes(TRACE_BYTES)):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                inspect_failure_trace(raw)
        for offset, value in ((16, 0), (16, 4097), (HEADER.size + 8, 999), (TRACE_BYTES - 8, 1)):
            raw = self.failure_evidence()
            struct.pack_into("<Q", raw, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                inspect_failure_trace(raw)

    def test_failed_capture_retains_raw_bytes_even_if_validation_fails(self):
        bringup = Bringup.__new__(Bringup)
        bringup.trace = {"pa": 0x42000000}
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            path = output / "cpu0-budget-failure-prefix.bin"
            qmp = Mock()
            for raw in (self.failure_evidence(), self.evidence(version=4)):
                qmp.execute.side_effect = lambda cmd, args: Path(args["filename"]).write_bytes(raw)
                if struct.unpack_from("<Q", raw)[0] == FAILURE_MAGIC:
                    self.assertEqual(bringup.capture_overrun(qmp, output)["intervals"], 4)
                else:
                    with self.assertRaises(ValueError):
                        bringup.capture_overrun(qmp, output)
                qmp.execute.assert_called_with("pmemsave", {"val": 0x42000000,
                    "size": TRACE_BYTES, "filename": str(path)})
                self.assertEqual(path.read_bytes(), raw)

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

    def test_early_boot_replenishment_keeps_both_window_bounds_and_full_debit(self):
        self.start = 10_000_000
        self.rows = [
            (12_000_000, 1_201_000, 0, 0, 0, 11_999_984),
            (WINDOW + 10_000, 1_251_000, 0, 0, 0, WINDOW + 9_984),
            (WINDOW + 2_000_000, 2_451_000, 0, 0, 0, WINDOW + 1_999_984),
            (WINDOW + 2_200_000, 2_551_000, 0, 0, 0, WINDOW + 2_199_984),
        ]
        self.summary = [2_550_000, 2_550_000, 1_350_000, 1, self.start,
                        self.rows[-1][0], 0, 0, 0, 2_550_000, 0, 0]
        boundary = (3, self.rows[2][0], 2_450_000)
        result = verify_trace(self.evidence(version=4), self.summary, boot_accounting=boundary)
        self.assertEqual(result["early_boot_coordination_cpu_ns"], 2_450_000)
        self.assertEqual(result["budget_max_window_upper_ns"], 1_350_000)
        # A mere extra sample without an actual window crossing cannot reset
        # the 2ms coordination credit. Keep the same measured execution.
        self.rows = [(end - (WINDOW - 20_000_000) if i else end, tick,
                      quota, deadline, scope, lower - (WINDOW - 20_000_000) if i else lower)
                     for i, (end, tick, quota, deadline, scope, lower) in enumerate(self.rows)]
        with self.assertRaisesRegex(ValueError, "EL1 coordination sublimit"):
            verify_trace(self.evidence(version=4), self.summary,
                         boot_accounting=(3, self.rows[2][0], 2_450_000))

    def test_256m_early_boot_overrun_cannot_be_accepted_as_success(self):
        # Reproduce both measured debit shapes from 46130235312, not an
        # attestation of a new QEMU run. Extra rows alone cannot replenish
        # coordination credit; the second capture exceeds it in one gap.
        for debits in ((1_880_699, 220_990), (2_351_746,)):
            with self.subTest(debits=debits):
                self.start = 10_000_000
                wall, counter = self.start, 1_000
                self.rows = []
                for debit in (*debits, 100):
                    wall += 10_000_000
                    counter += debit
                    self.rows.append((wall, counter, 0, 0, 0, wall - 16))
                total = sum(debits) + 100
                self.summary = [total, total, total, 0, self.start, wall,
                                0, 0, 0, total, 0, 0]
                with self.assertRaisesRegex(ValueError, "EL1 coordination sublimit"):
                    verify_trace(self.evidence(version=4), self.summary,
                                 boot_accounting=(len(debits), self.rows[-2][0], sum(debits)))

    def test_boot_reports_follow_timer_readiness_in_diagnostic_source(self):
        # Supplemental wiring guard, never a native timing or G4 proof.
        root = Path(__file__).resolve().parents[1] / "kernel/src/arch/aarch64"
        boot = (root / "boot.rs").read_text()
        smp = (root / "smp.rs").read_text()
        self.assertEqual(boot.count('budget.observe_boot_phase();'), 1)
        before = boot.split('budget.observe_boot_phase();', 1)[0]
        self.assertIn('assert_eq!(vbar, core::ptr::addr_of!(exception_vectors) as u64);', before)
        for block in ('log(b"BOOT_ENTRY', 'log(b"HIGH_VA_OK'):
            self.assertIn('#[cfg(not(feature = "v0199-control-bringup"))]\n    {\n        ' + block, before)
        run = smp.split('pub fn run(', 1)[1]
        early = run.split('gic().enable(irq).unwrap();', 1)[1].split('init_memory();', 1)[0]
        markers = ['super::log(b"BOOT_ENTRY', 'super::log(b"PLATFORM_OK',
                   'super::log(b"HIGH_VA_OK', 'super::clock::init(info);']
        for marker in markers:
            before_marker, early = early.split(marker, 1)
            self.assertIn('budget.boot_checkpoint();', before_marker)
        self.assertIn('budget.boot_checkpoint();', early)

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
            serviced = 255 ^ (1 << (2 + window % 2))
            windows.append((window, begin, len(trace), serviced, 3, 4))
        trace.append((10 * WINDOW + 32, tick, 0, 0, 0, 10 * WINDOW + 16))
        HEADER.pack_into(raw, 0, MAGIC, 4, len(trace), WINDOW + 32, 10_000, WINDOW + 16)
        for index, row in enumerate(trace):
            ROW.pack_into(raw, HEADER.size + index * ROW.size, *row)
        result = verify_sustained(raw, windows)
        self.assertEqual(result["sustained_windows"], 8)
        self.assertEqual(result["sustained_slot_refusals"], 16)
        self.assertEqual(result["sustained_role_grants"], [8, 32, 8, 8, 8, 8, 8, 8])
        self.assertEqual(result["sustained_role_calls_mask_by_window"], [251, 247] * 4)
        missing_publisher = [(window, begin, end, mask & ~(1 << 3), refused, reads)
                             for window, begin, end, mask, refused, reads in windows]
        with self.assertRaisesRegex(ValueError, "missing sustained decision or publisher syscall"):
            verify_sustained(raw, missing_publisher)
        last = windows[0][2] - 1
        struct.pack_into("<Q", raw, HEADER.size + last * ROW.size + 32, (2 << 32) | (7 << 8) | 4)
        with self.assertRaisesRegex(ValueError, "missing sustained role grant"):
            verify_sustained(raw, windows)


if __name__ == "__main__":
    unittest.main()
