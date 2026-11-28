import unittest

from verify_v020_g1_file_budget import CAPACITY, HEADER, ROW, WINDOW_CAPACITY, WINDOW_HEADER, WINDOW_ROW, replay


def evidence(rows, owner_limit=12_000_000, omitted=0):
    header = HEADER.pack(2, 100_000_000, 90_000_000, owner_limit, 3, 12, len(rows), omitted)
    return header + b"".join(ROW.pack(*row) for row in rows) + bytes((CAPACITY - len(rows)) * ROW.size)


def sustained():
    rows = []
    for i in range(CAPACITY):
        actor, generation = (12, 7) if i % 2 == 0 else (19, 2)
        now = 100_000_000 + i * 40_000
        rows.append((i + 1, actor, generation, 1, now, now + 20_000, 2_000_000, 5_000, 1))
    first = (1, 1, 128, 64, 64, 320_000, 320_000, 0, 0, 2_315_000, 2_315_000, 2_635_000, 0, 0, 0, 0, 0)
    with_reads = (2, 129, 132, 2, 2, 100, 100, 0, 0, 2050, 2050, 2150, 1, 1, 1, 1, 0)
    next_read = (3, 133, 136, *with_reads[3:])
    open_window = (4, 137, 138, 1, 1, 50, 50, 0, 0, 2000, 2000, 2050, 0, 0, 0, 0, 0)
    header = [276, 2, 7, 3, 0, 0, 69, 69, 138, 401_000_000, 2, 2, 2, 2, 1, 0]
    return evidence(rows, omitted=10), header, [first, with_reads, next_read], open_window


def summary(header, closed, open_window):
    return (WINDOW_HEADER.pack(*header) + b"".join(WINDOW_ROW.pack(*row) for row in closed)
            + bytes((WINDOW_CAPACITY - len(closed)) * WINDOW_ROW.size) + WINDOW_ROW.pack(*open_window))


class FileOwnerBudget(unittest.TestCase):
    def test_charges_both_windows_when_the_scheduler_carries_completion(self):
        rows = [(4, 12, 7, 1, 199_000_000, 200_700_000, 2_000_000, 1_100_000, 1),
                (6, 19, 3, 2, 200_700_000, 201_000_000, 2_000_000, 300_000, 1),
                (9, 12, 7, 2, 201_000_000, 202_000_000, 2_000_000, 500_000, 1)]
        report = replay(evidence(rows), 2, 7, 12_000_000)
        self.assertEqual(report['measured_cpu_ns'], [1_600_000, 300_000])
        self.assertEqual(report['peak_owner_window_ns'], 1_600_000)
        self.assertEqual(report['peak_core_window_ns'], 1_900_000)

    def test_rejects_unsettled_or_excess_reservation_and_wrong_generation(self):
        peer = (2, 19, 3, 1, 100_000_000, 101_000_000, 2_000_000, 200_000, 1)
        owner = (3, 12, 7, 1, 101_000_000, 102_000_000, 2_000_000, 1_500_000, 1)
        replay(evidence([peer, owner]), 2, 7, 12_000_000)
        with self.assertRaisesRegex(ValueError, 'settlement'):
            replay(evidence([peer, (*owner[:-1], 0)]), 2, 7, 12_000_000)
        with self.assertRaisesRegex(ValueError, 'stale generation'):
            replay(evidence([peer, owner]), 2, 8, 12_000_000)
        excessive = (4, 12, 7, 1, 102_000_000, 105_000_000, 2_000_000, 400_000, 1)
        with self.assertRaisesRegex(ValueError, 'available window credit'):
            replay(evidence([peer, owner, excessive], owner_limit=3_000_000), 2, 7, 3_000_000)

    def test_closes_two_active_read_windows_after_exact_prefix_fills(self):
        prefix, header, closed, active = sustained()
        report = replay(prefix, 2, 7, 12_000_000, summary(header, closed, active), 2, (2, 2, 2, 2))
        self.assertEqual(report["rows_omitted"], 10)
        windows = report["whole_windows"]
        self.assertEqual(windows["closed_windows_omitted"], 0)
        self.assertEqual(windows["lifetime_settled_turns"], [69, 69])
        self.assertEqual(windows["authorized_read_windows"], [2, 3])

    def test_rejects_late_observation_error_prefix_mismatch_and_straddle(self):
        prefix, header, closed, active = sustained()
        interrupted = header.copy()
        interrupted[0] -= 1
        failed = header.copy()
        failed[5] = 1
        fabricated = [(*closed[0][:5], closed[0][5] + 1, *closed[0][6:]), *closed[1:]]
        uncertain = [closed[0], (*closed[1][:-1], 1), closed[2]]
        for changed, rows, message in (
            (interrupted, closed, "unsealed"),
            (failed, closed, "observation failed"),
            (header, fabricated, "disagree with exact"),
            (header, uncertain, "insufficient whole windows"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                replay(prefix, 2, 7, 12_000_000, summary(changed, rows, active), 2)

    def test_reports_omitted_closed_windows_separately_from_exact_rows(self):
        prefix, header, closed, active = sustained()
        retained = list(ROW.iter_unpack(prefix[HEADER.size:]))
        for window in range(4, WINDOW_CAPACITY + 1):
            first = 137 + 2 * (window - 4)
            closed.append((window, first, first + 1, *active[3:]))
        active = (18, 165, 166, *active[3:])
        header = [332, 2, 7, 16, 1, 0, 83, 83, 166, 1_801_000_000, 2, 2, 2, 2, 1, 0]
        prefix = evidence(retained, omitted=38)
        record = replay(prefix, 2, 7, 12_000_000, summary(header, closed, active), 2)
        self.assertEqual(record["rows_omitted"], 38)
        self.assertEqual(record["whole_windows"]["closed_windows_omitted"], 1)
        header[4] = 2
        with self.assertRaisesRegex(ValueError, "omission count"):
            replay(prefix, 2, 7, 12_000_000, summary(header, closed, active), 2)

    def test_equal_deadline_does_not_carry_to_the_next_window(self):
        rows = [(4, 12, 7, 1, 199_000_000, 200_000_000, 2_000_000, 1_100_000, 1),
                (6, 19, 2, 2, 200_000_000, 201_000_000, 2_000_000, 300_000, 1)]
        report = replay(evidence(rows), 2, 7, 12_000_000)
        self.assertEqual(report["peak_core_window_ns"], 1_100_000)


if __name__ == '__main__':
    unittest.main()
