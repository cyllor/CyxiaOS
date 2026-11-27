"""Independent replay of the signed scratch CPU0 trace."""

import unittest

from v0199_budget_trace import (
    ROLE_GRANTS, SIGNED_HEADER, SIGNED_MAGIC, SIGNED_ROW, SIGNED_TRACE_BYTES,
    WINDOW, verify_signed_trace,
)


class SignedBudgetTraceTests(unittest.TestCase):
    def setUp(self):
        roles = (6, 7, 2, 8, 9, 3, 10, 11)
        self.roles = [(i, actor, (1 << 40) + i) for i, actor in enumerate(roles)]
        self.origin, initial_tick = WINDOW + 32, 10_000
        self.rows = [(self.origin + 2_000, initial_tick + 1_000, 8_000_000,
                      self.origin + 50_000_000, 5, self.origin + 1_984, 0, 0)]
        lifetime = [0, 0, 0, 0, 1_000, 0]
        tick = self.rows[-1][1]
        for window in range(2, 10):
            wall = window * WINDOW + 32
            tick += 100
            lifetime[3] += 100
            self.rows.append((wall, tick, 0, 0, 0, wall - 16, 0, 0))
            for (i, actor, generation), (category, domain, quota) in zip(self.roles, ROLE_GRANTS):
                deadline = wall + 50_000_000
                wall += 1_000
                tick += 100
                lifetime[category] += 100
                scope = (category + 1) | ((i + 1) << 8) | (domain << 16) | (1 << 32)
                self.rows.append((wall, tick, quota, deadline, scope, wall - 16, actor, generation))
        end = 10 * WINDOW + 32
        tick += 100
        lifetime[3] += 100
        self.rows.append((end, tick, 0, 0, 0, end - 16, 0, 0))
        self.header = [SIGNED_MAGIC, 1, len(self.rows), self.origin, initial_tick,
                       self.origin - 16, 2, 0, 300, end, tick, tick - initial_tick,
                       1_100, 500, *lifetime]
        self.uart = [(tick - initial_tick, tick - initial_tick, 500)]

    def evidence(self):
        raw = bytearray(SIGNED_TRACE_BYTES)
        SIGNED_HEADER.pack_into(raw, 0, *self.header)
        for index, row in enumerate(self.rows):
            SIGNED_ROW.pack_into(raw, SIGNED_HEADER.size + index * SIGNED_ROW.size, *row)
        return raw

    def replay(self, epoch=2):
        return verify_signed_trace(self.evidence(), epoch, self.roles, (300, 1_000), self.uart)

    def test_replays_eight_complete_windows_and_all_returned_role_turns(self):
        proof = self.replay()
        self.assertEqual(proof["budget_role_returns"], [8] * 8)
        self.assertEqual(proof["budget_complete_eight_role_windows"], list(range(2, 10)))
        self.assertEqual(proof["budget_max_window_upper_ns"], 1_100)
        self.assertEqual(proof["budget_kernel_coordination_max_upper_ns"], 200)
        self.assertEqual(proof["budget_crossing_gaps"], 9)

    def test_binds_boot_generation_and_successful_user_returns(self):
        with self.assertRaisesRegex(ValueError, "BootEpoch"):
            self.replay(epoch=1)
        original = self.rows[2]
        self.rows[2] = (*original[:-1], original[-1] & 0xffffffff)
        with self.assertRaisesRegex(ValueError, "signed role identity"):
            self.replay()
        scope = original[4] & 0xffffffff
        self.rows[2] = (*original[:4], scope, *original[5:])
        with self.assertRaisesRegex(ValueError, "eight roles"):
            self.replay()

    def test_same_window_bootstrap_debit_prevents_fresh_recovery_credit(self):
        self.header[7] = 1
        with self.assertRaisesRegex(ValueError, "class or total window limit"):
            self.replay()


if __name__ == "__main__":
    unittest.main()
