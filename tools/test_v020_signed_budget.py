"""Independent replay of the signed scratch CPU0 trace."""

import unittest
from unittest.mock import patch

from v0199_budget_trace import (
    ROLE_GRANTS, SIGNED_EARLY_TRACE_BYTES, SIGNED_FRAME_SPAN, SIGNED_HEADER, SIGNED_MAGIC,
    SIGNED_ROW, SIGNED_TRACE_BYTES, WINDOW, verify_signed_trace,
)

from verify_v020_signed_resident import capture_role_syscall_abi


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

    def evidence(self, size=SIGNED_TRACE_BYTES, frame_span=None):
        raw = bytearray(size)
        SIGNED_HEADER.pack_into(raw, 0, *self.header)
        offset = SIGNED_HEADER.size
        if frame_span is not None:
            SIGNED_FRAME_SPAN.pack_into(raw, offset, *frame_span)
            offset += SIGNED_FRAME_SPAN.size
        for index, row in enumerate(self.rows):
            SIGNED_ROW.pack_into(raw, offset + index * SIGNED_ROW.size, *row)
        return raw

    def replay(self, epoch=2):
        return verify_signed_trace(self.evidence(), epoch, self.roles, (300, 1_000), self.uart)

    def test_role_abi_readback_accepts_archived_elf_without_the_symbol(self):
        missing = ValueError("missing symbol V020_SIGNED_ROLE_SYSCALL_ABI")
        with patch("verify_v020_signed_resident.symbol", side_effect=missing):
            self.assertEqual(capture_role_syscall_abi(None, None, b""), {})
        with patch("verify_v020_signed_resident.symbol", return_value={"pa": 0x4000, "size": 14}):
            with self.assertRaisesRegex(ValueError, "invalid linked role syscall ABI table"):
                capture_role_syscall_abi(None, None, b"")

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

    def early_boot(self, dense=False):
        initial_tick = self.header[4]
        prefix = []
        wall = self.origin
        tick = initial_tick
        debits = (100, 400, 200, 300) if dense else (100, 200, 300)
        for step, used in enumerate(debits):
            if step:
                wall = (step + 1) * WINDOW + 32
                tick += 10
                prefix.append((wall, tick, 0, 0, 0, wall - 16, 0, 0))
            tick += used
            prefix.append((wall + 1_000, tick, 8_000_000, wall + 50_000_000, 5,
                           wall + 984, 0, 0))
        shift_wall = len(debits) * WINDOW
        wall = self.origin + shift_wall
        tick += 10
        prefix.append((wall, tick, 0, 0, 0, wall - 16, 0, 0))
        shift = tick - initial_tick
        self.rows = prefix + [(end + shift_wall, end_tick + shift, quota,
                               deadline + shift_wall if deadline else 0,
                               scope, lower + shift_wall, actor, generation)
                              for end, end_tick, quota, deadline, scope, lower, actor,
                              generation in self.rows]
        self.header[1:3] = (3 if dense else 2, len(self.rows))
        self.header[7:9] = (len(prefix) - 3, len(prefix) - 1)
        self.header[9] += shift_wall
        self.header[10] += shift
        self.header[11] += shift
        self.header[12] += 10
        self.header[17] += 10 * len(debits)
        self.header[18] += sum(debits)
        self.uart = [(self.header[11], self.header[11], 500)]

    def test_replays_boot_and_media_before_the_existing_role_windows(self):
        self.early_boot()
        raw = self.evidence(SIGNED_EARLY_TRACE_BYTES)
        result = verify_signed_trace(raw, 2, self.roles, (100, 200, 1_000), self.uart,
                                     media_budget=(1, 300, 8_000_000))
        self.assertEqual(result["early_boot_recovery_cpu_ns"], 100)
        self.assertEqual(result["boot_media_recovery_cpu_ns"], 300)
        self.assertEqual(result["budget_complete_eight_role_windows"], list(range(5, 13)))

    def test_requires_a_separate_frame_meta_phase_before_signed_policy(self):
        self.early_boot(dense=True)
        raw = self.evidence(SIGNED_EARLY_TRACE_BYTES, frame_span=(1, 3))
        args = (2, self.roles, (100, 200, 1_000), self.uart)
        media = (1, 300, 8_000_000)
        result = verify_signed_trace(raw, *args, media_budget=media,
                                     frame_budget=(1, 400, 8_000_000))
        self.assertEqual(result["boot_frame_meta_recovery_cpu_ns"], 400)
        self.assertEqual(result["boot_frame_meta_accounting_intervals"], 2)
        self.assertEqual(result["budget_complete_eight_role_windows"], list(range(6, 14)))
        with self.assertRaisesRegex(ValueError, "missing or unexpected FrameMeta"):
            verify_signed_trace(raw, *args, media_budget=media)
        with self.assertRaisesRegex(ValueError, "FrameMeta PMU debits"):
            verify_signed_trace(raw, *args, media_budget=media, frame_budget=(1, 401, 8_000_000))
        invalid = self.evidence(SIGNED_EARLY_TRACE_BYTES, frame_span=(1, 5))
        with self.assertRaisesRegex(ValueError, "precede policy and media"):
            verify_signed_trace(invalid, *args, media_budget=media, frame_budget=(1, 400, 8_000_000))


if __name__ == "__main__":
    unittest.main()
