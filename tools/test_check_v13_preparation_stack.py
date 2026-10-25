import unittest

from check_v13_preparation_stack import frame_size, inspect, instructions, NAMES


def function(key, address, frame, calls=()):
    rows = [f"{address:x} <{NAMES[key]}>:"]
    rows.append(f"{address:x}: sub sp, sp, #0x{frame:x}")
    for offset, target in enumerate(calls, 1):
        rows.append(f"{address + offset * 4:x}: bl 0x{target:x}")
    rows.append(f"{address + (len(calls) + 1) * 4:x}: ret")
    return "\n".join(rows)


def chain(nested):
    functions = [
        function("secondary_entry", 0x1000, 7264, [0x2000]),
        function("run_turn", 0x2000, 10176, [0x3000]),
        function("next_input", 0x3000, 30688 if nested else 512, [0x4000, 0x5000]),
        function("read_only", 0x5000, 27728, [0x6000, 0x7000]),
        function("candidate_new", 0x6000, 7248),
        function("encode_job", 0x7000, 64, [0x7200]),
        function("encode_prepared_job", 0x7100, 64, [0x7200]),
        function("encode_job_inner", 0x7200, 4784),
        function("next_normal", 0x4000, 30688, [0x6000, 0x7100]),
    ]
    return "\n\n".join(functions)


class PreparationStackTests(unittest.TestCase):
    def test_large_parent_frame_retains_large_preparation_child(self):
        result = inspect(chain(True))
        self.assertFalse(result["passed"])
        self.assertEqual(result["peak"]["frame_bytes"], 86064)
        self.assertEqual(result["peak"]["path"][-2:], ["next_normal", "candidate_new"])

    def test_sibling_preparation_frames_are_not_summed(self):
        result = inspect(chain(False))
        self.assertTrue(result["passed"])
        self.assertEqual(result["peak"]["frame_bytes"], 55888)
        self.assertEqual(result["exception_reserve_bytes"], 4096)
        self.assertEqual(result["stack_bytes"], 65536)

    def test_llvm_probe_loop_reserves_every_page(self):
        text = """1000 <probe>:
1000: stp x29, x30, [sp, #-0x60]!
1004: sub x9, sp, #0x7, lsl #12
1008: sub sp, sp, #0x1, lsl #12
100c: cmp sp, x9
1010: str xzr, [sp]
1014: b.ne 0x1008 <probe+0x8>
1018: sub sp, sp, #0x780
101c: bl 0x2000
"""
        code = next(iter(instructions(text).values()))
        self.assertEqual(frame_size(code), 30688)

    def test_missing_edges_and_dynamic_prologues_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "missing direct preparation path"):
            inspect(chain(False).replace("bl 0x4000", "bl 0x8000")
                    .replace("bl 0x5000", "bl 0x9000"))
        with self.assertRaisesRegex(ValueError, "unrecognized stack prologue"):
            frame_size([(0x1000, "sub", "sp, sp, x8")])

    def test_unknown_stack_pointer_writes_fail_closed_after_known_allocation(self):
        for opcode, operands in [("mov", "sp, x0"), ("add", "sp, sp, x0")]:
            with self.subTest(opcode=opcode), self.assertRaisesRegex(
                ValueError, "unrecognized stack prologue"
            ):
                frame_size([(0x1000, "sub", "sp, sp, #16"),
                            (0x1004, opcode, operands), (0x1008, "bl", "0x2000")])

    def test_late_stack_growth_cannot_hide_behind_first_call_or_branch(self):
        for opcode, operands in [("sub", "sp, sp, #8192"), ("mov", "sp, x0"),
                                 ("stp", "x19, x20, [sp, #-0x10]!")]:
            with self.subTest(opcode=opcode), self.assertRaisesRegex(ValueError, "stack write"):
                frame_size([(0x1000, "sub", "sp, sp, #16"),
                            (0x1004, "bl", "0x2000"), (0x1008, opcode, operands)])
        self.assertEqual(frame_size([(0x1000, "sub", "sp, sp, #16"),
                                    (0x1004, "bl", "0x2000"),
                                    (0x1008, "add", "sp, sp, #16"),
                                    (0x100c, "ret", "")]), 16)


if __name__ == "__main__":
    unittest.main()
