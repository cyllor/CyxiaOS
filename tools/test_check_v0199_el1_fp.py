"""Regression checks for the static EL1 FP instruction audit."""

import unittest

from tools import check_v0199_el1_fp as checker


class El1FpTests(unittest.TestCase):
    def test_all_executable_words_are_accounted_and_match_the_elf(self):
        raw = bytes.fromhex("1f2003d578563412")
        loads = [{"va": 0x4000, "offset": 0, "size": len(raw), "flags": 5}]
        text = "4000: d503201f  nop\n4004: 78 56 34 12  .word 0x12345678\n"
        rows = list(checker.executable_rows(raw, loads, text))
        self.assertEqual(rows, [(0x4000, "nop"), (0x4004, None)])
        with self.assertRaisesRegex(ValueError, "missing executable bytes"):
            list(checker.executable_rows(raw, loads, text.splitlines()[0]))
        with self.assertRaisesRegex(ValueError, "disassembly bytes differ"):
            list(checker.executable_rows(raw, loads, text.replace("d503201f", "d65f03c0")))
        with self.assertRaisesRegex(ValueError, "duplicate or unordered"):
            list(checker.executable_rows(raw, loads, text + text.splitlines()[0]))

    def test_context_moves_must_match_the_complete_reviewed_sequence(self):
        for name in checker.CONTEXTS:
            seq = checker.context_sequence(name)
            with self.subTest(routine=name):
                self.assertTrue(checker.context_matches(name, ["nop", *seq, "ret"]))
                self.assertFalse(checker.context_matches(name, seq[:-1]))
                self.assertFalse(checker.context_matches(name, seq + ["fadd d0,d0,d1"]))
                changed = [op.replace("[x30,#0x330]", "[x30,#0x338]") for op in seq]
                self.assertFalse(checker.context_matches(name, changed))

    def test_sha_and_fp_are_disallowed_outside_the_context(self):
        for instruction in ("sha256h q0,q1,v2.4s", "msr FPCR,x9", "fmov d0,x9",
                            "zip1 z0.b,z1.b,z2.b", "smstart"):
            with self.subTest(instruction=instruction):
                self.assertTrue(checker.uses_fp(instruction))
        self.assertFalse(checker.uses_fp("b 0x4000 <fmove>"))
        self.assertFalse(checker.uses_fp("add x0,x1,#0x20"))


if __name__ == "__main__":
    unittest.main()
