"""Exercise the linked admission oracle on small instruction transcripts."""

import unittest

from tools import check_v0199_virtio_blk_admission as checker


class VirtioBlockAdmissionTests(unittest.TestCase):
    def test_read_only_comparison_guards_the_same_register_used_for_driver_features(self):
        start, failure = 0x100, 0x500
        sequence = checker.PREFIX + [
            "ldr w10,[x9,#0x10]", "str wzr,[x9,#0x14]", "dsb sy", "ldr w8,[x9,#0x10]",
            f"tbz w10,#0x0,{failure:#x}", "mov w10,#0x220", "and w8,w8,w10",
            "cmp w8,#0x200", f"b.ne {failure:#x}", "str wzr,[x9,#0x24]", "mov w10,#0x1",
            "str w8,[x9,#0x20]", "mov w8,#0xb", "str w10,[x9,#0x24]", "str w10,[x9,#0x20]",
            "mov w10,#0xc8", "str w8,[x9,#0x70]", "dsb sy", "ldr w8,[x9,#0x70]", "and w8,w8,w10",
            "cmp w8,#0x8", f"b.ne {failure:#x}",
        ]
        words = {start + 4 * i: value for i, value in enumerate(sequence)}
        words.update({failure: "ldr w8,[x9,#0x70]", failure + 4: "orr w8,w8,#0x80",
                      failure + 8: "str w8,[x9,#0x70]", failure + 12: "mov w23,#0x3"})
        evidence = checker.negotiation(words, start)
        self.assertEqual(evidence["possible_low_driver_features"], [1 << 9])
        self.assertTrue(evidence["rejects_read_only_before_publishing_features"])
        for original, changed in (("cmp w8,#0x200", "cmp w8,#0x220"),
                                  ("str w8,[x9,#0x20]", "str w10,[x9,#0x20]")):
            with self.subTest(changed=changed):
                different = dict(words)
                different[start + 4 * sequence.index(original)] = changed
                with self.assertRaisesRegex(ValueError, "expected"):
                    checker.negotiation(different, start)

    def test_branch_scan_counts_both_outcomes_and_rejects_unreviewed_control_transfer(self):
        words = {0x100: "cbz w0,0x200", 0x104: "b 0x300"}
        self.assertEqual(checker.paths_to_exits(words, 0x100, {0x200, 0x300}), {0x100, 0x104})
        with self.assertRaisesRegex(ValueError, "unverified bytes"):
            checker.paths_to_exits(words, 0x100, {0x300})
        words[0x104] = "br x0"
        with self.assertRaisesRegex(ValueError, "unexpected control transfer"):
            checker.paths_to_exits(words, 0x100, {0x200, 0x300})


if __name__ == "__main__":
    unittest.main()
