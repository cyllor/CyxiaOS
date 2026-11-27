"""Focused regressions for the linked default stack accounting."""
import unittest

from tools.check_v020_el1_stack import ROOTS, linked_frames, stack_change


class LinkedEl1Stacks(unittest.TestCase):
    def measure(self, boot_ops):
        code = {root: ["ret"] for root in ROOTS}
        code.update(boot_entry=boot_ops, builtin=["str x30,[sp,#-0x10]!", "ldr x30,[sp],#0x10", "ret"])
        instructions, symbols, notes = {}, [], []
        for i, (name, ops) in enumerate(code.items(), 1):
            va = i * 4096
            symbols.append({"Symbol": {
                "Name": {"Name": name}, "Value": va, "Size": 4 * len(ops), "Type": {"Name": "Function"},
            }})
            instructions.update((va + 4 * n, op) for n, op in enumerate(ops))
            if name in ROOTS:
                notes.append({"Entry": {"Functions": [name], "Size": 0}})
        return linked_frames({
            "FileSummary": {"Arch": "aarch64"}, "Symbols": symbols, "StackSizes": notes,
        }, instructions)

    def test_frame_depth_includes_machine_builtin_without_note(self):
        roots, count, no_notes = self.measure([
            "sub sp,sp,#0x1,lsl #12", "bl 0x5000", "add sp,sp,#0x1,lsl #12", "ret",
        ])
        self.assertEqual(roots["boot_entry"], {"path": ["boot_entry", "builtin"], "bytes": 4112})
        self.assertEqual(count, 5)
        self.assertEqual(no_notes, ["builtin"])

    def test_growing_back_edge_and_unclassified_indirect_call_fail(self):
        with self.assertRaisesRegex(ValueError, "conflicting SP"):
            self.measure(["sub sp,sp,#0x10", "b 0x1000"])
        with self.assertRaisesRegex(ValueError, "unmeasured control transfer"):
            self.measure(["blr x0", "ret"])

    def test_unreachable_noreturn_trap_and_live_trap_are_distinguished(self):
        roots, _, _ = self.measure(["b 0x1000", "brk #0x1"])
        self.assertEqual(roots["boot_entry"]["bytes"], 0)
        with self.assertRaisesRegex(ValueError, "reachable compiler trap"):
            self.measure(["brk #0x1"])

    def test_stack_writeback_and_unmeasured_register_update(self):
        self.assertEqual(stack_change("str x0,[sp],#-0x10", "f"), 16)
        self.assertEqual(stack_change("ldp x0,x1,[sp],#0x20", "f"), -32)
        with self.assertRaisesRegex(ValueError, "unmeasured SP update"):
            stack_change("mov sp,x0", "f")


if __name__ == "__main__":
    unittest.main()
