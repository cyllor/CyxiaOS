from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NativeTaskCredit(unittest.TestCase):
    def test_builtin_workers_do_not_run_on_tail_credit_below_one_full_turn(self):
        source = (ROOT / "kernel/src/domain_tasks.rs").read_text()

        self.assertIn("const BUILTIN_MIN_GRANT_NS: u64 = 10_000_000;", source)
        self.assertIn("if d.thread == builtin(slot)", source)
        self.assertIn("BUILTIN_MIN_GRANT_NS", source[source.index("let safety ="):])

    def test_builtin_fixture_yields_after_a_fixed_batch_with_timer_backstop(self):
        assembly = (ROOT / "kernel/src/smp_user.S").read_text()
        runtime = (ROOT / "kernel/src/smp.rs").read_text()

        self.assertIn("mov x12, #128", assembly)
        self.assertIn("subs x12, x12, #1", assembly)
        self.assertIn("svc #4", assembly)
        self.assertIn("cbz x2, smp_busy", assembly)
        self.assertIn("cmp x2, #4", assembly)
        self.assertIn("b.eq smp_bounded", assembly)
        self.assertIn("ctx.regs[2] = 4;", runtime)
        self.assertIn("enter_service(\n            ctx", runtime)
        self.assertIn("            false,\n        );", runtime)
        self.assertIn("fn fixture_yielded", runtime)
        self.assertIn("ctx.kind == 9", runtime[runtime.index("fn fixture_yielded"):])
        self.assertIn(
            '#[cfg(feature = "unified-runtime")]',
            runtime[runtime.index("fn fixture_yielded"):],
        )
        self.assertIn("ctx.esr & 0xffff == 4", runtime[runtime.index("fn fixture_yielded"):])


if __name__ == "__main__":
    unittest.main()
