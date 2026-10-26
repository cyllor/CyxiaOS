from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NativeTaskCredit(unittest.TestCase):
    def test_builtin_workers_do_not_run_on_tail_credit_below_one_full_turn(self):
        source = (ROOT / "kernel/src/domain_tasks.rs").read_text()

        self.assertIn("const BUILTIN_MIN_GRANT_NS: u64 = 10_000_000;", source)
        self.assertIn("if d.thread == builtin(slot)", source)
        self.assertIn("BUILTIN_MIN_GRANT_NS", source[source.index("let safety ="):])


if __name__ == "__main__":
    unittest.main()
