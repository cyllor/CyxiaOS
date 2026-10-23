"""Reject incomplete, changed or misleading reactor evidence without a guest."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import verify_rust_reactor as verify


def successful_log():
    rows = [verify.START]
    for name in verify.CHECKS:
        rows.append("RUST_REACTOR CHECK name=" + name + " result=PASS")
        if name in ("timer-first-expiration", "timer-rearm"):
            cycle = 1 if name == "timer-first-expiration" else 2
            rows.append(f"RUST_REACTOR TIMER cycle={cycle} expirations=1 elapsed_ns=20000000")
    rows.append(verify.SUCCESS)
    return ("\n".join(rows) + "\n").encode()


class ReactorEvidenceTests(unittest.TestCase):
    def test_every_readiness_and_cleanup_observation_is_required(self):
        good = successful_log()
        self.assertEqual(len(verify.validate(good)), 25)
        for name in verify.CHECKS:
            marker = ("RUST_REACTOR CHECK name=" + name + " result=PASS\n").encode()
            for bad in (good.replace(marker, b""), good.replace(marker, marker * 2),
                        good.replace(marker, marker.replace(b"PASS", b"FAIL"))):
                with self.subTest(name=name), self.assertRaises(AssertionError):
                    verify.validate(bad)

    def test_timer_order_count_duration_and_damage_cannot_pass(self):
        good = successful_log()
        for bad in (
            good.replace(b"elapsed_ns=20000000", b"elapsed_ns=19999999"),
            good.replace(b"elapsed_ns=20000000", b"elapsed_ns=2000000000"),
            good.replace(b"cycle=2 expirations=1", b"cycle=1 expirations=1"),
            good.replace(b"cycle=2 expirations=1", b"cycle=2 expirations=2"),
            good.replace(b"RUST_REACTOR TIMER cycle=1 expirations=1 elapsed_ns=20000000\n", b""),
            good.replace(b"name=waker-cycle-2 result=PASS", b"name=waker-cycle-2 result=PA\nnoise\nSS"),
            good + b"RUST_REACTOR PASS mio=1.1.1 cycles=3 cosmic_runtime=0\n",
            good.replace(b"mio=1.1.1", b"mio=0.0.0"),
            good.replace(b"cosmic_runtime=0", b"cosmic_runtime=1"),
        ):
            with self.subTest(data=bad[-150:]), self.assertRaises(AssertionError):
                verify.validate(bad)


if __name__ == "__main__":
    unittest.main()
