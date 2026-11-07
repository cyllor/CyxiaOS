"""Production-bound R02/R08/R09 host regressions, not native acceptance.

Run with Rust 1.95.0 and an offline populated Cargo cache. Generated harnesses
and source binding metadata live outside the repository; no kernel substitutes
are written. R09 exercises only enumeration, never a replay reservation/probe.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ControlRemediation(unittest.TestCase):
    def run_harness(self, generator, scenarios=((),)):
        with tempfile.TemporaryDirectory(prefix="cyxia-control-") as directory:
            out = Path(directory)
            subprocess.run([sys.executable, str(ROOT / "tests/host" / generator),
                            str(out)], check=True, cwd=ROOT)
            manifest = str(out / "Cargo.toml")
            # The isolated harness has no checked-in lock. Resolve only from
            # the offline cache, then freeze every build/run with --locked.
            subprocess.run(["cargo", "generate-lockfile", "--offline",
                            "--manifest-path", manifest], check=True, cwd=ROOT)
            env = dict(os.environ)
            env.setdefault("CARGO_TARGET_DIR", str(out / "target"))
            for arguments in scenarios:
                subprocess.run(["cargo", "run", "--locked", "--offline",
                                "--manifest-path", manifest, "--", *arguments],
                               check=True, cwd=ROOT, env=env)

    def test_unknown_feedback_remains_monotonic_through_real_poll(self):
        self.run_harness("generate_control_feedback.py",
                         [(mode,) for mode in ("late_pending", "early_pending",
                                              "deadline", "foreign_service")])

    def test_all_ordinary_ipc_endpoints_and_retry_cursor(self):
        self.run_harness("generate_task_target_regression.py")

    def test_replay_target_lookup_retains_typed_errors(self):
        self.run_harness("generate_replay_target_cursor.py")


if __name__ == "__main__":
    unittest.main()
