"""Bounded preparation skips retain a durable per-family reason."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from doctor import RUST_BIN, env


class PreparationSkipEvidence(unittest.TestCase):
    def test_per_family_reason_counters_are_bounded_and_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            harness = directory / "harness.rs"
            harness.write_text(
                "#[path="
                + json.dumps(str(ROOT / "kernel/src/domain_control/preparation_skip.rs"))
                + "] mod preparation_skip;\n"
            )
            (directory / "Cargo.toml").write_text(
                "[package]\n"
                'name="preparation-skip-evidence"\n'
                'version="0.1.0"\n'
                'edition="2024"\n'
                "[lib]\n"
                'path="harness.rs"\n'
                "[dependencies]\n"
                "cyxia-prototype={path="
                + json.dumps(str(ROOT / "crates/prototype"))
                + "}\n[workspace]\n"
            )
            command = [
                str(RUST_BIN / "cargo"),
                "test",
                "--offline",
                "--manifest-path",
                str(directory / "Cargo.toml"),
                "--target-dir",
                str(ROOT / "target/host-preparation-skip-evidence"),
                "--",
                "--test-threads=1",
            ]
            result = subprocess.run(
                command,
                cwd=ROOT,
                env=env(),
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("3 passed; 0 failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
