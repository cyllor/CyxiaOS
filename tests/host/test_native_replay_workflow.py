"""The release replay workflow must be reproducible without historical artifacts."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/native-replay-current.yml"


class NativeReplayWorkflow(unittest.TestCase):
    def test_builds_the_pinned_patched_qemu_from_source(self):
        text = WORKFLOW.read_text()
        self.assertIn("CyxiaOS-V0.11", text)
        self.assertNotIn("actions/download-artifact", text)
        self.assertNotIn("artifact-ids:", text)
        self.assertNotIn("run-id:", text)
        self.assertIn("f8ed81651e61d9c2166df6121ce2af0f44f06b3e", text)
        self.assertIn("tools/qemu/cyxia-per-vcpu-pmu.patch", text)
        self.assertIn("ninja -C build qemu-system-aarch64", text)
        self.assertIn('--qemu "$RUNNER_TEMP/qemu/build/qemu-system-aarch64"', text)

    def test_runs_every_service_restart_boundary_with_source_attestation(self):
        text = WORKFLOW.read_text()
        for profile in ("after-ready", "after-reserve", "after-start",
                        "after-completion", "after-result-record"):
            self.assertIn(profile, text)
        for expectation in ("service-restart-ready", "service-restart-reserve",
                            "service-restart-start", "service-restart-completion",
                            "service-restart-result"):
            self.assertIn(expectation, text)
        self.assertIn('--qemu-source "$RUNNER_TEMP/qemu"', text)
        self.assertIn("service-restart-status.tsv", text)


if __name__ == "__main__":
    unittest.main()
