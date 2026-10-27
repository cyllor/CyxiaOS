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


if __name__ == "__main__":
    unittest.main()
