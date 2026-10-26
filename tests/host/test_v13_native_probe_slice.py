from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NativeProbeSlice(unittest.TestCase):
    def test_mapping_probe_has_wall_escape_headroom_without_larger_cpu_credit(self):
        source = (ROOT / "kernel/src/prototype_runtime/native.rs").read_text()

        self.assertRegex(source, r"const PROBE_PREPAY_NS: u64 = 8_000_000;")
        self.assertRegex(source, r"const SERVICE_SLICE_NS: u64 = 100_000;")
        match = re.search(r"const PROBE_SERVICE_SLICE_NS: u64 = ([0-9_]+);", source)
        self.assertIsNotNone(match)
        self.assertGreater(int(match.group(1).replace("_", "")), 8_000_000)
        self.assertIn("if worker.native.probing {\n            PROBE_SERVICE_SLICE_NS", source)
        self.assertIn("let reservation_ns = if worker.probed && !worker.native.probing", source)
        self.assertIn("PROBE_PREPAY_NS\n    };", source)
        self.assertIn("!worker.native.probing", source)

        entry = (ROOT / "kernel/src/smp.rs").read_text()
        self.assertIn("a02_capture::enter(task);", entry)
        self.assertIn("a02_capture::returned();", entry)
        self.assertIn("if record_slice_evidence && slot < 4", entry)
        self.assertIn("RECORD_SLICE_EXCEPTION[slot].store(record_slice_evidence", entry)
        self.assertIn("RECORD_SLICE_EXCEPTION[slot].load(Ordering::Acquire)", entry)


if __name__ == "__main__":
    unittest.main()
