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
        self.assertIn("if capture_boundary", entry)
        self.assertIn("a02_capture::enter(task);", entry)
        self.assertIn("a02_capture::returned();", entry)
        self.assertIn("user::enter_integer_probe(context, root);", entry)
        native = (ROOT / "kernel/src/prototype_runtime/native.rs").read_text()
        self.assertEqual(native.count("!worker.native.probing,"), 2)
        self.assertIn("if record_slice_evidence && slot < 4", entry)
        self.assertIn("RECORD_SLICE_EXCEPTION[slot].store(record_slice_evidence", entry)
        self.assertIn("RECORD_SLICE_EXCEPTION[slot].load(Ordering::Acquire)", entry)

        arch = (ROOT / "crates/arch-aarch64/src/user.rs").read_text()
        assembly = (ROOT / "crates/arch-aarch64/src/user.S").read_text()
        self.assertIn("pub unsafe fn enter_integer_probe", arch)
        self.assertIn("enter_inner(context, root | (asid << 48), false)", arch)
        self.assertIn("cbz x1, .Luser_integer_restore", assembly)
        self.assertIn("cbz x10, .Luser_integer_save", assembly)
        self.assertIn("cbz x1, .Luser_features_configured", assembly)
        self.assertIn("cbz x10, .Luser_features_restored", assembly)
        self.assertIn("cbz x10, .Luser_state_restored", assembly)
        self.assertIn("cbz x10, .Luser_low_walks_revoked", assembly)
        self.assertIn("static INTEGER_ONLY", arch)
        self.assertIn("context.regs.copy_from_slice(regs)", arch)
        self.assertIn("if !INTEGER_ONLY[slot]", arch)
        self.assertIn("let asid = 0x80u64 + super::cpu::slot() as u64", arch)
        self.assertIn("root | (asid << 48)", arch)
        self.assertIn("if restore_fp", arch)


if __name__ == "__main__":
    unittest.main()
