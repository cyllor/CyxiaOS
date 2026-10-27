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
        self.assertIn("ticks(PROBE_SERVICE_SLICE_NS)", source)
        self.assertIn("fn run_probe_turn(", source)
        self.assertIn("if !worker.probed {", source)
        self.assertIn("run_probe_turn(worker, credit, begin);", source)
        probe = source[source.index("fn run_probe_turn(") : source.index("fn run_turn(")]
        self.assertNotIn("PaidWorkWitness", probe)
        self.assertNotIn("ns(timer::ticks())", probe)
        self.assertIn("let now = timer::ticks();", probe)
        self.assertIn("now >= worker.native.probe_deadline", probe)
        self.assertIn("timer::frequency().saturating_mul(PROBE_WALL_SECONDS)", probe)
        self.assertIn("let reservation_ns = if worker.probed && !worker.native.probing", source)
        self.assertIn("PROBE_PREPAY_NS\n    };", source)
        self.assertIn("!worker.native.probing", source)

        entry = (ROOT / "kernel/src/smp.rs").read_text()
        probe_path = entry[entry.index("if !capture_boundary {") : entry.index("let saved_daif")]
        self.assertIn("timer::arm(deadline);", probe_path)
        self.assertIn("user::enter_integer_probe(context, root);", probe_path)
        self.assertNotIn("heartbeat(true);", probe_path)
        self.assertIn("return;", probe_path)
        self.assertNotIn("msr daifset", probe_path)
        self.assertIn("pub(crate) fn restore_service_heartbeat()", entry)
        self.assertIn("probe_heartbeat_pending: bool", source)
        self.assertIn("if worker.native.probe_heartbeat_pending", source)
        self.assertIn("crate::smp::restore_service_heartbeat();", source)
        self.assertIn("worker.native.probe_heartbeat_pending = true;", source)
        self.assertIn("if capture_boundary", entry)
        self.assertIn("a02_capture::enter(task);", entry)
        self.assertIn("a02_capture::returned();", entry)
        self.assertIn("user::enter_integer_probe(context, root);", entry)
        self.assertIn(
            "worker.native.capture_index,\n            false,\n            false,",
            probe,
        )
        self.assertIn("if record_slice_evidence && slot < 4", entry)
        self.assertIn("if record_slice_evidence {\n            RECORD_SLICE_EXCEPTION[slot].store(true", entry)
        self.assertIn("RECORD_SLICE_EXCEPTION[slot].store(false", entry)
        self.assertIn("RECORD_SLICE_EXCEPTION[slot].load(Ordering::Acquire)", entry)

        arch = (ROOT / "crates/arch-aarch64/src/user.rs").read_text()
        assembly = (ROOT / "crates/arch-aarch64/src/user.S").read_text()
        self.assertIn("pub unsafe fn enter_integer_probe", arch)
        self.assertIn("enter_inner(context, root | (asid << 48), false, false)", arch)
        self.assertIn("cbz x1, .Luser_integer_restore", assembly)
        self.assertIn("cbz x10, .Luser_integer_save", assembly)
        self.assertIn("cbz x1, .Luser_features_configured", assembly)
        self.assertIn("cbz x10, .Luser_features_restored", assembly)
        self.assertIn("cbz x10, .Luser_state_restored", assembly)
        self.assertIn("cbz x11, .Luser_low_walks_revoked", assembly)
        self.assertIn("static INTEGER_ONLY", arch)
        self.assertIn("context.regs.copy_from_slice(regs)", arch)
        self.assertIn("if !INTEGER_ONLY[slot]", arch)
        self.assertIn("let asid = 0x80u64 + super::cpu::slot() as u64", arch)
        self.assertIn("root | (asid << 48)", arch)
        self.assertIn("INTEGER_ONLY[slot].store(!restore_fp", arch)
        self.assertIn("if invalidate", arch)


if __name__ == "__main__":
    unittest.main()
