from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NativeInputPage(unittest.TestCase):
    def test_paid_preparation_encodes_directly_into_private_input_page(self):
        source = (ROOT / "kernel/src/prototype_runtime/native.rs").read_text()

        self.assertIn("let input = unsafe { &mut (*input_ptr(slot)).0 };", source)
        self.assertNotIn("let mut input = [0; 512];", source)
        self.assertNotIn("(*page).0.copy_from_slice(&input);", source)
        self.assertIn('core::arch::asm!("dsb ish", options(nostack));', source)

        encoder = (ROOT / "kernel/src/domain_control.rs").read_text()
        self.assertIn("input.fill(0);", encoder)

    def test_failed_target_lookup_retains_attributable_context(self):
        source = (ROOT / "kernel/src/domain_control.rs").read_text()
        target = source.index("let target_result = read_target_batch")
        checked = source.index("if let Err(error) = target_result", target)
        lookup = source.index("preparation_lookup(index, f, ordinal, wall_started);", checked)

        self.assertLess(target, checked)
        self.assertLess(checked, lookup)
        self.assertIn("descriptor.target_source", source)

    def test_preparation_diagnostics_use_zero_terminated_rows(self):
        source = (ROOT / "kernel/src/domain_control.rs").read_text()

        self.assertIn("DOMAIN_PREPARATION_DETAIL.0[base + phase + 1].store(0", source)
        self.assertIn("DOMAIN_PREPARATION_EVIDENCE.0[base + phase + 1].store(0", source)
        self.assertIn("DOMAIN_PREPARATION_CONTEXT.0[base + 7].store(0", source)


if __name__ == "__main__":
    unittest.main()
