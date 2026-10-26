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
        lookup = source.index("preparation_lookup(index, f, ordinal, wall_started);")
        target = source.index("let target_result = read_target_batch", lookup)
        checked = source.index("target_result?;", target)

        self.assertLess(lookup, target)
        self.assertLess(target, checked)
        self.assertIn("descriptor.target_source", source)


if __name__ == "__main__":
    unittest.main()
