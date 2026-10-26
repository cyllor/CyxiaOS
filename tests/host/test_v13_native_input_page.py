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


if __name__ == "__main__":
    unittest.main()
