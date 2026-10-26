from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NativePrivateClear(unittest.TestCase):
    def test_private_clear_is_bounded_by_one_page_not_an_in_tb_clock(self):
        source = (ROOT / "kernel/src/prototype_runtime/native.rs").read_text()

        self.assertIn("const PRIVATE_CLEAR_SLICE_BYTES: usize = 4096;", source)
        self.assertNotIn("const PRIVATE_CLEAR_SLICE_NS", source)
        self.assertIn("let slice_end = offset", source)
        self.assertIn("while offset < slice_end", source)
        self.assertNotIn("timer::cpu_ticks().saturating_sub(started) >= slice_ticks", source)
        self.assertNotIn('core::arch::asm!("dc zva', source)
        self.assertIn("core::ptr::write_bytes(address, 0, block_bytes);", source)
        self.assertIn('core::arch::asm!("dsb ish", options(nostack));', source)


if __name__ == "__main__":
    unittest.main()
