"""Scanout fixtures reject boot bars, a cursor and incomplete rectangle transfers.

These validate the diagnostic's evidence boundary, not a rendered guest frame.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from os_cosmic_startup_probe import scanout_evidence

HEADER = b'P6\n1024 768\n255\n'
COLORS = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0),
          (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0)]
BOOT = b''.join(bytes(color) * 128 for color in COLORS) * 768
DARK_ROW = bytes((39, 41, 42)) * 1024


class CosmicScanoutEvidence(unittest.TestCase):
    def test_boot_cursor_and_partial_scanout_do_not_pass(self):
        cursor_only = bytearray(BOOT)
        cursor_only[:3] = b'\x27\x29\x2a'
        for pixels in (BOOT, cursor_only, DARK_ROW * 64 + BOOT[64 * 1024 * 3:]):
            with self.subTest(changed=len(pixels) - len(BOOT)):
                self.assertFalse(scanout_evidence(HEADER + pixels)['boot_scanout_replaced'])
        self.assertEqual(scanout_evidence(HEADER + BOOT)['boot_pixels_remaining'], 786432)

    def test_full_dark_scanout_has_its_actual_hash_and_dimensions(self):
        proof = scanout_evidence(HEADER + DARK_ROW * 768)
        self.assertTrue(proof['boot_scanout_replaced'])
        self.assertEqual(proof['boot_pixels_remaining'], 0)
        self.assertEqual(proof['pixels'], 786432)
        self.assertEqual(len(proof['scanout_sha256']), 64)

    def test_incomplete_and_unexpected_ppm_data_is_rejected(self):
        for data in (HEADER + BOOT[:-1], HEADER + BOOT + b'x',
                     (HEADER + BOOT).replace(b'1024 768', b'1024 767', 1),
                     (HEADER + BOOT).replace(b'255\n', b'256\n', 1)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                scanout_evidence(data)


if __name__ == '__main__':
    unittest.main()
