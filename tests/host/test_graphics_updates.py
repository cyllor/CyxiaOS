"""Ensure scanout acceptance cannot hide corrupt pixels or truncated evidence."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from verify_graphics_updates import FIRST_COLOR, expected_pixels, validate_pixels


class GraphicsEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'frame.ppm'
        self.expected = expected_pixels(FIRST_COLOR)

    def write(self, pixels, header=b'P6\n1024 768\n255\n'):
        self.path.write_bytes(header + pixels)

    def test_complete_evidence_accepts_exact_pixels(self):
        self.write(self.expected)
        self.assertEqual(validate_pixels(self.path, self.expected),
                         hashlib.sha256(self.expected).hexdigest())
        self.assertEqual(len(self.expected), 1024 * 768 * 3)

    def test_one_corrupt_pixel_on_either_side_of_blit_is_rejected(self):
        # Cover the near edge, last screen pixel and an interior pixel. None may
        # disappear into a rectangle-only comparison or ignored screen padding.
        for x, y in [(16, 23), (49, 23), (17, 22), (17, 39), (1023, 767), (20, 25)]:
            with self.subTest(x=x, y=y):
                pixels = bytearray(self.expected)
                pixels[(y * 1024 + x) * 3] ^= 1
                self.write(pixels)
                with self.assertRaisesRegex(AssertionError, f'x={x}, y={y}'):
                    validate_pixels(self.path, self.expected)

    def test_truncation_extra_data_and_incorrect_dimensions_are_rejected(self):
        for pixels in [self.expected[:-1], self.expected + b'\0']:
            self.write(pixels)
            with self.assertRaisesRegex(AssertionError, 'byte count'):
                validate_pixels(self.path, self.expected)
        self.write(self.expected, b'P6\n1024 767\n255\n')
        with self.assertRaisesRegex(AssertionError, 'dimensions/format'):
            validate_pixels(self.path, self.expected)
