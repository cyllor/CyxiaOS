"""A real EGL layer's two regions must reach their actual scanout position."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from os_wayland_egl_probe import pixels

HEADER = b'P6\n1024 768\n255\n'


def layer(top=704, right=b'\0\xff\0'):
    raw = bytearray(bytes((38, 40, 41)) * (1024 * 768))
    for y in range(top, top + 64):
        begin = (y * 1024) * 3
        raw[begin:begin + 128 * 3] = b'\xff\0\0' * 64 + right * 64
    return HEADER + raw


class WaylandEglPixels(unittest.TestCase):
    def test_both_regions_at_actual_layer_position_pass(self):
        result = pixels(layer())
        self.assertTrue(result['matched'])
        self.assertEqual((result['red_pixels'], result['green_pixels']), (2304, 2304))

    def test_blank_or_original_boot_frame_cannot_pass(self):
        self.assertFalse(pixels(HEADER + bytes(1024 * 768 * 3))['matched'])
        colors = ((255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0),
                  (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0))
        row = b''.join(bytes(rgb) * 128 for rgb in colors)
        self.assertFalse(pixels(HEADER + row * 768)['matched'])

    def test_wrong_location_or_missing_second_region_fails(self):
        self.assertFalse(pixels(layer(top=0))['matched'])
        self.assertFalse(pixels(layer(right=b'\xff\0\0'))['matched'])

    def test_truncated_scanout_fails(self):
        with self.assertRaises(ValueError):
            pixels(layer()[:-1])


if __name__ == '__main__':
    unittest.main()
