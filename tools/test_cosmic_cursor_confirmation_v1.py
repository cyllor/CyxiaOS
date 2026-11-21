"""Opaque cursor-shape validation rejects partial and displaced input evidence."""
import unittest
import os_cosmic_workspace_probe as subject


class CursorShape(unittest.TestCase):
    def test_background_edges_do_not_replace_any_opaque_cursor_pixel(self):
        width, height = subject.pointer_probe.WIDTH, subject.pointer_probe.HEIGHT
        data = bytearray([80]) * (3 * width * height)
        mask = ([(1, 1), (3, 4)], [(0, 0), (2, 6)])
        def put(dx, dy, value):
            at = 3 * ((100 + dy) * width + 100 + dx); data[at:at + 3] = bytes([value]) * 3
        for dx, dy in mask[0]: put(dx, dy, 255)
        for dx, dy in mask[1]: put(dx, dy, 0)
        self.assertTrue(subject.cursor_matches(data, (100, 100), mask))
        put(4, 1, 139)  # Background-dependent antialiasing is outside the opaque mask.
        self.assertTrue(subject.cursor_matches(data, (100, 100), mask))
        self.assertFalse(subject.cursor_matches(data, (101, 100), mask))
        put(3, 4, 80)
        self.assertFalse(subject.cursor_matches(data, (100, 100), mask))
        put(3, 4, 255); put(2, 6, 80)
        self.assertFalse(subject.cursor_matches(data, (100, 100), mask))
        self.assertFalse(subject.cursor_matches(data, (width, height), mask))
        self.assertFalse(subject.cursor_matches(data, (100, 100), ([], [])))


if __name__ == '__main__': unittest.main()
