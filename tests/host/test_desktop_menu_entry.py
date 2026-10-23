from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import verify_desktop_menu as gate


class LocationEntryBarrierTests(unittest.TestCase):
    def image(self, directory, focused, selected):
        pixels = bytearray(b"\xff" * (1024 * 768 * 3))
        view = dict(x=192, y=139, width=640, height=480)
        points = [(view["x"] + dx, view["y"] + 29)
                  for dx in (270, 350, 500)] if focused else []
        if selected:
            points += [(view["x"] + 270, view["y"] + dy) for dy in range(35, 45)]
        for x, y in points:
            start = (y * 1024 + x) * 3
            pixels[start:start + 3] = bytes((53, 132, 228))
        path = directory / "entry.ppm"
        path.write_bytes(b"P6\n1024 768\n255\n" + pixels)
        return path, view

    def test_selected_text_without_focus_cannot_establish_entry_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, view = self.image(Path(temporary), focused=False, selected=True)
            state = gate.location_entry_state(path, view)
            self.assertFalse(state["focused"])
            self.assertEqual(state["selected_pixels"], 10)

    def test_entry_border_does_not_count_as_selected_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, view = self.image(Path(temporary), focused=True, selected=False)
            state = gate.location_entry_state(path, view)
            self.assertTrue(state["focused"])
            self.assertEqual(state["selected_pixels"], 0)

    def test_truncated_scanout_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, view = self.image(Path(temporary), focused=True, selected=True)
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(AssertionError):
                gate.location_entry_state(path, view)

    def test_ready_barrier_waits_for_both_focus_and_consumed_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = SimpleNamespace(output=Path(temporary), qmp=Mock())
            observations = [dict(focused=False, selected_pixels=0),
                            dict(focused=True, selected_pixels=10),
                            dict(focused=True, selected_pixels=0)]
            with patch.object(gate, "location_entry_state", side_effect=observations), \
                    patch.object(gate, "pump") as pump:
                state = gate.wait_location_entry(guest, {}, "test", selected=False)
            self.assertEqual(state, observations[-1])
            self.assertEqual(guest.qmp.execute.call_count, 3)
            self.assertEqual(pump.call_count, 2)


if __name__ == "__main__":
    unittest.main()
