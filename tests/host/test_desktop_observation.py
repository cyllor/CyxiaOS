"""Window absence is accepted only from a complete guest observation."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'tools'))
from desktop_session import parse_windows


class WindowObservationTests(unittest.TestCase):
    def complete(self, records, count):
        return records+f'X11_INSPECT PASS windows={count}\n'.encode()

    def record(self, ident=1):
        return b'X11_INSPECT WINDOW '+json.dumps(dict(
            id=ident, x=0, y=0, width=640, height=480,
            title='directory', **{'class': 'Pcmanfm'}, instance='pcmanfm')).encode()+b'\n'

    def test_complete_set_and_real_empty_set(self):
        self.assertEqual([w['id'] for w in parse_windows(self.complete(self.record(1)+self.record(2), 2))], [1, 2])
        self.assertEqual(parse_windows(self.complete(b'X11_INSPECT WM_READY\n', 0)), [])

    def test_corrupt_client_is_not_silently_dropped(self):
        corrupt = self.record(2).replace(b'directory', b'dirKERNEL_LOG\nectory')
        with self.assertRaises(ValueError):
            parse_windows(self.complete(self.record(1)+corrupt, 2))

    def test_truncated_and_invalid_json_and_duplicate_reject_whole_set(self):
        for bad, count in [(self.record()[:-2], 1), (b'X11_INSPECT WINDOW {not-json}\n', 1),
                           (self.record()+self.record(), 2)]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    parse_windows(self.complete(bad, count))

    def test_invalid_schema_is_not_a_valid_absence_observation(self):
        with self.assertRaises(ValueError):
            parse_windows(self.complete(b'X11_INSPECT WINDOW {}\n', 1))

    def test_split_prefix_cannot_hide_an_entire_window(self):
        split = self.record().replace(b'WINDOW ', b'WINkernel-log\nDOW ')
        with self.assertRaises(ValueError):
            parse_windows(self.complete(split, 1))

    def test_missing_wrong_and_ambiguous_footer_are_invalid(self):
        for data in [self.record(), self.record()+b'X11_INSPECT PASS\n',
                     self.complete(self.record(), 0),
                     self.complete(self.complete(self.record(), 1), 1)]:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    parse_windows(data)


if __name__ == '__main__':
    unittest.main()
