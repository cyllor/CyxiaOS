import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from shell import InputQueue


class InputIntegrity(unittest.TestCase):
    def test_terminator_in_overflow_chunk_does_not_discard_next_command(self):
        q = InputQueue()
        q.feed(b'x' * 4090)
        self.assertTrue(q.feed(b'1234567\r'))
        self.assertFalse(q.discarding)
        q.feed(b'pwd\r')
        self.assertEqual(q.take(), b'pwd\r')

    def test_overflow_suffix_never_becomes_command(self):
        q = InputQueue()
        physical_line = b'write /long ' + b'x' * (4352 - 12) + b'rm /victim\r'
        delivered = bytearray()
        for offset in range(0, len(physical_line), 256):
            if q.feed(physical_line[offset:offset + 256]):
                delivered.extend(b'\x03')
            delivered.extend(q.take())
        while q.pending:
            delivered.extend(q.take())
        self.assertIn(b'\x03', delivered)
        self.assertNotIn(b'rm /victim', delivered)
        q.feed(b'pwd\r')
        self.assertEqual(q.take(), b'pwd\r')

    def test_next_complete_line_after_discard_is_preserved(self):
        q = InputQueue()
        self.assertTrue(q.feed(b'x' * 4097))
        self.assertFalse(q.feed(b'rm /victim'))
        self.assertEqual(q.take(), b'')
        q.feed(b' ignored\r\npwd\r')
        self.assertEqual(q.take(), b'\npwd\r')
