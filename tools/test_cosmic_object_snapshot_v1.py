"""Receipt fixtures verify complete markers; these are not guest evidence."""
import re
import unittest
import os_cosmic_time_probe as subject


class Console:
    def __init__(self, raw): self.raw = raw; self.commands = []
    def command(self, value): self.commands.append(value); return 0
    def until(self, pattern, start):
        match = re.search(pattern, self.raw[start:])
        if match is None: raise TimeoutError('incomplete fixture')
        return match


class CompleteObjectReceipt(unittest.TestCase):
    def test_compact_is_explicit_and_original_system_marker_remains_required(self):
        body = b'SHARED_OBJECTS objects=0 pages=0 mappings=0\r\n'
        original = Console(body + b'AI_SYSTEM_END\r\n')
        self.assertEqual(subject.shared_state(original), dict(objects=0, pages=0, mappings=0))
        self.assertEqual(original.commands, ['ai system'])
        compact = Console(body + b'AI_OBJECTS_END\r\n')
        self.assertEqual(subject.shared_state(compact, compact=True), dict(objects=0, pages=0, mappings=0))
        self.assertEqual(compact.commands, ['ai objects'])
        with self.assertRaises(TimeoutError): subject.shared_state(compact)
        for raw in (body, body + b'AI_SYSTEM_END\r\n'):
            with self.assertRaises(TimeoutError): subject.shared_state(Console(raw), compact=True)
        for raw in (b'AI_OBJECTS_END\r\n', body + body + b'AI_OBJECTS_END\r\n'):
            with self.assertRaises(ValueError): subject.shared_state(Console(raw), compact=True)


if __name__ == '__main__': unittest.main()
