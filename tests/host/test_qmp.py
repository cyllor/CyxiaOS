import unittest
from tools.run_qemu import JsonLines, required_markers
class QmpTests(unittest.TestCase):
 def test_partial_and_events(self):
  q=JsonLines();self.assertEqual(q.feed(b'{"event":"STOP"}\r\n{"ret'),[{'event':'STOP'}]);self.assertEqual(q.feed(b'urn":{}}\r\n'),[{'return':{}}])
 def test_invalid(self):
  with self.assertRaises(ValueError):JsonLines().feed(b'no-json\n')
 def test_no_output_never_passes(self):self.assertFalse(required_markers(b'', 'boot-entry'))
 def test_failure_never_passes(self):self.assertFalse(required_markers(b'BOOT_ENTRY PLATFORM_OK FAIL', 'boot-entry'))
