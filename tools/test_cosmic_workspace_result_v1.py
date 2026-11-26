"""Partial capture records survive a later failure; no guest behavior is mocked as evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import os_cosmic_workspace_probe as subject


class PartialCapture(unittest.TestCase):
    def test_later_error_preserves_completed_steps_and_red_verdict(self):
        class Qmp:
            transcript = [{'command': 'fixture-not-a-real-guest'}]
        def fail(*args, _result, **options):
            _result['completed_step'] = dict(matched=True, elapsed_seconds=3.1)
            raise RuntimeError('later fixture failure')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            with patch.object(subject, '_interaction', side_effect=fail), self.assertRaises(RuntimeError):
                subject.interaction(None, Qmp(), output)
            value = json.loads((output / 'workspace-result.json').read_text())
            self.assertEqual(value['status'], 'FAIL')
            self.assertFalse(value['full_os_verified'])
            self.assertFalse(value['cosmic_session_verified'])
            self.assertEqual(value['completed_step']['elapsed_seconds'], 3.1)
            self.assertEqual(value['error'], 'later fixture failure')
            self.assertNotIn('complete_teardown', value)
            self.assertEqual(json.loads((output / 'workspace-qmp.json').read_text()), Qmp.transcript)


if __name__ == '__main__': unittest.main()
