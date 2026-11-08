import json
from pathlib import Path
import struct
import tempfile
import unittest

from verify_unified import capture


class OptionalCaptureTests(unittest.TestCase):
    def run_capture(self, optional, *, fail_optional=False, fail_core=False):
        class Qmp:
            def execute(self, command, arguments=None):
                if command == 'stop':
                    return {}
                if command != 'pmemsave':
                    raise AssertionError(command)
                address = arguments['val']
                if address == 1 and fail_core or address == 2 and fail_optional:
                    raise OSError('injected memory read failure')
                Path(arguments['filename']).write_bytes(b'corebank' if address == 1 else optional)

        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            guest = {'qmp': Qmp(), 'folder': folder}
            locations = {'CORE': {'pa': 1, 'size': 8},
                         'APPLICATION_REQUEST_EVIDENCE': {'pa': 2, 'size': 6208}}
            result = capture([guest], [locations], 'final-')
            raw = (folder / 'final-APPLICATION_REQUEST_EVIDENCE.bin')
            errors = folder / 'optional-capture-errors.json'
            return result, raw.read_bytes() if raw.exists() else None, (
                json.loads(errors.read_text()) if errors.exists() else None)

    def test_unpublished_and_interrupted_optional_banks_preserve_raw_bytes(self):
        for sequence in (0, 1):
            raw = struct.pack('<Q', sequence) + bytes(6200)
            result, stored, errors = self.run_capture(raw)
            self.assertEqual(result[0]['CORE'], b'corebank')
            self.assertEqual(result[0]['APPLICATION_REQUEST_EVIDENCE'], raw)
            self.assertEqual(stored, raw)
            self.assertIsNone(errors)

    def test_optional_read_failure_cannot_discard_core_bank(self):
        result, stored, errors = self.run_capture(bytes(6208), fail_optional=True)
        self.assertEqual(result, [{'CORE': b'corebank'}])
        self.assertIsNone(stored)
        self.assertEqual(errors[0]['symbol'], 'APPLICATION_REQUEST_EVIDENCE')
        self.assertIn('injected memory read failure', errors[0]['error'])

    def test_core_read_failure_is_still_fatal(self):
        with self.assertRaisesRegex(OSError, 'injected memory read failure'):
            self.run_capture(bytes(6208), fail_core=True)


if __name__ == '__main__':
    unittest.main()
