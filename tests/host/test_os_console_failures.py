"""UART failure tokens must not match a success stage named FAILURE_ATOMICITY."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import os_smoke


class ByteStream:
    def __init__(self):
        self.chunks = []

    def setblocking(self, _):
        pass

    def recv(self, _):
        if self.chunks:
            return self.chunks.pop(0)
        raise BlockingIOError()


class ConsoleFailures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.stream = ByteStream()
        self.console = os_smoke.Console(self.stream, SimpleNamespace(poll=lambda: None),
                                       Path(self.temporary.name) / 'serial.raw')

    def test_failure_atomicity_success_is_not_a_failure_token(self):
        self.stream.chunks.append(b'SCM_PROBE FAILURE_ATOMICITY PASS\n')
        self.console.pump()

    def test_split_success_prefix_waits_for_a_token_boundary(self):
        self.stream.chunks.append(b'SCM_PROBE FAIL')
        self.console.pump()
        self.stream.chunks.append(b'URE_ATOMICITY PASS\n')
        self.console.pump()

    def test_explicit_probe_failures_remain_failures(self):
        for suffix in (b' step errno=38\n', b'\n', b'\r\n', b': detail\n'):
            with self.subTest(suffix=suffix):
                self.console.raw.clear()
                self.stream.chunks.append(b'SOCKET_RIGHTS_PROBE FAIL' + suffix)
                with self.assertRaisesRegex(ValueError, 'guest failure'):
                    self.console.pump()
        self.console.raw.clear()
        self.stream.chunks.append(b'SOCKET_RIGHTS_PROBE RESULT FAIL\n')
        with self.assertRaisesRegex(ValueError, 'guest failure'):
            self.console.pump()

    def test_failure_tail_is_captured_while_the_verdict_stays_red(self):
        self.stream.chunks.append(b"thread 'main' panicked at source/")
        with self.assertRaisesRegex(ValueError, 'guest failure'):
            self.console.pump()
        self.stream.chunks.append(b'keyboard.rs:301: XKBNotFound\n')
        with self.assertRaisesRegex(ValueError, 'guest failure'):
            self.console.pump(require_running=False)
        self.assertIn(b'source/keyboard.rs:301: XKBNotFound\n', self.console.raw)
        self.assertEqual(self.console.capture_path.read_bytes(), self.console.raw)


if __name__ == '__main__':
    unittest.main()
