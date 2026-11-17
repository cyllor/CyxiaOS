"""Exercise the real capture finalization with controlled VM/socket fixtures."""
from contextlib import ExitStack, nullcontext
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import os_smoke


class CaptureFinalization(unittest.TestCase):
    def capture(self, *, phase='last-display', payload=b'', read_error=False, returncode=0):
        current = {'phase': 'running', 'sent': False, 'read_error': read_error}

        class Process:
            done = False

            def poll(self):
                return returncode if self.done else None

            def wait(self, timeout=None):
                self.done = True
                current['phase'] = 'after-wait'
                return returncode

        class Socket:
            def setblocking(self, value):
                pass

            def recv(self, size):
                if current['phase'] == phase and not current['sent']:
                    current['sent'] = True
                    if current['read_error']:
                        raise OSError('final serial read failed')
                    return payload
                raise BlockingIOError

        class Console(os_smoke.Console):
            def until(self, *args, **kwargs):
                return None

            def command(self, command, expected=()):
                self.commands.append({'command': command, 'serial_offset': len(self.raw)})
                return len(self.raw)

        class Qmp:
            def __init__(self, connection):
                self.transcript = []
                self.screenshots = 0

            def receive(self, deadline):
                pass

            def execute(self, command, arguments=None):
                if command == 'query-cpus-fast':
                    return [{}] * 4
                if command == 'human-monitor-command':
                    return '\n'.join(['CR0=00000020 EFER=00000000'] * 4)
                if command == 'screendump':
                    self.screenshots += 1
                    if self.screenshots == 2:
                        current['phase'] = 'last-display'
                return {}

        def create_disk(path):
            path.write_bytes(b'fixture disk')
            return path

        with tempfile.TemporaryDirectory(prefix='cyxia-finalization-') as temporary:
            root = Path(temporary)
            build = root / 'build'
            build.mkdir()
            (build / 'build-manifest.json').write_text('{}')
            manifest = {'features': ['graphics'], 'source_sha256': 'fixture-source'}
            with ExitStack() as stack:
                for target, name, options in [
                    (os_smoke, 'native_lease', {'return_value': nullcontext()}),
                    (os_smoke, 'idle_native_host', {}),
                    (os_smoke.os_x86, 'validate_build', {'return_value': manifest}),
                    (os_smoke.os_x86, 'launch_argv', {'return_value': ['/usr/bin/true', '-serial', 'stdio']}),
                    (os_smoke, 'create_disk', {'side_effect': create_disk}),
                    (os_smoke.subprocess, 'Popen', {'return_value': Process()}),
                    (os_smoke, 'connect', {'return_value': Socket()}),
                    (os_smoke, 'Console', {'new': Console}),
                    (os_smoke, 'Qmp', {'new': Qmp}),
                    (os_smoke, 'verify_boot_frame', {'return_value': {'verified_pixels': 786432}}),
                ]:
                    stack.enter_context(patch.object(target, name, **options))
                result = os_smoke.capture(build, root / 'capture', qemu='/usr/bin/true')
            serial = (root / 'capture/serial.raw').read_bytes()
            persisted = json.loads((root / 'capture/summary.json').read_text())
            self.assertEqual(persisted, result)
            self.assertEqual(result['serial_sha256'], os_smoke.pc.sha_bytes(serial))
            return result, serial

    def test_failure_after_last_display_cannot_retain_pass(self):
        result, serial = self.capture(payload=b'NATIVE_SERVICE_PANIC final read\r\n')
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('guest failure', result['error'])
        self.assertIn(b'NATIVE_SERVICE_PANIC', serial)

    def test_failure_buffered_at_normal_shutdown_is_rejected(self):
        result, serial = self.capture(phase='after-wait', payload=b'STORAGE_ERROR on shutdown\r\n')
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('guest failure', result['error'])
        self.assertIn(b'STORAGE_ERROR', serial)
        self.assertEqual(result['returncode'], 0)

    def test_final_socket_error_is_retained_as_failure(self):
        result, _ = self.capture(read_error=True)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('final serial read failed', result['error'])

    def test_success_retains_last_bytes_after_expected_exit(self):
        result, serial = self.capture(phase='after-wait', payload=b'normal shutdown\r\n')
        self.assertEqual(result['status'], 'OS_CORE_PASS')
        self.assertNotIn('error', result)
        self.assertEqual(serial, b'normal shutdown\r\n')
        self.assertEqual(result['returncode'], 0)

    def test_nonzero_exit_cannot_pass(self):
        result, _ = self.capture(returncode=3)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('QEMU did not exit normally', result['error'])


if __name__ == '__main__':
    unittest.main()
