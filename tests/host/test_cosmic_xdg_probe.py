"""Prevent timing/launch noise from hiding actual session path failures."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from os_cosmic_xdg_probe import assess


class CosmicXdgVerdict(unittest.TestCase):
    def setUp(self):
        self.raw = b'theme work begin phase=initial-reset\n' + b''.join(
            f'EL0 UserStatus {{ pid: {pid}, parent_pid: 2, state: Waiting, code: 0, syscalls: 800 }}\r\n'.encode()
            for pid in range(2, 7))
        self.capture = dict(status='PASS', qemu_exit_code=0)

    def test_live_initialized_services_can_pass_only_the_path_scope(self):
        self.assertEqual(assess(self.raw, self.capture)['status'], 'PASS')
        partial = dict(self.capture, status='FAIL', boot_scanout_replaced=False)
        self.assertEqual(assess(self.raw, partial)['status'], 'PASS')

    def test_launch_messages_alone_do_not_establish_live_services(self):
        raw = b'starting cosmic-panel cosmic-settings-daemon\n'
        self.assertEqual(assess(raw, self.capture)['status'], 'FAIL')

    def test_interleaved_mechanism_log_cannot_hide_the_state_error(self):
        error = b'Failed to watch xdg state dir: No patSTORAGE_CHECKPOINT_BEGIN\r\nh was found.'
        result = assess(self.raw + error, self.capture)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('Failed to watch xdg state dir:', result['errors'])

    def test_config_directory_error_or_guest_capture_failure_cannot_pass(self):
        self.assertEqual(assess(self.raw + b'Panel Entry Error: NoConfigDirectory', self.capture)['status'], 'FAIL')
        self.assertEqual(assess(self.raw, dict(self.capture, error='guest failure'))['status'], 'FAIL')
        self.assertEqual(assess(self.raw, dict(self.capture, qemu_exit_code=1))['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
