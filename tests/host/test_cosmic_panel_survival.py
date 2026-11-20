"""Panel survival evidence must reject replaced, absent and briefly live clients."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from os_cosmic_panel_allocation_probe import assess


def rows(pids):
    return b'theme work begin phase=initial-reset\n' + b''.join(
        f'EL0 UserStatus {{ pid: {pid}, entry: 0x1000000, state: Waiting, code: 0, threads: 8 }}\n'.encode()
        for pid in pids)


def capture(seconds=90):
    return dict(status='PASS', qemu_exit_code=0, first_frame_seconds=45,
                later_diagnostic=dict(observed_seconds=seconds),
                bus_inspection=dict(notifications_name_present=True))


class PanelSurvival(unittest.TestCase):
    def test_healthy_core_establishes_only_panel_survival(self):
        result = assess(rows(range(2, 7)), capture())
        self.assertEqual(result['status'], 'PASS')
        for name in ('full_os_verified', 'cosmic_session_verified', 'semantic_frame_verified',
                     'panel_applets_verified'):
            self.assertFalse(result[name])

    def test_public_bus_and_replaced_pixels_do_not_establish_panel_survival(self):
        self.assertEqual(assess(rows(range(2, 6)), capture())['status'], 'FAIL')

    def test_a_replacement_does_not_erase_original_panel_abort(self):
        raw = rows([2, 3, 4, 5, 9]) + b'USER pid=6 Exited code=134\n'
        self.assertEqual(assess(raw, capture())['status'], 'FAIL')

    def test_short_observation_and_failed_first_frame_stay_failures(self):
        self.assertEqual(assess(rows(range(2, 7)), capture(45))['status'], 'FAIL')
        value = capture()
        value['status'] = 'FAIL'
        self.assertEqual(assess(rows(range(2, 7)), value)['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
