import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import os_x86


class OsBootCapacityTests(unittest.TestCase):
    def test_default_regression_uses_one_gib_and_four_cpus(self):
        command = os_x86.launch_argv('qemu', 'boot.bin')
        self.assertEqual(command[command.index('-m') + 1], '1024M')
        self.assertEqual(command[command.index('-smp') + 1], 'cpus=4,sockets=1,cores=4,threads=1')

    def test_same_image_can_boot_with_a_smaller_hardware_configuration(self):
        command = os_x86.launch_argv('qemu', 'boot.bin', cpus=2, ram_mib=960)
        self.assertEqual(command[command.index('-kernel') + 1], 'boot.bin')
        self.assertEqual(command[command.index('-m') + 1], '960M')
        self.assertEqual(command[command.index('-smp') + 1], 'cpus=2,sockets=1,cores=2,threads=1')

    def test_launcher_rejects_configurations_beyond_the_supported_hardware(self):
        for limits in ({'cpus': 0}, {'cpus': 5}, {'ram_mib': 2048}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                os_x86.launch_argv('qemu', 'boot.bin', **limits)
