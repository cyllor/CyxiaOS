"""Decoder-only A01 cold-boot CPU assertions, not native execution evidence."""
import unittest

from test_verify_v13_boot_recovery import fixture, verify


class NormalBootCpus(unittest.TestCase):
    def test_each_stopped_normal_sample_requires_exact_registered_cpu_set(self):
        for sample in (0, 1):
            for mask in (0, 1, 7, 14, 31):
                with self.subTest(sample=sample, mask=mask):
                    first, last, config = fixture(0)
                    (first, last)[sample][9] = mask
                    with self.assertRaisesRegex(ValueError, 'four registered guest CPUs'):
                        verify(first, last, config)

    def test_report_exposes_guest_registration_not_only_launch_configuration(self):
        for mode in range(4):
            with self.subTest(mode=mode):
                observed = verify(*fixture(mode))
                self.assertEqual(observed['online_mask'], 15)
                self.assertEqual(observed['native_acceptance_status'], 'NOT_RUN')


if __name__ == '__main__':
    unittest.main()
