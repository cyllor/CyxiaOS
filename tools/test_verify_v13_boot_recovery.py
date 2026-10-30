"""Decoder fixtures only; never evidence of native A01 acceptance."""
import struct
import unittest

from verify_v13_boot_recovery import CONFIG_MAGIC, MAGIC, verify_samples


def packed(words):
    return struct.pack('<64Q', *words)


def fixture(mode):
    c = [CONFIG_MAGIC, 1, mode, 0, 17, 23] + list(range(1, 13)) + [0] * 46
    h = [0] * 64
    h[:6] = [MAGIC, 1, 2, 3 if mode == 0 else 2, 0 if mode == 0 else (5 if mode == 3 else 4), mode]
    h[8:14] = [100, 15, 5, 8, 12, 15]
    h[32:46] = c[4:18]
    if mode in (0, 3):
        h[6:8] = [1, 50]
        h[20:25] = [1000, 8, 1, 1, 1 if mode == 0 else 2]
    if mode == 0:
        h[14:16] = [60, 70]
    if mode in (1, 2):
        h[16:19] = [mode, 3 if mode == 1 else 0, 40]
    a = h.copy()
    h[2] += 2
    h[8] += 100
    for i in (10, 11, 12, 13):
        h[i] += 10
    return a, h, c


def verify(a, b, c, control=bytes(4096), runtime=bytes(8192), unified=bytes(4096)):
    return verify_samples(packed(a), packed(b), control, runtime, unified, packed(c))


class BootRecoveryDecoder(unittest.TestCase):
    def test_all_frozen_modes_do_not_claim_acceptance(self):
        for mode in range(4):
            with self.subTest(mode=mode):
                result = verify(*fixture(mode))
                self.assertTrue(result['boot_recovery_contract_valid'])
                self.assertEqual(result['native_acceptance_status'], 'NOT_RUN')

    def test_recovery_requires_real_progress(self):
        for index in (2, 8, 10, 11, 12, 13):
            with self.subTest(index=index):
                a, b, c = fixture(1)
                b[index] = a[index]
                with self.assertRaises(ValueError):
                    verify(a, b, c)

    def test_failed_boot_has_no_authority_or_guessed_epoch(self):
        for mode in (1, 2, 3):
            for bank, size in (('control', 4096), ('runtime', 8192), ('unified', 4096)):
                with self.subTest(mode=mode, bank=bank):
                    value = bytearray(size)
                    value[8] = 1
                    with self.assertRaises(ValueError):
                        verify(*fixture(mode), **{bank: bytes(value)})
        a, b, c = fixture(1)
        a[6] = b[6] = 7
        with self.assertRaises(ValueError):
            verify(a, b, c)

    def test_identity_reserved_fields_and_partial_samples_fail(self):
        for index, value in ((2, 3), (5, 3), (25, 1), (32, 91), (46, 1)):
            a, b, c = fixture(1)
            b[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify(a, b, c)
        a, b, c = fixture(1)
        c[18] = 1
        with self.assertRaises(ValueError):
            verify(a, b, c)

    def test_activation_requires_order_selftest_owner_and_cpu(self):
        for index, value in ((7, 80), (14, 40), (20, 0), (20, 8_000_001), (22, 2), (23, 0), (24, 2)):
            a, b, c = fixture(0)
            b[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify(a, b, c)

    def test_corrupt_model_must_execute_and_fail(self):
        for index, value in ((20, 0), (22, 2), (23, 0), (24, 1), (14, 1)):
            a, b, c = fixture(3)
            b[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify(a, b, c)

    def test_missing_real_device_injection_is_not_a_pass(self):
        for mode in (1, 2):
            for index in (16, 18):
                a, b, c = fixture(mode)
                b[index] = 0
                with self.subTest(mode=mode, index=index), self.assertRaises(ValueError):
                    verify(a, b, c)

    def test_wrong_capture_length_fails_closed(self):
        a, b, c = fixture(0)
        with self.assertRaises(ValueError):
            verify_samples(packed(a), packed(b)[:-1], bytes(4096), bytes(8192), bytes(4096), packed(c))


if __name__ == '__main__':
    unittest.main()
