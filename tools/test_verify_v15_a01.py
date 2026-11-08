"""Adversarial host vectors for the raw A01 authority contract; never native evidence."""
import struct
import unittest

from verify_v15_a01 import MAGIC, verify_formal_samples


def packed(words):
    return struct.pack('<' + str(len(words)) + 'Q', *words)


def fixture(mode=0):
    b = [0] * 64
    b[:2] = [0x435958424f4f5431, 1]
    b[3:8] = [3 if mode == 0 else 2, 0 if mode == 0 else (5 if mode == 3 else 4), mode,
               7 if mode in (0, 3) else 0, 100 if mode in (0, 3) else 0]
    b[9] = 15
    b[14:16] = [200, 300] if mode == 0 else [0, 0]
    b[32:46] = list(range(1, 15))
    f = [0] * 256
    f[:8] = [MAGIC, 1, 256, mode, b[6], b[7], b[14], b[15]]
    f[16:30] = b[32:46]
    for cpu in range(4):
        r = 32 + cpu * 24
        f[r:r + 9] = [2, cpu, 10 + cpu, 4, 0x1005, 0x80, 0x41000000,
                        0xffff000040100000, cpu]
        if cpu >= 2 or mode == 0 or (cpu == 1 and mode == 3):
            f[r + 12:r + 23] = [2, 350 + cpu, 0, 0x15 << 26, 8,
                                  0x100004, 0x42000000 + cpu * 0x1000,
                                  0x42000000 + cpu * 0x1000, 0x80, 4,
                                  2 if cpu == 1 else 1]
    if mode == 0:
        f[8:10] = [1, 1]
        f[128:148] = [2, 400, 7, 1, 1, 22, 3, 1, 1, 2, 1, 0] + [1] * 8
        f[148:152] = [0, 1, 1, 2]
        f[160:184] = [2, 500, 7, 1, 1, 22, 3, 1, 1, 1, 1, 2, 1] + [1] * 8 + [1, 0, 0]
        f[182:185] = [1, 1, 2]
    return b, f


def check(b, f):
    return verify_formal_samples(packed(f), packed(b))


class FormalA01RawContract(unittest.TestCase):
    def test_all_profiles_and_first_actual_key_publication(self):
        for mode in range(4):
            b, f = fixture(mode)
            result = check(b, f)
            self.assertEqual(result['mode'], mode)
            self.assertEqual(result['architecture_verified'], True)

    def test_old_regression_or_activation_timestamp_cannot_supply_decision_key(self):
        b, f = fixture()
        for bank in ([0] * 256, f[:128] + [0] * 128):
            with self.assertRaises(ValueError):
                check(b, bank)

    def test_first_key_and_publication_epoch_model_and_order_are_checked(self):
        b, f = fixture()
        mutations = [(128, 1), (129, 99), (130, 6), (131, 0), (132, 0),
                     (133, 0), (134, 0), (135, 2), (136, 0),
                     (160, 1), (161, 99), (162, 6), (163, 0), (164, 0),
                     (165, 0), (166, 0), (167, 2), (168, 0), (169, 0),
                     (170, 0), (10, 1)]
        for index, value in mutations:
            bad = f.copy()
            bad[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                check(b, bad)

    def test_each_real_el1_and_required_el0_role_is_mandatory(self):
        b, f = fixture()
        for cpu in range(4):
            r = 32 + cpu * 24
            mutations = [(0, 0), (1, 9), (2, 0), (3, 8), (4, 0),
                                  (6, 0), (7, 0), (8, 99)]
            if cpu in (1, 2):
                mutations += [(12, 1),
                                  (13, 0), (14, 5), (15, 0), (16, 0),
                                  (17, 0), (18, 1), (19, 0), (20, 0),
                                  (21, 8), (22, 0)]
            for offset, value in mutations:
                bad = f.copy()
                bad[r + offset] = value
                with self.subTest(cpu=cpu, offset=offset), self.assertRaises(ValueError):
                    check(b, bad)

    def test_fault_profile_forbids_every_new_key_or_publication(self):
        for mode in (1, 2, 3):
            b, f = fixture(mode)
            for index in (8, 9, 128, 129, 160, 161):
                bad = f.copy()
                bad[index] = 1
                with self.subTest(mode=mode, index=index), self.assertRaises(ValueError):
                    check(b, bad)

    def test_reserved_words_lengths_and_run_identity_fail_closed(self):
        b, f = fixture()
        for index in (11, 15, 30, 31, 127, 152, 159, 185, 255):
            bad = f.copy()
            bad[index] = 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                check(b, bad)
        for index in (3, 4, 5, 6, 7, 16, 29):
            bad = f.copy()
            bad[index] += 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                check(b, bad)
        with self.assertRaises(ValueError):
            verify_formal_samples(packed(f)[:-8], packed(b))


class FormalA01CaptureContract(unittest.TestCase):
    def calls(self):
        from test_verify_v13_boot_receipt import calls, ROOT
        result = []
        for entry in calls():
            result.append(entry)
            if entry[0] == 'pmemsave' and entry[1]['filename'].endswith('/first.bin'):
                result.append(('pmemsave', {'val': 0x41600000, 'size': 2048,
                    'filename': str(ROOT / 'formal-first.bin')}, {}))
            if entry[0] == 'pmemsave' and entry[1]['filename'].endswith('/last.bin'):
                result.append(('pmemsave', {'val': 0x41600000, 'size': 2048,
                    'filename': str(ROOT / 'formal-last.bin')}, {}))
        return result

    def replay(self, calls):
        from test_verify_v13_boot_receipt import SYMBOLS, PLATFORM, ROOT, transcript
        from verify_v13_boot_receipt import verify_qmp
        symbols = dict(SYMBOLS, formal={'pa': 0x41600000})
        return verify_qmp(transcript(calls), ROOT, symbols, 64, PLATFORM, formal=True)

    def test_formal_bank_requires_exact_both_stopped_capture_groups(self):
        self.assertEqual(self.replay(self.calls()), b'raw serial')
        original = self.calls()
        for index, entry in enumerate(original):
            if entry[0] == 'pmemsave' and '/formal-' in entry[1]['filename']:
                bad = original[:index] + original[index + 1:]
                with self.assertRaises(ValueError):
                    self.replay(bad)
                for key, value in (('val', 0x41600008), ('size', 2040)):
                    bad = list(original)
                    bad[index] = (entry[0], dict(entry[1], **{key: value}), entry[2])
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        self.replay(bad)

    def test_live_formal_bytes_cannot_replace_stopped_authority(self):
        original = self.calls()
        i = next(i for i, e in enumerate(original) if e[0] == 'pmemsave'
                 and e[1]['filename'].endswith('/formal-first.bin'))
        entry = original.pop(i)
        first_stop = next(i for i, e in enumerate(original) if e[0] == 'stop')
        original.insert(first_stop, entry)
        with self.assertRaises(ValueError):
            self.replay(original)


if __name__ == '__main__':
    unittest.main()
