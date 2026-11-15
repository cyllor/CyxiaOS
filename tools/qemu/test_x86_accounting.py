"""Clock ABI and provenance rejection tests; no compilation or VM activity."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('x86_accounting', ROOT / 'x86_accounting.py')
clock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clock)


class AccountingTests(unittest.TestCase):
    def capability(self):
        return [0x43595831, 0x00010007, 0x4b595801, 1_000_000_000]

    def test_complete_capability(self):
        self.assertEqual(clock.decode_capability(self.capability()), dict(
            abi=1, execution_msr=0x4b595801, monotonic_msr=0x4b595802,
            frequency_hz=1_000_000_000, flags=7))

    def test_missing_wrong_and_future_capabilities_rejected(self):
        for leaf in ([0, 0, 0, 0], [1, 2, 3, 4],
                     [0x43595831, 0x00020007, 0x4b595801, 1_000_000_000],
                     [0x43595831, 0x0001000f, 0x4b595801, 1_000_000_000],
                     [0x43595831, 0x00010007, 0x4b595800, 1_000_000_000],
                     [0x43595831, 0x00010007, 0x4b595801, 100_000_000]):
            with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                clock.decode_capability(leaf)

    def test_malformed_unsigned_words_rejected(self):
        for leaf in ([], [0] * 5, [True, 0, 0, 0], [-1, 0, 0, 0], [2**32, 0, 0, 0]):
            with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                clock.decode_capability(leaf)

    def test_execution_stamp_identity_and_regression(self):
        a = dict(cpu=1, source=1, ns=100)
        self.assertEqual(clock.elapsed_ns(a, dict(cpu=1, source=1, ns=200)), 100)
        self.assertEqual(clock.elapsed_ns(a, a), 0)
        for b in (dict(cpu=2, source=1, ns=200), dict(cpu=1, source=2, ns=200),
                  dict(cpu=1, source=1, ns=99), dict(cpu=1, source=1, ns=2**64),
                  dict(cpu=True, source=1, ns=200)):
            with self.subTest(stamp=b), self.assertRaises(ValueError):
                clock.elapsed_ns(a, b)

    def test_checked_debit_add_rejects_overflow(self):
        self.assertEqual(clock.add_debit_ns(2**64 - 2, 1), 2**64 - 1)
        with self.assertRaises(ValueError):
            clock.add_debit_ns(2**64 - 1, 1)

    def test_profile_denies_single_icount_kvm_and_migration(self):
        clock.validate_profile(dict(accelerator='tcg', threads='multi', icount=False, migration=False))
        for field, bad in [('accelerator', 'kvm'), ('threads', 'single'),
                           ('icount', True), ('migration', True)]:
            profile = dict(accelerator='tcg', threads='multi', icount=False, migration=False)
            profile[field] = bad
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                clock.validate_profile(profile)

    def test_exact_version_is_only_supplementary_identity(self):
        for first in ('QEMU emulator version 10.2.2',
                      'QEMU emulator version 10.2.2 (v10.2.2-dirty)'):
            self.assertEqual(clock.validate_version(first), first)
        for first in ('QEMU emulator version 10.2.3', '10.2.2',
                      'QEMU emulator version 10.2.2 (attacker-build)'):
            with self.assertRaises(ValueError):
                clock.validate_version(first)

    def test_manifest_and_standalone_patch_are_bound(self):
        manifest = clock.load_manifest()
        self.assertEqual(manifest['upstream_commit'], 'f8ed81651e61d9c2166df6121ce2af0f44f06b3e')
        self.assertEqual(set(manifest['source_sha256']), {
            'cpu-common.c', 'include/hw/core/cpu.h', 'accel/tcg/cpu-exec.c',
            'target/i386/cpu.c', 'target/i386/cpu.h', 'target/i386/tcg/system/misc_helper.c'})
        self.assertEqual(manifest['patch_sha256'], clock.sha(ROOT / 'cyxia-x86-execution.patch'))
        self.assertNotIn('target/arm/cpregs-pmu.c', manifest['source_sha256'])
        bad = copy.deepcopy(manifest)
        bad['patch_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            clock.validate_manifest(bad)


if __name__ == '__main__':
    unittest.main()
