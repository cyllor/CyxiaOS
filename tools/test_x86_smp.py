"""Mechanism evidence mutations; fixtures never establish native acceptance."""
import importlib
import unittest

from test_x86_64 import frame


def words():
    w = [0] * 128
    w[:10] = [0x003731565f504d53, 1, 128, 4, 0xfee00000, 0x7000, 0x8000, 2, 0, 7]
    for slot, apic in enumerate((7, 11, 2, 19)):
        at = 16 + slot * 28
        base = 0x200000 + slot * 0x40000
        guard = base + 0x10000
        low, high = guard + 4096, guard + 4096 + 65536
        trap_guard = high
        rsp0 = trap_guard + 4096 + 32768
        ist_guard = rsp0
        ist = ist_guard + 4096 + 16384
        w[at:at+13] = [slot, apic, base, base+4096, base+8192, rsp0, ist,
                       low, high, guard, trap_guard, ist_guard, 1]
        if slot:
            w[at+13:at+26] = [6, 2, 2, 10, 10, 3, 20, 4, 4, 30, 30, 5, 40]
    return w


class SmpEvidence(unittest.TestCase):
    def setUp(self):
        try:
            self.smp = importlib.import_module('x86_smp')
        except ModuleNotFoundError:
            self.fail('independent SMP evidence decoder is absent')
        self.pc = importlib.import_module('x86_64')

    def test_sparse_apic_identity_and_real_two_round_progress(self):
        result = self.smp.validate_words(words())
        self.assertEqual(result['apic_ids'], [7, 11, 2, 19])
        self.assertEqual(result['stopped_rounds'], 2)
        self.assertFalse(result['unified_runtime_supported'])

    def test_stale_ack_late_work_aliases_and_wrong_cpu_cannot_pass(self):
        at = 16 + 28
        for field, value in [(3, 1), (8, 1), (at, 0), (at+1, 7),
                             (at+2, 0x200000), (at+5, 0x200010), (at+9, 0x8000),
                             (at+12, 0), (at+13, 0), (at+15, 1), (at+17, 11),
                             (at+19, 10), (at+21, 2), (at+23, 31), (at+25, 30),
                             (at+26, 1), (127, 1)]:
            w = words(); w[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.smp.validate_words(w)

    def test_raw_word_lines_cannot_be_missing_duplicated_or_reordered(self):
        lines = [f'SMP_V17 {i} {value:016x}' for i, value in enumerate(words())]
        self.assertEqual(self.smp.decode(lines)['apic_ids'], [7, 11, 2, 19])
        for changed in (lines[:-1], lines+[lines[-1]], [lines[1], lines[0], *lines[2:]],
                        [*lines[:-1], 'SMP_V17 127 10000000000000000']):
            with self.assertRaises(ValueError):
                self.smp.decode(changed)

    def test_bsp_output_and_mismatched_cpu_configuration_cannot_certify_smp(self):
        bsp = b''.join(frame((label+'\n').encode(), i) for i, label in enumerate(self.pc.MARKERS, 1))
        with self.assertRaises(ValueError):
            self.pc.validate_serial(bsp, 33, forced=False, eof=True, mechanism='smp')
        argv = self.pc.launch_argv('qemu', 'image', 'tcg', mechanism='smp')
        self.assertEqual(argv[argv.index('-smp')+1], 'cpus=4,sockets=1,cores=4,threads=1')
        self.assertEqual(self.pc.build_argv('cargo', 'dev', mechanism='smp')[-1], 'smp-selftest')

    def test_only_complete_serial_smp_receipt_and_terminal_exit_pass(self):
        lines = list(self.pc.MARKERS[:-1])
        lines += ['SMP_DISCOVERY_OK', 'SMP_AP_ONLINE_OK', 'SMP_IPI_OK', 'SMP_STOP_RESUME_OK']
        lines += [f'SMP_V17 {i} {v:016x}' for i,v in enumerate(words())]
        lines += ['SMP_V17_OK', 'X86_SELFTEST_OK']
        raw = b''.join(frame((line+'\n').encode(), i) for i,line in enumerate(lines, 1))
        got = self.pc.validate_serial(raw, 33, forced=False, eof=True, mechanism='smp')
        self.assertEqual(got['smp']['apic_ids'], [7, 11, 2, 19])
        with self.assertRaises(ValueError):
            self.pc.validate_serial(raw, 33, forced=True, eof=True, mechanism='smp')
