"""Keep static-musl acceptance strict about runtime evidence and its limits."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from verify_ported import (parse_processes, validate_absent_rng, validate_probe,
                           verify)


TRANSCRIPT = b'''ELF pid=1 started; ABI=Linux-AArch64-subset image AI_DIRECT model=8195 pages=20
PORTED_PROBE START argc=1 argv0=/bin/probe
PORTED_PROBE TLS_ERRNO PASS
PORTED_PROBE MALLOC_FREE PASS bytes=262144 cycles=3
PORTED_PROBE FILE_IO PASS
PORTED_PROBE FLOAT PASS value=3.625
PORTED_PROBE FP_IRQ PASS elapsed_ns=50000000
PORTED_PROBE PASS
EL0 pid=1 Exited code=0 free_pages=64 esr=0x0 far=0x0
'''
STATUS = dict(pid=1, state='Exited', code=0, syscalls=28, preemptions=2,
              ai_slices=11, cpu_model=12290, esr=0, far=0, free_pages=64,
              rank_model=12289, ai_selections=11, heap_pages=0,
              heap_free=2048, heap_model=8194)


class PortedEvidenceTests(unittest.TestCase):
    def test_complete_evidence_reports_unobserved_image_reclamation(self):
        result = validate_probe(TRANSCRIPT, {1: STATUS}, 20)
        self.assertEqual(result['pid'], 1)
        self.assertFalse(result['image_reclamation_observed'])
        self.assertEqual(result['preemptions'], 2)
        self.assertEqual(result['fp_irq_elapsed_ns'], 50000000)

    def test_image_reclamation_requires_actual_accounting(self):
        with self.assertRaises(AssertionError):
            validate_probe(TRANSCRIPT, {1: STATUS}, 20, require_image=True)
        row = dict(STATUS, image_pages=0, image_free=4096)
        self.assertTrue(validate_probe(TRANSCRIPT, {1: row}, 20,
                                       require_image=True)['image_reclamation_observed'])
        for changed in [dict(image_pages=1), dict(image_free=4095)]:
            with self.assertRaises(AssertionError):
                validate_probe(TRANSCRIPT, {1: dict(row, **changed)}, 20)

    def test_every_stage_is_required_in_order_exactly_once(self):
        stages = TRANSCRIPT.splitlines()[1:8]
        for stage in stages:
            for changed in [TRANSCRIPT.replace(stage + b'\n', b''),
                            TRANSCRIPT.replace(stage, stage + b'\n' + stage),
                            TRANSCRIPT.replace(stage, stage + b'_NOT_ACTUAL_PASS')]:
                with self.subTest(stage=stage), self.assertRaises(AssertionError):
                    validate_probe(changed, {1: STATUS}, 20)
        swapped = TRANSCRIPT.replace(stages[1], b'TEMP').replace(stages[2], stages[1])
        swapped = swapped.replace(b'TEMP', stages[2])
        with self.assertRaises(AssertionError):
            validate_probe(swapped, {1: STATUS}, 20)

    def test_fp_loop_duration_is_not_an_unchecked_pass_label(self):
        for duration in [b'0', b'49999999', b'-1', b'unknown', b'50000000x']:
            with self.subTest(duration=duration), self.assertRaises(AssertionError):
                validate_probe(TRANSCRIPT.replace(b'elapsed_ns=50000000',
                               b'elapsed_ns=' + duration), {1: STATUS}, 20)

    def test_status_cannot_hide_faults_leaks_missing_ai_or_irq(self):
        for changed in [dict(state='Fault'), dict(code=1), dict(syscalls=0),
                        dict(preemptions=0), dict(esr=1), dict(far=1),
                        dict(free_pages=63), dict(heap_pages=1), dict(heap_free=1023),
                        dict(rank_model=0), dict(ai_selections=0), dict(cpu_model=0),
                        dict(heap_model=0)]:
            with self.subTest(changed=changed), self.assertRaises(AssertionError):
                validate_probe(TRANSCRIPT, {1: dict(STATUS, **changed)}, 20)

    def test_launch_identity_and_terminal_record_must_agree(self):
        for changed in [TRANSCRIPT.replace(b'EL0 pid=1', b'EL0 pid=2'),
                        TRANSCRIPT.replace(b'pages=20', b'pages=19'),
                        TRANSCRIPT.replace(b'model=8195', b'model=0'),
                        TRANSCRIPT.replace(b'code=0', b'code=1'),
                        TRANSCRIPT + TRANSCRIPT,
                        TRANSCRIPT + b'PORTED_PROBE FAIL late errno=5\n',
                        TRANSCRIPT + b'FAIL unexpected exception\n']:
            with self.assertRaises(AssertionError):
                validate_probe(changed, {1: STATUS}, 20)
        with self.assertRaises(AssertionError):
            validate_probe(TRANSCRIPT, {2: dict(STATUS, pid=2)}, 20)

    def test_missing_rng_requires_denial_without_execution_and_live_shell(self):
        boot = b'ENTROPY_UNAVAILABLE MECHANISM\n'
        denied = b'ELF start failed: Nodev\r\n'
        pwd = b'pwd\r\n/\r\ncyxia:/> '
        validate_absent_rng(boot + denied, pwd)
        for changed in [boot, denied, boot + denied + TRANSCRIPT,
                        boot + denied + b'PORTED_PROBE START argc=1 argv0=/bin/probe\n',
                        boot + denied + b'ELF pid=42 started; unknown\n']:
            with self.assertRaises(AssertionError):
                validate_absent_rng(changed, pwd)
        with self.assertRaises(AssertionError):
            validate_absent_rng(boot + denied, b'cyxia:/> ')

    def test_process_snapshots_reject_duplicates_and_missing_rows(self):
        record = b'EL0 UserStatus { pid: 1, state: Exited, code: 0 }\n'
        self.assertEqual(parse_processes(record)[1]['state'], 'Exited')
        for data in [b'', record + record]:
            with self.assertRaises(AssertionError):
                parse_processes(data)

    def test_early_failure_still_writes_fail_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = verify(root / 'missing.elf', root / 'out', root / 'probe.elf')
            saved = json.loads((root / 'out/summary.json').read_text())
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(saved, result)
            self.assertIn('FileNotFoundError', saved['error'])


if __name__ == '__main__':
    unittest.main()
