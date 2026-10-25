"""Host-only A02 trace fixtures; these bytes are never native acceptance evidence."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))

# Literal wire values are deliberate: the production decoder cannot define its
# own expected input or expected scheduling/accounting result.
IMAGE = bytes.fromhex('11' * 32)
INPUT = bytes.fromhex('22' * 32)
SOURCE = bytes.fromhex('33' * 32)


def event(sequence, tick, kind, cpu, task=0, generation=0, core=1, *payload):
    return [sequence, tick, kind, cpu, task, generation, core,
            *payload, *([0] * (9 - len(payload)))]


def fixture():
    rows = [
        event(1, 100, 1, 4, 10, 1, 1, 1, 5),  # business: CPUs 0 and 2
        event(2, 101, 1, 4, 20, 1, 1, 2, 2),  # control: CPU 1
        event(3, 110, 3, 0, 10, 1, 1, 1),
        event(4, 111, 5, 0, 10, 1, 1, 1, 2),  # actual business asks for C
        event(5, 112, 6, 0, 10, 1, 1, 1, 1),  # E_AUTH
        event(6, 113, 3, 1, 20, 1, 1, 1),
        event(7, 120, 4, 1, 20, 1, 1, 1),
        event(8, 121, 4, 0, 10, 1, 1, 1),
        event(9, 122, 2, 4, 0, 0, 2, 2, 9, 4, 0, 0, 0),
        event(10, 123, 2, 4, 0, 0, 3, 2, 9, 0, 4, 0, 0),
        event(11, 124, 2, 4, 0, 0, 4, 2, 13, 0, 0, 0, 0),
        event(12, 125, 3, 2, 10, 1, 4, 1),
        event(13, 130, 4, 2, 10, 1, 4, 1),
        event(14, 131, 3, 1, 20, 1, 4, 2),
        event(15, 135, 4, 1, 20, 1, 4, 2),
    ]
    header = [0] * 64
    header[:20] = [0x4359584130325452, 1, 16, 15, 0, 2, 7, 41, 42,
                   100, 140, 1000, 1, 2, 13, 0, 0, 0, 0, 4]
    header[24:28] = struct.unpack('<4Q', IMAGE)
    header[28:32] = struct.unpack('<4Q', INPUT)
    header[32:36] = struct.unpack('<4Q', SOURCE)
    snapshot = [0] * 64
    snapshot[:16] = [0x4359584130324354, 1, 2, 7, 41, 42, 140, 15, 0,
                     4, 2, 13, 0, 0, 0, 0]
    snapshot[16:20] = [1, 2, 1, 0]
    snapshot[20:24] = [1, 2, 1, 0]
    snapshot[24:28] = [1, 1, 0, 2]
    snapshot[28:32] = struct.unpack('<4Q', IMAGE)
    snapshot[32:36] = struct.unpack('<4Q', INPUT)
    snapshot[36:40] = struct.unpack('<4Q', SOURCE)
    snapshot[40:44] = [11, 11, 5, 0]
    return header, rows, snapshot


def encode(header, rows, snapshot):
    return (struct.pack('<64Q', *header) + b''.join(struct.pack('<16Q', *r) for r in rows),
            struct.pack('<64Q', *snapshot))


class A02RawContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'tools/verify_v13_a02.py').is_file(),
                        'A02 raw scheduler trace verifier is not implemented')
        import verify_v13_a02
        self.verify = verify_v13_a02.verify
        self.header, self.rows, self.snapshot = fixture()

    def check(self):
        return self.verify(*encode(self.header, self.rows, self.snapshot),
                           image_sha256=IMAGE.hex(), input_sha256=INPUT.hex(),
                           source_sha256=SOURCE.hex())

    def test_reconstructs_dispatch_and_denial_without_promoting_fixture(self):
        result = self.check()
        self.assertEqual(result['dispatches_per_cpu'], [1, 2, 1, 0])
        self.assertEqual(result['elapsed_ticks_per_cpu'], [11, 11, 5, 0])
        self.assertEqual(result['business_control_bind_denials'], 1)
        self.assertEqual(result['ownership_publications'], 3)
        self.assertEqual(result['native_acceptance_status'], 'NOT_RUN')
        self.assertFalse(result['runtime_truth_attested'])

    def test_v2_records_dynamic_tasks_and_post_trap_affinity_admission(self):
        self.header[1] = self.snapshot[1] = 2
        # The syscall handler executes after the actual EL0 return, so the
        # caller's exit precedes its binding admission, not the reverse.
        self.rows = [self.rows[i] for i in (0, 2, 7, 3, 4, 1, 5, 6, 8, 9, 10, 11, 12, 13, 14)]
        for sequence, row in enumerate(self.rows, 1):
            row[0] = sequence
            row[1] = 100 + sequence
        self.snapshot[40:44] = [1, 2, 1, 0]
        self.assertEqual(self.check()['denied_bindings'], 1)

    def test_v2_still_rejects_binding_without_an_actual_returned_caller(self):
        self.header[1] = self.snapshot[1] = 2
        with self.assertRaisesRegex(ValueError, 'returned caller'):
            self.check()

    def deferred_capture(self):
        self.header[1] = self.snapshot[1] = 2
        self.rows = [event(1, 101, 1, 4, 10, 1, 1, 1, 5),
            event(2, 102, 3, 0, 10, 1, 1, 1), event(3, 103, 4, 0, 10, 1, 1, 1),
            event(4, 104, 1, 4, 30, 1, 1, 1, 1), event(5, 105, 3, 0, 30, 1, 1, 2),
            event(6, 106, 5, 0, 10, 1, 1, 1, 2), event(7, 107, 6, 0, 10, 1, 1, 1, 1),
            event(8, 108, 4, 0, 30, 1, 1, 2), event(9, 109, 1, 4, 20, 1, 1, 2, 2),
            event(10, 110, 3, 1, 20, 1, 1, 1), event(11, 111, 4, 1, 20, 1, 1, 1)]
        self.header[3] = self.snapshot[7] = 11
        self.snapshot[9:16] = [1, 2, 13, 0, 0, 0, 0]
        self.snapshot[16:28] = [2, 1, 0, 0, 2, 1, 0, 0, 1, 1, 0, 3]
        self.snapshot[40:44] = [4, 1, 0, 0]

    def test_v2_deferred_binding_keeps_exact_caller_while_another_task_runs(self):
        self.deferred_capture()
        self.assertEqual(self.check()['business_control_bind_denials'], 1)

    def test_v2_reentry_and_wrong_return_origin_cannot_authorize_deferred_bind(self):
        for mutate in ('reentry', 'origin'):
            with self.subTest(mutate=mutate):
                self.deferred_capture()
                if mutate == 'reentry': self.rows[4][4] = 10
                else: self.rows[5][3] = 2
                with self.assertRaisesRegex(ValueError, 'returned caller'):
                    self.check()

    def test_rejects_accepted_business_control_affinity(self):
        self.rows[4][8] = 0
        with self.assertRaisesRegex(ValueError, 'forbidden affinity'):
            self.check()

    def test_requires_actual_business_control_binding_attempt(self):
        del self.rows[3:5]
        for sequence, row in enumerate(self.rows, 1):
            row[0] = sequence
        self.header[3] = self.snapshot[7] = 13
        self.snapshot[24:27] = [0, 0, 0]
        with self.assertRaisesRegex(ValueError, 'business.*control.*denial'):
            self.check()

    def test_rejects_missing_complete_trace_even_with_renumbered_rows(self):
        del self.rows[11:13]
        for sequence, row in enumerate(self.rows, 1):
            row[0] = sequence
        self.header[3] = self.snapshot[7] = 13
        with self.assertRaisesRegex(ValueError, 'dispatch counters'):
            self.check()

    def test_rejects_counter_rewritten_to_hide_missing_execution_time(self):
        self.snapshot[40] -= 1
        with self.assertRaisesRegex(ValueError, 'elapsed counters'):
            self.check()

    def test_business_cannot_enter_control_transition_or_quarantine_cpu(self):
        # All are observed ownership states; granting a wider initial affinity
        # cannot make execution on their protected cores legitimate.
        for masks in ((6, 9, 0, 0), (2, 9, 4, 0), (2, 9, 0, 4)):
            with self.subTest(masks=masks):
                self.header, self.rows, self.snapshot = fixture()
                self.rows[10][7:11] = masks
                with self.assertRaisesRegex(ValueError, 'business.*protected'):
                    self.check()

    def test_business_cannot_enter_draining_or_suspect_core(self):
        for index in (11, 12):
            with self.subTest(index=index):
                self.header, self.rows, self.snapshot = fixture()
                self.rows[10][index] = 4
                with self.assertRaisesRegex(ValueError, 'draining/suspect'):
                    self.check()

    def test_ownership_cannot_move_a_running_business_task_to_control(self):
        self.rows[5] = event(6, 113, 2, 4, 0, 0, 2, 3, 12, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, 'business.*protected'):
            self.check()

    def test_stale_core_generation_cannot_authorize_dispatch(self):
        self.rows[11][6] = 3
        with self.assertRaisesRegex(ValueError, 'core generation'):
            self.check()

    def test_stale_task_generation_cannot_authorize_dispatch(self):
        self.rows[11][5] = 2
        with self.assertRaisesRegex(ValueError, 'task generation'):
            self.check()

    def test_task_cannot_run_on_two_cpus_concurrently(self):
        self.rows[5] = event(6, 113, 3, 2, 10, 1, 1, 1)
        with self.assertRaisesRegex(ValueError, 'concurrent task'):
            self.check()

    def test_binding_request_must_come_from_running_caller(self):
        self.rows[3][4] = 20
        with self.assertRaisesRegex(ValueError, 'running caller'):
            self.check()

    def test_binding_result_must_match_request(self):
        self.rows[4][7] = 2
        with self.assertRaisesRegex(ValueError, 'binding result'):
            self.check()

    def test_control_role_cannot_be_relabelled_mid_run(self):
        self.rows[10] = event(11, 124, 1, 4, 10, 1, 3, 2, 2)
        with self.assertRaisesRegex(ValueError, 'registration'):
            self.check()

    def test_requires_quiescent_sealed_end(self):
        self.rows.pop()
        self.header[3] = self.snapshot[7] = 14
        with self.assertRaisesRegex(ValueError, 'unfinished dispatch'):
            self.check()

    def test_requires_zero_initial_dispatch_counters(self):
        self.header[20] = 1
        with self.assertRaisesRegex(ValueError, 'before first dispatch'):
            self.check()

    def test_requires_disjoint_complete_ownership(self):
        self.rows[8][8] |= 2
        with self.assertRaisesRegex(ValueError, 'ownership partition'):
            self.check()

    def test_rejects_reordered_trace_and_sequence_gaps(self):
        self.rows[6], self.rows[7] = self.rows[7], self.rows[6]
        with self.assertRaisesRegex(ValueError, 'event sequence'):
            self.check()

    def test_rejects_clock_regression(self):
        self.rows[5][1] = 105
        with self.assertRaisesRegex(ValueError, 'event clock'):
            self.check()

    def test_rejects_overflow_and_unsealed_capture(self):
        for index, value in ((4, 1), (5, 0), (5, 3)):
            with self.subTest(index=index, value=value):
                self.header, self.rows, self.snapshot = fixture()
                self.header[index] = value
                with self.assertRaises(ValueError):
                    self.check()

    def test_rejects_different_boot_run_or_capture_in_counter_snapshot(self):
        for index in (2, 3, 4, 5, 6, 7, 8, 9):
            with self.subTest(index=index):
                self.header, self.rows, self.snapshot = fixture()
                self.snapshot[index] += 1
                with self.assertRaises(ValueError):
                    self.check()

    def test_rejects_wrong_artifact_identity_even_when_both_captures_agree(self):
        trace, counters = encode(self.header, self.rows, self.snapshot)
        for field in ('image_sha256', 'input_sha256', 'source_sha256'):
            with self.subTest(field=field):
                args = dict(image_sha256=IMAGE.hex(), input_sha256=INPUT.hex(),
                            source_sha256=SOURCE.hex())
                args[field] = '44' * 32
                with self.assertRaisesRegex(ValueError, 'artifact identity'):
                    self.verify(trace, counters, **args)

    def test_rejects_missing_suffix_extra_bytes_and_unknown_events(self):
        trace, counters = encode(self.header, self.rows, self.snapshot)
        for candidate in (trace[:-8], trace + bytes(8)):
            with self.subTest(length=len(candidate)):
                with self.assertRaisesRegex(ValueError, 'trace length'):
                    self.verify(candidate, counters, image_sha256=IMAGE.hex(),
                                input_sha256=INPUT.hex(), source_sha256=SOURCE.hex())
        self.rows[7][2] = 99
        with self.assertRaisesRegex(ValueError, 'event kind'):
            self.check()

    def test_rejects_nonzero_reserved_data(self):
        for part, index in ((self.header, 63), (self.snapshot, 63), (self.rows[2], 15)):
            with self.subTest(index=index):
                part[index] = 1
                with self.assertRaisesRegex(ValueError, 'reserved'):
                    self.check()
                part[index] = 0

    def test_cli_rejects_text_pass_marker_in_optimized_python(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fake.bin'
            path.write_bytes(b'A02 PASS\n')
            result = subprocess.run([sys.executable, '-O', str(ROOT / 'tools/verify_v13_a02.py'),
                                     '--trace', str(path), '--counters', str(path), '--image', str(path),
                                     '--input', str(path), '--source-manifest', str(path)],
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('a02-evidence:', result.stderr)


if __name__ == '__main__':
    unittest.main()
